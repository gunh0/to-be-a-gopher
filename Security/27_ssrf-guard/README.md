# 27. SSRF Defence

> **Abstract.** A server that fetches user-supplied URLs (webhooks, link previews, image imports, PDF renderers) can be pointed at its own network: `127.0.0.1`, the cloud metadata service at `169.254.169.254`, an admin API on `10.x`. Validating the URL string cannot work, because the string is not where the connection goes. Resolvers accept `2130706433`, `0x7f000001` and `127.1`; a DNS name can resolve to a public address when you check and to `127.0.0.1` when you connect (rebinding); a public URL can redirect to an internal one; and a configured proxy resolves the name itself. The check has to run on the **resolved IP at dial time**: `net.Dialer.Control` sees `ip:port` immediately before `connect(2)`, for every address attempt and every redirect hop, and `netip.Addr`'s predicates (`Unmap`, `IsLoopback`, `IsPrivate`, `IsLinkLocalUnicast`, `IsUnspecified`, …) classify it.

| | |
|---|---|
| Weaknesses | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) Server-Side Request Forgery (SSRF) |
| Go packages | `net`, `net/netip`, `net/http`, `net/url`, `syscall` |
| Code | [`addr.go`](addr.go), [`client.go`](client.go), [`ssrf_test.go`](ssrf_test.go) |

## 1. Threat model

The attacker submits a URL that the server fetches with its own network position and credentials. They control the URL, the DNS records of any domain they own (including TTL 0 and answers that change per query), and the responses of any server they run, including redirects. Targets: instance metadata (cloud credentials), internal HTTP services without authentication, `localhost`-only admin endpoints, and port scanning of the internal network through timing and error differences. Full-read SSRF returns the response to the attacker; blind SSRF still triggers side effects.

## 2. What the standard library does

| Component | Behaviour relevant to SSRF |
|---|---|
| `http.DefaultClient` | Any destination; follows up to 10 redirects; `DefaultTransport` uses `ProxyFromEnvironment` (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) |
| `net.ParseIP`, `netip.ParseAddr` | Strict: reject `127.1`, `2130706433`, `0x7f000001`, and (since Go 1.17) leading zeros like `0177.0.0.1` |
| System resolver (cgo / `getaddrinfo`) | May accept the `inet_aton` forms above and return `127.0.0.1` — the URL's host and the dialled address differ |
| `net.Dialer.Control` / `ControlContext` (1.20) | Called with the resolved `"ip:port"` after the socket is created and before it connects; a non-nil error aborts that attempt |
| `netip.Addr` predicates | `IsLoopback`, `IsPrivate` (RFC 1918, RFC 4193 `fc00::/7`), `IsLinkLocalUnicast` (`169.254/16`, `fe80::/10`), `IsUnspecified`, `IsMulticast`, …; `Unmap` turns `::ffff:a.b.c.d` into IPv4 |

The predicates are not a complete "is public" test: `0.0.0.0/8` other than `0.0.0.0`, CGNAT `100.64.0.0/10`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16` and Teredo `2001::/32` (which embed IPv4 addresses) are none of loopback, private or link-local. [`IsPublic`](addr.go) adds them as explicit prefixes.

## 3. Insecure pattern

```go
http.Get(userURL)                                  // FetchInsecure

if isBlocked(u.Hostname()) { return errBlocked }   // string blocklist
http.Get(userURL)

ips, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
for _, ip := range ips { if !isPublic(ip) { return errBlocked } }
http.Get(userURL)                                  // resolves again: TOCTOU
```

[`IsBlockedHostNaive`](addr.go) misses twelve spellings in the test, from `2130706433` to `[::ffff:7f00:1]` to a public wildcard-DNS name. [`CheckThenFetch`](client.go) is the better-looking version and still loses: the test's resolver answers `93.184.215.14` for the check and `127.0.0.1` for the dial, and the internal secret comes back. It also never looks at redirects, which the test exploits separately with an outer server that redirects into the inner one.

## 4. Secure pattern

[`Guard.Client`](client.go):

```go
dialer := &net.Dialer{Control: func(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)     // always "ip:port" here
	if err != nil || !IsPublic(ap.Addr()) {
		return ErrBlocked
	}
	return nil
}}
transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext}
client := &http.Client{Transport: transport, CheckRedirect: limitHopsAndSchemes, Timeout: 10 * time.Second}
```

Why each part:

1. **Check at `Control`**, not before the request: it runs on the exact address being connected, after resolution, for each Happy Eyeballs attempt and for every redirect hop. Rebinding and redirects are handled by construction.
2. **`Unmap` first**, then the predicates plus the extra prefixes; deny by default.
3. **`Proxy: nil`.** With a proxy, `Control` only ever sees the proxy's address and the proxy resolves the target. If egress must go through a proxy, the proxy has to enforce the policy.
4. **`CheckRedirect`** caps the chain and rejects non-HTTP schemes early. The address check on redirects comes from (1), not from here.
5. **Only `tcp4`/`tcp6`**, a scheme allowlist before the request, timeouts, and a response size limit (chapter 22).

## 5. Where the guard ends

- **Allowed ports.** The default policy allows any port on public addresses; restrict `Allow` to 80/443 if the feature does not need others.
- **Your own public IPs.** A service reachable on the instance's public address, or via a load balancer that routes back inside, is "public" to `IsPublic`. Add those prefixes to the deny list.
- **Non-HTTP clients.** The same `Control` hook works for any `net.Dialer` (SMTP, database drivers that accept a dialer); clients that dial on their own are outside the guard.
- **Cloud metadata hardening** (IMDSv2 session tokens with hop limit 1, GCP's `Metadata-Flavor` header) is a valuable second layer, not a replacement.
- **Network egress policy** (security groups, Kubernetes NetworkPolicy, a dedicated egress proxy) is the layer that also covers code you did not write.
- **Open redirects on your own domain** (chapter 26) are a common SSRF stepping stone for allowlist-based fetchers.

## 6. Verification

```bash
go test -v ./Security/27_ssrf-guard/
```

| Test | Shows |
|---|---|
| `TestPlainClientReachesLoopback` | The default client reads the loopback "internal" service |
| `TestGuardRefusesLoopback` | `127.0.0.1`, `localhost`, `0.0.0.0` URLs fail with `ErrBlocked` at dial time |
| `TestGuardAllowsPermittedAddress` | Positive control: the same server is reachable when the policy allows it |
| `TestRedirectToInternalIsRechecked` | Plain client follows a redirect into the internal server; the guard refuses the second hop |
| `TestDNSRebinding` | Check-then-fetch is bypassed by a TTL-0 resolver; the dial-time guard is not |
| `TestIsPublic` | 23 addresses: metadata (v4, v6, Alibaba), mapped, NAT64, 6to4, IPv4-compatible, `172.16.0.0/12` upper boundary |
| `TestNaiveBlocklistMissesAlternativeSpellings` | String blocklist misses 12 spellings; Go's parsers reject `inet_aton` forms |
| `TestGuardTransportIgnoresProxyEnvironment` | Guarded transport has no `Proxy`; `DefaultTransport` does |
| `TestGuardRefusesNonHTTPSchemes` | `file:`, `gopher:`, `ftp:` refused before any dial |
| `ExampleIsPublic` | Mapped private, metadata v4 and v6 |

## 7. Checklist

- [ ] Every outbound fetch of a user-influenced URL uses a client with a dial-time address check.
- [ ] The check unmaps IPv4-mapped addresses and denies loopback, private, link-local, unspecified, multicast, CGNAT, NAT64/6to4/Teredo and reserved ranges.
- [ ] The transport has `Proxy: nil` (or the proxy enforces the same policy).
- [ ] Redirects are capped and re-checked; schemes are limited to `http`/`https`.
- [ ] Response size and total time are bounded.
- [ ] Network-level egress controls exist independently of application code.

## References

- Go documentation — [`net.Dialer.Control`](https://pkg.go.dev/net#Dialer), [`netip.Addr`](https://pkg.go.dev/net/netip#Addr), [`http.Transport.Proxy`](https://pkg.go.dev/net/http#Transport)
- OWASP — [Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- IANA — [IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) Special-Purpose Address Registries
- AWS — [Instance metadata service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html) (`169.254.169.254`, `fd00:ec2::254`, IMDSv2)
- Orange Tsai — [A New Era of SSRF](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) (Black Hat USA 2017)
