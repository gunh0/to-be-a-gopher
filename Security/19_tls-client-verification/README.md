# 19. TLS Client Verification

> **Abstract.** TLS without server authentication is encryption to whoever answers. In Go, turning authentication off is one field, `InsecureSkipVerify: true`, and it is the most common TLS weakness found in Go code: added to reach a self-signed test server or an internal CA, then shipped. The secure alternatives are just as short — a `RootCAs` pool holding the internal CA, `httptest`'s own client in tests — and Go's verifier already checks the chain, validity, key usage and the hostname against SANs. Custom verification is where it goes wrong a second time: a hand-written callback that validates the chain but forgets the hostname accepts every certificate the CA ever issued. Pinning, when used, belongs in `VerifyConnection`, after normal verification, with a backup pin.

| | |
|---|---|
| Weaknesses | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) Improper Certificate Validation, [CWE-297](https://cwe.mitre.org/data/definitions/297.html) Improper Validation of Certificate with Host Mismatch |
| Go packages | `crypto/tls`, `crypto/x509`, `net/http`, `net/http/httptest` |
| Code | [`tlsclient.go`](tlsclient.go), [`tlsclient_test.go`](tlsclient_test.go), [`pki_test.go`](pki_test.go) |

## 1. Threat model

A Go service calls another service over HTTPS and sends credentials: a bearer token, an API key, a database password. The attacker can intercept the connection (compromised network segment, ARP/DNS spoofing, a malicious sidecar, a misrouted load balancer) and present a certificate: self-signed, or a genuine certificate from the same internal CA issued for a different service. They want the credentials and the data.

## 2. What Go's verifier does

With `InsecureSkipVerify: false` (the default), every handshake checks:

| Check | Detail |
|---|---|
| Chain | To `Config.RootCAs`, or system roots when nil; intermediates from the server's chain |
| Validity | `NotBefore`/`NotAfter` against the current time |
| Key usage | Leaf must allow `ExtKeyUsageServerAuth` (or have no EKU) |
| Hostname | `ServerName` (default: host from the URL) against DNS and IP SANs. CN is ignored since Go 1.15. Wildcards cover exactly one left-most label; matching is case-insensitive |
| Algorithms | SHA-1 signed certificates rejected (since Go 1.18; no override since 1.24) |

Errors are typed: `x509.UnknownAuthorityError`, `x509.HostnameError`, `x509.CertificateInvalidError`, wrapped in `*tls.CertificateVerificationError` (Go 1.20), so `errors.As` works through `http.Client`'s `*url.Error`.

Two hooks run after normal verification:

| Hook | Receives | On resumed sessions |
|---|---|---|
| `VerifyPeerCertificate` | Raw certs, verified chains | **Not called** |
| `VerifyConnection` (Go 1.15) | Full `ConnectionState` | Called |

## 3. Insecure pattern

[`NewClientUnsafe`](tlsclient.go):

```go
TLSClientConfig: &tls.Config{InsecureSkipVerify: true}
```

`TestInsecureSkipVerifyHandsTokenToImpostor` runs an impostor with a self-signed certificate; the client completes the handshake and sends its bearer token. How it gets in:

- **Tests**: a test against `httptest.NewTLSServer` fails verification, so someone adds `InsecureSkipVerify`. `srv.Client()` already trusts the test certificate (`TestTestServersNeedNoSkipVerify`).
- **Internal CAs**: the system pool does not contain the company CA, and loading it into `RootCAs` looks like work.
- **Config flags**: `--insecure` / `TLS_SKIP_VERIFY=true` exists for debugging and ends up set in production.

[`NewClientNoHostnameUnsafe`](tlsclient.go) is the "I'll verify it myself" version: `InsecureSkipVerify: true` plus a `VerifyPeerCertificate` that calls `leaf.Verify` with the right roots but no `DNSName`. `TestHostnameIsVerified` connects to `metrics.internal.test`'s genuine certificate while expecting `api.internal.test`; the standard client returns `x509.HostnameError`, the custom one accepts. Every certificate the internal CA issued is now valid for every service.

## 4. Secure pattern

[`NewClient`](tlsclient.go):

```go
roots := x509.NewCertPool()
roots.AppendCertsFromPEM(internalCAPEM)
cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
```

1. **Trust the right roots.** For internal services, a pool with only the internal CA. Adding it to the system pool (`x509.SystemCertPool()` + `AppendCertsFromPEM`) also lets every public CA vouch for internal names.
2. **Let Go check the hostname.** Leave `ServerName` empty unless connecting by IP to a name-based certificate; never verify chains manually without `VerifyOptions.DNSName`.
3. **Pin in `VerifyConnection`, not instead of verification.** [`PinVerifier`](tlsclient.go) runs after normal verification, accepts if any certificate in a verified chain has a pinned SPKI hash (`base64(SHA-256(RawSubjectPublicKeyInfo))`, [`SPKIPin`](tlsclient.go)), requires at least two pins (current key plus an offline backup, or the issuing CA's key), and runs on resumed sessions too (`TestVerifyConnectionRunsOnResumption`). A certificate mis-issued by the trusted CA for the right name fails the pin (`TestPinning`).
4. **Tests use real verification**: `srv.Client()`, or an in-process CA as in [`pki_test.go`](pki_test.go).
5. **Detect regressions**: gosec G402 flags `InsecureSkipVerify: true`; review any `VerifyPeerCertificate` that coexists with it.

Pin only in clients you ship and can update. Browsers abandoned HPKP because a lost key or a wrong pin locks out every user until the pin expires.

## 5. Where the guarantee ends

- **Revocation.** Go does not check CRLs or OCSP during verification. Rely on short-lived certificates, or check stapled OCSP (`ConnectionState.OCSPResponse`) in `VerifyConnection`.
- **The CA itself.** A compromised internal CA can issue anything; pinning or name constraints on the CA certificate limit the blast radius.
- **`ServerName` from untrusted input.** If the hostname comes from user data (webhooks, SSRF-prone fetchers), verification proves you reached *that* host, not that the host is safe to reach.
- **Client authentication** (mutual TLS) is chapter 20; **server configuration** is chapter 18.

## 6. Verification

```bash
go test -race -v ./Security/19_tls-client-verification/
```

| Test | Shows |
|---|---|
| `TestInsecureSkipVerifyHandsTokenToImpostor` | `InsecureSkipVerify` sends the bearer token to a self-signed impostor |
| `TestVerifyingClientRejectsImpostor` | `x509.UnknownAuthorityError`, and the request never reaches the server |
| `TestVerifyingClientAcceptsInternalCA` | A private CA in `RootCAs` is all an internal client needs |
| `TestHostnameIsVerified` | Right CA, wrong name: rejected by Go, accepted by the hand-rolled verifier |
| `TestHostnameMatchingRules` | Single-label wildcards, case-insensitivity, CN ignored without SANs |
| `TestPinning` | Primary pin accepted, mis-issued certificate rejected, rotation to the backup key accepted |
| `TestPinningRequiresBackup` | A single pin is refused at construction |
| `TestVerifyConnectionRunsOnResumption` | On a resumed session `VerifyPeerCertificate` is skipped, `VerifyConnection` is not |
| `TestTestServersNeedNoSkipVerify` | `httptest`'s client already trusts its server |
| `ExampleNewClient` | A pinned client against a private root |

## 7. Checklist

- [ ] No `InsecureSkipVerify: true` outside code that sets its own complete verification, and none behind a runtime flag.
- [ ] Internal clients trust only the internal CA.
- [ ] No manual `x509.Verify` without `DNSName`; no hostname checks on CN.
- [ ] Pinning, if any, is in `VerifyConnection`, with ≥ 2 pins and a rotation plan.
- [ ] Tests use `srv.Client()` or an in-process CA, not `InsecureSkipVerify`.
- [ ] gosec (G402) or an equivalent check runs in CI.

## References

- [`crypto/tls.Config`](https://pkg.go.dev/crypto/tls#Config) (`InsecureSkipVerify`, `VerifyPeerCertificate`, `VerifyConnection`), [`x509.Certificate.Verify`](https://pkg.go.dev/crypto/x509#Certificate.Verify)
- [Go 1.15 release notes](https://go.dev/doc/go1.15) (CommonName no longer used as a host name)
- [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) / [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525) Service Identity in TLS
- [RFC 7469](https://www.rfc-editor.org/rfc/rfc7469) Public Key Pinning Extension for HTTP (SPKI pin format)
- M. Georgiev et al. — *The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software* (ACM CCS 2012)
- [gosec](https://github.com/securego/gosec) rule G402
