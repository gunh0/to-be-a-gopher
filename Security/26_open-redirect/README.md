# 26. Open Redirects

> **Abstract.** An open redirect turns your domain into a trusted-looking hop to anywhere: phishing links that start with your login page, OAuth flows that leak codes, SSRF filters that follow the redirect. Validating `?next=` looks trivial and is not, because two URL parsers are involved. Go's `url.Parse` follows RFC 3986; the browser follows the WHATWG URL Standard, which reads `\` as `/`, strips tabs and newlines, and treats any run of leading slashes as the start of a host. So `/\evil.example` is a hostless path to Go and `//evil.example` to Chrome. `http.Redirect` validates nothing. The robust rule is narrow: accept only a path that starts with exactly one `/`, contains no backslash or control character, and re-serialises to the same shape — or an absolute `https` URL whose parsed host is in an exact allowlist.

| | |
|---|---|
| Weaknesses | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) URL Redirection to Untrusted Site ('Open Redirect') |
| Go packages | `net/http`, `net/url` |
| Code | [`redirect.go`](redirect.go), [`redirect_test.go`](redirect_test.go) |

## 1. Threat model

A login page accepts `?next=` so users return where they were. The attacker crafts `https://app.example/login?next=<target>` and sends it to a victim; the visible domain is the real one. After login the browser follows the `Location` header. The attacker's goal is to land the victim on a look-alike page that asks for the password again, or to collect an OAuth code or token appended to the redirect. They control the whole value of `next`, including encoding and control characters.

## 2. What the standard library does

`http.Redirect(w, r, url, code)` only normalises:

| Input to `http.Redirect` | `Location` sent | Why |
|---|---|---|
| `//evil.example` | `//evil.example` | `url.Parse` finds a host, so the value is left alone |
| `/\evil.example` | `/\evil.example` | No scheme or host per RFC 3986; `path.Clean` keeps `\` |
| `\\evil.example` | `/\\evil.example` | Relative path, joined to the request directory |
| `///evil.example` | `/evil.example` | `path.Clean` collapses slashes (accidentally safe) |
| `https:evil.example` | `https:evil.example` | Has a scheme; passed through |
| `/\t/evil.example` | unchanged | `url.Parse` fails on the control character; the raw string is used |
| `/x\r\nSet-Cookie: a` | `/x  Set-Cookie: a` on the wire | `net/http` writes CR/LF in header values as spaces: no header injection |

And `url.Parse` is lenient in ways that matter to a validator: `/\evil.example`, `\\evil.example` and ` //evil.example` are all valid relative references with an empty `Host`. It is strict in others: `https://evil.example\@good.example` is an error (`invalid userinfo`), while a browser reads it as host `evil.example`.

What the browser does with the `Location` value (WHATWG URL Standard, for `http`/`https`):

- removes tab, CR and LF anywhere, and trims leading/trailing C0 controls and spaces;
- treats `\` exactly like `/`;
- starts an authority at two or more leading slashes, skipping any extra ones;
- for `scheme:rest` with a *different* special scheme than the page (`http:evil.example` on an `https` page), treats `rest` as the host even without `//`; with the *same* scheme it is a relative path.

## 3. Insecure pattern

```go
http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusSeeOther)  // no check

strings.HasPrefix(next, "/")                                        // "//evil.example"

u, _ := url.Parse(next); u.Scheme == "" && u.Host == ""             // "/\evil.example"
```

[`LoginRedirectInsecure`](redirect.go), [`IsLocalNaive`](redirect.go), [`IsLocalParsed`](redirect.go). The tests resolve each `Location` with a small model of the WHATWG rules (`browserHost` in the test file) and show where a browser lands. `IsLocalParsed` is the instructive one: it is correct according to RFC 3986 and wrong according to every browser.

## 4. Secure pattern

[`SafeLocalPath`](redirect.go):

1. first byte is `/`, second byte is neither `/` nor `\`;
2. no `\` anywhere and no byte below `0x20` or equal to `0x7f`;
3. `url.Parse` succeeds with no scheme, host, userinfo or opaque part;
4. the re-serialised `u.String()` still starts with exactly one `/`, and *that* string is what is sent.

[`SafeRedirect`](redirect.go) additionally accepts absolute URLs for cross-origin returns (SSO, a separate accounts domain) when the scheme is `https`, there is no userinfo, and `u.Host` equals an allowlisted `host[:port]` case-insensitively. Never compare with `HasPrefix`/`HasSuffix`/`Contains` on the raw string.

[`LoginRedirect`](redirect.go) falls back to `/` instead of erroring. Even better is not to accept a URL at all: store the return path server-side (in the session, chapter 29) or pass an opaque key that maps to a fixed list of destinations.

## 5. Where the check ends

- **Encoded slashes** (`/%2F%2Fevil.example`) are a local path to the browser and are accepted. They become dangerous only if some later stage decodes again and redirects with the result; validate at the last decoding step.
- **`javascript:` in `Location`** is not executed by browsers, but the same `next` value is often rendered in an `<a href>` or a meta refresh, where it is; chapter 25's `#ZgotmplZ` filter covers the link, not the redirect.
- **Redirect chains**: a local path to another endpoint that itself redirects openly is still an open redirect. Audit every handler that calls `http.Redirect` with request data.
- **Server-side clients follow redirects too**: an allowed URL on your domain that redirects to an internal address bypasses a naive SSRF filter (chapter 27).
- **OAuth `redirect_uri`** must be compared exactly against a registered value, not with these looser rules.

## 6. Verification

```bash
go test -v ./Security/26_open-redirect/
```

| Test | Shows |
|---|---|
| `TestInsecureRedirectGoesOffsite` | 12 `next` values through `http.Redirect`, resolved as a browser would; which leave `app.example` |
| `TestValidators` | Verdicts of the prefix check, the `url.Parse` check and `SafeLocalPath` for the same 12 values |
| `TestValidatorsVersusBrowser` | Both naive validators approve off-site targets; `SafeLocalPath` approves none |
| `TestSafeRedirectAllowlist` | Downgrade, suffix, userinfo, backslash-userinfo, port and control-character tricks rejected |
| `TestLoginRedirectFallsBackToRoot` | Unsafe values redirect to `/` |
| `TestHTTPRedirectDoesNotAllowHeaderInjection` | Real server: CR/LF become spaces, no extra `Set-Cookie` |
| `ExampleSafeLocalPath` | Three canonical inputs |

## 7. Checklist

- [ ] Every `http.Redirect` whose target derives from the request goes through one validator.
- [ ] The validator rejects `//`, `/\`, any `\`, and control characters before parsing.
- [ ] Absolute targets are matched on parsed `Host` against an exact allowlist, `https` only, no userinfo.
- [ ] The value sent is the value validated (re-serialised), not the raw input.
- [ ] Where possible, store return paths server-side instead of round-tripping them through the URL.

## References

- WHATWG — [URL Standard](https://url.spec.whatwg.org/) (special schemes, backslash handling, "special authority ignore slashes" state); [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
- Go documentation — [`http.Redirect`](https://pkg.go.dev/net/http#Redirect), [`url.Parse`](https://pkg.go.dev/net/url#Parse)
- OWASP — [Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- Orange Tsai — [A New Era of SSRF: Exploiting URL Parsers in Trending Programming Languages](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) (Black Hat USA 2017), on parser differentials
