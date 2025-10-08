# 24. CSRF Protection

> **Abstract.** CSRF exists because browsers attach cookies to requests that another site triggers. For two decades the answer was a secret token in every form, because the server had no reliable way to ask *who* initiated a request. Browsers now say so: every major browser has sent `Sec-Fetch-Site` since 2023. Go 1.25's `http.CrossOriginProtection` is built on that header, falling back to an `Origin`-versus-`Host` comparison for older browsers, and it needs no tokens, no session state and no template changes. Its boundaries are explicit and worth memorising: safe methods (`GET`, `HEAD`, `OPTIONS`) are never checked, requests without either header pass, `same-site` is rejected (sibling subdomains are not trusted), and the bypass-pattern feature had an over-broad matching bug fixed in Go 1.25.1 (CVE-2025-47910).

| | |
|---|---|
| Weaknesses | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) Cross-Site Request Forgery (CSRF) |
| Go packages | `net/http` |
| Code | [`csrf.go`](csrf.go), [`csrf_test.go`](csrf_test.go) |

## 1. Threat model

A user is logged in to `app.example` with a cookie session. While logged in they visit `evil.example`, which submits a form, issues a `fetch` with `credentials: "include"`, or loads an image pointing at `app.example`. The attacker cannot read the response (the same-origin policy prevents that) but does not need to: the request itself transfers money, changes an email address, or logs the user out. A second attacker position is a sibling origin on the same site (`blog.app.example`, a user-content subdomain, a taken-over DNS record) which is *same-site* and so receives `SameSite` cookies.

## 2. What the standard library does

`http.CrossOriginProtection` (Go 1.25) exposes exactly this API:

| Member | Behaviour |
|---|---|
| `NewCrossOriginProtection()` | The zero value is also valid: no trusted origins, no bypasses |
| `Check(*Request) error` | Decision only; never calls the deny handler |
| `Handler(h) Handler` | Runs `Check`; on failure calls the deny handler, default `403 Forbidden` |
| `AddTrustedOrigin(origin) error` | Exact match on the `Origin` header; must be `scheme://host[:port]` with no path, query or fragment |
| `AddInsecureBypassPattern(pattern)` | `ServeMux` pattern syntax; matching requests skip the check. Since 1.25.1 only direct matches count, not paths `ServeMux` would redirect to a pattern |
| `SetDenyHandler(h)` | Replaces the 403 response |

The decision in `Check`, in order:

| Condition | Result |
|---|---|
| Method is `GET`, `HEAD` or `OPTIONS` | allow |
| `Sec-Fetch-Site: same-origin` or `none` (typed URL, bookmark) | allow |
| `Sec-Fetch-Site` any other value (`cross-site`, `same-site`) | reject unless trusted origin or bypass pattern |
| No `Sec-Fetch-Site`, no `Origin` | allow (same-origin from an old browser, or not a browser) |
| No `Sec-Fetch-Site`, `Origin` host equals `Host` | allow (scheme is not compared: HTTP→HTTPS is not detected; HSTS mitigates) |
| Otherwise | reject unless trusted origin or bypass pattern |

`SameSite` cookies are the other browser-side control. `Lax` withholds the cookie on cross-site sub-requests and cross-site `POST`, `Strict` also on top-level navigations. Their limit is the word *site*: `blog.app.example` and `app.example` are the same site, so `SameSite` does nothing against a hostile sibling, while `CrossOriginProtection` rejects `Sec-Fetch-Site: same-site`. Chromium treats cookies without a `SameSite` attribute as `Lax` (with a short window in which top-level cross-site `POST` still carries them); not every browser does, so set the attribute explicitly (chapter 29).

## 3. Insecure pattern

```go
if o := r.Header.Get("Origin"); o != "" && !strings.HasPrefix(o, "https://app.example") {
	return 403
}
```

[`NaiveOriginCheck`](csrf.go) is accepted by review surprisingly often. `https://app.example.evil.example` passes the prefix test, and a request with `Sec-Fetch-Site: cross-site` but no `Origin` passes because the filter only knows one header. The test performs both forged transfers.

Two more patterns defeat any origin-based defence, including the standard one:

- **State change on `GET`** ([`Ledger.Routes`](csrf.go) `GET /logout`). Safe methods are exempt by design; an `<img src>` is enough.
- **Bypass patterns that are broader than intended.** On Go 1.25.0 a bypass of `POST /hooks/` also exempted `POST /hooks`, which `ServeMux` would merely redirect, while the application routed it to a different, cookie-authenticated handler.

## 4. Secure pattern

```go
cop := http.NewCrossOriginProtection()
cop.AddTrustedOrigin("https://sso.example")         // exact, validated
cop.AddInsecureBypassPattern("POST /hooks/{provider}") // signature-authenticated only
handler := cop.Handler(mux)
```

[`Protect`](csrf.go) wraps this with validation errors at start-up and a deny handler that does not echo the reason. Combine it with:

1. **No state changes on safe methods**; method-qualified `ServeMux` patterns (`"POST /transfer"`, Go 1.22) make this reviewable.
2. **`SameSite=Lax` (or `Strict`) session cookies** as a second, independent layer.
3. **Bypass patterns only for endpoints that do not use cookie authentication**, written as precisely as possible, on Go ≥ 1.25.1.
4. **HSTS** so the scheme gap in the `Origin` fallback does not matter.

Why tokens were needed and mostly are not now: a synchronizer token proves that the request came from a page the server rendered, which was the only available proxy for "same origin". It costs server state or an HMAC scheme, has to be threaded through every form and `fetch`, breaks on cached pages and multiple tabs, and can leak through URLs and logs. Fetch Metadata answers the original question directly. Tokens remain relevant only if you must defend users of browsers older than 2023 *and* cannot rely on `Origin`.

## 5. Where the protection ends

- **Non-browser clients are allowed.** A request with neither header is assumed same-origin or programmatic. That is correct for CSRF (only browsers attach ambient cookies) but means this is not authentication.
- **Same-origin XSS** produces genuine `same-origin` requests; CSRF defences assume the origin itself is not compromised (chapters 23 and 25).
- **CORS.** A permissive CORS policy is a separate decision; `CrossOriginProtection` does not read `Access-Control-*` and a trusted origin added here should match what CORS allows.
- **Login CSRF** (forcing a victim into the attacker's account) is blocked too, since the login `POST` is checked like any other; session fixation is chapter 29.
- **Proxies that rewrite `Host`** break the `Origin` fallback; make sure the `Host` seen by Go is the public one.

## 6. Verification

```bash
go test -v ./Security/24_csrf-protection/
```

| Test | Shows |
|---|---|
| `TestNaiveOriginCheckBypasses` | Prefix-matched origin and missing `Origin` both forge transfers |
| `TestCrossOriginProtection` | 14 cases: `Sec-Fetch-Site` values, `Origin` fallback (port, `null`), trusted origin exact match, bypass pattern |
| `TestSafeMethodsAreNotProtected` | Cross-site `GET /logout` succeeds through the middleware |
| `TestCheckDoesNotCallDenyHandler` | `Check` returns an error without invoking `SetDenyHandler` |
| `TestAddTrustedOriginValidates` | Origins with paths, queries, or no scheme/host are rejected |
| `TestBypassDoesNotCoverRedirectTargets` | CVE-2025-47910: `/hooks` does not inherit the `/hooks/` bypass (documents the bug when run on 1.25.0) |
| `ExampleProtect` | `same-origin` → 200, `cross-site` → 403 |

The toolchain in CI should be at least Go 1.25.1 for this chapter's guarantee; `govulncheck` reports the standard-library CVE on 1.25.0.

## 7. Checklist

- [ ] Every cookie-authenticated router is wrapped in `http.CrossOriginProtection` (or an equivalent Fetch Metadata check).
- [ ] No handler reachable by `GET`/`HEAD`/`OPTIONS` changes state.
- [ ] Trusted origins are exact and few; bypass patterns cover only non-cookie endpoints.
- [ ] Session cookies set `SameSite` explicitly.
- [ ] The Go toolchain includes the CVE-2025-47910 fix (1.25.1+).

## References

- Go documentation — [`http.CrossOriginProtection`](https://pkg.go.dev/net/http#CrossOriginProtection); proposal [golang/go#73626](https://go.dev/issue/73626); [Go 1.25 release notes](https://go.dev/doc/go1.25)
- Filippo Valsorda — [Cross-Site Request Forgery](https://words.filippo.io/csrf/) (2025), the design rationale
- [CVE-2025-47910](https://nvd.nist.gov/vuln/detail/CVE-2025-47910) — over-broad `AddInsecureBypassPattern` matching, fixed in Go 1.25.1
- W3C — [Fetch Metadata Request Headers](https://www.w3.org/TR/fetch-metadata/); [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454) The Web Origin Concept
- OWASP — [Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
