# 23. Security Response Headers

> **Abstract.** Security headers are instructions to the browser; they never fix a bug, they limit what a bug can do. Go's `net/http` sets none of them, and it actively works against one: when a handler writes a body without `Content-Type`, the server runs `http.DetectContentType` and *declares* the sniffed type, so an uploaded file that starts with `<html>` is served as `text/html` from your origin. `X-Content-Type-Options: nosniff` does not undo that, because the guess is made server-side. The headers that matter are cheap to set in one middleware: a CSP whose script nonce is fresh per request (a nonce that never changes is a published password), nosniff with an explicit type, framing controls, a referrer and permissions policy, COOP, and HSTS only where TLS is actually terminated.

| | |
|---|---|
| Weaknesses | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) Protection Mechanism Failure, [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) Improper Restriction of Rendered UI Layers or Frames, [CWE-79](https://cwe.mitre.org/data/definitions/79.html) Improper Neutralization of Input During Web Page Generation |
| Go packages | `net/http`, `crypto/rand`, `context`, `html/template`, `mime` |
| Code | [`headers.go`](headers.go), [`insecure.go`](insecure.go), [`secheaders_test.go`](secheaders_test.go) |

## 1. Threat model

A web application renders HTML and serves user-uploaded files from its own origin. The attacker can place content in a page (a stored comment that slipped past escaping, see chapter 25), upload a file, or load the application in a frame on their own site. Their goals: run script in the application's origin, trick a user into clicking through an invisible frame (clickjacking), or learn URLs and tokens through the `Referer` header.

## 2. What the standard library does

| Behaviour | Detail |
|---|---|
| Default security headers | None. `http.Error` is the exception: it sets `Content-Type: text/plain; charset=utf-8` and `X-Content-Type-Options: nosniff` |
| Missing `Content-Type` | On the first `Write`, the server sets `Content-Type` to `http.DetectContentType` of the first 512 bytes (unless `Content-Encoding` or `Transfer-Encoding` is set). `httptest.ResponseRecorder` emulates this |
| `DetectContentType` | Implements the [WHATWG MIME Sniffing](https://mimesniff.spec.whatwg.org/) algorithm: skips leading whitespace, matches `<!DOCTYPE HTML`, `<html`, `<script` and other tags case-insensitively, and image/archive magic numbers |
| `nosniff` | Purely a browser instruction; Go's own sniffing ignores it |
| `r.TLS` | Non-nil only when this process terminated TLS. Behind a proxy it is `nil` even for HTTPS users |

The polyglot detail matters: `GIF89a<html>...` sniffs as `image/gif`, so neither an allowlist of sniffed types nor the browser's own sniffing is a security boundary.

## 3. Insecure pattern

```go
func avatar(w http.ResponseWriter, r *http.Request) {
	w.Write(load(r))                        // server sniffs: text/html; charset=utf-8
}

var staticNonce = newNonce()                // once, at start-up
h.Set("Content-Security-Policy", "script-src 'nonce-"+staticNonce+"'")
h.Set("Strict-Transport-Security", "...")   // on plain HTTP too
h.Set("X-Frame-Options", "SAMEORIGIN")      // no frame-ancestors, no nosniff
```

[`ServeUploadInsecure`](insecure.go) and [`InsecureMiddleware`](insecure.go). The tests show the upload served as `text/html` by a real server (with and without `nosniff`), and the same nonce on consecutive responses: an attacker who can inject markup reads the nonce from any page and adds it to their `<script>`.

## 4. Secure pattern

[`Middleware`](headers.go) sets every header **before** calling the next handler, so they are present on `http.NotFound`, `http.Error` and any other status the handler writes.

| Header | Value | Why |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'nonce-…' 'strict-dynamic'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` | Nonce-based "strict CSP": no host allowlist to bypass; `base-uri` stops `<base>` hijacking of relative script URLs |
| `X-Content-Type-Options` | `nosniff` | Browser must honour the declared type (and blocks scripts/styles with a wrong type) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Path and query never leave the origin; use `no-referrer` if URLs carry secrets |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Features denied to the page and every frame in it |
| `Cross-Origin-Opener-Policy` | `same-origin` | Severs `window.opener` from cross-origin popups (tabnabbing, XS-Leaks) |
| `X-Frame-Options` | `DENY` | Only for browsers without CSP 2; `frame-ancestors` takes precedence where supported |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | **Only if `r.TLS != nil`** (or a trusted proxy says so); RFC 6797 §7.2 forbids it over HTTP |

The nonce comes from `crypto/rand.Text()` (Go 1.24): 128 bits in base32, whose alphabet is a subset of the base64 characters the CSP `nonce-source` grammar requires. It travels to templates through the request context ([`Nonce`](headers.go)), and `html/template` places it in the attribute with correct escaping.

For user files, [`ServeUploadSafe`](insecure.go) declares `application/octet-stream`, adds `nosniff`, forces `Content-Disposition: attachment` (built with `mime.FormatMediaType`, which quotes the filename), and adds `Content-Security-Policy: sandbox` in case a browser renders it anyway. Serving uploads from a separate, cookieless origin is stronger still.

## 5. Where headers end

- **CSP is defence in depth for XSS, not a fix.** Injection into a nonced script, into `href` with `javascript:`, or into a JSONP endpoint on your own origin still runs. Chapter 25 covers the escaping that should prevent injection in the first place.
- **`'strict-dynamic'`** propagates trust to scripts a nonced script creates. A nonced loader that builds script URLs from user input is a bypass.
- **Caches.** A cached HTML page replays its nonce. Mark nonced pages `Cache-Control: no-store` or private, or the "per-request" nonce is per-cache-entry.
- **Proxies.** Behind a TLS-terminating proxy `r.TLS` is nil; trust `X-Forwarded-Proto` only from a known proxy (the same rule as `X-Forwarded-For` in chapter 28), or let the proxy set HSTS.
- **`X-XSS-Protection`** is obsolete; the auditor it controlled was removed from browsers and could itself be abused. Omit it or send `0`.

## 6. Verification

```bash
go test -v ./Security/23_security-headers/
```

| Test | Shows |
|---|---|
| `TestDetectContentTypeSniffsHTML` | HTML detected after leading whitespace; a GIF magic prefix wins over HTML |
| `TestServeUploadInsecureIsServedAsHTML` | A real server declares `text/html` for an untyped upload |
| `TestNosniffDoesNotStopServerSideSniffing` | `nosniff` without an explicit type changes nothing on the wire |
| `TestServeUploadSafe` | Explicit type, `nosniff`, quoted attachment filename, CSP sandbox |
| `TestMiddlewareSetsHeaders` | All headers present on a 404; CSP has no `unsafe-inline` |
| `TestNoncePerRequestAndInBody` | Nonce differs per response and matches the `<script nonce>` in the body |
| `TestInsecureMiddlewareReusesNonce` | Start-up nonce repeats; HSTS on HTTP; no nosniff |
| `TestHSTSOnlyOverTLS` | HSTS absent on `httptest.NewServer`, present on `NewTLSServer` |
| `ExampleCSP` | The exact policy string |

## 7. Checklist

- [ ] Every response that carries a body has an explicit `Content-Type`; user files are never served untyped.
- [ ] Headers are set in one middleware, before the handler, and appear on error responses.
- [ ] CSP nonce is generated per response from `crypto/rand` and never cached.
- [ ] CSP has `object-src 'none'`, `base-uri 'none'`, `frame-ancestors`, and no `unsafe-inline`/`unsafe-eval`.
- [ ] HSTS is emitted only where TLS terminates, with a deliberate `max-age` and `preload` decision.
- [ ] Uploads are served as attachments, ideally from a separate origin.

## References

- W3C — [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) (`nonce-source`, `strict-dynamic`, `frame-ancestors`)
- Google — [Strict CSP](https://csp.withgoogle.com/docs/strict-csp.html); Weichselbaum et al., [CSP Is Dead, Long Live CSP!](https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/) (CCS 2016)
- [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) HTTP Strict Transport Security; WHATWG [MIME Sniffing](https://mimesniff.spec.whatwg.org/)
- Go documentation — [`http.DetectContentType`](https://pkg.go.dev/net/http#DetectContentType), [`http.ResponseWriter`](https://pkg.go.dev/net/http#ResponseWriter), [`rand.Text`](https://pkg.go.dev/crypto/rand#Text)
- OWASP — [HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
