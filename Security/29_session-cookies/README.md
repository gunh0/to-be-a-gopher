# 29. Session Cookies

> **Abstract.** A session cookie is a bearer credential: whoever presents the value is the user. Its security is the sum of small decisions, each of which Go leaves to the caller: `http.Cookie` defaults to no `Secure`, no `HttpOnly` and no `SameSite`, and `Cookie.Valid` checks syntax (plus, since Go 1.23, that `Partitioned` implies `Secure`) but not the `__Host-` prefix rules or `SameSite=None` without `Secure`. The server side matters as much as the attributes: the ID must be unguessable (128 bits from `crypto/rand`, `rand.Text()` in Go 1.24), must **change at login** or a planted pre-login ID becomes an authenticated one (session fixation), must expire by **server-side** idle and absolute timeouts, and logout must delete the server record — clearing the cookie only clears the honest user's copy.

| | |
|---|---|
| Weaknesses | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) Sensitive Cookie in HTTPS Session Without 'Secure' Attribute, [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) Sensitive Cookie Without 'HttpOnly' Flag, [CWE-384](https://cwe.mitre.org/data/definitions/384.html) Session Fixation |
| Go packages | `net/http`, `net/http/cookiejar`, `crypto/rand` |
| Code | [`store.go`](store.go), [`handlers.go`](handlers.go), [`session_test.go`](session_test.go) |

## 1. Threat model

Users authenticate once and are then identified by a cookie. Attackers may: observe plain-HTTP traffic on a shared network; run script in the page through an XSS bug; control a sibling subdomain (`*.app.example`) or a URL the victim follows, and use it to plant a cookie; obtain a copy of a cookie from logs, a shared computer or malware; or guess IDs if they are predictable. Their goal is to act as the victim for as long as possible.

## 2. What the standard library does

| Attribute | `http.Cookie` field | Default | Effect when set |
|---|---|---|---|
| `Secure` | `Secure bool` | off | Sent only over HTTPS; `net/http/cookiejar` enforces this too |
| `HttpOnly` | `HttpOnly bool` | off | Invisible to `document.cookie`; XSS cannot read (but can still *use*) the session |
| `SameSite` | `SameSite` (`Lax`, `Strict`, `None`) | unset (attribute omitted) | `Lax`: not sent on cross-site sub-requests or `POST`; `None` requires `Secure` in browsers |
| `Path`, `Domain` | strings | request path / host-only | `Domain` *widens* scope to subdomains; omit it |
| `Expires`, `MaxAge` | | none (browser-session cookie) | Client-side hint only; `MaxAge < 0` deletes |
| `Partitioned` | `Partitioned bool` (Go 1.23) | off | CHIPS: third-party cookie keyed by top-level site; `Valid` rejects it without `Secure` |

Name prefixes are enforced by browsers, not by Go: a `__Secure-` cookie must be `Secure`; a `__Host-` cookie must be `Secure`, have `Path=/`, and have **no** `Domain`. That makes `__Host-` cookies impossible to set from a sibling subdomain or over HTTP, closing the main route for cookie planting. `http.Cookie.Valid` checks name/value/path/domain syntax, `Expires` range and the `Partitioned`/`Secure` pairing; [`CheckCookie`](handlers.go) adds the prefix and `SameSite=None` rules.

## 3. Insecure pattern

[`NewInsecureApp`](handlers.go) collects the classic mistakes:

```go
id := strconv.FormatInt(counter.Add(1), 10)                  // guessable
http.SetCookie(w, &http.Cookie{Name: "session", Value: id,   // no Secure/HttpOnly/SameSite
	Path: "/", Expires: time.Now().Add(8 * time.Hour)})       // expiry only on the client
// login: mark the existing session as authenticated          // fixation
// logout: http.SetCookie(w, &http.Cookie{..., MaxAge: -1})   // server record lives on
```

Session fixation, step by step (`TestSessionFixation`): the attacker obtains a valid anonymous session ID, plants it in the victim's browser, the victim logs in, and the attacker's copy of the same ID now reads `alice` from `/me`. Logout (`TestLogoutInvalidatesServerSide`): the victim logs out, the browser drops the cookie, and a previously stolen copy still works.

## 4. Secure pattern

```go
http.SetCookie(w, &http.Cookie{
	Name: "__Host-session", Value: rand.Text(), Path: "/",
	Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
})
```

| Control | Implementation |
|---|---|
| Unguessable ID | [`NewID`](store.go): `crypto/rand.Text()`, 128 bits, 26 base32 characters (OWASP minimum: 64 bits of entropy; chapter 08) |
| Cookie hardening | [`Cookie`](handlers.go): `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Lax`, no `Domain`, no persistence |
| No fixation | [`Store.Login`](store.go) issues a new ID and deletes the old one at every privilege change |
| Server-side lifetime | [`Store.Get`](store.go) enforces `Idle` (time since last request) and `Absolute` (time since login) from server time |
| Real logout | `Store.Destroy` on logout; [`Store.DestroyUser`](store.go) for "log out everywhere" and password changes |

`SameSite=Lax` rather than `Strict` keeps users logged in when they follow a link from another site; state-changing requests are protected by `Lax` against cross-site `POST` and, independently, by `http.CrossOriginProtection` (chapter 24).

## 5. Where cookie hardening ends

- **XSS still rides the session.** `HttpOnly` stops theft, not use: injected script can send authenticated requests from the victim's browser. Chapters 23 and 25.
- **`SameSite` is about sites, not origins.** A compromised `blog.app.example` is same-site; the `__Host-` prefix and origin-based CSRF checks cover what `SameSite` does not.
- **Stolen cookies.** Nothing in the cookie binds it to a device. Short idle timeouts, re-authentication for sensitive actions, and anomaly detection limit the damage; Device Bound Session Credentials are an emerging browser mechanism, not something to rely on yet.
- **Stateless sessions** (signed or encrypted cookies, JWTs) cannot be revoked by deleting a record; logout and timeouts then need a deny-list or short lifetimes. Chapter 30.
- **Store growth.** Anonymous sessions created per visitor are a memory target; bound them like the limiter table in chapter 28, or create sessions only when needed.
- **ID comparison.** Looking the ID up in a map is fine; if IDs are ever compared to a stored value directly, use `crypto/subtle.ConstantTimeCompare`.

## 6. Verification

```bash
go test -v ./Security/29_session-cookies/
```

| Test | Shows |
|---|---|
| `TestSessionFixation` | Over TLS with real cookie jars: the planted ID becomes `alice` in the insecure app; rotated and dead in the secure one |
| `TestLogoutInvalidatesServerSide` | A cookie copied before logout still authenticates (insecure) / gets 401 (secure) |
| `TestCookieAttributes` | Parsed `Set-Cookie` (`http.ParseSetCookie`, Go 1.23): `__Host-`, `Secure`, `HttpOnly`, `Lax`, no persistence; insecure cookie has none |
| `TestSecureCookieNotSentOverHTTP` | `cookiejar` withholds a `Secure` cookie from `http://` |
| `TestCheckCookie` | Prefix rules, `SameSite=None` and `Partitioned` without `Secure`, invalid name/value |
| `TestTimeoutsAreServerSide` | Activity every 10 min survives exactly the 8 h absolute limit; 15 min idle expires |
| `TestDestroyUser` | All of one user's sessions removed, others kept |
| `TestSessionIDs` | 10,000 unique 26-character base32 IDs; insecure IDs are `1`, `2` |
| `ExampleCookie` | The exact `Set-Cookie` value |

## 7. Checklist

- [ ] Session IDs come from `crypto/rand` with ≥ 128 bits; never from `math/rand`, counters, timestamps or user data.
- [ ] Session cookie: `__Host-` prefix, `Secure`, `HttpOnly`, explicit `SameSite`, no `Domain`.
- [ ] The ID is replaced at login and at every privilege change.
- [ ] Idle and absolute timeouts are enforced server-side.
- [ ] Logout deletes the server-side session; password change deletes all of the user's sessions.
- [ ] No session ID in URLs, logs or error messages.

## References

- [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265) HTTP State Management; IETF draft [RFC 6265bis](https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/) (cookie prefixes, `SameSite`)
- Go documentation — [`http.Cookie`](https://pkg.go.dev/net/http#Cookie), [`http.ParseSetCookie`](https://pkg.go.dev/net/http#ParseSetCookie), [`net/http/cookiejar`](https://pkg.go.dev/net/http/cookiejar), [`rand.Text`](https://pkg.go.dev/crypto/rand#Text)
- OWASP — [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- MDN — [Cookies Having Independent Partitioned State (CHIPS)](https://developer.mozilla.org/en-US/docs/Web/Privacy/Privacy_sandbox/Partitioned_cookies)
