# 11. HMAC-Signed Tokens

> **Abstract.** A stateless token — a password-reset link, an e-mail confirmation code, a signed cookie value — is a claim the server wrote and the client carries back. HMAC-SHA-256 makes it unforgeable, but only for **the exact bytes that were MACed**, and most token bugs live in the gap between those bytes and what the verifier believes they mean. Base64 JSON without a MAC is an editable form; a MAC over `user + expiry` without a separator lets `("bob1", 1760000000)` and `("bob", 11760000000)` share one tag; one key for every purpose lets a session token open a password reset. The design in this chapter closes each gap: a length-prefixed binary payload, per-purpose keys from HKDF, key IDs for rotation, a strict canonical encoding, and a verifier that checks the MAC in constant time before it reads a single field — expiry included.

| | |
|---|---|
| Weaknesses | [CWE-345](https://cwe.mitre.org/data/definitions/345.html) Insufficient Verification of Data Authenticity, [CWE-347](https://cwe.mitre.org/data/definitions/347.html) Improper Verification of Cryptographic Signature, [CWE-613](https://cwe.mitre.org/data/definitions/613.html) Insufficient Session Expiration |
| Go packages | `crypto/hmac`, `crypto/sha256`, `crypto/hkdf`, `encoding/base64`, `encoding/binary` |
| Code | [`token.go`](token.go), [`unsafe.go`](unsafe.go), [`hmactoken_test.go`](hmactoken_test.go) |

## 1. Threat model

The attacker is a registered user (or anyone who can obtain *some* valid token) and can read and modify every token they hold. They want a token for another subject, a token with elevated claims, a token that outlives its expiry, or a token minted for one purpose (session, newsletter unsubscribe, e-mail verification) accepted for another (password reset). They cannot read server memory or the signing keys.

## 2. What the standard library provides

| Building block | Notes |
|---|---|
| `hmac.New(sha256.New, key)` | PRF/MAC; output 32 bytes (chapter 10 for why not `SHA-256(key‖msg)`) |
| `hmac.Equal` | Constant-time comparison of MACs (chapter 09) |
| `crypto/hkdf.Key` (Go 1.24) | `hkdf.Key(sha256.New, secret, salt, info, n)` — derive independent per-purpose keys from one master secret; previously only in `x/crypto` |
| `base64.RawURLEncoding` | URL-safe, unpadded; `.Strict()` rejects non-zero trailing bits (RFC 4648 §3.5) so each byte string has one spelling |
| `binary.AppendUvarint`, `binary.BigEndian.AppendUint64` | Length-prefixed, fixed-width encodings without a parser |
| `crypto/rand.Text`, `rand.Read` | Master secrets (chapter 08) |

There is no token format in the standard library. JWT, PASETO and similar formats live outside it; their verification pitfalls are covered in chapter 30.

## 3. Insecure pattern

**Unsigned claims.** [`EncodeUnsigned`](unsafe.go) is `base64(json)`. The client decodes it, sets `"admin": true` and a ten-year expiry, and re-encodes. `DecodeUnsigned` accepts it: encoding is not integrity.

**MAC over an ambiguous concatenation.** [`SignAmbiguous`](unsafe.go) issues `user|exp|HMAC(key, user+exp)`. The MAC and its comparison are correct; the *input* is not uniquely decodable:

```text
registered as "bob1", exp 1760000000  →  MAC input "bob11760000000"
forged: "bob|11760000000|<same tag>"  →  MAC input "bob11760000000"  ✓  user=bob, expires in 2342
```

The same flaw appears with `fmt.Sprintf("%s%d", ...)`, with delimiters that may occur inside fields (`"a|b" + "|" + "c"`), and with signing a re-serialised struct instead of the received bytes.

**Shared keys across purposes.** If one key signs sessions, unsubscribe links and password resets with the same layout, any of them is a valid instance of the others.

## 4. Secure pattern

[`Signer`](token.go) issues

```text
v1.<kid>.<b64(uvarint(len(sub)) ‖ sub ‖ int64be(exp))>.<b64(HMAC-SHA-256(k_purpose, "v1.<kid>.<b64 payload>"))>
```

1. **Unambiguous payload.** The subject is length-prefixed and the expiry fixed-width, so distinct `(subject, expiry)` pairs never share bytes. The MAC covers the version and key ID too, so neither can be swapped.
2. **MAC first, then parse.** `Verify` splits on the last `.`, selects the key by ID, decodes the tag, and compares `hmac.Equal(tag, HMAC(k, signed))` over the **received** string. Only then is the payload decoded and the expiry checked. A forged far-future expiry is `ErrInvalid`, never `ErrExpired` or valid.
3. **One key per purpose.** `NewSigner(purpose, ...)` derives `hkdf.Key(sha256.New, master, nil, "hmactoken/v1/"+purpose, 32)`. A session token does not verify as a reset token even with the same master secret.
4. **Rotation by key ID.** `NewSigner(p, newKey, oldKey)` issues with `newKey` and accepts both; dropping `oldKey` after one maximum TTL invalidates everything it signed.
5. **Canonical encoding.** All segments use `RawURLEncoding.Strict()`; a tag with non-zero spare bits, padding or whitespace is rejected, so deny-lists and caches keyed by token string cannot be bypassed with an alternate spelling.
6. **One error for all failures.** Callers see `ErrInvalid` (or `ErrExpired` for an authentic, stale token) and should map both to the same client response (chapter 07).

```go
s, _ := NewSigner("password-reset", Key{ID: "k1", Secret: master})
tok, _ := s.Issue("alice@example.com", 15*time.Minute)
claims, err := s.Verify(tok)
```

## 5. Where the guarantee ends

- **Stateless means unrevocable.** A valid token stays valid until expiry. Keep TTLs short (minutes for password reset), and make one-time tokens single-use by binding them to state that changes on use — e.g. include a hash of the current password hash or a per-user counter in the MAC input, or record the token's MAC in a used-token store (keyed by the MAC bytes, not the string).
- **HMAC tokens are readable.** Anyone holding the token can decode the payload. Put identifiers in it, not secrets or personal data; use an AEAD (chapter 13) if the contents must be confidential.
- **Tokens in URLs leak** through `Referer`, proxy logs and browser history. Send `Referrer-Policy: no-referrer` on pages that receive them (chapter 23) and exchange the link token for a session promptly.
- **Clock skew.** Expiry compares against the verifier's clock; multi-host deployments need synchronised time. The injected `Clock` keeps tests deterministic.
- **Key management is the real secret.** Master secrets come from `crypto/rand` (≥ 32 bytes), live outside the repository, and rotate. A leaked key forges every token until it is removed from the signer.
- **Cookies** add their own flags and scoping rules (chapter 29); signed JWTs add algorithm confusion (chapter 30).

## 6. Verification

```bash
go test -race -v ./Security/11_hmac-tokens/
```

| Test | Shows |
|---|---|
| `TestUnsignedTokenIsForgeable` | Base64 JSON edited to `admin: true` and a ten-year expiry is accepted |
| `TestAmbiguousMACForgery` | A token issued to `bob1` becomes a valid token for `bob`, still valid 100 years later |
| `TestSignerRoundTrip` | Issue/verify, exact expiry, URL-safe output |
| `TestSignerRejectsTampering` | 13 manipulations — payload/tag swap, unknown kid, version, truncation, padding, whitespace, foreign formats — all `ErrInvalid` |
| `TestSignerExpiryAfterMAC` | Valid at 14 min, `ErrExpired` at 15 min; forged far-future payload is `ErrInvalid` |
| `TestPurposeSeparation` | Same master secret, different purpose: rejected |
| `TestKeyRotation` | Old tokens verify while the old key is listed, fail once it is retired; new tokens use the active key |
| `TestStrictBase64` | Lenient decoding maps two spellings to one tag; the signer rejects the non-canonical one |
| `TestNewSignerValidation` | Short secrets, bad or duplicate key IDs, empty subjects are refused |
| `ExampleSigner` | Normal use and a one-character modification |

## 7. Checklist

- [ ] Every token the server issues and later trusts carries a MAC (or signature); base64/JSON alone is never trusted.
- [ ] The MAC input is an unambiguous encoding (length prefixes or fixed widths) and covers version, key ID and every field.
- [ ] Verification compares MACs with `hmac.Equal` over the received bytes before parsing or checking expiry.
- [ ] Each purpose has its own key, derived with HKDF or generated separately.
- [ ] Tokens carry a key ID; rotation and retirement are tested.
- [ ] Encoding is canonical (`.Strict()`); revocation lists key on MAC bytes.
- [ ] TTLs are short and one-time tokens are invalidated on use.

## References

- RFC 2104 — [HMAC](https://www.rfc-editor.org/rfc/rfc2104); RFC 5869 — [HKDF](https://www.rfc-editor.org/rfc/rfc5869); RFC 4648 §3.5 — [Canonical encoding](https://www.rfc-editor.org/rfc/rfc4648#section-3.5)
- [`crypto/hkdf`](https://pkg.go.dev/crypto/hkdf), [`encoding/base64.Encoding.Strict`](https://pkg.go.dev/encoding/base64#Encoding.Strict), [Go 1.24 release notes](https://go.dev/doc/go1.24)
- OWASP — [Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html), [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- Duong, Rizzo — *Flickr's API Signature Forgery Vulnerability* (2009), the classic length-extension + concatenation case
