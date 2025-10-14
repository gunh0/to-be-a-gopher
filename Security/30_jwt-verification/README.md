# 30. JWT Verification Pitfalls

> **Abstract.** A JWT carries its own instructions for verification: the header names the algorithm (`alg`) and the key (`kid`). Every classic JWT vulnerability comes from obeying them. `"alg":"none"` asks for no signature; `"alg":"HS256"` against a server that holds an asymmetric public key turns that **public** key into an HMAC secret anyone can use (algorithm confusion). The fix is structural: the server decides the algorithm, pinned **per key**, and the token's `alg` must match it exactly. Around that sit quieter requirements: strict base64url (Go's decoders skip `\n` and accept non-canonical trailing bits, so one signature has many valid spellings), a JSON policy for duplicate names (`encoding/json` keeps the last and matches `sub`, `SUB` and `ſub` to the same field), and claim checks — `exp` required, `nbf`, `iss`, `aud`, small leeway — performed only after the signature has been verified. A minimal standard-library HS256/EdDSA verifier makes each point testable; production code should use a maintained library configured the same way.

| | |
|---|---|
| Weaknesses | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) Improper Verification of Cryptographic Signature, [CWE-345](https://cwe.mitre.org/data/definitions/345.html) Insufficient Verification of Data Authenticity, [CWE-613](https://cwe.mitre.org/data/definitions/613.html) Insufficient Session Expiration |
| Go packages | `crypto/ed25519`, `crypto/hmac`, `crypto/sha256`, `encoding/base64`, `encoding/json` |
| Code | [`jws.go`](jws.go), [`verifier.go`](verifier.go), [`jwt_test.go`](jwt_test.go) |

## 1. Threat model

An API accepts bearer JWTs issued by an identity provider. The attacker can obtain valid tokens for their own account, read the issuer's public keys (JWKS endpoints are public by design), and send arbitrary strings as tokens. They may also influence a field the issuer copies into a token (a display name, an e-mail address). Goals: mint a token for another subject or with elevated claims, keep using an expired or revoked token, or make two services disagree about what a token says.

## 2. What the standard library provides

| Need | Standard library | Behaviour to know |
|---|---|---|
| HMAC-SHA256 | `crypto/hmac`, `crypto/sha256` | Compare MACs with `hmac.Equal` (constant time) |
| Ed25519 (`EdDSA`, RFC 8037) | `crypto/ed25519` | `Verify` panics if the public key length is wrong; check `len` first |
| base64url without padding | `base64.RawURLEncoding` | Rejects `=`; **ignores `\r` and `\n`**; accepts non-zero trailing bits unless `.Strict()` |
| JSON | `encoding/json` | Duplicate names: last wins. Field matching: case-insensitive with Unicode folding (`ſ` → `s`) |
| JSON v2 | `encoding/json/v2` behind `GOEXPERIMENT=jsonv2` (Go 1.25, experimental) | Rejects duplicate names and matches case-sensitively by default |
| JWS/JWT | none | Use a maintained library (e.g. `github.com/golang-jwt/jwt/v5` with `jwt.WithValidMethods`, or `github.com/go-jose/go-jose/v4`) |

Chapter 35 covers `encoding/json` hazards in general; chapters 11 and 15 cover HMAC tokens and signatures without the JOSE layer. RFC 7515 §4 lets a JWS parser either reject duplicate header names or take the lexically last one; `encoding/json` does the latter. Case-insensitive matching, however, is a Go-specific extension that other parsers do not share, which is what makes it a differential.

## 3. Insecure pattern

```go
switch header.Alg {           // the token chooses
case "none":                  // no verification
case "HS256":
	hmacVerify(keyMaterial)    // keyMaterial is the Ed25519/RSA PUBLIC key
case "EdDSA":
	ed25519.Verify(keyMaterial)
}
json.Unmarshal(payload, &claims) // exp, nbf, iss, aud never checked
```

[`VerifyNaive`](jws.go). The tests forge three tokens against it with nothing but public information: an unsigned `alg: none` token, an `HS256` token MAC'd with the public key's bytes (the same flaw as CVE-2015-9235 in Node's `jsonwebtoken`, there with RSA PEM bytes), and a month-old expired token. They also show the parser issues: a signature with an inserted newline or flipped padding bits still verifies, and an honestly signed payload with `"sub":"alice"` followed by `"ſub":"admin"` is read as `admin`.

## 4. Secure pattern

[`Verifier.Verify`](verifier.go), in this order:

1. **Exactly three segments; strict base64url** (alphabet check, no padding, `Strict()` for trailing bits).
2. **Header JSON without duplicate names**; reject unknown `crit`.
3. **Select the key by `kid` from a fixed map.** `kid` is attacker input: never a file path, URL, or SQL; `jku`/`x5u` are ignored. Missing or unknown `kid` fails.
4. **`header.alg` must equal the key's configured `Alg`.** This single comparison eliminates `none` and algorithm confusion. HS256 secrets shorter than 256 bits are refused (RFC 7518 §3.2).
5. **Verify the signature** (`hmac.Equal`, `ed25519.Verify`).
6. **Then** decode claims (again rejecting duplicates) and validate: `exp` required and in the future (with leeway), `nbf` not in the future, dates within a sane range (no `int64` overflow from `1e300`), `iss` exact, `aud` contains this service.

```go
key, ok := v.Keys[h.Kid]
if !ok { return ErrKey }
if h.Alg != key.Alg { return ErrAlgorithm }   // pinned per key
```

With a library, the equivalent is to pass the expected algorithm list and a key function that returns a key *for that algorithm only*, and to enable required-claim options (`exp`, `iss`, `aud`).

## 5. Where verification ends

- **Revocation.** A valid signature on an unexpired token cannot be "logged out". Keep access tokens short-lived, use server-side sessions (chapter 29) where revocation matters, or maintain a deny-list keyed on `jti`.
- **Token type confusion.** An ID token, access token and refresh token from the same issuer share keys; check `typ` and `aud` so one cannot be used as another.
- **Key rotation.** Fetching JWKS is fine; fetching keys named by the token (`jku`, `x5u`, embedded `jwk`) is not. Cache JWKS, bound its size, and fetch it with an SSRF-safe client (chapter 27).
- **Leeway** compensates for skew between hosts, not for slow clients; minutes, not hours.

## 6. Verification

```bash
go test -v ./Security/30_jwt-verification/
```

| Test | Shows |
|---|---|
| `TestNaiveAcceptsAlgNone` | Unsigned token accepted as `admin` by the naive verifier; rejected by the safe one |
| `TestNaiveAlgorithmConfusion` | HS256 token MAC'd with the Ed25519 public key accepted; safe verifier returns `ErrAlgorithm` |
| `TestNaiveIgnoresExpiry` | 30-day-old token accepted / `ErrClaims` |
| `TestSignatureMalleability` | Non-canonical trailing bits and an inserted newline give new valid strings to the naive verifier; padding, both rejected as `ErrMalformed` by the strict one |
| `TestDuplicateClaimNames` | `sub` then `sub`/`SUB`/`ſub` → `admin` with `encoding/json`; rejected by the duplicate check |
| `TestVerifier` | 18 cases: leeway edges, `aud` string vs array, `iss`, missing/overflowing `exp`, `nbf`, `none` with a `kid`, cross-key algorithm, unknown/missing/path-like `kid`, wrong key, `crit`, extra segment, tampered payload |
| `TestShortHMACSecretRejected` | A 48-bit HS256 secret is refused |
| `ExampleVerifier_Verify` | Valid EdDSA token; `none` rejected with the pinned-algorithm error |

## 7. Checklist

- [ ] The accepted algorithm is configured per key on the server; the token's `alg` is only compared, never obeyed.
- [ ] `none` is impossible to configure; symmetric and asymmetric keys can never be confused.
- [ ] `kid` selects from a fixed or cached key set; `jku`, `x5u`, `jwk` headers are ignored.
- [ ] `exp` is required; `nbf`, `iss`, `aud` (and `typ` where tokens share issuers) are validated; leeway ≤ 1 minute.
- [ ] Decoding is strict (base64url and JSON duplicates) or delegated to a library that is.
- [ ] HS256 secrets are ≥ 32 random bytes; production uses a maintained JWT library.

## References

- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) JSON Web Token Best Current Practices; [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) JWT; [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) JWS; [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) JWA; [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) EdDSA in JOSE
- Tim McLean — [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) (2015); [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)
- Go documentation — [`base64.Encoding.Strict`](https://pkg.go.dev/encoding/base64#Encoding.Strict), [`json.Unmarshal`](https://pkg.go.dev/encoding/json#Unmarshal) (case-insensitive matching), [`encoding/json/v2`](https://pkg.go.dev/encoding/json/v2)
- OWASP — [JSON Web Token for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) (language-independent sections)
