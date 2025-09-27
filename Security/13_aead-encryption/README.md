# 13. Authenticated Encryption

> **Abstract.** Encryption without authentication is a malleability primitive: with CTR (and GCM's CTR core) a flipped ciphertext bit is a flipped plaintext bit, and the decryptor cannot tell. AEADs fix that, but AES-GCM moves the whole risk onto one 12-byte value: reuse a nonce under the same key once and the two plaintexts XOR together in the clear, and the authentication key falls out of the two tags. The robust choices are APIs that never let the caller supply a nonce — `cipher.NewGCMWithRandomNonce` (Go 1.24), good for 2^32 messages per key, or XChaCha20-Poly1305 with its 192-bit nonce — plus associated data that ties each ciphertext to where it belongs.

| | |
|---|---|
| Weaknesses | [CWE-323](https://cwe.mitre.org/data/definitions/323.html) Reusing a Nonce, Key Pair in Encryption, [CWE-353](https://cwe.mitre.org/data/definitions/353.html) Missing Support for Integrity Check, [CWE-327](https://cwe.mitre.org/data/definitions/327.html) Use of a Broken or Risky Cryptographic Algorithm |
| Go packages | `crypto/cipher` (`NewGCMWithRandomNonce`, 1.24), `crypto/aes`, `golang.org/x/crypto/chacha20poly1305` |
| Code | [`aead.go`](aead.go), [`aead_test.go`](aead_test.go) |

## 1. Threat model

Data at rest (database columns, object storage, cookies, tokens) or in a custom protocol is encrypted with a long-lived symmetric key. The attacker can read and **write** ciphertext: they own one row of the table, can replay or edit a cookie, or sit on the network. They do not have the key. They want to read other users' data or change what the application decrypts.

## 2. What the standard library provides

| API | Nonce handling | Safe message count per key | Notes |
|---|---|---|---|
| `cipher.NewCTR`, `NewCBCEncrypter` | Caller's IV | n/a | No integrity. `NewCFB*`, `NewOFB` are deprecated since 1.24 |
| `cipher.NewGCM` | Caller passes 12-byte nonce to every `Seal` | 2^32 if random; unlimited if a never-repeating counter | Errors in `fips140=only` mode (chapter 17) |
| `cipher.NewGCMWithRandomNonce` (1.24) | Generated internally, prepended; `NonceSize() == 0`, `Overhead() == 28` | 2^32 (documented) | AES only; FIPS-approved form |
| `chacha20poly1305.NewX` (x/crypto) | Caller's 24-byte nonce; random is safe | Effectively unbounded | Not FIPS-approved |

`Open` on every AEAD verifies the tag before returning any plaintext and returns a single opaque error: there is no partial plaintext and no padding oracle.

Birthday bound for random nonces (`CollisionProbability`, n²/2^(b+1)):

| Nonce | Messages under one key | P(any collision) |
|---|---|---|
| 96-bit (GCM) | 2^32 | 2^-33 |
| 96-bit (GCM) | 2^48 | ~2^-1 |
| 192-bit (XChaCha) | 2^64 | 2^-65 |

NIST SP 800-38D sets the 2^32 limit for random-IV GCM. A service sealing 1 000 records per second under one key reaches it in about 50 days; one sealing 1 000 000 per second, in 72 minutes. Rotate keys (chapter 14) or use XChaCha20-Poly1305 for high-volume keys.

## 3. Insecure pattern

**No authentication.** [`EncryptCTRUnsafe`](aead.go) is AES-CTR with a random IV. The attacker knows the JSON layout, so XORing `'0' ^ '9'` into byte 11 of the body turns `"amount":"0100"` into `"amount":"9100"`; `DecryptCTRUnsafe` returns it without complaint. CBC is no better: the IV is a bit-flip vector for the first block and padding errors become a decryption oracle.

**Nonce reuse.** [`CounterSealerUnsafe`](aead.go) uses GCM correctly except that its nonce is an in-memory counter starting at zero. Two replicas sharing the key, or one replica after a restart, emit nonce 0 again:

```go
binary.BigEndian.PutUint64(nonce[4:], s.n) // s.n starts at 0 in every process
s.n++
return s.aead.Seal(nonce, nonce, plaintext, nil)
```

Under one nonce both messages are XORed with the same keystream, so `c1 ⊕ c2 = p1 ⊕ p2`; one known plaintext reveals the other (`TestGCMNonceReuseLeaksPlaintextXOR`). Worse, GCM's tag is a polynomial in the hash key H evaluated over the ciphertext; two tags under one nonce give an equation whose roots include H (Joux, 2006). With H the attacker forges valid tags for chosen ciphertexts under that nonce. Böck et al. found HTTPS servers doing exactly this in 2016.

## 4. Secure pattern

[`NewGCM`](aead.go) wraps `cipher.NewGCMWithRandomNonce`; [`NewXChaCha`](aead.go) wraps `chacha20poly1305.NewX` with a random 24-byte nonce. Both expose `Seal(plaintext, ad)` / `Open(ciphertext, ad)`: **the caller never handles a nonce**.

```go
block, _ := aes.NewCipher(key)                  // 32-byte key
g, _ := cipher.NewGCMWithRandomNonce(block)
ct := g.Seal(nil, nil, plaintext, ad)            // nonce generated and prepended
pt, err := g.Open(nil, nil, ct, ad)
```

**Associated data** is authenticated but not encrypted. [`FieldAD`](aead.go) binds a column value to `(version, table, column, rowID)`, each length-prefixed so no two tuples encode the same bytes. Mallory copying Alice's encrypted email into her own row gets `ErrOpen`, not Alice's email (`TestAssociatedDataStopsCutAndPaste`). Without AD, every ciphertext under a key is interchangeable with every other one; that is the "confused deputy" behind many encrypted-cookie and encrypted-ID bugs.

Choosing between the two:

- **AES-256-GCM (random nonce)**: FIPS contexts, AES hardware (all current server CPUs), fewer than 2^32 messages per key.
- **XChaCha20-Poly1305**: very high message counts per key, no AES hardware, no FIPS requirement.

## 5. Where the protection ends

- **Nonce-misuse resistance** is a different property. AES-GCM-SIV (RFC 8452) degrades to "equal plaintexts are visible" on reuse; it is in neither the standard library nor x/crypto.
- **Key commitment.** GCM and ChaCha20-Poly1305 are not key-committing: one ciphertext can be crafted to open under two different keys ("invisible salamanders"). It matters when the key is chosen by a party you do not trust, such as multi-recipient encryption or password-derived keys.
- **Length and timing** are not hidden; pad if message size is sensitive.
- **Replay** is not prevented: a valid ciphertext stays valid. Put a version, an expiry or a sequence number in the AD or the plaintext.
- **Key management** — where keys come from, how many derive from one secret, and rotation — is chapter 14. Signatures (third-party verifiability) are chapter 15.

## 6. Verification

```bash
go test -race -v ./Security/13_aead-encryption/
```

| Test | Shows |
|---|---|
| `TestCTRBitFlipGoesUnnoticed` | An attacker without the key rewrites `0100` to `9100` through CTR |
| `TestAEADDetectsBitFlip` | Every single-bit flip in nonce, body or tag is rejected by both AEADs |
| `TestGCMNonceReuseLeaksPlaintextXOR` | Restarted counter → same nonce → `c1⊕c2 = p1⊕p2`, second plaintext recovered |
| `TestRandomNonceSealersNeverRepeat` | Encrypting the same plaintext 1 000 times gives 1 000 distinct ciphertexts |
| `TestAssociatedDataStopsCutAndPaste` | A ciphertext moved to another row or column fails to open |
| `TestFieldADIsUnambiguous` | Length prefixes keep `("email","10")` and `("email1","0")` apart |
| `TestTruncatedCiphertextRejected` | Every truncation, including shorter than nonce+tag, is `ErrOpen` |
| `TestCollisionBound` | The birthday-bound figures in the table above |
| `ExampleNewGCM` | 28 bytes of overhead; wrong AD fails |

## 7. Checklist

- [ ] No `NewCTR`, `NewCBCEncrypter`, `NewCFB*` or `NewOFB` for confidentiality without a MAC (encrypt-then-MAC at minimum; an AEAD preferably).
- [ ] No code path where a caller supplies a GCM nonce, or a nonce comes from a counter that can restart or `math/rand`.
- [ ] Message count per GCM key is estimated and below 2^32, or the key is XChaCha20-Poly1305.
- [ ] Associated data binds every ciphertext to its context (record, field, tenant, version), unambiguously encoded.
- [ ] Decryption failures return one generic error and no partial plaintext.

## References

- NIST [SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) — GCM, section 8 (uniqueness requirement on IVs)
- [`cipher.NewGCMWithRandomNonce`](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce), [Go 1.24 release notes](https://go.dev/doc/go1.24)
- A. Joux — *Authentication Failures in NIST version of GCM*, public comment on the SP 800-38D draft (2006)
- H. Böck, A. Zauner, S. Devlin, J. Somorovsky, P. Jovanovic — [Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS](https://eprint.iacr.org/2016/475) (WOOT 2016)
- [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/) — XChaCha20-Poly1305; [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) ChaCha20-Poly1305
- [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452) AES-GCM-SIV
- Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg — [How to Abuse and Fix Authenticated Encryption Without Key Commitment](https://www.usenix.org/conference/usenixsecurity22/presentation/albertini) (USENIX Security 2022)
