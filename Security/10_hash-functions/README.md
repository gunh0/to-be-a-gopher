# 10. Choosing Hash Functions

> **Abstract.** "Hash" names at least four different tools: hash-table hashes (`hash/maphash`, FNV), checksums (`hash/crc32`), cryptographic hashes (SHA-2, SHA-3) and keyed MACs (HMAC). They answer different questions, and swapping one for another fails silently. A fast non-cryptographic hash used as a content ID lets an attacker manufacture collisions in milliseconds; MD5 and SHA-1 have practical collision attacks; and even SHA-256 is the wrong tool as a MAC when written as `SHA-256(key || msg)`, because a Merkle–Damgård digest *is* the hash's internal state and can be extended without the key. Pick by property — collision resistance, keyed authenticity, stability across processes — and the choice in Go is short: SHA-256/SHA-512 or `crypto/sha3` for digests, HMAC for authenticity.

| | |
|---|---|
| Weaknesses | [CWE-328](https://cwe.mitre.org/data/definitions/328.html) Use of Weak Hash, [CWE-327](https://cwe.mitre.org/data/definitions/327.html) Use of a Broken or Risky Cryptographic Algorithm |
| Go packages | `crypto/sha256`, `crypto/sha512`, `crypto/sha3`, `crypto/hmac`, `hash/fnv`, `hash/maphash`, `crypto/md5`, `crypto/sha1` |
| Code | [`hashing.go`](hashing.go), [`hashing_test.go`](hashing_test.go) |

## 1. Threat model

The attacker controls some of the data being hashed: uploaded files in a de-duplicating store, cache keys built from request parameters, messages that the server "signs" with a hash, artefacts whose integrity is pinned by digest. They want two different inputs to map to the same digest (so one stands in for the other), or a valid authenticator for a message the server never signed.

## 2. What Go provides

| Package | Property | Use for | Never for |
|---|---|---|---|
| `hash/maphash` | Fast, randomly seeded per process; `Comparable` (Go 1.24) | Hash tables, sharding within one process | Persistent IDs, MACs, anything cross-process |
| `hash/fnv`, `hash/crc32`, `hash/adler32` | Fast, unkeyed, no adversarial resistance (CRC is linear) | Detecting accidental corruption, non-adversarial bucketing | Content IDs, dedup, integrity against attackers |
| `crypto/md5`, `crypto/sha1` | Package docs: "cryptographically broken"; practical collisions | Interop with legacy protocols only | New designs, signatures, content addressing |
| `crypto/sha256`, `crypto/sha512` | Collision resistant; Merkle–Damgård (length-extendable except the truncated `sha512.Sum512_256`) | Digests, content IDs, inside HMAC/HKDF/signatures | `H(key‖msg)` MACs |
| `crypto/sha3` (Go 1.24) | FIPS 202 SHA-3 and SHAKE; sponge construction, no length extension | Digests, domain-separated XOF (`NewCSHAKE128/256`) | Passwords |
| `crypto/hmac` | Keyed PRF/MAC (RFC 2104) | Authenticating messages, keyed IDs | — |

`crypto/x509` has rejected SHA-1-signed certificates since Go 1.18, and the `x509sha1` GODEBUG escape hatch was removed in Go 1.24. Nothing stops application code from calling `md5.Sum`, which is why reviews have to.

## 3. Insecure pattern

**Non-cryptographic content IDs.** [`StoreUnsafe`](hashing.go) de-duplicates uploads by FNV-1a-32. A birthday search over generated names finds a colliding pair in about 10⁵ hashes (`TestStoreUnsafeCollision`, well under a second). The attacker uploads their file first; the victim's upload is "already present", and every later download of the victim's key serves the attacker's bytes. Wider FNV variants raise the cost but are still not designed to resist an adversary; MD5 (collisions since 2004, chosen-prefix since 2007, used by the Flame malware in 2012 to forge a Microsoft code-signing certificate) and SHA-1 (SHAttered, 2017; chosen-prefix "Shambles", 2020) are in the same category for anything where the attacker supplies input.

**Secret-prefix MAC.** [`SignUnsafe`](hashing.go) computes `SHA-256(key || msg)`. SHA-256 pads its input (`0x80`, zeros, 64-bit bit length) and outputs the eight 32-bit chaining words after the last block. That output is everything needed to keep hashing. `TestSHA256TagIsInternalState` shows the precondition directly: after writing `key‖msg‖pad`, the hash object's serialised state contains the published tag byte for byte. From there `key‖msg‖pad‖"&role=admin"` has a computable tag without the key. This chapter stops at the precondition; HMAC removes it.

## 4. Secure pattern

1. **Content IDs and integrity pins: SHA-256** ([`ContentID`](hashing.go)), SHA-512, or SHA3-256. `TestStoreKeepsDistinctContent` stores the FNV-colliding pair under distinct IDs.
2. **Authenticity: HMAC.** [`Sign`](hashing.go) uses `hmac.New(sha256.New, key)`; [`Verify`](hashing.go) compares with `hmac.Equal` (chapter 09). HMAC's nested construction `H(k⊕opad ‖ H(k⊕ipad ‖ m))` means the published tag is not a resumable state, and HMAC is secure even over hashes whose collision resistance is weakened.
3. **Prefer constructions over primitives.** Derive keys with `crypto/hkdf` (Go 1.24, chapter 14), sign tokens with HMAC (chapter 11), hash passwords with a password KDF (chapter 12) — never with a fast hash (CWE-916).
4. **Hash tables: `hash/maphash`.** Random per-process seeds make hash-flooding hard; values must never leave the process.
5. **Treat `crypto/md5` and `crypto/sha1` imports as review findings** unless a legacy protocol requires them, and document why.

```go
mac := hmac.New(sha256.New, key)
mac.Write(msg)
tag := mac.Sum(nil)
ok := hmac.Equal(tag, presented)
```

## 5. Where the guarantee ends

- **Collision resistance is not authenticity.** Anyone can compute `SHA-256(file)`; a digest proves integrity only if the digest itself arrives over a trusted channel (signed manifest, `go.sum` checked against the checksum database). Otherwise use a MAC or a signature.
- **Structure matters even with SHA-3.** `SHA3(key ‖ msg)` does not suffer length extension, but concatenating variable-length fields without encoding is ambiguous for every hash (chapter 11). KMAC is the standardised SHA-3 MAC; the standard library offers HMAC, which works with `sha3.New256` too.
- **Truncation trades security for size.** A 64-bit truncated SHA-256 has 2³² birthday security — fine for display, not for dedup keys an attacker targets.
- **Fast hashes and secrets.** `SHA-256(password)` and `SHA-256(token)` differ: tokens have ≥ 128 bits of entropy, so a fast hash is the right way to store them (chapter 08); passwords have little entropy and need a slow, salted KDF.
- **Git and other SHA-1 users.** Git defends with collision detection (SHA-1DC) and offers a SHA-256 object format. Do not extend that reasoning to your own SHA-1 usage.

## 6. Verification

```bash
go test -race -v ./Security/10_hash-functions/
```

| Test | Shows |
|---|---|
| `TestStoreUnsafeCollision` | A birthday search finds an FNV-1a-32 collision; the second upload resolves to the first blob |
| `TestStoreKeepsDistinctContent` | The SHA-256 store keeps both colliding blobs apart and still de-duplicates identical ones |
| `TestSHA256TagIsInternalState` | `SHA-256(key‖msg)` equals the serialised chaining value after `key‖msg‖pad`; the HMAC tag does not |
| `TestSignVerify` | HMAC rejects other keys, the padded-and-extended message, and modified messages |
| `TestKnownAnswers` | SHA-256 and `crypto/sha3` SHA3-256 known-answer vectors |
| `TestMaphashIsPerProcess` | Two `maphash` seeds give different values for the same input |
| `ExampleContentID` | SHA-256 vs FNV-1a output for `"abc"` |

## 7. Checklist

- [ ] No `hash/fnv`, `crc32`, `maphash`, MD5 or SHA-1 where an attacker supplies input and collisions matter.
- [ ] Content addressing and integrity pins use SHA-256, SHA-512 or SHA3-256, at full length.
- [ ] Every keyed hash is HMAC (or a library construction built on it), never `H(key ‖ msg)` or `H(msg ‖ key)`.
- [ ] Digests used for integrity are delivered or stored over an authenticated channel.
- [ ] Passwords use a password KDF; tokens with ≥ 128 bits of entropy may use SHA-256.

## References

- RFC 2104 — [HMAC: Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/rfc/rfc2104)
- NIST FIPS 180-4 [Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final), FIPS 202 [SHA-3 Standard](https://csrc.nist.gov/pubs/fips/202/final); NIST — [Retiring SHA-1](https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm) (by 2030)
- Stevens et al. — [SHAttered](https://shattered.io/) (2017); Leurent, Peyrin — [SHA-1 is a Shambles](https://sha-mbles.github.io/) (2020)
- [`crypto/sha3`](https://pkg.go.dev/crypto/sha3), [`hash/maphash`](https://pkg.go.dev/hash/maphash), [Go 1.24 release notes](https://go.dev/doc/go1.24)
