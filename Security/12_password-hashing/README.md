# 12. Password Storage

> **Abstract.** A password hash exists for one scenario: the table has leaked and the attacker is guessing offline, with no rate limit. In that scenario the only property that matters is **cost per guess**, and general-purpose hashes are engineered to make that cost tiny. SHA-256 with a salt stops precomputed tables but still lets a GPU test billions of guesses per second. Argon2id makes each guess spend tens of megabytes of memory for tens of milliseconds, stored as a self-describing PHC string so cost can be raised later and old hashes upgraded transparently at the next successful login. bcrypt and PBKDF2 remain acceptable, each with a sharp edge: bcrypt ignores every byte after the 72nd, and PBKDF2 is not memory-hard.

| | |
|---|---|
| Weaknesses | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) Use of Password Hash With Insufficient Computational Effort, [CWE-759](https://cwe.mitre.org/data/definitions/759.html) Use of a One-Way Hash without a Salt, [CWE-760](https://cwe.mitre.org/data/definitions/760.html) Use of a One-Way Hash with a Predictable Salt |
| Go packages | `golang.org/x/crypto/argon2`, `golang.org/x/crypto/bcrypt`, `crypto/pbkdf2` (1.24), `crypto/subtle`, `crypto/rand` |
| Code | [`argon2id.go`](argon2id.go), [`legacy.go`](legacy.go), [`passhash_test.go`](passhash_test.go) |

## 1. Threat model

The attacker has a copy of the credentials table: a SQL injection, a stolen backup, a misconfigured bucket. Online rate limiting no longer applies. They want plaintext passwords, both to log in here and to replay them elsewhere (credential stuffing). Their cost model is guesses per second per dollar of GPU or ASIC time, multiplied by the number of accounts, and divided by anything that lets one guess be tested against many accounts at once.

## 2. What Go provides

| Need | Package | Notes |
|---|---|---|
| Argon2id (RFC 9106) | `golang.org/x/crypto/argon2` | `IDKey(pw, salt, t, m, p, keyLen)`; no encoder, the PHC string is your job |
| bcrypt | `golang.org/x/crypto/bcrypt` | Self-encoding (`$2a$10$...`); `GenerateFromPassword` rejects inputs > 72 bytes, `CompareHashAndPassword` does not |
| PBKDF2 | `crypto/pbkdf2` (Go 1.24) | Generic `Key(sha256.New, password, salt, iter, keyLen)`; inside the Go Cryptographic Module (chapter 17) |
| Constant-time comparison | `crypto/subtle.ConstantTimeCompare` | |
| Salt | `crypto/rand.Read` | Never fails on supported platforms since Go 1.24 |

The standard library deliberately has no Argon2 or bcrypt; this chapter is the one place in the series that takes the `x/crypto` dependency for it.

Cost on an Apple M1 Pro (`go test -bench . ./Security/12_password-hashing/`):

| Scheme | Time per hash | Memory per guess |
|---|---|---|
| Salted SHA-256 (plus hex encoding) | ~0.14 µs | none |
| Argon2id m=19 MiB, t=2, p=1 | ~32 ms | 19 MiB |
| PBKDF2-HMAC-SHA256, 600 000 iterations | ~87 ms | none |

PBKDF2 looks "slower" on the CPU, but its inner loop is a few hundred bytes of state, which GPUs parallelise trivially. Argon2id's 19 MiB per guess is what limits how many guesses fit on a card at once.

## 3. Insecure pattern

[`HashSHA256Unsafe`](legacy.go) (no salt) gives every user with the same password the same hash, so one precomputed table cracks the whole breach. [`HashSaltedSHA256Unsafe`](legacy.go) fixes that and nothing else: the dictionary loop in `TestSaltedFastHashFallsToDictionary` is exactly the attacker's loop, at one SHA-256 per guess. A predictable salt (username, a constant, the user ID) is CWE-760: it is unique per account but reusable across sites and precomputable.

The bcrypt trap is quieter. [`BcryptCacheKeyUnsafe`](legacy.go) feeds `userID:username:password` to bcrypt and truncates to 72 bytes because the library rejects longer input:

```go
in := []byte(userID + ":" + username + ":" + password)
if len(in) > 72 { in = in[:72] } // "fix" for ErrPasswordTooLong
return bcrypt.GenerateFromPassword(in, cost)
```

With a 67-byte username only five password bytes are hashed; with a slightly longer one, none. Okta's AD/LDAP delegated-authentication advisory (October 2024) was this construction. Even without explicit truncation, `CompareHashAndPassword` silently compares only the first 72 bytes of the candidate.

## 4. Secure pattern

[`Hash`](argon2id.go) / [`Verify`](argon2id.go) / [`Login`](argon2id.go):

1. **Argon2id**, 16-byte random salt, 32-byte output. Parameters are `OWASPParams` (m=19 MiB, t=2, p=1), the OWASP Password Storage Cheat Sheet minimum, rather than RFC 9106's first recommendation (t=1, p=4, m=2 GiB): a login endpoint hashes concurrently, and 2 GiB per attempt is a memory-exhaustion lever. RFC 9106's second option (t=3, p=4, m=64 MiB) is a step up when memory allows. Also bound concurrent hashes with a semaphore, because the endpoint is now the most expensive one you have (chapter 21).
2. **PHC string** `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`, so the parameters travel with the hash.
3. **Strict parsing with limits.** [`Parse`](argon2id.go) rejects other algorithms, other versions, reordered or zero-padded numbers, padded base64 and, crucially, parameters outside `maxMemory`/`maxTime`. A stored string decides how much memory `Verify` allocates; an imported or tampered row must not be able to ask for 4 GiB.
4. **Constant-time comparison** with `subtle.ConstantTimeCompare`. Honest note: with a secret salt, timing on the hash comparison leaks little that an attacker can use, but it costs nothing and removes the argument.
5. **Rehash on login.** `Verify` reports `needsRehash` when stored parameters differ from policy; `Login` returns the replacement hash. The successful login is the only time the server holds the plaintext, so cost upgrades happen there. Accounts that never log in keep old hashes; set a deadline after which they must reset.

For bcrypt where it is mandated: hash only the password, reject inputs over 72 **bytes** (UTF-8; 25 Hangul syllables are already 75 bytes) on both paths ([`BcryptHash`](legacy.go), [`BcryptVerify`](legacy.go)), and never concatenate other fields into the input. Pre-hashing to fit the limit is possible but has its own pitfalls (raw digests contain NUL bytes some bcrypt implementations stop at; base64-encode them).

For FIPS 140-3 deployments, Argon2id and bcrypt are not approved algorithms; use [`PBKDF2SHA256`](legacy.go) with at least 600 000 iterations (OWASP), 16-byte salts and 32-byte keys. In `GODEBUG=fips140=only` mode `crypto/pbkdf2` itself rejects salts under 128 bits and keys under 112 bits.

## 5. Where the protection ends

- **Weak passwords.** Argon2id multiplies the cost of each guess; it does not help `123456`. Pair it with a breached-password check and MFA.
- **Pepper.** An HMAC key kept outside the database (KMS, HSM) applied before or after hashing makes a database-only leak useless. It also makes key rotation an operational problem; decide deliberately.
- **Online attacks** are a rate-limiting problem, not a hashing one.
- **Deriving encryption keys from passwords** uses the same KDFs, never HKDF (chapter 14): HKDF assumes its input already has full entropy.
- **Memory.** `[]byte(password)` copies are not zeroed; Go gives no reliable way to scrub them (the GC may have copied them). Keep plaintext lifetimes short.

## 6. Verification

```bash
go test -race -v ./Security/12_password-hashing/
go test -run '^$' -bench . ./Security/12_password-hashing/
```

| Test | Shows |
|---|---|
| `TestUnsaltedHashIsIdenticalAcrossUsers` | Equal passwords give equal hashes; a precomputed table answers instantly (CWE-759) |
| `TestSaltedFastHashFallsToDictionary` | A salt alone still leaves a fast offline dictionary attack (CWE-916) |
| `TestArgon2idRoundTripAndUniqueSalt` | PHC encoding, fresh salt per hash, correct/incorrect password |
| `TestParseRejectsMalformedAndAbusiveHashes` | Strict PHC parsing, including a 4 GiB memory parameter and a bcrypt string |
| `TestLoginRehashesOutdatedParams` | Outdated parameters are upgraded on successful login only, and only once |
| `TestBcryptTruncationMakesPasswordIrrelevant` | `userID:username:password` truncated to 72 bytes accepts any password |
| `TestBcryptSafeRejectsOverlongInput` | `CompareHashAndPassword` ignores byte 73; the wrappers reject it, counting bytes not characters |
| `TestPBKDF2KnownAnswer` | `crypto/pbkdf2` matches the RFC 7914 PBKDF2-HMAC-SHA256 vector |
| `Benchmark*` | Cost per guess for salted SHA-256, Argon2id (OWASP) and PBKDF2 (600 000) |

## 7. Checklist

- [ ] No `sha256`/`sha512`/`md5` call touches a password, salted or not.
- [ ] Argon2id with at least m=19 MiB, t=2, p=1 (or bcrypt cost ≥ 10, or PBKDF2-HMAC-SHA256 ≥ 600 000 iterations under FIPS).
- [ ] Salts are ≥ 16 bytes from `crypto/rand`, unique per hash.
- [ ] Stored hashes are self-describing, parsed strictly, and their cost parameters are bounded.
- [ ] Verification is constant-time; successful logins upgrade outdated hashes.
- [ ] bcrypt inputs are only the password, and > 72 bytes is rejected on hash **and** verify.
- [ ] Concurrent password hashing is bounded.

## References

- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) Argon2 Memory-Hard Function, section 4 (parameter choice)
- OWASP — [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)
- NIST [SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) Digital Identity Guidelines, memorized secret verifiers
- [Go 1.24 release notes](https://go.dev/doc/go1.24) — `crypto/pbkdf2`, `crypto/rand.Read` no longer returning errors
- [golang.org/x/crypto/argon2](https://pkg.go.dev/golang.org/x/crypto/argon2), [golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt)
- Okta — [Okta AD/LDAP Delegated Authentication: Username Above 52 Characters Security Advisory](https://trust.okta.com/security-advisories/) (2024)
- [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914) section 11, PBKDF2-HMAC-SHA256 test vectors
