# 08. Secure Randomness

> **Abstract.** Go ships two random packages that differ in contract, not just quality. `math/rand` and `math/rand/v2` are **deterministic generators**: their output is a function of a seed you (or the runtime) supply, their state is ordinary data that can be copied and serialised, and their documentation says they "should not be used for security-sensitive work" — even though since Go 1.22 the default generator is ChaCha8 and much harder to predict than it used to be. `crypto/rand` is the operating system's CSPRNG with no seed to guess, and since Go 1.24 it cannot fail silently: `Read` never returns an error and `Text` returns a ready-made 128-bit token. Most real bugs are not exotic: a generator seeded from the clock, and a modulo that makes some symbols more likely than others.

| | |
|---|---|
| Weaknesses | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) Use of Cryptographically Weak PRNG, [CWE-330](https://cwe.mitre.org/data/definitions/330.html) Use of Insufficiently Random Values, [CWE-335](https://cwe.mitre.org/data/definitions/335.html) Incorrect Usage of Seeds in PRNG |
| Go packages | `crypto/rand`, `math/rand`, `math/rand/v2`, `math/big` |
| Code | [`secrand.go`](secrand.go), [`secrand_test.go`](secrand_test.go) |

## 1. Threat model

The application generates secrets: password-reset and email-verification tokens, session IDs, API keys, invitation codes, initial passwords, nonces. The attacker can request their own secrets, knows the source code (or guesses the library), and knows roughly *when* a victim's secret was created (the reset email went out "around 09:40"). The goal is to predict or enumerate the victim's secret, or to reduce the search space enough for online guessing.

## 2. What Go guarantees

| Package / version | Behaviour |
|---|---|
| `math/rand`, `rand.New(rand.NewSource(seed))` | Fully determined by `seed`; same seed, same stream |
| `math/rand` top-level functions, Go 1.20 | Global source seeded randomly at start-up; `rand.Seed` deprecated |
| `math/rand/v2`, Go 1.22 | New API; `ChaCha8` and `PCG` sources; top-level functions use a runtime ChaCha8 generator, and unseeded `math/rand` top-level functions do too |
| `math/rand`, Go 1.24 | Top-level `rand.Seed` is a no-op unless `GODEBUG=randseednop=0` |
| `math/rand/v2.ChaCha8` | Documented as cryptographically strong *as an algorithm*, but `NewChaCha8(seed)` is reproducible and `MarshalBinary` exports its state |
| Both `math/rand` packages | "This package's outputs might be easily predictable regardless of how it's seeded" — no security contract |
| `crypto/rand.Reader` | OS CSPRNG (`getrandom(2)` on Linux, platform APIs elsewhere) |
| `crypto/rand.Read`, Go 1.24 | Never returns an error and always fills the buffer; on OS failure the program **crashes irrecoverably** instead of returning zeros |
| `crypto/rand.Text`, Go 1.24 | RFC 4648 base32 string with at least 128 bits of randomness (26 characters today) |
| `crypto/rand.Int(rand.Reader, max)` | Uniform in `[0, max)` |

The improvements in 1.20–1.24 make *accidental* misuse of the global `math/rand` functions far less catastrophic than in older Go. They do not change the contract, and they do nothing for code that builds its own seeded generator.

## 3. Insecure pattern

**Clock-seeded generator.** [`TokenUnsafe`](secrand.go) is the pattern that survives in copy-pasted code:

```go
r := mrand.New(mrand.NewSource(now.Unix()))
for i := range b { b[i] = Alphabet[r.Intn(len(Alphabet))] }
```

The token has 16 × log₂62 ≈ 95 bits of *apparent* entropy and about 10 bits of real entropy (the second within a ±10 minute window). Two users resetting in the same second receive the same token; an attacker who knows the approximate time enumerates 1,201 candidates offline — the test finds the victim's token after 668. `UnixNano` widens the search but remains a guessable, often coarse, value. The same applies to seeds from PIDs, user IDs, or hashes of them: a strong generator with a guessable seed is a guessable generator.

**Modulo bias.** [`PasswordUnsafe`](secrand.go) reads bytes from `crypto/rand` — the source is fine — and maps them with `b % 62`. Because 256 = 4 × 62 + 8, the symbols `A`–`H` are produced by five byte values and the rest by four: eight symbols are 25 % more likely. Fed every byte value exactly once, the mapping produces exactly that distribution.

## 4. Secure pattern

1. **Tokens: `crypto/rand.Text()`** (Go 1.24). 128+ bits, URL-safe base32 alphabet, no error to handle. For a fixed byte length, `rand.Read` into a slice and encode with `base64.RawURLEncoding` ([`TokenBytes`](secrand.go)).
2. **Ranges: reject, don't reduce.** [`Password`](secrand.go) discards bytes ≥ 248 (the largest multiple of 62 that fits in a byte) and redraws; every accepted byte maps to exactly four values per symbol. For arbitrary ranges use `crypto/rand.Int(rand.Reader, big.NewInt(n))`, which does the same internally.
3. **Size for the threat.** ≥ 128 bits for long-lived secrets and anything checkable offline; OWASP's floor for session IDs is 64 bits of entropy. Short human-typed codes (6-digit OTPs) are only acceptable with strict attempt limits and expiry (chapters 04, 28).
4. **Keep `math/rand/v2` for what it is for:** simulation, jitter, sampling, shuffling non-secret data, load balancing.

## 5. Where the guarantee ends

- **Not every random-looking ID is a secret.** UUIDv4 from a CSPRNG has 122 random bits and is usable as a token; UUIDv1 and UUIDv7 embed timestamps and are identifiers, not secrets. Check what your UUID library does.
- **Store tokens as hashes.** A strong token leaked from a database dump is still a valid token. Store `SHA-256(token)` and compare by hash (chapters 09, 10).
- **Bias also hides in floats and shuffles.** `int(f * n)` from a `float64`, or a hand-written shuffle that swaps with `rand.Intn(n)` instead of `Intn(i+1)`, introduces non-uniformity. Use integer APIs and `rand.Shuffle` (non-secret data) or `crypto/rand.Int`.
- **VM snapshots and forks** can duplicate in-process generator state. The OS CSPRNG is designed to handle reseeding; a user-space `math/rand/v2` generator seeded once at start-up is not.
- **Linters.** gosec's G404 flags `math/rand` imports in security-relevant code; treat it as a review prompt, not as proof.

## 6. Verification

```bash
go test -race -v ./Security/08_secure-randomness/
```

| Test | Shows |
|---|---|
| `TestTokenUnsafeCollidesWithinASecond` | Two tokens issued 400 ms apart are identical |
| `TestTokenUnsafeIsRecoverable` | Enumerating seconds in ±10 minutes recovers the victim's token |
| `TestToken` | `crypto/rand.Text` tokens: ≥ 26 base32 characters, no duplicates in 1,000 |
| `TestSeedableGeneratorsAreReproducible` | Two ChaCha8 generators with one seed produce the same stream; serialised state clones it |
| `TestPasswordUnsafeIsBiased` | Exhaustive input: `A`–`H` appear 5 times, the other 54 symbols 4 times |
| `TestPasswordIsUniform` | Rejection sampling: all 62 symbols appear exactly 4 times |
| `TestCryptoRandIntRange` | `crypto/rand.Int` stays in range |
| `ExampleTokenUnsafe` | Same-second collision vs `Token()` |

## 7. Checklist

- [ ] Every secret value comes from `crypto/rand` (`Text`, `Read`, `Int`); `math/rand` imports are absent from auth, session and key code.
- [ ] No generator is seeded from time, PID, counters or user data.
- [ ] Mapping bytes to symbols or ranges uses rejection sampling or `crypto/rand.Int`, never `%`.
- [ ] Tokens carry ≥ 128 bits unless rate-limited and short-lived by design.
- [ ] Tokens are stored hashed and compared by hash.

## References

- Go Blog — [Secure Randomness in Go 1.22](https://go.dev/blog/chacha8rand), [Evolving the Go Standard Library with math/rand/v2](https://go.dev/blog/randv2)
- [`crypto/rand`](https://pkg.go.dev/crypto/rand) — `Read`, `Text`, `Int`; [Go 1.24 release notes](https://go.dev/doc/go1.24)
- [`math/rand/v2`](https://pkg.go.dev/math/rand/v2), [Go 1.20 release notes](https://go.dev/doc/go1.20)
- OWASP — [Session Management Cheat Sheet: Session ID entropy](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy)
- NIST SP 800-90A Rev. 1 — [Recommendation for Random Number Generation Using Deterministic RBGs](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final)
