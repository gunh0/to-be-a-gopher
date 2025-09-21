# 09. Constant-Time Comparison

> **Abstract.** `==` on strings, `bytes.Equal` and nearly every hand-written loop stop at the first differing byte. When one operand is a secret — an API key, a MAC, a reset token — the comparison's running time encodes how many leading bytes the attacker guessed right, and a secret of n bytes falls to about 256·n guesses instead of 256ⁿ. `crypto/subtle.ConstantTimeCompare` and `hmac.Equal` remove the content-dependent exit, but **not** the length check: they return immediately when lengths differ. The robust pattern is to compare fixed-length values only — MACs or digests of the secret — so that neither content nor length is observable.

| | |
|---|---|
| Weaknesses | [CWE-208](https://cwe.mitre.org/data/definitions/208.html) Observable Timing Discrepancy, [CWE-203](https://cwe.mitre.org/data/definitions/203.html) Observable Discrepancy |
| Go packages | `crypto/subtle`, `crypto/hmac`, `crypto/sha256` |
| Code | [`consttime.go`](consttime.go), [`consttime_test.go`](consttime_test.go) |

## 1. Threat model

A service checks a client-supplied secret against a stored one: a static API key in a header, a webhook signature, an HMAC on a cookie or link (chapter 11), a one-time token. The attacker can submit many guesses and measure response times, from the same data centre, through HTTP/2 multiplexing that cancels network jitter, or locally from a co-tenant. They want the secret without brute force. Rate limiting (chapter 28) raises the cost; it does not remove a channel that leaks one byte per few thousand queries.

## 2. What Go guarantees

| API | Content-independent? | Length-independent? |
|---|---|---|
| `a == b` (string), `bytes.Equal`, `bytes.HasPrefix`, `strings.EqualFold` | No — early exit (word-at-a-time, but still prefix-dependent) | No |
| `subtle.ConstantTimeCompare(x, y)` | Yes: "the time taken is a function of the length of the slices and is independent of the contents" | **No**: returns 0 immediately if lengths differ |
| `hmac.Equal(mac1, mac2)` | Yes (built on `ConstantTimeCompare`) | Same caveat; intended for fixed-size MACs |
| `subtle.ConstantTimeByteEq`, `ConstantTimeEq`, `ConstantTimeSelect`, `XORBytes` (Go 1.20) | Building blocks for constant-time code | — |
| `subtle.WithDataIndependentTiming(f)` (Go 1.24) | Enables the CPU's data-independent-timing mode while `f` runs: `PSTATE.DIT` on arm64 with FEAT_DIT; a plain call elsewhere | Does not make variable-time code constant-time |

The standard library's own MAC and signature checks (`crypto/hmac`, `crypto/ed25519`, AEAD `Open`) are constant-time with respect to secret data. The leak comes from application code that compares secrets itself.

## 3. Insecure pattern

```go
func CheckKeyUnsafe(stored, presented string) bool {
	return presented == stored
}
```

[`EqualUnsafe`](consttime.go) is the same algorithm with a step counter in place of a clock. The step count is the length of the matching prefix plus one, so the attacker's loop is trivial: for each position try 256 values, keep the one that made the comparison take longest. `TestEqualUnsafeLeaksPrefix` recovers a 12-byte key in under 3,000 queries; brute force would need 256¹². Real attacks need many samples per guess to average out noise, which changes the constant, not the complexity.

## 4. Secure pattern

1. **Fixed, public length: `subtle.ConstantTimeCompare`.** For MACs, digests and keys of a known format ([`CheckKey`](consttime.go)), or `hmac.Equal` for MACs. [`EqualConstant`](consttime.go) shows why it works: it ORs together the XOR of every byte pair and inspects the result once, so the work is identical for every guess of the right length.
2. **Variable or secret length: compare MACs, not secrets.** [`Verifier`](consttime.go) stores `HMAC(k, secret)` under a random per-process key and checks `hmac.Equal(HMAC(k, presented), stored)`. Both operands are 32 bytes regardless of input, so the secret's length is hidden too, and the random key prevents precomputing digests for chosen inputs. A plain SHA-256 of both sides also equalises length; the keyed version is the conservative default.
3. **Verify the MAC first, then parse.** For signed tokens, compute the expected MAC over the received bytes and compare in constant time before acting on any field (chapter 11).
4. **Don't look up secrets by value.** `WHERE token = $1`, `map[token]` and B-tree indexes compare the secret in variable time inside code you do not control. Use a split token: a non-secret *selector* for lookup and a *verifier* stored as a hash and compared with `hmac.Equal`.

```go
want := mac(key, secret)                  // once
ok := hmac.Equal(mac(key, presented), want) // per request
```

## 5. Where the guarantee ends

- **Everything around the comparison.** Early `return` on a missing header, a database lookup that only happens for valid usernames, or a password hash computed only for existing users are timing oracles of their own. Make the failure paths do comparable work.
- **Decoding the stored secret.** `hex` and `base64` decoders are not constant-time in their input. Decoding the attacker's value is harmless (they know it); decode the *stored* secret once at start-up and keep it in raw form.
- **CPU-level effects.** Constant-time at the Go level assumes instructions whose timing does not depend on operands; `WithDataIndependentTiming` exists for the arm64 cases where that is configurable. Caches and speculative execution are outside what a comparison function can fix.
- **Length is metadata.** If the secret's length matters (variable-length passwords, tokens of different classes), do not rely on `ConstantTimeCompare` alone.
- **Password storage** is a different problem (chapter 12): compare with the password-hashing library's own verify function (bcrypt's `CompareHashAndPassword` uses `subtle` internally), never by hashing and `==`.

## 6. Verification

```bash
go test -race -v ./Security/09_constant-time-compare/
```

| Test | Shows |
|---|---|
| `TestEqualUnsafeLeaksPrefix` | Prefix-length side channel recovers a 12-byte secret in < 256·12 queries |
| `TestEqualConstantGivesNoSignal` | Identical step counts for every guess; the same attack fails |
| `TestLengthIsNotHidden` | Length mismatch short-circuits both the model and `subtle.ConstantTimeCompare` |
| `TestCheckKey` | `==` and `ConstantTimeCompare` agree on correctness, including empty and longer inputs |
| `TestVerifier` | HMAC-then-compare accepts only the exact secret; per-process keys differ |
| `ExampleEqualUnsafe` | Steps 1/2/4 for growing prefixes vs a constant 4 |

## 7. Checklist

- [ ] No `==`, `bytes.Equal`, `strings.EqualFold` or `HasPrefix` on API keys, tokens, MACs, signatures or OTPs.
- [ ] Fixed-length secrets use `subtle.ConstantTimeCompare` or `hmac.Equal`; variable-length secrets are compared as HMACs/digests.
- [ ] Secrets are never the lookup key in a map or database index; selector/verifier split instead.
- [ ] Failure paths (unknown user, malformed token, wrong secret) take comparable time and return the same response.
- [ ] Signed data is MAC-verified before any field is parsed or acted on.

## References

- [`crypto/subtle`](https://pkg.go.dev/crypto/subtle) — `ConstantTimeCompare`, `WithDataIndependentTiming`; [`hmac.Equal`](https://pkg.go.dev/crypto/hmac#Equal)
- [Go 1.24 release notes](https://go.dev/doc/go1.24) — `crypto/subtle.WithDataIndependentTiming`
- Crosby, Wallach, Riedi — *Opportunities and Limits of Remote Timing Attacks*, ACM TISSEC 12(3), 2009
- Van Goethem, Pöpper, Joosen, Vanhoef — [*Timeless Timing Attacks*](https://www.usenix.org/conference/usenixsecurity20/presentation/van-goethem), USENIX Security 2020
- Arm — [DIT, Data Independent Timing](https://developer.arm.com/documentation/ka005181/1-0/?lang=en)
