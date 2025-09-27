# Secure Go

A security engineer's field notes on Go, written as short white papers. Each chapter takes one weakness class, explains what the Go language, runtime or standard library already does about it, shows the pattern that still goes wrong, and proves both sides with runnable code and tests.

The point is not "Go is safe" or "Go is unsafe". It is to know **exactly where the guarantees end**, so code review and threat modelling can focus there.

## How a chapter is written

Every chapter directory holds a `README.md` with the same structure, plus Go code and tests that back up each claim.

| Section | Content |
|---|---|
| Abstract | The finding in one paragraph |
| Metadata table | CWE weakness classes, Go packages involved, code files |
| 1. Threat model | Who the attacker is, what they control, what they want |
| 2. What Go guarantees | Language, runtime and standard library behaviour, with versions where it changed |
| 3. Insecure pattern | The code that looks fine and is not |
| 4. Secure pattern | The fix, and why it works |
| 5. Where the guarantee ends | Edge cases, escape hatches, related chapters |
| 6. Verification | `go test` command and what each test proves |
| 7. Checklist | Review items to carry into real code |
| References | Go documentation, release notes, standards, CVEs |

Rules for the code:

- **Standard library first.** A dependency is added only when the standard library has no answer (for example Argon2id from `golang.org/x/crypto`).
- **Offline tests.** Network behaviour is exercised with `net/http/httptest` and loopback listeners, never the internet.
- **Both sides are tested.** The insecure function exists so a test can show it failing; the secure function has a test showing it holding.
- **Baseline: Go 1.25.** Features newer than the `go` line in `go.mod` are not used; `go vet` reports them.

## Running

```bash
go test ./Security/...              # all chapters
go test -v ./Security/01_memory-safety/
make race                           # whole repository with the race detector
```

## Chapters

<!-- CHAPTERS:START -->

### I. Language & Runtime

| # | Chapter | Weaknesses |
|---|---|---|
| 01 | [Memory Safety](01_memory-safety/) | CWE-125, CWE-226, CWE-130 |
| 02 | [Integer Overflow & Truncation](02_integer-overflow/) | CWE-190, CWE-681, CWE-197 |
| 03 | [Slice & Map Aliasing](03_slice-aliasing/) | CWE-374, CWE-375, CWE-471 |
| 04 | [Data Races](04_data-races/) | CWE-362, CWE-367, CWE-820 |
| 05 | [Panics as Denial of Service](05_panic-boundaries/) | CWE-248, CWE-476, CWE-400 |
| 06 | [Goroutine Leaks & Unbounded Concurrency](06_goroutine-leaks/) | CWE-400, CWE-770, CWE-772 |
| 07 | [Error Messages as Information Disclosure](07_error-disclosure/) | CWE-209, CWE-497, CWE-200 |

### II. Cryptography

| # | Chapter | Weaknesses |
|---|---|---|
| 08 | [Secure Randomness](08_secure-randomness/) | CWE-338, CWE-330, CWE-335 |
| 09 | [Constant-Time Comparison](09_constant-time-compare/) | CWE-208, CWE-203 |
| 10 | [Choosing Hash Functions](10_hash-functions/) | CWE-328, CWE-327 |
| 11 | [HMAC-Signed Tokens](11_hmac-tokens/) | CWE-345, CWE-347, CWE-613 |
| 12 | [Password Storage](12_password-hashing/) | CWE-916, CWE-759, CWE-760 |
| 13 | [Authenticated Encryption](13_aead-encryption/) | CWE-323, CWE-353, CWE-327 |

<!-- CHAPTERS:END -->
