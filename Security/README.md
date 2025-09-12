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
<!-- CHAPTERS:END -->
