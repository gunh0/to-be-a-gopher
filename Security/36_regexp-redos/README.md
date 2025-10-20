# 36. Regular Expressions without ReDoS

> **Abstract.** Go's `regexp` package implements RE2: matching is guaranteed to run in time linear in the input for a fixed pattern, and the features that need backtracking — backreferences, lookaround, atomic groups, possessive quantifiers — do not compile. The textbook catastrophic pattern `(a+)+$` scans 100 000 characters in milliseconds in Go, where a backtracking engine would never finish. ReDoS as a *class* is therefore closed. What remains is ordinary resource exhaustion: matching costs O(input × program size), compiling is not free and must not happen per request, user-supplied patterns need size limits, and `regexp.MustCompile` on user input is a panic waiting for an attacker.

| | |
|---|---|
| Weaknesses | [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) Inefficient Regular Expression Complexity, [CWE-400](https://cwe.mitre.org/data/definitions/400.html) Uncontrolled Resource Consumption |
| Go packages | `regexp`, `regexp/syntax` |
| Code | [`redos.go`](redos.go), [`redos_test.go`](redos_test.go) |

## 1. Threat model

A service validates input with regular expressions (emails, identifiers, log filters) and, in some products, lets users supply their own patterns (search, alert rules, routing). The attacker controls the subject text and possibly the pattern. Their goal is to burn CPU or memory per request, or to crash the process.

## 2. What Go guarantees

The package documentation: *"The regexp implementation provided by this package is guaranteed to run in time linear in the size of the input."* The engine never backtracks exponentially; it chooses between a one-pass matcher, a bounded bit-state backtracker (only when program × input is small enough to memoise every state) and a Pike-VM NFA simulation.

| Pattern on `"a"×100000 + "!"` | PCRE / Java / JS / Python `re` | Go `regexp` |
|---|---|---|
| `(a+)+$`, `^(a+)+$`, `^(a\|a)*$` | Exponential: effectively never returns | Milliseconds (`TestCatastrophicPatternsAreLinear`) |

| Feature | Go |
|---|---|
| Backreference `\1` | Compile error |
| Lookahead / lookbehind `(?=` `(?!` `(?<=` | Compile error |
| Atomic group `(?>`, possessive `a++` | Compile error |
| Repeat count `{n}` above 1000, or nested repeats whose product exceeds it | Compile error (`invalid repeat count`) |
| Nesting deeper than 1000 | Compile error (`expression nests too deeply`, after CVE-2022-24921) |
| Pathologically large parse trees | Compile error (`expression too large`, after CVE-2022-41715) |

The benchmark in the test file shows linear scaling of `^(a+)+$`: 1 KiB, 16 KiB and 256 KiB inputs take proportionally longer, at a roughly constant ~20 MB/s on a laptop.

## 3. Insecure pattern

```go
func IsValidEmailUnsafe(s string) bool {
	return regexp.MustCompile(emailPattern).MatchString(s)   // compile per call, no length cap
}

func MatchUserPatternUnsafe(pattern, input string) bool {
	return regexp.MustCompile(pattern).MatchString(input)     // user pattern, panics on "("
}
```

- **Compile per request.** Parsing and compiling allocate a syntax tree and a program on every call (`TestCompileOnceAllocations` measures dozens of allocations versus near zero).
- **Unbounded input.** Linear is not free: 1 MiB through a 15-instruction program is ~15 million steps, and `^(a+)+$` runs at roughly 20 MB/s. An endpoint that accepts 100 MB "emails" accepts 5 s of CPU per request.
- **`MustCompile` on user input** panics on `(`; in an HTTP handler `net/http` recovers it, anywhere else (a goroutine, a queue consumer) it kills the process (chapter 05).
- **Unbounded user patterns.** `a{1000}` compiles to 1002 instructions; `[a-z]{1000}` likewise. Every instruction is paid for at every input position.

## 4. Secure pattern

1. **Compile constant patterns once**, at package level, with `MustCompile` — a panic there can only happen at startup. `*regexp.Regexp` is safe for concurrent use.
2. **Cap input length before matching** with a domain limit (`IsValidEmail` rejects > 254 bytes) or a generic `MaxInput` ([`MatchBounded`](redos.go)).
3. **Validate user patterns** with [`CompileUserPattern`](redos.go):
   ```go
   if len(pattern) > MaxPatternLen { ... }
   n, err := ProgramSize(pattern)        // syntax.Parse → Simplify → syntax.Compile
   if n > MaxProgInsts { ... }
   re, err := regexp.Compile(pattern)    // never MustCompile
   ```
   `ProgramSize` runs the same pipeline as `regexp.Compile` and counts instructions, which is the factor that multiplies input length at match time.
4. **Bound work per request**, not only per match: limit how many user patterns run against one input, and how many inputs one pattern runs against.

## 5. Where the guarantee ends

- **Other engines.** Ports of backtracking engines (e.g. `github.com/dlclark/regexp2`, chosen for .NET/PCRE compatibility) reintroduce ReDoS; if one is unavoidable, set its `MatchTimeout`. The same applies to patterns shipped to browsers (JavaScript) or to databases (`REGEXP` in SQL engines), where Go's guarantee does not travel.
- **`FindAll*` with n = -1** allocates one result per match; cap `n` or the input.
- **`MatchReader` / `FindReaderIndex`** read from an `io.RuneReader` until a match or EOF; wrap the reader in `io.LimitReader`.
- **Memory.** Large Unicode classes (`\p{L}`) and many alternatives compile to few instructions but large rune-range tables; the instruction cap does not bound that exactly. Keep the source-length cap too.
- **Correctness ≠ safety.** A linear-time regexp that accepts `../` or `javascript:` is still wrong; regexps are a poor fit for URL, path or HTML validation (chapters 25, 26, 31).

## 6. Verification

```bash
go test -v ./Security/36_regexp-redos/
go test -run '^$' -bench Catastrophic ./Security/36_regexp-redos/   # linear scaling
```

| Test | Shows |
|---|---|
| `TestCatastrophicPatternsAreLinear` | `(a+)+$` and friends on 100 001 bytes finish within a 1 s budget (milliseconds in practice, also under `-race`) |
| `TestBacktrackingFeaturesRejected` | Backreferences, lookaround, atomic/possessive, repeat counts > 1000, nested repeats, nesting depth |
| `TestMatchUserPatternUnsafePanics` | `MustCompile("(")` panics |
| `TestCompileUserPattern` | Length, syntax and program-size limits; harmless-in-RE2 `(a+)+$` accepted |
| `TestProgramSizeGrowsWithRepeats` | `a{1000}` costs ~100× the instructions of `a{10}` |
| `TestMatchBounded`, `TestIsValidEmail` | Input caps applied before matching |
| `TestCompileOnceAllocations` | Compiling per call allocates on every request; a precompiled regexp does not |
| `BenchmarkCatastrophic` | Time per byte stays flat as input grows |
| `ExampleCompileUserPattern` | Accepted and rejected patterns with their errors |

## 7. Checklist

- [ ] Every constant pattern is compiled once at package level.
- [ ] No `MustCompile` on anything that is not a compile-time constant.
- [ ] Inputs are length-capped before matching; readers are wrapped in `io.LimitReader`.
- [ ] User-supplied patterns go through length + program-size limits and `regexp.Compile`.
- [ ] Backtracking regexp libraries are flagged in review and run with a timeout.

## References

- Package [`regexp`](https://pkg.go.dev/regexp), [`regexp/syntax`](https://pkg.go.dev/regexp/syntax) (RE2 syntax and error codes)
- Russ Cox — [Regular Expression Matching Can Be Simple And Fast](https://swtch.com/~rsc/regexp/regexp1.html) (2007), [Regular Expression Matching: the Virtual Machine Approach](https://swtch.com/~rsc/regexp/regexp2.html)
- [CVE-2022-24921](https://nvd.nist.gov/vuln/detail/CVE-2022-24921) (regexp stack exhaustion on deep nesting), [CVE-2022-41715](https://nvd.nist.gov/vuln/detail/CVE-2022-41715) (regexp/syntax memory exhaustion)
- OWASP — [Regular expression Denial of Service](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- Cloudflare — [Details of the Cloudflare outage on July 2, 2019](https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/) (a backtracking WAF regexp)
