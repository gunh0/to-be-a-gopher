# 41. Static Analysis for Security

> **Abstract.** Go is unusually friendly to static analysis: one parser and type checker in the standard library (`go/parser`, `go/ast`, `go/types`), one analysis framework (`golang.org/x/tools/go/analysis`) shared by `go vet`, gopls and staticcheck, and a culture of gofmt-canonical code. Security value comes from three layers: `go vet` (correctness bugs that become security bugs — lost cancels, copied locks, bad format strings, too-new APIs), staticcheck (deeper bug patterns, deprecated APIs), and gosec (security-specific heuristics such as `InsecureSkipVerify`, weak hashes, subprocess and file inclusion). The difference between a useful rule and noise is mostly whether it understands the code's structure; this chapter shows that with a small `go/ast` checker next to the `grep` it replaces.

| | |
|---|---|
| Weaknesses | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) Improper Certificate Validation (rule SEC001), [CWE-338](https://cwe.mitre.org/data/definitions/338.html) Use of Cryptographically Weak PRNG (rule SEC002), [CWE-1006](https://cwe.mitre.org/data/definitions/1006.html) Bad Coding Practices |
| Go packages | `go/ast`, `go/parser`, `go/token`; tools: `go vet`, `staticcheck`, `gosec` |
| Code | [`seclint.go`](seclint.go), [`seclint_test.go`](seclint_test.go), [`testdata/`](testdata/) (fixture packages) |

## 1. Threat model

Not an attacker but a process: insecure patterns enter through copy-paste ("just skip verify for now"), rushed fixes, and dependencies. Review catches some; tooling that runs on every change catches the mechanical ones consistently. The risk of tooling is noise: a check that fires on comments or test fixtures trains developers to ignore it.

## 2. What the toolchain provides

**`go vet`** runs on every `go test` (a subset) and via `go vet ./...` (all analyzers). The security-relevant ones in Go 1.25:

| Analyzer | Catches | Why it matters |
|---|---|---|
| `printf` | Format/argument mismatches; since Go 1.24 also `Printf(s)` with a non-constant format and no args | Format-string bugs, garbled logs (chapter 37) |
| `copylocks` | `sync.Mutex` and friends copied by value | Silent loss of mutual exclusion → data races (chapter 04) |
| `lostcancel` | `cancel` from `context.WithCancel/Timeout` not called on all paths | Goroutine and timer leaks (chapter 06) |
| `loopclosure` | Loop variable captured by goroutine/defer | Since Go 1.22 loop variables are per-iteration; the analyzer only reports in files whose language version is older |
| `httpresponse` | `resp.Body` used before checking `err` | Nil dereference → panic (chapter 05) |
| `stdversion` (Go 1.23) | Standard-library symbols newer than the `go` line in `go.mod` | Builds that silently need a newer toolchain; this repository relies on it |
| `waitgroup` (Go 1.25) | `wg.Add` called inside the goroutine it counts | `Wait` can return early: use-before-ready races |
| `hostport` (Go 1.25) | `fmt.Sprintf("%s:%d", host, port)` passed to `net.Dial` | Breaks on IPv6 literals; use `net.JoinHostPort` (chapter 27) |
| `unsafeptr`, `errorsas`, `unusedresult`, `slog` | Invalid `uintptr` conversions, `errors.As` misuse, discarded results, odd key/value lists | Memory safety (chapter 01), error handling, logging |

**staticcheck** (2025.1.1, module version v0.6.1) adds checks such as SA1019 (use of deprecated identifiers — e.g. deprecated crypto APIs), SA5011 (possible nil pointer dereference), SA4006 (value overwritten before use — often a dropped `err`), SA1012 (nil `context.Context`), SA1029 (bad `context.WithValue` key type), SA2002 (`t.FailNow` from a goroutine).

**gosec** encodes security heuristics; rules worth knowing by ID:

| Rule | Pattern | Chapter |
|---|---|---|
| G101 | Hard-coded credentials | 38 |
| G104 | Unchecked errors | 07 |
| G107 | HTTP request URL from a variable | 27 |
| G112 | `http.Server` without `ReadHeaderTimeout` (Slowloris) | 21 |
| G115 | Integer conversion that can overflow | 02 |
| G204 | Subprocess launched with variable arguments | 33 |
| G304 | File path from a variable (file inclusion) | 31 |
| G401 / G501 | Weak hash or cipher (MD5, SHA-1, DES, RC4) / blocklisted crypto import | 10 |
| G402 | Bad TLS settings, including `InsecureSkipVerify: true` | 19 |

## 3. Insecure pattern

The first "security check" in many repositories is a grep:

```bash
grep -rn 'InsecureSkipVerify: true' .
```

[`GrepCheck`](seclint.go) is that grep. On the [`tlsclient`](testdata/tlsclient/client.go) fixture it reports a **comment** and a **string constant** (false positives) and misses `InsecureSkipVerify: skip` and `cfg.InsecureSkipVerify = true` (false negatives). On the [`token`](testdata/token/) fixture — `math/rand` in `token.go`, `crypto/hmac` in `sign.go` — a per-file grep cannot connect the two and reports nothing.

## 4. Secure pattern

[`seclint`](seclint.go) parses each package with `go/parser` and walks the AST:

- **SEC001** — resolves the local name of `crypto/tls` (alias, dot import), matches composite literals of `tls.Config`, and reports `InsecureSkipVerify` unless its value is literally `false`; a non-constant value is reported as "review". Assignments to a field named `InsecureSkipVerify` are reported too.
- **SEC002** — package-wide: `math/rand` or `math/rand/v2` imported anywhere in a package that imports a crypto primitive (`crypto/*` except `crypto/tls`/`crypto/x509`, or `golang.org/x/crypto/*`).

Comments and strings are invisible to an AST walk, so the checker is quiet on its own source (`TestSelfCheck`) while grep is not.

**Proposed Makefile target and CI step:**

```make
STATICCHECK ?= honnef.co/go/tools/cmd/staticcheck@2025.1.1

lint:
	$(GO) run $(STATICCHECK) ./...
```

```yaml
      - name: staticcheck
        run: make lint
```

`make vet` (already in CI) covers the `go vet` analyzers. gosec can be added the same way at a pinned version; triage its findings once and annotate accepted ones (`#nosec G402 -- reason`) rather than disabling rules.

## 5. Where the guarantee ends

- **Syntax-only checks** cannot follow types or data flow: `type C = tls.Config`, a config built by a helper in another package, or `skip := true` two functions away. Production rules should be `go/analysis` passes with `go/types` information (what vet, staticcheck and gosec are), and taint-style questions (G107, G304) need data-flow analysis that all of these tools approximate.
- **Heuristics fire on tests and fixtures.** Exclude `testdata/` and generated code deliberately, not by turning rules off.
- **Absence of findings is not evidence of safety.** None of these tools reason about authorisation, business logic, or protocol state.
- **Tool supply chain.** Running `go run tool@version` executes downloaded code in CI; pin versions and rely on the checksum database (chapter 39). Go 1.24's `tool` directive records tools in `go.mod`.
- **Runtime checks complement static ones:** the race detector (chapter 04), fuzzing (chapter 42) and `govulncheck` (chapter 40).

## 6. Verification

```bash
go test -v ./Security/41_static-analysis/
```

| Test | Shows |
|---|---|
| `TestTLSFixture` | Aliased import, non-constant value and assignment reported; explicit `false` and comments not |
| `TestGrepCheckOnTLSFixture` | Grep: 2 false positives (comment, string), 2 false negatives |
| `TestWeakRandIsPackageWide` | `math/rand` + `crypto/hmac` in different files found by AST, missed by grep |
| `TestCleanFixture` | `math/rand/v2` for jitter next to `crypto/tls`, default TLS config: no findings |
| `TestDotImport` | `import . "crypto/tls"` resolved |
| `TestSelfCheck` | No AST findings on the checker's own source; grep reports its comments |
| `ExampleCheckDir` | Diagnostics in `file:line: rule message` form |

## 7. Checklist

- [ ] `go vet ./...` and `staticcheck` run in CI at pinned versions and block merges.
- [ ] gosec (or equivalent) runs with findings triaged; suppressions carry a rule ID and reason.
- [ ] `go.mod`'s `go` line is accurate so `stdversion` and `loopclosure` reason about the right language version.
- [ ] Custom rules use the AST/types, not text search, and have fixture tests for both positives and negatives.
- [ ] Generated code and fixtures are excluded explicitly.

## References

- [`cmd/vet`](https://pkg.go.dev/cmd/vet) and analyzer docs under [`golang.org/x/tools/go/analysis/passes`](https://pkg.go.dev/golang.org/x/tools/go/analysis/passes); release notes for [Go 1.22](https://go.dev/doc/go1.22) (loop variables), [Go 1.24](https://go.dev/doc/go1.24) (printf), [Go 1.25](https://go.dev/doc/go1.25) (waitgroup, hostport)
- Go Blog — [Fixing For Loops in Go 1.22](https://go.dev/blog/loopvar-preview) (2023)
- [Staticcheck checks](https://staticcheck.dev/docs/checks/); [gosec rules](https://github.com/securego/gosec#available-rules)
- Packages [`go/ast`](https://pkg.go.dev/go/ast), [`go/parser`](https://pkg.go.dev/go/parser); [`golang.org/x/tools/go/analysis`](https://pkg.go.dev/golang.org/x/tools/go/analysis)
