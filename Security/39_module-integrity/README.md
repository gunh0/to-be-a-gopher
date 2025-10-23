# 39. Module Integrity

> **Abstract.** Go's module system answers "are these the bytes everyone else got?" with unusual rigour: `go.sum` pins a hash of every module version, and the checksum database (`sum.golang.org`) is an append-only transparency log, so a proxy or origin cannot serve one user different code for the same version. It does not answer "should this code be in my build?". A typosquat is checksummed as faithfully as the real module — the backdoored `github.com/boltdb-go/bolt` stayed available from the module proxy for years — and a `replace` directive can swap the code behind an allowlisted path without changing a single `require` line. This chapter separates what the toolchain verifies from what a dependency policy must check, and implements that policy gate over `go list -m -json all` and embedded build info.

| | |
|---|---|
| Weaknesses | [CWE-494](https://cwe.mitre.org/data/definitions/494.html) Download of Code Without Integrity Check, [CWE-829](https://cwe.mitre.org/data/definitions/829.html) Inclusion of Functionality from Untrusted Control Sphere, [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) Reliance on Insufficiently Trustworthy Component |
| Go packages | `cmd/go` (modules), `encoding/json`, `runtime/debug` |
| Code | [`modcheck.go`](modcheck.go), [`modcheck_test.go`](modcheck_test.go), [`testdata/golist.json`](testdata/golist.json), [`testdata/buildinfo.txt`](testdata/buildinfo.txt) |

## 1. Threat model

The attacker wants their code compiled into your binary. Routes: publish a lookalike module and wait for a typo or a careless AI-suggested import (typosquatting); take over an abandoned GitHub account or renamed repository that a module path still points to (repo-jacking); compromise a maintainer and tag a malicious release; or get a `replace` directive or toolchain change merged in a large pull request. The defender controls `go.mod`, `go.sum`, CI and environment variables.

## 2. What Go guarantees

| Mechanism | Guarantees | Does not guarantee |
|---|---|---|
| `go.sum` | Every module zip and `go.mod` matches the `h1:` hash recorded when it was first added | That the first download was benign |
| Checksum database (`GOSUMDB`, default `sum.golang.org`) | The hash for `path@version` is the one in a public Merkle-tree log; the `go` command verifies inclusion and consistency proofs, so targeted or retroactive substitution is detectable | Anything about the content's intent |
| Module proxy (`GOPROXY`, default `https://proxy.golang.org,direct`) | Availability; versions are immutable once cached | Removal of malicious versions you already depend on |
| `-mod=readonly` (default for builds since Go 1.16) | Builds fail instead of silently editing `go.mod`/`go.sum` | Review of edits made by `go get` / `go mod tidy` |
| `go mod verify` | Module cache contents still match `go.sum` (no local tampering) | Anything about upstream |
| `replace` | Honoured only in the main module's `go.mod` (and `go.work`), ignored in dependencies | Visibility: the `require` line is unchanged |
| `retract` (Go 1.16) | Authors can mark bad versions; `go get` avoids them on upgrade, `go list -m -u` reports them | Removal: pinned retracted versions still build |
| `GOTOOLCHAIN` (Go 1.21) | A newer toolchain named by `go`/`toolchain` lines is downloaded as the module `golang.org/toolchain` and checksum-verified | That you wanted a toolchain change; `GOTOOLCHAIN=local` disables switching |

Environment knobs that weaken the defaults: `GOSUMDB=off`, `GONOSUMDB`/`GOPRIVATE` patterns (skip the checksum database for matching paths; `go.sum` still applies), `GONOPROXY`, `GOINSECURE` (allows plain HTTP for matching paths), `GOFLAGS=-mod=mod`. In CI they should be set explicitly and reviewed like code.

**Case study.** In February 2025 Socket reported `github.com/boltdb-go/bolt`, a typosquat of the widely used `github.com/boltdb/bolt` carrying a remote-access backdoor. The backdoored version had been cached by the Go module proxy since 2021; the attacker later rewrote the git tag to point to clean code, so inspecting the repository showed nothing while `go get` kept serving the cached malicious version. Every integrity mechanism above worked as designed.

## 3. Insecure pattern

The typical dependency allowlist checks the `require` path:

```go
for _, m := range mods {
	if !m.Main && !p.allowed(m.Path) { ... }   // CheckNaive
}
```

With this `go.mod`, it reports nothing:

```
require github.com/sirupsen/logrus v1.9.3        // allowlisted
replace github.com/sirupsen/logrus => github.com/attacker/logrus v1.9.3
replace github.com/example/shared  => ../shared  // not in go.sum, differs per machine
```

`go list -m -json all` reports the replacement in the `Replace` field; the naive check never looks there. Pseudo-versions (`v0.0.0-20250911093012-4f2c9a71d0e8`) and retracted versions pass for the same reason.

## 4. Secure pattern

[`Check`](modcheck.go) evaluates the module whose code is compiled:

| Finding | Trigger |
|---|---|
| `replace` | Any replacement (unless `AllowReplace`), target still checked against the allowlist |
| `local-replace` | Replacement by a directory (`Replace.Version == ""`, `(devel)` in build info); never allowed |
| `not-allowed` | Effective path outside the allowlist (exact paths, or prefixes ending in `/`) |
| `lookalike` | Not allowed, but same final path element as an allowlisted module (`boltdb-go/bolt` vs `boltdb/bolt`, major-version suffix ignored) |
| `pseudo-version` | Untagged commit, per the `golang.org/x/mod` pseudo-version grammar |
| `retracted`, `deprecated` | Populated by `go list -m -u -json all` |

Input comes from either source:

```bash
go list -m -u -json all > modules.json                  # source tree
go version -m ./bin/server                              # shipped binary
```

`ParseList` fails closed (empty or malformed input is an error, never "no findings"), and `FromBuildInfo` accepts `runtime/debug.ReadBuildInfo()` or `debug.ParseBuildInfo` output so the gate can run against the artefact that ships.

Operational rules:

1. Commit `go.sum`; never run CI with `GOSUMDB=off`, `GOFLAGS=-mod=mod` or broad `GONOSUMDB`.
2. Set `GOPRIVATE` narrowly (`github.com/yourorg/*`), not to `*`.
3. Pin the toolchain: `GOTOOLCHAIN=local` in CI, or review every `toolchain` line change.
4. Review `go.mod` diffs as code: new modules, `replace`, `go`/`toolchain` lines.
5. Prefer the Go 1.24 `tool` directive (`go get -tool`) over `go run pkg@latest` for build tools, so they are pinned in `go.mod`/`go.sum`.

## 5. Where the guarantee ends

- **First use is trust on first use.** The checksum database proves consistency, not safety. New dependencies need human review, or at least a lookalike/allowlist gate.
- **Repo-jacking** affects new versions and pseudo-versions of a path whose owner changed; cached versions stay intact. Prefer vanity import paths you control for your own modules.
- **Vendoring** (`go mod vendor`) moves the review surface into the repository; `go mod verify` does not check `vendor/`, while builds check `vendor/modules.txt` against `go.mod`.
- **cgo, `//go:generate` and build tools** run code at build time; a dependency's `go generate` is not run automatically, but tools you invoke are.
- **Known-vulnerable but legitimate** versions are a separate question (chapter 40). Provenance of your own binaries is chapter 43.

## 6. Verification

```bash
go test -v ./Security/39_module-integrity/
```

| Test | Shows |
|---|---|
| `TestParseList`, `TestParseListFailsClosed` | Concatenated JSON stream parsed; empty, truncated, non-JSON and path-less input rejected |
| `TestCheckNaiveMissesReplacements` | The path-only allowlist catches the typosquat and nothing else |
| `TestCheck` | Fork replacement, local replacement, pseudo-version, retraction, deprecation and lookalike all reported |
| `TestCheckAllowReplaceStillChecksTarget` | Allowing `replace` still checks the target; local replacements stay forbidden |
| `TestIsPseudoVersion` | All three pseudo-version forms, `+incompatible`, and near-misses |
| `TestLookalikeIgnoresMajorVersion` | `goog1e/uuid/v2` is flagged against `google/uuid` |
| `TestFromBuildInfo` | The same policy over `debug.ParseBuildInfo` of a `go version -m`-style fixture |
| `TestRunningBinary` | This repository's own test binary has no replace or pseudo-version findings |
| `ExampleCheck` | Naive check: 0 findings; `Check`: replace + lookalike |

## 7. Checklist

- [ ] `go.sum` is committed; CI runs with default `GOPROXY`/`GOSUMDB` and `-mod=readonly`.
- [ ] `GOPRIVATE`/`GONOSUMDB` cover only your own module paths.
- [ ] CI fails on `replace` directives, local replacements and unreviewed pseudo-versions.
- [ ] New module paths are checked against an allowlist and for lookalikes.
- [ ] `go mod verify` runs in CI; `GOTOOLCHAIN` is pinned.
- [ ] Release binaries are checked with `go version -m` against the same policy.

## References

- Go Modules Reference — [Authenticating modules](https://go.dev/ref/mod#authenticating), [Module proxies](https://go.dev/ref/mod#module-proxy), [Private modules](https://go.dev/ref/mod#private-modules), [`replace`](https://go.dev/ref/mod#go-mod-file-replace), [`retract`](https://go.dev/ref/mod#go-mod-file-retract), [`go mod verify`](https://go.dev/ref/mod#go-mod-verify)
- Go documentation — [Go Toolchains](https://go.dev/doc/toolchain); `go help list` (Module struct)
- Russ Cox — [Transparent Logs for Skeptical Clients](https://research.swtch.com/tlog) (2019); [Go Checksum Database proposal](https://go.googlesource.com/proposal/+/master/design/25530-sumdb.md)
- Go Blog — [How Go Mitigates Supply Chain Attacks](https://go.dev/blog/supply-chain) (2022)
- Socket — "Go Supply Chain Attack: Malicious Package Exploits Go Module Proxy Caching for Persistence" (February 2025)
