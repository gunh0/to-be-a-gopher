# 43. Build Provenance & Reproducibility

> **Abstract.** Every Go binary carries a machine-readable record of how it was built: main module and version, every dependency with its `go.sum` hash, the Go version, the VCS revision and whether the tree was modified, and the build flags. `go version -m` prints it, `runtime/debug.ReadBuildInfo` returns it, and it survives `-ldflags=-s -w`. That record is the raw material of provenance — answering "which source produced this artefact?" — and, together with `-trimpath` and a toolchain that has been bit-for-bit reproducible since Go 1.21, the basis for reproducible builds. Served carelessly on a `/version` endpoint, the same record is a vulnerability lookup table and can contain build-machine paths and `-X`-injected secrets.

| | |
|---|---|
| Weaknesses | [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) Reliance on Insufficiently Trustworthy Component, [CWE-494](https://cwe.mitre.org/data/definitions/494.html) Download of Code Without Integrity Check, [CWE-200](https://cwe.mitre.org/data/definitions/200.html) Exposure of Sensitive Information to an Unauthorized Actor |
| Go packages | `runtime/debug`, `net/http`, `cmd/go` (`-trimpath`, `-buildvcs`, `go version -m`) |
| Code | [`version.go`](version.go), [`version_test.go`](version_test.go), [`testdata/release.txt`](testdata/release.txt), [`testdata/dev.txt`](testdata/dev.txt) |

## 1. Threat model

Two adversaries. A **supply-chain attacker** who can tamper with a build (a compromised CI runner, a developer laptop producing "release" binaries, an altered artefact in a registry) and relies on nobody being able to tell which source a binary came from. A **reconnaissance attacker** who reads public endpoints and error pages to learn the Go version and dependency versions, then picks matching CVEs (chapter 40).

## 2. What Go records

`go version -m ./server` on a release build:

```
server: go1.25.3
	path	example.com/app/cmd/server
	mod	example.com/app	v1.8.0
	dep	golang.org/x/crypto	v0.42.0	h1:chiH31gI…
	build	-trimpath=true
	build	CGO_ENABLED=0
	build	vcs.revision=4f2c9a71d0e8…
	build	vcs.time=2025-10-01T12:00:00Z
	build	vcs.modified=false
```

| Item | Since | Notes |
|---|---|---|
| Module path, version, deps with `h1:` sums, `=>` replacements | Go 1.12 (`ReadBuildInfo`) | Same hashes as `go.sum`; usable for SBOMs and govulncheck `-mode binary` |
| `Settings`: `-buildmode`, `-compiler`, `-tags`, `-race`, `CGO_ENABLED`, `GOOS`, `GOARCH`, `GOAMD64`… | Go 1.18 | `debug.ParseBuildInfo` (1.18) parses the `String()` form back, except `GoVersion` |
| `vcs`, `vcs.revision`, `vcs.time`, `vcs.modified` | Go 1.18 (`-buildvcs=auto` default) | Absent with `-buildvcs=false` or outside a repository |
| Main module version from VCS tag or pseudo-version, `+dirty` suffix | Go 1.24 | Previously `(devel)` for builds in the main module |
| `-ldflags`, `CGO_*FLAGS` | Go 1.18 | **Recorded only without `-trimpath`** (go.dev/issue/52372: they may contain paths); `-X` values are in the binary's data either way |
| `-trimpath` | Go 1.13 | Removes file system paths from the binary and build info |

**Reproducibility.** Since Go 1.21 the Go toolchain distributions are perfectly reproducible and independently verified (`golang.org/x/build/cmd/gorebuild`). Your own binaries are reproducible when the inputs are fixed: same toolchain version, same source revision, `-trimpath`, `CGO_ENABLED=0` (cgo pulls in the host C toolchain and headers), same `GOOS`/`GOARCH`/`GO*` variables and flags. Two parties building the same tag can then compare SHA-256 hashes.

## 3. Insecure pattern

```go
func HandlerUnsafe(bi *debug.BuildInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(bi.String()))
	})
}
```

For a build made on a developer machine (`testdata/dev.txt`) this publishes, unauthenticated: `go1.25.1` (every stdlib fix after it is missing), the full dependency list, `-ldflags="-X main.stripeKey=sk_live_…"`, `CGO_CFLAGS=-I/home/dev/…`, a local `=> /home/dev/src/billing` replacement, and `-race=true`. Injecting secrets with `-X` is a CWE-798 problem on its own: the value is a string constant in the binary that `strings` finds.

Release processes fail in the quieter way: a binary built from a dirty tree, without VCS stamping, or with race instrumentation ships because nothing looked.

## 4. Secure pattern

[`version.Handler`](version.go) splits the record:

| View | Fields | Audience |
|---|---|---|
| `Public()` | `version`, `revision`, `time` | Anyone: enough to identify the build and open the exact commit |
| `Redacted()` | Everything, with `-ldflags`, `-gcflags`, `-asmflags`, `CGO_*` replaced by `[REDACTED]` | Operators and inventory systems, behind an `authorized(r)` decision (mTLS, internal network, admin token) |

[`ReleaseProblems`](version.go) is a pre-release gate over the same record (run it against `go version -m` output of the artefact, or at startup with `version.Read()`): missing `vcs.revision`, `vcs.modified=true` or `+dirty`, `(devel)` version, missing `-trimpath`, `-race`/`-cover`/`-asan`/`-msan`, recorded `-X` flags, replaced dependencies.

Release build recipe:

```bash
CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=local \
  go build -trimpath -o server ./cmd/server     # -buildvcs=auto by default
go version -m server                            # inspect, then gate
sha256sum server                                # publish alongside the provenance
```

`-ldflags=-s -w` (strip symbol table and DWARF) shrinks binaries; build info, panic stack traces (function names and lines come from the runtime's own tables) and `govulncheck -mode binary` keep working, while debuggers and some profilers lose information. It is a size trade-off, not a security control.

Provenance beyond the binary: [SLSA](https://slsa.dev/spec/v1.0/levels) v1.0 Build levels — L1 provenance exists, L2 signed provenance from a hosted build platform, L3 hardened builds whose provenance the tenant cannot forge. GitHub artifact attestations or Sigstore/cosign sign it; SBOMs in CycloneDX or SPDX can be generated from the embedded module list with external tools (e.g. `cyclonedx-gomod`, Syft).

## 5. Where the guarantee ends

- **Build info is self-reported.** A malicious builder can write any `vcs.revision`; only signed provenance from a trusted builder, or an independent reproduction, makes it evidence.
- **`vcs.modified` reflects the repository only.** It follows the VCS status (with git, untracked files also count as modifications); inputs outside the repository — a poisoned module cache, environment variables, the toolchain itself — do not appear (chapter 39: `go mod verify`, `GOTOOLCHAIN`).
- **cgo** breaks reproducibility unless the C toolchain is pinned as well, and its flags are recorded only without `-trimpath`.
- **Version-hiding is not patching.** Removing the Go version from public output slows reconnaissance; it does not fix anything. Patch releases and scheduled `govulncheck -mode binary` scans of deployed artefacts (chapter 40) do.
- **Error pages and headers** can leak the same data (`Server:` headers, stack traces in responses — chapter 07).

## 6. Verification

```bash
go test -v ./Security/43_build-provenance/
```

Fixtures are `debug.BuildInfo.String()` texts parsed with `debug.ParseBuildInfo`; the `go` line is restored by a test helper because `ParseBuildInfo` documents that it does not set `GoVersion`.

| Test | Shows |
|---|---|
| `TestFromBuildInfo` | Version, Go version, VCS revision, modified flag and deps extracted |
| `TestHandlerUnsafeLeaks` | `-X` secret, `/home/dev` paths, dependency list and Go patch level served unauthenticated |
| `TestHandlerPublicView` | Unauthenticated JSON has exactly `version`, `revision`, `time` |
| `TestHandlerAuthorizedViewIsRedacted` | Operators get inventory and Go version, never linker/cgo flags; the original record is not mutated |
| `TestReleaseProblems` | Clean release passes; dirty tree, no `-trimpath`, `-race`, `-X`, local replacement and no-VCS builds are flagged |
| `TestReadRunningBinary` | `version.Read()` works on the test binary |
| `ExampleInfo_Public` | The public JSON document |

## 7. Checklist

- [ ] Release builds use `-trimpath`, `CGO_ENABLED=0` where possible, a pinned toolchain, and VCS stamping.
- [ ] A gate rejects artefacts with `vcs.modified=true`, missing revision, instrumentation or replacements.
- [ ] Public version endpoints show version and revision only; full build info is authenticated and redacted.
- [ ] No secrets are injected with `-ldflags -X`; configuration is loaded at runtime (chapter 38).
- [ ] Artefact hashes and signed provenance are published; at least one independent rebuild is compared.
- [ ] Deployed binaries are inventoried with `go version -m` and rescanned for vulnerabilities.

## References

- [`runtime/debug.BuildInfo`](https://pkg.go.dev/runtime/debug#BuildInfo), [`ReadBuildInfo`](https://pkg.go.dev/runtime/debug#ReadBuildInfo), [`ParseBuildInfo`](https://pkg.go.dev/runtime/debug#ParseBuildInfo); `go help build` (`-trimpath`, `-buildvcs`), [`go version`](https://pkg.go.dev/cmd/go#hdr-Print_Go_version)
- Release notes: [Go 1.18](https://go.dev/doc/go1.18) (VCS stamping, build settings), [Go 1.24](https://go.dev/doc/go1.24) (main module version from VCS)
- Go Blog — [Perfectly Reproducible, Verified Go Toolchains](https://go.dev/blog/rebuild) (2023)
- [go.dev/issue/52372](https://go.dev/issue/52372) (`-ldflags` and cgo flags omitted with `-trimpath`)
- [SLSA v1.0 — Security levels](https://slsa.dev/spec/v1.0/levels); [Reproducible Builds](https://reproducible-builds.org/)
