# 17. FIPS 140-3 Mode

> **Abstract.** Since Go 1.24 the standard library contains the Go Cryptographic Module, a FIPS 140-3 module selected at build time with `GOFIPS140` and switched on at run time with `GODEBUG=fips140=on` (approved implementations, self-tests, approved DRBG, restricted TLS) or `fips140=only` (non-approved algorithms additionally fail). Compliance is a property of the *process*, decided once at startup, and the most common failure is not cryptographic at all: the flag is missing in one deployment and the service runs anyway. The fix is a startup gate that refuses to run, plus knowing exactly what the module does not cover — `golang.org/x/crypto` runs happily even in `only` mode.

| | |
|---|---|
| Weaknesses | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) Use of a Broken or Risky Cryptographic Algorithm, [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) Initialization of a Resource with an Insecure Default |
| Go packages | `crypto/fips140` (1.24), `crypto/cipher`, `crypto/md5`, `golang.org/x/crypto/chacha20poly1305` (to show the boundary) |
| Code | [`fipsmode.go`](fipsmode.go), [`fipsmode_test.go`](fipsmode_test.go) |

## 1. Threat model

The adversary here is mostly an auditor, and occasionally a real one. A regulated deployment (FedRAMP, US federal, some financial and healthcare contracts) must use validated cryptographic modules. The risk is a binary built or launched without FIPS mode, a code path using a non-approved algorithm, or a dependency doing its own cryptography outside the module — each producing a system that claims compliance it does not have.

## 2. What Go provides

| Control | When | Values | Effect |
|---|---|---|---|
| `GOFIPS140` | Build (`go build`) | `off` (default), `latest`, `v1.0.0`, or an alias such as `inprocess` | Selects the module source: the current tree or a frozen snapshot under validation. Any value other than `off` also makes `fips140=on` the binary's default |
| `GODEBUG=fips140` | Process start (env, `godebug` in `go.mod`, `//go:debug` in main) | `off`, `on`, `only` | Fixed at startup; later changes to `GODEBUG` are ignored |
| `crypto/fips140.Enabled()` | Run time | bool | True for `on` and `only`; panics if the module's integrity self-check did not pass |

What `on` changes, per the Go 1.24/1.25 implementation:

- Power-on integrity check and known-answer self-tests for the module's algorithms.
- `crypto/rand` output goes through an SP 800-90A DRBG seeded from the OS.
- `crypto/tls` filters its defaults and the configured lists down to approved choices: TLS 1.2 and 1.3; AES-GCM suites (no ChaCha20-Poly1305); P-256/P-384/P-521 and X25519MLKEM768; RSA ≥ 2048-bit, ECDSA on NIST curves, or Ed25519 certificates.

What `only` adds: non-approved operations return errors or panic. `TestModes` observes, in each mode:

| Operation | `off` | `on` | `only` |
|---|---|---|---|
| `cipher.NewGCM` (caller nonce) | ok | ok | error: use `NewGCMWithRandomNonce` |
| `cipher.NewGCMWithRandomNonce` | ok | ok | ok |
| `md5.New().Write` | ok | ok | error |
| `sha256` | ok | ok | ok |
| `x/crypto/chacha20poly1305.NewX` | ok | ok | **ok** |

Other `only`-mode restrictions in the standard library include `crypto/pbkdf2` and `crypto/hkdf` key-length minimums (chapters 12 and 14) and ECDSA signing only with `crypto/rand.Reader`. Go 1.25 offers no API that reports `only`; [`Current`](fipsmode.go) probes it with `cipher.NewGCM`, a stopgap documented as such.

**Validation status.** Go Cryptographic Module v1.0.0 is the snapshot frozen with Go 1.24 (`GOFIPS140=v1.0.0`). The Go project reported in 2025 that its algorithms passed CAVP testing and that the module was submitted to NIST's CMVP and is on the *Modules In Process* list; the Go 1.25 toolchains define the `inprocess` alias as `v1.0.0` and ship no `certified` alias. "Uses the Go Cryptographic Module in FIPS mode" is therefore not the same statement as "uses a module with a CMVP certificate". Check the CMVP database for the current status before writing either sentence into a compliance document. Alternatives with their own validation stories exist (Go+BoringCrypto via `GOEXPERIMENT=boringcrypto`; vendor toolchains that call OpenSSL).

## 3. Insecure pattern

[`Policy.CheckUnsafe`](fipsmode.go) notices the missing mode and logs:

```go
if p.RequireFIPS && !s.Enabled {
	logf("WARNING: FIPS mode is not enabled")
}
// ...and main() continues
```

One Helm chart without the `GODEBUG` variable, one Dockerfile with a different build command, and the fleet is partly non-compliant with a log line as the only evidence. The default (`off`) wins whenever a setting is forgotten (CWE-1188).

The second trap is believing `only` means "nothing non-approved can run". It polices the standard library's cryptographic packages. Code in `golang.org/x/crypto` (Argon2, bcrypt, XChaCha20-Poly1305), cgo libraries and hand-written cryptography run as before (`TestModes`, last row).

## 4. Secure pattern

[`Policy.Check`](fipsmode.go) is a startup gate:

```go
func main() {
	if err := (fipsmode.Policy{RequireFIPS: cfg.FIPS}).Check(fipsmode.Current()); err != nil {
		log.Fatal(err) // refuse to start
	}
	// ...
}
```

1. **Make FIPS the binary's default**, not an environment variable someone can forget: build with `GOFIPS140=v1.0.0` (validated snapshot) or put `//go:debug fips140=on` in package main.
2. **Gate startup** on the policy; exit non-zero. Readiness probes then catch misconfiguration at deploy time.
3. **Test in FIPS mode** in CI (`GODEBUG=fips140=on go test ./...`); `only` mode is a good way to find non-approved standard-library calls in tests, keeping the boundary limits above in mind.
4. **Inventory crypto outside the module**: `go list -deps` for `golang.org/x/crypto/...` and cgo. Chapter 12's Argon2id and chapter 13's XChaCha20-Poly1305 are examples of what must be replaced (PBKDF2, AES-GCM) in a FIPS build.
5. **Use the FIPS-shaped APIs** even when not required: `NewGCMWithRandomNonce`, `crypto/hkdf`, `crypto/pbkdf2`, `crypto/mlkem`. The same code then works in both modes.

## 5. Where the guarantee ends

- **Module boundary.** Only `crypto/internal/fips140/...` is the module; the public `crypto/...` packages route into it. Anything else is outside.
- **Operational requirements** (key management, entropy assessment, physical security, the security policy document) are not provided by a compiler flag.
- **`only` enforces the checks that exist** in the standard library at that release. Treat it as a test aid, not as proof of an approved-only process.
- **Platform**: validation covers specific operating environments listed in the certificate's security policy.

## 6. Verification

```bash
go test -race -v ./Security/17_fips-140-3/
```

| Test | Shows |
|---|---|
| `TestModes` | Re-executes the test binary with `fips140=off/on/only` and records `Enabled`, the policy result and which algorithms fail |
| `TestSettingIsFixedAtStartup` | Setting `GODEBUG` at run time does not change the mode |
| `TestPolicyCheck` | The gate's decision table, including `RequireEnforce` |
| `TestCheckUnsafeOnlyWarns` | The anti-pattern produces one log line and no failure |
| `ExamplePolicy_Check` | The error message points at the fix |

The subprocess pattern (`TestMain` checks an environment variable and acts as the child) is required because `fips140` cannot be changed inside a running process.

Proposed CI addition: run the suite once more with `GODEBUG=fips140=on` (see the final report for the exact job).

## 7. Checklist

- [ ] FIPS deployments build with `GOFIPS140=v1.0.0` (or `//go:debug fips140=on`), not only an environment variable.
- [ ] `main` refuses to start when policy requires FIPS and `fips140.Enabled()` is false.
- [ ] CI runs tests with `GODEBUG=fips140=on`.
- [ ] `golang.org/x/crypto`, cgo crypto and custom primitives are inventoried and justified or replaced.
- [ ] Compliance documents state the module version and its CMVP status as checked on a date.

## References

- Go — [FIPS 140-3 Compliance](https://go.dev/doc/security/fips140)
- Go Blog — [The FIPS 140-3 Go Cryptographic Module](https://go.dev/blog/fips140) (2025)
- [`crypto/fips140`](https://pkg.go.dev/crypto/fips140), [Go 1.24 release notes](https://go.dev/doc/go1.24), [GODEBUG history](https://go.dev/doc/godebug)
- NIST CMVP — [Modules In Process List](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list), [validated modules search](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search)
- NIST [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final); SP 800-140C (approved security functions)
