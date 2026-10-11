<p align="center"><img src="README.assets/golang-logo.png"></p>

<p align="center">
  <a href="https://github.com/gunh0/to-be-a-gopher/actions/workflows/ci.yml"><img src="https://github.com/gunh0/to-be-a-gopher/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <img src="https://img.shields.io/badge/go-1.25-00ADD8?logo=go&logoColor=white" alt="go 1.25">
  <img src="https://img.shields.io/badge/Secure%20Go-43%20chapters-2E7D32" alt="43 chapters">
</p>

# To Be a Gopher

A Go notebook that started with first programs in 2021 and grew into **Secure Go**, a series of 43 short white papers on writing Go as a security engineer.

| Part | What it is |
|---|---|
| [Discovery](Discovery/) | Language basics, written while learning Go (2021), plus generics (2024) |
| [Practice](Practice/) | Small programs: multiple returns, raw TCP, HTTP GET (2022) |
| [**Secure Go**](Security/) | 43 chapters, each with a threat model, an insecure and a secure pattern, and tests that prove both (2025) |

<br/>

## Contents

### Discovery

First steps with the language: packages, functions, strings and Hangul, arrays and slices, maps, I/O, generics. Most examples are `Example` tests, so `go test` checks their output.

```bash
$ tree -L 2 Discovery
Discovery
├── 00_WebServer
│   └── main.go
├── 01_TryGo
│   └── main.go
├── 02_Packages
│   ├── README.md
│   ├── fiboMain.go
│   ├── fibonacci
│   └── randomNumber
├── 03_TypeDeduction
│   └── main.go
├── 04_BasicFunction
│   ├── factorial
│   └── hanoi
├── 05_String
│   ├── 1_hangul
│   ├── 2_HasConsonantSuffix
│   ├── 3_Example_printBytes_test.go
│   ├── 4_Modify_printBytes_test.go
│   └── 5_concatenate_test.go
├── 06_Array+Slice
│   ├── 1_Example_array_test.go
│   ├── 2_Example_slicing_test.go
│   ├── 3_Appending_to_a_slice_test.go
│   ├── 4_slice_capacity_test.go
│   ├── 5_slice_duplication_test.go
│   ├── 6_slice_insert_test.go
│   └── 7_stack_test.go
├── 07_Map
│   ├── 1_character_count
│   ├── 2_map_equality
│   ├── 3_maps_test.go
│   └── 4_set_test.go
├── 08_Input+Output
│   └── 1_io_test.go
└── 09_Generics
    └── simple_generic_return.go
```

### Practice

- Getting into Go (`Practice/01_Getting-into-Go`)
  - Multiple returns: `returns/`
  - Named return values: `named_return/`
  - Read TCP status: `read_status/`
  - HTTP GET: `http_get/`

### Secure Go

Each chapter takes one weakness class (with CWE IDs), explains what the Go language, runtime or standard library already guarantees, shows the code that still goes wrong, and backs every claim with runnable tests. Standard library first, Go 1.25 baseline, tests offline.

| Part | Chapters | Topics |
|---|---|---|
| I. Language & Runtime | 01–07 | memory safety and capacity re-slicing, integer overflow, aliasing, data races, panics as DoS, goroutine leaks, error disclosure |
| II. Cryptography | 08–17 | `crypto/rand`, constant-time compare, hash choice, HMAC tokens, Argon2id/PBKDF2, AEAD and nonce reuse, `crypto/hkdf`, signatures, `crypto/mlkem`, FIPS 140-3 mode |
| III. Transport Security | 18–20 | TLS server hardening, client verification and pinning, mutual TLS |
| IV. HTTP Services | 21–30 | timeouts, body limits and gzip bombs, security headers, `http.CrossOriginProtection`, `html/template`, open redirects, SSRF, rate limiting, session cookies, JWT |
| V. Input, Files & Processes | 31–38 | `os.Root` path traversal, zip slip, command injection, SQL injection, `encoding/json` pitfalls, RE2 and ReDoS, log injection, secret redaction |
| VI. Supply Chain & Assurance | 39–43 | module integrity, govulncheck, static analysis, native fuzzing, build provenance |

Full index with CWE mapping: [Security/README.md](Security/README.md)

<br/>

## Getting started

Requires Go 1.25 or later.

```bash
make            # gofmt check, go vet, go test
make race       # tests with the race detector
make lint       # staticcheck
make vuln       # govulncheck
make fuzz       # 10 s fuzz run of the chapter 42 parser
GODEBUG=fips140=on go test ./...   # every test also passes in FIPS 140-3 mode
```

CI runs all of the above on every push: gofmt, vet, staticcheck, race tests, FIPS 140-3 mode tests and a fuzz smoke test in the `ci` workflow (the badge above), and govulncheck in its own `govulncheck` workflow, so a newly published advisory does not show up as a failing build.

<br/>

## Notes on the toolchain

- **gofmt**: `gofmt -w .` (or `make fmt`) formats everything; CI fails on unformatted files.
- **go run**: `go run ./Discovery/01_TryGo` builds and runs a main package; `go run -work` keeps the temporary build directory.
- **go test**: test files end in `_test.go` and sit next to the code they test; `go test -v ./...` runs them recursively.

## License

[MIT](LICENSE)
