# 42. Native Fuzzing

> **Abstract.** Since Go 1.18, coverage-guided fuzzing is part of `go test`: a `FuzzXxx(f *testing.F)` function, a seed corpus, and `-fuzz` turn any parser into a target, and every crash the fuzzer finds becomes a file in `testdata/fuzz/` that plain `go test` replays forever after. Memory safety means Go fuzzing rarely finds corruption; it finds **panics** (index out of range, nil dereference, slice bounds — remote crashes for any service without `recover`) and, with the right oracle, **logic bugs**: round-trip failures and disagreements between two implementations. This chapter's TLV parser decodes a 16-bit length as signed; unit tests written by the author pass, and the fuzzer finds the crash in under a second.

| | |
|---|---|
| Weaknesses | [CWE-129](https://cwe.mitre.org/data/definitions/129.html) Improper Validation of Array Index, [CWE-194](https://cwe.mitre.org/data/definitions/194.html) Unexpected Sign Extension, [CWE-20](https://cwe.mitre.org/data/definitions/20.html) Improper Input Validation |
| Go packages | `testing` (`testing.F`), `encoding/binary` |
| Code | [`tlv.go`](tlv.go), [`tlv_test.go`](tlv_test.go), [`testdata/fuzz/FuzzParse/negative-length`](testdata/fuzz/FuzzParse/negative-length) |

## 1. Threat model

Any code that decodes attacker-controlled bytes: protocol framing, file formats, archive headers (chapter 32), certificates, configuration. The attacker sends crafted input; the goal is a panic that kills the process or worker (availability), or a parser that accepts something a second parser interprets differently (integrity; compare the JSON differentials in chapter 35).

## 2. What Go provides

| Piece | Behaviour |
|---|---|
| `func FuzzXxx(f *testing.F)` | Lives in `_test.go`; `f.Add(...)` adds seed inputs; `f.Fuzz(func(t *testing.T, ...))` is the target. Argument types: `[]byte`, `string`, `bool`, `byte`, `rune`, `int*`, `uint*`, `float32`, `float64` |
| Seed corpus | `f.Add` values plus files in `testdata/fuzz/FuzzXxx/`, run as ordinary subtests by `go test` — no `-fuzz` needed |
| `go test -fuzz=^FuzzXxx$` | Mutates inputs with coverage guidance (instrumentation on amd64/arm64), runs workers in parallel (`-parallel`) |
| `-fuzztime 30s` or `-fuzztime 10000x` | Bound the run; without it fuzzing continues until a failure |
| Failures | Minimised (`-fuzzminimizetime`), written to `testdata/fuzz/FuzzXxx/<hash>`; commit that file and it becomes a regression test |
| Generated corpus | Interesting inputs are cached in `$GOCACHE/fuzz`, not in the repository |

Restrictions: `-fuzz` must match exactly one target in exactly one package, and the target must be deterministic and fast; global state or goroutines that outlive the call make findings irreproducible.

## 3. Insecure pattern

```go
n := int(int16(binary.BigEndian.Uint16(b[off+1:])))   // 0xFFFF → -1
if off+3+n > len(b) { return nil, ErrTruncated }      // -1 passes
recs = append(recs, Record{typ, b[off+3 : off+3+n]})  // b[3:2] → panic
```

[`ParseUnsafe`](tlv.go) reads the length as `int16` because "the spec says 32767 is the maximum". Every length ≥ `0x8000` sign-extends to a negative number, slips under the bounds check, and produces a slice expression with high < low. Hand-written tests use small lengths and pass. With the same seeds, `FuzzParseUnsafe` reported `[]byte("0\xba0")` (length `0xBA30` = −17872) after **0.3 s** on a laptop.

The bounds check also computes `off+3+n` before comparing. Harmless with 16-bit lengths, it can overflow once a length field is 64-bit, or 32-bit on a platform where `int` is 32 bits (chapter 02); `Parse` compares against the remaining length instead.

## 4. Secure pattern

[`Parse`](tlv.go):

```go
n := int(binary.BigEndian.Uint16(b[off+1:]))   // unsigned, as specified
off += headerLen
if n > len(b)-off { return nil, ErrTruncated } // compare against what remains
recs = append(recs, Record{typ, b[off : off+n : off+n]}) // capacity capped
```

plus a `MaxRecords` bound. The fuzz target `FuzzParse` (the one that runs by default) checks three oracles:

1. **No panic** for any input.
2. **Round trip:** if `Parse(b)` succeeds, `Encode(records) == b` — the format is canonical, so any difference is a parsing bug.
3. **Differential:** [`Decode`](tlv.go), an independent streaming implementation over `io.Reader`, must return the same records and the same error class.

A 15-second run (3.4 M executions) found nothing; the minimised crash input for the unsafe parser is checked in as `testdata/fuzz/FuzzParse/negative-length`, so every `go test` replays it against the secure parser, and `TestSeedReproducesUnsafeBug` proves it still crashes the unsafe one.

**Proposed Makefile target and CI step:**

```make
FUZZTIME ?= 10s

fuzz:
	$(GO) test -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME) ./Security/42_fuzzing/
```

```yaml
      - name: fuzz (smoke)
        run: make fuzz FUZZTIME=30s
```

A short run on every PR catches regressions in the oracle's reach; long runs belong in a scheduled job or a continuous service (OSS-Fuzz supports Go native fuzz targets). To see the insecure parser fail:

```bash
TLV_FUZZ_INSECURE=1 go test -run '^$' -fuzz '^FuzzParseUnsafe$' -fuzztime 30s ./Security/42_fuzzing/
```

## 5. Where the guarantee ends

- **The oracle is the limit.** Without round-trip or differential checks, fuzzing only finds panics and timeouts; a parser that silently accepts malformed input passes.
- **Coverage, not proof.** Fuzzing samples the input space; deep states behind checksums, compression or cryptographic MACs are rarely reached without a structure-aware harness (fuzz the inner layer directly).
- **Resource bugs.** The fuzzer looks for failures and panics; slow or allocation-heavy inputs go unreported unless the target asserts limits. Bound sizes explicitly (chapter 22) and check them in the target.
- **Concurrency bugs** need the race detector and `testing/synctest` (chapter 04), not input mutation.
- **Committed corpus files are inputs, not code**, but they run in CI; keep them small and review additions.

## 6. Verification

```bash
go test -v ./Security/42_fuzzing/                                       # seeds + corpus, no fuzzing
go test -run '^$' -fuzz '^FuzzParse$' -fuzztime 10s ./Security/42_fuzzing/
```

| Test | Shows |
|---|---|
| `FuzzParse` (seeds and `negative-length`) | No panic, round trip, Parse/Decode agreement on every corpus entry |
| `FuzzParseUnsafe` | Skipped unless `TLV_FUZZ_INSECURE=1`; with it, the fuzzer finds the sign-extension panic |
| `TestSeedReproducesUnsafeBug` | The checked-in corpus entry makes `ParseUnsafe` panic with a `runtime.Error`; `Parse` returns `ErrTruncated` |
| `TestParse` | Valid messages, truncation, length `0x8000` read as 32768, record limit |
| `TestParseValueCapacityCapped` | Values cannot be re-sliced into the next record |
| `TestEncodeRejectsLargeValue` | Encoder enforces the 16-bit length |
| `ExampleParse` | Same input: error from `Parse`, panic from `ParseUnsafe` |

## 7. Checklist

- [ ] Every decoder of external bytes has a `FuzzXxx` target with seeds from real samples.
- [ ] Targets assert an oracle beyond "no panic": round trip, a reference implementation, or invariants on the output.
- [ ] Crashers are minimised, committed under `testdata/fuzz/`, and fixed — never deleted.
- [ ] CI runs a short fuzz smoke test; a scheduled job runs longer.
- [ ] Length fields are decoded with the signedness the format specifies and compared against remaining bytes.

## References

- Go documentation — [Go Fuzzing](https://go.dev/security/fuzz/), [Tutorial: Getting started with fuzzing](https://go.dev/doc/tutorial/fuzz); package [`testing`](https://pkg.go.dev/testing#hdr-Fuzzing); `go help testflag` (`-fuzz`, `-fuzztime`, `-fuzzminimizetime`)
- [Go 1.18 release notes](https://go.dev/doc/go1.18)
- Google — [OSS-Fuzz: Go](https://google.github.io/oss-fuzz/getting-started/new-project-guide/go-lang/)
- CWE-194 — [Unexpected Sign Extension](https://cwe.mitre.org/data/definitions/194.html)
