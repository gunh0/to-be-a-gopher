# 01. Memory Safety

> **Abstract.** Go removes the classic memory-corruption bugs of C: every slice and string access is bounds-checked, there is no pointer arithmetic, and the garbage collector rules out use-after-free. What it does *not* remove is logic that hands out more memory than it should. Re-slicing a buffer up to its **capacity** is legal Go, so a length taken from the wire can still disclose stale bytes from a reused buffer — Heartbleed with no `unsafe` in sight.

| | |
|---|---|
| Weaknesses | [CWE-125](https://cwe.mitre.org/data/definitions/125.html) Out-of-bounds Read, [CWE-226](https://cwe.mitre.org/data/definitions/226.html) Sensitive Information in Resource Not Removed Before Reuse, [CWE-130](https://cwe.mitre.org/data/definitions/130.html) Improper Handling of Length Parameter Inconsistency |
| Go packages | `encoding/binary`, `runtime` |
| Code | [`heartbeat.go`](heartbeat.go), [`bounds.go`](bounds.go), [`memsafety_test.go`](memsafety_test.go) |

## 1. Threat model

A network service parses length-prefixed messages and reuses buffers across requests to keep allocations down (`sync.Pool`, a per-connection scratch slice, a ring buffer). The attacker controls the length prefix and the payload. Their goal is to read memory that belonged to another request: tokens, passwords, keys.

## 2. What Go guarantees

| Bug class | C | Go |
|---|---|---|
| Read/write past the end of an array | Undefined behaviour, silent | `panic: runtime error: index out of range` |
| Use after free | Undefined behaviour | Impossible without `unsafe`: the GC keeps referenced memory alive |
| Pointer arithmetic | Allowed | Only through `unsafe.Pointer` / `unsafe.Add` |
| Uninitialised memory | Contains old data | Every allocation is zeroed (`make`, `new`, composite literals) |

The bounds check is against **`len`** for indexing (`s[i]`) but against **`cap`** for slicing (`s[:n]`). That second rule is the gap this chapter is about.

```go
buf := make([]byte, 0, 1024) // len 0, cap 1024
buf = append(buf, "secret"...)
buf = buf[:0]                 // "cleared"
buf = append(buf, "hi"...)
leak := buf[:6]               // legal: 6 <= cap(buf)  →  "hicret"
```

## 3. Insecure pattern

[`EchoUnsafe`](heartbeat.go) copies the received payload into a pooled scratch buffer and answers with `scratch[:declared]`, trusting the 2-byte length field:

```go
declared := int(binary.BigEndian.Uint16(msg))
r.scratch = append(r.scratch[:0], msg[2:]...)
return r.scratch[:declared] // declared ≤ cap(scratch) → no panic, stale bytes returned
```

A peer that sends `"hi"` with a declared length of 16 receives `"hissword=hunter2"` — the tail of the previous request.

The other half of the picture is [`ReadAt`](bounds.go): reading past `len` of a slice is caught by the runtime. The process panics instead of disclosing memory, so the failure mode moves from **confidentiality** to **availability** (an unrecovered panic kills the whole program; see chapter 05).

## 4. Secure pattern

1. **Validate declared lengths against what actually arrived** before slicing — never against capacity.
2. **Bound every length** by a protocol maximum (`MaxPayload`).
3. **Return copies, not views,** of pooled buffers, or cap the view with a full slice expression `s[lo:hi:hi]` so the caller cannot re-slice into the rest of the buffer.
4. **Compare against the remaining length** (`n > len(buf)-off`) rather than computing `off+n`, which can overflow when both come from the wire.

```go
if declared != len(payload) || declared > MaxPayload {
	return nil, ErrMalformed
}
out := make([]byte, declared)
copy(out, r.scratch)
```

`ReadAtChecked` applies points 2–4 and returns `buf[off:off+n:off+n]`, a view whose capacity ends where its length ends.

## 5. Where Go's guarantees end

- **`unsafe`** — `unsafe.Slice`, `unsafe.String` and `unsafe.Pointer` conversions skip all checks. Treat every import of `unsafe` as a code-review hotspot.
- **cgo** — C code called from Go has C's memory model.
- **Data races** — a racing write to a multi-word value (an interface, a slice header) can be observed half-updated, which *is* memory corruption. Chapter 04 covers this.
- **`sync.Pool`** — objects come back with their old contents. Reset them (`buf = buf[:0]` is not enough if any code re-slices by capacity; `clear(buf[:cap(buf)])` is).

## 6. Verification

```bash
go test -v ./Security/01_memory-safety/
```

| Test | Shows |
|---|---|
| `TestEchoUnsafeDisclosesStaleBytes` | A lying length leaks an earlier request's session token without a panic |
| `TestEchoSafeRejectsLyingLength` | Short, long and over-limit declared lengths are all rejected |
| `TestEchoSafeReturnsCopy` | The response does not alias the pooled buffer |
| `TestReadAtPanicsInsteadOfReading` | Reading past `len` is a `runtime.Error`, not a silent read |
| `TestReadAtChecked` | Range validation, including the `off+n` overflow case, and capped capacity |

## 7. Checklist

- [ ] Every length or offset from input is compared with `len()` of the data actually received.
- [ ] Protocol maximums are enforced before allocating or slicing.
- [ ] Pooled or reused buffers are returned as copies, or as full slice expressions `s[a:b:b]`.
- [ ] `unsafe` and cgo usage is listed and reviewed separately.

## References

- The Go Programming Language Specification — [Slice expressions](https://go.dev/ref/spec#Slice_expressions), [Run-time panics](https://go.dev/ref/spec#Run_time_panics)
- Go Blog — [Go Slices: usage and internals](https://go.dev/blog/slices-intro)
- [CVE-2014-0160 (Heartbleed)](https://nvd.nist.gov/vuln/detail/CVE-2014-0160)
- CISA — [The Case for Memory Safe Roadmaps](https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps) (2023), which lists Go as a memory-safe language
