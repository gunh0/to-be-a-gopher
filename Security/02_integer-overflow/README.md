# 02. Integer Overflow & Truncation

> **Abstract.** Go has no undefined behaviour for integers: signed and unsigned arithmetic wraps modulo 2^n, and every conversion between integer types is defined to sign-extend or truncate. That determinism removes the C compiler's freedom to delete overflow checks, but it also means **nothing ever fails loudly**. A size computed as `count*size` from wire fields, a length written as `uint16(len(p))`, or an ID checked after `int32(id)` silently produces a different number, and the program carries on with it. The bounds checks of chapter 01 catch some of the fallout as panics; the rest is a passed size check, a smuggled frame, or an authorisation decision made about the wrong object.

| | |
|---|---|
| Weaknesses | [CWE-190](https://cwe.mitre.org/data/definitions/190.html) Integer Overflow or Wraparound, [CWE-681](https://cwe.mitre.org/data/definitions/681.html) Incorrect Conversion between Numeric Types, [CWE-197](https://cwe.mitre.org/data/definitions/197.html) Numeric Truncation Error |
| Go packages | `math/bits`, `math`, `strconv`, `encoding/binary` |
| Code | [`budget.go`](budget.go), [`convert.go`](convert.go), [`intoverflow_test.go`](intoverflow_test.go) |

## 1. Threat model

A service parses binary or textual input whose numeric fields the attacker controls: record counts, element sizes, length prefixes, offsets, object IDs. The service computes buffer sizes and limits from them, converts between the widths used by the wire format, the database schema and Go's `int`, and makes allow/deny decisions on the result. The attacker wants a check to pass for a value that the rest of the program interprets differently: a huge allocation or loop (availability), a frame boundary in the wrong place (integrity), or another tenant's object (confidentiality).

## 2. What Go guarantees

| Operation | Go behaviour | Consequence |
|---|---|---|
| `+ - * <<` on any integer type | Wraps modulo 2^n, signed is two's complement ([spec](https://go.dev/ref/spec#Integer_overflow)) | No panic, no UB, no compiler-removed checks |
| `math.MinInt64 / -1` | Result is `math.MinInt64`, no trap | `-x` and `abs` can stay negative |
| Integer division by zero, negative shift count | Run-time panic | DoS rather than a wrong value |
| Conversion to a narrower type | Keeps the low bits ([spec](https://go.dev/ref/spec#Conversions)) | `int32(1<<32 \| 7) == 7` |
| Signed → unsigned of a negative value | Bit pattern reinterpreted | `uint32(-1) == 4294967295` |
| Overflow in a **constant** expression | Compile error | Only literals are protected |
| `int` / `uint` width | 64-bit on amd64/arm64, **32-bit on 386, arm, mips** | Code that is safe on a laptop can overflow on a 32-bit target |

`go vet` does not report non-constant overflow or lossy conversions. Linters can: gosec's G115 rule flags integer conversions that may overflow; it is noisy, which is why the fix is a habit, not a tool.

## 3. Insecure pattern

**Wrapped size checks.** [`BudgetUnsafe`](budget.go) computes `HeaderSize + count*size` in `uint64` and compares with a 64 MiB limit. With `count = size = 2^32` the product is `2^64 ≡ 0`, the total is 16, and the check passes; the caller then iterates 2^32 times or allocates per record. A carry in the addition does the same with `count = 3, size = 0x5555555555555553`.

**Truncating length prefixes.** [`EncodeFrameUnsafe`](convert.go) writes `uint16(len(p))`. A 65,540-byte comment is announced as 4 bytes; the decoder reads `"note"` and then parses the remaining attacker-chosen 65,536 bytes as **new frames**, including `cmd:grant-admin`. The same shape appears with `uint32(len(body))` in 32-bit length fields of RPC, TLV and database wire protocols.

**Checking a different value than the one used.** [`CanReadUnsafe`](convert.go) authorises against an ACL keyed by legacy `int32` IDs, while storage fetches by `int64`:

```go
return owned[int32(id)] // id = 1<<32 | 7 → checks doc 7, fetches doc 4294967303
```

**Sign reinterpretation.** [`ParseLengthUnsafe`](convert.go) uses `strconv.Atoi` then `uint32(n)`: `"-1"` becomes 4,294,967,295 and `"4294967297"` becomes 1.

## 4. Secure pattern

1. **Check the arithmetic, not its result.** `bits.Mul64` returns the full 128-bit product and `bits.Add64` the carry; non-zero `hi` or `carry` means the true value did not fit. Both are compiler intrinsics on amd64/arm64.

   ```go
   hi, lo := bits.Mul64(count, size)
   total, carry := bits.Add64(lo, HeaderSize, 0)
   if hi != 0 || carry != 0 || total > MaxBody { return 0, ErrTooLarge }
   ```

   Where `math/bits` is awkward, divide instead of multiplying: `size != 0 && count > (Max-Header)/size` ([`BudgetDiv`](budget.go)).
2. **Compare before converting.** Range-check against the target type's limits (`math.MaxUint16`, `math.MinInt32`/`math.MaxInt32`) and only then convert, so the conversion is exact by construction ([`EncodeFrame`](convert.go), [`CanRead`](convert.go)).
3. **Let the parser enforce the width.** `strconv.ParseUint(s, 10, 32)` rejects signs and values above 2^32-1 with `strconv.ErrRange`; `ParseInt(s, 10, 16)` does the same for `int16`. Parse into the width you need instead of `Atoi` plus a cast.
4. **Compare against what remains, not `off+n`** (chapter 01, `ReadAtChecked`).
5. **Use one integer type end to end** for identifiers. Mixed `int32`/`int64` IDs across schema, API and cache are a standing invitation for aliasing.

## 5. Where the guarantee ends

- **Panics instead of values.** Some wrapped results are caught later: a negative `int` reaching `make([]byte, n)` panics with `makeslice: len out of range`, and an index past `len` panics. That converts integrity bugs into availability bugs (chapter 05), which is better but not fixed.
- **Allocation is the real sink.** A check that passes with a correct but large value (`count = 10^9`) still exhausts memory. Bound counts by protocol limits *and* by the bytes actually received (chapter 01), and bound concurrent work (chapter 06).
- **`unsafe` and cgo.** `unsafe.Slice(ptr, n)` with a wrapped `n`, or a size passed to C `malloc`, removes the bounds checks that otherwise contain the damage.
- **`len()` is an `int`.** Converting it to `uint32`/`uint16` for a wire field is the most common truncation in Go; grep for `uint16(len(` and `uint32(len(`.
- **Time and money.** `time.Duration` is an `int64` of nanoseconds: `time.Duration(days) * 24 * time.Hour` overflows after ~292 years and wraps negative. Use decimal or big types for currency rather than wrapping integers.

## 6. Verification

```bash
go test -race -v ./Security/02_integer-overflow/
```

| Test | Shows |
|---|---|
| `TestBudgetUnsafeAcceptsWrappedSizes` | Multiplication wrap and addition carry both pass the 64 MiB check |
| `TestBudgetRejectsOverflow` | `bits.Mul64`/`Add64` and the division form reject all three, accept exact boundary values |
| `TestEncodeFrameUnsafeSmugglesFrames` | A 65,540-byte payload decodes as three frames, one of them an injected command |
| `TestEncodeFrameRejectsOversize` | The checked encoder refuses it and still round-trips a 65,535-byte frame |
| `TestCanRead` | `1<<32\|7` and `-(1<<32)+7` alias document 7 in the unsafe check only |
| `TestParseLength` | `Atoi`+cast accepts `-1`, `4294967297`, `+5`; `ParseUint(…, 32)` rejects them |
| `TestLanguageSemantics` | `MaxInt64+1`, `-MinInt64`, `MinInt64/-1` are defined wrap-around, not traps |
| `ExampleBudgetUnsafe` | `2^32 × 2^32` budgets to 16 bytes |

## 7. Checklist

- [ ] Every size, count and offset product/sum built from input is computed with `math/bits` carries or checked by division first.
- [ ] Narrowing conversions (`int32(`, `uint16(`, `uint32(len(`) are preceded by an explicit range check.
- [ ] Numeric input is parsed with `strconv.ParseInt/ParseUint` at the target bit size, not `Atoi` plus a cast.
- [ ] Authorisation is decided on exactly the value later used to fetch or act.
- [ ] Code is reviewed (or tested) with 32-bit `int` in mind if it ships to `GOARCH=386/arm`.

## References

- The Go Programming Language Specification — [Integer overflow](https://go.dev/ref/spec#Integer_overflow), [Conversions between numeric types](https://go.dev/ref/spec#Conversions), [Arithmetic operators](https://go.dev/ref/spec#Arithmetic_operators)
- [`math/bits`](https://pkg.go.dev/math/bits) — `Mul64`, `Add64`, `Sub64`
- [`strconv.ParseUint`](https://pkg.go.dev/strconv#ParseUint) — `bitSize` and `ErrRange`
- [gosec rules](https://github.com/securego/gosec#available-rules) — G115 integer conversion overflow
- SEI CERT C — [INT30-C / INT31-C](https://wiki.sei.cmu.edu/confluence/display/c/INT30-C.+Ensure+that+unsigned+integer+operations+do+not+wrap) (the C original of the same reasoning)
