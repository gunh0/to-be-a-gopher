# 03. Slice & Map Aliasing

> **Abstract.** A Go slice is a three-word header — pointer, length, capacity — and a map value is a pointer to a runtime table. Passing either by value copies the header, never the data. An object that stores a caller's slice, returns its internal map, or derives new slices with `append` therefore shares mutable state with code it does not control. Nothing in the type system says "this is mine": a validated role list can be rewritten after validation, two users' permission lists can share an element, and an 8-byte key ID can keep a 4 KiB secret alive. Whether `append` shares or copies depends on spare capacity at run time, so the bug hides in tests and appears under production allocation patterns.

| | |
|---|---|
| Weaknesses | [CWE-374](https://cwe.mitre.org/data/definitions/374.html) Passing Mutable Objects to an Untrusted Method, [CWE-375](https://cwe.mitre.org/data/definitions/375.html) Returning a Mutable Object to an Untrusted Caller, [CWE-471](https://cwe.mitre.org/data/definitions/471.html) Modification of Assumed-Immutable Data |
| Go packages | `slices`, `maps`, `bytes`, `iter`, `net/http` |
| Code | [`policy.go`](policy.go), [`append.go`](append.go), [`aliasing_test.go`](aliasing_test.go) |

## 1. Threat model

The attacker is not on the network here; it is **the other side of an API boundary inside the process**: a plugin, a handler written by another team, a library callback, or simply a later line of the same caller. It holds a slice or map that the security-relevant object also holds. Its goal is to change validated state (roles, allowlists, headers, limits) after the check, or to read data the object meant to keep private. In multi-tenant code the "attacker" is often an innocent code path that mutates a slice for one tenant and thereby changes another tenant's view.

## 2. What Go guarantees

| Value | Copied on assignment / call | Shared |
|---|---|---|
| Array `[N]T` | All N elements | Nothing (unless elements are pointers) |
| Struct | All fields (shallow) | Whatever slice/map/pointer fields point to |
| Slice `[]T` | Header (ptr, len, cap) | Backing array |
| Map | Pointer to the table | Everything |
| String | Header (ptr, len) | Bytes — but they are immutable, so sharing is safe |

`append(s, x)` writes into `s`'s backing array **if `len(s) < cap(s)`** and allocates a new one otherwise ([spec](https://go.dev/ref/spec#Appending_and_copying_slices)); the growth policy is an implementation detail. The full slice expression `s[lo:hi:max]` limits capacity so that later appends must reallocate. The standard library has the copying helpers: `bytes.Clone`, `strings.Clone` (Go 1.20), `slices.Clone`, `maps.Clone` (Go 1.21), `slices.Concat` (Go 1.22), and read-only iteration with `iter.Seq` / `slices.Values` (Go 1.23). Strings are the only built-in sequence type whose contents cannot change under you without `unsafe`.

## 3. Insecure pattern

**Storing the caller's slice.** [`NewPolicyUnsafe`](policy.go) validates `roles` (no `admin`) and keeps the same slice. The caller writes `roles[1] = "admin"` afterwards; the policy now grants it. This is a TOCTOU (chapter 04) with no concurrency at all.

**Returning internals.** `RolesUnsafe()` and `HeadersUnsafe()` return the policy's own slice and map. `p.RolesUnsafe()[0] = "admin"` escalates; `p.HeadersUnsafe()["Access-Control-Allow-Origin"] = "*"` changes the CORS policy for every later response.

**Deriving with `append`.** [`WithRoleUnsafe`](append.go) is `append(base, role)`:

```go
base := make([]string, 1, 4)        // spare capacity, e.g. from a pool or a previous trim
alice := WithRoleUnsafe(base, "writer")
_      = WithRoleUnsafe(base, "admin") // for someone else
// alice == [reader admin]
```

With `cap(base) == len(base)` the same code is correct, which is exactly why unit tests built from literals pass.

**Sub-slicing secrets.** [`KeyIDUnsafe`](append.go) returns `record[:8]`. The ID keeps the whole record — key material included — reachable (the GC frees arrays, not ranges), and anyone holding the ID can re-slice to `cap` and read it (chapter 01). Wiping the record also corrupts the ID, a sign that the two were never independent.

## 4. Secure pattern

1. **Copy at the boundary, in both directions.** Constructors clone inputs *before* validating them (so the validated data and the stored data are the same object); accessors return clones.

   ```go
   roles = slices.Clone(roles)
   if err := validate(roles); err != nil { ... }
   return &Policy{roles: roles, headers: maps.Clone(headers)}, nil
   ```

2. **Prefer APIs that cannot be written through.** `func (p *Policy) All() iter.Seq[string]` lets callers range without receiving a slice; `Has(role)` answers the actual question. Return strings instead of `[]byte` where the data is text.
3. **Cap before appending to a shared base:** `append(base[:len(base):len(base)], x)` or `slices.Concat(base, []T{x})`. The new list never shares storage with `base`.
4. **Copy small views out of large buffers:** `bytes.Clone(record[:8])`, then `clear(record)` when the secret is no longer needed.
5. **Know which clones are shallow.** `maps.Clone` and `slices.Clone` copy one level. `maps.Clone(http.Header)` still shares every `[]string` value; `http.Header.Clone` copies them. Nested structures need a hand-written deep copy.

## 5. Where the guarantee ends

- **Decoders reuse what you give them.** `json.Unmarshal` into a non-nil slice resets its length to zero and appends, reusing the backing array; into a non-nil map it adds keys to the existing map. Decoding untrusted input into a struct that aliases shared state rewrites that state. Decode into fresh values.
- **`sync.Pool` and buffer reuse** hand the same backing array to the next user (chapter 01). Never retain a slice of a pooled buffer past `Put`.
- **Concurrency.** A shared backing array mutated from two goroutines is a data race, and racing on the slice header itself can be torn (chapter 04). Defensive copies are also a concurrency tool.
- **`unsafe.String` / `unsafe.Slice`** break string immutability: a string built over a `[]byte` changes when the bytes do.
- **Copies are not erasure.** Cloning leaves the original in memory until it is collected; Go offers no guaranteed zeroing of copies made by `append` growth or by the GC. `clear` what you own; do not assume every copy is gone.

## 6. Verification

```bash
go test -race -v ./Security/03_slice-aliasing/
```

| Test | Shows |
|---|---|
| `TestNewPolicyUnsafeAliasesInput` | Writing to the caller's slice after validation grants `admin` |
| `TestNewPolicyCopiesInput` | Cloned inputs are immune; `admin` is still rejected at construction |
| `TestAccessorsUnsafeExposeInternalState` | Writes through returned slice and map change the policy |
| `TestAccessorsReturnCopies` | Clone accessors and `iter.Seq` leave the policy intact |
| `TestMapsCloneIsShallow` | `maps.Clone(http.Header)` shares value slices; `Header.Clone` does not |
| `TestWithRoleUnsafeDependsOnCapacity` | Same code is correct with `cap == len`, leaks roles with spare capacity |
| `TestWithRoleIsIndependent` | Full slice expression forces reallocation; `base` is untouched |
| `TestKeyIDUnsafeRetainsSecret` | A sub-slice reaches the secret via `cap`; the clone survives `clear(record)` |
| `ExampleWithRoleUnsafe` | `[reader admin]` vs `[reader writer]` |

## 7. Checklist

- [ ] Constructors of security-relevant types clone slice/map arguments before validating them.
- [ ] Getters never return internal slices or maps; prefer `iter.Seq`, predicates, or clones.
- [ ] Every `append` to a slice that is not exclusively owned uses a full slice expression or `slices.Concat`.
- [ ] Small values cut from buffers that held secrets are `bytes.Clone`d, and the buffer is `clear`ed.
- [ ] Nested values (`map[string][]string`, structs with slices) are deep-copied where it matters.

## References

- The Go Programming Language Specification — [Slice types](https://go.dev/ref/spec#Slice_types), [Slice expressions](https://go.dev/ref/spec#Slice_expressions), [Appending and copying slices](https://go.dev/ref/spec#Appending_and_copying_slices)
- Go Blog — [Arrays, slices (and strings): The mechanics of 'append'](https://go.dev/blog/slices)
- [`slices`](https://pkg.go.dev/slices), [`maps`](https://pkg.go.dev/maps), [`iter`](https://pkg.go.dev/iter), [`http.Header.Clone`](https://pkg.go.dev/net/http#Header.Clone)
- [`encoding/json.Unmarshal`](https://pkg.go.dev/encoding/json#Unmarshal) — slice and map reuse rules
- SEI CERT Oracle Coding Standard for Java — [OBJ05-J. Do not return references to private mutable class members](https://wiki.sei.cmu.edu/confluence/display/java/OBJ05-J.+Do+not+return+references+to+private+mutable+class+members)
