# 35. JSON Decoding Pitfalls

> **Abstract.** `encoding/json` (v1) is memory-safe and type-safe, and permissive by design: it matches keys to struct fields case-insensitively (with Unicode folding, so `"\u212Aey"` (KELVIN SIGN) sets `Key`), keeps the **last** of duplicate keys, ignores unknown keys, replaces invalid UTF-8 with U+FFFD, and `Decoder.Decode` stops after the first value without looking at the rest. None of this is a bug in isolation. It becomes one when another component — a gateway, a WAF, a schema validator, a service in another language — reads the same bytes differently, or when a request body is decoded straight into a struct that has privileged fields. Go 1.25's experimental `encoding/json/v2` flips most of these defaults; until it is the default, strictness is something the caller builds.

| | |
|---|---|
| Weaknesses | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) Improperly Controlled Modification of Dynamically-Determined Object Attributes, [CWE-436](https://cwe.mitre.org/data/definitions/436.html) Interpretation Conflict, [CWE-20](https://cwe.mitre.org/data/definitions/20.html) Improper Input Validation |
| Go packages | `encoding/json`, `encoding/json/v2` + `encoding/json/jsontext` (Go 1.25, `GOEXPERIMENT=jsonv2`), `unicode/utf8` |
| Code | [`decode.go`](decode.go), [`profile.go`](profile.go), [`jsondecode_test.go`](jsondecode_test.go), [`jsonv2_test.go`](jsonv2_test.go) |

## 1. Threat model

A JSON API sits behind a gateway that enforces some rules on the body ("clients may not send `isAdmin`", a JSON Schema, a signature over selected fields). The attacker controls the request body byte for byte. Their goals: set fields they should not (role, owner, price), make the gateway and the Go service disagree about what the body says, or smuggle a second value past a validator that looks only at the first.

## 2. What encoding/json (v1) does

| Input | v1 behaviour | Shown by |
|---|---|---|
| `{"ISADMIN":true}` into field tagged `isAdmin` | Matched (exact match preferred, case-insensitive accepted) | `TestV1CaseInsensitiveFieldMatch` |
| `{"\u212Aey":…}` (KELVIN SIGN), `"pa\u017F\u017F"` (LONG S) | Matched to `key`, `pass` via Unicode folding | `TestV1UnicodeFolding` |
| `{"isAdmin":false,"ISADMIN":true}` | No error, last one wins → `true` | `TestV1DuplicateKeysLastWins` |
| Unknown key | Ignored unless `Decoder.DisallowUnknownFields` | `TestV1UnknownFieldsIgnored` |
| `"ad\xffmin"`, `"\ud800"` | Replaced with U+FFFD, no error (documented) | `TestV1InvalidUTF8Replaced` |
| Field tagged `json:"-,"` | Not hidden: it is the field named `"-"` | `TestV1DashCommaTagIsAField` |
| `9007199254740993` into `any` | `float64`, rounded; `UseNumber` keeps it exact | `TestV1LargeIntegerLosesPrecision` |
| `{…} garbage` | `Unmarshal` errors; `Decoder.Decode` succeeds and leaves the rest unread | `TestDecodeLenientTrailingData` |

`Decoder.More()` is not a trailing-data check: after `{…}]` it reports `false`, because `]` would end an enclosing array. Only a second `Decode` that returns `io.EOF` proves the input is exhausted.

Duplicate-key disagreement is not hypothetical: CVE-2017-12635 gave CouchDB users admin rights because its Erlang parser kept the first `"roles"` key and its JavaScript validator kept the last.

## 3. Insecure pattern

```go
func UpdateProfileUnsafe(u *User, body []byte) error {
	return json.NewDecoder(bytes.NewReader(body)).Decode(u) // u has IsAdmin, ID
}
```

Every exported field of `User` is now client-writable — mass assignment, the class behind the 2012 GitHub/Rails public-key incident. A gateway rule that strips `"isAdmin"` is bypassed by `"ISADMIN"`; a validator that reads the first of two keys is bypassed by a duplicate; and anything after the first object is never looked at.

## 4. Secure pattern

1. **Separate input DTOs.** Decode into a struct that contains only what the client may set (`ProfileUpdate`), validate every field, then copy onto the record — after *all* validation has passed. Privileged fields do not exist in the DTO, so case tricks have nothing to hit.
2. **Decode strictly.** [`DecodeStrict`](decode.go):
   ```go
   if len(data) > MaxBody          { return ErrTooLarge }      // chapter 22 for the HTTP layer
   if !utf8.Valid(data)            { return ErrInvalidUTF8 }
   if err := CheckKeys(data); ...  // duplicates after case folding, depth ≤ MaxDepth
   dec.DisallowUnknownFields()
   dec.Decode(v)
   if dec.Decode(&struct{}{}) != io.EOF { return ErrTrailingData }
   ```
   `CheckKeys` walks `Decoder.Token()` with a stack of per-object key sets. Keys are compared with `FoldKey` (`ToLower(ToUpper(k))`), which maps U+212A KELVIN SIGN to `k` and U+017F LONG S to `s` the way v1's field matching does, so `{"isAdmin":…,"ISADMIN":…}` is a duplicate.
3. **Use `json.Number` or typed fields** for identifiers and amounts; never round-trip large integers through `float64`.
4. **Audit tags**: `json:"-"` hides a field, `json:"-,"` exposes one named `-`.

### Go 1.25: `GOEXPERIMENT=jsonv2`

Go 1.25 ships `encoding/json/v2` and `encoding/json/jsontext` behind `GOEXPERIMENT=jsonv2`. Verified in [`jsonv2_test.go`](jsonv2_test.go) (build-tagged, run with `GOEXPERIMENT=jsonv2 go test -run V2 ./Security/35_json-decoding/`):

| Default | v1 | v2 | Option to change v2 |
|---|---|---|---|
| Name matching | case-insensitive | **case-sensitive** | `json.MatchCaseInsensitiveNames(true)` |
| Duplicate names | last wins | **error** | `jsontext.AllowDuplicateNames(true)` |
| Invalid UTF-8 / lone surrogates | U+FFFD | **error** | `jsontext.AllowInvalidUTF8(true)` |
| Unknown members | ignored | ignored | `json.RejectUnknownMembers(true)` |
| Trailing data (`Unmarshal`) | error | error | — |

With the experiment enabled, v1 `encoding/json` is reimplemented on the v2 engine but keeps v1 semantics; the v1 tests in this chapter pass in both modes. Being experimental, the v2 API may change before it becomes the default, so production code on Go 1.25 should keep a strict v1 wrapper.

## 5. Where the guarantee ends

- **Lone surrogates.** `"\ud800"` is valid UTF-8 *text* (it is an escape), so `utf8.Valid` passes and v1 still substitutes U+FFFD. Reject at the schema level, or use v2.
- **Case-insensitive matching within the DTO** remains (`{"NAME":"x"}` sets `Name`). It is harmless once the DTO holds only permitted fields, and it is exactly why the DTO matters.
- **`null`** into a struct is a no-op, not an error; into a pointer it sets `nil`. Check required fields explicitly.
- **Embedded structs** promote their fields into the JSON object: embedding `User` in a DTO re-introduces `isAdmin`.
- **Other parsers** have their own footguns: `encoding/xml` accepts leading and trailing garbage around the root element, and YAML libraries map keys differently again (Trail of Bits, 2025).
- **Size and depth** limits belong at the transport layer too (`http.MaxBytesReader`, chapter 22); `MaxDepth` here bounds the token walk.

## 6. Verification

```bash
go test -v ./Security/35_json-decoding/
GOEXPERIMENT=jsonv2 go test -run V2 -v ./Security/35_json-decoding/   # Go 1.25 toolchain
```

| Test | Shows |
|---|---|
| `TestV1*` (7 tests) | Each v1 default in the table of section 2 |
| `TestDecodeLenientTrailingData` | `Decode` accepts trailing garbage, a second value, and `]`; `More()` misses `]` |
| `TestUpdateProfileUnsafeMassAssignment` | `isAdmin`, `ISADMIN` and `id` are all writable through the handler |
| `TestUpdateProfile` | DTO + `DecodeStrict` reject privileged fields, case duplicates, invalid UTF-8, trailing data, oversize; record untouched on error |
| `TestCheckKeys` | Duplicates in nested objects and arrays, KELVIN SIGN / LONG S folding, depth limit, no false positives on string values |
| `TestV2StricterDefaults`, `TestV2OptionsRestoreV1Behaviour` | v2 defaults and the options that restore v1 behaviour (`GOEXPERIMENT=jsonv2` only) |
| `ExampleUpdateProfileUnsafe` | `{"ISADMIN":true}` grants admin through the naive handler, not through the DTO |

## 7. Checklist

- [ ] Request bodies decode into input DTOs, never into stored models or structs with privileged fields.
- [ ] Decoders call `DisallowUnknownFields` and check for `io.EOF` after the value.
- [ ] Bodies that pass through another parser first are rejected on duplicate keys and invalid UTF-8.
- [ ] Large integers use `json.Number`, `int64` or strings, not `float64`.
- [ ] No `json:"-,"` tags on sensitive fields; no embedding of models into DTOs.
- [ ] Body size is limited before decoding (chapter 22).

## References

- Package [`encoding/json`](https://pkg.go.dev/encoding/json#Unmarshal) — `Unmarshal` (case-insensitive matching, U+FFFD substitution), [`Decoder.DisallowUnknownFields`](https://pkg.go.dev/encoding/json#Decoder.DisallowUnknownFields); [`encoding/json/v2`](https://pkg.go.dev/encoding/json/v2), [`encoding/json/jsontext`](https://pkg.go.dev/encoding/json/jsontext); [Go 1.25 release notes](https://go.dev/doc/go1.25)
- Trail of Bits — [Unexpected security footguns in Go's parsers](https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/) (2025)
- Bishop Fox — [An Exploration of JSON Interoperability Vulnerabilities](https://bishopfox.com/blog/json-interoperability-vulnerabilities) (2021)
- [CVE-2017-12635](https://nvd.nist.gov/vuln/detail/CVE-2017-12635) (Apache CouchDB duplicate-key privilege escalation)
- OWASP — [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html); RFC 8259 §4 ("names within an object SHOULD be unique")
