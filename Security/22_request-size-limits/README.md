# 22. Request Size Limits & Decompression Bombs

> **Abstract.** `net/http` puts no limit on request body size, and `json.NewDecoder(r.Body).Decode` buffers the whole value it is decoding, so a single POST can pin gigabytes of memory. The usual fix, `io.LimitReader`, bounds memory but reports `io.EOF` at the limit: oversized input is *silently truncated* rather than rejected. `http.MaxBytesReader` returns a typed `*http.MaxBytesError` and closes the connection; for any other reader, read `limit+1` bytes and fail if you get them. With compression the expensive quantity is the **decompressed** size: an 8 KiB gzip body expands to 8 MiB at roughly 1000:1, so the limit belongs on the decompressor's output, not on the wire.

| | |
|---|---|
| Weaknesses | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) Uncontrolled Resource Consumption, [CWE-409](https://cwe.mitre.org/data/definitions/409.html) Improper Handling of Highly Compressed Data (Data Amplification), [CWE-770](https://cwe.mitre.org/data/definitions/770.html) Allocation of Resources Without Limits or Throttling |
| Go packages | `net/http`, `io`, `encoding/json`, `compress/gzip`, `mime/multipart` |
| Code | [`body.go`](body.go), [`gzip.go`](gzip.go), [`reqlimit_test.go`](reqlimit_test.go) |

## 1. Threat model

An unauthenticated client can reach an HTTP endpoint that accepts JSON, form uploads, or gzip-encoded bodies. The attacker controls the body length, the `Content-Length` header (or uses chunked encoding and sends none), the `Content-Encoding`, and the content. Their goal is availability: exhaust memory, disk or CPU of the process with as few bytes and requests as possible. Amplification matters more than raw size: the attack is cheap when one byte sent costs the server a thousand.

## 2. What the standard library does

| Layer | Default bound | Notes |
|---|---|---|
| Request line + headers | `http.Server.MaxHeaderBytes`, default `http.DefaultMaxHeaderBytes` = 1 MiB | The only size limit that applies without code |
| Request body | **none** | `r.Body` streams whatever the client sends |
| `r.ParseForm` (urlencoded) | 10 MiB | Skipped if `r.Body` is already a `MaxBytesReader`: your limit replaces it |
| `r.ParseMultipartForm(maxMemory)` | `maxMemory` in RAM **+ 10 MiB** for non-file parts; files beyond `maxMemory` go to **temp files on disk**; at most 1000 parts (`GODEBUG=multipartmaxparts`) | Part and header caps date from [CVE-2023-24536](https://nvd.nist.gov/vuln/detail/CVE-2023-24536) (Go 1.19.8 / 1.20.3). Total upload size is not bounded |
| `json.Decoder.Decode` | none | Reads until the value is complete; long strings and arrays are buffered whole |
| `gzip.Reader` | none | Multistream by default: concatenated members decode as one stream |

`http.MaxBytesReader(w, r.Body, n)` is the primitive designed for this. On the first read past `n` it returns `*http.MaxBytesError` (exported in Go 1.19, with a `Limit` field) and, when `w` is the server's `ResponseWriter`, marks the connection to be closed after the response, so the client cannot keep streaming the rest of a multi-gigabyte body into the same socket. `http.MaxBytesHandler(h, n)` (Go 1.18) applies it to every request of a handler.

`io.LimitReader` is a different tool: it ends the stream with `io.EOF` at the limit. That bounds memory, but the consumer cannot tell "the body was exactly n bytes" from "the body was longer and was cut".

## 3. Insecure pattern

```go
// No limit: the body is read until the client stops sending.
json.NewDecoder(r.Body).Decode(&v)

// Bounded but silent: a 10 GB upload becomes a corrupt 10 MB file, no error.
data, _ := io.ReadAll(io.LimitReader(r.Body, 10<<20))

// Limit on the wrong side of the decompressor.
zr, _ := gzip.NewReader(http.MaxBytesReader(w, r.Body, 1<<20))
plain, _ := io.ReadAll(zr) // 1 MiB on the wire, ~1 GiB in memory

// maxMemory is a spill threshold, not a size limit.
r.ParseMultipartForm(32 << 20) // a 50 GB file part is written to /tmp
```

[`DecodeUnbounded`](body.go), [`ReadTruncating`](body.go) and [`GunzipUnsafe`](gzip.go) reproduce these. The tests decode a 4 MiB JSON string with no complaint, accept `"0123456789"` as `"0123"`, and inflate 8 KiB of gzip into 8 MiB.

## 4. Secure pattern

1. **Bound the wire bytes** with `http.MaxBytesReader` before any parser touches `r.Body`, and map `*http.MaxBytesError` to `413`.
2. **Bound decompressed bytes separately**, on the reader the handler consumes. A wire limit says nothing about the expanded size.
3. **Fail, do not truncate**: read `limit+1` bytes and treat getting them as an error ([`ReadAtMost`](body.go)).
4. **Reject trailing data** after a JSON value; a bare `Decode` silently ignores it.
5. **Wrap the body before `ParseMultipartForm`**: `maxMemory` decides RAM versus disk; only `MaxBytesReader` decides how much is accepted.

```go
r.Body = http.MaxBytesReader(w, r.Body, limit)
dec := json.NewDecoder(r.Body)
if err := dec.Decode(v); err != nil {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) { /* 413 */ }
}
if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) { /* trailing data */ }
```

[`DecompressBody`](gzip.go) composes both limits as middleware: `MaxBytesReader(maxWire)` underneath `gzip.NewReader`, and a reader that returns `ErrTooLarge` past `maxPlain` on top. Because the decompressor is pulled lazily, rejecting a bomb costs work proportional to `maxPlain`: the test shows less than half of a 16 MiB bomb's compressed bytes are ever read.

## 5. Where the limits end

- **Time is a resource too.** A client that sends one byte per second stays under every size limit. Set `http.Server.ReadHeaderTimeout` and `ReadTimeout` (or per-request deadlines with `http.ResponseController.SetReadDeadline`, Go 1.20); chapter 21.
- **Many small requests** defeat per-request limits; that is rate limiting, chapter 28.
- **Archives** carry the same amplification per entry plus path attacks; chapter 32 applies these limits to `archive/zip` and `archive/tar`.
- **Multipart temp files** live in `os.TempDir()` until `r.MultipartForm.RemoveAll()` runs; the server calls it after the handler returns, but a full disk is reached before that.

## 6. Verification

```bash
go test -v ./Security/22_request-size-limits/
```

| Test | Shows |
|---|---|
| `TestDecodeUnboundedConsumesWholeBody` | `json.Decoder` on a raw body reads and holds a 4 MiB value |
| `TestReadTruncatingSilentlyAcceptsOversizedInput` | `io.LimitReader` returns a prefix and `nil` error |
| `TestReadAtMost` | `limit+1` read distinguishes exact-size from oversized input |
| `TestDecodeLimitedOverHTTP` | Real server: 413 plus `Connection: close` past the limit; trailing JSON value rejected |
| `TestGunzipUnsafeExpandsBomb` | ~8 KiB of gzip becomes 8 MiB in memory (ratio > 900:1) |
| `TestGunzipLimitedStopsEarly` | Output limit triggers after reading under half of the compressed input |
| `TestGunzipLimitedConcatenatedMembers` | Multistream members are counted together against one limit |
| `TestDecompressBody` | Middleware rejects both a wire-oversized body and a bomb that fits the wire limit |
| `TestParseMultipartFormMaxMemoryIsNotASizeLimit` | A 4 MiB file with `maxMemory` = 1 MiB is accepted and spilled to `TMPDIR` |
| `TestParseMultipartFormWithMaxBytesReader` | The same upload fails with `*http.MaxBytesError` when the body is wrapped |

## 7. Checklist

- [ ] Every handler that reads a body wraps it in `http.MaxBytesReader` (or sits behind `http.MaxBytesHandler`).
- [ ] `*http.MaxBytesError` maps to 413, not 400 or 500.
- [ ] No `io.LimitReader` where truncation would be accepted as valid data.
- [ ] Decompressed and decoded sizes have their own limit, applied after every decoding stage.
- [ ] `ParseMultipartForm` is preceded by a body limit; temp-file disk usage is monitored.
- [ ] `http.Server` has `ReadHeaderTimeout`/`ReadTimeout` set; `MaxHeaderBytes` is a conscious choice.

## References

- Go documentation — [`http.MaxBytesReader`](https://pkg.go.dev/net/http#MaxBytesReader), [`http.MaxBytesError`](https://pkg.go.dev/net/http#MaxBytesError), [`Request.ParseMultipartForm`](https://pkg.go.dev/net/http#Request.ParseMultipartForm), [`multipart.Reader.ReadForm`](https://pkg.go.dev/mime/multipart#Reader.ReadForm), [`gzip.Reader.Multistream`](https://pkg.go.dev/compress/gzip#Reader.Multistream)
- [Go 1.19 release notes](https://go.dev/doc/go1.19#net/http) — `MaxBytesError`
- [CVE-2023-24536](https://nvd.nist.gov/vuln/detail/CVE-2023-24536) — excessive resource consumption in `mime/multipart` form parsing
- zlib — [Technical details](https://www.zlib.net/zlib_tech.html) (maximum DEFLATE compression factor of 1032:1)
- OWASP — [Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
