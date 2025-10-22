# 38. Secrets in Memory and Logs

> **Abstract.** Most secret leaks in Go services are not memory attacks; they are `log.Printf("config: %+v", cfg)`. A secret type with a `String` method is the usual fix and covers only `%v` and `%s`: `%#v`, `%d`, `json.Marshal`, `slog.JSONHandler`, and *any unexported struct field* (on which `fmt` cannot call methods) still print the value. A robust `Secret` implements `fmt.Formatter`, `GoStringer`, `json.Marshaler`, `encoding.TextMarshaler` and `slog.LogValuer`, and keeps its bytes behind a pointer so that reflection-based printing shows an address. In memory, Go offers less: strings are immutable, `append` and stack growth leave copies, and `clear` zeroes one backing array — so zeroing is hygiene, not a guarantee.

| | |
|---|---|
| Weaknesses | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) Insertion of Sensitive Information into Log File, [CWE-226](https://cwe.mitre.org/data/definitions/226.html) Sensitive Information in Resource Not Removed Before Reuse, [CWE-312](https://cwe.mitre.org/data/definitions/312.html) Cleartext Storage of Sensitive Information |
| Go packages | `fmt`, `log/slog`, `encoding/json`, `crypto/subtle`, `os`, `runtime/debug` |
| Code | [`secret.go`](secret.go), [`load.go`](load.go), [`secrets_test.go`](secrets_test.go) |

## 1. Threat model

The service holds database passwords, API keys and signing keys. The attacker is anyone who can read what the service emits: log aggregation users, error-tracking SaaS, crash reports, CI output, a support engineer with `kubectl logs`, a child process, or someone with a core dump. Their goal is to obtain a credential without ever touching the process's memory directly.

## 2. What Go guarantees

**Formatting.** `fmt` checks, in order: `Formatter` (all verbs), then for `%#v` `GoStringer`, then `error`/`Stringer` for `%v %s %q %x %X`. Other verbs (`%d`) on a string type print the underlying value. Per the `fmt` documentation, "when printing a struct, fmt cannot and therefore does not invoke formatting methods such as Error or String on unexported fields" — it walks them with reflection.

| Path | `string` | `NaiveSecret` (String only) | `Secret` |
|---|---|---|---|
| `%v`, `%s`, `%+v` (exported field) | leak | redacted | redacted |
| `%#v`, `%d` | leak | **leak** | redacted |
| Unexported struct field, any verb | leak | **leak** | `{0xc000…}` (address only) |
| `json.Marshal` | leak | **leak** | `"[REDACTED]"` |
| `slog.JSONHandler` | leak | **leak** | `"[REDACTED]"` (`LogValue`) |
| `slog.TextHandler`, `encoding/xml` | leak | redacted / leak | redacted (`LogValue`, `MarshalText`) |

**Memory.** Go zeroes memory on allocation, not on release. There is no API to pin, lock or wipe the heap. `clear(b)` (Go 1.21) zeroes the elements of one slice; it does nothing to earlier backing arrays left behind by `append` growth, to copies made by `string(b)` / `[]byte(s)`, to goroutine stacks that were copied when they grew, or to pages the OS swapped out.

## 3. Insecure pattern

```go
type Config struct{ User, Password string }
log.Printf("loaded config: %+v", cfg)              // {User:app Password:hunter2}

type NaiveSecret string
func (NaiveSecret) String() string { return "[REDACTED]" }
fmt.Sprintf("%#v", NaiveSecret("hunter2"))           // "hunter2"
json.Marshal(struct{ P NaiveSecret }{"hunter2"})    // {"P":"hunter2"}
```

Related leaks: `fmt.Errorf("connect %s: %w", dsn, err)` with a DSN containing a password (use [`url.URL.Redacted`](https://pkg.go.dev/net/url#URL.Redacted), Go 1.15), `httputil.DumpRequest` with an `Authorization` header, and `panic(err)` where `err` embeds a credential — the runtime prints the panic value.

## 4. Secure pattern

[`Secret`](secret.go) closes every path in the table:

```go
type Secret struct{ p *secretValue }               // pointer: reflection prints an address
func (Secret) Format(f fmt.State, verb rune)       { io.WriteString(f, Redacted) } // all verbs
func (Secret) GoString() string                    { ... }
func (Secret) MarshalJSON() ([]byte, error)        { ... }
func (Secret) MarshalText() ([]byte, error)        { ... }
func (Secret) LogValue() slog.Value                { return slog.StringValue(Redacted) }
func (s Secret) Reveal() string                    // explicit, greppable
func (s Secret) Equal(candidate string) bool       // crypto/subtle, chapter 09
```

Supporting rules:

1. **Type secrets at the boundary.** Configuration structs hold `Secret`, not `string`; the only way out is `Reveal()`, which is easy to grep and review.
2. **Load carefully.** [`FromFile`](load.go) refuses group/world-accessible files and non-regular files, bounds the size, trims one newline and clears its read buffer. Kubernetes secret volumes default to mode `0644` and Docker secrets to `0444`; set `defaultMode: 0400` (or relax the check deliberately). [`FromEnv`](load.go) unsets the variable after reading, so children started with `Cmd.Env == nil` do not inherit it (chapter 33).
3. **Zero what you own, without overclaiming.** `FromBytes` copies then clears the caller's buffer; `Destroy` clears the secret's buffer. `TestDestroyCannotReachCopies` and `TestClearDoesNotReachOldBackingArrays` show the limits.
4. **Keep secrets out of crash output.** Leave `GOTRACEBACK` at the default (`single`); `crash` additionally raises `SIGABRT` and produces a core dump on Unix — a full memory image. `runtime/debug.SetTraceback` can raise the level at run time but cannot lower it below the environment variable's setting. Disable core dumps (`ulimit -c 0`, `RLIMIT_CORE`) for processes holding long-lived keys. Tracebacks themselves print argument words (pointers, lengths), not string contents.

## 5. Where the guarantee ends

- **`Reveal()` output is a normal string.** Once passed to a driver, an HTTP header or a log line, it is outside this package's control.
- **`reflect` and `unsafe`** can read any field; so can a debugger, `/proc/<pid>/mem` for the same user, and a heap dump (`debug.WriteHeapDump`).
- **Environment variables** remain visible in `/proc/<pid>/environ` on Linux (the initial environment block is not rewritten by `Unsetenv`) and in orchestration metadata (`docker inspect`, pod specs). Prefer mounted files or a secret manager.
- **Third-party loggers and error trackers** may serialise structs with their own reflection and ignore `LogValuer`; test them with the same table.
- **Error wrapping** keeps the original text: `fmt.Errorf("...: %w", err)` with a driver error that quotes the DSN leaks through every layer above (chapter 07).
- **Crypto keys** in `crypto/*` types (`*ecdsa.PrivateKey`, `cipher.AEAD`) hold their own copies; `Secret` cannot reach those either.

## 6. Verification

```bash
go test -v ./Security/38_secret-handling/
```

| Test | Shows |
|---|---|
| `TestPlainConfigLeaks` | `%+v` on a config struct prints the password |
| `TestNaiveSecretLeaks` | String-only redaction leaks via `%#v`, `%d`, unexported field, `json.Marshal`, slog JSON |
| `TestSecretRedactsEveryFmtPath` | 10 verbs × 7 positions (value, pointer, exported/unexported/nested field, slice, map): no plaintext, no hex |
| `TestSecretRedactsEncoders` | JSON, XML, slog text/JSON, `log.Printf`, `fmt.Errorf` |
| `TestSecretAccessors` | `Reveal`, constant-time `Equal`, zero value |
| `TestDestroyCannotReachCopies` | A revealed string survives `Destroy` |
| `TestFromBytesClearsSource` | The caller's buffer is zeroed |
| `TestClearDoesNotReachOldBackingArrays` | `append` growth leaves the old array intact after `clear` |
| `TestFromEnvRemovesVariable` | The variable is gone from `os.Environ` after loading |
| `TestFromFile` | `0600` accepted with newline trimmed; `0644` and directories refused |
| `Example` | Redacted output of `%v`, `%+v`, `%#v`, JSON |

## 7. Checklist

- [ ] Credentials are typed (`Secret`), never plain `string` fields in config structs.
- [ ] The secret type implements `Format`, `GoString`, `MarshalJSON`, `MarshalText`, `LogValue`.
- [ ] `Reveal()` calls are few and reviewed.
- [ ] DSNs and URLs are logged with `Redacted()`; request dumps strip `Authorization` and cookies.
- [ ] Secret files are `0400`/`0600`; environment secrets are unset after reading.
- [ ] Core dumps are disabled and `GOTRACEBACK` is not `crash` in production.
- [ ] Logging and error-tracking libraries are tested against the table above.

## References

- Package [`fmt`](https://pkg.go.dev/fmt) — "Printing" (method precedence, unexported fields); [`log/slog.LogValuer`](https://pkg.go.dev/log/slog#LogValuer); [`url.URL.Redacted`](https://pkg.go.dev/net/url#URL.Redacted)
- Package [`runtime`](https://pkg.go.dev/runtime#hdr-Environment_Variables) (`GOTRACEBACK`), [`runtime/debug.SetTraceback`](https://pkg.go.dev/runtime/debug#SetTraceback)
- Go spec — [Clear](https://go.dev/ref/spec#Clear) (Go 1.21)
- OWASP — [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- Kubernetes — [Secrets: using Secrets as files from a Pod](https://kubernetes.io/docs/concepts/configuration/secret/)
