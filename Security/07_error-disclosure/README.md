# 07. Error Messages as Information Disclosure

> **Abstract.** Idiomatic Go error handling builds a string: each layer wraps the error from below with `fmt.Errorf("...: %w", err)` and adds the context it knows — the SQL statement, the database host, the file path, the key name. That makes errors excellent for operators and dangerous for clients, because `err.Error()` returns the entire chain. A handler that writes `err.Error()` into the response turns every failure into a reconnaissance report. The fix is not to write vaguer errors, but to **classify** them — `errors.Is`/`errors.As` on sentinels and typed public errors — send the client a fixed message plus a request ID, and log the full chain server side under that ID.

| | |
|---|---|
| Weaknesses | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) Generation of Error Message Containing Sensitive Information, [CWE-497](https://cwe.mitre.org/data/definitions/497.html) Exposure of Sensitive System Information to an Unauthorized Control Sphere, [CWE-200](https://cwe.mitre.org/data/definitions/200.html) Exposure of Sensitive Information to an Unauthorized Actor |
| Go packages | `errors`, `fmt`, `log/slog`, `net/http`, `crypto/rand` |
| Code | [`errors.go`](errors.go), [`handler.go`](handler.go), [`errdisclose_test.go`](errdisclose_test.go) |

## 1. Threat model

An unauthenticated or low-privilege client probes the API with malformed IDs, quotes, oversized values and wrong types. It does not need the request to succeed; it reads the error responses. Useful findings: SQL fragments that confirm an injection point and the schema (`tenant_id`), internal hostnames and ports for SSRF (chapter 27), file paths and key names for path traversal (chapter 31), library and version strings for known CVEs, and different messages for "user does not exist" vs "wrong password" (account enumeration).

## 2. What the standard library does

| Behaviour | Detail |
|---|---|
| `fmt.Errorf("%w")`, `errors.Join` (multiple wrapping since Go 1.20) | Keep the **full text** of every wrapped error in `Error()` and keep each cause reachable for `errors.Is`/`errors.As` |
| `*fs.PathError`, `*net.OpError`, `*url.Error` | Include paths, addresses and URLs in their messages |
| `strconv` errors | Echo the input: `strconv.Atoi: parsing "<payload>": invalid syntax` |
| `encoding/json` type errors | Name Go struct types, fields and kinds |
| `http.Error` | Writes the string verbatim as `text/plain; charset=utf-8` with `X-Content-Type-Options: nosniff` (limits reflected-XSS, not disclosure) |
| Handler panic | Stack trace goes to `Server.ErrorLog`, not to the client (chapter 05) |
| `net/http` responses | No `Server` header by default |
| `import _ "net/http/pprof"`, `expvar` | Register `/debug/pprof/` and `/debug/vars` on `http.DefaultServeMux` as a side effect — goroutine stacks, command line, memory stats |

## 3. Insecure pattern

[`HandlerUnsafe`](handler.go) is the shortest error path in Go and the most common one in code review:

```go
inv, err := LoadInvoice(id)
if err != nil {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
```

With the repository's ordinary wrapping, the client receives:

```text
load invoice: query "SELECT amount FROM invoices WHERE tenant_id = 42 AND id = '1' OR '1'='1'" on db-primary.billing.internal:5432: pq: syntax error at or near "'"
load invoice 1000 from /var/lib/billing/invoices.db: not found
sign invoice 1001: open /etc/billing/keys/invoice-signing.pem: permission denied
```

The first line confirms SQL injection and shows the multi-tenant schema; the second and third map the file system. The same leak happens through `fmt.Fprintf(w, "%v", err)`, error fields in JSON responses, and gRPC `status.Error(codes.Internal, err.Error())`.

## 4. Secure pattern

1. **Classify, don't stringify.** [`classify`](handler.go) decides the client-visible outcome with `errors.As(err, &*PublicError)` and `errors.Is(err, ErrNotFound)`; everything unrecognised is `500 internal error`. Wrapping can add any detail without changing the response.
2. **Make "safe for clients" a type.** [`PublicError`](errors.go) carries `Status`, a stable `Code`, a vetted `Msg` and an internal `Err` for logs. Only code that deliberately constructs one can put text in front of a client; validation messages ("invoice id is required") still get through.
3. **Correlate with a request ID.** The handler generates the ID server side (`crypto/rand.Text`, Go 1.24), returns it in `X-Request-ID` and the body, and logs `err.Error()` with `slog` under the same key. Support can find the full chain; the client sees `{"error":"internal","message":"internal error","request_id":"…"}`.
4. **Redact secrets at the type level.** [`Secret`](errors.go) implements `slog.LogValuer`, `fmt.Stringer` and `fmt.GoStringer`, so a key that ends up in a log attribute or an error message prints `[REDACTED]`.
5. **Keep debug endpoints off the public mux.** Serve `pprof`/`expvar` on a separate, internal listener, never on `http.DefaultServeMux` of an internet-facing server.

## 5. Where the guarantee ends

- **Status codes and timing are messages too.** Distinct 404/403 responses, or a fast "no such user" vs a slow password hash, enumerate accounts without any text (CWE-204, CWE-208; chapter 09). Return the same response for both and do comparable work.
- **Logs are a disclosure channel.** Moving detail from responses to logs is only safe if logs are access-controlled and free of credentials (CWE-532). Redact tokens, passwords and session IDs before they are wrapped into errors; `LogValuer` helps but only for typed values (chapters 37 and 38).
- **Errors cross trust boundaries in both directions.** Wrapping an upstream service's error message and returning it relays *their* internals; treat errors from dependencies as untrusted text.
- **Generic messages are not a substitute for validation.** Hiding the SQL error does not remove the SQL injection that produced it; parameterised queries (`db.QueryContext(ctx, "... WHERE id = $1", id)`, chapter 34) do.
- **Panic recovery middleware** that writes `debug.Stack()` or the panic value to the response undoes all of this (chapter 05).

## 6. Verification

```bash
go test -race -v ./Security/07_error-disclosure/
```

| Test | Shows |
|---|---|
| `TestHandlerUnsafeLeaksInternals` | SQL, hostnames, ports and paths appear in the unsafe response bodies |
| `TestHandlerMapsErrors` | Correct status/code per error class, no sensitive fragment in any body, request ID in header, body and log; 500s keep full detail in the log |
| `TestPublicMessagePassesThrough` | A `PublicError` message reaches the client; default IDs come from `crypto/rand.Text` |
| `TestWrappingKeepsDetailAndIdentity` | `%w` keeps both the text and the identity (`errors.Is/As`); classification works through extra wrapping |
| `TestSecretIsRedacted` | `slog` JSON output and `%v`/`%s`/`%#v` print `[REDACTED]` |
| `ExampleHandler` | The exact client-visible bodies |

## 7. Checklist

- [ ] No handler writes `err.Error()`, `%v` of an error, or a panic value into a response.
- [ ] A single error-to-response function maps errors with `errors.Is/As`; unknown errors become a generic 500.
- [ ] Client-visible messages come only from a dedicated public error type or fixed strings.
- [ ] Every error response carries a server-generated request ID that is also in the log entry.
- [ ] Secrets are typed (`LogValuer`/`Stringer`) or never placed in errors and log attributes.
- [ ] `net/http/pprof` and `expvar` are not reachable on public listeners.

## References

- Go Blog — [Working with Errors in Go 1.13](https://go.dev/blog/go1.13-errors), [Structured Logging with slog](https://go.dev/blog/slog)
- [`errors`](https://pkg.go.dev/errors), [`log/slog.LogValuer`](https://pkg.go.dev/log/slog#LogValuer), [`crypto/rand.Text`](https://pkg.go.dev/crypto/rand#Text)
- [`net/http/pprof`](https://pkg.go.dev/net/http/pprof) — registration on `DefaultServeMux`
- OWASP — [Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html), [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- RFC 9457 — [Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457)
