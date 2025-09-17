# 05. Panics as Denial of Service

> **Abstract.** Go turns most memory errors into panics (chapter 01), which moves the failure from confidentiality to availability. Whether that availability loss is one request or the whole service depends on **which goroutine panics**. `net/http` recovers panics on the goroutine that runs `ServeHTTP` and drops only that connection; a panic on any goroutine the handler starts — a background job, a fan-out worker, a callback — is unrecovered and exits the process with status 2, taking every in-flight request with it. And some failures are not panics at all: concurrent map writes and stack exhaustion are fatal errors that no `recover` can catch. A single malformed header or JSON body should never be able to reach either.

| | |
|---|---|
| Weaknesses | [CWE-248](https://cwe.mitre.org/data/definitions/248.html) Uncaught Exception, [CWE-476](https://cwe.mitre.org/data/definitions/476.html) NULL Pointer Dereference, [CWE-400](https://cwe.mitre.org/data/definitions/400.html) Uncontrolled Resource Consumption |
| Go packages | `net/http`, `runtime`, `runtime/debug`, `log/slog`, `strings` |
| Code | [`input.go`](input.go), [`boundary.go`](boundary.go), [`panics_test.go`](panics_test.go) |

## 1. Threat model

An unauthenticated client sends malformed but well-formed-enough input: an `Authorization` header without a token, a JSON body missing a field or with a field of the wrong type, `null` where an object is expected, a deeply nested document. The attacker's goal is availability: crash the process (and with it every other user's requests), trigger a restart loop, or make each crash cheap enough to repeat faster than the orchestrator restarts the pod.

## 2. What Go guarantees

| Failure | Kind | Recoverable | Under `net/http` |
|---|---|---|---|
| Index/slice out of range, nil pointer dereference, nil map write, failed single-value type assertion, integer divide by zero | Run-time panic (`runtime.Error`) | Yes, on the same goroutine | Handler goroutine: recovered, stack logged to `Server.ErrorLog`, connection closed (HTTP/1) or stream reset (HTTP/2) |
| `panic(http.ErrAbortHandler)` | Panic | Yes | Response aborted, **not** logged |
| Any panic on a goroutine started by the handler | Panic | Only by a `defer`/`recover` on that goroutine | **Process exits**, status 2 |
| Concurrent map writes, stack exceeding the max (1 GB on 64-bit, 250 MB on 32-bit), out of memory, `sync: unlock of unlocked mutex` | Fatal error (throw) | **No** | Process exits |
| `panic(nil)` | Since Go 1.21, becomes `*runtime.PanicNilError` | Yes | As above |

`recover` only works when called directly by a deferred function on the panicking goroutine. There is no process-wide handler, by design.

## 3. Insecure pattern

**Panicking parsers.** Each of these is a one-request crash, recovered by `net/http` but still logged with a stack trace per request (log flooding, CWE-400) and a dropped connection:

```go
strings.Split(header, " ")[1]      // "Bearer" → index out of range [1] with length 1
claims["role"].(string)            // missing claim or {"role": 1} → interface conversion panic
ev.Labels["received_by"] = host    // {"labels": null} → assignment to entry in nil map
```

**Unbounded goroutines.** [`AsyncHandlerUnsafe`](boundary.go) acknowledges the request and processes it with a bare `go func() { ... }()`. A body of `{"action":"x"}` reaches the nil map write on that goroutine; nothing recovers it and the server exits. `TestGoroutinePanicKillsProcess` shows this in a child process: exit status 2, `panic: assignment to entry in nil map`.

## 4. Secure pattern

1. **Parse without panicking.** `strings.Cut` instead of `Split(...)[i]`; comma-ok type assertions (`v, ok := x.(T)`); initialise every map/pointer the server writes to after decoding, whatever the client sent ([`DecodeEvent`](input.go)); decode into typed structs rather than `map[string]any`.
2. **A recovery boundary on every goroutine that touches input.** [`Go`](boundary.go) wraps `fn` in `defer recover()` and reports the value and `debug.Stack()` to a callback (log, metric, error channel). `sync.WaitGroup.Go` (Go 1.25) is not a boundary: its documentation states that `f` must not panic.
3. **Middleware that answers instead of dropping.** [`Recover`](boundary.go) converts a handler panic into a generic 500 and a structured `slog` entry, and re-panics `http.ErrAbortHandler` so deliberate aborts keep their meaning. The stack goes to the log, never to the client (chapter 07).
4. **Bound recursion and size before parsing.** Fatal stack exhaustion cannot be recovered; limit nesting depth in recursive decoders and limit request bodies (`http.MaxBytesReader`, chapter 22).

```go
Go(func(v any, stack []byte) {
	log.Error("worker panic", "panic", v, "stack", string(stack))
}, func() { process(body) })
```

## 5. Where the guarantee ends

- **Recovery is not rollback.** A panic halfway through a critical section can leave a mutex locked (unless released by `defer`) or an invariant half-updated. Recover at request/job boundaries, not deep inside state mutation, and keep `defer mu.Unlock()`.
- **Other servers differ.** `net/http` recovers handler panics; grpc-go does not install a recovery interceptor by default, and most job queues and custom TCP servers do not either. Check each entry point.
- **Fatal errors bypass everything.** `concurrent map writes` (chapter 04), runaway recursion and OOM end the process regardless of middleware. Several 2022 standard-library fixes were exactly this class, e.g. stack exhaustion in `encoding/xml` (CVE-2022-28131, CVE-2022-30633), and panics in `math/big` `GobDecode` on crafted input (CVE-2022-32189).
- **Restart loops are still DoS.** If one request can crash a replica, the attacker sends it once per restart. Recovery plus input validation is the fix; liveness probes are not.
- **Panics as control flow.** Libraries that panic on bad input (some template, regexp `MustCompile` with user patterns, `reflect`) need the same boundary when given untrusted data.

## 6. Verification

```bash
go test -race -v ./Security/05_panic-boundaries/
```

| Test | Shows |
|---|---|
| `TestBearer` | `Split(...)[1]` panics on `"Bearer"` and `""`; `strings.Cut` rejects without panicking |
| `TestRole` | Missing, `null`, numeric claims and a nil map all panic the single-value assertion only |
| `TestDecodeEvent` | Omitted or `null` labels panic the unsafe decoder; the safe one initialises the map |
| `TestNetHTTPRecoversHandlerPanic` | The panicking request's connection drops, the next request succeeds, the panic is in `ErrorLog` |
| `TestRecoverMiddleware` | 500 without panic details in the body, details in `slog`; `ErrAbortHandler` is re-raised |
| `TestHandlerValidates` | Malformed headers get 401 instead of a panic |
| `TestGoRecovers` | The `Go` boundary reports the panic value and stack, the test binary survives |
| `TestGoroutinePanicKillsProcess` | A re-executed child process running `AsyncHandlerUnsafe` dies with exit status 2 |
| `TestPanicNilIsVisible` | `panic(nil)` is recovered as `*runtime.PanicNilError` |

## 7. Checklist

- [ ] No `x.(T)` single-value assertion, `s[i]` from a split, or map write into a decoded struct without validation on request paths.
- [ ] Every `go` statement in server code runs behind a recover boundary that logs and reports.
- [ ] HTTP and RPC servers have recovery middleware that returns a generic error and logs the stack server side.
- [ ] Request bodies and recursive structures are bounded before decoding.
- [ ] Crash-on-input is tested: fuzz targets (`go test -fuzz`) for parsers, since a fuzzer's first finding is usually a panic.

## References

- [`net/http.Handler`](https://pkg.go.dev/net/http#Handler) — panic recovery contract, [`http.ErrAbortHandler`](https://pkg.go.dev/net/http#ErrAbortHandler)
- The Go Programming Language Specification — [Handling panics](https://go.dev/ref/spec#Handling_panics), [Run-time panics](https://go.dev/ref/spec#Run_time_panics)
- Go Blog — [Defer, Panic, and Recover](https://go.dev/blog/defer-panic-and-recover)
- [Go 1.21 release notes](https://go.dev/doc/go1.21#language) — `panic(nil)` and `runtime.PanicNilError`
- [`runtime/debug.SetMaxStack`](https://pkg.go.dev/runtime/debug#SetMaxStack)
- [CVE-2022-28131](https://nvd.nist.gov/vuln/detail/CVE-2022-28131), [CVE-2022-30633](https://nvd.nist.gov/vuln/detail/CVE-2022-30633), [CVE-2022-32189](https://nvd.nist.gov/vuln/detail/CVE-2022-32189)
