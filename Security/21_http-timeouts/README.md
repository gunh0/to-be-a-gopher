# 21. HTTP Timeouts & Slowloris

> **Abstract.** Every zero value in `net/http` means "wait forever". `http.ListenAndServe` and `&http.Server{}` have no read, write or idle timeouts, so a client that sends one header byte every few seconds holds a connection and a goroutine indefinitely; a few thousand such clients exhaust file descriptors. `http.Client{}` and `http.DefaultClient` have no overall timeout, so one silent upstream parks every calling goroutine. Go gives a separate knob for each phase — `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `MaxHeaderBytes`, `http.TimeoutHandler`, per-request deadlines through `http.ResponseController` (Go 1.20), and `Client.Timeout` plus `Transport` phase timeouts — and none of them is on by default.

| | |
|---|---|
| Weaknesses | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) Uncontrolled Resource Consumption, [CWE-1088](https://cwe.mitre.org/data/definitions/1088.html) Synchronous Access of Remote Resource without Timeout |
| Go packages | `net/http` (`Server`, `TimeoutHandler`, `ResponseController`, `Client`, `Transport`), `net` |
| Code | [`httptimeout.go`](httptimeout.go), [`httptimeout_test.go`](httptimeout_test.go) |

## 1. Threat model

The attacker can open TCP connections to the service, from one host or a botnet, and wants to make it unavailable at low cost: few bytes per second per connection, no bandwidth flood. On the client side the "attacker" may be nothing more than a slow or hung dependency, or a malicious server the service fetches from (webhooks, URL previews) that accepts the connection and never responds.

## 2. What `net/http` does by default

| Setting | Zero value means | Notes |
|---|---|---|
| `Server.ReadHeaderTimeout` | `ReadTimeout`; if that is zero, no limit | The Slowloris window |
| `Server.ReadTimeout` | No limit | Covers headers and body; handlers can extend it per request |
| `Server.WriteTimeout` | No limit | From the end of the request headers to the end of the response |
| `Server.IdleTimeout` | `ReadTimeout`; if that is zero, no limit | Keep-alive wait between requests |
| `Server.MaxHeaderBytes` | `http.DefaultMaxHeaderBytes` (1 MiB) | Exceeding it returns 431 |
| `Client.Timeout` | No limit | Whole exchange including reading the body |
| `http.DefaultTransport` | Dial 30 s, TLS handshake 10 s, idle 90 s | **No** `ResponseHeaderTimeout` |

For TLS connections the server bounds the handshake with the smallest of `ReadHeaderTimeout`, `ReadTimeout` and `WriteTimeout` that is set, so the same settings also cover slow TLS clients. HTTP/2 has its own limits in `Server.HTTP2` (`*http.HTTP2Config`, Go 1.24): `MaxConcurrentStreams`, ping timeouts and more.

## 3. Insecure pattern

```go
http.ListenAndServe(":8080", mux)                 // gosec G114
srv := &http.Server{Addr: ":8080", Handler: mux}  // gosec G112: no ReadHeaderTimeout
resp, err := http.Get(url)                        // http.DefaultClient, no timeout
```

[`NewServerUnsafe`](httptimeout.go) is exactly that server. `TestSlowlorisHoldsUnsafeServer` opens a raw TCP connection, sends a request line and then one header line every 20 ms without ever ending the header block; after the test's 200 ms limit the connection is still open, and it would stay open indefinitely. The goroutine, the socket buffer and the file descriptor stay allocated for each such connection.

[`NewClientUnsafe`](httptimeout.go) (`http.Client{}`) against a server that accepts and never answers is still waiting when `TestDefaultClientWaitsForever` gives up looking. In production, every request that touches that dependency adds one more stuck goroutine.

## 4. Secure pattern

[`NewServer`](httptimeout.go) with [`Production`](httptimeout.go):

```go
&http.Server{
	ReadHeaderTimeout: 5 * time.Second,
	ReadTimeout:       30 * time.Second,
	WriteTimeout:      30 * time.Second,
	IdleTimeout:       120 * time.Second,
	MaxHeaderBytes:    64 << 10,
}
```

1. **`ReadHeaderTimeout` always.** Legitimate clients send headers in one packet; a short value costs nothing. With 50 ms in the test, the Slowloris connection is closed after about 50 ms (`TestReadHeaderTimeoutCutsSlowloris`).
2. **`ReadTimeout`/`WriteTimeout` as server-wide ceilings**, generous enough for normal requests.
3. **Per-route exceptions, not global relaxation.** [`ExtendDeadlines`](httptimeout.go) uses `http.NewResponseController(w).SetReadDeadline/SetWriteDeadline` for the upload or report route that needs minutes, while the rest of the server keeps tight limits (`TestWriteTimeoutAndPerRouteExtension`). Middleware that wraps the `ResponseWriter` must implement `Unwrap() http.ResponseWriter`, or the controller returns `http.ErrNotSupported`; check that error (`TestResponseControllerNeedsUnwrap`).
4. **Bound handler work** with [`WithHandlerTimeout`](httptimeout.go) (`http.TimeoutHandler`): after the limit the client gets 503 and `r.Context()` is cancelled, which stops database and outbound calls that use it (`TestTimeoutHandlerCancelsWork`). It buffers the response, so it does not suit streaming endpoints.
5. **`MaxHeaderBytes`** well below the 1 MiB default (`TestMaxHeaderBytes`: 16 KiB of headers → 431).
6. **Clients**: [`NewClient`](httptimeout.go) sets `Client.Timeout` and the `Transport` phases (`DialContext` timeout, `TLSHandshakeTimeout`, `ResponseHeaderTimeout`, `MaxResponseHeaderBytes`). Per-call deadlines come from `http.NewRequestWithContext`. `TestClientTimeout` fails after 50 ms with an error whose `Timeout()` is true.

## 5. Where the protection ends

- **Connection count.** Timeouts shorten how long each connection is held, not how many there are. Limit concurrent connections (`golang.org/x/net/netutil.LimitListener`, or the load balancer) and requests per client.
- **Expensive requests.** A fast, valid request that triggers expensive work (password hashing, chapter 12; large JSON; regex) needs its own limits: `http.MaxBytesReader`, concurrency semaphores, rate limits.
- **Streaming and WebSockets** need deadlines managed per message rather than per request.
- **Behind a proxy**, the proxy's timeouts protect the edge; the Go server still needs its own for traffic that bypasses it and for the proxy-to-server hop.
- **HTTP/2** multiplexes many streams over one connection; per-connection timeouts do not bound per-stream work. Keep the Go version current (HTTP/2 Rapid Reset, CVE-2023-44487, was fixed in Go 1.21.3 and 1.20.10).

## 6. Verification

```bash
go test -race -v ./Security/21_http-timeouts/
```

| Test | Shows |
|---|---|
| `TestSlowlorisHoldsUnsafeServer` | A trickling client keeps a connection to a zero-value server open |
| `TestReadHeaderTimeoutCutsSlowloris` | With `ReadHeaderTimeout` 50 ms the connection is closed within ~50 ms |
| `TestMaxHeaderBytes` | 16 KiB of headers pass the 1 MiB default; a 1 KiB limit returns 431 |
| `TestTimeoutHandlerCancelsWork` | 503 after the limit, and the handler's context is cancelled |
| `TestWriteTimeoutAndPerRouteExtension` | `WriteTimeout` breaks a slow response; `ResponseController` extends it for one route |
| `TestResponseControllerNeedsUnwrap` | A wrapper without `Unwrap` makes deadline control fail visibly |
| `TestDefaultClientWaitsForever` | `http.Client{}` does not return from a hung server |
| `TestClientTimeout` | `NewClient` fails with a `net.Error` timeout |

Timeouts in the tests are 50 ms; no test sleeps longer than 100 ms.

## 7. Checklist

- [ ] No `http.ListenAndServe`, `http.ListenAndServeTLS` or `http.Serve` in production code.
- [ ] Every `http.Server` sets `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout` and `MaxHeaderBytes`.
- [ ] Long-running routes extend deadlines with `http.ResponseController` and check its error.
- [ ] Handlers pass `r.Context()` downstream; slow handlers are bounded by `http.TimeoutHandler` or context deadlines.
- [ ] No `http.Get`/`http.DefaultClient`/`http.Client{}` for outbound calls; clients set `Timeout` and `Transport` phase timeouts.
- [ ] gosec G112/G114 (or an equivalent check) runs in CI.

## References

- [`net/http.Server`](https://pkg.go.dev/net/http#Server), [`http.ResponseController`](https://pkg.go.dev/net/http#ResponseController), [`http.TimeoutHandler`](https://pkg.go.dev/net/http#TimeoutHandler), [`http.HTTP2Config`](https://pkg.go.dev/net/http#HTTP2Config)
- [Go 1.20 release notes](https://go.dev/doc/go1.20) (`ResponseController`), [Go 1.24 release notes](https://go.dev/doc/go1.24) (`Server.HTTP2`)
- Cloudflare — [The complete guide to Go net/http timeouts](https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/)
- [CVE-2023-44487](https://nvd.nist.gov/vuln/detail/CVE-2023-44487) HTTP/2 Rapid Reset
- [gosec](https://github.com/securego/gosec) rules G112, G114
