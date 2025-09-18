# 06. Goroutine Leaks & Unbounded Concurrency

> **Abstract.** A goroutine costs a few kilobytes and a `go` keyword, so it is easy to forget that the runtime never reclaims one that is blocked: there is no goroutine garbage collection, and a goroutine waiting on a channel nobody will ever touch keeps its stack and everything reachable from it forever. The classic leak is a worker sending its result on an **unbuffered** channel after the caller has timed out — one leaked goroutine per slow request, which an attacker controls by making requests slow. Its sibling is the unbounded fan-out: one goroutine per item in the request, so the client decides how much concurrency, memory and backend load the server takes on. Both are resource-exhaustion bugs that pass every functional test.

| | |
|---|---|
| Weaknesses | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) Uncontrolled Resource Consumption, [CWE-770](https://cwe.mitre.org/data/definitions/770.html) Allocation of Resources Without Limits or Throttling, [CWE-772](https://cwe.mitre.org/data/definitions/772.html) Missing Release of Resource after Effective Lifetime |
| Go packages | `context`, `sync`, `testing/synctest`, `runtime` |
| Code | [`leaks.go`](leaks.go), [`leaks_test.go`](leaks_test.go) |

## 1. Threat model

The attacker sends ordinary requests that are expensive in a way the server does not account for: requests that hit a slow dependency (or that the attacker makes slow, e.g. by pointing a webhook at a tarpit), requests with thousands of items in a batch, or connections that never finish. They want memory and goroutine count to grow without bound until the process is OOM-killed or latency collapses for everyone. Unlike a crash (chapter 05), a leak is cumulative: each request leaves a little behind, and the damage persists after the attacker stops.

## 2. What Go guarantees

| Fact | Consequence |
|---|---|
| A goroutine runs until its function returns; it cannot be killed from outside | Cancellation is cooperative: code must watch `ctx.Done()` |
| A blocked goroutine is never collected, nor is what its stack references | Leaks are permanent until restart |
| Send on an unbuffered channel blocks until a receiver arrives; with a buffer of 1, the first send never blocks | `make(chan T, 1)` decouples the worker from the caller's lifetime |
| `context.WithTimeout`/`WithCancel` return a `cancel` that must be called | `go vet`'s `lostcancel` check reports a discarded cancel |
| Go 1.23: unreferenced `time.Timer`/`Ticker` values are collectable even if not stopped | `time.After` in a loop no longer leaks timers (with `go ≥ 1.23` in `go.mod`); it still allocates per iteration |
| `net/http.Server` starts a goroutine per connection with no built-in cap | Concurrency limits are the application's job |
| `testing/synctest` (Go 1.25): `synctest.Test` fails if goroutines started in the bubble are still blocked when it returns | Leak tests become exact and run on a fake clock |

## 3. Insecure pattern

**Abandoned sender.** [`FetchUnsafe`](leaks.go) is the textbook "call with timeout":

```go
ch := make(chan string)              // unbuffered
go func() { ch <- work(ctx) }()
select {
case v := <-ch:     return v, nil
case <-ctx.Done():  return "", ctx.Err() // nobody will ever receive from ch
}
```

When the caller times out first, the worker eventually finishes and blocks on `ch <-` forever. `TestFetchUnsafeLeaks` makes 50 timed-out calls and then finds exactly 50 goroutines parked in `[chan send]` inside `FetchUnsafe.func1` by reading all goroutine stacks.

**Fan-out sized by the client.** [`ProcessAllUnsafe`](leaks.go) starts `len(items)` goroutines. With a 1,000-item batch and a slow `fn`, the synctest bubble shows 1,000 calls in flight at once: 1,000 stacks, 1,000 buffers, 1,000 backend connections.

## 4. Secure pattern

1. **Buffer the result channel to the number of senders** (here 1). The worker's send completes whether or not anyone is listening, and the goroutine exits ([`Fetch`](leaks.go)).
2. **Pass `ctx` into the work and honour it.** Buffering prevents the leak; cancellation also stops the wasted work. `TestFetchStopsCancellationAwareWork` shows the worker returning at the deadline instead of after an hour.
3. **Own every deadline.** `ctx, cancel := context.WithTimeout(parent, d); defer cancel()` ([`FetchWithTimeout`](leaks.go)).
4. **Bound concurrency with a semaphore or a fixed pool.** [`ProcessAll`](leaks.go) uses a buffered channel of `limit` tokens; dispatch blocks while all are out and stops on cancellation:

   ```go
   select {
   case sem <- struct{}{}:
   case <-ctx.Done(): return ctx.Err()
   }
   wg.Go(func() { defer func() { <-sem }(); fn(ctx, it) })
   ```

   Outside the standard library, `golang.org/x/sync/semaphore.Weighted` and `errgroup.Group.SetLimit` implement the same idea.
5. **Test for leaks.** Run concurrency tests inside `synctest.Test`: the fake clock makes timeouts instant and the bubble fails on any goroutine left blocked. Replacing `Fetch` with `FetchUnsafe` in `TestFetchDoesNotLeak` turns it into a deadlock failure.

## 5. Where the guarantee ends

- **Bounding goroutines does not bound queues.** A semaphore moves the backlog into the dispatcher; an unbounded batch is still unbounded input. Cap batch sizes and bodies (chapter 22) and rate-limit callers (chapter 28).
- **Slow clients hold goroutines too.** Without `http.Server.ReadHeaderTimeout`/`ReadTimeout`/`IdleTimeout`, a client that trickles bytes (Slowloris) keeps a connection goroutine alive indefinitely. Limit connections at the listener or proxy.
- **Detached contexts.** `context.WithoutCancel` (Go 1.21) and `context.Background()` inside a handler create work that outlives the request on purpose; give it its own timeout and bound.
- **Leaks outside goroutines.** Unclosed `resp.Body`, `*os.File`, `sql.Rows` and tickers leak file descriptors and connections with the same effect. `defer x.Close()` right after the error check.
- **Process-wide checks.** `runtime.NumGoroutine` deltas are noisy in tests that share a binary; synctest bubbles, stack inspection, or `go.uber.org/goleak` are more precise. In production, export the goroutine count as a metric and alert on growth.

## 6. Verification

```bash
go test -race -v ./Security/06_goroutine-leaks/
```

| Test | Shows |
|---|---|
| `TestFetchUnsafeLeaks` | 50 timed-out calls leave 50 goroutines blocked in `chan send` (outside a bubble, on purpose) |
| `TestFetchDoesNotLeak` | Same scenario in a synctest bubble: returns at exactly 1 s fake time, worker exits, bubble ends clean |
| `TestFetchStopsCancellationAwareWork` | A ctx-aware worker stops at the deadline, not after its hour of work |
| `TestProcessAllUnsafeIsUnbounded` | 1,000 items → 1,000 concurrent calls |
| `TestProcessAllIsBounded` | Limit 8 → exactly 8 in flight, all 1,000 processed |
| `TestProcessAllStopsOnCancel` | Cancellation stops dispatch after the 4 in-flight items |
| `ExampleFetchWithTimeout` | Normal use |

## 7. Checklist

- [ ] Every goroutine has a documented exit condition, and that condition includes `ctx.Done()`.
- [ ] Result/error channels written by workers are buffered to the number of writers, or the writer selects on `ctx.Done()`.
- [ ] Every `WithTimeout`/`WithCancel` has `defer cancel()`.
- [ ] No goroutine-per-item over client-controlled collections; a semaphore, pool or `SetLimit` caps concurrency.
- [ ] `http.Server` has read-header, read and idle timeouts.
- [ ] Concurrency code has `testing/synctest` tests that would fail on a leaked goroutine.

## References

- [`context`](https://pkg.go.dev/context), Go Blog — [Go Concurrency Patterns: Context](https://go.dev/blog/context), [Pipelines and cancellation](https://go.dev/blog/pipelines)
- [`testing/synctest`](https://pkg.go.dev/testing/synctest), Go Blog — [Testing concurrent code with testing/synctest](https://go.dev/blog/synctest), [Go 1.25 release notes](https://go.dev/doc/go1.25)
- [Go 1.23 release notes](https://go.dev/doc/go1.23) — timer garbage collection
- [`golang.org/x/sync/semaphore`](https://pkg.go.dev/golang.org/x/sync/semaphore), [`errgroup.Group.SetLimit`](https://pkg.go.dev/golang.org/x/sync/errgroup#Group.SetLimit)
- OWASP — [Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
