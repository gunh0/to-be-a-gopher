# 04. Data Races

> **Abstract.** Go makes concurrency cheap and gives two very different failure modes the same name. A **data race** — two goroutines touching the same memory, at least one writing, with no happens-before edge — is undefined enough to corrupt memory: interfaces, slices, strings and maps are multi-word values and can be observed half-written. The race detector finds these, but only on paths a test executes. A **race condition** — check-then-act on shared state — survives perfect synchronisation: every access can be locked, `go test -race` can be green, and a balance still goes negative because the check and the act were two critical sections. Security bugs live mostly in the second kind: double spends, quota bypass, one-time tokens used twice.

| | |
|---|---|
| Weaknesses | [CWE-362](https://cwe.mitre.org/data/definitions/362.html) Concurrent Execution using Shared Resource with Improper Synchronization, [CWE-367](https://cwe.mitre.org/data/definitions/367.html) Time-of-check Time-of-use Race Condition, [CWE-820](https://cwe.mitre.org/data/definitions/820.html) Missing Synchronization |
| Go packages | `sync`, `sync/atomic`, `testing` (`-race`) |
| Code | [`account.go`](account.go), [`store.go`](store.go), [`races_test.go`](races_test.go) |

## 1. Threat model

The attacker sends many requests at once — the same coupon redemption, withdrawal, OTP guess or password-reset confirmation in parallel (a "limit overrun" or single-packet attack). Every request is individually valid. The server handles each in its own goroutine (`net/http` does this by default). The attacker wins if any invariant that the code checks ("balance ≥ amount", "attempts < 5", "token unused") is violated by the combined effect of requests that each passed the check.

## 2. What Go guarantees

| Situation | Behaviour |
|---|---|
| Data race on a word-sized value (`int`, pointer) | A read observes *some* value actually written; no out-of-thin-air values ([memory model](https://go.dev/ref/mem)) |
| Data race on a multi-word value (interface, slice, string) | May observe a torn mix of two writes; the memory model warns this "can in turn lead to arbitrary memory corruption" |
| Concurrent map write + read/write | Best-effort detection; the runtime aborts with `fatal error: concurrent map writes` (a throw — `recover` cannot catch it, the whole process dies) |
| `go test -race` / `go build -race` | ThreadSanitizer-based; reports races that **actually happen** during the run; no report means no race was *observed* |
| Check-then-act with each step locked or atomic | Fully defined, race-detector-clean, and still wrong |

Tools: `sync.Mutex`/`RWMutex`; typed atomics `atomic.Int64`, `atomic.Bool`, `atomic.Pointer[T]` (Go 1.19, together with the revised memory model); `sync.WaitGroup.Go` (Go 1.25), which removes the misplaced-`Add` bug class; and the Go 1.25 `waitgroup` vet analyzer for the remaining manual `Add` calls. The race detector's documented cost is roughly 5–10× memory and 2–20× CPU, which is why it belongs in CI rather than production.

## 3. Insecure pattern

**Check-then-act across two critical sections.** [`WithdrawUnsafe`](account.go) is the shape most "thread-safe" code takes after someone adds a mutex to each method:

```go
if a.Balance() < amount { return ErrInsufficientFunds } // lock, read, unlock
a.mu.Lock(); a.balance -= amount; a.mu.Unlock()        // lock, write, unlock
```

Two concurrent withdrawals of 100 from a balance of 100 both pass the check; the balance ends at −100. The test forces that interleaving with a two-party barrier in a test hook, so it is deterministic — and it runs under `-race` without a single report.

**Atomic steps, non-atomic sequence.** [`AllowUnsafe`](account.go) uses `atomic.Int64`, yet `Load` → compare → `Add` lets eight callers through a limit of one. Atomics make each operation indivisible, not the decision built from several.

**Unsynchronised publication.** A config reload that assigns `s.cfg = newCfg` while handlers read `s.cfg` is a data race. On a pointer it "only" risks stale reads and reordering of the fields' initialisation; on an `any` or `[]string` field a reader can combine one version's data pointer with another's type or length word. This is the one class where Go's memory safety (chapter 01) genuinely fails.

## 4. Secure pattern

1. **One critical section per invariant.** [`Withdraw`](account.go) takes the lock once and checks and debits inside it. Expose operations (`Withdraw`, `Redeem`, `ConsumeToken`), not getters that tempt callers to decide outside the lock.
2. **Compare-and-swap for lock-free counters.** [`Allow`](account.go) loops on `CompareAndSwap(cur, cur+1)`: the increment applies only if nothing changed since the check.
3. **Publish immutable snapshots.** [`ConfigStore`](store.go) holds an `atomic.Pointer[Config]`; reloads build a fresh `Config` and `Store` it, readers `Load` and never mutate. The store happens-before every load that observes it, so readers see fully initialised values.
4. **Guard maps.** `sync.RWMutex` around a plain map ([`Sessions`](store.go)), or `sync.Map` for its two documented sweet spots (write-once/read-many keys, disjoint key sets per goroutine).
5. **Run every test with `-race` in CI**, and write concurrency tests that force the bad interleaving (hooks, barriers, `testing/synctest`) instead of hoping the scheduler finds it.

## 5. Where the guarantee ends

- **The race detector is dynamic.** It cannot report a race on a path tests do not run, and it never reports race *conditions*. `TestWithdrawUnsafeDoubleSpends` is green under `-race` while demonstrating a double spend.
- **The process is not the unit of consistency.** With two replicas, an in-process mutex protects nothing. Push the invariant into the store: `UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1` and check the affected-row count, `SELECT … FOR UPDATE` inside a transaction, a unique constraint for one-time tokens, or idempotency keys. Distributed limits are chapter 28.
- **Filesystem TOCTOU.** `os.Stat` then `os.Open` races with a concurrent rename or symlink swap; open once and operate on the handle, and use `os.Root` for directory confinement (chapter 31).
- **Copied locks.** A struct containing a `sync.Mutex` passed by value has its own unlocked mutex; `go vet`'s `copylocks` check catches most cases.
- **`sync.Map` and atomics do not compose.** `Load` then `Store` on a `sync.Map` is the same check-then-act bug; use `LoadOrStore`, `CompareAndSwap` or `CompareAndDelete`.

## 6. Verification

```bash
go test -race -v ./Security/04_data-races/
```

| Test | Shows |
|---|---|
| `TestWithdrawUnsafeDoubleSpends` | Forced interleaving: both withdrawals succeed, balance −100, no race report |
| `TestWithdrawIsAtomic` | 100 concurrent withdrawals of 10 from 500: exactly 50 succeed, balance 0 |
| `TestLimiterUnsafeOverAdmits` | 8 callers pass a limit of 1 with nothing but atomic operations |
| `TestLimiterAllowIsExact` | CAS loop admits exactly 10 of 64 |
| `TestConfigStoreSnapshots` | Readers never see a snapshot mixing two versions during 200 reloads |
| `TestSessionsConcurrentUse` | Guarded map under 8 concurrent writers/readers, race-detector clean |
| `ExampleAccount_WithdrawUnsafe` | `-100` vs `0` |

## 7. Checklist

- [ ] Every invariant over shared state is checked and updated inside one lock, one CAS, or one database statement.
- [ ] Types expose operations, not "get then set" pairs; atomics are not combined with separate loads.
- [ ] Shared config/allowlists are immutable snapshots behind `atomic.Pointer[T]` or a lock.
- [ ] No map is written from more than one goroutine without a lock.
- [ ] CI runs `go test -race ./...`; concurrency-sensitive code has a test that forces the losing interleaving.
- [ ] One-time and limited resources are enforced in the shared store, not only in process memory.

## References

- [The Go Memory Model](https://go.dev/ref/mem) (revised for Go 1.19), in particular "Implementation Restrictions for Programs Containing Data Races"
- [Data Race Detector](https://go.dev/doc/articles/race_detector)
- [`sync/atomic`](https://pkg.go.dev/sync/atomic), [`sync.WaitGroup.Go`](https://pkg.go.dev/sync#WaitGroup.Go), [Go 1.25 release notes](https://go.dev/doc/go1.25)
- Go FAQ — [Why are map operations not defined to be atomic?](https://go.dev/doc/faq#atomic_maps)
- PortSwigger Research — [Smashing the state machine: the true potential of web race conditions](https://portswigger.net/research/smashing-the-state-machine) (2023)
