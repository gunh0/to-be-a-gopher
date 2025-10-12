# 28. Rate Limiting

> **Abstract.** A token bucket is twenty lines of arithmetic; the security of a rate limiter lives in everything around it. **Whose** bucket a request spends from decides whether the limit applies at all: keyed on a client-supplied `X-Forwarded-For`, every request is a new client. **How many** buckets exist decides whether the limiter is itself a denial-of-service target: a map with one entry per attacker-chosen key grows without bound. And **eviction** must not reset a client that is currently limited. This chapter builds a token bucket on an injectable clock, keys clients by `RemoteAddr` (IPv6 by `/64`) and reads `X-Forwarded-For` right-to-left only behind trusted proxies, bounds the key table by evicting only buckets that have refilled (provably equivalent to forgetting them), and answers `429` with `Retry-After`. For production, `golang.org/x/time/rate` provides the bucket; keys, table bounds and the HTTP response remain the application's job.

| | |
|---|---|
| Weaknesses | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) Allocation of Resources Without Limits or Throttling, [CWE-307](https://cwe.mitre.org/data/definitions/307.html) Improper Restriction of Excessive Authentication Attempts, [CWE-799](https://cwe.mitre.org/data/definitions/799.html) Improper Control of Interaction Frequency |
| Go packages | `time`, `sync`, `net/netip`, `net/http`, `math` |
| Code | [`bucket.go`](bucket.go), [`limiter.go`](limiter.go), [`ratelimit_test.go`](ratelimit_test.go) |

## 1. Threat model

An attacker sends many requests to an endpoint whose cost is high or whose outcome is guessable: login and password reset (credential stuffing, CWE-307), OTP verification, expensive search, outbound e-mail or SMS. They control request headers, can rotate source ports freely, may hold an IPv6 `/64` or larger, and may control many IPv4 addresses (botnets, cloud). Goals: bypass the limit, or make the limiter consume the server's memory or CPU.

## 2. What Go provides

| Need | Standard library | Note |
|---|---|---|
| Token bucket | none | `golang.org/x/time/rate.Limiter` (`Allow`, `Reserve`, `Wait`) is the de-facto choice |
| Monotonic time | `time.Now()` carries a monotonic reading; `Sub` uses it | Wall-clock jumps do not distort elapsed time within a process |
| Client address | `Request.RemoteAddr` (`"ip:port"`), set by the server from the TCP peer | `X-Forwarded-For`, `X-Real-IP`, `Forwarded` are ordinary headers anyone can send |
| Address handling | `net/netip`: `ParseAddr`, `Unmap`, `Prefix(64)` | Allocation-free, comparable, usable as map keys |
| Deterministic tests | `testing/synctest` (Go 1.25) fakes time for `time.Sleep`/timers inside a bubble | This chapter injects a `Clock` instead, which also works for code that only calls `Now` |

A token bucket holds up to `burst` tokens and refills at `rate` per second; each request spends one. It allows short bursts and bounds the long-run average at `rate`. When empty, the time until the next token is `(1 - tokens) / rate`, which is the value `Retry-After` should carry.

## 3. Insecure pattern

```go
var buckets = map[string]*rate.Limiter{}          // grows forever

key := strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]  // client-chosen
if !buckets[key].Allow() { ... }
```

[`UnboundedLimiter`](limiter.go) and [`KeyFromXFF`](limiter.go). The tests send 100 login attempts from one TCP peer with a different `X-Forwarded-For` each time: all 100 are allowed, and 50,000 distinct keys produce 50,000 live buckets. Even a correct header-reading function fails if it takes the **leftmost** entry: proxies *append*, so the left end is whatever the client sent.

Two quieter mistakes: keying IPv6 by full address (a single host can use 2^64 addresses from its `/64`), and evicting least-recently-used buckets when a table is full (the attacker churns the table and gets their own bucket evicted, returning with a full burst).

## 4. Secure pattern

1. **Bucket** — [`Bucket`](bucket.go): float tokens, capped at `burst`, credit only for positive elapsed time (a backwards clock grants nothing).
2. **Key** — [`ClientKey`](limiter.go): `RemoteAddr` by default. Only when the peer is in a configured trusted-proxy prefix, walk `X-Forwarded-For` **right to left**, skipping trusted proxies; the first untrusted entry is the client. IPv6 is truncated to `/64`; IPv4-mapped addresses are unmapped.
3. **Bounded table** — [`Limiter`](limiter.go): at most `maxKeys` buckets. When full, delete only buckets that are back at capacity (`tokens + elapsed·rate ≥ burst`): a full bucket and a missing bucket give identical answers, so eviction is invisible. If nothing is evictable, refuse the new key (fail closed, `503`) instead of evicting an active one.
4. **Response** — [`Middleware`](limiter.go): `429 Too Many Requests` with `Retry-After` in whole seconds, rounded up.

| Choice | Effect |
|---|---|
| Limit per account *and* per IP on login | Stops both stuffing many accounts from one IP and one account from many IPs |
| Fail closed when the table is full | Availability degrades for new clients under attack; the limit is never lifted |
| Evict only full buckets | Eviction cannot be used to reset a limit |

## 5. Where rate limiting ends

- **Distributed attackers.** Per-IP limits do not stop a botnet; combine with per-account limits, CAPTCHA/proof-of-work escalation, and breached-password checks.
- **Multiple instances.** In-process buckets are per replica; N replicas allow N × rate. Use a shared store or a gateway limiter when the exact rate matters.
- **Sweep cost.** `sweep` is O(n) and runs when the table is full; under a sustained flood of new keys that is O(n) per request. Shard the map or sweep on a timer.
- **Locking out victims.** Per-account limits can be abused to lock a real user out; prefer slowing down (exponential delays) over hard lockout for authentication.
- **The cost may be elsewhere.** A rate limit does not bound request size or time (chapter 22) or slow handlers; it bounds frequency only.
- **Header trust is deployment configuration.** The trusted-proxy prefixes must match the actual topology; the same rule applies to `X-Forwarded-Proto` for HSTS (chapter 23).

## 6. Verification

```bash
go test -v ./Security/28_rate-limiting/
```

| Test | Shows |
|---|---|
| `TestBucketBurstThenRefill` | Burst of 3, then exact `retryAfter` of 1 s and 600 ms on a fake clock |
| `TestBucketDoesNotOverfill` | A day of idleness yields only `burst` tokens |
| `TestBucketClockGoingBackwards` | A backwards step grants no tokens |
| `TestUnboundedLimiterGrowsWithEveryKey` | 50,000 keys → 50,000 buckets |
| `TestLimiterTableIsBounded` | Table stays at 100; 900 new keys refused; refilled buckets are swept |
| `TestEvictionCannotResetALimitedClient` | Churning the table with 100 new keys does not free the attacker's bucket |
| `TestXForwardedForSpoofing` | 100/100 allowed with `KeyFromXFF`; 5/100 (the burst) with `ClientKey` |
| `TestClientKey` | Direct peers ignore the header; right-to-left walk through trusted proxies; IPv6 `/64`; mapped IPv4 |
| `TestMiddleware` | `429` with `Retry-After: 2`, then success after advancing 2 s |
| `TestLimiterConcurrent` | 200 goroutines (`sync.WaitGroup.Go`, Go 1.25) get exactly the burst of 50 under `-race` |
| `ExampleBucket_Allow` | Step-by-step token arithmetic |

## 7. Checklist

- [ ] Authentication, reset, OTP and other guessable or costly endpoints are rate limited.
- [ ] The key is the TCP peer, or the right-most untrusted hop behind an explicitly configured proxy list.
- [ ] IPv6 keys are aggregated to at least `/64`.
- [ ] The key table has a hard bound, and eviction cannot reset an active limit.
- [ ] Over-limit responses are `429` with `Retry-After`.
- [ ] Limits are enforced per account as well as per address where accounts exist.

## References

- [`golang.org/x/time/rate`](https://pkg.go.dev/golang.org/x/time/rate) — production token bucket
- [RFC 6585 §4](https://www.rfc-editor.org/rfc/rfc6585#section-4) `429 Too Many Requests`; [RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3) `Retry-After`; [RFC 7239](https://www.rfc-editor.org/rfc/rfc7239) `Forwarded`
- MDN — [X-Forwarded-For: security and privacy concerns](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For#security_and_privacy_concerns)
- OWASP — [Authentication Cheat Sheet: protect against automated attacks](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- NIST [SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) §5.2.2 Rate Limiting (Throttling)
