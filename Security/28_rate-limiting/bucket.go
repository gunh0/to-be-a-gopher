// Package ratelimit implements a token bucket with an injectable clock, a
// per-client limiter whose key table is bounded, and client-key extraction
// that does not trust X-Forwarded-For blindly. In production code
// golang.org/x/time/rate provides a well-tested token bucket (rate.Limiter);
// this package stays within the standard library to show the mechanics and
// the parts x/time/rate leaves to you: keys, table size and the HTTP response.
package ratelimit

import (
	"math"
	"time"
)

// Clock abstracts time so tests can advance it deterministically.
type Clock interface{ Now() time.Time }

// SystemClock is the real clock. time.Now carries a monotonic reading, so
// subtracting two values is immune to wall-clock jumps.
type SystemClock struct{}

// Now returns time.Now().
func (SystemClock) Now() time.Time { return time.Now() }

// Bucket is a token bucket: it holds at most Burst tokens, gains Rate tokens
// per second, and each allowed event spends one. It permits short bursts and
// enforces the long-run average. Not safe for concurrent use; Limiter
// serialises access.
type Bucket struct {
	Rate  float64 // tokens per second, > 0
	Burst float64 // capacity, >= 1

	tokens float64
	last   time.Time
}

// NewBucket returns a full bucket.
func NewBucket(rate float64, burst int, now time.Time) *Bucket {
	return &Bucket{Rate: rate, Burst: float64(burst), tokens: float64(burst), last: now}
}

// Allow spends one token if available. Otherwise it reports how long until
// one will be, which is what Retry-After should carry.
func (b *Bucket) Allow(now time.Time) (ok bool, retryAfter time.Duration) {
	b.refill(now)
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	need := (1 - b.tokens) / b.Rate
	return false, time.Duration(math.Ceil(need * float64(time.Second)))
}

// refill credits tokens for the time since the last call. A clock that moves
// backwards (a different host, a VM restore, a test) yields no credit rather
// than negative tokens or, with unsigned arithmetic, a huge refill.
func (b *Bucket) refill(now time.Time) {
	elapsed := now.Sub(b.last)
	if elapsed <= 0 {
		return
	}
	b.last = now
	b.tokens = math.Min(b.Burst, b.tokens+elapsed.Seconds()*b.Rate)
}

// full reports whether the bucket would be at capacity at now, meaning
// forgetting it is indistinguishable from keeping it.
func (b *Bucket) full(now time.Time) bool {
	return b.tokens+now.Sub(b.last).Seconds()*b.Rate >= b.Burst
}
