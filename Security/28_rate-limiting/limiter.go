package ratelimit

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UnboundedLimiter keeps one bucket per key forever. Every distinct key an
// attacker can produce (a spoofed X-Forwarded-For value, a random username,
// an IPv6 address from their /64) allocates a bucket that is never freed:
// the rate limiter itself becomes the memory-exhaustion target (CWE-770).
type UnboundedLimiter struct {
	mu      sync.Mutex
	clock   Clock
	rate    float64
	burst   int
	buckets map[string]*Bucket
}

// NewUnboundedLimiter returns a limiter without eviction.
func NewUnboundedLimiter(c Clock, rate float64, burst int) *UnboundedLimiter {
	return &UnboundedLimiter{clock: c, rate: rate, burst: burst, buckets: map[string]*Bucket{}}
}

// Allow reports whether key may proceed.
func (l *UnboundedLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	b, ok := l.buckets[key]
	if !ok {
		b = NewBucket(l.rate, l.burst, now)
		l.buckets[key] = b
	}
	allowed, _ := b.Allow(now)
	return allowed
}

// Len returns the number of tracked keys.
func (l *UnboundedLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// ErrTableFull is reported when a new key arrives while every slot belongs
// to a client that is still being limited.
var ErrTableFull = errors.New("ratelimit: too many active clients")

// Limiter is a per-key token bucket limiter with a bounded key table.
//
// Eviction only removes buckets that have refilled to capacity: forgetting
// such a bucket and recreating it later gives the same answer, so eviction
// can never be used to reset a limited client. If the table is full of
// buckets that are still draining, new keys are refused (fail closed) rather
// than evicting an active key, which would hand its owner a fresh burst.
type Limiter struct {
	mu      sync.Mutex
	clock   Clock
	rate    float64
	burst   int
	maxKeys int
	buckets map[string]*Bucket
}

// NewLimiter returns a limiter allowing rate events per second with the
// given burst, tracking at most maxKeys clients.
func NewLimiter(c Clock, rate float64, burst, maxKeys int) *Limiter {
	return &Limiter{clock: c, rate: rate, burst: burst, maxKeys: maxKeys, buckets: map[string]*Bucket{}}
}

// Allow reports whether key may proceed and, if not, when to retry.
func (l *Limiter) Allow(key string) (bool, time.Duration, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.sweep(now)
		}
		if len(l.buckets) >= l.maxKeys {
			return false, time.Second, ErrTableFull
		}
		b = NewBucket(l.rate, l.burst, now)
		l.buckets[key] = b
	}
	ok, retry := b.Allow(now)
	return ok, retry, nil
}

// sweep drops every bucket that is back at capacity. It is O(n) but runs
// only when the table is full; a production limiter would sweep on a timer
// or shard the map.
func (l *Limiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if b.full(now) {
			delete(l.buckets, k)
		}
	}
}

// Len returns the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Middleware rejects over-limit requests with 429 Too Many Requests and a
// Retry-After header in whole seconds (RFC 9110 §10.2.3, RFC 6585 §4).
func Middleware(l *Limiter, key func(*http.Request) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, retry, err := l.Allow(key(r))
		if !ok {
			secs := int64((retry + time.Second - 1) / time.Second)
			w.Header().Set("Retry-After", strconv.FormatInt(max(secs, 1), 10))
			status := http.StatusTooManyRequests
			if errors.Is(err, ErrTableFull) {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// KeyFromXFF trusts the first X-Forwarded-For entry. Any client can set
// that header, so each request can claim a new identity and get a fresh
// bucket; combined with UnboundedLimiter it is also a memory leak on demand.
func KeyFromXFF(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	return r.RemoteAddr
}

// ClientKey returns a function that derives the rate-limit key from the
// connection's peer address. X-Forwarded-For is consulted only when the peer
// is one of the trusted proxies, and then read from the right: each trusted
// proxy appends the address it saw, so the rightmost entry that is not a
// trusted proxy is the first one an attacker could not have forged.
// IPv6 clients are keyed by /64, the smallest block a subscriber typically
// controls; keying by /128 lets one host rotate through 2^64 keys.
func ClientKey(trusted ...netip.Prefix) func(*http.Request) string {
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	return func(r *http.Request) string {
		addr, err := peerAddr(r.RemoteAddr)
		if err != nil {
			return "invalid"
		}
		if isTrusted(addr) {
			hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
			for i := len(hops) - 1; i >= 0; i-- {
				a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
				if err != nil {
					break // garbage from an untrusted hop: stop at the last good peer
				}
				addr = a.Unmap()
				if !isTrusted(addr) {
					break
				}
			}
		}
		return keyFor(addr)
	}
}

func peerAddr(remote string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, err
	}
	a, err := netip.ParseAddr(host)
	return a.Unmap(), err
}

func keyFor(a netip.Addr) string {
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}
