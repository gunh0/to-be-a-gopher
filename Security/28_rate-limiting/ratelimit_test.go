package ratelimit

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeClock is advanced explicitly by the test; no real time passes.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestBucketBurstThenRefill(t *testing.T) {
	clk := newFakeClock()
	b := NewBucket(1, 3, clk.Now()) // 1 token/s, burst 3

	for i := range 3 {
		if ok, _ := b.Allow(clk.Now()); !ok {
			t.Fatalf("burst request %d denied", i)
		}
	}
	ok, retry := b.Allow(clk.Now())
	if ok || retry != time.Second {
		t.Fatalf("4th request: ok=%v retry=%v, want denied, retry 1s", ok, retry)
	}
	clk.Advance(400 * time.Millisecond)
	if ok, retry := b.Allow(clk.Now()); ok || retry != 600*time.Millisecond {
		t.Fatalf("after 400ms: ok=%v retry=%v, want denied, retry 600ms", ok, retry)
	}
	clk.Advance(600 * time.Millisecond)
	if ok, _ := b.Allow(clk.Now()); !ok {
		t.Fatal("after 1s: denied, want one token")
	}
}

func TestBucketDoesNotOverfill(t *testing.T) {
	clk := newFakeClock()
	b := NewBucket(10, 5, clk.Now())
	clk.Advance(24 * time.Hour)
	n := 0
	for {
		if ok, _ := b.Allow(clk.Now()); !ok {
			break
		}
		n++
	}
	if n != 5 {
		t.Fatalf("allowed %d after a long idle period, want burst 5", n)
	}
}

func TestBucketClockGoingBackwards(t *testing.T) {
	clk := newFakeClock()
	b := NewBucket(1, 1, clk.Now())
	b.Allow(clk.Now())
	clk.Advance(-time.Hour)
	if ok, _ := b.Allow(clk.Now()); ok {
		t.Fatal("a backwards clock step granted a token")
	}
	clk.Advance(time.Hour + time.Second)
	if ok, _ := b.Allow(clk.Now()); !ok {
		t.Fatal("bucket did not recover once the clock moved forward again")
	}
}

func TestUnboundedLimiterGrowsWithEveryKey(t *testing.T) {
	l := NewUnboundedLimiter(newFakeClock(), 1, 1)
	const keys = 50_000
	for i := range keys {
		l.Allow(fmt.Sprintf("198.51.100.%d-%d", i%256, i))
	}
	if l.Len() != keys {
		t.Fatalf("tracked %d keys, want %d: one allocation per attacker-chosen key", l.Len(), keys)
	}
}

func TestLimiterTableIsBounded(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(clk, 1, 2, 100)

	refused := 0
	for i := range 1000 {
		if _, _, err := l.Allow(fmt.Sprint("k", i)); errors.Is(err, ErrTableFull) {
			refused++
		}
	}
	if l.Len() > 100 || refused != 900 {
		t.Fatalf("len=%d refused=%d, want len<=100 and 900 refused", l.Len(), refused)
	}

	// Once the buckets have refilled (burst/rate = 2s), they are evictable.
	clk.Advance(2 * time.Second)
	if ok, _, err := l.Allow("newcomer"); !ok || err != nil {
		t.Fatalf("newcomer after refill: ok=%v err=%v", ok, err)
	}
	if l.Len() != 1 {
		t.Fatalf("len after sweep = %d, want 1", l.Len())
	}
}

func TestEvictionCannotResetALimitedClient(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(clk, 0.1, 1, 10) // 1 request per 10 s

	if ok, _, _ := l.Allow("attacker"); !ok {
		t.Fatal("first request denied")
	}
	// Flood with fresh keys hoping to push "attacker" out of the table.
	for i := range 100 {
		l.Allow(fmt.Sprint("sybil", i))
	}
	clk.Advance(time.Second)
	if ok, _, _ := l.Allow("attacker"); ok {
		t.Fatal("attacker got a fresh bucket after churning the table")
	}
}

func TestXForwardedForSpoofing(t *testing.T) {
	clk := newFakeClock()
	req := func(i int) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		r.RemoteAddr = "203.0.113.7:51000"
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		return r
	}

	naive := NewLimiter(clk, 1, 5, 10_000)
	allowed := 0
	for i := range 100 {
		if ok, _, _ := naive.Allow(KeyFromXFF(req(i))); ok {
			allowed++
		}
	}
	if allowed != 100 {
		t.Fatalf("KeyFromXFF: %d of 100 allowed; expected the spoofed header to bypass the limit", allowed)
	}

	safe := NewLimiter(clk, 1, 5, 10_000)
	key := ClientKey() // no trusted proxies: the header is ignored
	allowed = 0
	for i := range 100 {
		if ok, _, _ := safe.Allow(key(req(i))); ok {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("ClientKey: %d of 100 allowed, want the burst of 5", allowed)
	}
}

func TestClientKey(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	tests := []struct {
		name, remote, xff, want string
	}{
		{"direct client, header ignored", "198.51.100.9:443", "1.2.3.4", "198.51.100.9"},
		{"via trusted proxy", "10.0.0.5:8080", "203.0.113.9", "203.0.113.9"},
		{"client-forged prefix", "10.0.0.5:8080", "1.2.3.4, 203.0.113.9", "203.0.113.9"},
		{"two trusted hops", "10.0.0.5:8080", "1.2.3.4, 203.0.113.9, 10.0.0.4", "203.0.113.9"},
		{"garbage from client", "10.0.0.5:8080", "not-an-ip", "10.0.0.5"},
		{"IPv6 keyed by /64", "[2001:db8:1:2:aaaa::1]:443", "", "2001:db8:1:2::/64"},
		{"IPv4-mapped peer", "[::ffff:198.51.100.9]:443", "", "198.51.100.9"},
	}
	key := ClientKey(proxies...)
	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = tt.remote
		if tt.xff != "" {
			r.Header.Set("X-Forwarded-For", tt.xff)
		}
		if got := key(r); got != tt.want {
			t.Errorf("%s: key = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestMiddleware(t *testing.T) {
	clk := newFakeClock()
	h := Middleware(NewLimiter(clk, 0.5, 1, 100), ClientKey(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	do := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	if rec := do(); rec.Code != http.StatusOK {
		t.Fatalf("first request: %d", rec.Code)
	}
	rec := do()
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("second request: %d Retry-After=%q, want 429 and 2", rec.Code, rec.Header().Get("Retry-After"))
	}
	clk.Advance(2 * time.Second)
	if rec := do(); rec.Code != http.StatusOK {
		t.Fatalf("after Retry-After: %d", rec.Code)
	}
}

func TestLimiterConcurrent(t *testing.T) {
	clk := newFakeClock()
	l := NewLimiter(clk, 1, 50, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for range 200 {
		wg.Go(func() {
			if ok, _, _ := l.Allow("shared"); ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if allowed != 50 {
		t.Fatalf("allowed %d concurrent requests, want exactly the burst of 50", allowed)
	}
}

func ExampleBucket_Allow() {
	start := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
	b := NewBucket(2, 2, start) // 2 per second, burst 2
	for _, ms := range []int{0, 0, 0, 250, 500} {
		ok, retry := b.Allow(start.Add(time.Duration(ms) * time.Millisecond))
		fmt.Printf("t=%3dms ok=%v retry=%v\n", ms, ok, retry)
	}
	// Output:
	// t=  0ms ok=true retry=0s
	// t=  0ms ok=true retry=0s
	// t=  0ms ok=false retry=500ms
	// t=250ms ok=false retry=250ms
	// t=500ms ok=true retry=0s
}
