package races

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// barrier returns a hook that blocks each of n callers until all n have
// reached it: every goroutine finishes its check before any of them acts.
func barrier(n int) func() {
	var wg sync.WaitGroup
	wg.Add(n)
	return func() {
		wg.Done()
		wg.Wait()
	}
}

// TestWithdrawUnsafeDoubleSpends runs under -race without a report: every
// access is locked. The bug is in the logic, not in the memory accesses.
func TestWithdrawUnsafeDoubleSpends(t *testing.T) {
	a := NewAccount(100)
	a.afterCheck = barrier(2)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Go(func() { errs[i] = a.WithdrawUnsafe(100) })
	}
	wg.Wait()

	if errs[0] != nil || errs[1] != nil || a.Balance() != -100 {
		t.Fatalf("expected both withdrawals to succeed: errs=%v balance=%d", errs, a.Balance())
	}
}

func TestWithdrawIsAtomic(t *testing.T) {
	a := NewAccount(500)
	var ok, refused atomic.Int64
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			switch err := a.Withdraw(10); {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrInsufficientFunds):
				refused.Add(1)
			default:
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 50 || refused.Load() != 50 || a.Balance() != 0 {
		t.Fatalf("ok=%d refused=%d balance=%d", ok.Load(), refused.Load(), a.Balance())
	}
}

func TestLimiterUnsafeOverAdmits(t *testing.T) {
	const callers = 8
	l := NewLimiter(1)
	l.afterLoad = barrier(callers)

	var admitted atomic.Int64
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			if l.AllowUnsafe() {
				admitted.Add(1)
			}
		})
	}
	wg.Wait()
	if admitted.Load() != callers {
		t.Fatalf("admitted %d, expected all %d callers past a limit of 1", admitted.Load(), callers)
	}
}

func TestLimiterAllowIsExact(t *testing.T) {
	l := NewLimiter(10)
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			if l.Allow() {
				admitted.Add(1)
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 10 || l.Used() != 10 {
		t.Fatalf("admitted=%d used=%d, want 10", admitted.Load(), l.Used())
	}
}

// TestConfigStoreSnapshots reloads the config while readers check that every
// snapshot they see is internally consistent (no mix of two versions).
func TestConfigStoreSnapshots(t *testing.T) {
	mk := func(v int) *Config {
		ips := make([]string, v)
		for i := range ips {
			ips[i] = "10.0.0." + strconv.Itoa(i)
		}
		return &Config{Version: v, AllowedIP: ips, AdminOnly: v%2 == 0}
	}
	s := NewConfigStore(mk(0))

	var wg sync.WaitGroup
	wg.Go(func() {
		for v := 1; v <= 200; v++ {
			s.Store(mk(v))
		}
	})
	for range 4 {
		wg.Go(func() {
			for range 500 {
				c := s.Load()
				if len(c.AllowedIP) != c.Version || c.AdminOnly != (c.Version%2 == 0) {
					t.Errorf("torn snapshot: %+v", c)
					return
				}
			}
		})
	}
	wg.Wait()
	if s.Load().Version != 200 {
		t.Fatalf("final version %d", s.Load().Version)
	}
}

func TestSessionsConcurrentUse(t *testing.T) {
	s := NewSessions()
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Go(func() {
			for i := range 100 {
				id := fmt.Sprintf("%d-%d", w, i)
				s.Put(id, "user")
				if _, ok := s.Get(id); !ok {
					t.Errorf("lost %s", id)
				}
			}
		})
	}
	wg.Wait()
	if s.Len() != 800 {
		t.Fatalf("len = %d", s.Len())
	}
}

func ExampleAccount_WithdrawUnsafe() {
	a := NewAccount(100)
	a.afterCheck = barrier(2) // both requests pass the balance check first

	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { _ = a.WithdrawUnsafe(100) })
	}
	wg.Wait()
	fmt.Println(a.Balance())

	b := NewAccount(100)
	for range 2 {
		wg.Go(func() { _ = b.Withdraw(100) })
	}
	wg.Wait()
	fmt.Println(b.Balance())
	// Output:
	// -100
	// 0
}
