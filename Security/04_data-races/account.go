// Package races separates data races (unsynchronised memory access, which
// the race detector finds) from race conditions (check-then-act logic that
// is fully synchronised and still wrong, which it does not).
package races

import (
	"errors"
	"sync"
	"sync/atomic"
)

// ErrInsufficientFunds is returned when a withdrawal exceeds the balance.
var ErrInsufficientFunds = errors.New("races: insufficient funds")

// Account holds a balance guarded by a mutex.
type Account struct {
	mu      sync.Mutex
	balance int64

	// afterCheck, when set, runs between the check and the debit of
	// WithdrawUnsafe. Tests use it to force the interleaving a busy server
	// produces by chance.
	afterCheck func()
}

// NewAccount returns an account with the given opening balance.
func NewAccount(balance int64) *Account { return &Account{balance: balance} }

// Balance returns the current balance.
func (a *Account) Balance() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.balance
}

// WithdrawUnsafe reads the balance under the lock, releases it, and debits
// under the lock again. Every memory access is synchronised, so the race
// detector stays silent, but two concurrent withdrawals can both pass the
// check before either debits: a double spend (CWE-367, time-of-check to
// time-of-use).
func (a *Account) WithdrawUnsafe(amount int64) error {
	if a.Balance() < amount {
		return ErrInsufficientFunds
	}
	if a.afterCheck != nil {
		a.afterCheck()
	}
	a.mu.Lock()
	a.balance -= amount
	a.mu.Unlock()
	return nil
}

// Withdraw holds the lock across the check and the debit, so the invariant
// "balance >= 0" is established and used in one critical section.
func (a *Account) Withdraw(amount int64) error {
	if amount <= 0 {
		return errors.New("races: amount must be positive")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.balance < amount {
		return ErrInsufficientFunds
	}
	a.balance -= amount
	return nil
}

// Limiter admits at most limit operations in total (a per-key quota, a
// one-time coupon, an OTP attempt counter).
type Limiter struct {
	n     atomic.Int64
	limit int64

	afterLoad func() // test hook, see Account.afterCheck
}

// NewLimiter returns a Limiter admitting limit operations.
func NewLimiter(limit int64) *Limiter { return &Limiter{limit: limit} }

// AllowUnsafe loads the counter, compares, then increments. Each step is
// atomic; the sequence is not. N concurrent callers can all observe the same
// value below the limit, so a "1 attempt" quota admits N (CWE-362).
func (l *Limiter) AllowUnsafe() bool {
	if l.n.Load() >= l.limit {
		return false
	}
	if l.afterLoad != nil {
		l.afterLoad()
	}
	l.n.Add(1)
	return true
}

// Allow makes the check and the increment one atomic step with
// CompareAndSwap: the increment only happens if nobody changed the counter
// since it was checked, otherwise the loop re-checks.
func (l *Limiter) Allow() bool {
	for {
		cur := l.n.Load()
		if cur >= l.limit {
			return false
		}
		if l.n.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// Used returns how many operations were admitted.
func (l *Limiter) Used() int64 { return l.n.Load() }
