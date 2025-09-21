package consttime

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
	"fmt"
	"testing"
)

type comparator func(secret, guess []byte, p *Probe) bool

// recoverSecret plays the timing attacker against cmp: for each position it tries
// all 256 values and keeps the one that made the comparison run longer. It
// returns what it believes the secret is and how many queries it used.
func recoverSecret(cmp comparator, secret []byte) ([]byte, int) {
	guess := make([]byte, len(secret))
	queries := 0
	for pos := range guess {
		best, bestSteps := byte(0), -1
		for c := range 256 {
			guess[pos] = byte(c)
			var p Probe
			queries++
			if cmp(secret, guess, &p) {
				return guess, queries
			}
			if p.Steps > bestSteps {
				best, bestSteps = byte(c), p.Steps
			}
		}
		guess[pos] = best
	}
	return guess, queries
}

func TestEqualUnsafeLeaksPrefix(t *testing.T) {
	secret := []byte("k7Qz-api-key")
	got, queries := recoverSecret(EqualUnsafe, secret)
	if !bytes.Equal(got, secret) {
		t.Fatalf("recovered %q", got)
	}
	if queries > 256*len(secret) {
		t.Fatalf("%d queries", queries)
	}
	t.Logf("recovered a %d-byte secret in %d queries (brute force: 256^%d)", len(secret), queries, len(secret))
}

func TestEqualConstantGivesNoSignal(t *testing.T) {
	secret := []byte("k7Qz-api-key")
	steps := map[int]bool{}
	for _, g := range []string{"aaaaaaaaaaaa", "kaaaaaaaaaaa", "k7Qz-api-kez", "k7Qz-api-key"} {
		var p Probe
		EqualConstant(secret, []byte(g), &p)
		steps[p.Steps] = true
	}
	if len(steps) != 1 {
		t.Fatalf("step counts vary with content: %v", steps)
	}
	if got, _ := recoverSecret(EqualConstant, secret); bytes.Equal(got, secret) {
		t.Fatal("constant-time comparison leaked the secret")
	}
}

func TestLengthIsNotHidden(t *testing.T) {
	// ConstantTimeCompare returns 0 immediately on a length mismatch: its
	// running time reveals len(secret). So does EqualConstant's probe.
	var short, right Probe
	EqualConstant([]byte("secret"), []byte("s"), &short)
	EqualConstant([]byte("secret"), []byte("xxxxxx"), &right)
	if short.Steps == right.Steps {
		t.Fatal("expected the length check to be observable")
	}
	if subtle.ConstantTimeCompare([]byte("secret"), []byte("secret!")) != 0 {
		t.Fatal("different lengths compared equal")
	}
}

func TestCheckKey(t *testing.T) {
	stored := "sk_live_8f14e45fceea167a"
	for _, tt := range []struct {
		presented string
		want      bool
	}{
		{stored, true},
		{"sk_live_8f14e45fceea167b", false},
		{"", false},
		{stored + "x", false},
	} {
		if got := CheckKeyUnsafe(stored, tt.presented); got != tt.want {
			t.Errorf("CheckKeyUnsafe(%q) = %v", tt.presented, got)
		}
		if got := CheckKey(stored, tt.presented); got != tt.want {
			t.Errorf("CheckKey(%q) = %v", tt.presented, got)
		}
	}
}

func TestVerifier(t *testing.T) {
	v := NewVerifier([]byte("correct horse battery staple"))
	for _, tt := range []struct {
		in   string
		want bool
	}{
		{"correct horse battery staple", true},
		{"correct horse battery stapl", false},
		{"correct horse battery staple ", false},
		{"", false},
	} {
		if got := v.Verify([]byte(tt.in)); got != tt.want {
			t.Errorf("Verify(%q) = %v", tt.in, got)
		}
	}
	// Two verifiers for the same secret use different keys, so their stored
	// digests are unrelated and cannot be precomputed.
	w := NewVerifier([]byte("correct horse battery staple"))
	if hmac.Equal(v.want, w.want) {
		t.Fatal("per-process HMAC keys are not random")
	}
}

func ExampleEqualUnsafe() {
	secret := []byte("k7Qz")
	for _, g := range []string{"a000", "k000", "k7Q0"} {
		var p Probe
		EqualUnsafe(secret, []byte(g), &p)
		var q Probe
		EqualConstant(secret, []byte(g), &q)
		fmt.Printf("%s unsafe=%d constant=%d\n", g, p.Steps, q.Steps)
	}
	// Output:
	// a000 unsafe=1 constant=4
	// k000 unsafe=2 constant=4
	// k7Q0 unsafe=4 constant=4
}
