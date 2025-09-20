package secrand

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"strings"
	"testing"
	"time"
)

var issued = time.Date(2025, 9, 1, 9, 41, 7, 513_000_000, time.UTC)

func TestTokenUnsafeCollidesWithinASecond(t *testing.T) {
	alice := TokenUnsafe(issued)
	bob := TokenUnsafe(issued.Add(400 * time.Millisecond))
	if alice != bob {
		t.Fatalf("expected identical tokens in the same second: %s %s", alice, bob)
	}
}

// TestTokenUnsafeIsRecoverable plays the attacker: it knows only that a
// reset was requested "around 09:40" and tries every second in ±10 minutes.
func TestTokenUnsafeIsRecoverable(t *testing.T) {
	victim := TokenUnsafe(issued)
	guess := time.Date(2025, 9, 1, 9, 40, 0, 0, time.UTC)
	tries := 0
	for d := -10 * time.Minute; d <= 10*time.Minute; d += time.Second {
		tries++
		if TokenUnsafe(guess.Add(d)) == victim {
			t.Logf("token recovered after %d candidates", tries)
			return
		}
	}
	t.Fatal("expected the token to be in the search window")
}

func TestToken(t *testing.T) {
	seen := make(map[string]bool)
	for range 1000 {
		tok := Token()
		if len(tok) < 26 || strings.Trim(tok, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
			t.Fatalf("unexpected token %q", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate token %q", tok)
		}
		seen[tok] = true
	}
	if got := TokenBytes(32); len(got) != 43 {
		t.Fatalf("TokenBytes(32) length %d, want 43", len(got))
	}
}

// TestSeedableGeneratorsAreReproducible: math/rand/v2's ChaCha8 is a strong
// algorithm, but a Rand built from it is a deterministic function of a seed
// you supply, and its whole state can be serialised. Nothing in the API stops
// the seed from being guessable.
func TestSeedableGeneratorsAreReproducible(t *testing.T) {
	var seed [32]byte
	copy(seed[:], fmt.Sprint(issued.Unix()))
	a := mrand.New(mrand.NewChaCha8(seed))
	b := mrand.New(mrand.NewChaCha8(seed))
	for range 100 {
		if a.Uint64() != b.Uint64() {
			t.Fatal("same seed, different stream")
		}
	}

	src := mrand.NewChaCha8(seed)
	state, err := src.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	clone := mrand.NewChaCha8([32]byte{})
	if err := clone.UnmarshalBinary(state); err != nil {
		t.Fatal(err)
	}
	if src.Uint64() != clone.Uint64() {
		t.Fatal("restored state diverged")
	}
}

// exhaustive yields every byte value exactly once, which turns the bias of a
// byte-to-symbol mapping into an exact count instead of a statistical test.
func exhaustive() *bytes.Reader {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return bytes.NewReader(b)
}

func counts(s string) map[byte]int {
	m := make(map[byte]int)
	for i := range len(s) {
		m[s[i]]++
	}
	return m
}

func TestPasswordUnsafeIsBiased(t *testing.T) {
	p, err := PasswordUnsafe(exhaustive(), 256)
	if err != nil {
		t.Fatal(err)
	}
	c := counts(p)
	for i := range len(Alphabet) {
		want := 4
		if i < 8 {
			want = 5 // "A".."H" are hit by 5 of the 256 byte values
		}
		if c[Alphabet[i]] != want {
			t.Errorf("%c: %d occurrences, want %d", Alphabet[i], c[Alphabet[i]], want)
		}
	}
}

func TestPasswordIsUniform(t *testing.T) {
	p, err := Password(exhaustive(), 248)
	if err != nil {
		t.Fatal(err)
	}
	for sym, n := range counts(p) {
		if n != 4 {
			t.Errorf("%c: %d occurrences, want 4", sym, n)
		}
	}
	if _, err := Password(exhaustive(), 249); err == nil {
		t.Fatal("expected an error once the rejected bytes exhaust the source")
	}
	if p := NewPassword(); len(p) != 20 || strings.Trim(p, Alphabet) != "" {
		t.Fatalf("NewPassword = %q", p)
	}
}

func TestCryptoRandIntRange(t *testing.T) {
	limit := big.NewInt(62)
	for range 1000 {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil || n.Sign() < 0 || n.Cmp(limit) >= 0 {
			t.Fatalf("rand.Int = %v, %v", n, err)
		}
	}
}

func ExampleTokenUnsafe() {
	t := time.Date(2025, 9, 1, 9, 41, 7, 0, time.UTC)
	fmt.Println(TokenUnsafe(t) == TokenUnsafe(t.Add(999*time.Millisecond)))
	a, b := Token(), Token()
	fmt.Println(a == b)
	// Output:
	// true
	// false
}
