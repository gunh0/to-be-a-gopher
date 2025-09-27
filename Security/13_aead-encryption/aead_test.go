package aead

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"testing"
)

func key32() []byte {
	k := make([]byte, 32)
	rand.Read(k)
	return k
}

func xor(a, b []byte) []byte {
	out := make([]byte, min(len(a), len(b)))
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func TestCTRBitFlipGoesUnnoticed(t *testing.T) {
	k := key32()
	pt := []byte(`{"amount":"0100","to":"alice"}`)
	ct, err := EncryptCTRUnsafe(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	// The attacker knows the message layout, not the key. Offset 16 (IV) +
	// 11 is the first digit of the amount.
	ct[16+11] ^= '0' ^ '9'
	got, err := DecryptCTRUnsafe(k, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"amount":"9100","to":"alice"}` {
		t.Fatalf("got %s", got)
	}
}

func TestAEADDetectsBitFlip(t *testing.T) {
	for name, s := range sealers(t) {
		ct := s.Seal([]byte(`{"amount":"0100","to":"alice"}`), nil)
		for i := range ct { // every single-bit flip, in nonce, body and tag
			mod := bytes.Clone(ct)
			mod[i] ^= 0x01
			if _, err := s.Open(mod, nil); !errors.Is(err, ErrOpen) {
				t.Fatalf("%s: flip at byte %d accepted", name, i)
			}
		}
	}
}

func TestGCMNonceReuseLeaksPlaintextXOR(t *testing.T) {
	k := key32()
	replicaA, _ := NewCounterSealerUnsafe(k)
	replicaB, _ := NewCounterSealerUnsafe(k) // second pod, or the same pod after a restart

	p1 := []byte("transfer 100 EUR to alice; ref=7731")
	p2 := []byte("password reset code for bob: 482913")
	c1 := replicaA.Seal(p1)
	c2 := replicaB.Seal(p2)

	if !bytes.Equal(c1[:12], c2[:12]) {
		t.Fatal("expected identical nonces")
	}
	body1, body2 := c1[12:12+len(p1)], c2[12:12+len(p2)]
	if !bytes.Equal(xor(body1, body2), xor(p1, p2)) {
		t.Fatal("ciphertext XOR should equal plaintext XOR under a reused nonce")
	}
	// Knowing (or guessing) one message reveals the other, with no key.
	recovered := xor(xor(body1, body2), p1)
	if !bytes.Equal(recovered, p2) {
		t.Fatalf("recovered %q", recovered)
	}
}

func TestRandomNonceSealersNeverRepeat(t *testing.T) {
	for name, s := range sealers(t) {
		seen := map[string]bool{}
		for range 1000 {
			ct := s.Seal([]byte("same plaintext"), nil)
			if seen[string(ct)] {
				t.Fatalf("%s: identical ciphertext for repeated plaintext", name)
			}
			seen[string(ct)] = true
		}
	}
}

func TestAssociatedDataStopsCutAndPaste(t *testing.T) {
	for name, s := range sealers(t) {
		// Mallory can write to her own row but cannot read Alice's email.
		aliceEmail := s.Seal([]byte("alice@example.com"), FieldAD("users", "email", "1001"))

		// Copying Alice's ciphertext into Mallory's row (id 1002) and asking the
		// app to "show my profile" would decrypt Alice's data without AD.
		if _, err := s.Open(aliceEmail, FieldAD("users", "email", "1002")); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: ciphertext moved to another row opened", name)
		}
		if _, err := s.Open(aliceEmail, FieldAD("users", "recovery_email", "1001")); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: ciphertext moved to another column opened", name)
		}
		pt, err := s.Open(aliceEmail, FieldAD("users", "email", "1001"))
		if err != nil || string(pt) != "alice@example.com" {
			t.Errorf("%s: legitimate open failed: %q %v", name, pt, err)
		}
	}
}

func TestFieldADIsUnambiguous(t *testing.T) {
	if bytes.Equal(FieldAD("users", "email", "10"), FieldAD("users", "email1", "0")) {
		t.Fatal("length prefixes should keep part boundaries distinct")
	}
}

func TestTruncatedCiphertextRejected(t *testing.T) {
	for name, s := range sealers(t) {
		ct := s.Seal([]byte("x"), nil)
		for n := range len(ct) {
			if _, err := s.Open(ct[:n], nil); !errors.Is(err, ErrOpen) {
				t.Fatalf("%s: truncated to %d bytes accepted", name, n)
			}
		}
	}
}

func TestCollisionBound(t *testing.T) {
	tests := []struct {
		name      string
		messages  float64
		bits      int
		wantLog2P float64
	}{
		{"GCM at its 2^32 limit", math.Exp2(32), 96, -33},
		{"GCM at 2^48 messages", math.Exp2(48), 96, -1},
		{"XChaCha at 2^64 messages", math.Exp2(64), 192, -65},
	}
	for _, tt := range tests {
		if got := math.Log2(CollisionProbability(tt.messages, tt.bits)); got != tt.wantLog2P {
			t.Errorf("%s: log2(p) = %v, want %v", tt.name, got, tt.wantLog2P)
		}
	}
}

func sealers(t *testing.T) map[string]Sealer {
	g, err := NewGCM(key32())
	if err != nil {
		t.Fatal(err)
	}
	x, err := NewXChaCha(key32())
	if err != nil {
		t.Fatal(err)
	}
	return map[string]Sealer{"AES-256-GCM/random-nonce": g, "XChaCha20-Poly1305": x}
}

func ExampleNewGCM() {
	key := make([]byte, 32) // from a KMS or HKDF (chapter 14) in real code
	s, _ := NewGCM(key)
	ct := s.Seal([]byte("4111 1111 1111 1111"), FieldAD("cards", "pan", "42"))
	fmt.Println(len(ct) - len("4111 1111 1111 1111")) // 12-byte nonce + 16-byte tag
	_, err := s.Open(ct, FieldAD("cards", "pan", "43"))
	fmt.Println(err)
	// Output:
	// 28
	// aead: message authentication failed
}
