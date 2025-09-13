package memsafety

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"testing"
)

func TestEchoUnsafeDisclosesStaleBytes(t *testing.T) {
	r := NewResponder()
	r.Remember([]byte("session=4f2c9a71d0e8"))

	// The peer sends 4 bytes but claims 20.
	got := r.EchoUnsafe(Frame(20, []byte("ping")))

	if !bytes.Contains(got, []byte("9a71d0e8")) {
		t.Fatalf("expected the stale session token to leak, got %q", got)
	}
}

func TestEchoSafeRejectsLyingLength(t *testing.T) {
	r := NewResponder()
	r.Remember([]byte("session=4f2c9a71d0e8"))

	for _, declared := range []uint16{0, 3, 5, 20, MaxPayload + 1} {
		if _, err := r.EchoSafe(Frame(declared, []byte("ping"))); !errors.Is(err, ErrMalformed) {
			t.Errorf("declared=%d: err = %v, want ErrMalformed", declared, err)
		}
	}
}

func TestEchoSafeReturnsCopy(t *testing.T) {
	r := NewResponder()
	got, err := r.EchoSafe(Frame(4, []byte("ping")))
	if err != nil {
		t.Fatal(err)
	}
	r.Remember([]byte("secret"))
	if string(got) != "ping" {
		t.Fatalf("response aliased the scratch buffer: %q", got)
	}
}

func TestEchoSafeShortMessage(t *testing.T) {
	if _, err := NewResponder().EchoSafe([]byte{0}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestReadAtPanicsInsteadOfReading(t *testing.T) {
	v := Recovered(func() { ReadAt([]byte("abc"), 2, 8) })
	if _, ok := v.(runtime.Error); !ok {
		t.Fatalf("recovered %T (%v), want runtime.Error", v, v)
	}
}

func TestReadAtChecked(t *testing.T) {
	buf := []byte("0123456789")
	tests := []struct {
		off, n int
		ok     bool
	}{
		{0, 10, true},
		{9, 1, true},
		{10, 0, true},
		{11, 0, false},
		{-1, 2, false},
		{2, -1, false},
		{1, int(^uint(0) >> 1), false}, // off+n would overflow int
	}
	for _, tt := range tests {
		got, err := ReadAtChecked(buf, tt.off, tt.n)
		if (err == nil) != tt.ok {
			t.Errorf("ReadAtChecked(%d, %d) err = %v, want ok=%v", tt.off, tt.n, err, tt.ok)
			continue
		}
		if tt.ok && cap(got) != len(got) {
			t.Errorf("ReadAtChecked(%d, %d) cap = %d, want capped at len %d", tt.off, tt.n, cap(got), len(got))
		}
	}
}

func ExampleResponder_EchoUnsafe() {
	r := NewResponder()
	r.Remember([]byte("password=hunter2"))
	fmt.Printf("%q\n", r.EchoUnsafe(Frame(16, []byte("hi"))))
	// Output:
	// "hissword=hunter2"
}
