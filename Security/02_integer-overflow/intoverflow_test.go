package intoverflow

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"testing"
)

// overflowing inputs: each pair's true size is far above MaxBody.
var overflowing = []struct {
	name        string
	count, size uint64
}{
	{"product wraps to zero", 1 << 32, 1 << 32},
	{"product wraps to zero (odd split)", 1 << 63, 2},
	{"addition carries", 3, 0x5555555555555553}, // 3*size = 2^64-7; +16 wraps to 9
}

func TestBudgetUnsafeAcceptsWrappedSizes(t *testing.T) {
	for _, tt := range overflowing {
		got, err := BudgetUnsafe(tt.count, tt.size)
		if err != nil {
			t.Errorf("%s: expected the wrapped size to pass the check, got %v", tt.name, err)
			continue
		}
		if got > MaxBody {
			t.Errorf("%s: total = %d, expected a small wrapped value", tt.name, got)
		}
	}
}

func TestBudgetRejectsOverflow(t *testing.T) {
	for name, budget := range map[string]func(uint64, uint64) (uint64, error){
		"Budget":    Budget,
		"BudgetDiv": BudgetDiv,
	} {
		for _, tt := range overflowing {
			if _, err := budget(tt.count, tt.size); !errors.Is(err, ErrTooLarge) {
				t.Errorf("%s(%s): err = %v, want ErrTooLarge", name, tt.name, err)
			}
		}
		ok := []struct{ count, size, want uint64 }{
			{0, math.MaxUint64, HeaderSize},
			{1024, 1024, HeaderSize + 1<<20},
			{1, MaxBody - HeaderSize, MaxBody},
		}
		for _, tt := range ok {
			got, err := budget(tt.count, tt.size)
			if err != nil || got != tt.want {
				t.Errorf("%s(%d, %d) = %d, %v; want %d", name, tt.count, tt.size, got, err, tt.want)
			}
		}
		if _, err := budget(1, MaxBody-HeaderSize+1); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: one byte over the limit accepted", name)
		}
	}
}

// smuggle builds a payload whose length is 65,536 + 4: after uint16
// truncation the receiver sees a 4-byte frame followed by attacker frames.
func smuggle(t *testing.T) []byte {
	t.Helper()
	inner, err := EncodeFrame([]byte("cmd:grant-admin"))
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte("note"), inner...)
	filler := (1 << 16) + 4 - len(payload) - 2
	pad, err := EncodeFrame(bytes.Repeat([]byte{' '}, filler))
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, pad...)
	if len(payload) != 1<<16+4 {
		t.Fatalf("payload length %d", len(payload))
	}
	return payload
}

func TestEncodeFrameUnsafeSmugglesFrames(t *testing.T) {
	frames, err := DecodeFrames(EncodeFrameUnsafe(smuggle(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 || string(frames[0]) != "note" || string(frames[1]) != "cmd:grant-admin" {
		t.Fatalf("expected 3 frames with an injected command, got %d (first %q)", len(frames), frames[0])
	}
}

func TestEncodeFrameRejectsOversize(t *testing.T) {
	if _, err := EncodeFrame(smuggle(t)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	full := bytes.Repeat([]byte{'x'}, math.MaxUint16)
	enc, err := EncodeFrame(full)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := DecodeFrames(enc)
	if err != nil || len(frames) != 1 || len(frames[0]) != math.MaxUint16 {
		t.Fatalf("round trip of a maximal frame failed: %v", err)
	}
}

func TestCanRead(t *testing.T) {
	owned := map[int32]bool{7: true}
	tests := []struct {
		id         int64
		unsafe, ok bool
	}{
		{7, true, true},
		{8, false, false},
		{1<<32 | 7, true, false},          // high bits dropped by int32()
		{-(1 << 32) + 7, true, false},     // negative int64 aliases 7 too
		{math.MaxInt32 + 1, false, false}, // becomes MinInt32
		{math.MinInt32, false, false},
	}
	for _, tt := range tests {
		if got := CanReadUnsafe(owned, tt.id); got != tt.unsafe {
			t.Errorf("CanReadUnsafe(%d) = %v, want %v", tt.id, got, tt.unsafe)
		}
		if got := CanRead(owned, tt.id); got != tt.ok {
			t.Errorf("CanRead(%d) = %v, want %v", tt.id, got, tt.ok)
		}
	}
}

func TestParseLength(t *testing.T) {
	tests := []struct {
		in     string
		unsafe uint32
		ok     bool
	}{
		{"42", 42, true},
		{"4294967295", math.MaxUint32, true},
		{"-1", math.MaxUint32, false},
		{"4294967297", 1, false},
		{"+5", 5, false},
	}
	for _, tt := range tests {
		got, err := ParseLengthUnsafe(tt.in)
		if err != nil || got != tt.unsafe {
			t.Errorf("ParseLengthUnsafe(%q) = %d, %v; want %d", tt.in, got, err, tt.unsafe)
		}
		got, err = ParseLength(tt.in)
		if (err == nil) != tt.ok || (tt.ok && got != tt.unsafe) {
			t.Errorf("ParseLength(%q) = %d, %v; want ok=%v", tt.in, got, err, tt.ok)
		}
	}
}

func TestLanguageSemantics(t *testing.T) {
	// Signed overflow is defined two's-complement wrap-around in Go, not UB.
	x := int64(math.MaxInt64)
	x++
	if x != math.MinInt64 {
		t.Fatalf("MaxInt64+1 = %d", x)
	}
	// Negating the most negative value yields itself: abs() can stay negative.
	m := int64(math.MinInt64)
	if -m != m {
		t.Fatal("expected -MinInt64 == MinInt64")
	}
	// MinInt64 / -1 does not trap (spec: "Integer operators").
	d := int64(-1)
	if m/d != m {
		t.Fatal("expected MinInt64 / -1 == MinInt64")
	}
}

func ExampleBudgetUnsafe() {
	total, err := BudgetUnsafe(1<<32, 1<<32)
	fmt.Println(total, err)
	_, err = Budget(1<<32, 1<<32)
	fmt.Println(err)
	// Output:
	// 16 <nil>
	// intoverflow: size exceeds limit
}
