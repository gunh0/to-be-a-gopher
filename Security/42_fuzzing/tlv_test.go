package tlv

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// seeds are added to both fuzz targets. None of them triggers the bug in
// ParseUnsafe: all lengths are below 0x8000.
var seeds = [][]byte{
	{},
	{0x01, 0x00, 0x00},
	{0x01, 0x00, 0x02, 'h', 'i'},
	{0x01, 0x00, 0x02, 'h', 'i', 0x02, 0x00, 0x01, '!'},
	{0x01, 0x00, 0x05, 'h', 'i'}, // truncated value
	{0x01, 0x00},                 // truncated header
}

// FuzzParse is the fuzz target that runs by default (its seeds and
// testdata/fuzz/FuzzParse run under plain "go test"). It checks three
// oracles on the secure parser:
//
//  1. no panic, for any input;
//  2. round trip: Encode(Parse(b)) == b whenever Parse accepts b;
//  3. differential: the streaming Decode agrees with Parse.
func FuzzParse(f *testing.F) {
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		recs, err := Parse(b)
		if err == nil {
			enc, err := Encode(recs)
			if err != nil {
				t.Fatalf("Encode of parsed records: %v", err)
			}
			if !bytes.Equal(enc, b) {
				t.Fatalf("round trip: Encode(Parse(%x)) = %x", b, enc)
			}
		}
		recs2, err2 := Decode(bytes.NewReader(b))
		if !errors.Is(err2, err) {
			t.Fatalf("differential: Parse err = %v, Decode err = %v (input %x)", err, err2, b)
		}
		if err == nil && !equalRecords(recs, recs2) {
			t.Fatalf("differential: Parse = %v, Decode = %v", recs, recs2)
		}
	})
}

// FuzzParseUnsafe targets the vulnerable parser. It is skipped unless
// TLV_FUZZ_INSECURE=1, so that "go test ./..." stays green; run it to watch
// the fuzzer find the sign-extension bug:
//
//	TLV_FUZZ_INSECURE=1 go test -run '^$' -fuzz '^FuzzParseUnsafe$' -fuzztime 30s ./Security/42_fuzzing/
func FuzzParseUnsafe(f *testing.F) {
	if os.Getenv("TLV_FUZZ_INSECURE") != "1" {
		f.Skip("set TLV_FUZZ_INSECURE=1 to fuzz the vulnerable parser")
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseUnsafe(b) // oracle: must not panic
	})
}

func equalRecords(a, b []Record) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type || !bytes.Equal(a[i].Value, b[i].Value) {
			return false
		}
	}
	return true
}

// readCorpusFile decodes a single-[]byte "go test fuzz v1" corpus file.
func readCorpusFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || lines[0] != "go test fuzz v1" ||
		!strings.HasPrefix(lines[1], "[]byte(") || !strings.HasSuffix(lines[1], ")") {
		t.Fatalf("%s: unexpected corpus format", path)
	}
	s, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(lines[1], "[]byte("), ")"))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(s)
}

func TestSeedReproducesUnsafeBug(t *testing.T) {
	// The checked-in corpus entry is what the fuzzer reported (minimised):
	// a record whose length field is 0xFFFF, i.e. int16(-1).
	in := readCorpusFile(t, "testdata/fuzz/FuzzParse/negative-length")

	var v any
	func() {
		defer func() { v = recover() }()
		ParseUnsafe(in)
	}()
	if _, ok := v.(runtime.Error); !ok {
		t.Fatalf("ParseUnsafe(%x) recovered %v, want a runtime.Error panic", in, v)
	}
	if _, err := Parse(in); !errors.Is(err, ErrTruncated) {
		t.Fatalf("Parse(%x) err = %v, want ErrTruncated", in, err)
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		in   []byte
		want []Record
		err  error
	}{
		{nil, nil, nil},
		{[]byte{7, 0, 0}, []Record{{7, []byte{}}}, nil},
		{[]byte{1, 0, 2, 'h', 'i', 2, 0, 1, '!'}, []Record{{1, []byte("hi")}, {2, []byte("!")}}, nil},
		{[]byte{1, 0, 3, 'h', 'i'}, nil, ErrTruncated},
		{[]byte{1, 0x80, 0x00, 'x'}, nil, ErrTruncated}, // 32768, not -32768
		{[]byte{1, 0}, nil, ErrTruncated},
		{bytes.Repeat([]byte{1, 0, 0}, MaxRecords+1), nil, ErrTooMany},
	}
	for _, tt := range tests {
		got, err := Parse(tt.in)
		if !errors.Is(err, tt.err) || !equalRecords(got, tt.want) {
			t.Errorf("Parse(%x) = %v, %v; want %v, %v", tt.in, got, err, tt.want, tt.err)
		}
	}
}

func TestParseValueCapacityCapped(t *testing.T) {
	recs, err := Parse([]byte{1, 0, 1, 'a', 2, 0, 6, 's', 'e', 'c', 'r', 'e', 't'})
	if err != nil {
		t.Fatal(err)
	}
	if v := recs[0].Value; cap(v) != len(v) {
		t.Fatalf("cap = %d, len = %d: caller can re-slice into the next record", cap(v), len(v))
	}
}

func TestEncodeRejectsLargeValue(t *testing.T) {
	if _, err := Encode([]Record{{1, make([]byte, 0x10000)}}); !errors.Is(err, ErrValueLarge) {
		t.Fatalf("err = %v, want ErrValueLarge", err)
	}
}

func ExampleParse() {
	in := []byte{0x01, 0xFF, 0xFF, 'a', 'b', 'c'} // length 65535, 3 bytes present
	_, err := Parse(in)
	fmt.Println(err)

	defer func() { fmt.Println("ParseUnsafe panicked:", recover() != nil) }()
	ParseUnsafe(in)
	// Output:
	// tlv: truncated record
	// ParseUnsafe panicked: true
}
