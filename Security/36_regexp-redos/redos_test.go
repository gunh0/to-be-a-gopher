package redos

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Patterns that take exponential time in backtracking engines (PCRE, Java,
// JavaScript, Python re, .NET without a timeout) on a long run of "a"
// followed by a non-matching character.
var catastrophic = []string{
	`(a+)+$`,
	`^(a+)+$`,
	`^(a|a)*$`,
}

func TestCatastrophicPatternsAreLinear(t *testing.T) {
	input := strings.Repeat("a", 100_000) + "!"
	// Generous budget for slow CI machines and -race (~10x slowdown); a
	// backtracking engine would not finish this input in our lifetime.
	const budget = time.Second
	for _, p := range catastrophic {
		re := regexp.MustCompile(p)
		start := time.Now()
		if re.MatchString(input) {
			t.Fatalf("%s matched", p)
		}
		if d := time.Since(start); d > budget {
			t.Errorf("%s took %v on %d bytes, budget %v", p, d, len(input), budget)
		}
	}
}

func TestBacktrackingFeaturesRejected(t *testing.T) {
	for _, p := range []string{
		`(a)\1`,         // backreference
		`(?=a)`,         // lookahead
		`(?!a)`,         // negative lookahead
		`(?<=a)b`,       // lookbehind
		`(?>a+)`,        // atomic group
		`a++`,           // possessive quantifier
		`a{1001}`,       // repeat count above 1000
		`(a{100}){100}`, // nested repeats multiply
		strings.Repeat("(", 1001) + strings.Repeat(")", 1001), // nesting depth
	} {
		if _, err := regexp.Compile(p); err == nil {
			t.Errorf("Compile(%.20q) succeeded, want error", p)
		}
	}
}

func TestMatchUserPatternUnsafePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustCompile on an invalid user pattern did not panic")
		}
	}()
	MatchUserPatternUnsafe("(", "x")
}

func TestCompileUserPattern(t *testing.T) {
	tests := []struct {
		pattern string
		ok      bool
	}{
		{`^[a-z0-9_]+$`, true},
		{`^(a+)+$`, true}, // harmless in RE2
		{`(`, false},
		{`(a)\1`, false},
		{strings.Repeat("a", MaxPatternLen+1), false},
		{`a{1000}`, false},          // parses, but 1002 instructions
		{`[a-z]{100}\d{100}`, true}, // ~200 instructions
		{`(?:[a-z]{50}){10}`, false},
	}
	for _, tt := range tests {
		re, err := CompileUserPattern(tt.pattern)
		if (err == nil) != tt.ok {
			t.Errorf("CompileUserPattern(%.30q) err = %v, want ok=%v", tt.pattern, err, tt.ok)
		}
		if err != nil && !errors.Is(err, ErrPattern) {
			t.Errorf("err = %v, want ErrPattern", err)
		}
		if tt.ok && re == nil {
			t.Errorf("CompileUserPattern(%q) returned nil regexp", tt.pattern)
		}
	}
}

func TestProgramSizeGrowsWithRepeats(t *testing.T) {
	small, err := ProgramSize(`a{10}`)
	if err != nil {
		t.Fatal(err)
	}
	large, err := ProgramSize(`a{1000}`)
	if err != nil {
		t.Fatal(err)
	}
	if large < 50*small {
		t.Fatalf("a{10}=%d, a{1000}=%d instructions; want roughly linear growth", small, large)
	}
}

func TestMatchBounded(t *testing.T) {
	re := regexp.MustCompile(`^[a-z]+$`)
	if ok, err := MatchBounded(re, "abc"); !ok || err != nil {
		t.Fatalf("MatchBounded(abc) = %v, %v", ok, err)
	}
	if _, err := MatchBounded(re, strings.Repeat("a", MaxInput+1)); !errors.Is(err, ErrInputTooLong) {
		t.Fatalf("err = %v, want ErrInputTooLong", err)
	}
}

func TestIsValidEmail(t *testing.T) {
	tests := map[string]bool{
		"alice@example.com":   true,
		"a.b+tag@sub.example": true,
		"no-at-sign":          false,
		"a@b":                 false,
		"a@@example.com":      false,
		strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63): false, // 256 bytes
	}
	for in, want := range tests {
		if got := IsValidEmail(in); got != want {
			t.Errorf("IsValidEmail(%.30q) = %v, want %v", in, got, want)
		}
		if len(in) <= 254 && IsValidEmailUnsafe(in) != want {
			t.Errorf("IsValidEmailUnsafe(%.30q) disagrees", in)
		}
	}
}

func TestCompileOnceAllocations(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip()
	}
	const in = "alice@example.com"
	perCall := testing.AllocsPerRun(50, func() { IsValidEmailUnsafe(in) })
	once := testing.AllocsPerRun(50, func() { IsValidEmail(in) })
	// Compiling allocates the parse tree and program on every request.
	if perCall < 20 || once*4 > perCall {
		t.Fatalf("allocs/op: compile per call = %.0f, compile once = %.0f", perCall, once)
	}
}

// BenchmarkCatastrophic shows linear scaling: doubling the input doubles
// the time per operation.
//
//	go test -run '^$' -bench Catastrophic ./Security/36_regexp-redos/
func BenchmarkCatastrophic(b *testing.B) {
	re := regexp.MustCompile(`^(a+)+$`)
	for _, n := range []int{1 << 10, 1 << 14, 1 << 18} {
		input := strings.Repeat("a", n) + "!"
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				re.MatchString(input)
			}
		})
	}
}

func ExampleCompileUserPattern() {
	for _, p := range []string{`^(a+)+$`, `(a)\1`, `a{1000}`} {
		_, err := CompileUserPattern(p)
		fmt.Println(p, err)
	}
	// Output:
	// ^(a+)+$ <nil>
	// (a)\1 redos: pattern rejected: error parsing regexp: invalid escape sequence: `\1`
	// a{1000} redos: pattern rejected: program has 1002 instructions (max 500)
}
