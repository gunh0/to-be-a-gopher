// Package redos shows why Go's regexp package is immune to catastrophic
// backtracking and which denial-of-service risks remain. regexp implements
// RE2 semantics: matching runs in time linear in the input for a given
// pattern, and features that require backtracking (backreferences,
// lookaround) are rejected at compile time. Cost is still O(len(input) ×
// len(program)), compiling is not free, and MustCompile panics on bad input.
package redos

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
)

// Limits for patterns and inputs that come from users.
const (
	MaxInput      = 4 << 10 // bytes of subject text
	MaxPatternLen = 256     // bytes of pattern source
	MaxProgInsts  = 500     // instructions in the compiled program
)

// Errors returned by the safe functions.
var (
	ErrInputTooLong = errors.New("redos: input too long")
	ErrPattern      = errors.New("redos: pattern rejected")
)

// emailPattern is deliberately simple: the goal is to filter, not to
// implement RFC 5322.
const emailPattern = `^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`

// IsValidEmailUnsafe compiles the pattern on every call and matches input of
// any length. Neither is a correctness bug; both are free CPU for an
// attacker: compilation allocates on each request, and a multi-megabyte
// "email" is scanned in full.
func IsValidEmailUnsafe(s string) bool {
	return regexp.MustCompile(emailPattern).MatchString(s)
}

// emailRE is compiled once, at package initialisation. A *regexp.Regexp is
// safe for concurrent use. MustCompile is right here: the pattern is a
// constant, so a panic can only happen at startup.
var emailRE = regexp.MustCompile(emailPattern)

// IsValidEmail caps the input length before matching (254 is the practical
// maximum length of an address in SMTP).
func IsValidEmail(s string) bool {
	if len(s) > 254 {
		return false
	}
	return emailRE.MatchString(s)
}

// MatchUserPatternUnsafe compiles a user-supplied pattern with MustCompile.
// An invalid pattern panics (taking down the process unless something
// recovers, see chapter 05), and there is no bound on pattern size or input
// length.
func MatchUserPatternUnsafe(pattern, input string) bool {
	return regexp.MustCompile(pattern).MatchString(input)
}

// CompileUserPattern validates a user-supplied pattern before it is used:
// source length, parse errors (including Go's own nesting and repeat-count
// limits), and the size of the compiled program, which is what a match pays
// for every input byte.
func CompileUserPattern(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > MaxPatternLen {
		return nil, fmt.Errorf("%w: longer than %d bytes", ErrPattern, MaxPatternLen)
	}
	n, err := ProgramSize(pattern)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPattern, err)
	}
	if n > MaxProgInsts {
		return nil, fmt.Errorf("%w: program has %d instructions (max %d)", ErrPattern, n, MaxProgInsts)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPattern, err)
	}
	return re, nil
}

// ProgramSize returns the number of instructions regexp would execute per
// input position, using the same parse → simplify → compile pipeline as
// regexp.Compile.
func ProgramSize(pattern string) (int, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0, err
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return 0, err
	}
	return len(prog.Inst), nil
}

// MatchBounded matches re against input after enforcing MaxInput.
func MatchBounded(re *regexp.Regexp, input string) (bool, error) {
	if len(input) > MaxInput {
		return false, ErrInputTooLong
	}
	return re.MatchString(input), nil
}
