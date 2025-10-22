// Package secrets keeps credentials out of logs, error messages and
// serialised output. Secret implements every formatting hook that fmt,
// encoding/json, encoding (text), and log/slog consult, and stores its value
// behind a pointer so that even reflection-based printing of an unexported
// field shows an address instead of the bytes. It cannot make memory
// disappear: Go strings are immutable, append growth and goroutine stack
// growth leave old copies behind, and every Reveal creates a copy that
// Destroy cannot reach.
package secrets

import (
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
)

// Redacted is what every formatting path prints instead of the value.
const Redacted = "[REDACTED]"

// NaiveSecret is the common first attempt: a string type with a String
// method. It redacts %v and %s, and nothing else — %#v, %d, json.Marshal,
// slog.JSONHandler, and any unexported struct field holding it all print the
// value (CWE-532).
type NaiveSecret string

func (NaiveSecret) String() string { return Redacted }

// Config is a typical configuration struct that ends up in a startup log
// line ("loaded config: %+v").
type Config struct {
	User     string
	Password string // plain string: printed by every verb
}

// Secret holds a sensitive value. The zero value is an empty secret.
type Secret struct {
	p *secretValue
}

type secretValue struct {
	b []byte
}

// New copies s into a Secret. The caller's string remains in memory until
// the garbage collector reclaims it; see the package comment.
func New(s string) Secret {
	return Secret{p: &secretValue{b: []byte(s)}}
}

// FromBytes copies b into a Secret and clears b, so the caller's buffer
// (for example one read from a file) no longer holds the value.
func FromBytes(b []byte) Secret {
	s := Secret{p: &secretValue{b: append([]byte(nil), b...)}}
	clear(b)
	return s
}

// Reveal returns the value as a new string. Every call is a copy that lives
// until the GC reclaims it; call it as late as possible and do not store the
// result.
func (s Secret) Reveal() string {
	if s.p == nil {
		return ""
	}
	return string(s.p.b)
}

// Equal compares the secret with a candidate in constant time (chapter 09).
func (s Secret) Equal(candidate string) bool {
	var b []byte
	if s.p != nil {
		b = s.p.b
	}
	return subtle.ConstantTimeCompare(b, []byte(candidate)) == 1
}

// Destroy zeroes the Secret's own buffer. This is best-effort: copies made
// by Reveal, by earlier append growth, by the caller's original string, or
// by the operating system (swap, core dumps) are out of reach.
func (s Secret) Destroy() {
	if s.p != nil {
		clear(s.p.b)
		s.p.b = nil
	}
}

// String implements fmt.Stringer.
func (Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer (used directly by callers; fmt itself
// prefers Format).
func (Secret) GoString() string { return "secrets.Secret(" + Redacted + ")" }

// Format implements fmt.Formatter, which fmt consults before Stringer and
// GoStringer and for every verb, including %d, %x and %#v.
func (Secret) Format(f fmt.State, verb rune) { io.WriteString(f, Redacted) }

// MarshalJSON implements json.Marshaler.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler (encoding/xml, slog
// TextHandler, flag and many config libraries).
func (Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue implements slog.LogValuer, which slog resolves before any handler
// sees the value.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// SafeConfig is Config with the password typed as a Secret.
type SafeConfig struct {
	User     string
	Password Secret
}
