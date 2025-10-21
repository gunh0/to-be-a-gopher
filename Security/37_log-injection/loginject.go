// Package loginject shows how untrusted strings forge or corrupt log entries
// and how log/slog prevents it. The log package writes the formatted message
// verbatim, so a newline in user input starts a new, attacker-written entry
// (CWE-117) and an ANSI escape sequence is executed by the terminal that
// displays the log (CWE-150). slog handlers encode values: TextHandler quotes
// them with strconv.Quote rules, JSONHandler escapes them as JSON strings.
package loginject

import (
	"log"
	"log/slog"
	"strconv"
	"strings"
	"unicode"
)

// LogFailedLoginUnsafe writes user-controlled values with %s. A user name
// containing "\n" plus a timestamp produces a second line that is
// indistinguishable from a real entry.
func LogFailedLoginUnsafe(l *log.Logger, user, ip string) {
	l.Printf("login failed user=%s ip=%s", user, ip)
}

// LogFailedLoginQuoted is the minimal fix for legacy text logs: %q escapes
// control characters, quotes and non-printable runes, so every entry stays on
// one line and its fields stay delimited.
func LogFailedLoginQuoted(l *log.Logger, user, ip string) {
	l.Printf("login failed user=%q ip=%q", user, ip)
}

// LogFailedLogin uses structured logging: the message is a constant and the
// untrusted values are typed attributes that the handler encodes.
func LogFailedLogin(l *slog.Logger, user, ip string) {
	l.Warn("login failed", slog.String("user", user), slog.String("ip", ip))
}

// Sanitize escapes s for inclusion in a plain-text sink (a terminal, a
// syslog line, an email subject) using Go string-literal escapes, without the
// surrounding quotes. The result contains only printable runes.
func Sanitize(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}

// EscapeFormatChars is a slog.HandlerOptions.ReplaceAttr function for
// JSONHandler. JSON escaping covers control characters but leaves Unicode
// format characters (category Cf) raw: bidirectional overrides such as
// U+202E reorder how a log viewer displays the line (the "Trojan Source"
// technique, CVE-2021-42574), and zero-width and tag characters (U+E0000
// block) hide text. This rewrites them as \uXXXX or \UXXXXXXXX text in string
// values. The message itself is not an Attr; keep it constant.
func EscapeFormatChars(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() != slog.KindString {
		return a
	}
	s := a.Value.String()
	if strings.IndexFunc(s, isFormat) < 0 {
		return a
	}
	var b strings.Builder
	for _, r := range s {
		if isFormat(r) {
			q := strconv.QuoteRune(r) // '\u202e' or '\U000e0041'
			b.WriteString(q[1 : len(q)-1])
			continue
		}
		b.WriteRune(r)
	}
	return slog.String(a.Key, b.String())
}

func isFormat(r rune) bool { return unicode.Is(unicode.Cf, r) }
