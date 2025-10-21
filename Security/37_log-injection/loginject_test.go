package loginject

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"testing"
)

// A user name that ends the real entry and writes a fake one.
const forged = "bob\n2025/10/01 12:00:00 login ok user=admin ip=10.0.0.1"

// ANSI: erase the line, return to column 0, print a green OK.
const ansi = "bob\x1b[2K\r\x1b[32mlogin ok user=admin\x1b[0m"

// U+202E RIGHT-TO-LEFT OVERRIDE: a viewer renders this as "evilexe.txt".
const bidi = "evil\u202Etxt.exe"

// entry matches a line produced by log.LstdFlags.
var entry = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} `)

func lines(b *bytes.Buffer) []string {
	return strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
}

// noTime drops slog's time attribute so output is deterministic.
func noTime(groups []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey && len(groups) == 0 {
		return slog.Attr{}
	}
	return a
}

func TestUnsafeForgesEntry(t *testing.T) {
	var buf bytes.Buffer
	LogFailedLoginUnsafe(log.New(&buf, "", log.LstdFlags), forged, "203.0.113.7")

	got := lines(&buf)
	if len(got) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(got), got)
	}
	for _, l := range got {
		if !entry.MatchString(l) {
			t.Fatalf("line %q does not look like a log entry", l)
		}
	}
	if !strings.Contains(got[1], "login ok user=admin") {
		t.Fatalf("forged line = %q", got[1])
	}
}

func TestUnsafePassesANSIToTerminal(t *testing.T) {
	var buf bytes.Buffer
	LogFailedLoginUnsafe(log.New(&buf, "", 0), ansi, "203.0.113.7")
	if !bytes.ContainsAny(buf.Bytes(), "\x1b\r") {
		t.Fatalf("expected raw ESC/CR in output: %q", buf.String())
	}
}

func TestQuotedStaysOnOneLine(t *testing.T) {
	for _, in := range []string{forged, ansi, bidi} {
		var buf bytes.Buffer
		LogFailedLoginQuoted(log.New(&buf, "", 0), in, "203.0.113.7")
		assertSafeLine(t, buf.String())
	}
}

func TestSlogHandlersEncodeValues(t *testing.T) {
	for _, in := range []string{forged, ansi, "x\u2028y", `a" admin="true`} {
		var tb, jb bytes.Buffer
		opts := &slog.HandlerOptions{ReplaceAttr: noTime}
		LogFailedLogin(slog.New(slog.NewTextHandler(&tb, opts)), in, "203.0.113.7")
		LogFailedLogin(slog.New(slog.NewJSONHandler(&jb, opts)), in, "203.0.113.7")

		assertSafeLine(t, tb.String())
		assertSafeLine(t, jb.String())

		// JSON is lossless: the exact input comes back out.
		var rec map[string]any
		if err := json.Unmarshal(jb.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["user"] != in || rec["msg"] != "login failed" {
			t.Errorf("JSON record = %v, want user=%q", rec, in)
		}
		// Text quoting keeps fields delimited: no injected admin="true" attribute.
		if strings.Contains(tb.String(), ` admin="true"`) {
			t.Errorf("text handler let a value break out of its field: %s", tb.String())
		}
	}
}

func TestSlogTextQuotesKeys(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: noTime}))
	l.Info("x", slog.String("a\nb", "v"))
	if got := buf.String(); got != "level=INFO msg=x \"a\\nb\"=v\n" {
		t.Fatalf("got %q", got)
	}
}

func TestJSONLeavesFormatCharsRaw(t *testing.T) {
	var raw, fixed bytes.Buffer
	LogFailedLogin(slog.New(slog.NewJSONHandler(&raw, &slog.HandlerOptions{ReplaceAttr: noTime})), bidi, "")
	if !strings.Contains(raw.String(), "\u202E") {
		t.Fatalf("expected raw U+202E in JSON output: %q", raw.String())
	}

	opts := &slog.HandlerOptions{ReplaceAttr: func(g []string, a slog.Attr) slog.Attr {
		return EscapeFormatChars(g, noTime(g, a))
	}}
	LogFailedLogin(slog.New(slog.NewJSONHandler(&fixed, opts)), bidi+"\u200B\U000E0041", "")
	if strings.ContainsAny(fixed.String(), "\u202E\u200B\U000E0041") {
		t.Fatalf("format characters survived: %q", fixed.String())
	}
	if !strings.Contains(fixed.String(), `evil\\u202etxt.exe\\u200b\\U000e0041`) {
		t.Fatalf("got %s", fixed.String())
	}
}

func TestSanitize(t *testing.T) {
	tests := map[string]string{
		"plain":       "plain",
		"a\nb":        `a\nb`,
		"\x1b[31m":    `\x1b[31m`,
		"\u202E":      `\u202e`,
		"caf\u00e9":   "caf\u00e9", // printable non-ASCII is kept
		"bad\xffutf8": `bad\xffutf8`,
	}
	for in, want := range tests {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetDefaultRoutesLogPackageThroughHandler(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: noTime})))
	log.Printf("login failed user=%s", forged) // legacy call site, still %s
	assertSafeLine(t, buf.String())
}

// assertSafeLine checks that s is exactly one line with no raw control or
// bidi characters.
func assertSafeLine(t *testing.T, s string) {
	t.Helper()
	body := strings.TrimSuffix(s, "\n")
	if strings.ContainsAny(body, "\n\r\x1b\u2028\u202E") {
		t.Errorf("unsafe characters in %q", s)
	}
}

func Example() {
	std := log.New(os.Stdout, "", 0)
	LogFailedLoginUnsafe(std, "bob\nlogin ok user=admin", "203.0.113.7")
	LogFailedLoginQuoted(std, "bob\nlogin ok user=admin", "203.0.113.7")

	opts := &slog.HandlerOptions{ReplaceAttr: noTime}
	LogFailedLogin(slog.New(slog.NewJSONHandler(os.Stdout, opts)), "bob\nlogin ok user=admin", "203.0.113.7")
	fmt.Println(Sanitize("bob\x1b[2K\rok"))
	// Output:
	// login failed user=bob
	// login ok user=admin ip=203.0.113.7
	// login failed user="bob\nlogin ok user=admin" ip="203.0.113.7"
	// {"level":"WARN","msg":"login failed","user":"bob\nlogin ok user=admin","ip":"203.0.113.7"}
	// bob\x1b[2K\rok
}
