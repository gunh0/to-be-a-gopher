package secrets

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const pw = "hunter2"

// verbs covers the fmt verbs a log line or error message is likely to use.
var verbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10s", "%-12v"}

// wrappers put the value in the positions fmt handles differently: top
// level, exported field, unexported field, pointer, slice, map, nested.
func wrappers[T any](v T) map[string]any {
	type exported struct{ F T }
	type unexported struct{ f T }
	type nested struct{ Inner struct{ f T } }
	return map[string]any{
		"value":      v,
		"pointer":    &v,
		"exported":   exported{v},
		"unexported": unexported{v},
		"nested":     nested{Inner: struct{ f T }{v}},
		"slice":      []T{v},
		"map":        map[string]T{"k": v},
	}
}

func TestPlainConfigLeaks(t *testing.T) {
	got := fmt.Sprintf("loaded config: %+v", Config{User: "app", Password: pw})
	if !strings.Contains(got, pw) {
		t.Fatalf("expected the password in %q", got)
	}
}

func TestNaiveSecretLeaks(t *testing.T) {
	// The Stringer covers some paths ...
	if got := fmt.Sprintf("%v", NaiveSecret(pw)); got != Redacted {
		t.Fatalf("%%v = %q", got)
	}
	// ... and these print the value. (Verbs come from the shared table:
	// go vet and staticcheck rightly flag a literal %d on a string type.)
	leaks := map[string]string{
		"unexported field": fmt.Sprintf("%v", struct{ p NaiveSecret }{pw}),
	}
	for _, verb := range verbs {
		if verb == "%#v" || verb == "%d" {
			leaks[verb] = fmt.Sprintf(verb, NaiveSecret(pw))
		}
	}
	b, _ := json.Marshal(struct{ P NaiveSecret }{pw})
	leaks["json.Marshal"] = string(b)
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", "p", NaiveSecret(pw))
	leaks["slog JSON"] = buf.String()

	for path, out := range leaks {
		if !strings.Contains(out, pw) {
			t.Errorf("%s: expected a leak, got %q", path, out)
		}
	}
}

func TestSecretRedactsEveryFmtPath(t *testing.T) {
	for name, w := range wrappers(New(pw)) {
		for _, verb := range verbs {
			out := fmt.Sprintf(verb, w)
			if strings.Contains(out, pw) || strings.Contains(out, fmt.Sprintf("%x", pw)) {
				t.Errorf("%s with %s leaked: %q", name, verb, out)
			}
		}
	}
}

func TestSecretRedactsEncoders(t *testing.T) {
	cfg := SafeConfig{User: "app", Password: New(pw)}

	j, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	x, err := xml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var text, js, std bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("cfg", "cfg", cfg, "pw", cfg.Password)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("cfg", "cfg", cfg, "pw", cfg.Password)
	log.New(&std, "", 0).Printf("cfg=%+v pw=%s", cfg, cfg.Password)
	wrapped := fmt.Errorf("connect as %v: %w", cfg, errors.New("refused"))

	for name, out := range map[string]string{
		"json":       string(j),
		"xml":        string(x),
		"slog text":  text.String(),
		"slog json":  js.String(),
		"log":        std.String(),
		"fmt.Errorf": wrapped.Error(),
	} {
		if strings.Contains(out, pw) {
			t.Errorf("%s leaked: %s", name, out)
		}
		if !strings.Contains(out, Redacted) {
			t.Errorf("%s: no redaction marker in %s", name, out)
		}
	}
	if string(j) != `{"User":"app","Password":"[REDACTED]"}` {
		t.Errorf("json = %s", j)
	}
}

func TestSecretAccessors(t *testing.T) {
	s := New(pw)
	if s.Reveal() != pw || !s.Equal(pw) || s.Equal("hunter3") || s.Equal("") {
		t.Fatal("Reveal/Equal disagree with the stored value")
	}
	var zero Secret
	if zero.Reveal() != "" || !zero.Equal("") || zero.String() != Redacted {
		t.Fatal("zero Secret misbehaves")
	}
	zero.Destroy() // must not panic
}

func TestDestroyCannotReachCopies(t *testing.T) {
	s := New(pw)
	revealed := s.Reveal() // an independent string
	s.Destroy()
	if s.Reveal() != "" {
		t.Fatal("Destroy did not clear the secret's buffer")
	}
	if revealed != pw {
		t.Fatal("unexpected: a revealed copy changed")
	}
}

func TestFromBytesClearsSource(t *testing.T) {
	src := []byte(pw)
	s := FromBytes(src)
	if !bytes.Equal(src, make([]byte, len(pw))) {
		t.Fatalf("source buffer not cleared: %q", src)
	}
	if s.Reveal() != pw {
		t.Fatal("secret lost its value")
	}
}

func TestClearDoesNotReachOldBackingArrays(t *testing.T) {
	b := make([]byte, 0, 4)
	b = append(b, "pass"...)
	old := b                 // still the first backing array
	b = append(b, "word"...) // grows: data copied to a new array
	clear(b)                 // zeroes only the new array
	if string(old) != "pass" {
		t.Fatalf("old = %q", old)
	}
}

func TestFromEnvRemovesVariable(t *testing.T) {
	t.Setenv("SECRETS_TEST_TOKEN", "tok_4f2c9a71")
	s, err := FromEnv("SECRETS_TEST_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv("SECRETS_TEST_TOKEN"); ok {
		t.Fatal("variable still in the environment children would inherit")
	}
	if s.Reveal() != "tok_4f2c9a71" {
		t.Fatal("wrong value")
	}
	if _, err := FromEnv("SECRETS_TEST_TOKEN"); !errors.Is(err, ErrSecretSource) {
		t.Fatalf("second read err = %v, want ErrSecretSource", err)
	}
}

func TestFromFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "db-password")
	if err := os.WriteFile(good, []byte(pw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := FromFile(good)
	if err != nil || s.Reveal() != pw {
		t.Fatalf("FromFile = %q, %v", s.Reveal(), err)
	}

	if runtime.GOOS == "windows" {
		return
	}
	loose := filepath.Join(dir, "world-readable")
	if err := os.WriteFile(loose, []byte(pw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil { // Chmod: not subject to umask
		t.Fatal(err)
	}
	if _, err := FromFile(loose); !errors.Is(err, ErrSecretSource) {
		t.Fatalf("0644 file err = %v, want ErrSecretSource", err)
	}
	if _, err := FromFile(dir); !errors.Is(err, ErrSecretSource) {
		t.Fatalf("directory err = %v, want ErrSecretSource", err)
	}
}

func Example() {
	cfg := SafeConfig{User: "app", Password: New("hunter2")}
	fmt.Printf("%v\n%+v\n%#v\n", cfg, cfg, cfg.Password)
	b, _ := json.Marshal(cfg)
	fmt.Println(string(b))
	// Output:
	// {app [REDACTED]}
	// {User:app Password:[REDACTED]}
	// [REDACTED]
	// {"User":"app","Password":"[REDACTED]"}
}
