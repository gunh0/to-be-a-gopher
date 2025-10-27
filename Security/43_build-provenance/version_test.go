package version

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
)

// fixture parses a build info fixture in debug.BuildInfo.String format.
func fixture(t *testing.T, name string) *Info {
	t.Helper()
	text, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	bi, err := parse(string(text))
	if err != nil {
		t.Fatal(err)
	}
	in := FromBuildInfo(bi)
	return &in
}

func get(t *testing.T, h http.Handler, header string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
	return string(body)
}

func TestFromBuildInfo(t *testing.T) {
	in := fixture(t, "release.txt")
	if in.Version != "v1.8.0" || in.GoVersion != "go1.25.3" || in.Modified ||
		in.Revision != "4f2c9a71d0e8b6c35a1f0e2d9c7b4a6e3f1d8c5b" || len(in.Deps) != 2 {
		t.Fatalf("Info = %+v", in)
	}
}

func TestHandlerUnsafeLeaks(t *testing.T) {
	text, err := os.ReadFile("testdata/dev.txt")
	if err != nil {
		t.Fatal(err)
	}
	bi, err := parse(string(text))
	if err != nil {
		t.Fatal(err)
	}
	body := get(t, HandlerUnsafe(bi), "")
	for _, leak := range []string{
		"sk_live_51Hc0ffee",   // -X value
		"/home/dev",           // build-machine paths
		"golang.org/x/crypto", // dependency inventory
		"go1.25.1",            // Go patch level → stdlib CVEs
	} {
		if !strings.Contains(body, leak) {
			t.Errorf("expected %q in unauthenticated output", leak)
		}
	}
}

func TestHandlerPublicView(t *testing.T) {
	in := fixture(t, "dev.txt")
	h := Handler(*in, func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer ops" })

	body := get(t, h, "")
	var pub map[string]any
	if err := json.Unmarshal([]byte(body), &pub); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(pub))
	for k := range pub {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"revision", "time", "version"}) {
		t.Fatalf("public keys = %q, body %s", keys, body)
	}
	for _, leak := range []string{"sk_live", "/home/dev", "golang.org/x", "go1.25"} {
		if strings.Contains(body, leak) {
			t.Errorf("public view leaks %q: %s", leak, body)
		}
	}
}

func TestHandlerAuthorizedViewIsRedacted(t *testing.T) {
	in := fixture(t, "dev.txt")
	h := Handler(*in, func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer ops" })

	body := get(t, h, "Bearer ops")
	if !strings.Contains(body, "golang.org/x/crypto") || !strings.Contains(body, `"go_version":"go1.25.1"`) {
		t.Fatalf("authorized view lacks inventory: %s", body)
	}
	if strings.Contains(body, "sk_live") || strings.Contains(body, "-I/home/dev") {
		t.Fatalf("authorized view leaks flags: %s", body)
	}
	// Redacted must not alias the original settings map.
	if in.Settings["-ldflags"] == "[REDACTED]" {
		t.Fatal("Redacted modified the original Info")
	}
}

func TestReleaseProblems(t *testing.T) {
	if p := ReleaseProblems(*fixture(t, "release.txt")); len(p) != 0 {
		t.Fatalf("release build flagged: %q", p)
	}
	p := ReleaseProblems(*fixture(t, "dev.txt"))
	for _, want := range []string{"modified working tree", "-trimpath", "(-race)", "-ldflags -X", "replaced dependency"} {
		if !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, want) }) {
			t.Errorf("missing problem %q in %q", want, p)
		}
	}
	if p := ReleaseProblems(Info{Version: "(devel)"}); len(p) < 3 {
		t.Errorf("no-VCS build: %q", p)
	}
}

func TestReadRunningBinary(t *testing.T) {
	in, ok := Read()
	if !ok {
		t.Skip("no build info")
	}
	// Test binaries are built by "go test": the module path is known and the
	// Go version is the toolchain's.
	if in.GoVersion == "" || !strings.HasPrefix(in.GoVersion, "go") {
		t.Fatalf("GoVersion = %q", in.GoVersion)
	}
}

func ExampleInfo_Public() {
	text, _ := os.ReadFile("testdata/release.txt")
	bi, _ := parse(string(text))
	b, _ := json.Marshal(FromBuildInfo(bi).Public())
	fmt.Println(string(b))
	// Output:
	// {"version":"v1.8.0","revision":"4f2c9a71d0e8b6c35a1f0e2d9c7b4a6e3f1d8c5b","time":"2025-10-01T12:00:00Z"}
}

// parse wraps debug.ParseBuildInfo and restores GoVersion from the "go"
// line, which ParseBuildInfo ignores (as of Go 1.25).
func parse(text string) (*debug.BuildInfo, error) {
	bi, err := debug.ParseBuildInfo(text)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(line, "go\t"); ok && bi.GoVersion == "" {
			bi.GoVersion = v
		}
	}
	return bi, nil
}
