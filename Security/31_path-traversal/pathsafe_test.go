package pathsafe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	secret  = "TOP SECRET"
	private = "PRIVATE KEY"
)

// layout builds:
//
//	tmp/secret.txt                 outside the base
//	tmp/public-private/key.txt     sibling whose name starts with "public"
//	tmp/public/hello.txt           base directory
//	tmp/public/docs/readme.txt
//
// and returns tmp/public.
func layout(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	base := filepath.Join(tmp, "public")
	for path, content := range map[string]string{
		filepath.Join(tmp, "secret.txt"):                secret,
		filepath.Join(tmp, "public-private", "key.txt"): private,
		filepath.Join(base, "hello.txt"):                "hello",
		filepath.Join(base, "docs", "readme.txt"):       "readme",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return base
}

// symlinks adds links inside base; tests that need them skip on Windows,
// where creating symlinks needs a privilege.
//
//	base/escape -> ../secret.txt     relative, leaves base
//	base/inside -> docs/readme.txt   relative, stays inside
//	base/abs    -> <base>/hello.txt  absolute, points inside
func symlinks(t *testing.T, base string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests are skipped on Windows")
	}
	for name, target := range map[string]string{
		"escape": filepath.Join("..", "secret.txt"),
		"inside": filepath.Join("docs", "readme.txt"),
		"abs":    filepath.Join(base, "hello.txt"),
	} {
		if err := os.Symlink(target, filepath.Join(base, name)); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
	}
}

func TestReadJoinTraversal(t *testing.T) {
	base := layout(t)
	if got, err := ReadJoin(base, "../secret.txt"); err != nil || string(got) != secret {
		t.Fatalf("got %q, %v; expected Join to resolve ../ out of base", got, err)
	}
	if got := filepath.Join("/srv/files", "../../etc/passwd"); got != filepath.FromSlash("/etc/passwd") {
		t.Fatalf("Join = %q", got)
	}
}

func TestReadCleanPrefixBypasses(t *testing.T) {
	base := layout(t)
	if _, err := ReadCleanPrefix(base, "../secret.txt"); err == nil {
		t.Fatal("plain ../ was not rejected")
	}
	if got, err := ReadCleanPrefix(base, "../public-private/key.txt"); err != nil || string(got) != private {
		t.Fatalf("got %q, %v; expected the string-prefix check to accept a sibling directory", got, err)
	}
}

func TestLexicalChecksFollowSymlinks(t *testing.T) {
	base := layout(t)
	symlinks(t, base)
	for name, read := range map[string]func(string, string) ([]byte, error){
		"ReadCleanPrefix": ReadCleanPrefix,
		"ReadIsLocal":     ReadIsLocal,
	} {
		if got, err := read(base, "escape"); err != nil || string(got) != secret {
			t.Errorf("%s(escape) = %q, %v; expected the symlink to leak the secret", name, got, err)
		}
	}
}

func TestReadIsLocalRejectsLexicalEscapes(t *testing.T) {
	base := layout(t)
	for _, name := range []string{"../secret.txt", "docs/../../secret.txt", "", filepath.Join(base, "hello.txt")} {
		if _, err := ReadIsLocal(base, name); err != ErrNotLocal {
			t.Errorf("ReadIsLocal(%q) err = %v, want ErrNotLocal", name, err)
		}
	}
}

func TestReadInRoot(t *testing.T) {
	base := layout(t)
	symlinks(t, base)
	tests := []struct {
		name, want string // want "" means an error is expected
	}{
		{"hello.txt", "hello"},
		{"docs/../hello.txt", "hello"}, // ".." that stays inside is fine
		{"inside", "readme"},           // relative symlink inside the root
		{"../secret.txt", ""},
		{"docs/../../secret.txt", ""},
		{"escape", ""},                         // symlink leaving the root
		{"abs", ""},                            // absolute symlinks are refused even when they point inside
		{"../public-private/key.txt", ""},      // sibling prefix
		{filepath.Join(base, "hello.txt"), ""}, // absolute name
	}
	for _, tt := range tests {
		got, err := ReadInRoot(base, tt.name)
		if tt.want == "" {
			if err == nil {
				t.Errorf("ReadInRoot(%q) = %q, want an error", tt.name, got)
			}
			continue
		}
		if err != nil || string(got) != tt.want {
			t.Errorf("ReadInRoot(%q) = %q, %v; want %q", tt.name, got, err, tt.want)
		}
	}
}

func TestIsLocalAndLocalize(t *testing.T) {
	tests := []struct {
		in             string
		isLocal, local bool // filepath.IsLocal, filepath.Localize succeeds
	}{
		{"a/b.txt", true, true},
		{"a/../b.txt", true, false}, // IsLocal cleans lexically; Localize wants a valid io/fs path
		{"../b.txt", false, false},
		{"/etc/passwd", false, false},
		{"", false, false},
		{"a/./b", true, false},
	}
	for _, tt := range tests {
		if got := filepath.IsLocal(tt.in); got != tt.isLocal {
			t.Errorf("IsLocal(%q) = %v, want %v", tt.in, got, tt.isLocal)
		}
		if _, err := filepath.Localize(tt.in); (err == nil) != tt.local {
			t.Errorf("Localize(%q) err = %v, want ok=%v", tt.in, err, tt.local)
		}
	}
}

func get(h http.Handler, target string) (int, string) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://files.example"+target, nil))
	return rec.Code, rec.Body.String()
}

func TestDownloadInsecureEncodedSlashes(t *testing.T) {
	h := DownloadInsecure(layout(t))
	if code, _ := get(h, "/files/../secret.txt"); code/100 != 3 {
		t.Fatalf("literal ../: status %d, expected ServeMux to redirect to the cleaned path", code)
	}
	if code, body := get(h, "/files/..%2Fsecret.txt"); code != http.StatusOK || body != secret {
		t.Fatalf("encoded ../: %d %q; expected PathValue to deliver ../secret.txt", code, body)
	}
}

func TestDownloadSafe(t *testing.T) {
	base := layout(t)
	symlinks(t, base)
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	h := Download(root)

	tests := []struct {
		target string
		code   int
	}{
		{"/files/docs/readme.txt", http.StatusOK},
		{"/files/..%2Fsecret.txt", http.StatusBadRequest},
		{"/files/docs%2F..%2F..%2Fsecret.txt", http.StatusBadRequest},
		{"/files/%2Fetc%2Fpasswd", http.StatusBadRequest},
		{"/files/escape", http.StatusNotFound},
		{"/files/missing", http.StatusNotFound},
	}
	for _, tt := range tests {
		code, body := get(h, tt.target)
		if code != tt.code || strings.Contains(body, secret) {
			t.Errorf("%s: %d %q, want %d and no secret", tt.target, code, body, tt.code)
		}
	}
}

func TestFileServerAndSymlinks(t *testing.T) {
	base := layout(t)
	symlinks(t, base)

	// http.FileServer cleans the URL path as rooted at "/", so ".." cannot
	// climb out lexically; http.Dir then follows symlinks.
	insecure := StaticInsecure(base)
	if code, body := get(insecure, "/..%2fsecret.txt"); code != http.StatusNotFound || strings.Contains(body, secret) {
		t.Errorf("http.FileServer with encoded ..: %d %q, want 404", code, body)
	}
	if code, body := get(insecure, "/escape"); code != http.StatusOK || body != secret {
		t.Errorf("http.Dir via symlink: %d %q; expected the secret", code, body)
	}

	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	safe := Static(root)
	if code, body := get(safe, "/escape"); code == http.StatusOK || strings.Contains(body, secret) {
		t.Errorf("FileServerFS(root.FS()) via symlink: %d %q", code, body)
	}
	if code, body := get(safe, "/hello.txt"); code != http.StatusOK || body != "hello" {
		t.Errorf("FileServerFS(root.FS()) /hello.txt: %d %q", code, body)
	}
}

func TestRootWriteMethods(t *testing.T) {
	base := layout(t)
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	// MkdirAll and WriteFile are Go 1.25 additions to os.Root.
	if err := root.MkdirAll("uploads/2025/10", 0o750); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("uploads/2025/10/a.txt", []byte("ok"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("../planted.txt", []byte("x"), 0o640); err == nil {
		t.Fatal("WriteFile outside the root succeeded")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(base), "planted.txt")); !os.IsNotExist(err) {
		t.Fatalf("file appeared outside the root: %v", err)
	}
	if err := root.RemoveAll(".."); err == nil {
		t.Fatal("RemoveAll(\"..\") succeeded")
	}
}

func ExampleReadInRoot() {
	base, _ := os.MkdirTemp("", "pathsafe")
	defer os.RemoveAll(base)
	os.WriteFile(filepath.Join(base, "a.txt"), []byte("contents"), 0o600)

	b, err := ReadInRoot(base, "a.txt")
	fmt.Printf("%s %v\n", b, err)
	_, err = ReadInRoot(base, "../a.txt")
	fmt.Println(err != nil)
	// Output:
	// contents <nil>
	// true
}
