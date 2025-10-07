package secheaders

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

const htmlUpload = "<html><body><script>alert(document.cookie)</script></body></html>"

func get(t *testing.T, client *http.Client, url string) (*http.Response, string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(b)
}

func TestDetectContentTypeSniffsHTML(t *testing.T) {
	tests := map[string]string{
		htmlUpload:                 "text/html; charset=utf-8",
		"\n\t <!DOCTYPE html><p>x": "text/html; charset=utf-8", // leading whitespace is skipped
		"GIF89a" + htmlUpload:      "image/gif",
		`{"a":1}`:                  "text/plain; charset=utf-8",
	}
	for in, want := range tests {
		if got := http.DetectContentType([]byte(in)); got != want {
			t.Errorf("DetectContentType(%.20q) = %q, want %q", in, got, want)
		}
	}
}

func TestServeUploadInsecureIsServedAsHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ServeUploadInsecure(w, []byte(htmlUpload))
	}))
	defer srv.Close()

	resp, _ := get(t, srv.Client(), srv.URL)
	if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want the server to have sniffed text/html", ct)
	}
}

func TestNosniffDoesNotStopServerSideSniffing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		ServeUploadInsecure(w, []byte(htmlUpload))
	}))
	defer srv.Close()

	resp, _ := get(t, srv.Client(), srv.URL)
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q; nosniff instructs the browser, Go's server still sniffs", ct)
	}
}

func TestServeUploadSafe(t *testing.T) {
	rec := httptest.NewRecorder()
	ServeUploadSafe(rec, `a"b.html`, []byte(htmlUpload))
	want := map[string]string{
		"Content-Type":            "application/octet-stream",
		"X-Content-Type-Options":  "nosniff",
		"Content-Disposition":     `attachment; filename="a\"b.html"`,
		"Content-Security-Policy": "sandbox; default-src 'none'",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

var nonceRE = regexp.MustCompile(`'nonce-([A-Za-z0-9+/_-]+={0,2})'`)

func TestMiddlewareSetsHeaders(t *testing.T) {
	srv := httptest.NewServer(Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // headers must survive error responses too
	})))
	defer srv.Close()

	resp, _ := get(t, srv.Client(), srv.URL)
	want := map[string]string{
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "strict-origin-when-cross-origin",
		"Permissions-Policy":         "camera=(), microphone=(), geolocation=(), payment=()",
		"Cross-Origin-Opener-Policy": "same-origin",
		"X-Frame-Options":            "DENY",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	csp := resp.Header.Get("Content-Security-Policy")
	for _, d := range []string{"object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "'strict-dynamic'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP %q lacks %s", csp, d)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP %q allows inline script", csp)
	}
}

func TestNoncePerRequestAndInBody(t *testing.T) {
	srv := httptest.NewServer(Middleware(http.HandlerFunc(Page)))
	defer srv.Close()

	seen := map[string]bool{}
	for range 3 {
		resp, body := get(t, srv.Client(), srv.URL)
		m := nonceRE.FindStringSubmatch(resp.Header.Get("Content-Security-Policy"))
		if m == nil {
			t.Fatalf("no nonce-source in %q", resp.Header.Get("Content-Security-Policy"))
		}
		nonce := m[1]
		if len(nonce) < 22 { // 128 bits in base32 is 26 characters
			t.Fatalf("nonce %q is too short", nonce)
		}
		if !strings.Contains(body, `<script nonce="`+nonce+`">`) {
			t.Fatalf("body does not carry the header nonce: %s", body)
		}
		if seen[nonce] {
			t.Fatalf("nonce %q reused", nonce)
		}
		seen[nonce] = true
	}
}

func TestInsecureMiddlewareReusesNonce(t *testing.T) {
	srv := httptest.NewServer(InsecureMiddleware(http.HandlerFunc(Page)))
	defer srv.Close()

	r1, _ := get(t, srv.Client(), srv.URL)
	r2, _ := get(t, srv.Client(), srv.URL)
	c1, c2 := r1.Header.Get("Content-Security-Policy"), r2.Header.Get("Content-Security-Policy")
	if c1 != c2 || !strings.Contains(c1, StaticNonce()) {
		t.Fatalf("expected the same nonce on every response: %q vs %q", c1, c2)
	}
	if r1.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("insecure middleware should send HSTS over plain HTTP")
	}
	if r1.Header.Get("X-Content-Type-Options") != "" {
		t.Fatal("insecure middleware should omit nosniff")
	}
}

func TestHSTSOnlyOverTLS(t *testing.T) {
	h := Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	plain := httptest.NewServer(h)
	defer plain.Close()
	resp, _ := get(t, plain.Client(), plain.URL)
	if v := resp.Header.Get("Strict-Transport-Security"); v != "" {
		t.Errorf("HSTS over HTTP: %q", v)
	}

	tls := httptest.NewTLSServer(h)
	defer tls.Close()
	resp, _ = get(t, tls.Client(), tls.URL)
	if v := resp.Header.Get("Strict-Transport-Security"); v != HSTS {
		t.Errorf("HSTS over HTTPS = %q, want %q", v, HSTS)
	}
}

func TestNonceOutsideMiddleware(t *testing.T) {
	if n := Nonce(httptest.NewRequest(http.MethodGet, "/", nil).Context()); n != "" {
		t.Fatalf("Nonce without middleware = %q, want empty", n)
	}
}

func ExampleCSP() {
	fmt.Println(CSP("R4ND0M"))
	// Output:
	// default-src 'self'; script-src 'nonce-R4ND0M' 'strict-dynamic'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
}
