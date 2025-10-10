package redirect

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// browserHost approximates where a WHATWG-compliant browser navigates when
// it receives location on a page served from base. It models only what
// matters here: tab/newline removal, trimming of leading C0 controls and
// spaces, "\" read as "/" in http(s) URLs, any run of two or more leading
// slashes starting an authority, and "scheme:host" without slashes being an
// authority when the scheme differs from the page's.
func browserHost(base *url.URL, location string) string {
	s := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, location)
	s = strings.TrimLeft(s, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f ")
	s = strings.ReplaceAll(s, `\`, "/")

	if i := strings.IndexByte(s, ':'); i > 0 && !strings.ContainsAny(s[:i], "/?#") {
		scheme, rest := strings.ToLower(s[:i]), s[i+1:]
		switch {
		case scheme != "http" && scheme != "https":
			return scheme + ":" // not a navigation to a host
		case scheme == base.Scheme && !strings.HasPrefix(rest, "//"):
			return base.Host // same special scheme, no "//": relative
		default:
			return authority(strings.TrimLeft(rest, "/"))
		}
	}
	if strings.HasPrefix(s, "//") {
		return authority(strings.TrimLeft(s, "/"))
	}
	return base.Host
}

func authority(s string) string {
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	return strings.ToLower(s)
}

func location(t *testing.T, h http.HandlerFunc, scheme, next string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, scheme+"://app.example/login?"+url.Values{"next": {next}}.Encode(), nil)
	rec := httptest.NewRecorder()
	h(rec, r)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	return rec.Header().Get("Location")
}

var cases = []struct {
	next    string
	from    string // scheme of the login page
	offsite bool   // where LoginRedirectInsecure sends a browser
	naive   bool   // IsLocalNaive verdict
	parsed  bool   // IsLocalParsed verdict
	safe    bool   // SafeLocalPath verdict
}{
	{"/account?tab=keys", "https", false, true, true, true},
	{"//evil.example", "https", true, true, false, false},
	{`/\evil.example`, "https", true, true, true, false},
	{`\\evil.example`, "https", true, false, true, false},
	{"https://evil.example", "https", true, false, false, false},
	{"http:evil.example", "https", true, false, false, false},
	{"https:evil.example", "http", true, false, false, false},
	{"/\t/evil.example", "https", true, true, false, false},
	{" //evil.example", "https", false, false, true, false}, // http.Redirect prefixes "/"
	{"///evil.example", "https", false, true, true, false},  // http.Redirect's path.Clean saves it
	{"/%2F%2Fevil.example", "https", false, true, true, true},
	{"evil.example", "https", false, false, true, false},
}

func TestInsecureRedirectGoesOffsite(t *testing.T) {
	for _, tt := range cases {
		base := &url.URL{Scheme: tt.from, Host: "app.example"}
		loc := location(t, LoginRedirectInsecure, tt.from, tt.next)
		host := browserHost(base, loc)
		if got := host != "app.example"; got != tt.offsite {
			t.Errorf("next=%q: Location %q lands on %q (offsite=%v), want offsite=%v", tt.next, loc, host, got, tt.offsite)
		}
	}
}

func TestValidators(t *testing.T) {
	for _, tt := range cases {
		if got := IsLocalNaive(tt.next); got != tt.naive {
			t.Errorf("IsLocalNaive(%q) = %v, want %v", tt.next, got, tt.naive)
		}
		if got := IsLocalParsed(tt.next); got != tt.parsed {
			t.Errorf("IsLocalParsed(%q) = %v, want %v", tt.next, got, tt.parsed)
		}
		if _, got := SafeLocalPath(tt.next); got != tt.safe {
			t.Errorf("SafeLocalPath(%q) = %v, want %v", tt.next, got, tt.safe)
		}
	}
}

// TestValidatorsVersusBrowser is the property that matters: whenever a
// validator says "local", a browser must stay on app.example.
func TestValidatorsVersusBrowser(t *testing.T) {
	validators := map[string]func(string) bool{
		"IsLocalNaive":  IsLocalNaive,
		"IsLocalParsed": IsLocalParsed,
		"SafeLocalPath": func(s string) bool { _, ok := SafeLocalPath(s); return ok },
	}
	bypassed := map[string]int{}
	for name, ok := range validators {
		for _, tt := range cases {
			if !ok(tt.next) {
				continue
			}
			for _, scheme := range []string{"http", "https"} {
				base := &url.URL{Scheme: scheme, Host: "app.example"}
				// The validator approved the raw value, so it is sent verbatim.
				if host := browserHost(base, tt.next); host != "app.example" {
					bypassed[name]++
					break
				}
			}
		}
	}
	if bypassed["IsLocalNaive"] == 0 || bypassed["IsLocalParsed"] == 0 {
		t.Errorf("expected both naive validators to approve off-site targets: %v", bypassed)
	}
	if n := bypassed["SafeLocalPath"]; n != 0 {
		t.Errorf("SafeLocalPath approved %d off-site targets", n)
	}
}

func TestSafeRedirectAllowlist(t *testing.T) {
	tests := []struct {
		next string
		ok   bool
	}{
		{"https://accounts.example/welcome", true},
		{"https://ACCOUNTS.example/welcome", true},
		{"/local", true},
		{"http://accounts.example/", false},                  // downgrade
		{"https://accounts.example.evil.example/", false},    // suffix trick
		{"https://evil.example/accounts.example", false},     // path, not host
		{"https://accounts.example@evil.example/", false},    // userinfo
		{`https://evil.example\@accounts.example/`, false},   // browsers: host evil.example
		{"https://accounts.example:8443/", false},            // port is part of the origin
		{"https://accounts.example/\r\nSet-Cookie:x", false}, // control characters
		{"//accounts.example/", false},                       // scheme-relative
	}
	for _, tt := range tests {
		got, ok := SafeRedirect(tt.next, "accounts.example")
		if ok != tt.ok {
			t.Errorf("SafeRedirect(%q) = %q, %v; want ok=%v", tt.next, got, ok, tt.ok)
		}
	}
}

func TestLoginRedirectFallsBackToRoot(t *testing.T) {
	h := LoginRedirect("accounts.example")
	for next, want := range map[string]string{
		"/account":                   "/account",
		"https://accounts.example/x": "https://accounts.example/x",
		"//evil.example":             "/",
		`/\evil.example`:             "/",
		"":                           "/",
	} {
		if got := location(t, h, "https", next); got != want {
			t.Errorf("next=%q: Location = %q, want %q", next, got, want)
		}
	}
}

func TestHTTPRedirectDoesNotAllowHeaderInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(LoginRedirectInsecure))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Get(srv.URL + "/login?next=" + url.QueryEscape("/x\r\nSet-Cookie: session=attacker"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if c := resp.Header.Values("Set-Cookie"); len(c) != 0 {
		t.Fatalf("header injection: Set-Cookie = %q", c)
	}
	// net/http replaces CR and LF in header values with spaces on the wire.
	if loc := resp.Header.Get("Location"); loc != "/x  Set-Cookie: session=attacker" {
		t.Fatalf("Location = %q", loc)
	}
}

func ExampleSafeLocalPath() {
	for _, next := range []string{"/settings", "//evil.example", `/\evil.example`} {
		p, ok := SafeLocalPath(next)
		fmt.Printf("%-16q %v %q\n", next, ok, p)
	}
	// Output:
	// "/settings"      true "/settings"
	// "//evil.example" false ""
	// "/\\evil.example" false ""
}
