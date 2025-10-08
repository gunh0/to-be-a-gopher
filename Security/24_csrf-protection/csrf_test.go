package csrfguard

import (
	"fmt"
	"go/version"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

// request builds the request a browser would send from a page whose
// origin is from, to http://app.example. Empty values mean "header absent".
func request(method, target, secFetchSite, origin string) *http.Request {
	r := httptest.NewRequest(method, "http://app.example"+target, strings.NewReader("to=mallory"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secFetchSite != "" {
		r.Header.Set("Sec-Fetch-Site", secFetchSite)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func serve(h http.Handler, r *http.Request) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

func TestNaiveOriginCheckBypasses(t *testing.T) {
	ledger := &Ledger{}
	h := NaiveOriginCheck("https://app.example", ledger.Routes())

	// Prefix match: an attacker-registered domain starting with the allowed origin.
	if code := serve(h, request("POST", "/transfer", "cross-site", "https://app.example.evil.example")); code != http.StatusNoContent {
		t.Fatalf("status = %d, expected the prefix bypass to succeed", code)
	}
	// Sec-Fetch-Site says cross-site but Origin is absent: the naive check
	// never looks at Fetch Metadata.
	if code := serve(h, request("POST", "/transfer", "cross-site", "")); code != http.StatusNoContent {
		t.Fatalf("status = %d, expected missing Origin to be allowed", code)
	}
	if len(ledger.Transfers) != 2 {
		t.Fatalf("transfers = %v, want two forged transfers", ledger.Transfers)
	}
}

func TestCrossOriginProtection(t *testing.T) {
	tests := []struct {
		name, method, path, sfs, origin string
		want                            int
	}{
		{"same-origin fetch", "POST", "/transfer", "same-origin", "http://app.example", 204},
		{"user-initiated (address bar, bookmark)", "POST", "/transfer", "none", "", 204},
		{"non-browser client", "POST", "/transfer", "", "", 204},
		{"cross-site form", "POST", "/transfer", "cross-site", "https://evil.example", 403},
		{"same-site sibling subdomain", "POST", "/transfer", "same-site", "http://blog.app.example", 403},
		{"Sec-Fetch-Site wins over a matching Origin", "POST", "/transfer", "cross-site", "http://app.example", 403},
		{"old browser, Origin matches Host", "POST", "/transfer", "", "http://app.example", 204},
		{"old browser, Origin mismatch", "POST", "/transfer", "", "https://evil.example", 403},
		{"old browser, Origin null (sandboxed iframe)", "POST", "/transfer", "", "null", 403},
		{"Origin differs only by port", "POST", "/transfer", "", "http://app.example:8080", 403},
		{"cross-site PUT", "PUT", "/transfer", "cross-site", "https://evil.example", 403},
		{"trusted SSO origin", "POST", "/transfer", "cross-site", "https://sso.example", 204},
		{"trusted origin must match exactly", "POST", "/transfer", "cross-site", "https://sso.example:443", 403},
		{"bypassed webhook", "POST", "/hooks/stripe", "cross-site", "https://evil.example", 204},
	}

	ledger := &Ledger{}
	mux := ledger.Routes()
	mux.HandleFunc("POST /hooks/{provider}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent) // authenticated by a signature, not a cookie
	})
	h, err := Protect(Config{
		TrustedOrigins: []string{"https://sso.example"},
		BypassPatterns: []string{"POST /hooks/{provider}"},
	}, mux)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serve(h, request(tt.method, tt.path, tt.sfs, tt.origin)); got != tt.want {
				t.Fatalf("status = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSafeMethodsAreNotProtected(t *testing.T) {
	ledger := &Ledger{}
	h, _ := Protect(Config{}, ledger.Routes())

	code := serve(h, request("GET", "/logout", "cross-site", "https://evil.example"))
	if code != http.StatusNoContent || !ledger.LoggedOut {
		t.Fatalf("status = %d, loggedOut = %v; a GET that changes state is outside the protection", code, ledger.LoggedOut)
	}
}

func TestCheckDoesNotCallDenyHandler(t *testing.T) {
	cop := http.NewCrossOriginProtection()
	called := false
	cop.SetDenyHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	err := cop.Check(request("POST", "/transfer", "cross-site", "https://evil.example"))
	if err == nil || called {
		t.Fatalf("Check err = %v, deny handler called = %v; want an error and no call", err, called)
	}
}

func TestAddTrustedOriginValidates(t *testing.T) {
	cop := http.NewCrossOriginProtection()
	for _, bad := range []string{"sso.example", "https://", "https://sso.example/", "https://sso.example/login", "https://sso.example?x"} {
		if err := cop.AddTrustedOrigin(bad); err == nil {
			t.Errorf("AddTrustedOrigin(%q) accepted a malformed origin", bad)
		}
	}
	if _, err := Protect(Config{TrustedOrigins: []string{"https://sso.example/"}}, http.NotFoundHandler()); err == nil {
		t.Error("Protect accepted a trusted origin with a path")
	}
}

// TestBypassDoesNotCoverRedirectTargets checks the fix for CVE-2025-47910
// (Go 1.25.1): a request that ServeMux would only redirect to a bypassed
// pattern must not be exempt, because the application mux may route the
// original path to a different, protected handler.
func TestBypassDoesNotCoverRedirectTargets(t *testing.T) {
	ledger := &Ledger{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hooks/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("POST /hooks", func(w http.ResponseWriter, r *http.Request) { // state-changing, cookie-authenticated
		ledger.Transfers = append(ledger.Transfers, r.FormValue("to"))
		w.WriteHeader(http.StatusNoContent)
	})
	h, _ := Protect(Config{BypassPatterns: []string{"POST /hooks/"}}, mux)

	got := serve(h, request("POST", "/hooks", "cross-site", "https://evil.example"))
	if version.Compare(runtime.Version(), "go1.25.1") < 0 && strings.HasPrefix(runtime.Version(), "go1.25") {
		if got != http.StatusNoContent {
			t.Fatalf("%s: status = %d; expected the CVE-2025-47910 bypass on this release", runtime.Version(), got)
		}
		t.Logf("%s is vulnerable to CVE-2025-47910: upgrade to go1.25.1 or later", runtime.Version())
		return
	}
	if got != http.StatusForbidden || len(ledger.Transfers) != 0 {
		t.Fatalf("status = %d, transfers = %v; /hooks must not inherit the /hooks/ bypass", got, ledger.Transfers)
	}
}

func ExampleProtect() {
	h, _ := Protect(Config{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	for _, sfs := range []string{"same-origin", "cross-site"} {
		r := httptest.NewRequest("POST", "http://app.example/", nil)
		r.Header.Set("Sec-Fetch-Site", sfs)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		fmt.Println(sfs, rec.Code)
	}
	// Output:
	// same-origin 200
	// cross-site 403
}
