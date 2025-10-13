package session

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	idle     = 15 * time.Minute
	absolute = 8 * time.Hour
)

type browser struct {
	t      *testing.T
	client *http.Client
	base   *url.URL
}

func newBrowser(t *testing.T, srv *httptest.Server) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	// srv.Client() returns one shared client; each browser needs its own jar.
	c := &http.Client{Transport: srv.Client().Transport, Jar: jar}
	u, _ := url.Parse(srv.URL)
	return &browser{t: t, client: c, base: u}
}

func (b *browser) do(method, path string, form url.Values) (int, string) {
	b.t.Helper()
	var resp *http.Response
	var err error
	if method == http.MethodPost {
		resp, err = b.client.PostForm(b.base.String()+path, form)
	} else {
		resp, err = b.client.Get(b.base.String() + path)
	}
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func (b *browser) cookie(name string) string {
	for _, c := range b.client.Jar.Cookies(b.base) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func (b *browser) plant(name, value string) {
	b.client.Jar.SetCookies(b.base, []*http.Cookie{{Name: name, Value: value, Path: "/", Secure: true}})
}

func apps() map[string]*App {
	return map[string]*App{
		"insecure": NewInsecureApp(idle, absolute),
		"secure":   {Store: NewStore(idle, absolute)},
	}
}

func TestSessionFixation(t *testing.T) {
	want := map[string]int{"insecure": http.StatusOK, "secure": http.StatusUnauthorized}
	for name, app := range apps() {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(app.Routes())
			defer srv.Close()

			attacker := newBrowser(t, srv)
			attacker.do("GET", "/", nil)
			fixed := attacker.cookie(app.cookieName())
			if fixed == "" {
				t.Fatal("attacker got no session cookie")
			}

			victim := newBrowser(t, srv)
			victim.plant(app.cookieName(), fixed) // e.g. via a sibling subdomain or a URL-borne ID
			victim.do("POST", "/login", url.Values{"user": {"alice"}})

			code, body := attacker.do("GET", "/me", nil)
			if code != want[name] {
				t.Fatalf("attacker /me = %d %q, want %d", code, body, want[name])
			}
			if name == "secure" && victim.cookie(CookieName) == fixed {
				t.Fatal("session ID was not rotated at login")
			}
		})
	}
}

func TestLogoutInvalidatesServerSide(t *testing.T) {
	want := map[string]int{"insecure": http.StatusOK, "secure": http.StatusUnauthorized}
	for name, app := range apps() {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(app.Routes())
			defer srv.Close()

			victim := newBrowser(t, srv)
			victim.do("GET", "/", nil)
			victim.do("POST", "/login", url.Values{"user": {"alice"}})
			stolen := victim.cookie(app.cookieName())
			victim.do("POST", "/logout", nil)
			if victim.cookie(app.cookieName()) != "" {
				t.Fatal("logout did not clear the browser cookie")
			}

			thief := newBrowser(t, srv)
			thief.plant(app.cookieName(), stolen)
			if code, _ := thief.do("GET", "/me", nil); code != want[name] {
				t.Fatalf("replayed cookie after logout: %d, want %d", code, want[name])
			}
		})
	}
}

func setCookie(t *testing.T, app *App) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest("GET", "https://app.example/", nil))
	c, err := http.ParseSetCookie(rec.Header().Get("Set-Cookie"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCookieAttributes(t *testing.T) {
	c := setCookie(t, &App{Store: NewStore(idle, absolute)})
	if c.Name != CookieName || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("secure cookie = %+v", c)
	}
	if err := CheckCookie(c); err != nil {
		t.Fatal(err)
	}
	if !c.Expires.IsZero() || c.MaxAge != 0 {
		t.Fatalf("session cookie should not persist: Expires=%v MaxAge=%d", c.Expires, c.MaxAge)
	}

	bad := setCookie(t, NewInsecureApp(idle, absolute))
	if bad.Secure || bad.HttpOnly || bad.SameSite != 0 {
		t.Fatalf("insecure cookie unexpectedly hardened: %+v", bad)
	}
}

func TestSecureCookieNotSentOverHTTP(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(&url.URL{Scheme: "https", Host: "app.example", Path: "/"}, []*http.Cookie{Cookie("id")})
	if got := jar.Cookies(&url.URL{Scheme: "http", Host: "app.example", Path: "/"}); len(got) != 0 {
		t.Fatalf("Secure cookie offered to http://: %v", got)
	}
	if got := jar.Cookies(&url.URL{Scheme: "https", Host: "app.example", Path: "/"}); len(got) != 1 {
		t.Fatalf("Secure cookie not offered to https://: %v", got)
	}
}

func TestCheckCookie(t *testing.T) {
	tests := []struct {
		name string
		c    *http.Cookie
		ok   bool
	}{
		{"hardened", Cookie("x"), true},
		{"__Host- with Domain", &http.Cookie{Name: "__Host-s", Value: "x", Path: "/", Secure: true, Domain: "app.example"}, false},
		{"__Host- with sub-path", &http.Cookie{Name: "__Host-s", Value: "x", Path: "/app", Secure: true}, false},
		{"__Host- without Secure", &http.Cookie{Name: "__Host-s", Value: "x", Path: "/"}, false},
		{"__Secure- without Secure", &http.Cookie{Name: "__Secure-s", Value: "x"}, false},
		{"SameSite=None without Secure", &http.Cookie{Name: "s", Value: "x", SameSite: http.SameSiteNoneMode}, false},
		{"Partitioned without Secure", &http.Cookie{Name: "s", Value: "x", Partitioned: true}, false},
		{"Partitioned embed cookie", &http.Cookie{Name: "__Host-embed", Value: "x", Path: "/", Secure: true, SameSite: http.SameSiteNoneMode, Partitioned: true}, true},
		{"invalid name", &http.Cookie{Name: "a b", Value: "x"}, false},
		{"invalid value", &http.Cookie{Name: "s", Value: "x;y"}, false},
	}
	for _, tt := range tests {
		if err := CheckCookie(tt.c); (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok=%v", tt.name, err, tt.ok)
		}
	}
}

func TestTimeoutsAreServerSide(t *testing.T) {
	now := time.Date(2025, 10, 1, 9, 0, 0, 0, time.UTC)
	s := NewStore(idle, absolute)
	s.Now = func() time.Time { return now }

	id := s.Login("", "alice").ID
	// Active every 10 minutes: idle timeout never fires, absolute does.
	for elapsed := 10 * time.Minute; elapsed <= absolute; elapsed += 10 * time.Minute {
		now = now.Add(10 * time.Minute)
		if _, err := s.Get(id); err != nil {
			t.Fatalf("session died after %v of activity: %v", elapsed, err)
		}
	}
	now = now.Add(10 * time.Minute)
	if _, err := s.Get(id); err != ErrNoSession {
		t.Fatalf("absolute timeout: err = %v", err)
	}

	id = s.Login("", "bob").ID
	now = now.Add(idle + time.Second)
	if _, err := s.Get(id); err != ErrNoSession {
		t.Fatalf("idle timeout: err = %v", err)
	}
}

func TestDestroyUser(t *testing.T) {
	s := NewStore(idle, absolute)
	a1, a2, b := s.Login("", "alice").ID, s.Login("", "alice").ID, s.Login("", "bob").ID
	s.DestroyUser("alice")
	for _, id := range []string{a1, a2} {
		if _, err := s.Get(id); err == nil {
			t.Error("alice's session survived DestroyUser")
		}
	}
	if _, err := s.Get(b); err != nil {
		t.Error("bob's session was destroyed")
	}
}

var idRE = regexp.MustCompile(`^[A-Z2-7]{26}$`)

func TestSessionIDs(t *testing.T) {
	seen := make(map[string]bool, 10000)
	for range 10000 {
		id := NewID()
		if !idRE.MatchString(id) || seen[id] {
			t.Fatalf("bad or repeated ID %q", id)
		}
		seen[id] = true
	}

	ins := NewInsecureApp(idle, absolute).Store
	a, b := ins.Create().ID, ins.Create().ID
	if a != "1" || b != "2" {
		t.Fatalf("insecure IDs %q, %q; expected a guessable sequence", a, b)
	}
}

func ExampleCookie() {
	fmt.Println(Cookie("ABCDEFGHIJKLMNOPQRSTUVWXYZ").String())
	fmt.Println(strings.Contains(expired().String(), "Max-Age=0"))
	// Output:
	// __Host-session=ABCDEFGHIJKLMNOPQRSTUVWXYZ; Path=/; HttpOnly; Secure; SameSite=Lax
	// true
}
