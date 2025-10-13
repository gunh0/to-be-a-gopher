package session

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// CookieName uses the __Host- prefix. Browsers accept such a cookie only if
// it is Secure, has Path=/ and no Domain attribute, so it cannot be set by
// a sibling subdomain or over plain HTTP, and is never sent to subdomains.
const CookieName = "__Host-session"

// Cookie returns the session cookie. No Expires/Max-Age: it is a browser
// session cookie, and lifetime is enforced by the Store.
func Cookie(id string) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		Secure:   true,                 // never sent over http:// (CWE-614)
		HttpOnly: true,                 // not readable by document.cookie (CWE-1004)
		SameSite: http.SameSiteLaxMode, // not sent on cross-site POST or sub-requests
	}
}

// expired returns a cookie that tells the browser to delete the session
// cookie. Attributes must match for __Host- cookies to be replaced.
func expired() *http.Cookie {
	c := Cookie("")
	c.MaxAge = -1
	return c
}

// CheckCookie applies the rules http.Cookie.Valid does not: cookie prefix
// requirements and SameSite=None requiring Secure. Valid does check that a
// Partitioned cookie (Go 1.23) is Secure.
func CheckCookie(c *http.Cookie) error {
	if err := c.Valid(); err != nil {
		return err
	}
	var errs []error
	if strings.HasPrefix(c.Name, "__Host-") {
		if !c.Secure || c.Path != "/" || c.Domain != "" {
			errs = append(errs, errors.New("__Host- cookie needs Secure, Path=/ and no Domain"))
		}
	}
	if strings.HasPrefix(c.Name, "__Secure-") && !c.Secure {
		errs = append(errs, errors.New("__Secure- cookie needs Secure"))
	}
	if c.SameSite == http.SameSiteNoneMode && !c.Secure {
		errs = append(errs, errors.New("SameSite=None needs Secure"))
	}
	return errors.Join(errs...)
}

// App wires the store to HTTP handlers. Insecure switches every decision
// this chapter warns about.
type App struct {
	Store    *Store
	Insecure bool
}

// NewInsecureApp returns an App with sequential session IDs, a plain cookie,
// no rotation at login and client-side-only logout.
func NewInsecureApp(idle, absolute time.Duration) *App {
	s := NewStore(idle, absolute)
	var n atomic.Int64
	s.idFunc = func() string { return strconv.FormatInt(n.Add(1), 10) }
	return &App{Store: s, Insecure: true}
}

func (a *App) cookieName() string {
	if a.Insecure {
		return "session"
	}
	return CookieName
}

func (a *App) setCookie(w http.ResponseWriter, id string) {
	if a.Insecure {
		// No Secure, no HttpOnly, no SameSite, and the only expiry is
		// client-side.
		http.SetCookie(w, &http.Cookie{Name: "session", Value: id, Path: "/", Expires: a.Store.Now().Add(a.Store.Absolute)})
		return
	}
	http.SetCookie(w, Cookie(id))
}

func (a *App) current(r *http.Request) (Session, error) {
	c, err := r.Cookie(a.cookieName())
	if err != nil {
		return Session{}, ErrNoSession
	}
	return a.Store.Get(c.Value)
}

// Routes returns: GET / (start a session), POST /login, GET /me, POST /logout.
func (a *App) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if _, err := a.current(r); err != nil {
			a.setCookie(w, a.Store.Create().ID)
		}
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("user") // credential check omitted: not this chapter's subject
		old, err := a.current(r)
		if a.Insecure && err == nil {
			// Session fixation: the pre-login ID becomes authenticated.
			a.Store.authenticateInPlace(old.ID, user)
			return
		}
		a.setCookie(w, a.Store.Login(old.ID, user).ID)
	})
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		s, err := a.current(r)
		if err != nil || s.UserID == "" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, s.UserID)
	})
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		if s, err := a.current(r); err == nil && !a.Insecure {
			a.Store.Destroy(s.ID)
		}
		if a.Insecure {
			http.SetCookie(w, &http.Cookie{Name: "session", Path: "/", MaxAge: -1})
			return
		}
		http.SetCookie(w, expired())
	})
	return mux
}
