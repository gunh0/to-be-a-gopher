// Package csrfguard contrasts hand-rolled CSRF defences with
// http.CrossOriginProtection (Go 1.25), which rejects non-safe cross-origin
// browser requests using the Sec-Fetch-Site header, falling back to comparing
// Origin with Host, and needs no tokens or session state.
package csrfguard

import (
	"fmt"
	"net/http"
	"strings"
)

// NaiveOriginCheck is a typical hand-written CSRF filter. It has two bugs:
// a prefix match accepts "https://app.example.evil.example", and a missing
// Origin is allowed without considering Sec-Fetch-Site, so it relies on every
// browser sending Origin on every cross-site POST.
func NaiveOriginCheck(allowed string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if o := r.Header.Get("Origin"); o != "" && !strings.HasPrefix(o, allowed) {
				http.Error(w, "cross-origin request", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Config lists the deliberate exceptions to same-origin enforcement.
type Config struct {
	// TrustedOrigins are exact Origin values ("scheme://host[:port]") allowed
	// to make cross-origin requests, such as a separate SSO or admin origin.
	TrustedOrigins []string
	// BypassPatterns are ServeMux patterns for endpoints that are not
	// cookie-authenticated (webhooks with signatures, token APIs). Everything
	// they receive must be authenticated some other way.
	BypassPatterns []string
}

// Protect wraps next in http.CrossOriginProtection. GET, HEAD and OPTIONS
// always pass, so next must never change state on those methods.
//
// AddInsecureBypassPattern panics on an invalid or conflicting pattern, the
// same as ServeMux.Handle; configuration errors surface at start-up.
func Protect(cfg Config, next http.Handler) (http.Handler, error) {
	cop := http.NewCrossOriginProtection()
	for _, o := range cfg.TrustedOrigins {
		if err := cop.AddTrustedOrigin(o); err != nil {
			return nil, fmt.Errorf("csrfguard: %w", err)
		}
	}
	for _, p := range cfg.BypassPatterns {
		cop.AddInsecureBypassPattern(p)
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do not echo the reason; log it server-side if needed.
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	return cop.Handler(next), nil
}

// Ledger is a toy state-changing application: one cookie-authenticated
// endpoint that moves money, and one that (wrongly) changes state on GET.
type Ledger struct {
	Transfers []string
	LoggedOut bool
}

// Routes registers the ledger's handlers.
func (l *Ledger) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /transfer", func(w http.ResponseWriter, r *http.Request) {
		l.Transfers = append(l.Transfers, r.FormValue("to"))
		w.WriteHeader(http.StatusNoContent)
	})
	// State change on a safe method: no origin-based CSRF defence (and no
	// SameSite=Lax cookie) protects this, because top-level GET navigations
	// are expected to be cross-site.
	mux.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		l.LoggedOut = true
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}
