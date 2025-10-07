// Package secheaders sets browser security response headers from one
// middleware: a nonce-based Content-Security-Policy generated per request,
// nosniff, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy,
// framing controls, and HSTS only on HTTPS responses.
package secheaders

import (
	"context"
	"crypto/rand"
	"html/template"
	"net/http"
	"strings"
)

type nonceKey struct{}

// Nonce returns the CSP nonce of the current request, or "" outside the
// middleware. Templates put it on every inline <script> they emit.
func Nonce(ctx context.Context) string {
	s, _ := ctx.Value(nonceKey{}).(string)
	return s
}

// newNonce returns 128 bits from the OS CSPRNG. crypto/rand.Text (Go 1.24)
// encodes them in base32 (A-Z, 2-7), a subset of the base64 alphabet that the
// CSP nonce-source grammar requires. Since Go 1.24 crypto/rand never returns
// an error; a broken entropy source crashes the program instead.
func newNonce() string { return rand.Text() }

// CSP builds the policy for one response. 'strict-dynamic' lets a trusted,
// nonced script load further scripts, so the policy does not need a host
// allowlist (allowlists are routinely bypassable via JSONP or open CDNs).
// frame-ancestors replaces X-Frame-Options in browsers that support CSP 2.
func CSP(nonce string) string {
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'nonce-" + nonce + "' 'strict-dynamic'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	}, "; ")
}

// HSTS is sent only over TLS. RFC 6797 §7.2 says a host must not send it over
// plain HTTP and browsers ignore it there, so emitting it on every response
// only hides whether TLS is actually terminated where you think it is.
const HSTS = "max-age=63072000; includeSubDomains"

// Middleware sets the headers before the wrapped handler runs, so they are
// present whatever status the handler writes. The nonce is stored in the
// request context for templates to read.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := newNonce()
		h := w.Header()
		h.Set("Content-Security-Policy", CSP(nonce))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY") // for browsers without frame-ancestors
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", HSTS)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nonceKey{}, nonce)))
	})
}

var page = template.Must(template.New("page").Parse(
	`<!doctype html><title>{{.Title}}</title>` +
		`<script nonce="{{.Nonce}}">console.log("hello")</script>`))

// Page renders an HTML page whose inline script carries the request nonce.
func Page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page.Execute(w, struct{ Title, Nonce string }{"home", Nonce(r.Context())})
}
