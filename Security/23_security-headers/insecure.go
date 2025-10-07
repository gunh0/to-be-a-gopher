package secheaders

import (
	"mime"
	"net/http"
)

// staticNonce is generated once at start-up. A nonce that is the same for
// every response is a password printed on every page: an attacker reads it
// from any response and puts it on an injected <script>.
var staticNonce = newNonce()

// InsecureMiddleware shows the usual misconfigurations together: a reused
// nonce, HSTS on plain HTTP, framing controlled only by X-Frame-Options, and
// no nosniff.
func InsecureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "script-src 'nonce-"+staticNonce+"'")
		h.Set("Strict-Transport-Security", HSTS)
		h.Set("X-Frame-Options", "SAMEORIGIN")
		next.ServeHTTP(w, r)
	})
}

// StaticNonce exposes the start-up nonce so tests can show it never changes.
func StaticNonce() string { return staticNonce }

// ServeUploadInsecure writes user-supplied bytes without a Content-Type. The
// net/http server then calls http.DetectContentType on the first 512 bytes
// and declares the type itself: an uploaded "avatar" that starts with <html>
// is served as text/html from your origin (stored XSS, CWE-79). Setting
// X-Content-Type-Options: nosniff would not help, because the sniffing
// happens on the server and the browser is told text/html explicitly.
func ServeUploadInsecure(w http.ResponseWriter, data []byte) {
	w.Write(data)
}

// ServeUploadSafe declares the type instead of letting anyone guess it,
// forbids browser sniffing, forces a download, and sandboxes the document in
// case a browser renders it anyway.
func ServeUploadSafe(w http.ResponseWriter, filename string, data []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Write(data)
}
