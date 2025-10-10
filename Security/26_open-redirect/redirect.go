// Package redirect validates user-supplied redirect targets such as the
// "?next=" parameter of a login form. The difficulty is that Go's url.Parse
// and the browser's WHATWG URL parser disagree on inputs like "/\evil.example",
// so a check based on url.Parse alone approves URLs the browser sends
// off-site.
package redirect

import (
	"net/http"
	"net/url"
	"strings"
)

// LoginRedirectInsecure sends the user wherever ?next= says (CWE-601).
// http.Redirect does not validate the target: it only makes relative paths
// absolute and cleans them.
func LoginRedirectInsecure(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusSeeOther)
}

// IsLocalNaive is the check most code reviews accept: "it starts with a
// slash, so it is a path". "//evil.example" also starts with a slash.
func IsLocalNaive(next string) bool {
	return strings.HasPrefix(next, "/")
}

// IsLocalParsed asks url.Parse instead. It catches "//evil.example" and
// "https://evil.example", but "/\evil.example" parses as a path with no host,
// while browsers treat "\" as "/" in http(s) URLs and navigate to
// evil.example. The validator and the consumer parse differently: a parser
// differential.
func IsLocalParsed(next string) bool {
	u, err := url.Parse(next)
	return err == nil && u.Scheme == "" && u.Host == ""
}

// SafeLocalPath returns next if it is a same-origin absolute path, and
// ok=false otherwise. It rejects anything a browser could read as having an
// authority: a second leading "/" or "\", backslashes anywhere, and ASCII
// control characters (browsers strip tab and newline, so "/\t/evil.example"
// becomes "//evil.example"). The result is re-serialised from the parsed URL
// so what is sent is what was checked.
func SafeLocalPath(next string) (string, bool) {
	if len(next) == 0 || next[0] != '/' {
		return "", false
	}
	if len(next) > 1 && (next[1] == '/' || next[1] == '\\') {
		return "", false
	}
	for i := 0; i < len(next); i++ {
		if c := next[i]; c < 0x20 || c == 0x7f || c == '\\' {
			return "", false
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	out := u.String()
	if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") {
		return "", false
	}
	return out, true
}

// SafeRedirect accepts a local path (see SafeLocalPath) or an absolute https
// URL whose host is exactly one of allowedHosts. Comparison is on the parsed
// hostname, case-insensitively, never on string prefixes or suffixes, and
// userinfo is rejected so "https://trusted@evil" cannot confuse a reader.
func SafeRedirect(next string, allowedHosts ...string) (string, bool) {
	if p, ok := SafeLocalPath(next); ok {
		return p, true
	}
	for i := 0; i < len(next); i++ {
		if c := next[i]; c < 0x20 || c == 0x7f || c == '\\' {
			return "", false
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	for _, h := range allowedHosts {
		if u.Host != "" && strings.EqualFold(u.Host, h) {
			return u.String(), true
		}
	}
	return "", false
}

// LoginRedirect redirects to ?next= when it is safe and to "/" otherwise.
// Falling back silently (rather than erroring) keeps the login flow working
// for users who arrive with a stale or tampered link.
func LoginRedirect(allowedHosts ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target, ok := SafeRedirect(r.URL.Query().Get("next"), allowedHosts...)
		if !ok {
			target = "/"
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	}
}
