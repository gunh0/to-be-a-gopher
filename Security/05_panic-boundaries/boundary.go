package panics

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Go runs fn in a new goroutine behind a recovery boundary. net/http only
// recovers panics on the goroutine that called ServeHTTP; a panic on any
// goroutine a handler starts is unrecovered and terminates the process —
// every in-flight request on every connection (CWE-400). Every goroutine that
// processes untrusted input needs its own deferred recover.
func Go(onPanic func(v any, stack []byte), fn func()) {
	go func() {
		defer func() {
			if v := recover(); v != nil {
				onPanic(v, debug.Stack())
			}
		}()
		fn()
	}()
}

// Recover is HTTP middleware that turns a handler panic into a 500 response
// and a structured log entry, instead of net/http's default of logging to
// the server's ErrorLog and dropping the connection. http.ErrAbortHandler is
// re-raised: it is the documented way to abort a response deliberately and
// net/http suppresses its log line.
func Recover(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(v)
			}
			log.Error("handler panic",
				"method", r.Method, "path", r.URL.Path,
				"panic", fmt.Sprint(v), "stack", string(debug.Stack()))
			// If the handler already wrote headers this is a no-op on the
			// status line; the client sees a truncated response.
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}

// HandlerUnsafe authenticates with BearerUnsafe. A malformed Authorization
// header panics; net/http recovers it per request, logs a stack trace and
// closes the connection.
func HandlerUnsafe() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := BearerUnsafe(r.Header.Get("Authorization"))
		fmt.Fprintf(w, "token length %d\n", len(token))
	})
}

// Handler validates the header and answers 401 instead of panicking.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := Bearer(r.Header.Get("Authorization"))
		if !ok {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "token length %d\n", len(token))
	})
}

// AsyncHandlerUnsafe acknowledges the request and processes the event in the
// background with a bare go statement. A body like {"action":"x"} makes the
// background goroutine panic and the whole server exits.
func AsyncHandlerUnsafe(body []byte) {
	go func() {
		_, _ = DecodeEventUnsafe(body, "api-1")
	}()
}
