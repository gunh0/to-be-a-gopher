package errdisclose

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// HandlerUnsafe returns err.Error() to the client. Every wrapped layer of
// context — the SQL statement with the tenant ID, the database host and port,
// file system paths, the key file name — ends up in the response body
// (CWE-209, CWE-497).
func HandlerUnsafe() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inv, err := LoadInvoice(r.URL.Query().Get("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(inv)
	})
}

type errorBody struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// Handler maps errors to a small public vocabulary and logs the full error
// server side under a request ID that the client also receives, so support
// can find the log line without the client ever seeing it.
//
// newID generates request IDs; nil means crypto/rand.Text (Go 1.24).
func Handler(log *slog.Logger, newID func() string) http.Handler {
	if newID == nil {
		newID = rand.Text
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A server-generated ID: a client-supplied X-Request-ID would let
		// the client inject arbitrary text into the logs.
		id := newID()
		w.Header().Set("X-Request-ID", id)
		inv, err := LoadInvoice(r.URL.Query().Get("id"))
		if err != nil {
			writeError(w, r, log, id, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(inv)
	})
}

// classify decides what the client may learn. Only PublicError carries a
// client-visible message; known sentinels get fixed messages; everything else
// is "internal error".
func classify(err error) (status int, code, msg string) {
	var pe *PublicError
	switch {
	case errors.As(err, &pe):
		return pe.Status, pe.Code, pe.Msg
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, "not_found", "invoice not found"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable, "unavailable", "try again later"
	default:
		return http.StatusInternalServerError, "internal", "internal error"
	}
}

func writeError(w http.ResponseWriter, r *http.Request, log *slog.Logger, id string, err error) {
	status, code, msg := classify(err)
	level := slog.LevelWarn
	if status >= 500 {
		level = slog.LevelError
	}
	log.LogAttrs(r.Context(), level, "request failed",
		slog.String("request_id", id),
		slog.Int("status", status),
		slog.String("path", r.URL.Path),
		slog.String("error", err.Error()), // full chain, server side only
	)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: code, Message: msg, RequestID: id})
}
