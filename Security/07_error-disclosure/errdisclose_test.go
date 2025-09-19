package errdisclose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sensitive are fragments that must never reach a client.
var sensitive = []string{"SELECT", "tenant_id", "db-primary", ":5432", "/var/lib", "/etc/billing", ".pem", "pq:", "permission denied"}

func get(t *testing.T, h http.Handler, id string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/invoice?id="+id, nil))
	return rec
}

func leaks(body string) []string {
	var found []string
	for _, s := range sensitive {
		if strings.Contains(body, s) {
			found = append(found, s)
		}
	}
	return found
}

func TestHandlerUnsafeLeaksInternals(t *testing.T) {
	for _, id := range []string{"1'%20OR%20'1'='1", "1000", "1001"} {
		body := get(t, HandlerUnsafe(), id).Body.String()
		if len(leaks(body)) == 0 {
			t.Errorf("id=%s: expected internal detail in the response, got %q", id, body)
		}
	}
}

func TestHandlerMapsErrors(t *testing.T) {
	tests := []struct {
		id     string
		status int
		code   string
	}{
		{"", 400, "invalid_id"},
		{"1'%20OR%20'1'='1", 500, "internal"},
		{"1000", 404, "not_found"},
		{"1001", 500, "internal"},
	}
	for _, tt := range tests {
		var logs bytes.Buffer
		h := Handler(slog.New(slog.NewJSONHandler(&logs, nil)), func() string { return "req-7f3a" })
		rec := get(t, h, tt.id)

		var body errorBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("id=%s: %v", tt.id, err)
		}
		if rec.Code != tt.status || body.Error != tt.code {
			t.Errorf("id=%s: %d %q, want %d %q", tt.id, rec.Code, body.Error, tt.status, tt.code)
		}
		if found := leaks(rec.Body.String()); len(found) > 0 {
			t.Errorf("id=%s: response leaks %v", tt.id, found)
		}
		if body.RequestID != "req-7f3a" || rec.Header().Get("X-Request-ID") != "req-7f3a" {
			t.Errorf("id=%s: request ID missing from response", tt.id)
		}
		// The operator still gets everything, keyed by the same ID.
		if !strings.Contains(logs.String(), `"request_id":"req-7f3a"`) {
			t.Errorf("id=%s: log lacks request ID: %s", tt.id, logs.String())
		}
		if tt.status == 500 && len(leaks(logs.String())) == 0 {
			t.Errorf("id=%s: log lacks internal detail: %s", tt.id, logs.String())
		}
	}
}

func TestPublicMessagePassesThrough(t *testing.T) {
	h := Handler(slog.New(slog.NewJSONHandler(io.Discard, nil)), nil)
	rec := get(t, h, "")
	if !strings.Contains(rec.Body.String(), "invoice id is required") {
		t.Fatalf("validation message lost: %s", rec.Body.String())
	}
	if id := rec.Header().Get("X-Request-ID"); len(id) < 26 {
		t.Fatalf("crypto/rand.Text request ID too short: %q", id)
	}
}

func TestWrappingKeepsDetailAndIdentity(t *testing.T) {
	_, err := LoadInvoice("1001")
	// %w preserves the full text of every layer: wrapping is not sanitising.
	if !strings.Contains(err.Error(), "/etc/billing/keys/invoice-signing.pem") {
		t.Fatalf("err = %v", err)
	}
	// ...and the identity of the cause, which is what handlers should switch on.
	var pe *fs.PathError
	if !errors.Is(err, fs.ErrPermission) || !errors.As(err, &pe) || pe.Op != "open" {
		t.Fatalf("classification lost: %v", err)
	}
	// A PublicError wrapping an internal cause still classifies by the public part.
	wrapped := fmt.Errorf("handler: %w", &PublicError{Status: 409, Code: "conflict", Msg: "already paid", Err: err})
	if status, code, msg := classify(wrapped); status != 409 || code != "conflict" || msg != "already paid" {
		t.Fatalf("classify = %d %q %q", status, code, msg)
	}
}

func TestSecretIsRedacted(t *testing.T) {
	key := Secret("sk_live_51HxQ")
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("calling provider", "api_key", key)
	msg := fmt.Sprintf("auth failed with key %v (%s, %#v)", key, key, key)
	for _, out := range []string{logs.String(), msg} {
		if strings.Contains(out, "sk_live") || !strings.Contains(out, "[REDACTED]") {
			t.Errorf("secret not redacted: %s", out)
		}
	}
}

func ExampleHandler() {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h := Handler(log, func() string { return "req-1" })
	for _, id := range []string{"1001", "1000"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/invoice?id="+id, nil))
		fmt.Print(rec.Code, " ", rec.Body.String())
	}
	// Output:
	// 500 {"error":"internal","message":"internal error","request_id":"req-1"}
	// 404 {"error":"not_found","message":"invoice not found","request_id":"req-1"}
}
