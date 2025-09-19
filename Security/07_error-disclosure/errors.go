// Package errdisclose separates what an error tells the operator from what it
// tells the client. Go errors are strings built by wrapping, and every layer
// adds context — file paths, SQL, hostnames — that is exactly what an
// attacker wants and exactly what err.Error() returns.
package errdisclose

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
)

// ErrNotFound marks a missing resource. Handlers classify with errors.Is, so
// the message around it can carry any internal detail.
var ErrNotFound = errors.New("not found")

var errSyntax = errors.New("pq: syntax error at or near \"'\"")

// PublicError carries a message that is safe to show to clients, plus an
// optional internal cause for the logs. Error() is for operators; Public
// fields are for clients.
type PublicError struct {
	Status int    // HTTP status
	Code   string // stable machine-readable code
	Msg    string // human-readable, contains no internal detail
	Err    error  // internal cause, logged only
}

func (e *PublicError) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *PublicError) Unwrap() error { return e.Err }

// Invoice is the resource served by the example handlers.
type Invoice struct {
	ID     string `json:"id"`
	Amount int    `json:"amount"`
}

// LoadInvoice stands in for a repository layer. Each failure is wrapped the
// idiomatic way, with %w and as much context as helps debugging — which is
// also what makes err.Error() unsafe to return.
func LoadInvoice(id string) (Invoice, error) {
	switch {
	case id == "":
		return Invoice{}, &PublicError{Status: 400, Code: "invalid_id", Msg: "invoice id is required"}
	case strings.ContainsAny(id, "'\";"):
		q := "SELECT amount FROM invoices WHERE tenant_id = 42 AND id = '" + id + "'"
		return Invoice{}, fmt.Errorf("load invoice: query %q on db-primary.billing.internal:5432: %w", q, errSyntax)
	case id == "1000":
		return Invoice{}, fmt.Errorf("load invoice %s from /var/lib/billing/invoices.db: %w", id, ErrNotFound)
	case id == "1001":
		err := &fs.PathError{Op: "open", Path: "/etc/billing/keys/invoice-signing.pem", Err: fs.ErrPermission}
		return Invoice{}, fmt.Errorf("sign invoice %s: %w", id, err)
	}
	return Invoice{ID: id, Amount: 4200}, nil
}

// Secret is a string that redacts itself in logs (slog.LogValuer) and in
// fmt verbs (fmt.Stringer, fmt.GoStringer), so an error message or log line
// that includes it by accident does not disclose it (CWE-532).
type Secret string

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// String implements fmt.Stringer.
func (Secret) String() string { return "[REDACTED]" }

// GoString implements fmt.GoStringer for %#v.
func (Secret) GoString() string { return `"[REDACTED]"` }
