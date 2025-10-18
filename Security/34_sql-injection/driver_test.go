package sqlinject

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// The recording driver below is a minimal database/sql/driver implementation.
// It executes nothing; it records the two channels a real driver receives —
// the query text and the bound arguments — so tests can show which channel
// attacker input travelled on.

type call struct {
	Query string
	Args  []any
}

type recorder struct {
	mu    sync.Mutex
	calls []call
}

func (r *recorder) record(q string, args []driver.NamedValue) {
	c := call{Query: q}
	for _, a := range args {
		c.Args = append(c.Args, a.Value)
	}
	r.mu.Lock()
	r.calls = append(r.calls, c)
	r.mu.Unlock()
}

func (r *recorder) last(t *testing.T) call {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		t.Fatal("no query was sent")
	}
	return r.calls[len(r.calls)-1]
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

type connector struct{ rec *recorder }

func (c connector) Connect(context.Context) (driver.Conn, error) { return &conn{rec: c.rec}, nil }
func (c connector) Driver() driver.Driver                        { return fakeDriver{} }

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("recorder: use sql.OpenDB")
}

type conn struct{ rec *recorder }

// QueryContext implements driver.QueryerContext, the fast path database/sql
// takes for db.QueryContext.
func (c *conn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.rec.record(q, args)
	return emptyRows{}, nil
}

func (c *conn) Prepare(q string) (driver.Stmt, error) { return &stmt{rec: c.rec, q: q}, nil }
func (c *conn) Close() error                          { return nil }
func (c *conn) Begin() (driver.Tx, error)             { return nil, errors.New("recorder: no transactions") }

type stmt struct {
	rec *recorder
	q   string
}

func (s *stmt) Close() error  { return nil }
func (s *stmt) NumInput() int { return -1 }
func (s *stmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("recorder: exec not supported")
}
func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	named := make([]driver.NamedValue, len(args))
	for i, v := range args {
		named[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	s.rec.record(s.q, named)
	return emptyRows{}, nil
}

type emptyRows struct{}

func (emptyRows) Columns() []string         { return []string{"id", "name"} }
func (emptyRows) Close() error              { return nil }
func (emptyRows) Next([]driver.Value) error { return io.EOF }

// sqlOpen returns a *sql.DB whose connections record into rec.
func sqlOpen(rec *recorder) *sql.DB { return sql.OpenDB(connector{rec: rec}) }

// newStore returns a Store backed by a fresh recorder.
func newStore(t *testing.T) (*Store, *recorder) {
	t.Helper()
	rec := &recorder{}
	db := sqlOpen(rec)
	t.Cleanup(func() { db.Close() })
	return &Store{DB: db}, rec
}

// skeleton blanks the contents of single-quoted SQL string literals (a
// doubled quote inside a literal is an escaped quote). Two queries with equal
// skeletons have the same structure and differ only in literal values.
func skeleton(q string) string {
	var b strings.Builder
	in := false
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case c == '\'' && in && i+1 < len(q) && q[i+1] == '\'':
			i++ // escaped quote, still inside the literal
		case c == '\'':
			in = !in
			b.WriteByte(c)
		case !in:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func TestSkeleton(t *testing.T) {
	tests := map[string]string{
		"a = 'x'":            "a = ''",
		"a = 'it''s' AND b":  "a = '' AND b",
		"a = 'x' OR '1'='1'": "a = '' OR ''=''",
	}
	for in, want := range tests {
		if got := skeleton(in); got != want {
			t.Errorf("skeleton(%q) = %q, want %q", in, got, want)
		}
	}
}
