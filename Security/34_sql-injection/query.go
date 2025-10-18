// Package sqlinject contrasts SQL built with fmt.Sprintf against queries that
// keep code and data apart. database/sql forwards placeholder arguments to the
// driver separately from the query text, so a value can never change the
// statement's structure. Identifiers (column and table names, sort direction)
// and variable-length IN lists cannot be placeholders; they need an allowlist
// or generated placeholder lists instead.
package sqlinject

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// MaxIDs bounds IN-list size: every placeholder is a bind parameter, and
// databases cap those (SQLite 32766, PostgreSQL 65535, MySQL 65535).
const MaxIDs = 1000

// ErrBadInput is returned for sort keys outside the allowlist and oversized
// ID lists.
var ErrBadInput = errors.New("sqlinject: input rejected")

// User is one row of the users table.
type User struct {
	ID   int64
	Name string
}

// Store runs queries against any database/sql driver. Placeholders use the
// "?" style (SQLite, MySQL); PostgreSQL drivers expect $1, $2, ...
type Store struct {
	DB *sql.DB
}

// FindUserUnsafe interpolates name into the SQL text. A quote in name ends
// the string literal and everything after it is SQL (CWE-89):
// "x' OR '1'='1" returns every row.
func (s *Store) FindUserUnsafe(ctx context.Context, name string) ([]User, error) {
	q := fmt.Sprintf("SELECT id, name FROM users WHERE name = '%s'", name)
	return s.query(ctx, q)
}

// FindUser sends a constant query and passes name as an argument. The driver
// transmits it as a bound value (or escapes it itself), so it is only ever
// compared, never parsed.
func (s *Store) FindUser(ctx context.Context, name string) ([]User, error) {
	return s.query(ctx, "SELECT id, name FROM users WHERE name = ?", name)
}

// ListUsersUnsafe puts a client-chosen column and direction into ORDER BY.
// Placeholders cannot help here (ORDER BY ? sorts by a constant), so code
// like this is often written even by teams that always bind values.
func (s *Store) ListUsersUnsafe(ctx context.Context, column, dir string) ([]User, error) {
	q := "SELECT id, name FROM users ORDER BY " + column + " " + dir
	return s.query(ctx, q)
}

// sortKeys maps public sort keys to fixed SQL fragments. The client picks a
// key; it never supplies SQL.
var sortKeys = map[string]string{
	"":         "id ASC",
	"id":       "id ASC",
	"-id":      "id DESC",
	"name":     "name ASC, id ASC",
	"-name":    "name DESC, id ASC",
	"created":  "created_at ASC, id ASC",
	"-created": "created_at DESC, id ASC",
}

// ListUsers resolves sort through the allowlist and rejects anything else.
func (s *Store) ListUsers(ctx context.Context, sort string) ([]User, error) {
	order, ok := sortKeys[sort]
	if !ok {
		return nil, ErrBadInput
	}
	return s.query(ctx, "SELECT id, name FROM users ORDER BY "+order)
}

// FindByIDs builds "IN (?, ?, ...)" with one placeholder per ID. Only the
// number of placeholders depends on input, and that number is bounded. An
// empty list returns no rows without a query: "IN ()" is a syntax error in
// most dialects.
func (s *Store) FindByIDs(ctx context.Context, ids []int64) ([]User, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	if len(ids) > MaxIDs {
		return nil, ErrBadInput
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	q := "SELECT id, name FROM users WHERE id IN (" + Placeholders(len(ids)) + ")"
	return s.query(ctx, q, args...)
}

// Placeholders returns "?, ?, ?" with n markers.
func Placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?, ", n-1) + "?"
}

// SearchByPrefix binds the pattern and escapes LIKE wildcards in it, so a
// user searching for "50%" does not match everything starting with "50", and
// "%" alone does not turn a prefix search into a full table scan.
func (s *Store) SearchByPrefix(ctx context.Context, prefix string) ([]User, error) {
	q := "SELECT id, name FROM users WHERE name LIKE ? ESCAPE '!'"
	return s.query(ctx, q, EscapeLike(prefix)+"%")
}

// EscapeLike escapes the LIKE metacharacters %, _ and the escape character
// itself with "!". Pair it with ESCAPE '!' in the query. A backslash would
// work too, but its meaning differs by dialect: SQLite has no default escape
// character, and in MySQL the literal '\' is itself an escape sequence unless
// NO_BACKSLASH_ESCAPES is set.
func EscapeLike(s string) string {
	return likeEscaper.Replace(s)
}

var likeEscaper = strings.NewReplacer("!", "!!", "%", "!%", "_", "!_")

func (s *Store) query(ctx context.Context, q string, args ...any) ([]User, error) {
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Name); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
