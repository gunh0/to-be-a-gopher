package sqlinject

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

var payloads = []string{
	"x' OR '1'='1",
	"x'; DROP TABLE users; --",
	"x' UNION SELECT id, password FROM admins --",
}

func TestFindUserUnsafeInjectsIntoQueryText(t *testing.T) {
	s, rec := newStore(t)
	ctx := t.Context()

	if _, err := s.FindUserUnsafe(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	benign := skeleton(rec.last(t).Query)

	for _, p := range payloads {
		if _, err := s.FindUserUnsafe(ctx, p); err != nil {
			t.Fatal(err)
		}
		got := rec.last(t)
		if len(got.Args) != 0 {
			t.Fatalf("args = %v, want none", got.Args)
		}
		if skeleton(got.Query) == benign {
			t.Errorf("payload %q did not change the query structure: %q", p, got.Query)
		}
	}
}

func TestFindUserBindsValue(t *testing.T) {
	s, rec := newStore(t)
	for _, p := range append([]string{"alice"}, payloads...) {
		if _, err := s.FindUser(t.Context(), p); err != nil {
			t.Fatal(err)
		}
		got := rec.last(t)
		if got.Query != "SELECT id, name FROM users WHERE name = ?" {
			t.Errorf("query text changed with input: %q", got.Query)
		}
		if !slices.Equal(got.Args, []any{p}) {
			t.Errorf("args = %q, want [%q]", got.Args, p)
		}
	}
}

func TestListUsersUnsafeOrderByInjection(t *testing.T) {
	s, rec := newStore(t)
	// A boolean-based blind probe through the sort column: the row order
	// reveals whether the subquery condition is true.
	col := "(CASE WHEN (SELECT substr(password,1,1) FROM admins)='a' THEN id ELSE name END)"
	if _, err := s.ListUsersUnsafe(t.Context(), col, "ASC"); err != nil {
		t.Fatal(err)
	}
	if q := rec.last(t).Query; !strings.Contains(q, "FROM admins") {
		t.Fatalf("query = %q, want the injected subquery", q)
	}
}

func TestListUsersAllowlist(t *testing.T) {
	s, rec := newStore(t)
	if _, err := s.ListUsers(t.Context(), "-name"); err != nil {
		t.Fatal(err)
	}
	if q := rec.last(t).Query; q != "SELECT id, name FROM users ORDER BY name DESC, id ASC" {
		t.Fatalf("query = %q", q)
	}
	n := rec.count()
	for _, bad := range []string{"name; DROP TABLE users", "NAME", "password", "id DESC", "(SELECT 1)"} {
		if _, err := s.ListUsers(t.Context(), bad); !errors.Is(err, ErrBadInput) {
			t.Errorf("ListUsers(%q) err = %v, want ErrBadInput", bad, err)
		}
	}
	if rec.count() != n {
		t.Fatal("a rejected sort key still reached the database")
	}
}

func TestFindByIDs(t *testing.T) {
	s, rec := newStore(t)
	if _, err := s.FindByIDs(t.Context(), []int64{3, 1, 4}); err != nil {
		t.Fatal(err)
	}
	got := rec.last(t)
	if got.Query != "SELECT id, name FROM users WHERE id IN (?, ?, ?)" {
		t.Fatalf("query = %q", got.Query)
	}
	if !slices.Equal(got.Args, []any{int64(3), int64(1), int64(4)}) {
		t.Fatalf("args = %v", got.Args)
	}

	n := rec.count()
	if u, err := s.FindByIDs(t.Context(), nil); u != nil || err != nil {
		t.Fatalf("empty list = %v, %v; want no rows, no error", u, err)
	}
	if _, err := s.FindByIDs(t.Context(), make([]int64, MaxIDs+1)); !errors.Is(err, ErrBadInput) {
		t.Fatalf("oversized list err = %v, want ErrBadInput", err)
	}
	if rec.count() != n {
		t.Fatal("empty or oversized list reached the database")
	}
}

func TestSearchByPrefixEscapesWildcards(t *testing.T) {
	s, rec := newStore(t)
	tests := map[string]string{
		"al":    "al%",
		"%":     "!%%",
		"50%":   "50!%%",
		"a_b":   "a!_b%",
		"x!y":   "x!!y%",
		"'; --": "'; --%",
	}
	for in, want := range tests {
		if _, err := s.SearchByPrefix(t.Context(), in); err != nil {
			t.Fatal(err)
		}
		got := rec.last(t)
		if !strings.HasSuffix(got.Query, "LIKE ? ESCAPE '!'") || !slices.Equal(got.Args, []any{want}) {
			t.Errorf("SearchByPrefix(%q) = %q %q, want arg %q", in, got.Query, got.Args, want)
		}
	}
}

func TestPlaceholders(t *testing.T) {
	for n, want := range map[int]string{-1: "", 0: "", 1: "?", 3: "?, ?, ?"} {
		if got := Placeholders(n); got != want {
			t.Errorf("Placeholders(%d) = %q, want %q", n, got, want)
		}
	}
}

func ExampleStore_FindUserUnsafe() {
	rec := &recorder{}
	s := &Store{DB: sqlOpen(rec)}
	defer s.DB.Close()
	ctx := context.Background()

	s.FindUserUnsafe(ctx, "x' OR '1'='1")
	s.FindUser(ctx, "x' OR '1'='1")
	for _, c := range rec.calls {
		fmt.Printf("%s %q\n", c.Query, c.Args)
	}
	// Output:
	// SELECT id, name FROM users WHERE name = 'x' OR '1'='1' []
	// SELECT id, name FROM users WHERE name = ? ["x' OR '1'='1"]
}
