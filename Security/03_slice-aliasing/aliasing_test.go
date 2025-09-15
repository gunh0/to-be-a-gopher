package aliasing

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"testing"
)

func TestNewPolicyUnsafeAliasesInput(t *testing.T) {
	roles := []string{"reader", "writer"}
	p, err := NewPolicyUnsafe(roles, nil)
	if err != nil {
		t.Fatal(err)
	}
	roles[1] = "admin" // after validation
	if !p.Has("admin") {
		t.Fatal("expected the caller's write to reach the validated policy")
	}
}

func TestNewPolicyCopiesInput(t *testing.T) {
	roles := []string{"reader", "writer"}
	headers := map[string]string{"Cache-Control": "no-store"}
	p, err := NewPolicy(roles, headers)
	if err != nil {
		t.Fatal(err)
	}
	roles[1] = "admin"
	headers["Access-Control-Allow-Origin"] = "*"
	if p.Has("admin") {
		t.Fatal("policy shares the caller's role slice")
	}
	if _, ok := p.Headers()["Access-Control-Allow-Origin"]; ok {
		t.Fatal("policy shares the caller's header map")
	}
	if _, err := NewPolicy([]string{"admin"}, nil); !errors.Is(err, ErrPrivileged) {
		t.Fatalf("err = %v, want ErrPrivileged", err)
	}
}

func TestAccessorsUnsafeExposeInternalState(t *testing.T) {
	p, err := NewPolicyUnsafe([]string{"reader"}, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	p.RolesUnsafe()[0] = "admin"
	p.HeadersUnsafe()["Access-Control-Allow-Origin"] = "*"
	if !p.Has("admin") || p.HeadersUnsafe()["Access-Control-Allow-Origin"] != "*" {
		t.Fatal("expected writes through the returned slice and map to change the policy")
	}
}

func TestAccessorsReturnCopies(t *testing.T) {
	p, err := NewPolicy([]string{"reader"}, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	p.Roles()[0] = "admin"
	p.Headers()["Access-Control-Allow-Origin"] = "*"
	if p.Has("admin") || len(p.Headers()) != 0 {
		t.Fatal("copy accessors leaked internal state")
	}
	if got := slices.Collect(p.All()); !slices.Equal(got, []string{"reader"}) {
		t.Fatalf("All() = %v", got)
	}
}

func TestMapsCloneIsShallow(t *testing.T) {
	h := http.Header{"Set-Cookie": {"a=1"}}

	shallow := maps.Clone(h)
	shallow["Set-Cookie"][0] = "session=attacker"
	if h.Get("Set-Cookie") != "session=attacker" {
		t.Fatal("expected maps.Clone to share the []string values")
	}

	h = http.Header{"Set-Cookie": {"a=1"}}
	deep := h.Clone() // http.Header.Clone copies each value slice
	deep["Set-Cookie"][0] = "session=attacker"
	if h.Get("Set-Cookie") != "a=1" {
		t.Fatal("http.Header.Clone shared a value slice")
	}
}

func TestWithRoleUnsafeDependsOnCapacity(t *testing.T) {
	for _, spare := range []int{0, 3} {
		base := make([]string, 1, 1+spare)
		base[0] = "reader"
		alice := WithRoleUnsafe(base, "writer")
		_ = WithRoleUnsafe(base, "admin")
		leaked := alice[1] == "admin"
		// With no spare capacity append reallocates and the bug is invisible;
		// with spare capacity alice silently receives bob's role.
		if leaked != (spare > 0) {
			t.Errorf("spare=%d: alice = %v", spare, alice)
		}
	}
}

func TestWithRoleIsIndependent(t *testing.T) {
	base := make([]string, 1, 4)
	base[0] = "reader"
	alice := WithRole(base, "writer")
	bob := WithRole(base, "admin")
	if alice[1] != "writer" || bob[1] != "admin" {
		t.Fatalf("alice = %v, bob = %v", alice, bob)
	}
	if len(base) != 1 || base[:cap(base)][1] != "" {
		t.Fatal("WithRole wrote into base's spare capacity")
	}
}

func TestKeyIDUnsafeRetainsSecret(t *testing.T) {
	record := []byte("kid-0001:k=9f86d081884c7d659a2feaa0c55ad015")
	secret := []byte("9f86d081884c7d65")

	id := KeyIDUnsafe(record)
	if cap(id) != len(record) || !bytes.Contains(id[:cap(id)], secret) {
		t.Fatal("expected the ID to keep the whole record reachable")
	}

	safe := KeyID(record)
	clear(record) // wipe the record after use
	if string(safe) != "kid-0001" || bytes.Contains(safe[:cap(safe)], secret) {
		t.Fatalf("KeyID = %q, cap %d", safe, cap(safe))
	}
	if string(id) == "kid-0001" {
		t.Fatal("expected the aliased ID to be wiped together with the record")
	}
}

func ExampleWithRoleUnsafe() {
	base := make([]string, 1, 4)
	base[0] = "reader"
	alice := WithRoleUnsafe(base, "writer")
	_ = WithRoleUnsafe(base, "admin") // derived for someone else
	fmt.Println(alice)
	alice = WithRole(base, "writer")
	_ = WithRole(base, "admin")
	fmt.Println(alice)
	// Output:
	// [reader admin]
	// [reader writer]
}
