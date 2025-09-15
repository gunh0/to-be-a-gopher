// Package aliasing shows how slices and maps share their backing storage
// across assignments, function calls and appends, and how that sharing lets a
// caller change state an object believes it owns.
package aliasing

import (
	"errors"
	"iter"
	"maps"
	"slices"
)

// ErrPrivileged is returned when a policy would grant a role that only an
// administrator may assign.
var ErrPrivileged = errors.New("aliasing: privileged role requested")

// Policy is a validated, supposedly immutable set of roles plus the response
// headers the service attaches for this principal.
type Policy struct {
	roles   []string
	headers map[string]string
}

func validate(roles []string) error {
	if slices.Contains(roles, "admin") {
		return ErrPrivileged
	}
	return nil
}

// NewPolicyUnsafe validates roles and keeps the caller's slice and map. The
// caller still holds a reference to the same backing array, so it can write
// "admin" into it after validation succeeded (CWE-374, a time-of-check to
// time-of-use gap created purely by aliasing).
func NewPolicyUnsafe(roles []string, headers map[string]string) (*Policy, error) {
	if err := validate(roles); err != nil {
		return nil, err
	}
	return &Policy{roles: roles, headers: headers}, nil
}

// NewPolicy copies its inputs before validating them, so the object validates
// and keeps exactly the same data and nobody else can reach it.
func NewPolicy(roles []string, headers map[string]string) (*Policy, error) {
	roles = slices.Clone(roles)
	if err := validate(roles); err != nil {
		return nil, err
	}
	return &Policy{roles: roles, headers: maps.Clone(headers)}, nil
}

// RolesUnsafe returns the internal slice. Writes through it change the
// policy (CWE-375).
func (p *Policy) RolesUnsafe() []string { return p.roles }

// Roles returns a copy.
func (p *Policy) Roles() []string { return slices.Clone(p.roles) }

// All exposes the roles as a read-only iterator: callers can range over them
// but get no slice to write into.
func (p *Policy) All() iter.Seq[string] { return slices.Values(p.roles) }

// HeadersUnsafe returns the internal map; a caller can add or replace headers
// for every later response.
func (p *Policy) HeadersUnsafe() map[string]string { return p.headers }

// Headers returns a shallow copy. maps.Clone copies keys and values; values
// that are themselves slices, maps or pointers would still be shared.
func (p *Policy) Headers() map[string]string { return maps.Clone(p.headers) }

// Has reports whether the policy grants role.
func (p *Policy) Has(role string) bool { return slices.Contains(p.roles, role) }
