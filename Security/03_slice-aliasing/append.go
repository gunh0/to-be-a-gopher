package aliasing

import "bytes"

// WithRoleUnsafe derives a new role list from base. append writes into
// base's backing array whenever len(base) < cap(base), so two lists derived
// from the same base share their last element: deriving "admin" for one user
// rewrites the list already handed to another (CWE-471).
func WithRoleUnsafe(base []string, role string) []string {
	return append(base, role)
}

// WithRole caps base with a full slice expression. With cap == len, append
// must allocate a new array, so every derived list is independent.
// slices.Concat(base, []string{role}) is an equivalent spelling.
func WithRole(base []string, role string) []string {
	return append(base[:len(base):len(base)], role)
}

// KeyIDUnsafe returns the 8-byte key identifier at the start of a key record.
// The result shares the record's backing array: it keeps the whole record,
// secret included, reachable for as long as the ID is kept (in a cache, a log
// field, a map key), and anyone holding it can re-slice up to cap to read the
// secret (see chapter 01).
func KeyIDUnsafe(record []byte) []byte {
	return record[:8]
}

// KeyID returns an independent copy, so the record can be wiped and collected.
func KeyID(record []byte) []byte {
	return bytes.Clone(record[:8])
}
