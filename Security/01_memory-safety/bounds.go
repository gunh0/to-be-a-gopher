package memsafety

import "fmt"

// ReadAt reads n bytes at off from buf without any validation. An index past
// len(buf) is caught by the runtime bounds check and panics, which turns a
// would-be memory disclosure into a crash (a denial of service instead).
func ReadAt(buf []byte, off, n int) []byte {
	return buf[off : off+n]
}

// ReadAtChecked validates the range first. Comparing n against the remaining
// length (instead of computing off+n) also avoids integer overflow when off
// and n come from the wire.
func ReadAtChecked(buf []byte, off, n int) ([]byte, error) {
	if off < 0 || n < 0 || off > len(buf) || n > len(buf)-off {
		return nil, fmt.Errorf("memsafety: range [%d:+%d] outside buffer of %d bytes", off, n, len(buf))
	}
	return buf[off : off+n : off+n], nil
}

// Recovered runs fn and reports the value of any panic it raised. Tests use it
// to show that an out-of-range access is a runtime error, not silent reads.
func Recovered(fn func()) (v any) {
	defer func() { v = recover() }()
	fn()
	return nil
}
