// Package intoverflow shows how Go's well-defined but silent integer
// wrap-around and truncating conversions defeat size and identity checks, and
// how to check the arithmetic itself before trusting its result.
package intoverflow

import (
	"errors"
	"math/bits"
)

// HeaderSize is the fixed overhead of a record batch.
const HeaderSize = 16

// MaxBody bounds the total size a record batch may expand to.
const MaxBody = 64 << 20 // 64 MiB

// ErrTooLarge is returned when a computed size exceeds a limit or cannot be
// represented at all.
var ErrTooLarge = errors.New("intoverflow: size exceeds limit")

// BudgetUnsafe computes the buffer a batch of count records of size bytes
// needs and checks it against MaxBody. Both operands come from the wire. The
// multiplication and the addition wrap modulo 2^64 without a panic, so a
// batch declaring 2^32 records of 2^32 bytes "needs" HeaderSize bytes and
// passes the check (CWE-190). The caller then loops count times.
func BudgetUnsafe(count, size uint64) (uint64, error) {
	total := HeaderSize + count*size
	if total > MaxBody {
		return 0, ErrTooLarge
	}
	return total, nil
}

// Budget performs the same computation with explicit carries. bits.Mul64
// returns the full 128-bit product; a non-zero high word means the product
// does not fit. bits.Add64 reports the carry out of the addition. Both are
// compiler intrinsics on the common architectures, so the check is cheap.
func Budget(count, size uint64) (uint64, error) {
	hi, lo := bits.Mul64(count, size)
	if hi != 0 {
		return 0, ErrTooLarge
	}
	total, carry := bits.Add64(lo, HeaderSize, 0)
	if carry != 0 || total > MaxBody {
		return 0, ErrTooLarge
	}
	return total, nil
}

// BudgetDiv is the portable alternative without math/bits: compare count
// against the quotient of the limit instead of computing the product.
func BudgetDiv(count, size uint64) (uint64, error) {
	if size != 0 && count > (MaxBody-HeaderSize)/size {
		return 0, ErrTooLarge
	}
	return HeaderSize + count*size, nil
}
