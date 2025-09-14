package intoverflow

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
)

// EncodeFrameUnsafe writes a 2-byte big-endian length prefix followed by p.
// uint16(len(p)) keeps only the low 16 bits, so a 65,540-byte payload is
// announced as 4 bytes. The receiver reads 4 bytes and parses the remaining
// 65,536 attacker-chosen bytes as further frames: message smuggling through
// a truncating conversion (CWE-197, CWE-681).
func EncodeFrameUnsafe(p []byte) []byte {
	out := make([]byte, 2, 2+len(p))
	binary.BigEndian.PutUint16(out, uint16(len(p)))
	return append(out, p...)
}

// EncodeFrame compares the length with the target type's range before the
// conversion, so the conversion can no longer lose bits.
func EncodeFrame(p []byte) ([]byte, error) {
	if len(p) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: frame of %d bytes", ErrTooLarge, len(p))
	}
	out := make([]byte, 2, 2+len(p))
	binary.BigEndian.PutUint16(out, uint16(len(p)))
	return append(out, p...), nil
}

// DecodeFrames splits a stream of length-prefixed frames. It is correct; the
// bug it exposes lives in the encoder.
func DecodeFrames(stream []byte) ([][]byte, error) {
	var frames [][]byte
	for len(stream) > 0 {
		if len(stream) < 2 {
			return nil, fmt.Errorf("intoverflow: truncated frame header")
		}
		n := int(binary.BigEndian.Uint16(stream))
		stream = stream[2:]
		if n > len(stream) {
			return nil, fmt.Errorf("intoverflow: frame of %d bytes, %d left", n, len(stream))
		}
		frames = append(frames, stream[:n:n])
		stream = stream[n:]
	}
	return frames, nil
}

// CanReadUnsafe checks a document ID against an ACL keyed by the legacy
// 32-bit ID, while the storage layer fetches by the full int64. The check and
// the use see different values: 1<<32|7 passes as document 7 and fetches a
// document the caller never owned (CWE-681).
func CanReadUnsafe(owned map[int32]bool, id int64) bool {
	return owned[int32(id)]
}

// CanRead rejects any ID outside the int32 range before converting, so the
// value that was authorised is the value that is used.
func CanRead(owned map[int32]bool, id int64) bool {
	if id < math.MinInt32 || id > math.MaxInt32 {
		return false
	}
	return owned[int32(id)]
}

// ParseLengthUnsafe parses a decimal length with strconv.Atoi and converts it
// to uint32. "-1" becomes 4294967295 and "4294967297" becomes 1: the sign is
// reinterpreted and the high bits are dropped, both without an error.
func ParseLengthUnsafe(s string) (uint32, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

// ParseLength lets strconv do the range check: ParseUint rejects a sign and
// its bitSize argument rejects values that do not fit in 32 bits, so the
// conversion afterwards is exact.
func ParseLength(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}
