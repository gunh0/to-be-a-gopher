// Package memsafety shows where Go's memory safety holds and where it quietly
// stops: bounds checks turn out-of-range reads into panics, but re-slicing a
// buffer within its capacity is legal and can still disclose stale bytes.
package memsafety

import (
	"encoding/binary"
	"errors"
)

// MaxPayload bounds the payload a single heartbeat may carry.
const MaxPayload = 1 << 10

// ErrMalformed is returned when a heartbeat's declared length does not match
// the bytes actually received.
var ErrMalformed = errors.New("memsafety: declared length does not match payload")

// Responder echoes heartbeat payloads back to the peer. It keeps one scratch
// buffer for every request, the same way a busy server reuses pooled buffers.
type Responder struct {
	scratch []byte
}

// NewResponder returns a Responder whose scratch buffer can hold the largest
// allowed payload.
func NewResponder() *Responder {
	return &Responder{scratch: make([]byte, 0, MaxPayload)}
}

// Remember copies data into the scratch buffer, standing in for any earlier
// request (a session token, a password) that used the same pooled memory.
func (r *Responder) Remember(data []byte) {
	r.scratch = append(r.scratch[:0], data...)
}

// EchoUnsafe trusts the 2-byte length prefix. The payload is copied into the
// scratch buffer and the buffer is re-sliced to the declared length. Because
// the declared length is still within cap(scratch), Go does not panic: the
// response includes whatever an earlier request left behind (Heartbleed,
// CVE-2014-0160, without a single line of unsafe code).
func (r *Responder) EchoUnsafe(msg []byte) []byte {
	declared := int(binary.BigEndian.Uint16(msg))
	payload := msg[2:]
	r.scratch = append(r.scratch[:0], payload...)
	return r.scratch[:declared]
}

// EchoSafe validates the declared length against the bytes that arrived and
// against MaxPayload before touching the scratch buffer, and returns a copy so
// the caller never aliases pooled memory.
func (r *Responder) EchoSafe(msg []byte) ([]byte, error) {
	if len(msg) < 2 {
		return nil, ErrMalformed
	}
	declared := int(binary.BigEndian.Uint16(msg))
	payload := msg[2:]
	if declared != len(payload) || declared > MaxPayload {
		return nil, ErrMalformed
	}
	r.scratch = append(r.scratch[:0], payload...)
	out := make([]byte, declared)
	copy(out, r.scratch)
	return out, nil
}

// Frame builds a heartbeat message with an explicit declared length, which
// lets tests lie about the length the way an attacker would.
func Frame(declared uint16, payload []byte) []byte {
	msg := make([]byte, 2, 2+len(payload))
	binary.BigEndian.PutUint16(msg, declared)
	return append(msg, payload...)
}
