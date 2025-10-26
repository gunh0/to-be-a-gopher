// Package tlv implements a small type-length-value format and is the target
// for this chapter's fuzz tests. A record is
//
//	type (1 byte) | length (2 bytes, big-endian, unsigned) | value (length bytes)
//
// and a message is a sequence of records with no padding. ParseUnsafe
// contains the bug a fuzzer finds in seconds and a reviewer can miss for
// years: the length is decoded as a signed int16, so 0x8000-0xFFFF become
// negative and pass the bounds check (CWE-194, CWE-129).
package tlv

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	headerLen  = 3
	MaxRecords = 64 // per message
)

// Errors returned by the parsers.
var (
	ErrTruncated  = errors.New("tlv: truncated record")
	ErrTooMany    = errors.New("tlv: too many records")
	ErrValueLarge = errors.New("tlv: value longer than 65535 bytes")
)

// Record is one decoded TLV record.
type Record struct {
	Type  byte
	Value []byte
}

// ParseUnsafe decodes b. The length field is read as int16 ("the spec says
// lengths are at most 32767") and checked with off+3+n > len(b). A negative
// n passes that check, and the slice expression b[off+3:off+3+n] then has
// high < low: a runtime panic, i.e. a remote crash for any server that
// parses untrusted input without recover (chapter 05).
func ParseUnsafe(b []byte) ([]Record, error) {
	var recs []Record
	for off := 0; off < len(b); {
		if len(b)-off < headerLen {
			return nil, ErrTruncated
		}
		typ := b[off]
		n := int(int16(binary.BigEndian.Uint16(b[off+1:])))
		if off+headerLen+n > len(b) {
			return nil, ErrTruncated
		}
		recs = append(recs, Record{Type: typ, Value: b[off+headerLen : off+headerLen+n]})
		off += headerLen + n
	}
	return recs, nil
}

// Parse decodes b. The length is unsigned, it is compared against the bytes
// remaining (never computed as off+n first), the record count is bounded,
// and each Value is capped at its length so a caller cannot re-slice into the
// next record (chapter 01).
func Parse(b []byte) ([]Record, error) {
	var recs []Record
	for off := 0; off < len(b); {
		if len(recs) == MaxRecords {
			return nil, ErrTooMany
		}
		if len(b)-off < headerLen {
			return nil, ErrTruncated
		}
		typ := b[off]
		n := int(binary.BigEndian.Uint16(b[off+1:]))
		off += headerLen
		if n > len(b)-off {
			return nil, ErrTruncated
		}
		recs = append(recs, Record{Type: typ, Value: b[off : off+n : off+n]})
		off += n
	}
	return recs, nil
}

// Decode is an independent, streaming implementation of the same format.
// It exists as a differential oracle: for every input, Parse and Decode must
// agree.
func Decode(r io.Reader) ([]Record, error) {
	var recs []Record
	var hdr [headerLen]byte
	for {
		if _, err := io.ReadFull(r, hdr[:1]); err == io.EOF {
			return recs, nil
		} else if err != nil {
			return nil, err
		}
		if len(recs) == MaxRecords {
			return nil, ErrTooMany
		}
		if _, err := io.ReadFull(r, hdr[1:]); err != nil {
			return nil, ErrTruncated
		}
		v := make([]byte, binary.BigEndian.Uint16(hdr[1:]))
		if _, err := io.ReadFull(r, v); err != nil {
			return nil, ErrTruncated
		}
		recs = append(recs, Record{Type: hdr[0], Value: v})
	}
}

// Encode serialises records. It is the inverse of Parse for every input
// Parse accepts, which gives the fuzz test a round-trip property.
func Encode(recs []Record) ([]byte, error) {
	var out []byte
	for _, r := range recs {
		if len(r.Value) > 0xFFFF {
			return nil, ErrValueLarge
		}
		out = append(out, r.Type)
		out = binary.BigEndian.AppendUint16(out, uint16(len(r.Value)))
		out = append(out, r.Value...)
	}
	return out, nil
}
