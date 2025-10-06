// Package reqlimit shows how unbounded request bodies turn a cheap request
// into an expensive one, and how to bound them: http.MaxBytesReader for the
// wire, an explicit "limit + 1" read for anything else, and a limit on the
// decompressed size rather than the compressed size for gzip.
package reqlimit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// ErrTooLarge is returned when a body or a decompressed stream exceeds its
// limit. Callers map it to 413 Request Entity Too Large.
var ErrTooLarge = errors.New("reqlimit: input exceeds limit")

// DecodeUnbounded reads a JSON document straight from the request body. The
// net/http server puts no limit on body size, and json.Decoder buffers the
// whole value it is decoding, so a single request with a multi-gigabyte array
// or string is held in memory (CWE-400, CWE-770).
func DecodeUnbounded(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// ReadTruncating is the common half-fix: io.LimitReader stops after n bytes
// and reports io.EOF, so the caller receives the first n bytes and no error.
// Memory is bounded, but an oversized upload is silently accepted as a
// shorter, corrupted one.
func ReadTruncating(r io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, n))
}

// ReadAtMost reads up to n bytes and returns ErrTooLarge if r holds more.
// Reading n+1 bytes is what distinguishes "exactly n" from "more than n";
// io.LimitReader on its own cannot tell the two apart.
func ReadAtMost(r io.Reader, n int64) ([]byte, error) {
	if n < 0 {
		n = 0
	}
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > n {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, n)
	}
	return b, nil
}

// DecodeLimited bounds the body with http.MaxBytesReader before decoding.
// Once the limit is crossed, Read returns *http.MaxBytesError (Go 1.19) and
// the server is told to close the connection after the response, so the
// client cannot keep streaming into the same socket. The function also
// rejects trailing data after the first JSON value, which a bare Decode
// silently ignores.
func DecodeLimited(w http.ResponseWriter, r *http.Request, v any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return wrapMaxBytes(err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err = wrapMaxBytes(err); errors.Is(err, ErrTooLarge) {
			return err
		}
		return errors.New("reqlimit: trailing data after JSON value")
	}
	return nil
}

// wrapMaxBytes turns *http.MaxBytesError into ErrTooLarge so callers have a
// single sentinel to test with errors.Is.
func wrapMaxBytes(err error) error {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return fmt.Errorf("%w: body over %d bytes", ErrTooLarge, mbe.Limit)
	}
	return err
}

// StatusFor maps an error from this package (or net/http) to an HTTP status.
func StatusFor(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrTooLarge):
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusBadRequest
	}
}
