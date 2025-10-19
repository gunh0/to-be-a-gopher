// Package jsondecode documents the permissive defaults of encoding/json (v1)
// and wraps them in a strict decoder. v1 matches object keys to struct fields
// case-insensitively (with Unicode folding), keeps the last of duplicate keys,
// ignores unknown keys, replaces invalid UTF-8 with U+FFFD, and Decoder.Decode
// stops after the first value without looking at what follows. Each default
// is harmless alone and a parser differential (CWE-436) next to any other
// component that reads the same bytes differently.
package jsondecode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Limits applied by DecodeStrict.
const (
	MaxBody  = 1 << 20 // bytes; use http.MaxBytesReader at the HTTP layer (chapter 22)
	MaxDepth = 32      // nesting of objects and arrays
)

// Errors returned by DecodeStrict.
var (
	ErrTooLarge     = errors.New("jsondecode: body too large")
	ErrInvalidUTF8  = errors.New("jsondecode: invalid UTF-8")
	ErrDuplicateKey = errors.New("jsondecode: duplicate object key")
	ErrTooDeep      = errors.New("jsondecode: nesting too deep")
	ErrTrailingData = errors.New("jsondecode: data after top-level value")
)

// DecodeLenient is the idiomatic one-liner found in most handlers:
// json.NewDecoder(r.Body).Decode(v). It accepts unknown fields, duplicate
// keys in any letter case, invalid UTF-8, and arbitrary bytes after the
// first value.
func DecodeLenient(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}

// DecodeStrict decodes exactly one JSON value into v and rejects inputs on
// which encoding/json and a stricter parser (a WAF, an API gateway, a JSON
// Schema validator, encoding/json/v2) could disagree:
//
//   - bodies over MaxBody;
//   - invalid UTF-8 (v1 would silently substitute U+FFFD);
//   - duplicate keys, compared after Unicode case folding, because v1 maps
//     "isAdmin", "ISADMIN" and "isadmin" to the same field and keeps the last;
//   - nesting deeper than MaxDepth;
//   - keys that match no field of v (DisallowUnknownFields);
//   - anything but whitespace after the value.
func DecodeStrict(data []byte, v any) error {
	if len(data) > MaxBody {
		return ErrTooLarge
	}
	if !utf8.Valid(data) {
		return ErrInvalidUTF8
	}
	if err := CheckKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// dec.More() is not enough: it reports false for a trailing "]" or "}".
	// Only a second Decode returning io.EOF proves the input is exhausted.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return ErrTrailingData
	}
	return nil
}

// CheckKeys walks the token stream of data and rejects duplicate keys within
// any object (after case folding) and nesting beyond MaxDepth.
func CheckKeys(data []byte) error {
	type frame struct {
		object  bool
		wantKey bool
		keys    map[string]bool
	}
	var stack []*frame
	top := func() *frame {
		if len(stack) == 0 {
			return nil
		}
		return stack[len(stack)-1]
	}
	valueDone := func() {
		if f := top(); f != nil && f.object {
			f.wantKey = true
		}
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if f := top(); f != nil && f.wantKey {
			if k, ok := tok.(string); ok {
				fk := FoldKey(k)
				if f.keys[fk] {
					return fmt.Errorf("%w: %q", ErrDuplicateKey, k)
				}
				f.keys[fk] = true
				f.wantKey = false
				continue
			}
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			if len(stack) == MaxDepth {
				return ErrTooDeep
			}
			obj := tok == json.Delim('{')
			stack = append(stack, &frame{object: obj, wantKey: obj, keys: map[string]bool{}})
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
			valueDone()
		default:
			valueDone()
		}
	}
}

// FoldKey maps a key to the form encoding/json v1 effectively compares: it
// folds ASCII case and the Unicode characters that fold onto ASCII letters,
// such as U+212A KELVIN SIGN ("k") and U+017F LATIN SMALL LETTER LONG S ("s").
func FoldKey(k string) string {
	return strings.ToLower(strings.ToUpper(k))
}
