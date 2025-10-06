package reqlimit

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
)

// GunzipUnsafe decompresses r with no output limit. DEFLATE reaches ratios
// near 1032:1 on repetitive input, and gzip.Reader concatenates members by
// default (multistream), so a 1 MiB upload expands to about 1 GiB in memory
// (CWE-409, Improper Handling of Highly Compressed Data).
func GunzipUnsafe(r io.Reader) ([]byte, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// GunzipLimited bounds the decompressed output, which is the quantity that
// costs memory and CPU. A limit on the compressed input alone does not help:
// the bomb is small by construction. The decompressor stops pulling input as
// soon as maxOut+1 bytes have been produced, so the cost of rejecting a bomb
// is proportional to the limit, not to the bomb.
func GunzipLimited(r io.Reader, maxOut int64) ([]byte, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return ReadAtMost(zr, maxOut)
}

// DecompressBody is middleware for request bodies sent with
// "Content-Encoding: gzip". It applies two independent limits: maxWire on
// the bytes received (http.MaxBytesReader) and maxPlain on the bytes the
// handler will see after decompression. The handler reads r.Body normally;
// reads past maxPlain fail with an error wrapping ErrTooLarge.
func DecompressBody(maxWire, maxPlain int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxWire)
		if !strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "bad gzip body", StatusFor(wrapMaxBytes(err)))
			return
		}
		r.Body = &limitedReadCloser{r: zr, c: r.Body, n: maxPlain}
		r.Header.Del("Content-Encoding")
		r.ContentLength = -1
		next.ServeHTTP(w, r)
	})
}

// limitedReadCloser returns ErrTooLarge, not io.EOF, once more than n bytes
// have been read: the explicit-error counterpart of io.LimitReader.
type limitedReadCloser struct {
	r io.Reader
	c io.Closer
	n int64
}

func (l *limitedReadCloser) Read(p []byte) (int, error) {
	if l.n < 0 {
		return 0, ErrTooLarge
	}
	if int64(len(p)) > l.n+1 {
		p = p[:l.n+1]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	if l.n < 0 {
		return n + int(l.n), ErrTooLarge
	}
	return n, wrapMaxBytes(err)
}

func (l *limitedReadCloser) Close() error { return l.c.Close() }
