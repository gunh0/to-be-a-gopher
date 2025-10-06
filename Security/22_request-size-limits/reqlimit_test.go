package reqlimit

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// countingReader records how many bytes were pulled from the underlying
// reader, which is how the tests measure work done on the attacker's behalf.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// mebibyteOfZeros is one gzip member that expands to 1 MiB of zeros
// (about 1 KiB compressed). Compressing it once keeps the tests fast.
var mebibyteOfZeros = sync.OnceValue(func() []byte {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.Write(make([]byte, 1<<20))
	zw.Close()
	return buf.Bytes()
})

// bomb returns a gzip stream that expands to mib MiB of zeros. It is built
// from concatenated members, which gzip.Reader decodes as a single stream.
func bomb(mib int) []byte {
	return bytes.Repeat(mebibyteOfZeros(), mib)
}

func gz(t testing.TB, data []byte, level int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeUnboundedConsumesWholeBody(t *testing.T) {
	const size = 4 << 20
	body := &countingReader{r: io.MultiReader(
		strings.NewReader(`{"name":"`),
		strings.NewReader(strings.Repeat("A", size)),
		strings.NewReader(`"}`),
	)}
	req := httptest.NewRequest(http.MethodPost, "/", body)

	var v struct{ Name string }
	if err := DecodeUnbounded(req, &v); err != nil {
		t.Fatal(err)
	}
	if body.n < size || len(v.Name) != size {
		t.Fatalf("read %d bytes, decoded %d; want the full %d-byte value in memory", body.n, len(v.Name), size)
	}
}

func TestReadTruncatingSilentlyAcceptsOversizedInput(t *testing.T) {
	got, err := ReadTruncating(strings.NewReader("0123456789"), 4)
	if err != nil || string(got) != "0123" {
		t.Fatalf("got %q, %v; want the truncated prefix and no error", got, err)
	}
}

func TestReadAtMost(t *testing.T) {
	tests := []struct {
		in    string
		limit int64
		ok    bool
	}{
		{"", 0, true},
		{"x", 0, false},
		{"abcd", 4, true},
		{"abcde", 4, false},
		{"abc", -1, false}, // negative limit behaves like 0
	}
	for _, tt := range tests {
		got, err := ReadAtMost(strings.NewReader(tt.in), tt.limit)
		if tt.ok && (err != nil || string(got) != tt.in) {
			t.Errorf("ReadAtMost(%q, %d) = %q, %v; want the input back", tt.in, tt.limit, got, err)
		}
		if !tt.ok && !errors.Is(err, ErrTooLarge) {
			t.Errorf("ReadAtMost(%q, %d) err = %v, want ErrTooLarge", tt.in, tt.limit, err)
		}
	}
}

func TestDecodeLimitedOverHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v map[string]any
		err := DecodeLimited(w, r, &v, 1<<10)
		w.WriteHeader(StatusFor(err))
	}))
	defer srv.Close()

	tests := []struct {
		name      string
		body      string
		status    int
		connClose bool
	}{
		{"small", `{"a":1}`, http.StatusOK, false},
		{"oversized", `{"a":"` + strings.Repeat("x", 4<<10) + `"}`, http.StatusRequestEntityTooLarge, true},
		{"trailing value", `{"a":1}{"b":2}`, http.StatusBadRequest, false},
		{"trailing whitespace", "{\"a\":1}\n", http.StatusOK, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Post(srv.URL, "application/json", strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.status)
			}
			// MaxBytesReader tells the server to drop the connection once
			// the limit is hit, so the client cannot keep streaming.
			if resp.Close != tt.connClose {
				t.Fatalf("Connection: close = %v, want %v", resp.Close, tt.connClose)
			}
		})
	}
}

func TestGunzipUnsafeExpandsBomb(t *testing.T) {
	const plain = 8 << 20
	z := bomb(8)
	if ratio := plain / len(z); ratio < 900 {
		t.Fatalf("compression ratio %d:1, expected a bomb", ratio)
	}
	out, err := GunzipUnsafe(bytes.NewReader(z))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != plain {
		t.Fatalf("got %d bytes, want %d", len(out), plain)
	}
	t.Logf("%d compressed bytes became %d bytes in memory", len(z), len(out))
}

func TestGunzipLimitedStopsEarly(t *testing.T) {
	z := bomb(16)
	in := &countingReader{r: bytes.NewReader(z)}
	_, err := GunzipLimited(in, 1<<20)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if in.n >= int64(len(z))/2 {
		t.Fatalf("consumed %d of %d compressed bytes; the limit should stop decompression early", in.n, len(z))
	}
}

func TestGunzipLimitedConcatenatedMembers(t *testing.T) {
	// gzip.Reader reads concatenated members as one stream (multistream is
	// on by default), so the limit must apply to the sum, not per member.
	if _, err := GunzipLimited(bytes.NewReader(bomb(2)), 1<<20); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge for two 1 MiB members against a 1 MiB limit", err)
	}
	if out, err := GunzipLimited(bytes.NewReader(bomb(1)), 1<<20); err != nil || len(out) != 1<<20 {
		t.Fatalf("single member: %d bytes, %v", len(out), err)
	}
}

func TestDecompressBody(t *testing.T) {
	h := DecompressBody(64<<10, 1<<20, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), StatusFor(err))
			return
		}
		fmt.Fprint(w, len(b))
	}))
	small := gz(t, []byte("hello"), gzip.DefaultCompression)
	tests := []struct {
		name   string
		body   []byte
		status int
	}{
		{"small gzip", small, http.StatusOK},
		{"bomb under wire limit", bomb(32), http.StatusRequestEntityTooLarge},
		{"wire limit", gz(t, make([]byte, 128<<10), gzip.NoCompression), http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "bomb under wire limit" && len(tt.body) > 64<<10 {
				t.Fatalf("fixture is %d bytes, it must fit under the 64 KiB wire limit", len(tt.body))
			}
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(tt.body))
			req.Header.Set("Content-Encoding", "gzip")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.status {
				t.Fatalf("status = %d (%s), want %d", rec.Code, rec.Body, tt.status)
			}
		})
	}
}

// multipartBody builds a form with one file part of the given size.
func multipartBody(t *testing.T, fileSize int) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("upload", "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write(bytes.Repeat([]byte("z"), fileSize))
	mw.WriteField("note", "hello")
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func setTempDir(t *testing.T) string {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir) // Unix
	t.Setenv("TMP", dir)    // Windows
	t.Setenv("TEMP", dir)
	return dir
}

func TestParseMultipartFormMaxMemoryIsNotASizeLimit(t *testing.T) {
	dir := setTempDir(t)
	body, ct := multipartBody(t, 4<<20)
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", ct)

	// maxMemory = 1 MiB, but a 4 MiB file is accepted: it spills to disk.
	if err := req.ParseMultipartForm(1 << 20); err != nil {
		t.Fatalf("ParseMultipartForm: %v", err)
	}
	defer req.MultipartForm.RemoveAll()

	fh := req.MultipartForm.File["upload"][0]
	if fh.Size != 4<<20 {
		t.Fatalf("file size = %d", fh.Size)
	}
	f, err := fh.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, onDisk := f.(*os.File); !onDisk {
		t.Fatalf("file part is %T, want *os.File (spilled to disk)", f)
	}
	if entries, _ := os.ReadDir(dir); len(entries) == 0 {
		t.Fatal("expected a temporary file under TMPDIR")
	}
}

func TestParseMultipartFormWithMaxBytesReader(t *testing.T) {
	setTempDir(t)
	body, ct := multipartBody(t, 4<<20)
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()

	req.Body = http.MaxBytesReader(rec, req.Body, 1<<20)
	err := req.ParseMultipartForm(256 << 10)
	var mbe *http.MaxBytesError
	if !errors.As(err, &mbe) || mbe.Limit != 1<<20 {
		t.Fatalf("err = %v, want *http.MaxBytesError with Limit 1 MiB", err)
	}
}

func ExampleReadAtMost() {
	_, err := ReadAtMost(strings.NewReader("12345"), 4)
	fmt.Println(err)
	b, _ := ReadTruncating(strings.NewReader("12345"), 4)
	fmt.Printf("%s\n", b)
	// Output:
	// reqlimit: input exceeds limit: more than 4 bytes
	// 1234
}
