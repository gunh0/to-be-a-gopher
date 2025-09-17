package panics

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// recovered runs fn and returns the value it panicked with, if any.
func recovered(fn func()) (v any) {
	defer func() { v = recover() }()
	fn()
	return nil
}

// syncBuffer is a bytes.Buffer safe for the server's logging goroutine and
// the test goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestBearer(t *testing.T) {
	tests := []struct {
		header string
		panics bool
		ok     bool
	}{
		{"Bearer abc", false, true},
		{"bearer abc", false, true},
		{"Bearer", true, false},
		{"", true, false},
		{"Basic dXNlcjpwYXNz", false, false},
		{"Bearer ", false, false},
	}
	for _, tt := range tests {
		v := recovered(func() { BearerUnsafe(tt.header) })
		if _, isRuntime := v.(runtime.Error); isRuntime != tt.panics {
			t.Errorf("BearerUnsafe(%q) recovered %v, want panic=%v", tt.header, v, tt.panics)
		}
		if _, ok := Bearer(tt.header); ok != tt.ok {
			t.Errorf("Bearer(%q) ok = %v, want %v", tt.header, ok, tt.ok)
		}
	}
}

func TestRole(t *testing.T) {
	for _, claims := range []map[string]any{{}, {"role": 1.0}, {"role": nil}, nil} {
		if v := recovered(func() { RoleUnsafe(claims) }); v == nil {
			t.Errorf("RoleUnsafe(%v) did not panic", claims)
		}
		if _, ok := Role(claims); ok {
			t.Errorf("Role(%v) ok", claims)
		}
	}
	if r, ok := Role(map[string]any{"role": "viewer"}); !ok || r != "viewer" {
		t.Fatalf("Role = %q, %v", r, ok)
	}
}

func TestDecodeEvent(t *testing.T) {
	for _, body := range []string{`{"action":"login"}`, `{"action":"login","labels":null}`} {
		v := recovered(func() { _, _ = DecodeEventUnsafe([]byte(body), "api-1") })
		if err, ok := v.(runtime.Error); !ok || !strings.Contains(err.Error(), "nil map") {
			t.Errorf("DecodeEventUnsafe(%s) recovered %v, want nil map panic", body, v)
		}
		ev, err := DecodeEvent([]byte(body), "api-1")
		if err != nil || ev.Labels["received_by"] != "api-1" {
			t.Errorf("DecodeEvent(%s) = %+v, %v", body, ev, err)
		}
	}
}

// TestNetHTTPRecoversHandlerPanic shows the built-in boundary: the panicking
// request loses its connection, the server keeps serving.
func TestNetHTTPRecoversHandlerPanic(t *testing.T) {
	var errLog syncBuffer
	srv := httptest.NewUnstartedServer(HandlerUnsafe())
	srv.Config.ErrorLog = log.New(&errLog, "", 0)
	srv.Start()

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Authorization", "Bearer")
	if resp, err := srv.Client().Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("expected a dropped connection, got %s", resp.Status)
	}

	req.Header.Set("Authorization", "Bearer abc")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("server did not survive the panic: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	srv.Close() // waits for handlers, so the log is complete
	if !strings.Contains(errLog.String(), "panic serving") {
		t.Fatalf("expected net/http to log the panic, log: %q", errLog.String())
	}
}

func TestRecoverMiddleware(t *testing.T) {
	var logs bytes.Buffer
	h := Recover(slog.New(slog.NewJSONHandler(&logs, nil)), HandlerUnsafe())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Basic")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "index out of range") {
		t.Fatal("panic detail leaked to the client (see chapter 07)")
	}
	if !strings.Contains(logs.String(), `"msg":"handler panic"`) || !strings.Contains(logs.String(), "index out of range") {
		t.Fatalf("panic not logged server side: %s", logs.String())
	}

	abort := Recover(slog.New(slog.NewJSONHandler(io.Discard, nil)), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	v := recovered(func() { abort.ServeHTTP(httptest.NewRecorder(), req) })
	if v != http.ErrAbortHandler {
		t.Fatalf("ErrAbortHandler swallowed, recovered %v", v)
	}
}

func TestHandlerValidates(t *testing.T) {
	for header, want := range map[string]int{"Bearer": 401, "": 401, "Basic x": 401, "Bearer abc": 200} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", header)
		Handler().ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%q: status %d, want %d", header, rec.Code, want)
		}
	}
}

func TestGoRecovers(t *testing.T) {
	got := make(chan any, 1)
	Go(func(v any, stack []byte) {
		if !bytes.Contains(stack, []byte("DecodeEventUnsafe")) {
			t.Errorf("stack does not name the panicking function:\n%s", stack)
		}
		got <- v
	}, func() {
		_, _ = DecodeEventUnsafe([]byte(`{"action":"x"}`), "api-1")
	})

	select {
	case v := <-got:
		if _, ok := v.(runtime.Error); !ok {
			t.Fatalf("recovered %T %v", v, v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("boundary never reported the panic")
	}
}

// TestGoroutinePanicKillsProcess runs the unsafe async handler in a child
// process (this test binary, re-executed) and checks that one malformed body
// terminated it.
func TestGoroutinePanicKillsProcess(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "PANICS_CRASH_CHILD=1")
	out, err := cmd.CombinedOutput()

	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("expected the child to die with exit status 2, err = %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("assignment to entry in nil map")) {
		t.Fatalf("unexpected child output:\n%s", out)
	}
}

func TestCrashChild(t *testing.T) {
	if os.Getenv("PANICS_CRASH_CHILD") != "1" {
		t.Skip("helper for TestGoroutinePanicKillsProcess")
	}
	AsyncHandlerUnsafe([]byte(`{"action":"x"}`))
	<-time.After(5 * time.Second) // the panic ends the process long before this
	t.Fatal("process survived a goroutine panic")
}

func TestPanicNilIsVisible(t *testing.T) {
	// Since Go 1.21 (with go >= 1.21 in go.mod) panic(nil) is turned into a
	// *runtime.PanicNilError, so `if recover() != nil` no longer misses it.
	v := recovered(func() { panic(nil) })
	if _, ok := v.(*runtime.PanicNilError); !ok {
		t.Fatalf("recovered %T", v)
	}
}

func ExampleBearer() {
	for _, h := range []string{"Bearer abc123", "Bearer", "Basic dXNlcg=="} {
		token, ok := Bearer(h)
		fmt.Printf("%q %v\n", token, ok)
	}
	// Output:
	// "abc123" true
	// "" false
	// "" false
}
