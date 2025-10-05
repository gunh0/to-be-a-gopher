package httptimeout

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Short timeouts keep the suite fast; the mechanism is the same at 5 s.
var short = Timeouts{
	ReadHeader:     50 * time.Millisecond,
	Read:           50 * time.Millisecond,
	Write:          50 * time.Millisecond,
	Idle:           50 * time.Millisecond,
	MaxHeaderBytes: 1 << 10,
}

var hello = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello") })

func serve(t *testing.T, s *http.Server) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(s.Handler)
	s.ErrorLog = log.New(io.Discard, "", 0)
	srv.Config = s
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// slowloris opens a raw TCP connection, sends a request line, then trickles
// one header line every 20 ms without ever finishing the header block. It
// returns how long the server kept the connection open, capped at limit.
func slowloris(t *testing.T, addr string, limit time.Duration) (open time.Duration, closed bool) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: test\r\n")
	buf := make([]byte, 512)
	for time.Since(start) < limit {
		if _, err := fmt.Fprint(conn, "X-Pad: a\r\n"); err != nil {
			return time.Since(start), true
		}
		conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		n, err := conn.Read(buf)
		var ne net.Error
		if n > 0 || (err != nil && !(errors.As(err, &ne) && ne.Timeout())) {
			return time.Since(start), true // EOF, reset, or a response: the server acted
		}
	}
	return time.Since(start), false
}

func TestSlowlorisHoldsUnsafeServer(t *testing.T) {
	srv := serve(t, NewServerUnsafe("", hello))
	held, closed := slowloris(t, srv.Listener.Addr().String(), 200*time.Millisecond)
	if closed {
		t.Fatalf("server without timeouts closed the connection after %v", held)
	}
}

func TestReadHeaderTimeoutCutsSlowloris(t *testing.T) {
	srv := serve(t, NewServer("", hello, short))
	held, closed := slowloris(t, srv.Listener.Addr().String(), time.Second)
	if !closed {
		t.Fatal("slow client was never disconnected")
	}
	if held > 500*time.Millisecond {
		t.Fatalf("disconnected after %v, want about ReadHeader (50ms)", held)
	}
}

func TestMaxHeaderBytes(t *testing.T) {
	big := strings.Repeat("a", 16<<10)
	get := func(srv *httptest.Server) int {
		req, _ := http.NewRequest("GET", srv.URL, nil)
		req.Header.Set("X-Big", big)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(serve(t, NewServerUnsafe("", hello))); code != http.StatusOK {
		t.Fatalf("default 1 MiB limit: status %d", code)
	}

	// After a 431 the server half-closes and waits 500 ms before closing
	// (net/http's RST-avoidance delay); don't make the test wait for it.
	s := NewServer("", hello, short)
	s.ErrorLog = log.New(io.Discard, "", 0)
	limited := httptest.NewUnstartedServer(hello)
	limited.Config = s
	limited.Start()
	t.Cleanup(func() { go limited.Close() })
	if code := get(limited); code != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("1 KiB limit: status %d, want 431", code)
	}
}

func TestTimeoutHandlerCancelsWork(t *testing.T) {
	cancelled := make(chan struct{})
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done(): // the database call would see this too
			close(cancelled)
		case <-time.After(5 * time.Second):
		}
	})
	srv := serve(t, NewServer("", WithHandlerTimeout(slow, 50*time.Millisecond), Production))
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || string(body) != "request timed out" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("handler context was not cancelled")
	}
}

func TestWriteTimeoutAndPerRouteExtension(t *testing.T) {
	report := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond) // building a report takes longer than the server-wide WriteTimeout
		io.WriteString(w, "report")
	})
	mux := http.NewServeMux()
	mux.Handle("/report", report)
	mux.Handle("/report-extended", ExtendDeadlines(report, time.Second, time.Second))
	srv := serve(t, NewServer("", mux, short))

	// Over the server-wide limit the connection is closed mid-response.
	if resp, err := srv.Client().Get(srv.URL + "/report"); err == nil {
		resp.Body.Close()
		t.Fatalf("expected the write deadline to break the response, got %d", resp.StatusCode)
	}
	// The one route that needs more time asks for it explicitly.
	resp, err := srv.Client().Get(srv.URL + "/report-extended")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "report" {
		t.Fatalf("body %q", body)
	}
}

// opaqueWriter is middleware that wraps the ResponseWriter without Unwrap.
type opaqueWriter struct{ http.ResponseWriter }

func TestResponseControllerNeedsUnwrap(t *testing.T) {
	h := ExtendDeadlines(hello, time.Second, time.Second)
	srv := serve(t, NewServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(opaqueWriter{w}, r)
	}), Production))
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status %d; ErrNotSupported must not be silently ignored", resp.StatusCode)
	}
}

func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := serve(t, NewServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}), Production))
	t.Cleanup(func() { close(release) }) // runs before srv.Close (LIFO)
	return srv
}

func TestDefaultClientWaitsForever(t *testing.T) {
	srv := hangingServer(t)
	done := make(chan error, 1)
	go func() {
		resp, err := NewClientUnsafe().Get(srv.URL)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("client without timeout returned: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Still waiting, and it would keep waiting; the cleanup releases it.
	}
}

func TestClientTimeout(t *testing.T) {
	srv := hangingServer(t)
	start := time.Now()
	_, err := NewClient(50 * time.Millisecond).Get(srv.URL)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v", d)
	}
}

func ExampleNewServer() {
	s := NewServer(":8080", http.NotFoundHandler(), Production)
	fmt.Println(s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout, s.IdleTimeout, s.MaxHeaderBytes)
	// Output:
	// 5s 30s 30s 2m0s 65536
}
