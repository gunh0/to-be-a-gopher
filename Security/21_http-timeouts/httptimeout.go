// Package httptimeout shows that net/http's zero values wait forever, on
// both the server and the client side, and how to bound every phase of a
// request without breaking the endpoints that legitimately need longer.
package httptimeout

import (
	"net"
	"net/http"
	"time"
)

// NewServerUnsafe is what http.ListenAndServe(addr, h) builds: an
// http.Server with no timeouts. A client that sends one header byte every
// few seconds holds a connection and a goroutine forever (Slowloris); a few
// thousand of them exhaust file descriptors (CWE-400). gosec reports this as
// G112 (no ReadHeaderTimeout) and G114 (http.ListenAndServe).
func NewServerUnsafe(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h}
}

// Timeouts bounds each phase of an HTTP/1.x connection.
type Timeouts struct {
	ReadHeader     time.Duration // request line + headers: the Slowloris window
	Read           time.Duration // headers + body; per-request extendable
	Write          time.Duration // from end of headers to end of response
	Idle           time.Duration // keep-alive wait for the next request
	MaxHeaderBytes int
}

// Production is a starting point for an API server behind a load balancer.
// ReadHeader is short because legitimate clients send headers in one packet;
// Read and Write are generous because they also cover slow mobile clients
// and large bodies, and the endpoints that need more extend them
// individually (see ExtendDeadlines).
var Production = Timeouts{
	ReadHeader:     5 * time.Second,
	Read:           30 * time.Second,
	Write:          30 * time.Second,
	Idle:           120 * time.Second,
	MaxHeaderBytes: 64 << 10, // default is http.DefaultMaxHeaderBytes, 1 MiB
}

// NewServer sets every server-side bound.
func NewServer(addr string, h http.Handler, t Timeouts) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: t.ReadHeader,
		ReadTimeout:       t.Read,
		WriteTimeout:      t.Write,
		IdleTimeout:       t.Idle,
		MaxHeaderBytes:    t.MaxHeaderBytes,
	}
}

// WithHandlerTimeout bounds the handler's own work with http.TimeoutHandler:
// after d the client gets 503 and the request context is cancelled, so
// handlers that pass r.Context() to the database and outbound calls stop too.
// It does not apply to hijacked or streaming responses.
func WithHandlerTimeout(h http.Handler, d time.Duration) http.Handler {
	return http.TimeoutHandler(h, d, "request timed out")
}

// ExtendDeadlines lets one route (uploads, report downloads, server-sent
// events) run past the server-wide ReadTimeout/WriteTimeout, using
// http.ResponseController (Go 1.20). Middleware between the server and this
// handler must implement Unwrap() http.ResponseWriter, or the controller
// returns http.ErrNotSupported; the error is checked rather than ignored.
func ExtendDeadlines(h http.Handler, read, write time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		now := time.Now()
		if err := rc.SetReadDeadline(now.Add(read)); err != nil {
			http.Error(w, "deadline control unavailable", http.StatusInternalServerError)
			return
		}
		if err := rc.SetWriteDeadline(now.Add(write)); err != nil {
			http.Error(w, "deadline control unavailable", http.StatusInternalServerError)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// NewClientUnsafe is http.Client{} (and http.DefaultClient, used by
// http.Get): no overall timeout. A server, or anything in between, that
// accepts the connection and never answers parks the calling goroutine
// forever (CWE-1088). Under load those goroutines pile up until the caller
// itself falls over.
func NewClientUnsafe() *http.Client { return &http.Client{} }

// NewClient bounds the whole exchange with Client.Timeout and each phase in
// the Transport, so a slow DNS, TCP or TLS step fails fast and with a
// precise error. Per-call deadlines still come from the request context.
func NewClient(total time.Duration) *http.Client {
	return &http.Client{
		Timeout: total, // dial + TLS + request + response headers + body
		Transport: &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			DialContext:            (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  total,
			ExpectContinueTimeout:  1 * time.Second,
			IdleConnTimeout:        90 * time.Second,
			MaxIdleConnsPerHost:    16,
			MaxResponseHeaderBytes: 64 << 10,
		},
	}
}
