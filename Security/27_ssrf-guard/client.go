package ssrf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// ErrBlocked is returned (wrapped in *url.Error and *net.OpError) when the
// guard refuses to connect to an address.
var ErrBlocked = errors.New("ssrf: destination address not allowed")

// FetchInsecure fetches a user-supplied URL with the default client: any
// host, any resolved address, redirects followed, HTTP_PROXY honoured
// (CWE-918).
func FetchInsecure(ctx context.Context, rawURL string) ([]byte, error) {
	return fetch(ctx, http.DefaultClient, rawURL)
}

// CheckThenFetch validates the URL by resolving its host and checking every
// address, then fetches it with a normal client. The client resolves the
// name again when it dials: a DNS server that answers with a public address
// for the check and 127.0.0.1 for the dial (DNS rebinding, a TTL of 0)
// passes the check. Redirects are not checked at all.
func CheckThenFetch(ctx context.Context, client *http.Client, lookup LookupFunc, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	addrs, err := lookup(ctx, "ip", u.Hostname())
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if !IsPublic(a) {
			return nil, fmt.Errorf("%w: %s", ErrBlocked, a)
		}
	}
	return fetch(ctx, client, rawURL)
}

// LookupFunc has the signature of (*net.Resolver).LookupNetIP.
type LookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// Guard configures a client that checks destination addresses at dial time.
type Guard struct {
	// Allow decides whether a resolved address and port may be dialled.
	// Nil means IsPublic on the address, any port.
	Allow func(netip.AddrPort) bool
	// MaxRedirects bounds redirect chains. Zero means 3.
	MaxRedirects int

	// lookup replaces the system resolver; tests use it to simulate DNS
	// rebinding. The address check is the same either way.
	lookup LookupFunc
}

func (g *Guard) allow(ap netip.AddrPort) bool {
	if g.Allow != nil {
		return g.Allow(ap)
	}
	return IsPublic(ap.Addr())
}

// control runs after the dialer has resolved the name and created the
// socket, immediately before connect(2). address is always "ip:port", so this
// is the one place that sees exactly where the connection will go, for every
// attempt (Happy Eyeballs tries several addresses) and every redirect hop.
func (g *Guard) control(network, address string, _ syscall.RawConn) error {
	if network != "tcp4" && network != "tcp6" {
		return fmt.Errorf("%w: network %s", ErrBlocked, network)
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBlocked, err)
	}
	if !g.allow(ap) {
		return fmt.Errorf("%w: %s", ErrBlocked, ap)
	}
	return nil
}

// Client returns an *http.Client whose every connection passes the guard.
func (g *Guard) Client() *http.Client {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: g.control,
	}
	dial := dialer.DialContext
	if g.lookup != nil {
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addrs, err := g.lookup(ctx, "ip", host)
			if err != nil || len(addrs) == 0 {
				return nil, fmt.Errorf("ssrf: lookup %s: %v", host, err)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0].String(), port))
		}
	}
	maxRedirects := g.MaxRedirects
	if maxRedirects == 0 {
		maxRedirects = 3
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// Proxy must stay nil. With a proxy, the guard would only see
			// the proxy's address and the proxy would resolve the target.
			// http.DefaultTransport uses ProxyFromEnvironment.
			Proxy:                 nil,
			DialContext:           dial,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
		},
		// Each redirect hop dials again and passes control(); this adds a
		// hop limit and refuses non-HTTP schemes early.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("ssrf: stopped after %d redirects", len(via))
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("%w: redirect to scheme %q", ErrBlocked, req.URL.Scheme)
			}
			return nil
		},
	}
}

// MaxBody bounds the response size read by Fetch (see chapter 22).
const MaxBody = 1 << 20

// Fetch retrieves rawURL through the guarded client.
func (g *Guard) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q", ErrBlocked, u.Scheme)
	}
	return fetch(ctx, g.Client(), rawURL)
}

func fetch(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err == nil && len(b) > MaxBody {
		return nil, fmt.Errorf("ssrf: response larger than %d bytes", MaxBody)
	}
	return b, err
}
