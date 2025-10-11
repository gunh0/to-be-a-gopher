package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
)

const secret = "internal-admin-token"

// internal starts a loopback server standing in for an internal service
// (an admin API, a metadata endpoint).
func internal(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, secret)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func port(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

func TestPlainClientReachesLoopback(t *testing.T) {
	srv := internal(t)
	b, err := FetchInsecure(t.Context(), srv.URL)
	if err != nil || string(b) != secret {
		t.Fatalf("got %q, %v; want the internal response", b, err)
	}
}

func TestGuardRefusesLoopback(t *testing.T) {
	srv := internal(t)
	p := port(t, srv)
	g := &Guard{}
	for _, host := range []string{"127.0.0.1", "localhost", "0.0.0.0"} {
		_, err := g.Fetch(t.Context(), "http://"+host+":"+p+"/")
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("host %s: err = %v, want ErrBlocked", host, err)
		}
	}
}

func TestGuardAllowsPermittedAddress(t *testing.T) {
	// Positive control: the same server is reachable when the policy allows
	// it, so the refusals above come from the policy and not a broken client.
	srv := internal(t)
	g := &Guard{Allow: func(ap netip.AddrPort) bool { return ap.String() == srv.Listener.Addr().String() }}
	b, err := g.Fetch(t.Context(), srv.URL)
	if err != nil || string(b) != secret {
		t.Fatalf("got %q, %v", b, err)
	}
}

func TestRedirectToInternalIsRechecked(t *testing.T) {
	inner := internal(t)
	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, inner.URL+"/admin", http.StatusFound)
	}))
	defer outer.Close()

	// The plain client follows the redirect into the internal service.
	if b, err := FetchInsecure(t.Context(), outer.URL); err != nil || string(b) != secret {
		t.Fatalf("plain client: %q, %v", b, err)
	}

	// The guard allows the "public" outer server only; the redirect target
	// is dialled again and refused.
	g := &Guard{Allow: func(ap netip.AddrPort) bool { return ap.String() == outer.Listener.Addr().String() }}
	_, err := g.Fetch(t.Context(), outer.URL)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked on the redirect hop", err)
	}
}

// rebinder is a DNS server with a TTL of zero: the first answer is public,
// every later answer is loopback.
type rebinder struct {
	mu    sync.Mutex
	calls int
}

func (r *rebinder) lookup(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.calls == 1 {
		return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func TestDNSRebinding(t *testing.T) {
	srv := internal(t)
	target := "http://rebind.attacker.example:" + port(t, srv) + "/"

	// Check-then-fetch: the check sees 93.184.215.14, the dial gets 127.0.0.1.
	rb := &rebinder{}
	dialer := &net.Dialer{}
	plain := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(address)
			addrs, _ := rb.lookup(ctx, "ip", "")
			return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0].String(), p))
		},
	}}
	b, err := CheckThenFetch(t.Context(), plain, rb.lookup, target)
	if err != nil || string(b) != secret {
		t.Fatalf("check-then-fetch: %q, %v; expected the rebinding to reach the internal server", b, err)
	}

	// The guard checks the address the socket connects to, whatever the
	// resolver said earlier. Consume the public answer first, as a
	// validation step would, so that nothing ever dials it.
	rb = &rebinder{}
	rb.lookup(t.Context(), "ip", "rebind.attacker.example")
	g := &Guard{lookup: rb.lookup}
	if _, err := g.Fetch(t.Context(), target); !errors.Is(err, ErrBlocked) {
		t.Fatalf("guard: err = %v, want ErrBlocked", err)
	}
}

func TestIsPublic(t *testing.T) {
	tests := []struct {
		addr   string
		public bool
	}{
		{"8.8.8.8", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"127.255.255.254", false},
		{"::1", false},
		{"::ffff:127.0.0.1", false}, // IPv4-mapped loopback
		{"::ffff:169.254.169.254", false},
		{"0.0.0.0", false},
		{"0.1.2.3", false},
		{"::", false},
		{"10.1.2.3", false},
		{"172.16.0.1", false},
		{"172.32.0.1", true}, // just outside 172.16.0.0/12
		{"192.168.1.1", false},
		{"169.254.169.254", false}, // AWS, GCP, Azure metadata
		{"fd00:ec2::254", false},   // AWS metadata over IPv6 (fd00::/8)
		{"fe80::1", false},
		{"100.100.100.200", false}, // Alibaba Cloud metadata, in 100.64.0.0/10
		{"224.0.0.1", false},
		{"255.255.255.255", false},
		{"64:ff9b::7f00:1", false}, // NAT64 for 127.0.0.1
		{"2002:7f00:1::", false},   // 6to4 for 127.0.0.1
		{"::127.0.0.1", false},     // IPv4-compatible
	}
	for _, tt := range tests {
		if got := IsPublic(netip.MustParseAddr(tt.addr)); got != tt.public {
			t.Errorf("IsPublic(%s) = %v, want %v", tt.addr, got, tt.public)
		}
	}
	if IsPublic(netip.Addr{}) {
		t.Error("zero Addr is public")
	}
}

func TestNaiveBlocklistMissesAlternativeSpellings(t *testing.T) {
	for _, host := range []string{
		"127.1", "2130706433", "0x7f000001", "0177.0.0.1", // inet_aton forms
		"0.0.0.0", "[::]", "[::ffff:7f00:1]", "LOCALHOST.", "127.0.0.2",
		"[fd00:ec2::254]", "100.100.100.200",
		"169.254.169.254.nip.io", // public DNS name that resolves internally
	} {
		if IsBlockedHostNaive(host) {
			t.Errorf("IsBlockedHostNaive(%q) = true; expected the blocklist to miss it", host)
		}
	}
	// Go's own parsers reject the inet_aton forms, so a validator built on
	// netip.ParseAddr cannot classify them either: only the resolver knows
	// what they become.
	for _, s := range []string{"127.1", "2130706433", "0x7f000001", "0177.0.0.1"} {
		if _, err := netip.ParseAddr(s); err == nil {
			t.Errorf("netip.ParseAddr(%q) succeeded", s)
		}
		if net.ParseIP(s) != nil {
			t.Errorf("net.ParseIP(%q) succeeded", s)
		}
	}
}

func TestGuardTransportIgnoresProxyEnvironment(t *testing.T) {
	tr := (&Guard{}).Client().Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Fatal("guarded transport has a Proxy func; the guard would only see the proxy's address")
	}
	if http.DefaultTransport.(*http.Transport).Proxy == nil {
		t.Fatal("expected DefaultTransport to use ProxyFromEnvironment")
	}
}

func TestGuardRefusesNonHTTPSchemes(t *testing.T) {
	for _, u := range []string{"file:///etc/passwd", "gopher://127.0.0.1:6379/_", "ftp://example.com/"} {
		if _, err := (&Guard{}).Fetch(t.Context(), u); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: err = %v, want ErrBlocked", u, err)
		}
	}
}

func TestGuardRefusesOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", MaxBody+1))
	}))
	defer srv.Close()
	g := &Guard{Allow: func(netip.AddrPort) bool { return true }}
	if _, err := g.Fetch(t.Context(), srv.URL); err == nil {
		t.Fatal("expected an error for a response over MaxBody")
	}
}

func ExampleIsPublic() {
	for _, s := range []string{"8.8.8.8", "::ffff:10.0.0.1", "169.254.169.254", "fd00:ec2::254"} {
		fmt.Println(s, IsPublic(netip.MustParseAddr(s)))
	}
	// Output:
	// 8.8.8.8 true
	// ::ffff:10.0.0.1 false
	// 169.254.169.254 false
	// fd00:ec2::254 false
}
