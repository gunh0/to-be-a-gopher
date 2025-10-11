// Package ssrf builds an HTTP client that refuses to connect to internal
// addresses. The check runs on the IP address the socket is about to connect
// to (net.Dialer.Control), after DNS resolution and on every redirect hop,
// because any check on the URL string can be bypassed by alternative IP
// spellings, DNS rebinding, redirects, or a proxy.
package ssrf

import (
	"net/netip"
	"strings"
)

// extraDenied lists ranges that netip.Addr's predicates do not cover but
// that are not ordinary public unicast either.
var extraDenied = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"; 0.0.0.0 reaches localhost on Linux and macOS
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT, also some cloud metadata (100.100.100.200)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, includes 255.255.255.255
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64: embeds an IPv4 address, may reach internal v4
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001::/32"),       // Teredo: embeds IPv4
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4: embeds IPv4
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("::/96"),           // IPv4-compatible IPv6 (deprecated, still routed as IPv4 by some stacks)
}

// IsPublic reports whether addr is a globally routable unicast address that
// a server-side fetcher may connect to. IPv4-mapped IPv6 (::ffff:127.0.0.1)
// is unmapped first; without Unmap, IsLoopback and IsPrivate already handle
// it, but prefix checks on the IPv4 ranges above would not match.
func IsPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	switch {
	case !addr.IsValid(),
		addr.IsUnspecified(),             // 0.0.0.0, ::
		addr.IsLoopback(),                // 127.0.0.0/8, ::1
		addr.IsPrivate(),                 // 10/8, 172.16/12, 192.168/16, fc00::/7 (fd00::/8 incl. fd00:ec2::254)
		addr.IsLinkLocalUnicast(),        // 169.254/16 (cloud metadata 169.254.169.254), fe80::/10
		addr.IsLinkLocalMulticast(),      // 224.0.0/24, ff02::/16
		addr.IsInterfaceLocalMulticast(), // ff01::/16
		addr.IsMulticast():               // 224/4, ff00::/8
		return false
	}
	for _, p := range extraDenied {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// IsBlockedHostNaive is the string blocklist that SSRF filters often start
// as. It compares the host part of a URL against well-known spellings of
// internal addresses. Resolvers accept many more spellings (127.1,
// 2130706433, 0x7f000001, 0177.0.0.1 via inet_aton), IPv6 has its own, and a
// public DNS name can resolve to anything.
func IsBlockedHostNaive(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "[::1]", "169.254.169.254", "metadata.google.internal":
		return true
	}
	return strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.")
}
