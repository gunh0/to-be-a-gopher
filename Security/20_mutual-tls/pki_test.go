package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// testCA is an in-process certificate authority (ECDSA P-256 for speed).
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newCA(t testing.TB, name string) *testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

type leafOpts struct {
	cn     string
	uri    string // SAN URI, e.g. a SPIFFE ID
	dns    []string
	ips    []net.IP
	eku    x509.ExtKeyUsage
	issuer *testCA // nil: self-signed
}

func issue(t testing.TB, o leafOpts) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: o.cn},
		DNSNames:     o.dns,
		IPAddresses:  o.ips,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour), // short-lived, like an SVID
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{o.eku},
	}
	if o.uri != "" {
		u, err := url.Parse(o.uri)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	parent, signer := tmpl, key
	if o.issuer != nil {
		parent, signer = o.issuer.cert, o.issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
