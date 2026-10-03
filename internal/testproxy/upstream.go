// SPDX-License-Identifier: Apache-2.0

package testproxy

import (
	"io"
	"log"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"time"
)

// TLSUpstream is a loopback HTTPS server presenting a self-signed
// certificate for the given names. RootCAs verifies it, so a probe can
// keep TLS verification on and still reach a `.invalid` target through
// the proxy's CONNECT map.
type TLSUpstream struct {
	Server  *httptest.Server
	RootCAs *x509.CertPool
}

// StartTLSUpstream serves handler over TLS on 127.0.0.1 with a
// certificate valid for names (DNS) and 127.0.0.1.
func StartTLSUpstream(handler http.Handler, names ...string) (*TLSUpstream, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "testproxy upstream"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              names,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	srv := httptest.NewUnstartedServer(handler)
	// A client that rejects the certificate (verification on, wrong
	// roots) is an expected test outcome, not a server error to log.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	return &TLSUpstream{Server: srv, RootCAs: pool}, nil
}

// Addr returns the upstream's 127.0.0.1:port.
func (u *TLSUpstream) Addr() string { return u.Server.Listener.Addr().String() }

// Close stops the server.
func (u *TLSUpstream) Close() { u.Server.Close() }
