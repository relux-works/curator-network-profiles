// SPDX-License-Identifier: Apache-2.0

// Package probe is the bounded proxy preflight of
// spec/network-profiles.md N10: three distinct facts, an open TCP port, a
// successful CONNECT to the agreed target, and a TLS handshake through
// the tunnel with verification on. It uses no credentials and stops at
// the first failed step. Every probe is bounded by a timeout and by the
// caller's context.
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"syscall"
	"time"

	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

// Status of one probe step.
type Status string

const (
	StatusOK      Status = "ok"
	StatusFailed  Status = "failed"
	StatusSkipped Status = "skipped"
)

// DefaultTimeout bounds a probe when the request sets none.
const DefaultTimeout = 3 * time.Second

// Request describes one probe.
type Request struct {
	// Subject names the profile in refusals.
	Subject string
	// Endpoint is the proxy, `http://host:port`.
	Endpoint string
	// Target is the agreed CONNECT target `host:port`; empty probes TCP only.
	Target string
	// Timeout bounds the whole probe; zero means DefaultTimeout. The
	// caller's context deadline applies as well.
	Timeout time.Duration
}

// Result carries the three facts; it is what a Record keeps.
type Result struct {
	Endpoint      string    `json:"endpoint"`
	Target        string    `json:"target,omitempty"`
	TCP           Status    `json:"tcp"`
	Connect       Status    `json:"connect"`
	ConnectStatus int       `json:"connect_status,omitempty"`
	TLS           Status    `json:"tls"`
	Detail        string    `json:"detail,omitempty"`
	CheckedAt     time.Time `json:"checked_at"`
}

// Prober runs probes; the CLI and process owners take it as a boundary
// so tests can inject one that fails the test when called.
type Prober interface {
	Probe(ctx context.Context, req Request) (Result, error)
}

// Dialer is the production Prober. RootCAs nil uses the system roots;
// Dial nil uses net.Dialer. Verification is never disabled.
type Dialer struct {
	RootCAs *x509.CertPool
	Dial    func(ctx context.Context, network, address string) (net.Conn, error)
	Now     func() time.Time
}

// Probe runs TCP → CONNECT → TLS and maps failures: a TCP failure or a
// deadline is network_proxy_unreachable; CONNECT 407 is
// network_proxy_auth_failed; any other non-2xx CONNECT or a TLS failure
// is network_proxy_unreachable with the fact recorded in the result.
func (d *Dialer) Probe(ctx context.Context, req Request) (Result, error) {
	now := time.Now
	if d != nil && d.Now != nil {
		now = d.Now
	}
	res := Result{Endpoint: req.Endpoint, Target: req.Target, TCP: StatusFailed, Connect: StatusSkipped, TLS: StatusSkipped, CheckedAt: now()}
	unreachable := func(detail string) (Result, error) {
		res.Detail = detail
		return res, refusal.New(refusal.CodeProxyUnreachable, req.Subject, detail)
	}
	u, err := url.Parse(req.Endpoint)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.Port() == "" {
		return unreachable("endpoint is not http://host:port")
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dial := (&net.Dialer{}).DialContext
	if d != nil && d.Dial != nil {
		dial = d.Dial
	}
	conn, err := dial(ctx, "tcp", u.Host)
	if err != nil {
		return unreachable("tcp: " + classify(err))
	}
	defer conn.Close()
	res.TCP = StatusOK
	if req.Target == "" {
		return res, nil
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	res.Connect = StatusFailed
	if _, err := io.WriteString(conn, "CONNECT "+req.Target+" HTTP/1.1\r\nHost: "+req.Target+"\r\n\r\n"); err != nil {
		return unreachable("connect: " + classify(err))
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return unreachable("connect: " + classify(err))
	}
	res.ConnectStatus = resp.StatusCode
	if resp.StatusCode == http.StatusProxyAuthRequired {
		res.Detail = "connect: proxy authentication required (407)"
		return res, refusal.New(refusal.CodeProxyAuthFailed, req.Subject, res.Detail)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return unreachable("connect: proxy answered " + strconv.Itoa(resp.StatusCode))
	}
	res.Connect = StatusOK

	res.TLS = StatusFailed
	host, _, err := net.SplitHostPort(req.Target)
	if err != nil {
		return unreachable("tls: target is not host:port")
	}
	var roots *x509.CertPool
	if d != nil {
		roots = d.RootCAs
	}
	tconn := tls.Client(&bufferedConn{Conn: conn, r: br}, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err := tconn.HandshakeContext(ctx); err != nil {
		return unreachable("tls: " + classify(err))
	}
	_ = tconn.Close()
	res.TLS = StatusOK
	return res, nil
}

// bufferedConn reads through the bufio.Reader that consumed the CONNECT
// response so no byte is lost, and writes to the connection directly.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// classify reduces an error to a short class. Endpoint addresses may
// appear (they are configuration, not secrets); nothing else does.
func classify(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "connection closed"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "name resolution failed"
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostnameErr) || errors.As(err, &certInvalid) {
		return "certificate verification failed: " + err.Error()
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) {
		return "not a TLS server"
	}
	return err.Error()
}
