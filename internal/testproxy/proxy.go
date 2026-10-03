// SPDX-License-Identifier: Apache-2.0

// Package testproxy is an in-process HTTP proxy bound to 127.0.0.1 for
// tests and the demo. It never dials the network: an absolute-URI GET to
// a `.invalid` host is answered by the proxy itself with `egress=<id>`,
// and CONNECT dials only the loopback addresses of a caller-provided
// target map. Every request is recorded. Modes: require
// Proxy-Authorization (407 otherwise) and hang (block before answering
// until Release, to test a probe deadline without sleeping).
package testproxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Request is one recorded request: the method and, for CONNECT, the
// authority; otherwise the absolute URL as received.
type Request struct {
	Method string
	Target string
}

// Options configure a proxy.
type Options struct {
	// ID is echoed in every GET answer as `egress=<ID>`.
	ID string
	// Listen is the bind address; empty means 127.0.0.1:0. A non-loopback
	// address is refused.
	Listen string
	// Targets maps a CONNECT authority (`probe.invalid:443`) to the
	// loopback address to dial. Anything else is answered 502.
	Targets map[string]string
	// RequireAuth answers 407 to requests without Proxy-Authorization.
	RequireAuth bool
	// Hang blocks every request before answering until Release or Close.
	Hang bool
	// Logf, when set, receives one line per request.
	Logf func(format string, args ...any)
}

// Proxy is a running loopback proxy.
type Proxy struct {
	opts Options
	ln   net.Listener
	srv  *http.Server

	mu   sync.Mutex
	reqs []Request

	hang     chan struct{}
	released sync.Once
}

// Start binds the listener before returning, so the proxy is ready.
func Start(opts Options) (*Proxy, error) {
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}
	host, _, err := net.SplitHostPort(opts.Listen)
	if err != nil {
		return nil, fmt.Errorf("testproxy: listen address: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("testproxy: refusing to listen outside loopback")
	}
	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return nil, err
	}
	p := &Proxy{opts: opts, ln: ln, hang: make(chan struct{})}
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = p.srv.Serve(ln) }()
	return p, nil
}

// ID returns the proxy id.
func (p *Proxy) ID() string { return p.opts.ID }

// Addr returns host:port.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// URL returns http://host:port.
func (p *Proxy) URL() string { return "http://" + p.Addr() }

// Requests returns a copy of the recorded requests in arrival order.
func (p *Proxy) Requests() []Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Request, len(p.reqs))
	copy(out, p.reqs)
	return out
}

// Release unblocks hanging requests; they are then answered 502.
func (p *Proxy) Release() { p.released.Do(func() { close(p.hang) }) }

// Close releases and stops the proxy, closing open connections.
func (p *Proxy) Close() error {
	p.Release()
	return p.srv.Close()
}

func (p *Proxy) record(method, target string) {
	p.mu.Lock()
	p.reqs = append(p.reqs, Request{Method: method, Target: target})
	p.mu.Unlock()
	if p.opts.Logf != nil {
		p.opts.Logf("proxy %s: %s %s", p.opts.ID, method, target)
	}
}

// ServeHTTP implements the proxy.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if r.Method != http.MethodConnect {
		target = r.URL.String()
	}
	p.record(r.Method, target)
	if p.opts.Hang {
		<-p.hang
		http.Error(w, "testproxy: released after hang", http.StatusBadGateway)
		return
	}
	if p.opts.RequireAuth && r.Header.Get("Proxy-Authorization") == "" {
		w.Header().Set("Proxy-Authenticate", `Basic realm="testproxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if r.URL.IsAbs() && strings.HasSuffix(strings.ToLower(r.URL.Hostname()), ".invalid") {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "egress="+p.opts.ID)
		return
	}
	http.Error(w, "testproxy: refusing to dial upstream", http.StatusBadGateway)
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	addr, ok := p.opts.Targets[r.Host]
	if !ok {
		http.Error(w, "testproxy: unknown CONNECT target", http.StatusBadGateway)
		return
	}
	if host, _, err := net.SplitHostPort(addr); err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		http.Error(w, "testproxy: target is not loopback", http.StatusBadGateway)
		return
	}
	upstream, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		http.Error(w, "testproxy: upstream unavailable", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "testproxy: cannot hijack", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	_, _ = rw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
	_ = rw.Flush()
	pipe(conn, rw.Reader, upstream)
}

// pipe copies both ways until either side ends, then closes both.
func pipe(client net.Conn, clientReader *bufio.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, clientReader); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}
