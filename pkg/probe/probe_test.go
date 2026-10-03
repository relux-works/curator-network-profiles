// SPDX-License-Identifier: Apache-2.0

package probe_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/curator-network-profiles/internal/testproxy"
	"github.com/relux-works/curator-network-profiles/pkg/probe"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

func upstream(t *testing.T, names ...string) *testproxy.TLSUpstream {
	t.Helper()
	u, err := testproxy.StartTLSUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}), names...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(u.Close)
	return u
}

func proxy(t *testing.T, opts testproxy.Options) *testproxy.Proxy {
	t.Helper()
	p, err := testproxy.Start(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// closedPort returns a loopback address nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestProbeTable(t *testing.T) {
	t.Parallel()
	up := upstream(t, "probe.invalid")
	other := upstream(t, "other.invalid")
	good := proxy(t, testproxy.Options{ID: "good", Targets: map[string]string{"probe.invalid:443": up.Addr(), "wrongname.invalid:443": other.Addr()}})
	auth := proxy(t, testproxy.Options{ID: "auth", RequireAuth: true})
	hang := proxy(t, testproxy.Options{ID: "hang", Hang: true})
	t.Cleanup(func() {
		if reqs := good.Requests(); len(reqs) < 2 {
			t.Errorf("proxy saw %d requests", len(reqs))
		}
	})
	fixed := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	withRoots := &probe.Dialer{RootCAs: up.RootCAs, Now: func() time.Time { return fixed }}
	systemRoots := &probe.Dialer{}
	redirect := &probe.Dialer{Now: func() time.Time { return fixed }, Dial: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if _, err := http.ReadRequest(bufio.NewReader(server)); err == nil {
				_, _ = io.WriteString(server, "HTTP/1.1 302 Found\r\nLocation: https://elsewhere.invalid/\r\nContent-Length: 0\r\n\r\n")
			}
		}()
		return client, nil
	}}

	cases := []struct {
		name    string
		d       *probe.Dialer
		req     probe.Request
		code    string
		tcp     probe.Status
		connect probe.Status
		status  int
		tls     probe.Status
		detail  string
	}{
		{name: "tcp connect tls all ok", d: withRoots, req: probe.Request{Subject: "egress-a", Endpoint: good.URL(), Target: "probe.invalid:443"}, tcp: "ok", connect: "ok", status: 200, tls: "ok"},
		{name: "tcp only without target", d: withRoots, req: probe.Request{Subject: "egress-a", Endpoint: good.URL()}, tcp: "ok", connect: "skipped", tls: "skipped"},
		{name: "302 redirect is unreachable", d: redirect, req: probe.Request{Subject: "egress-a", Endpoint: "http://127.0.0.1:1", Target: "probe.invalid:443"}, code: refusal.CodeProxyUnreachable, tcp: "ok", connect: "failed", status: 302, tls: "skipped", detail: "proxy answered 302"},
		{name: "407 is auth failed", d: withRoots, req: probe.Request{Subject: "egress-a", Endpoint: auth.URL(), Target: "probe.invalid:443"}, code: refusal.CodeProxyAuthFailed, tcp: "ok", connect: "failed", status: 407, tls: "skipped", detail: "407"},
		{name: "unmapped target 502 is unreachable", d: withRoots, req: probe.Request{Subject: "egress-a", Endpoint: good.URL(), Target: "nowhere.invalid:443"}, code: refusal.CodeProxyUnreachable, tcp: "ok", connect: "failed", status: 502, tls: "skipped", detail: "proxy answered 502"},
		{name: "closed port is unreachable", d: withRoots, req: probe.Request{Subject: "egress-a", Endpoint: "http://" + closedPort(t), Target: "probe.invalid:443"}, code: refusal.CodeProxyUnreachable, tcp: "failed", connect: "skipped", tls: "skipped", detail: "connection refused"},
		{name: "hang hits the deadline", d: withRoots, req: probe.Request{Subject: "egress-a", Endpoint: hang.URL(), Target: "probe.invalid:443", Timeout: 200 * time.Millisecond}, code: refusal.CodeProxyUnreachable, tcp: "ok", connect: "failed", tls: "skipped", detail: "timeout"},
		{name: "tls hostname mismatch is unreachable", d: withRoots, req: probe.Request{Subject: "egress-a", Endpoint: good.URL(), Target: "wrongname.invalid:443"}, code: refusal.CodeProxyUnreachable, tcp: "ok", connect: "ok", status: 200, tls: "failed", detail: "certificate verification failed"},
		{name: "verification stays on with system roots", d: systemRoots, req: probe.Request{Subject: "egress-a", Endpoint: good.URL(), Target: "probe.invalid:443"}, code: refusal.CodeProxyUnreachable, tcp: "ok", connect: "ok", status: 200, tls: "failed", detail: "certificate verification failed"},
		{name: "bad endpoint", d: withRoots, req: probe.Request{Subject: "egress-a", Endpoint: "127.0.0.1:1"}, code: refusal.CodeProxyUnreachable, tcp: "failed", connect: "skipped", tls: "skipped", detail: "endpoint is not http://host:port"},
		{name: "nil dialer works", d: nil, req: probe.Request{Subject: "egress-a", Endpoint: good.URL()}, tcp: "ok", connect: "skipped", tls: "skipped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			res, err := boundedProbe(t, tc.d, context.Background(), tc.req)
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("probe took %v", elapsed)
			}
			if tc.code == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v (%+v)", err, res)
				}
			} else {
				if err == nil {
					t.Fatalf("expected %s, got %+v", tc.code, res)
				}
				if c, _ := refusal.CodeOf(err); c != tc.code {
					t.Fatalf("code = %s (%v), want %s", c, err, tc.code)
				}
				if !strings.Contains(err.Error(), "egress-a") {
					t.Fatalf("subject missing: %v", err)
				}
			}
			if res.TCP != tc.tcp || res.Connect != tc.connect || res.TLS != tc.tls || res.ConnectStatus != tc.status {
				t.Fatalf("facts = tcp=%s connect=%s(%d) tls=%s, want %s/%s(%d)/%s (%s)", res.TCP, res.Connect, res.ConnectStatus, res.TLS, tc.tcp, tc.connect, tc.status, tc.tls, res.Detail)
			}
			if tc.detail != "" && !strings.Contains(res.Detail, tc.detail) {
				t.Fatalf("detail %q not in %q", tc.detail, res.Detail)
			}
			if tc.d == withRoots && !res.CheckedAt.Equal(fixed) {
				t.Fatalf("CheckedAt = %v", res.CheckedAt)
			}
			if res.Endpoint != tc.req.Endpoint || res.Target != tc.req.Target {
				t.Fatalf("result echo = %+v", res)
			}
		})
	}
}

func TestProbeHonoursContextDeadline(t *testing.T) {
	t.Parallel()
	hang := proxy(t, testproxy.Options{ID: "hang", Hang: true})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := boundedProbe(t, &probe.Dialer{}, ctx, probe.Request{Subject: "x", Endpoint: hang.URL(), Target: "probe.invalid:443", Timeout: time.Minute})
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("expected a fast deadline refusal, got %v after %v", err, time.Since(start))
	}
	if c, _ := refusal.CodeOf(err); c != refusal.CodeProxyUnreachable || res.TCP != probe.StatusOK || res.Connect != probe.StatusFailed {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

// The watchdog is a test bound, not synchronization: a lost connection
// deadline must fail this test within seconds rather than hang the suite.
func boundedProbe(t *testing.T, d *probe.Dialer, ctx context.Context, req probe.Request) (probe.Result, error) {
	t.Helper()
	type answer struct {
		result probe.Result
		err    error
	}
	done := make(chan answer, 1)
	go func() { result, err := d.Probe(ctx, req); done <- answer{result, err} }()
	select {
	case got := <-done:
		return got.result, got.err
	case <-time.After(5 * time.Second):
		t.Fatal("probe exceeded 5s watchdog")
	}
	return probe.Result{}, nil
}
