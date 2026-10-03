// SPDX-License-Identifier: Apache-2.0

package testproxy_test

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/relux-works/curator-network-profiles/internal/testproxy"
)

func client(t *testing.T, proxyURL string) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
}

func TestAnswersInvalidHostsItself(t *testing.T) {
	t.Parallel()
	p, err := testproxy.Start(testproxy.Options{ID: "A"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	resp, err := client(t, p.URL()).Get("http://egress.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "egress=A" || resp.StatusCode != 200 {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	resp, err = client(t, p.URL()).Get("http://not-invalid.example/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("non-.invalid host answered %d", resp.StatusCode)
	}
	reqs := p.Requests()
	if len(reqs) != 2 || reqs[0].Method != "GET" || reqs[0].Target != "http://egress.invalid/" {
		t.Fatalf("requests = %+v", reqs)
	}
}

func TestConnectOnlyToMappedLoopback(t *testing.T) {
	t.Parallel()
	upstream, err := testproxy.StartTLSUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from "+r.Host)
	}), "probe.invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	p, err := testproxy.Start(testproxy.Options{ID: "A", Targets: map[string]string{"probe.invalid:443": upstream.Addr()}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	u, _ := url.Parse(p.URL())
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: upstream.RootCAs, MinVersion: tls.VersionTLS12}}}
	resp, err := c.Get("https://probe.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from probe.invalid" {
		t.Fatalf("body = %q", body)
	}
	if _, err := c.Get("https://unmapped.invalid/"); err == nil {
		t.Fatal("unmapped CONNECT succeeded")
	}
	reqs := p.Requests()
	if len(reqs) != 2 || reqs[0].Method != "CONNECT" || reqs[0].Target != "probe.invalid:443" || reqs[1].Target != "unmapped.invalid:443" {
		t.Fatalf("requests = %+v", reqs)
	}
}

func TestRequireAuthAndHang(t *testing.T) {
	t.Parallel()
	auth, err := testproxy.Start(testproxy.Options{ID: "auth", RequireAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	resp, err := client(t, auth.URL()).Get("http://egress.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	hang, err := testproxy.Start(testproxy.Options{ID: "hang", Hang: true})
	if err != nil {
		t.Fatal(err)
	}
	defer hang.Close()
	conn, err := net.Dial("tcp", hang.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT probe.invalid:443 HTTP/1.1\r\nHost: probe.invalid:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	hang.Release()
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n])[:12] != "HTTP/1.1 502" {
		t.Fatalf("after release: %q, %v", buf[:n], err)
	}
}

func TestRefusesNonLoopback(t *testing.T) {
	t.Parallel()
	if _, err := testproxy.Start(testproxy.Options{Listen: "0.0.0.0:0"}); err == nil {
		t.Fatal("bound outside loopback")
	}
	if _, err := testproxy.Start(testproxy.Options{Listen: "nonsense"}); err == nil {
		t.Fatal("bad listen accepted")
	}
}
