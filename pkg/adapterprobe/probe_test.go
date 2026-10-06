// SPDX-License-Identifier: Apache-2.0
package adapterprobe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/catalog"
	"github.com/relux-works/curator-network-profiles/pkg/hosted"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

func request() Request {
	return Request{Adapter: Identity{Adapter: "generic-env-v1", Harness: "fake-harness", Entrypoint: "exec"}, Artifact: []byte("\x7fELFfake-native-snapshot"), Recipe: "fake-http-v1"}
}
func assertFailure(t *testing.T, res Result, err error, reason string) {
	t.Helper()
	var unsupported *Unsupported
	code, _ := refusal.CodeOf(err)
	if res.Verified || res.Reason != reason || !errors.Is(err, ErrUnsupported) || !errors.As(err, &unsupported) || unsupported.Reason != reason || code != refusal.CodeScopeUnsupported {
		t.Fatalf("result=%+v error=%v; want %s", res, err, reason)
	}
}
func approved(t *testing.T, req Request) (Policy, Result) {
	t.Helper()
	res, err := identify(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return Policy{Mode: Strict, Allowlist: []AllowedBuild{{Adapter: req.Adapter, BuildID: res.BuildID, Recipe: req.Recipe, Platform: runtime.GOOS, Scope: TransportScope}}}, res
}

func TestNoUnsafeExecutionOrFileAccess(t *testing.T) {
	req := request()
	// The binary path is never opened or launched, so no fixture file is
	// created at all: even an absent path cannot change the refusal.
	missing := filepath.Join(t.TempDir(), "must-not-run")
	req.Binary = missing
	for _, sandbox := range []bool{false, true} {
		req.Sandbox = sandbox
		res, err := Probe(context.Background(), req)
		reason := "platform_unsupported"
		if runtime.GOOS == "darwin" {
			reason = "secure_supervisor_required"
		}
		if runtime.GOOS == "linux" {
			reason = "namespace_supervisor_required"
		}
		assertFailure(t, res, err, reason)
	}
	// Supplied snapshot permits strict lookup without opening even a bad path.
	req.Binary = filepath.Join(missing, "not-a-directory", "binary")
	policy, _ := approved(t, req)
	res, err := Verified(context.Background(), req, missing, policy)
	if err != nil || !res.Verified {
		t.Fatalf("strict lookup touched a path: %+v %v", res, err)
	}
	req.Artifact = nil
	res, err = Probe(context.Background(), req)
	assertFailure(t, res, err, "artifact_snapshot_required")
}

func TestRecipeAndAdapterBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Request)
		reason string
	}{
		{"specialized", func(r *Request) { r.Adapter.Adapter = "codex-env-v1" }, "adapter_unsupported"},
		{"arbitrary adapter", func(r *Request) { r.Adapter.Adapter = "unknown" }, "adapter_unsupported"},
		{"raw args", func(r *Request) { r.Args = []string{"--config", "/untrusted"} }, "unversioned_invocation"},
		{"script", func(r *Request) { r.Artifact = []byte("#!/bin/sh\nexec /mutable/program") }, "runtime_closure_unsupported"},
		{"interpreter program", func(r *Request) { r.Args = []string{"/mutable/program"} }, "unversioned_invocation"},
		{"unknown revision", func(r *Request) { r.Recipe = "fake-http-v2" }, "recipe_unsupported"},
		{"recipe mismatch", func(r *Request) { r.Adapter.Entrypoint = "hosted" }, "recipe_unsupported"},
		{"auth before network", func(r *Request) { r.Adapter.Harness = "claude-code"; r.Recipe = "claude-exec-v1" }, "credential_free_recipe_unavailable"},
		{"mutable runtime", func(r *Request) { r.Adapter.Harness = "codex-cli"; r.Recipe = "codex-exec-v1" }, "runtime_closure_unsupported"},
		{"stdin protocol", func(r *Request) {
			r.Adapter.Harness = "codex-cli"
			r.Adapter.Entrypoint = "app-server"
			r.Recipe = "codex-hosted-v1"
		}, "protocol_recipe_unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := request()
			tc.change(&req)
			res, err := Probe(context.Background(), req)
			assertFailure(t, res, err, tc.reason)
		})
	}
}

func TestCancellationAndDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, call := range []func(context.Context, Request) (Result, error){Probe, func(ctx context.Context, req Request) (Result, error) { return Lookup(ctx, req, Policy{}) }, func(ctx context.Context, req Request) (Result, error) {
		return Verified(ctx, req, "/never-open", Policy{})
	}} {
		res, err := call(ctx, request())
		assertFailure(t, res, err, "cancelled")
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	res, err := Probe(ctx, request())
	assertFailure(t, res, err, "deadline_exceeded")
}

func TestDarwinPolicySpecification(t *testing.T) {
	profile, err := darwinProfile("/private/probe", "/Users/operator-fixture", "/private/probe/stage/harness", "127.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"(deny default)", "(deny mach-lookup)", "com.apple.SecurityServer", "com.apple.securityd.xpc", "com.apple.securityd.systemkeychain", `"/Users/operator-fixture"`, `"/Users/operator-fixture/Library/Keychains"`, `"/Library/Keychains"`, "(deny process-fork)", `"127.0.0.1:12345"`, `(deny file-write* (subpath "/private/probe/stage"))`} {
		if !strings.Contains(profile, required) {
			t.Fatalf("missing %s", required)
		}
	}
	for _, forbidden := range []string{"(allow default)", "localhost:*", "allow mach-lookup", "remote unix-socket"} {
		if strings.Contains(profile, forbidden) {
			t.Fatalf("unsafe rule %s", forbidden)
		}
	}
	for _, tc := range [][4]string{{"/Users/operator-fixture/probe", "/Users/operator-fixture", "/Users/operator-fixture/probe/stage/harness", "127.0.0.1:1"}, {"/tmp/probe", "/", "/tmp/probe/stage/harness", "127.0.0.1:1"}, {"/tmp/probe", "/home/operator", "/tmp/probe/stage/harness", "example.invalid:80"}} {
		if _, err := darwinProfile(tc[0], tc[1], tc[2], tc[3]); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	// A rendered profile never changes the native refusal into an execution.
	res, err := qualificationUnavailable(context.Background(), request(), Result{}, "darwin")
	assertFailure(t, res, err, "secure_supervisor_required")
}

// guardDial rejects all but the exact supplied numeric loopback endpoint
// before any DNS resolution. Missing proxy/bypass regressions fail safely.
func guardDial(endpoint string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		ip := net.ParseIP(host)
		if err != nil || addr != endpoint || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("fake dial refused")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
	}
}
func TestAuthenticatedScopedSinkAndSafeFake(t *testing.T) {
	token := strings.Repeat("a", 64)
	s, err := newSink(token, Observation{Kind: "absolute-URI", Target: "probe.invalid:80"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s)
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	proxyURL.User = url.UserPassword("probe", token)
	endpoint := strings.TrimPrefix(server.URL, "http://")
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: guardDial(endpoint)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("http://probe.invalid/private-path?secret=never-record")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 502 || len(s.observations()) != 1 {
		t.Fatal("authenticated intended request not observed")
	}
	raw, _ := json.Marshal(s.observations())
	for _, secret := range []string{token, "private-path", "secret", "never-record"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("observation leaked input")
		}
	}
	for _, proxy := range []func(*http.Request) (*url.URL, error){nil, func(*http.Request) (*url.URL, error) { return nil, nil }} {
		safe := &http.Transport{Proxy: proxy, DialContext: guardDial(endpoint)}
		_, err := (&http.Client{Transport: safe, Timeout: time.Second}).Get("http://probe.invalid/path")
		safe.CloseIdleConnections()
		if err == nil {
			t.Fatal("missing proxy or bypass unexpectedly dialed")
		}
	}
	for _, tc := range []struct{ name, auth, target string }{{"unrelated process", "", "http://probe.invalid/"}, {"wrong secret", "Basic wrong", "http://probe.invalid/"}, {"startup telemetry", s.authorization, "http://telemetry.invalid/"}, {"origin form", s.authorization, "/local"}} {
		req := httptest.NewRequest(http.MethodGet, tc.target, nil)
		req.Header.Set("Proxy-Authorization", tc.auth)
		before := len(s.observations())
		s.ServeHTTP(httptest.NewRecorder(), req)
		if len(s.observations()) != before {
			t.Fatalf("attributed %s", tc.name)
		}
	}
	for _, raw := range []string{"user:password@host:443", "host:443/path", "host:443?secret=x", "host:443#secret", "host:99999", "host:0", "bad_host:443"} {
		if authority(raw, "") != "" {
			t.Fatal("unsafe authority accepted")
		}
	}
}

func TestConnectAndBodyAreNotForwarded(t *testing.T) {
	token := strings.Repeat("b", 64)
	s, err := newSink(token, Observation{Kind: "CONNECT", Target: "probe.invalid:443"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s)
	defer server.Close()
	conn, err := guardDial(strings.TrimPrefix(server.URL, "http://"))(context.Background(), "tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err = io.WriteString(conn, "CONNECT probe.invalid:443 HTTP/1.1\r\nHost: probe.invalid:443\r\nProxy-Authorization: "+s.authorization+"\r\nContent-Length: 100000\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 512)
	n, err := conn.Read(data)
	if err != nil || !strings.Contains(string(data[:n]), "502") || len(s.observations()) != 1 {
		t.Fatalf("sink waited for body or tunneled: %v", err)
	}
}

func TestHostedDigestIdentityRoundTrip(t *testing.T) {
	req := request()
	policy, _ := approved(t, req)
	result, err := Lookup(context.Background(), req, policy)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.BoundIdentity()
	if err != nil {
		t.Fatal(err)
	}
	file, err := netprofile.Parse([]byte("schema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := file.Lookup("direct")
	carrier := hosted.Carrier{Schema: hosted.Schema, SchemaVersion: hosted.SchemaVersion, Ref: "direct", Origin: hosted.OriginExplicit, ExpectedDigest: netprofile.Digest(profile)}
	opts := hosted.Options{OperatorHome: t.TempDir(), Identity: id,
		LoadCatalog: func(context.Context, string) (*catalog.Catalog, error) { return &catalog.Catalog{File: file}, nil },
		LoadLedger: func(context.Context, string) (resolve.Confirmations, error) {
			return fixtureConfirmation{digest: carrier.ExpectedDigest}, nil
		},
		VerifyAdapter: func(ctx context.Context, tuple binding.AdapterIdentity, _ string) error {
			_, err := Lookup(ctx, req, policy)
			if tuple != id {
				return errors.New("wrong tuple")
			}
			return err
		},
	}
	fresh, record, err := hosted.ResolveForHost(context.Background(), carrier, opts)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var restored binding.Record
	if err = json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if err = hosted.CheckReattach(restored, fresh); err != nil {
		t.Fatal(err)
	}
	restored.AdapterIdentity.Build = "legacy-version"
	if err = hosted.CheckReattach(restored, fresh); err == nil {
		t.Fatal("legacy identity silently migrated")
	}
}

type fixtureConfirmation struct{ digest string }

func (c fixtureConfirmation) Confirmed(_ string, digest string) bool { return digest == c.digest }
