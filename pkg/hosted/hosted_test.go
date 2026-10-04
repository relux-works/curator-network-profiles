// SPDX-License-Identifier: Apache-2.0

package hosted_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/curator-network-profiles/internal/testproxy"
	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/catalog"
	"github.com/relux-works/curator-network-profiles/pkg/envpatch"
	"github.com/relux-works/curator-network-profiles/pkg/hosted"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/probe"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

var testIdentity = binding.AdapterIdentity{Adapter: envpatch.AdapterGeneric, Harness: "test-harness", Build: "test-build", Entrypoint: "test-hosted"}

type proberFunc func(context.Context, probe.Request) (probe.Result, error)

func (f proberFunc) Probe(ctx context.Context, req probe.Request) (probe.Result, error) {
	return f(ctx, req)
}

func fixture(t *testing.T, kind, endpoint, target string) (hosted.Carrier, hosted.Options) {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".curator")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	doc := "schema = \"relux-network-profiles-v1\"\ndefault = \"other\"\n[networks.other]\nkind = \"direct\"\n[networks.egress-a]\nkind = " + fmt.Sprintf("%q\n", kind)
	if kind != netprofile.KindDirect {
		doc += fmt.Sprintf("endpoint = %q\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n", endpoint)
		if target != "" {
			doc += fmt.Sprintf("probe_target = %q\n", target)
		}
	}
	f, err := netprofile.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := f.Lookup("egress-a")
	c := carrier()
	c.ExpectedDigest = netprofile.Digest(p)
	writeFile(t, filepath.Join(dir, "network.toml"), []byte(doc))
	ledger := `{"schema":"relux-network-confirmations-v1","confirmed":{"egress-a":{"digest":"` + c.ExpectedDigest + `","confirmed_at":"2026-10-04T00:00:00Z"}}}`
	writeFile(t, filepath.Join(dir, "network.confirmations.json"), []byte(ledger))
	return c, hosted.Options{OperatorHome: home, Identity: testIdentity,
		VerifyAdapter: func(_ context.Context, id binding.AdapterIdentity, assurance string) error {
			if id != testIdentity || assurance != binding.AssuranceCooperative {
				return errors.New("unsupported test tuple")
			}
			return nil
		}, EngineHosts: []string{"localhost", "127.0.0.1", "[::1]:11434"}}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveForHostOriginsAndDirect(t *testing.T) {
	for _, kind := range []string{netprofile.KindExternalHTTPProxy, netprofile.KindDirect} {
		t.Run(kind, func(t *testing.T) {
			c, opts := fixture(t, kind, "http://127.0.0.1:18081", "")
			opts.Prober = proberFunc(func(context.Context, probe.Request) (probe.Result, error) {
				t.Fatal("forbidden probe")
				return probe.Result{}, nil
			})
			if kind == netprofile.KindDirect {
				opts.Preflight = true
			}
			for origin, want := range map[hosted.Origin]string{
				hosted.OriginExplicit: "explicit", hosted.OriginInherited: "inherited", hosted.OriginRuntime: "runtime-default", hosted.OriginProject: "project-default", hosted.OriginOperator: "operator-default",
			} {
				c.Origin = origin
				b, r, err := hosted.ResolveForHost(context.Background(), c, opts)
				if err != nil {
					t.Fatal(err)
				}
				if b.ProfileRef != c.Ref || r.ProfileRef != c.Ref || r.Origin != want || r.Schema != binding.SchemaRecord || b.ProfileDigest != c.ExpectedDigest || b.AdapterIdentity != testIdentity || b.Assurance != binding.AssuranceCooperative {
					t.Fatalf("binding/record = %+v %+v", b, r)
				}
				if r.Probe.TCP != "skipped" || r.Probe.Connect != "skipped" || r.Probe.TLS != "skipped" || !r.Probe.CheckedAt.IsZero() {
					t.Fatalf("probe = %+v", r.Probe)
				}
				if kind == netprofile.KindDirect {
					if b.ResolvedEndpoint != "" || len(b.EnvPatch.Set) != 0 || b.EnvPatch.Empty() {
						t.Fatalf("direct binding = %+v", b)
					}
					if got := hosted.ApplyFinal([]string{"PATH=/bin", "HtTp_PrOxY=old", "NO_PROXY=*"}, b); !reflect.DeepEqual(got, []string{"PATH=/bin"}) {
						t.Fatalf("direct env = %v", got)
					}
				}
			}
		})
	}
}

func TestResolveRefusalsPrecedeProbe(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		change     func(*testing.T, *hosted.Carrier, *hosted.Options)
	}{
		{"unknown", refusal.CodeProfileUnknown, func(_ *testing.T, c *hosted.Carrier, _ *hosted.Options) { c.Ref = "missing" }},
		{"allowlist denied", refusal.CodeProfileDenied, func(_ *testing.T, _ *hosted.Carrier, o *hosted.Options) { o.Allowlist = []string{} }},
		{"revoked confirmation", refusal.CodeProfileDenied, func(t *testing.T, _ *hosted.Carrier, o *hosted.Options) {
			writeFile(t, filepath.Join(o.OperatorHome, ".curator/network.confirmations.json"), []byte(`{"schema":"relux-network-confirmations-v1"}`))
		}},
		{"stale confirmation", refusal.CodeProfileDenied, func(t *testing.T, _ *hosted.Carrier, o *hosted.Options) {
			path := filepath.Join(o.OperatorHome, ".curator/network.toml")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, []byte(strings.ReplaceAll(string(data), "18081", "18082")))
		}},
		{"expected drift", refusal.CodeProfileDrift, func(_ *testing.T, c *hosted.Carrier, _ *hosted.Options) {
			c.ExpectedDigest = "sha256:" + strings.Repeat("a", 64)
		}},
		{"enforced", refusal.CodeScopeUnsupported, func(_ *testing.T, _ *hosted.Carrier, o *hosted.Options) {
			o.RequiredAssurance = binding.AssuranceEnforced
		}},
		{"missing verifier", refusal.CodeScopeUnsupported, func(_ *testing.T, _ *hosted.Carrier, o *hosted.Options) { o.VerifyAdapter = nil }},
		{"different build", refusal.CodeScopeUnsupported, func(_ *testing.T, _ *hosted.Carrier, o *hosted.Options) { o.Identity.Build = "different" }},
		{"adapter identity mismatch", refusal.CodeScopeUnsupported, func(_ *testing.T, _ *hosted.Carrier, o *hosted.Options) { o.Identity.Adapter = "other-adapter" }},
		{"empty build", refusal.CodeScopeUnsupported, func(_ *testing.T, _ *hosted.Carrier, o *hosted.Options) { o.Identity.Build = "" }},
		{"identity URL", refusal.CodeScopeUnsupported, func(_ *testing.T, _ *hosted.Carrier, o *hosted.Options) {
			o.Identity.Entrypoint = "http://secret.invalid:1"
		}},
		{"engine bypass", refusal.CodeConfigurationConflict, func(_ *testing.T, _ *hosted.Carrier, o *hosted.Options) { o.EngineHosts = []string{"secret.invalid"} }},
		{"env name", refusal.CodeConfigurationConflict, func(_ *testing.T, _ *hosted.Carrier, o *hosted.Options) { o.EnvNames = []string{"hTtPs_PrOxY"} }},
		{"relative home", refusal.CodeFileUnreadable, func(_ *testing.T, _ *hosted.Carrier, o *hosted.Options) { o.OperatorHome = "relative" }},
		{"absent home", refusal.CodeFileUnreadable, func(_ *testing.T, _ *hosted.Carrier, o *hosted.Options) { o.OperatorHome = "" }},
		{"broken catalog", refusal.CodeProfileInvalid, func(t *testing.T, _ *hosted.Carrier, o *hosted.Options) {
			writeFile(t, filepath.Join(o.OperatorHome, ".curator/network.toml"), []byte("schema = \"wrong\"\n"))
		}},
		{"broken ledger", refusal.CodeFileUnreadable, func(t *testing.T, _ *hosted.Carrier, o *hosted.Options) {
			writeFile(t, filepath.Join(o.OperatorHome, ".curator/network.confirmations.json"), []byte("broken"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, opts := fixture(t, netprofile.KindExternalHTTPProxy, "http://127.0.0.1:18081", "")
			opts.Preflight = true
			opts.Prober = proberFunc(func(context.Context, probe.Request) (probe.Result, error) {
				t.Fatal("refusal reached probe")
				return probe.Result{}, nil
			})
			tc.change(t, &c, &opts)
			b, r, err := hosted.ResolveForHost(context.Background(), c, opts)
			requireCode(t, err, tc.code)
			if !reflect.DeepEqual(b, binding.Binding{}) || r != (binding.Record{}) {
				t.Fatal("refusal returned partial binding or record")
			}
			if strings.Contains(err.Error(), "secret.invalid") || strings.Contains(err.Error(), opts.OperatorHome+"/") {
				t.Fatal("refusal leaked host material")
			}
		})
	}
}

func TestResolveDriftWithFreshConfirmation(t *testing.T) {
	c, opts := fixture(t, netprofile.KindExternalHTTPProxy, "http://127.0.0.1:18081", "")
	cat, err := catalog.Load([]string{"HOME=" + opts.OperatorHome})
	if err != nil {
		t.Fatal(err)
	}
	p := cat.File.Networks[c.Ref]
	p.Endpoint = "http://127.0.0.1:18082"
	cat.File.Networks[c.Ref] = p
	opts.LoadCatalog = func(context.Context, string) (*catalog.Catalog, error) { return cat, nil }
	opts.LoadLedger = func(context.Context, string) (resolve.Confirmations, error) {
		return resolve.ConfirmedFunc(func(name, digest string) bool { return name == c.Ref && digest == netprofile.Digest(p) }), nil
	}
	_, _, err = hosted.ResolveForHost(context.Background(), c, opts)
	requireCode(t, err, refusal.CodeProfileDrift)
}

func TestInjectedBoundariesAndCancellation(t *testing.T) {
	c, opts := fixture(t, netprofile.KindDirect, "", "")
	calls := 0
	opts.LoadCatalog = func(_ context.Context, home string) (*catalog.Catalog, error) {
		calls++
		if home != opts.OperatorHome {
			t.Fatal("wrong operator HOME")
		}
		return catalog.Load([]string{"HOME=" + home})
	}
	invalid := c
	invalid.Ref = "http://secret.invalid"
	_, _, err := hosted.ResolveForHost(context.Background(), invalid, opts)
	requireCode(t, err, refusal.CodeConfigurationConflict)
	if calls != 0 {
		t.Fatal("malformed carrier reached loader")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = hosted.ResolveForHost(ctx, c, opts)
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("cancelled request: %v calls=%d", err, calls)
	}
	opts.LoadLedger = func(context.Context, string) (resolve.Confirmations, error) {
		return nil, errors.New("CANARY http://user:pass@secret.invalid:1")
	}
	_, _, err = hosted.ResolveForHost(context.Background(), c, opts)
	requireCode(t, err, refusal.CodeFileUnreadable)
	if strings.Contains(err.Error(), "CANARY") {
		t.Fatal("loader diagnostic leaked")
	}
	opts.LoadCatalog = func(context.Context, string) (*catalog.Catalog, error) { return nil, nil }
	_, _, err = hosted.ResolveForHost(context.Background(), c, opts)
	requireCode(t, err, refusal.CodeFileUnreadable)
}

func TestProbeRecordSanitizedAndBounded(t *testing.T) {
	c, opts := fixture(t, netprofile.KindExternalHTTPProxy, "http://127.0.0.1:18081", "")
	opts.Preflight = true
	opts.ProbeTimeout = time.Hour
	checked := time.Date(2026, 10, 4, 0, 0, 0, 0, time.FixedZone("CANARY", 3600))
	calls := 0
	opts.Prober = proberFunc(func(ctx context.Context, req probe.Request) (probe.Result, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 30*time.Second || req.Timeout != 30*time.Second || req.Subject != c.Ref || req.Endpoint != "http://127.0.0.1:18081" || req.Target != "" {
			t.Fatalf("probe request: %+v deadline=%v", req, deadline)
		}
		return probe.Result{Endpoint: "http://CANARY-ENDPOINT.invalid:1234", Target: "CANARY-TARGET.invalid:443", Detail: "CANARY-DETAIL", TCP: probe.StatusOK, Connect: "CANARY-STATUS", TLS: probe.StatusSkipped, CheckedAt: checked}, nil
	})
	b, r, err := hosted.ResolveForHost(context.Background(), c, opts)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"CANARY", b.ResolvedEndpoint, "endpoint", "target", "env_patch", "connect_status", "detail"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("record leaked %s: %s", secret, data)
		}
	}
	if calls != 1 || r.Probe.Connect != "failed" || r.Probe.TCP != "ok" || !r.Probe.CheckedAt.Equal(checked) || r.Probe.CheckedAt.Location() != time.UTC {
		t.Fatalf("probe record: %+v calls=%d", r.Probe, calls)
	}
	opts.Prober = proberFunc(func(context.Context, probe.Request) (probe.Result, error) {
		return probe.Result{}, errors.New("CANARY http://secret.invalid:1")
	})
	_, _, err = hosted.ResolveForHost(context.Background(), c, opts)
	requireCode(t, err, refusal.CodeProxyUnreachable)
	if strings.Contains(err.Error(), "CANARY") {
		t.Fatal("raw prober error leaked")
	}
	opts.Prober = proberFunc(func(context.Context, probe.Request) (probe.Result, error) { return probe.Result{}, nil })
	_, _, err = hosted.ResolveForHost(context.Background(), c, opts)
	requireCode(t, err, refusal.CodeProxyUnreachable)
}

func TestLoopbackPreflight(t *testing.T) {
	up, err := testproxy.StartTLSUpstream(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "probe.invalid")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(up.Close)
	for _, tc := range []struct {
		name, target, code string
		proxy              testproxy.Options
		verifiedTLS        bool
	}{
		{"tcp only", "", "", testproxy.Options{}, false},
		{"auth 407", "probe.invalid:443", refusal.CodeProxyAuthFailed, testproxy.Options{RequireAuth: true}, false},
		{"connect 502", "probe.invalid:443", refusal.CodeProxyUnreachable, testproxy.Options{}, false},
		{"deadline", "probe.invalid:443", refusal.CodeProxyUnreachable, testproxy.Options{Hang: true}, false},
		{"verified TLS", "probe.invalid:443", "", testproxy.Options{Targets: map[string]string{"probe.invalid:443": up.Addr()}}, true},
		{"untrusted TLS", "probe.invalid:443", refusal.CodeProxyUnreachable, testproxy.Options{Targets: map[string]string{"probe.invalid:443": up.Addr()}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := testproxy.Start(tc.proxy)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.Close() })
			c, opts := fixture(t, netprofile.KindExternalHTTPProxy, p.URL(), tc.target)
			opts.Preflight = true
			opts.ProbeTimeout = time.Second
			if tc.proxy.Hang {
				opts.ProbeTimeout = 30 * time.Millisecond
			}
			if tc.verifiedTLS {
				opts.Prober = &probe.Dialer{RootCAs: up.RootCAs}
			}
			b, r, err := hosted.ResolveForHost(context.Background(), c, opts)
			if tc.code != "" {
				requireCode(t, err, tc.code)
				if !reflect.DeepEqual(b, binding.Binding{}) || r != (binding.Record{}) {
					t.Fatal("partial probe refusal")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.Probe.TCP != "ok" {
				t.Fatalf("probe: %+v", r.Probe)
			}
			if tc.target == "" && (r.Probe.Connect != "skipped" || r.Probe.TLS != "skipped" || len(p.Requests()) != 0) {
				t.Fatal("TCP-only preflight sent CONNECT")
			}
			if tc.verifiedTLS && (r.Probe.Connect != "ok" || r.Probe.TLS != "ok") {
				t.Fatalf("TLS probe: %+v", r.Probe)
			}
		})
	}
}
