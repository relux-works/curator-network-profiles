// SPDX-License-Identifier: Apache-2.0

package hosted_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/hosted"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/probe"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

// A hosted binding applies the generic patch, which cannot carry a
// filtering gateway, so either confirmed sensitive or non-sensitive selection refuses
// network_scope_unsupported with no probe, no adapter verification and no
// binding. TestResolveForHostOriginsAndDirect is the valid control.
func TestFilteringGatewayRefusedForHost(t *testing.T) {
	for _, sensitive := range []bool{true, false} {
		t.Run(fmt.Sprint(sensitive), func(t *testing.T) { filteringGatewayRefusedForHost(t, sensitive) })
	}
}

func filteringGatewayRefusedForHost(t *testing.T, sensitive bool) {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".curator")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	doc := fmt.Sprintf("schema = \"relux-network-profiles-v1\"\n[networks.egress-a]\nkind = \"filtering-gateway\"\ncontrol = \"/run/netproxy/control.sock\"\nsensitive_egress = %t\n", sensitive)
	f, err := netprofile.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := f.Lookup("egress-a")
	c := carrier()
	c.ExpectedDigest = netprofile.Digest(p)
	writeFile(t, filepath.Join(dir, "network.toml"), []byte(doc))
	writeFile(t, filepath.Join(dir, "network.confirmations.json"), []byte(`{"schema":"relux-network-confirmations-v1","confirmed":{"egress-a":{"digest":"`+c.ExpectedDigest+`","confirmed_at":"2026-10-04T00:00:00Z"}}}`))
	verified := false
	opts := hosted.Options{OperatorHome: home, Identity: testIdentity, Preflight: true,
		VerifyAdapter: func(context.Context, binding.AdapterIdentity, string) error {
			verified = true
			return nil
		},
		Prober: proberFunc(func(context.Context, probe.Request) (probe.Result, error) {
			t.Fatal("forbidden probe")
			return probe.Result{}, nil
		}),
	}
	b, _, err := hosted.ResolveForHost(context.Background(), c, opts)
	if code, _ := refusal.CodeOf(err); code != refusal.CodeScopeUnsupported {
		t.Fatalf("err = %v", err)
	}
	if verified || !b.EnvPatch.Empty() {
		t.Fatalf("verified=%v patch=%+v", verified, b.EnvPatch)
	}
}
