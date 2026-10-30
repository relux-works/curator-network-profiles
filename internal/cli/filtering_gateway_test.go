// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/internal/confirm"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
)

const gatewayCatalog = `schema = "relux-network-profiles-v1"

[networks.secret-filter]
kind             = "filtering-gateway"
control          = "/run/netproxy/control.sock"
sensitive_egress = true
`

func (h *harness) confirmDoc(doc string) {
	h.t.Helper()
	f, err := netprofile.Parse([]byte(doc))
	if err != nil {
		h.t.Fatal(err)
	}
	l := confirm.Empty()
	for _, name := range f.Names() {
		p, _ := f.Lookup(name)
		l.Set(name, netprofile.Digest(p), h.now)
	}
	data, err := json.Marshal(l)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.home, ".curator", "network.confirmations.json"), data, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// A confirmed filtering-gateway profile is listed, shown and checked
// without any network call or generic proxy patch, and exec refuses it
// before running anything: the generic adapter would otherwise launch the
// command with no filter at all. The prober is fatal throughout.
func TestFilteringGatewayCLI(t *testing.T) {
	h := newHarness(t)
	h.writeFile(gatewayCatalog)
	h.confirmDoc(gatewayCatalog)
	h.tool("tool")
	for _, args := range [][]string{
		{"list"}, {"list", "--json"},
		{"check", "secret-filter", "--probe"}, {"check", "secret-filter", "--probe", "--json"},
		{"show", "secret-filter"}, {"show", "secret-filter", "--json"},
	} {
		code, out, diag := h.run(args...)
		if code != 0 || !strings.Contains(out, "secret-filter") {
			t.Fatalf("%v: %d %s %s", args, code, out, diag)
		}
		// The unset family may be listed; nothing is ever set.
		if strings.Contains(out, "set:   ") || strings.Contains(out, `"set":[{`) || strings.Contains(out, "PROXY=") {
			t.Fatalf("%v sets a generic proxy: %s", args, out)
		}
		if args[0] == "show" && !strings.Contains(out, "/run/netproxy/control.sock") {
			t.Fatalf("show omits control: %s", out)
		}
		if args[0] == "check" && !strings.Contains(out, "skipped") && !strings.Contains(out, "filtering-gateway") {
			t.Fatalf("check: %s", out)
		}
	}
	for _, args := range [][]string{
		{"exec", "secret-filter", "--", "tool"},
		{"exec", "secret-filter", "--json", "--", "tool"},
		{"exec", "secret-filter", "--dry-run", "--json", "--", "tool"},
	} {
		code, out, diag := h.run(args...)
		if code == 0 || !strings.Contains(out+diag, "network_scope_unsupported") {
			t.Fatalf("%v: %d %s %s", args, code, out, diag)
		}
	}
	if len(h.exec.calls) != 0 {
		t.Fatalf("exec ran %d commands", len(h.exec.calls))
	}
}
