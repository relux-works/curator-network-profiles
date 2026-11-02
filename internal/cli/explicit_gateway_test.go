// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Read-only provider commands expose a false gateway without changing its
// catalog or confirmation. Both generic execution forms still refuse before
// any workload or probe, as with the existing sensitive gateway control.
func TestExplicitFalseGatewayCLI(t *testing.T) {
	h := newHarness(t)
	doc := strings.Replace(gatewayCatalog, "sensitive_egress = true", "sensitive_egress = false", 1)
	h.writeFile(doc)
	h.confirmDoc(doc)
	catalog := filepath.Join(h.home, ".curator", "network.toml")
	ledger := filepath.Join(h.home, ".curator", "network.confirmations.json")
	before, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"list", "--json"}, {"show", "secret-filter"}, {"show", "secret-filter", "--json"}, {"check", "secret-filter", "--json"}, {"check", "secret-filter", "--probe", "--json"}} {
		code, out, diag := h.run(args...)
		if code != 0 || !strings.Contains(out, "secret-filter") {
			t.Fatalf("read-only command %v refused: %d %s", args, code, diag)
		}
		if len(args) == 2 && args[0] == "show" && !strings.Contains(out, "sensitive_egress: false") {
			t.Fatal("human readback obscures the gateway sensitivity")
		}
	}
	for _, args := range [][]string{{"exec", "secret-filter", "--", "tool"}, {"exec", "secret-filter", "--dry-run", "--json", "--", "tool"}} {
		code, out, diag := h.run(args...)
		if code == 0 || !strings.Contains(out+diag, "network_scope_unsupported") {
			t.Fatalf("generic gateway execution admitted: %d %s", code, out+diag)
		}
	}
	got, err := os.ReadFile(catalog)
	if err != nil || string(got) != doc {
		t.Fatal("read-only operations changed the catalog")
	}
	after, err := os.ReadFile(ledger)
	if err != nil || !bytes.Equal(before, after) || len(h.exec.calls) != 0 {
		t.Fatal("operation changed confirmation or launched a workload")
	}
	if _, err := os.Lstat(catalog + ".lock"); !os.IsNotExist(err) {
		t.Fatal("read-only operation left a catalog lock")
	}
}
