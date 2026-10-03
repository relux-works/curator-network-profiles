// SPDX-License-Identifier: Apache-2.0

package catalog_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/catalog"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

const doc = "schema = \"relux-network-profiles-v1\"\n[networks.egress-a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:18081\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n"

func TestLoadAbsentUnconfirmedAndConfirmed(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	env := []string{"HOME=" + home, "HTTPS_PROXY=http://127.0.0.1:18081", "TASK_BOARD_NETWORK=egress-a"}
	c, err := catalog.Load(env)
	if err != nil || c.File != nil {
		t.Fatalf("absent: %+v %v", c, err)
	}
	res, err := c.Resolve(resolve.Request{})
	if err != nil || res.Managed {
		t.Fatalf("absent catalog without selection: %+v %v", res, err)
	}
	if _, err := c.Resolve(resolve.Request{Explicit: "egress-a"}); err == nil {
		t.Fatal("selection against an absent catalog succeeded")
	} else if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileUnknown {
		t.Fatalf("code = %s", code)
	}

	dir := filepath.Join(home, ".curator")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "network.toml"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = catalog.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Resolve(resolve.Request{Explicit: "egress-a"}); err == nil {
		t.Fatal("unconfirmed profile resolved")
	} else if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileDenied {
		t.Fatalf("code = %s", code)
	}
	if _, _, ok := c.ConfirmedAt("egress-a"); ok {
		t.Fatal("ConfirmedAt on an unconfirmed profile")
	}
	p, _ := c.File.Lookup("egress-a")
	ledger := `{"schema":"relux-network-confirmations-v1","confirmed":{"egress-a":{"digest":"` + netprofile.Digest(p) + `","confirmed_at":"2026-10-01T12:00:00Z"}}}`
	if err := os.WriteFile(filepath.Join(dir, "network.confirmations.json"), []byte(ledger), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = catalog.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	res, err = c.Resolve(resolve.Request{Explicit: "egress-a"})
	if err != nil || !res.Managed || res.Digest != netprofile.Digest(p) {
		t.Fatalf("confirmed resolve: %+v %v", res, err)
	}
	res, err = c.Resolve(resolve.Request{Inherited: " egress-a "})
	if err != nil || !res.Managed || res.Selection.Origin != resolve.OriginInherited || res.Digest != netprofile.Digest(p) {
		t.Fatalf("inherited catalog resolution: %+v %v", res, err)
	}
	ambient, err := c.Resolve(resolve.Request{})
	if err != nil || ambient.Managed {
		t.Fatalf("environment inferred a selection: %+v %v", ambient, err)
	}
	if d, at, ok := c.ConfirmedAt("egress-a"); !ok || d != res.Digest || at.IsZero() {
		t.Fatalf("ConfirmedAt = %s %v %v", d, at, ok)
	}
	var nilCat *catalog.Catalog
	if nilCat.Confirmed("egress-a", res.Digest) {
		t.Fatal("nil catalog confirmed")
	}
	if r, err := nilCat.Resolve(resolve.Request{}); err != nil || r.Managed {
		t.Fatal("nil catalog resolve")
	}
}

func TestLoadRefusals(t *testing.T) {
	t.Parallel()
	if _, err := catalog.Load(nil); err == nil {
		t.Fatal("no HOME accepted")
	} else if code, _ := refusal.CodeOf(err); code != refusal.CodeFileUnreadable {
		t.Fatalf("code = %s", code)
	}
	home := t.TempDir()
	dir := filepath.Join(home, ".curator")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "network.toml"), []byte("schema = \"relux-network-profiles-v1\"\nx = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Load([]string{"HOME=" + home}); err == nil {
		t.Fatal("invalid catalog loaded")
	} else if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileInvalid {
		t.Fatalf("code = %s", code)
	}
	if err := os.WriteFile(filepath.Join(dir, "network.toml"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "network.confirmations.json"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Load([]string{"HOME=" + home}); err == nil {
		t.Fatal("broken ledger loaded")
	} else if code, _ := refusal.CodeOf(err); code != refusal.CodeFileUnreadable {
		t.Fatalf("code = %s", code)
	}
}
