// SPDX-License-Identifier: Apache-2.0

package netprofile_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

const gatewayHead = "schema = \"relux-network-profiles-v1\"\n[networks.secret-filter]\nkind = \"filtering-gateway\"\n"

// A filtering-gateway profile carries only its control socket and the
// mandatory sensitive egress; the gateway hands out endpoints per launch,
// so every endpoint-shaped key is refused, and so is a missing, relative,
// unclean or oversized control path. The first case is the valid control.
func TestFilteringGatewayProfile(t *testing.T) {
	const control = `control = "/Users/op/Library/netproxy/control.sock"` + "\n"
	const sensitive = "sensitive_egress = true\n"
	for _, tc := range []struct {
		name, fields string
		valid        bool
	}{
		{"control and sensitive egress", control + sensitive, true},
		{"no control", sensitive, false},
		{"empty control", `control = ""` + "\n" + sensitive, false},
		{"relative control", `control = "netproxy/control.sock"` + "\n" + sensitive, false},
		{"trailing slash", `control = "/run/netproxy/"` + "\n" + sensitive, false},
		{"dot segment", `control = "/run/./netproxy/control.sock"` + "\n" + sensitive, false},
		{"dot-dot segment", `control = "/run/../netproxy/control.sock"` + "\n" + sensitive, false},
		{"double slash", `control = "/run//control.sock"` + "\n" + sensitive, false},
		{"root", `control = "/"` + "\n" + sensitive, false},
		{"surrounding space", `control = " /run/control.sock"` + "\n" + sensitive, false},
		{"NUL", `control = "/run/con\u0000trol.sock"` + "\n" + sensitive, false},
		{"over socket limit", `control = "/` + strings.Repeat("a", netprofile.MaxControlPath) + `"` + "\n" + sensitive, false},
		{"no sensitive egress", control, false},
		{"sensitive egress false", control + "sensitive_egress = false\n", false},
		{"endpoint", control + sensitive + `endpoint = "http://127.0.0.1:47811"` + "\n", false},
		{"empty endpoint", control + sensitive + `endpoint = ""` + "\n", false},
		{"bypass", control + sensitive + `bypass_hosts = ["localhost", "127.0.0.1", "::1"]` + "\n", false},
		{"empty bypass", control + sensitive + "bypass_hosts = []\n", false},
		{"probe", control + sensitive + `probe_target = "api.anthropic.com:443"` + "\n", false},
		{"case-folded control key", `Control = "/run/control.sock"` + "\n" + sensitive, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := netprofile.Parse([]byte(gatewayHead + tc.fields))
			if !tc.valid {
				if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileInvalid {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p, _ := f.Lookup("secret-filter")
			if p.Kind != netprofile.KindFilteringGateway || p.Control != "/Users/op/Library/netproxy/control.sock" || !p.SensitiveEgress ||
				p.Endpoint != "" || p.BypassHosts != nil || p.ProbeTarget != "" || p.CredentialMode != "none" {
				t.Fatalf("profile = %+v", p)
			}
		})
	}
}

// The longest admitted control path fits a unix socket address; one byte
// more is the "over socket limit" case above.
func TestFilteringGatewayControlBoundary(t *testing.T) {
	path := "/" + strings.Repeat("a", netprofile.MaxControlPath-1)
	if _, err := netprofile.NormalizeControl(path); err != nil {
		t.Fatalf("%d-byte path refused: %v", len(path), err)
	}
	if _, err := netprofile.NormalizeControl(path + "a"); err == nil {
		t.Fatal("over-limit path admitted")
	}
}

// The digest covers kind, control and sensitive egress in the appendix
// encoding, never the name; a different control path changes it.
func TestFilteringGatewayDigest(t *testing.T) {
	p, err := netprofile.Normalize("secret-filter", netprofile.Input{Kind: netprofile.KindFilteringGateway, Control: "/run/netproxy/control.sock", SensitiveEgress: true})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"control":"/run/netproxy/control.sock","credential_mode":"none","kind":"filtering-gateway","schema":"relux-network-profiles-v1","sensitive_egress":true}`
	if got := string(netprofile.Canonical(p)); got != want {
		t.Fatalf("canonical = %s", got)
	}
	sum := sha256.Sum256([]byte(want))
	if netprofile.Digest(p) != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("digest = %s", netprofile.Digest(p))
	}
	renamed := p
	renamed.Name = "another"
	if netprofile.Digest(renamed) != netprofile.Digest(p) {
		t.Fatal("name changed the digest")
	}
	moved := p
	moved.Control = "/run/netproxy/other.sock"
	if netprofile.Digest(moved) == netprofile.Digest(p) {
		t.Fatal("control path is not digested")
	}
}

// control belongs to filtering-gateway only: the other kinds refuse it,
// even empty, from the file and through Normalize. Their valid forms
// without control are the controls of direct_test.go and profile_test.go.
func TestControlOnOtherKinds(t *testing.T) {
	for _, doc := range []string{
		"schema = \"relux-network-profiles-v1\"\n[networks.d]\nkind = \"direct\"\ncontrol = \"/run/c.sock\"\n",
		"schema = \"relux-network-profiles-v1\"\n[networks.d]\nkind = \"direct\"\ncontrol = \"\"\n",
		"schema = \"relux-network-profiles-v1\"\n[networks.e]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:3128\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\ncontrol = \"/run/c.sock\"\n",
		"schema = \"relux-network-profiles-v1\"\n[networks.e]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:3128\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\ncontrol = \"\"\n",
	} {
		if _, err := netprofile.Parse([]byte(doc)); err == nil {
			t.Fatalf("admitted:\n%s", doc)
		}
	}
	for _, in := range []netprofile.Input{
		{Kind: netprofile.KindDirect, Control: "/run/c.sock"},
		{Kind: netprofile.KindExternalHTTPProxy, Endpoint: "http://127.0.0.1:3128", BypassHosts: netprofile.RequiredBypassHosts, Control: "/run/c.sock"},
	} {
		if _, err := netprofile.Normalize("x", in); err == nil {
			t.Fatalf("admitted %+v", in)
		}
	}
}

// Normalize, the public entry that callers use without a file, applies the
// same filtering-gateway rules as Parse; the first input is the control.
func TestFilteringGatewayNormalize(t *testing.T) {
	base := netprofile.Input{Kind: netprofile.KindFilteringGateway, Control: "/run/c.sock", SensitiveEgress: true}
	if _, err := netprofile.Normalize("g", base); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*netprofile.Input){
		"endpoint":     func(in *netprofile.Input) { in.Endpoint = "http://127.0.0.1:47811" },
		"bypass":       func(in *netprofile.Input) { in.BypassHosts = netprofile.RequiredBypassHosts },
		"probe target": func(in *netprofile.Input) { in.ProbeTarget = "api.anthropic.com:443" },
		"no sensitive": func(in *netprofile.Input) { in.SensitiveEgress = false },
		"no control":   func(in *netprofile.Input) { in.Control = "" },
	} {
		in := base
		mutate(&in)
		if _, err := netprofile.Normalize("g", in); err == nil {
			t.Fatalf("%s admitted", name)
		}
	}
}
