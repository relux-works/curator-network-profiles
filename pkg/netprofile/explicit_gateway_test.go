// SPDX-License-Identifier: Apache-2.0

package netprofile_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

// Explicit false is a distinct gateway contract; its canonical bytes are
// independently specified here, while the existing true encoding stays stable.
func TestGatewayExplicitSensitivity(t *testing.T) {
	for _, sensitive := range []bool{true, false} {
		t.Run(fmt.Sprint(sensitive), func(t *testing.T) {
			doc := gatewayHead + fmt.Sprintf("control = %q\nsensitive_egress = %t\n", "/run/netproxy/control.sock", sensitive)
			file, err := netprofile.Parse([]byte(doc))
			if err != nil {
				t.Fatalf("explicit %t gateway must be admitted: %v", sensitive, err)
			}
			p, ok := file.Lookup("secret-filter")
			want := fmt.Sprintf(`{"control":"/run/netproxy/control.sock","credential_mode":"none","kind":"filtering-gateway","schema":"relux-network-profiles-v1","sensitive_egress":%t}`, sensitive)
			if !ok || p.SensitiveEgress != sensitive || string(netprofile.Canonical(p)) != want || netprofile.Digest(p) != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(want))) {
				t.Fatalf("explicit declaration or independently specified digest changed: %+v", p)
			}
		})
	}
}

// An explicit-false gateway cannot enter a catalog through an automatic
// default or binding. True remains a valid control for both placements.
func TestGatewayAutomaticCatalogSelections(t *testing.T) {
	for _, placement := range []string{"default = \"secret-filter\"\n", "[bindings.profiles]\nwork = \"secret-filter\"\n"} {
		for _, sensitive := range []bool{true, false} {
			doc := "schema = \"relux-network-profiles-v1\"\n" + placement + strings.TrimPrefix(gatewayHead, "schema = \"relux-network-profiles-v1\"\n") + fmt.Sprintf("control = \"/run/netproxy/control.sock\"\nsensitive_egress = %t\n", sensitive)
			file, err := netprofile.Parse([]byte(doc))
			if sensitive {
				if err != nil || file == nil {
					t.Fatalf("existing sensitive automatic selection refused: %v", err)
				}
			} else if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileInvalid || file != nil {
				t.Fatalf("non-sensitive automatic selection admitted or partially decoded: %v", err)
			}
		}
	}
}

// The public normalization API preserves explicit false intent; a zero-valued
// boolean remains an omitted declaration and cannot silently widen a gateway.
func TestGatewayNormalizeRequiresExplicitIntent(t *testing.T) {
	in := netprofile.Input{Kind: netprofile.KindFilteringGateway, Control: "/run/netproxy/control.sock"}
	_, err := netprofile.Normalize("gateway", in)
	if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileInvalid {
		t.Fatal("omitted programmatic gateway declaration was admitted")
	}
	in.SensitiveEgressSet = true
	p, err := netprofile.Normalize("gateway", in)
	if err != nil || p.SensitiveEgress {
		t.Fatalf("explicit programmatic false declaration lost: %v", err)
	}
	in.SensitiveEgress = true
	in.SensitiveEgressSet = false
	if p, err = netprofile.Normalize("gateway", in); err != nil || !p.SensitiveEgress {
		t.Fatalf("existing true-valued caller changed: %v", err)
	}
}
