// SPDX-License-Identifier: Apache-2.0

package resolve_test

import (
	"fmt"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

func gatewayFile(t *testing.T, sensitive bool) *netprofile.File {
	t.Helper()
	f, err := netprofile.Parse([]byte(fmt.Sprintf("schema = \"relux-network-profiles-v1\"\n[networks.gateway]\nkind = \"filtering-gateway\"\ncontrol = \"/run/netproxy/control.sock\"\nsensitive_egress = %t\n", sensitive)))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// Each non-explicit origin refuses a false gateway before confirmation is
// consulted, including inheritance used by retry/resume callers. The same
// origins still resolve a true gateway; explicit false is the positive control.
func TestGatewayExplicitSelectionOnly(t *testing.T) {
	for _, origin := range []string{"explicit", "inherited", "runtime", "binding", "project", "operator"} {
		for _, sensitive := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", origin, sensitive), func(t *testing.T) {
				f := gatewayFile(t, sensitive)
				req := resolve.Request{}
				switch origin {
				case "explicit":
					req.Explicit = "gateway"
				case "inherited":
					req.Inherited = "gateway"
				case "runtime":
					req.RuntimeDefault = "gateway"
				case "binding":
					req.CuratorProfile = "work"
					f.Bindings.Profiles = map[string]string{"work": "gateway"}
				case "project":
					req.ProjectDefault = "gateway"
				case "operator":
					f.Default = "gateway"
				}
				confirmations := 0
				result, err := resolve.Resolve(f, resolve.ConfirmedFunc(func(string, string) bool { confirmations++; return true }), req)
				if !sensitive && origin != "explicit" {
					if code, _ := refusal.CodeOf(err); code != refusal.CodeScopeUnsupported || result != nil || confirmations != 0 {
						t.Fatalf("implicit gateway admitted or reached confirmation: result=%v err=%v calls=%d", result, err, confirmations)
					}
					return
				}
				if err != nil || result == nil || !result.Managed || result.Profile.SensitiveEgress != sensitive || confirmations != 1 {
					t.Fatalf("valid selection refused: result=%v err=%v calls=%d", result, err, confirmations)
				}
			})
		}
	}
}

// Changing true to false at the same name/socket changes the digest. Its
// prior confirmation cannot authorize the new route; a fresh one can.
func TestGatewaySensitivityRequiresNewConfirmation(t *testing.T) {
	old := gatewayFile(t, true)
	f := gatewayFile(t, false)
	prior := netprofile.Digest(old.Networks["gateway"])
	current := netprofile.Digest(f.Networks["gateway"])
	if prior == current {
		t.Fatal("sensitivity change reused the digest")
	}
	for _, confirmed := range []string{prior, current} {
		result, err := resolve.Resolve(f, resolve.ConfirmedFunc(func(name, digest string) bool { return name == "gateway" && digest == confirmed }), resolve.Request{Explicit: "gateway"})
		if confirmed == prior {
			if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileDenied || result != nil {
				t.Fatalf("stale confirmation admitted: %v", err)
			}
		} else if err != nil || result == nil || result.Digest != current {
			t.Fatalf("fresh confirmation refused: %v", err)
		}
	}
}
