// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/internal/store"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
)

// The provider writer preserves the explicit gateway boolean and digest
// across a real fixture write/read; false must never be rendered as true.
func TestGatewaySensitivityRoundTrip(t *testing.T) {
	for _, sensitive := range []bool{true, false} {
		t.Run(fmt.Sprint(sensitive), func(t *testing.T) {
			p := paths(t)
			prof, err := netprofile.Normalize("gateway", netprofile.Input{Kind: netprofile.KindFilteringGateway, Control: "/run/netproxy/control.sock", SensitiveEgress: sensitive, SensitiveEgressSet: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Add(p, prof); err != nil {
				t.Fatal(err)
			}
			f, raw, err := store.Read(p)
			if err != nil || f == nil {
				t.Fatalf("round-trip failed: %v", err)
			}
			got := f.Networks["gateway"]
			if got.SensitiveEgress != sensitive || netprofile.Digest(got) != netprofile.Digest(prof) || !strings.Contains(string(raw), fmt.Sprintf("sensitive_egress = %t\n", sensitive)) {
				t.Fatalf("writer changed gateway intent or digest: %s", raw)
			}
		})
	}
}
