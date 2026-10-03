// SPDX-License-Identifier: Apache-2.0

package binding_test

import (
	"encoding/json"
	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/envpatch"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"strings"
	"testing"
)

func TestDirectRecordAndEquality(t *testing.T) {
	p, err := netprofile.Normalize("direct", netprofile.Input{Kind: netprofile.KindDirect})
	if err != nil {
		t.Fatal(err)
	}
	b := binding.Binding{ProfileRef: p.Name, ProfileDigest: netprofile.Digest(p), Assurance: binding.AssuranceCooperative, AdapterIdentity: binding.AdapterIdentity{Adapter: envpatch.AdapterGeneric}, EnvPatch: envpatch.Generic{}.Patch(p)}
	r := b.Record("explicit", nil)
	if r.ProfileRef != "direct" || r.ProfileDigest != netprofile.Digest(p) || r.Probe.TCP != "skipped" || r.Probe.Connect != "skipped" || r.Probe.TLS != "skipped" {
		t.Fatalf("record = %+v", r)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"endpoint", "env_patch", "unset", "set"} {
		if strings.Contains(string(data), `"`+forbidden+`"`) {
			t.Fatalf("unsafe record: %s", data)
		}
	}
	for _, tc := range []struct {
		name, digest string
		equal        bool
	}{
		{"direct", netprofile.Digest(p), true}, {"other-direct", netprofile.Digest(p), true}, {"direct", "sha256:changed", false},
	} {
		fresh := b
		fresh.ProfileRef, fresh.ProfileDigest = tc.name, tc.digest
		if binding.Equal(b, fresh) != tc.equal || binding.RecordEqual(r, fresh) != tc.equal {
			t.Fatalf("equality for %+v", tc)
		}
	}
}
