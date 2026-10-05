// SPDX-License-Identifier: Apache-2.0

package resolve_test

import (
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

func TestProfileBindingSelection(t *testing.T) {
	f := mustParse(t, catalog+"\n[bindings.profiles]\nwork = \"egress-a\"\nbroken = \"missing\"\n")
	for _, tc := range []struct {
		name   string
		req    resolve.Request
		ref    string
		origin resolve.Origin
		code   string
	}{
		{"binding", resolve.Request{CuratorProfile: "work", ProjectDefault: "egress-b"}, "egress-a", resolve.OriginProfileBinding, ""},
		{"omitted", resolve.Request{ProjectDefault: "egress-b"}, "egress-b", resolve.OriginProjectDefault, ""},
		{"unbound", resolve.Request{CuratorProfile: "other", ProjectDefault: "egress-b"}, "egress-b", resolve.OriginProjectDefault, ""},
		{"unknown target", resolve.Request{CuratorProfile: "broken", ProjectDefault: "egress-b"}, "", "", refusal.CodeProfileUnknown},
		{"unknown ignored by runtime", resolve.Request{CuratorProfile: "broken", RuntimeDefault: "egress-b"}, "egress-b", resolve.OriginRuntimeDefault, ""},
		{"denied", resolve.Request{CuratorProfile: "work", Allowed: []string{"egress-b"}}, "", "", refusal.CodeProfileDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := resolve.Resolve(f, ledgerAll(f), tc.req)
			if tc.code != "" {
				if code, _ := refusal.CodeOf(err); code != tc.code {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || !res.Managed || res.Selection.ProfileRef != tc.ref || res.Selection.Origin != tc.origin {
				t.Fatalf("result = %+v, %v", res, err)
			}
			if tc.origin == resolve.OriginProfileBinding {
				b := binding.Binding{ProfileRef: res.Selection.ProfileRef, ProfileDigest: res.Digest, Assurance: res.Assurance}
				r := b.Record(string(res.Selection.Origin), nil)
				if r.Origin != "profile-binding" || r.ProfileDigest != res.Digest || !binding.RecordEqual(r, b) {
					t.Fatalf("record = %+v", r)
				}
			}
		})
	}
	if _, err := resolve.Resolve(f, nil, resolve.Request{CuratorProfile: "work"}); err == nil {
		t.Fatal("binding bypassed confirmation")
	}
	for _, f := range []*netprofile.File{nil, {Bindings: netprofile.Bindings{Profiles: map[string]string{"work": "egress-a"}}}} {
		res, err := resolve.Resolve(f, nil, resolve.Request{})
		if err != nil || res.Managed {
			t.Fatalf("omitted profile should be unmanaged: %+v, %v", res, err)
		}
	}
}
