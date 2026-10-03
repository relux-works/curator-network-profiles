// SPDX-License-Identifier: Apache-2.0

package resolve_test

import (
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
	"testing"
)

func TestDirectResolution(t *testing.T) {
	p, err := netprofile.Normalize("direct", netprofile.Input{Kind: netprofile.KindDirect})
	if err != nil {
		t.Fatal(err)
	}
	f := file(t)
	f.Default = ""
	f.Networks["direct"] = p
	for _, tc := range []struct {
		name      string
		req       resolve.Request
		confirmed bool
		code      string
		origin    resolve.Origin
	}{
		{"explicit over parent", resolve.Request{Explicit: "direct", Inherited: "egress-a", Allowed: []string{"direct"}, EngineHosts: []string{"127.0.0.1", "engine.example"}}, true, "", resolve.OriginExplicit},
		{"inherited direct", resolve.Request{Inherited: "direct"}, true, "", resolve.OriginInherited},
		{"unconfirmed", resolve.Request{Explicit: "direct"}, false, refusal.CodeProfileDenied, ""},
		{"denied", resolve.Request{Explicit: "direct", Allowed: []string{"egress-a"}}, true, refusal.CodeProfileDenied, ""},
		{"enforced", resolve.Request{Explicit: "direct", RequiredAssurance: "enforced"}, true, refusal.CodeScopeUnsupported, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ledger := resolve.ConfirmedFunc(func(name, digest string) bool {
				return tc.confirmed && name == "direct" && digest == netprofile.Digest(p)
			})
			r, err := resolve.Resolve(f, ledger, tc.req)
			code, _ := refusal.CodeOf(err)
			if code != tc.code || (tc.code == "" && err != nil) {
				t.Fatalf("resolve error = %v", err)
			}
			if err == nil && (!r.Managed || r.Selection.Origin != tc.origin || r.Selection.ProfileRef != "direct" || r.Digest != netprofile.Digest(p) || r.Assurance != "cooperative") {
				t.Fatalf("result = %+v", r)
			}
		})
	}
	r, err := resolve.Resolve(f, nil, resolve.Request{})
	if err != nil || r.Managed {
		t.Fatalf("no selection = %+v, %v", r, err)
	}
}
