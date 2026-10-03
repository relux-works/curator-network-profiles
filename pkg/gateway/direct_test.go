// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"github.com/relux-works/curator-network-profiles/pkg/gateway"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"testing"
)

func TestDirectBackend(t *testing.T) {
	b, err := gateway.ForKind(netprofile.KindDirect)
	if err != nil || b.Kind() != "direct" {
		t.Fatalf("ForKind = %v, %v", b, err)
	}
	for _, tc := range []struct {
		p    netprofile.Profile
		code string
	}{
		{netprofile.Profile{Kind: "direct"}, ""},
		{netprofile.Profile{Kind: "external-http-proxy"}, refusal.CodeScopeUnsupported},
		{netprofile.Profile{Kind: "direct", Endpoint: "http://127.0.0.1:1"}, refusal.CodeProfileInvalid},
		{netprofile.Profile{Kind: "direct", BypassHosts: []string{}}, refusal.CodeProfileInvalid},
		{netprofile.Profile{Kind: "direct", ProbeTarget: "127.0.0.1:1"}, refusal.CodeProfileInvalid},
	} {
		ep, err := b.Endpoint(context.Background(), tc.p)
		code, _ := refusal.CodeOf(err)
		if ep != "" || code != tc.code || (tc.code == "" && err != nil) {
			t.Fatalf("Endpoint = %q, %v", ep, err)
		}
	}
	var _ gateway.Backend = gateway.Direct{}
}
