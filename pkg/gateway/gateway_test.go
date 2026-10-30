// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/gateway"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

func TestExternalBackend(t *testing.T) {
	t.Parallel()
	b, err := gateway.ForKind("external-http-proxy")
	if err != nil || b.Kind() != netprofile.KindExternalHTTPProxy {
		t.Fatalf("ForKind = %v, %v", b, err)
	}
	p := netprofile.Profile{Name: "egress-a", Kind: "external-http-proxy", Endpoint: "http://127.0.0.1:18081"}
	ep, err := b.Endpoint(context.Background(), p)
	if err != nil || ep != "http://127.0.0.1:18081" {
		t.Fatalf("Endpoint = %q, %v", ep, err)
	}
	if _, err := b.Endpoint(context.Background(), netprofile.Profile{Name: "x", Kind: "managed-sing-box"}); err == nil {
		t.Fatal("other kind accepted")
	} else if c, _ := refusal.CodeOf(err); c != refusal.CodeScopeUnsupported {
		t.Fatalf("code = %s", c)
	}
	if _, err := b.Endpoint(context.Background(), netprofile.Profile{Name: "x", Kind: "external-http-proxy"}); err == nil {
		t.Fatal("empty endpoint accepted")
	}
	if _, err := gateway.ForKind("managed-sing-box"); err == nil {
		t.Fatal("unknown kind served")
	} else if c, _ := refusal.CodeOf(err); c != refusal.CodeScopeUnsupported {
		t.Fatalf("code = %s", c)
	}
	var _ gateway.Backend = gateway.External{}
}

// No library backend serves a filtering gateway: only the owner of the
// actual runtime registers with it. Direct and external stay served.
func TestForKindFilteringGateway(t *testing.T) {
	if _, err := gateway.ForKind(netprofile.KindFilteringGateway); err == nil {
		t.Fatal("a backend serves filtering-gateway")
	} else if code, _ := refusal.CodeOf(err); code != refusal.CodeScopeUnsupported {
		t.Fatalf("err = %v", err)
	}
	for _, kind := range []string{netprofile.KindDirect, netprofile.KindExternalHTTPProxy} {
		if _, err := gateway.ForKind(kind); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
}
