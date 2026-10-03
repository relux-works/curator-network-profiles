// SPDX-License-Identifier: Apache-2.0

package envpatch_test

import (
	"github.com/relux-works/curator-network-profiles/pkg/envpatch"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"reflect"
	"testing"
)

func TestDirectPatch(t *testing.T) {
	p := envpatch.Generic{}.Patch(netprofile.Profile{Kind: netprofile.KindDirect})
	if p.Empty() || !reflect.DeepEqual(p.Unset, envpatch.UnsetNames()) || p.Set == nil || len(p.Set) != 0 {
		t.Fatalf("patch = %+v", p)
	}
	for _, env := range [][]string{
		{"PATH=/bin", "HTTPS_PROXY=wrong", "http_proxy=wrong", "all_proxy=wrong", "NO_PROXY=*", "nO_pRoXy=*", "FTP_PROXY=wrong", "Http_Proxy=wrong"},
		{"PATH=/bin"},
	} {
		before := append([]string(nil), env...)
		got := p.Apply(env)
		if !reflect.DeepEqual(got, []string{"PATH=/bin"}) || !reflect.DeepEqual(p.Apply(got), got) || !reflect.DeepEqual(env, before) {
			t.Fatalf("Apply = %v, input = %v", got, env)
		}
		if !reflect.DeepEqual(envpatch.Unmanaged().Apply(env), env) {
			t.Fatal("unmanaged changed environment")
		}
	}
}
