// SPDX-License-Identifier: Apache-2.0

package hosted_test

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/envpatch"
	"github.com/relux-works/curator-network-profiles/pkg/hosted"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

func TestApplyFinalGoldenVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/contract/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Digest []struct {
			ID         string
			Name       string
			Normalized netprofile.Profile
		}
		EnvPatch []struct {
			ID          string
			Profile     string
			Env, Result []string
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	profiles := map[string]netprofile.Profile{}
	for _, d := range vectors.Digest {
		p := d.Normalized
		p.Name = d.Name
		profiles[d.ID] = p
	}
	if len(vectors.EnvPatch) < 10 {
		t.Fatal("missing shared vectors")
	}
	for _, v := range vectors.EnvPatch {
		t.Run(v.ID, func(t *testing.T) {
			var b binding.Binding
			if v.Profile != "unmanaged" {
				p, ok := profiles[v.Profile]
				if !ok {
					t.Fatal("missing profile vector")
				}
				b = binding.Binding{ProfileRef: p.Name, ProfileDigest: netprofile.Digest(p), EnvPatch: envpatch.Generic{}.Patch(p)}
			}
			before := append([]string(nil), v.Env...)
			got := hosted.ApplyFinal(v.Env, b)
			if !reflect.DeepEqual(got, v.Result) {
				t.Fatalf("got %v; want %v", got, v.Result)
			}
			if !reflect.DeepEqual(v.Env, before) {
				t.Fatal("input mutated")
			}
			if !reflect.DeepEqual(hosted.ApplyFinal(got, b), got) {
				t.Fatal("not idempotent")
			}
			if len(got) > 0 {
				got[0] = "mutation"
				if !reflect.DeepEqual(v.Env, before) {
					t.Fatal("output aliases input")
				}
			}
		})
	}
}

func TestApplyFinalMixedCaseAndMissingUnset(t *testing.T) {
	// Even an adapter omitting the generic unset list cannot replay old proxies.
	b := binding.Binding{ProfileDigest: carrier().ExpectedDigest,
		EnvPatch: envpatch.Patch{Set: []envpatch.Pair{{Name: "HTTP_PROXY", Value: "fresh"}, {Name: "EXTRA", Value: "last"}}}}
	env := []string{"Z=1", "HtTp_PrOxY=stale", "http_proxy=old", "Http_Proxy=older", "HtTpS_PrOxY=old", "AlL_pRoXy=old", "FtP_pRoXy=old", "nO_pRoXy=*", "EXTRA=old", "NOTE=HTTP_PROXY=keep", "NOEQUALS"}
	want := []string{"Z=1", "NOTE=HTTP_PROXY=keep", "NOEQUALS", "HTTP_PROXY=fresh", "EXTRA=last"}
	if got := hosted.ApplyFinal(env, b); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestValidateEnvNames(t *testing.T) {
	for _, name := range envpatch.UnsetNames() {
		for _, spelling := range []string{name, strings.ToLower(name), mixedCase(name)} {
			requireCode(t, hosted.ValidateEnvNames([]string{"PATH", spelling}), refusal.CodeConfigurationConflict)
		}
	}
	if err := hosted.ValidateEnvNames([]string{"PATH", "HTTP_PROXY_EXTRA", "NOTE"}); err != nil {
		t.Fatal(err)
	}
}

func mixedCase(s string) string {
	b := []byte(strings.ToLower(s))
	for i := 0; i < len(b); i += 2 {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

func TestCheckReattach(t *testing.T) {
	b := binding.Binding{ProfileRef: "egress-a", ProfileDigest: carrier().ExpectedDigest, AdapterIdentity: testIdentity, Assurance: binding.AssuranceCooperative}
	r := b.Record("explicit", nil)
	if err := hosted.CheckReattach(r, b); err != nil {
		t.Fatal(err)
	}
	alias := b
	alias.ProfileRef = "equal-alias"
	alias.ResolvedEndpoint = "ignored"
	if err := hosted.CheckReattach(r, alias); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, code string
		mutate     func(*binding.Binding)
	}{
		{"digest", refusal.CodeProfileDrift, func(b *binding.Binding) { b.ProfileDigest = "sha256:" + strings.Repeat("5", 64) }},
		{"adapter", refusal.CodeScopeUnsupported, func(b *binding.Binding) { b.AdapterIdentity.Adapter += "-changed" }},
		{"harness", refusal.CodeScopeUnsupported, func(b *binding.Binding) { b.AdapterIdentity.Harness += "-changed" }},
		{"build", refusal.CodeScopeUnsupported, func(b *binding.Binding) { b.AdapterIdentity.Build += "-changed" }},
		{"entrypoint", refusal.CodeScopeUnsupported, func(b *binding.Binding) { b.AdapterIdentity.Entrypoint += "-changed" }},
		{"assurance", refusal.CodeScopeUnsupported, func(b *binding.Binding) { b.Assurance = binding.AssuranceEnforced }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fresh := b
			tc.mutate(&fresh)
			requireCode(t, hosted.CheckReattach(r, fresh), tc.code)
		})
	}
	requireCode(t, hosted.CheckReattach(binding.Record{}, b), refusal.CodeScopeUnsupported)
	requireCode(t, hosted.CheckReattach(r, binding.Binding{}), refusal.CodeScopeUnsupported)
	r.Schema = "foreign"
	requireCode(t, hosted.CheckReattach(r, b), refusal.CodeScopeUnsupported)
}
