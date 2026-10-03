// SPDX-License-Identifier: Apache-2.0

package netprofile_test

import (
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

func TestDirectProfile(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		valid        bool
	}{
		{"only kind", "", true},
		{"endpoint", `endpoint = "http://secret:password@127.0.0.1:1"`, false},
		{"empty endpoint", `endpoint = ""`, false},
		{"whitespace endpoint", `endpoint = " "`, false},
		{"bypass", `bypass_hosts = ["localhost"]`, false},
		{"empty bypass", `bypass_hosts = []`, false},
		{"probe", `probe_target = "secret.invalid:443"`, false},
		{"empty probe", `probe_target = ""`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := netprofile.Parse([]byte("schema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\n" + tc.fields))
			if !tc.valid {
				if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileInvalid {
					t.Fatalf("error = %v", err)
				}
				if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "password") {
					t.Fatalf("unsanitized error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p, _ := f.Lookup("direct")
			if p.Endpoint != "" || p.BypassHosts != nil || p.ProbeTarget != "" || p.CredentialMode != "none" {
				t.Fatalf("profile = %+v", p)
			}
			want := `{"credential_mode":"none","kind":"direct","schema":"relux-network-profiles-v1"}`
			if string(netprofile.Canonical(p)) != want {
				t.Fatalf("canonical = %s", netprofile.Canonical(p))
			}
			if netprofile.Digest(p) != "sha256:90781b39b78cd17c032c8f75f8936a6364958375b777466cb260336f9bc169e6" {
				t.Fatalf("digest = %s", netprofile.Digest(p))
			}
			copy := p
			copy.Name = "another"
			if netprofile.Digest(copy) != netprofile.Digest(p) {
				t.Fatal("name changed digest")
			}
		})
	}
	for _, in := range []netprofile.Input{
		{Kind: netprofile.KindDirect, Endpoint: " "},
		{Kind: netprofile.KindDirect, BypassHosts: []string{}},
		{Kind: netprofile.KindDirect, ProbeTarget: " "},
	} {
		if _, err := netprofile.Normalize("direct", in); err == nil {
			t.Fatalf("accepted %+v", in)
		}
	}
}
