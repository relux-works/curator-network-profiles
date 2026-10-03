// SPDX-License-Identifier: Apache-2.0

package envpatch_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/envpatch"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
)

func kv(name, value string) envpatch.Pair { return envpatch.Pair{Name: name, Value: value} }

var egressA = netprofile.Profile{Name: "egress-a", Kind: "external-http-proxy", Endpoint: "http://127.0.0.1:18081", BypassHosts: []string{"127.0.0.1", "::1", "localhost"}, CredentialMode: "none"}

func TestGenericPatchShape(t *testing.T) {
	t.Parallel()
	p := envpatch.Generic{}.Patch(egressA)
	wantUnset := []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy"}
	if !reflect.DeepEqual(p.Unset, wantUnset) {
		t.Fatalf("Unset = %v", p.Unset)
	}
	wantSet := []envpatch.Pair{
		kv("HTTP_PROXY", "http://127.0.0.1:18081"), kv("HTTPS_PROXY", "http://127.0.0.1:18081"),
		kv("http_proxy", "http://127.0.0.1:18081"), kv("https_proxy", "http://127.0.0.1:18081"),
		kv("NO_PROXY", "127.0.0.1,::1,localhost"), kv("no_proxy", "127.0.0.1,::1,localhost"),
	}
	if !reflect.DeepEqual(p.Set, wantSet) {
		t.Fatalf("Set = %v", p.Set)
	}
	for _, kv := range p.Set {
		if strings.EqualFold(kv.Name, "ALL_PROXY") || strings.Contains(strings.ToLower(kv.Name), "ws") {
			t.Fatalf("generic adapter set %s", kv.Name)
		}
	}
	if (envpatch.Generic{}).Identity() != "generic-env-v1" {
		t.Fatal("identity")
	}
	if p.Empty() || !envpatch.Unmanaged().Empty() {
		t.Fatal("Empty")
	}
	lits := p.SetLiterals()
	lits[0].Value = "mutated"
	if p.Set[0].Value == "mutated" {
		t.Fatal("SetLiterals aliases the patch")
	}
	names := p.UnsetNames()
	names[0] = "X"
	if p.Unset[0] == "X" {
		t.Fatal("UnsetNames aliases the patch")
	}
	all := envpatch.UnsetNames()
	all[0] = "X"
	if envpatch.UnsetNames()[0] == "X" {
		t.Fatal("UnsetNames() aliases the package list")
	}
}

func TestApplyVectors(t *testing.T) {
	t.Parallel()
	patch := envpatch.Generic{}.Patch(egressA)
	set := []string{
		"HTTP_PROXY=http://127.0.0.1:18081", "HTTPS_PROXY=http://127.0.0.1:18081",
		"http_proxy=http://127.0.0.1:18081", "https_proxy=http://127.0.0.1:18081",
		"NO_PROXY=127.0.0.1,::1,localhost", "no_proxy=127.0.0.1,::1,localhost",
	}
	cases := []struct {
		name string
		env  []string
		want []string
	}{
		{"clean env", []string{"PATH=/bin", "HOME=/h"}, append([]string{"PATH=/bin", "HOME=/h"}, set...)},
		{"lowercase and uppercase conflicts", []string{"http_proxy=http://wrong:1", "PATH=/bin", "HTTPS_PROXY=http://wrong:2", "https_proxy=http://wrong:3"}, append([]string{"PATH=/bin"}, set...)},
		{"mixed-case oddity", []string{"Http_Proxy=http://odd:1", "No_Proxy=*", "PATH=/bin"}, append([]string{"PATH=/bin"}, set...)},
		{"ambient NO_PROXY star", []string{"NO_PROXY=*", "no_proxy=*", "PATH=/bin"}, append([]string{"PATH=/bin"}, set...)},
		{"host-only conflicting vars removed not re-set", []string{"ALL_PROXY=socks5://host-only:1080", "all_proxy=socks5://host-only:1080", "FTP_PROXY=http://ftp:1", "ftp_proxy=http://ftp:1", "PATH=/bin"}, append([]string{"PATH=/bin"}, set...)},
		{"order of untouched entries and malformed entry kept", []string{"Z=1", "NOEQUALS", "A=2", "=weird", "HTTP_PROXY=x"}, append([]string{"Z=1", "NOEQUALS", "A=2", "=weird"}, set...)},
		{"empty env", nil, set},
		{"value containing proxy name is not a name", []string{"NOTE=HTTP_PROXY=1", "HTTP_PROXY_EXTRA=1"}, append([]string{"NOTE=HTTP_PROXY=1", "HTTP_PROXY_EXTRA=1"}, set...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := append([]string(nil), tc.env...)
			got := patch.Apply(tc.env)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Apply =\n%v\nwant\n%v", got, tc.want)
			}
			if !reflect.DeepEqual(tc.env, in) {
				t.Fatal("Apply mutated its input")
			}
			if again := patch.Apply(got); !reflect.DeepEqual(again, got) {
				t.Fatalf("not idempotent:\n%v\nvs\n%v", again, got)
			}
			seen := map[string]int{}
			for _, e := range got {
				name, _, _ := strings.Cut(e, "=")
				seen[strings.ToUpper(name)]++
			}
			for _, n := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} {
				if seen[n] != 2 {
					t.Fatalf("%s appears %d times (want exactly the two spellings)", n, seen[n])
				}
			}
			if seen["ALL_PROXY"] != 0 || seen["FTP_PROXY"] != 0 {
				t.Fatal("ALL_PROXY/FTP_PROXY survived")
			}
		})
	}
}

func TestApplyUnmanaged(t *testing.T) {
	t.Parallel()
	env := []string{"HTTPS_PROXY=http://ambient:1", "NO_PROXY=*", "PATH=/bin"}
	got := envpatch.Unmanaged().Apply(env)
	if !reflect.DeepEqual(got, env) {
		t.Fatalf("unmanaged changed the env: %v", got)
	}
	got[0] = "changed"
	if env[0] == "changed" {
		t.Fatal("Apply returned the input slice")
	}
}

func TestApplySetNamesNeverDuplicate(t *testing.T) {
	t.Parallel()
	p := envpatch.Patch{Set: []envpatch.Pair{kv("Foo", "1")}}
	got := p.Apply([]string{"Foo=0", "foo=keep", "Foo=00"})
	if !reflect.DeepEqual(got, []string{"foo=keep", "Foo=1"}) {
		t.Fatalf("got %v", got)
	}
}
