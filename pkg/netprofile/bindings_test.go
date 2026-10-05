// SPDX-License-Identifier: Apache-2.0

package netprofile_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

func TestParseBindings(t *testing.T) {
	const base = "schema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\n"
	for _, tc := range []struct{ name, text, code string }{
		{"absent", "", ""},
		{"empty", "[bindings.profiles]\n", ""},
		{"valid", "[bindings.profiles]\nwork = \"direct\"\n\"work.dev\" = \"direct\"\n", ""},
		{"identifier length boundary", "[bindings.profiles]\n" + strings.Repeat("a", 63) + " = \"direct\"\n", ""},
		{"identifier too long", "[bindings.profiles]\n" + strings.Repeat("a", 64) + " = \"direct\"\n", refusal.CodeProfileInvalid},
		{"inline bindings", "[bindings]\nprofiles = {work = \"direct\"}\n", ""},
		{"unknown target deferred", "[bindings.profiles]\nwork = \"missing\"\n", ""},
		{"invalid profile", "[bindings.profiles]\nWork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"invalid target", "[bindings.profiles]\nwork = \"bad name\"\n", refusal.CodeProfileInvalid},
		{"empty target", "[bindings.profiles]\nwork = \"\"\n", refusal.CodeProfileInvalid},
		{"target whitespace", "[bindings.profiles]\nwork = \" direct \"\n", refusal.CodeProfileInvalid},
		{"unknown binding key", "[bindings]\nsecret_key = \"secret-value\"\n", refusal.CodeProfileInvalid},
		{"unknown network key", "secret_key = \"secret-value\"\n", refusal.CodeProfileInvalid},
		{"wrong binding type", "[bindings]\nprofiles = []\n", refusal.CodeProfileInvalid},
		{"wrong target type", "[bindings.profiles]\nwork = 1\n", refusal.CodeProfileInvalid},
		{"nested target", "[bindings.profiles.work]\nnetwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"reserved paths empty", "[bindings.paths]\n", refusal.CodeScopeUnsupported},
		{"reserved paths", "[bindings.paths]\n\"/secret-path\" = \"direct\"\n", refusal.CodeScopeUnsupported},
		{"reserved paths inline", "[bindings]\npaths = {}\n", refusal.CodeScopeUnsupported},
		{"reserved paths scalar", "[bindings]\npaths = false\n", refusal.CodeScopeUnsupported},
		{"duplicate", "[bindings.profiles]\nwork = \"direct\"\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"conflicting duplicate", "[bindings.profiles]\nwork = \"missing\"\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"root case alias", "[Bindings.profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"root uppercase alias", "[BINDINGS.profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"nested case alias", "[bindings.Profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"nested uppercase alias", "[bindings.PROFILES]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"path case alias", "[bindings.Paths]\n", refusal.CodeProfileInvalid},
		{"root conflicts", "[bindings.profiles]\nwork = \"missing\"\n[Bindings.profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"root reversed conflicts", "[Bindings.profiles]\nwork = \"direct\"\n[bindings.profiles]\nwork = \"missing\"\n", refusal.CodeProfileInvalid},
		{"nested conflicts", "[bindings.profiles]\nwork = \"missing\"\n[bindings.Profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"nested reversed conflicts", "[bindings.Profiles]\nwork = \"direct\"\n[bindings.profiles]\nwork = \"missing\"\n", refusal.CodeProfileInvalid},
		{"masked invalid target", "[bindings.profiles]\nwork = \"bad name\"\n[Bindings.profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"quoted namespace", "['bindings'.\"profiles\"]\nwork = \"direct\"\n", ""},
		{"escaped namespace", "[\"b\\u0069ndings\".\"prof\\u0069les\"]\nwork = \"direct\"\n", ""},
		{"unicode dotted root escaped", "[\"b\\u0130ndings\".profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode dotted root literal", "[\"b\u0130ndings\".profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode dotless root", "[\"b\\u0131ndings\".profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode long s root", "[\"binding\\u017F\".profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode fullwidth root", "[\"\uff42\uff49\uff4e\uff44\uff49\uff4e\uff47\uff53\".profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode root conflict", "[bindings.profiles]\nwork = \"missing\"\n[\"b\\u0130ndings\".profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode root reversed conflict", "[\"b\\u0130ndings\".profiles]\nwork = \"direct\"\n[bindings.profiles]\nwork = \"missing\"\n", refusal.CodeProfileInvalid},
		{"unicode masked invalid target", "[bindings.profiles]\nwork = \"bad name\"\n[\"b\\u0130ndings\".profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode nested beneath unicode root", "[\"b\\u0130ndings\".Profiles]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode nested under canonical", "[bindings.\"prof\\u0130les\"]\nwork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode dotless key", "[bindings.profiles]\n\"w\\u0131\" = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode kelvin key", "[bindings.profiles]\n\"wor\\u212A\" = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode long s key", "[bindings.profiles]\n\"work\\u017F\" = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode fullwidth key", "[bindings.profiles]\n\"\uff57\uff4f\uff52\uff4b\" = \"direct\"\n", refusal.CodeProfileInvalid},
		{"unicode dotless target", "[bindings.profiles]\nwork = \"d\\u0131rect\"\n", refusal.CodeProfileInvalid},
		{"unicode kelvin target", "[bindings.profiles]\nwork = \"wor\\u212A\"\n", refusal.CodeProfileInvalid},
		{"unicode long s target", "[bindings.profiles]\nwork = \"work\\u017F\"\n", refusal.CodeProfileInvalid},
		{"unicode fullwidth target", "[bindings.profiles]\nwork = \"\uff57\uff4f\uff52\uff4b\"\n", refusal.CodeProfileInvalid},
		{"ascii mixed-case duplicate", "[bindings.profiles]\nwork = \"missing\"\nWork = \"direct\"\n", refusal.CodeProfileInvalid},
		{"ascii uppercase duplicate", "[bindings.profiles]\nwork = \"missing\"\nWORK = \"direct\"\n", refusal.CodeProfileInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := netprofile.Parse([]byte(base + tc.text))
			if tc.code != "" {
				if f != nil {
					t.Fatal("refusal returned a catalog")
				}
				if code, _ := refusal.CodeOf(err); code != tc.code {
					t.Fatalf("error = %v, want %s", err, tc.code)
				}
				if strings.Contains(err.Error(), "secret") {
					t.Fatalf("error exposed content: %v", err)
				}
				if tc.code == refusal.CodeScopeUnsupported && !strings.Contains(err.Error(), "[bindings.paths] is reserved and unsupported") {
					t.Fatalf("unclear reserved-path error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "valid" && (f.Bindings.Profiles["work"] != "direct" || f.Bindings.Profiles["work.dev"] != "direct") {
				t.Fatalf("bindings = %+v", f.Bindings)
			}
			plain, _ := netprofile.Parse([]byte(base))
			if netprofile.Digest(f.Networks["direct"]) != netprofile.Digest(plain.Networks["direct"]) {
				t.Fatal("bindings changed the network digest")
			}
		})
	}
}

func TestBindingDecodeErrorsNeverExposeUnsafeKeys(t *testing.T) {
	for _, key := range []string{`"/private/canary"`, `"u:canary@host"`, `"canary\ncontrol"`} {
		for _, text := range []string{
			"[bindings.profiles]\n" + key + " = 1\n",
			"[Bindings.profiles]\n" + key + " = 1\n",
			"[bindings.Profiles]\n" + key + " = 1\n",
			"[bindings.profiles]\n" + key + " = \"direct\"\n" + key + " = \"direct\"\n",
			"[bindings.paths]\n" + key + " = \"direct\"\n" + key + " = \"direct\"\n",
			// These legacy fallback cases have no binding table prefix.
			key + " = 1\n" + key + " = 2\n",
			"[networks." + key + "]\nendpoint = 1\n",
		} {
			t.Run(text, func(t *testing.T) {
				f, err := netprofile.Parse([]byte("schema = \"relux-network-profiles-v1\"\n" + text))
				var r *refusal.Refusal
				if f != nil || !errors.As(err, &r) || r.Code != refusal.CodeProfileInvalid {
					t.Fatalf("parse = %+v, %v", f, err)
				}
				for _, rendered := range []string{r.Subject, r.Detail, err.Error()} {
					if strings.Contains(rendered, "canary") || strings.Contains(rendered, "/private/") || strings.Contains(rendered, "\n") {
						t.Fatalf("unsafe diagnostic: %q", rendered)
					}
				}
			})
		}
	}
}
