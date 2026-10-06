// SPDX-License-Identifier: Apache-2.0

package netprofile_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

func TestSensitiveEgressParsing(t *testing.T) {
	proxy := func(field string) string {
		return "schema = \"relux-network-profiles-v1\"\n[networks.egress-a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:18081\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n" + field
	}
	for _, tc := range []struct {
		name    string
		doc     string
		profile string
		want    bool
	}{
		{"absent defaults to false", proxy(""), "egress-a", false},
		{"explicit false", proxy("sensitive_egress = false\n"), "egress-a", false},
		{"explicit true", proxy("sensitive_egress = true\n"), "egress-a", true},
		{"direct allows the declaration", "schema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\nsensitive_egress = true\n", "direct", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := netprofile.Parse([]byte(tc.doc))
			if err != nil {
				t.Fatal(err)
			}
			p, ok := f.Lookup(tc.profile)
			if !ok || p.SensitiveEgress != tc.want {
				t.Fatalf("profile=%+v ok=%v; want sensitive=%v", p, ok, tc.want)
			}
		})
	}
	f, err := netprofile.Parse([]byte(proxy("sensitive_egress = \"yes\"\n")))
	if code, _ := refusal.CodeOf(err); f != nil || code != refusal.CodeProfileInvalid {
		t.Fatalf("wrong type: %+v %v", f, err)
	}
	r, _ := refusal.As(err)
	if r.Subject != "egress-a" {
		t.Fatalf("subject=%q", r.Subject)
	}
	if !strings.Contains(err.Error(), "networks.egress-a.sensitive_egress: wrong type") {
		t.Fatalf("detail wrong: %v", err)
	}
}

func TestSensitiveEgressDigest(t *testing.T) {
	in := netprofile.Input{Kind: "external-http-proxy", Endpoint: "http://127.0.0.1:18081", BypassHosts: []string{"localhost", "127.0.0.1", "::1"}}
	absent, err := netprofile.Normalize("egress-a", in)
	if err != nil {
		t.Fatal(err)
	}
	in.SensitiveEgress = true
	declared, err := netprofile.Normalize("egress-a", in)
	if err != nil {
		t.Fatal(err)
	}
	if string(netprofile.Canonical(absent)) != `{"bypass_hosts":["127.0.0.1","::1","localhost"],"credential_mode":"none","endpoint":"http://127.0.0.1:18081","kind":"external-http-proxy","schema":"relux-network-profiles-v1"}` {
		t.Fatalf("absent canonical changed: %s", netprofile.Canonical(absent))
	}
	if string(netprofile.Canonical(declared)) != `{"bypass_hosts":["127.0.0.1","::1","localhost"],"credential_mode":"none","endpoint":"http://127.0.0.1:18081","kind":"external-http-proxy","schema":"relux-network-profiles-v1","sensitive_egress":true}` {
		t.Fatalf("declared canonical: %s", netprofile.Canonical(declared))
	}
	if netprofile.Digest(absent) == netprofile.Digest(declared) {
		t.Fatal("declaration did not change the digest")
	}
	in.SensitiveEgress = false
	explicit, err := netprofile.Normalize("egress-a", in)
	if err != nil {
		t.Fatal(err)
	}
	if netprofile.Digest(explicit) != netprofile.Digest(absent) {
		t.Fatal("explicit false differs from absent")
	}
	direct, err := netprofile.Normalize("direct", netprofile.Input{Kind: netprofile.KindDirect, SensitiveEgress: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(netprofile.Canonical(direct)) != `{"credential_mode":"none","kind":"direct","schema":"relux-network-profiles-v1","sensitive_egress":true}` {
		t.Fatalf("direct canonical: %s", netprofile.Canonical(direct))
	}
}

func TestSensitiveEgressAliasesRefuse(t *testing.T) {
	proxy := func(fields string) string {
		return "schema = \"relux-network-profiles-v1\"\n[networks.egress-a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:18081\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n" + fields
	}
	direct := func(fields string) string {
		return "schema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\n" + fields
	}
	for _, tc := range []struct {
		name string
		doc  string
	}{
		// Both value orders, proxy and direct: an alias must never win
		// by order, and a visible true must never parse as false.
		{"proxy true then alias false", proxy("sensitive_egress = true\nSensitive_Egress = false\n")},
		{"proxy alias false then true", proxy("Sensitive_Egress = false\nsensitive_egress = true\n")},
		{"proxy true then alias true", proxy("sensitive_egress = true\nSENSITIVE_EGRESS = true\n")},
		{"direct true then alias false", direct("sensitive_egress = true\nSensitive_Egress = false\n")},
		{"direct alias false then true", direct("Sensitive_Egress = false\nsensitive_egress = true\n")},
		// Sole wrong-case spelling, proxy and direct.
		{"proxy sole alias", proxy("Sensitive_Egress = true\n")},
		{"direct sole alias", direct("Sensitive_Egress = false\n")},
		{"proxy upper alias", proxy("SENSITIVE_EGRESS = false\n")},
		// Valid quoted aliases, both conflict orders.
		{"proxy quoted alias after canonical", proxy("sensitive_egress = true\n\"Sensitive_Egress\" = false\n")},
		{"proxy quoted alias before canonical", proxy("\"Sensitive_Egress\" = false\nsensitive_egress = true\n")},
		{"direct quoted alias after canonical", direct("sensitive_egress = true\n\"Sensitive_Egress\" = false\n")},
		{"direct quoted alias before canonical", direct("\"Sensitive_Egress\" = false\nsensitive_egress = true\n")},
		{"proxy sole quoted alias", proxy("\"SENSITIVE_EGRESS\" = true\n")},
		// Valid escaped aliases that decode to a folding spelling.
		{"proxy escaped alias", proxy("\"SENSITIVE\\u005FEGRESS\" = false\n")},
		{"proxy escaped alias conflict", proxy("sensitive_egress = true\n\"Sensitive\\u005Fegress\" = false\n")},
		{"direct escaped alias conflict reversed", direct("\"Sensitive\\u005Fegress\" = false\nsensitive_egress = true\n")},
		// Valid quoted Kelvin aliases that lowercase to known keys.
		{"proxy kelvin kind field", proxy("\"\\u212Aind\" = \"external-http-proxy\"\n")},
		{"direct kelvin kind field", "schema = \"relux-network-profiles-v1\"\n[networks.direct]\n\"\\u212Aind\" = \"direct\"\n"},
		{"kelvin networks table", "schema = \"relux-network-profiles-v1\"\n[\"networ\\u212As\" . \"egress-a\"]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:18081\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n"},
		{"kelvin networks conflict canonical first", "schema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\n[\"networ\\u212As\" . \"other\"]\nkind = \"direct\"\n"},
		{"kelvin networks conflict alias first", "schema = \"relux-network-profiles-v1\"\n[\"networ\\u212As\" . \"other\"]\nkind = \"direct\"\n[networks.direct]\nkind = \"direct\"\n"},
		// Duplicate exact keys refuse instead of choosing by order.
		{"proxy duplicate exact", proxy("sensitive_egress = true\nsensitive_egress = false\n")},
		{"direct duplicate exact", direct("sensitive_egress = false\nsensitive_egress = true\n")},
		// Aliases through enclosing namespaces, both orders.
		{"upper networks table", "schema = \"relux-network-profiles-v1\"\n[NETWORKS.egress-a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:18081\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n"},
		{"upper schema key", "SCHEMA = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\n"},
		{"schema conflict canonical first", "schema = \"relux-network-profiles-v1\"\nSCHEMA = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\n"},
		{"schema conflict alias first", "SCHEMA = \"relux-network-profiles-v1\"\nschema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\n"},
		{"networks conflict canonical first", "schema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\n[NETWORKS.other]\nkind = \"direct\"\n"},
		{"networks conflict alias first", "schema = \"relux-network-profiles-v1\"\n[NETWORKS.other]\nkind = \"direct\"\n[networks.direct]\nkind = \"direct\"\n"},
		{"upper kind field", proxy("Kind = \"external-http-proxy\"\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := netprofile.Parse([]byte(tc.doc))
			code, _ := refusal.CodeOf(err)
			if f != nil || code != refusal.CodeProfileInvalid {
				t.Fatalf("alias accepted or wrong code: %+v %v", f, err)
			}
			if err != nil && (strings.Contains(err.Error(), "Sensitive_Egress") || strings.Contains(err.Error(), "SENSITIVE_EGRESS") || strings.Contains(err.Error(), "K") || strings.Contains(err.Error(), "Ｓ")) {
				t.Fatalf("refusal echoes the alias: %v", err)
			}
		})
	}
	// Canonical true/false/absent declarations still parse.
	for _, tc := range []struct {
		name string
		doc  string
		want bool
	}{
		{"proxy absent", proxy(""), false},
		{"proxy false", proxy("sensitive_egress = false\n"), false},
		{"proxy true", proxy("sensitive_egress = true\n"), true},
		{"direct absent", direct(""), false},
		{"direct true", direct("sensitive_egress = true\n"), true},
		{"quoted exact key", proxy("\"sensitive_egress\" = true\n"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := netprofile.Parse([]byte(tc.doc))
			if err != nil {
				t.Fatal(err)
			}
			name := "egress-a"
			if strings.Contains(tc.doc, "[networks.direct]") {
				name = "direct"
			}
			p, ok := f.Lookup(name)
			if !ok || p.SensitiveEgress != tc.want {
				t.Fatalf("profile=%+v ok=%v; want %v", p, ok, tc.want)
			}
		})
	}
}

func TestSensitiveEgressNonFoldingLookalikes(t *testing.T) {
	proxy := func(fields string) string {
		return "schema = \"relux-network-profiles-v1\"\n[networks.egress-a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:18081\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n" + fields
	}
	direct := func(fields string) string {
		return "schema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\n" + fields
	}
	// Quoted lookalikes are valid TOML but never fold to an ASCII key,
	// so they refuse as unknown keys. Bare lookalikes are not valid
	// TOML bare keys at all, so they refuse as syntax errors. Neither
	// becomes the canonical spelling.
	for _, tc := range []struct {
		name string
		doc  string
		code string
	}{
		{"proxy quoted long-s lookalike", proxy("\"sen\\u017Fitive_egress\" = true\n"), refusal.CodeProfileInvalid},
		{"direct quoted fullwidth lookalike", direct("\"\\uFF33ensitive_egress\" = true\n"), refusal.CodeProfileInvalid},
		{"proxy quoted dotted-I lookalike", proxy("\"sens\\u0130tive_egress\" = true\n"), refusal.CodeProfileInvalid},
		{"proxy bare long-s is a syntax error", proxy("senſitive_egress = true\n"), refusal.CodeFileUnreadable},
		{"direct bare fullwidth is a syntax error", direct("Ｓensitive_egress = true\n"), refusal.CodeFileUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := netprofile.Parse([]byte(tc.doc))
			code, _ := refusal.CodeOf(err)
			if f != nil || code != tc.code {
				t.Fatalf("lookalike accepted or wrong code: %+v %v; want %s", f, err, tc.code)
			}
		})
	}
}

func TestSensitiveEgressChangeConfirmsAndDrifts(t *testing.T) {
	proxyIn := func(sensitive *bool) netprofile.Input {
		in := netprofile.Input{Kind: "external-http-proxy", Endpoint: "http://127.0.0.1:18081", BypassHosts: []string{"localhost", "127.0.0.1", "::1"}}
		if sensitive != nil {
			in.SensitiveEgress = *sensitive
		}
		return in
	}
	directIn := func(sensitive *bool) netprofile.Input {
		in := netprofile.Input{Kind: netprofile.KindDirect}
		if sensitive != nil {
			in.SensitiveEgress = *sensitive
		}
		return in
	}
	truth := true
	falsity := false
	for _, tc := range []struct {
		name string
		make func(*bool) netprofile.Input
	}{
		{"proxy", proxyIn},
		{"direct", directIn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			absent, err := netprofile.Normalize("egress-a", tc.make(nil))
			if err != nil {
				t.Fatal(err)
			}
			explicit, err := netprofile.Normalize("egress-a", tc.make(&falsity))
			if err != nil {
				t.Fatal(err)
			}
			declared, err := netprofile.Normalize("egress-a", tc.make(&truth))
			if err != nil {
				t.Fatal(err)
			}
			dAbsent, dExplicit, dTrue := netprofile.Digest(absent), netprofile.Digest(explicit), netprofile.Digest(declared)
			if dAbsent != dExplicit {
				t.Fatal("explicit false differs from absent")
			}
			if dAbsent == dTrue {
				t.Fatal("declaration did not change the digest")
			}
			// A confirmation at the old digest never confirms the new
			// one: adding or removing the declaration needs confirm.
			ledger := resolve.Confirmations(resolve.ConfirmedFunc(func(name, digest string) bool {
				return name == "egress-a" && digest == dAbsent
			}))
			if !ledger.Confirmed("egress-a", dAbsent) || ledger.Confirmed("egress-a", dTrue) {
				t.Fatal("sensitivity change kept its confirmation")
			}
			// Reattach drifts in both directions; explicit false
			// reattaches cleanly against an absent record.
			id := binding.AdapterIdentity{Adapter: "generic-env-v1", Harness: "claude-code", Build: "sha256-" + strings.Repeat("a", 64), Entrypoint: "exec"}
			bind := func(digest string) binding.Binding {
				return binding.Binding{ProfileRef: "egress-a", ProfileDigest: digest, AdapterIdentity: id, Assurance: binding.AssuranceCooperative}
			}
			if _, err := binding.CheckReattach(bind(dAbsent).Record("explicit", nil), bind(dTrue), binding.EventReattach, false); err == nil {
				t.Fatal("absent to true reattached without drift")
			} else if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileDrift {
				t.Fatalf("absent to true: %v; want network_profile_drift", err)
			}
			if _, err := binding.CheckReattach(bind(dTrue).Record("explicit", nil), bind(dAbsent), binding.EventReattach, false); err == nil {
				t.Fatal("true to absent reattached without drift")
			} else if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileDrift {
				t.Fatalf("true to absent: %v; want network_profile_drift", err)
			}
			if out, err := binding.CheckReattach(bind(dAbsent).Record("explicit", nil), bind(dExplicit), binding.EventReattach, false); err != nil || out != binding.OutcomeReattach {
				t.Fatalf("absent to explicit false: %v %v; want reattach", out, err)
			}
		})
	}
}

func TestSensitiveEgressConfirmationThroughResolve(t *testing.T) {
	proxyDoc := func(field string) string {
		return "schema = \"relux-network-profiles-v1\"\n[networks.egress-a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:18081\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n" + field
	}
	directDoc := func(field string) string {
		return "schema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\n" + field
	}
	for _, tc := range []struct {
		name    string
		profile string
		doc     func(string) string
	}{
		{"proxy", "egress-a", proxyDoc},
		{"direct", "direct", directDoc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parse := func(field string) (*netprofile.File, string) {
				t.Helper()
				f, err := netprofile.Parse([]byte(tc.doc(field)))
				if err != nil {
					t.Fatal(err)
				}
				p, ok := f.Lookup(tc.profile)
				if !ok {
					t.Fatalf("profile %q missing", tc.profile)
				}
				return f, netprofile.Digest(p)
			}
			confirming := func(digest string) resolve.Confirmations {
				return resolve.ConfirmedFunc(func(name, candidate string) bool {
					return name == tc.profile && candidate == digest
				})
			}
			// Both sensitivity directions pass through the real
			// Resolve gate: a confirmation at the old digest never
			// confirms the new one, and confirming the new digest
			// succeeds.
			for _, dir := range []struct {
				name     string
				oldField string
				newField string
			}{
				{"absent to true", "", "sensitive_egress = true\n"},
				{"true to absent", "sensitive_egress = true\n", ""},
			} {
				t.Run(dir.name, func(t *testing.T) {
					_, oldDigest := parse(dir.oldField)
					newFile, newDigest := parse(dir.newField)
					if oldDigest == newDigest {
						t.Fatal("sensitivity change kept its digest")
					}
					res, err := resolve.Resolve(newFile, confirming(oldDigest), resolve.Request{Explicit: tc.profile})
					if res != nil {
						t.Fatalf("stale confirmation resolved: %+v", res)
					}
					if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileDenied {
						t.Fatalf("stale confirmation: %v; want network_profile_denied", err)
					}
					res, err = resolve.Resolve(newFile, confirming(newDigest), resolve.Request{Explicit: tc.profile})
					if err != nil || res == nil || !res.Managed {
						t.Fatalf("new confirmation: %+v %v; want success", res, err)
					}
				})
			}
			// Explicit false and absence share a digest, so either
			// confirmation resolves both catalogs.
			t.Run("false equals absence", func(t *testing.T) {
				absentFile, absentDigest := parse("")
				falseFile, falseDigest := parse("sensitive_egress = false\n")
				if absentDigest != falseDigest {
					t.Fatal("explicit false differs from absent")
				}
				ledger := confirming(absentDigest)
				if res, err := resolve.Resolve(falseFile, ledger, resolve.Request{Explicit: tc.profile}); err != nil || res == nil || !res.Managed {
					t.Fatalf("false catalog: %+v %v; want success", res, err)
				}
				if res, err := resolve.Resolve(absentFile, ledger, resolve.Request{Explicit: tc.profile}); err != nil || res == nil || !res.Managed {
					t.Fatalf("absent catalog: %+v %v; want success", res, err)
				}
			})
		})
	}
}

func TestSensitiveEgressShowJSON(t *testing.T) {
	// show --json embeds netprofile.Profile: the field is additive, so
	// existing documents without the declaration are byte-identical.
	plain, err := netprofile.Normalize("egress-a", netprofile.Input{Kind: "external-http-proxy", Endpoint: "http://127.0.0.1:18081", BypassHosts: []string{"localhost", "127.0.0.1", "::1"}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sensitive_egress") {
		t.Fatalf("plain profile leaks the field: %s", data)
	}
	sensitive, err := netprofile.Normalize("egress-a", netprofile.Input{Kind: "external-http-proxy", Endpoint: "http://127.0.0.1:18081", BypassHosts: []string{"localhost", "127.0.0.1", "::1"}, SensitiveEgress: true})
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(sensitive)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"sensitive_egress":true`) {
		t.Fatalf("declared profile hides the field: %s", data)
	}
}
