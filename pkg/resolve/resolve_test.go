// SPDX-License-Identifier: Apache-2.0

package resolve_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

// Every ordered pair uses different known references so both the selected
// origin and the winning reference must agree with N4.
func TestResolveEveryPrecedencePair(t *testing.T) {
	t.Parallel()
	candidates := []struct {
		origin resolve.Origin
		set    func(*resolve.Request, *netprofile.File, string)
	}{
		{resolve.OriginExplicit, func(r *resolve.Request, _ *netprofile.File, ref string) { r.Explicit = ref }},
		{resolve.OriginInherited, func(r *resolve.Request, _ *netprofile.File, ref string) { r.Inherited = ref }},
		{resolve.OriginRuntimeDefault, func(r *resolve.Request, _ *netprofile.File, ref string) { r.RuntimeDefault = ref }},
		{resolve.OriginProjectDefault, func(r *resolve.Request, _ *netprofile.File, ref string) { r.ProjectDefault = ref }},
		{resolve.OriginOperatorDefault, func(_ *resolve.Request, f *netprofile.File, ref string) { f.Default = ref }},
	}
	for i, higher := range candidates {
		for _, lower := range candidates[i+1:] {
			t.Run(string(higher.origin)+" over "+string(lower.origin), func(t *testing.T) {
				f := file(t)
				f.Default = ""
				req := resolve.Request{}
				higher.set(&req, f, "egress-a")
				lower.set(&req, f, "egress-b")
				res, err := resolve.Resolve(f, ledgerAll(f), req)
				if err != nil {
					t.Fatal(err)
				}
				if !res.Managed || res.Selection.ProfileRef != "egress-a" || res.Selection.Origin != higher.origin {
					t.Fatalf("selection = %+v, want egress-a/%s", res.Selection, higher.origin)
				}
			})
		}
	}
}

func TestInheritedEmptySelection(t *testing.T) {
	t.Parallel()
	for _, ref := range []string{"", " \t\n\u00a0"} {
		t.Run(ref, func(t *testing.T) {
			res, err := resolve.Resolve(nil, nil, resolve.Request{Inherited: ref})
			if err != nil || res.Managed || res.Selection.ProfileRef != "" || res.Selection.Origin != "" {
				t.Fatalf("empty inherited reference = %+v, %v", res, err)
			}
		})
	}
}

func TestInheritedReResolvesOnChildHost(t *testing.T) {
	t.Parallel()
	parent := file(t)
	parentResult, err := resolve.Resolve(parent, ledgerAll(parent), resolve.Request{Explicit: "egress-a"})
	if err != nil {
		t.Fatal(err)
	}
	child := mustParse(t, strings.ReplaceAll(catalog, ":18081", ":18083"))
	res, err := resolve.Resolve(child, ledgerAll(child), resolve.Request{Inherited: parentResult.Selection.ProfileRef})
	if err != nil {
		t.Fatal(err)
	}
	if res.Profile.Endpoint != "http://127.0.0.1:18083" || res.Digest == parentResult.Digest || res.Selection.Origin != resolve.OriginInherited {
		t.Fatalf("child did not re-resolve the reference locally: %+v", res)
	}
	raw, err := json.Marshal(res.Selection)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"profile_ref":"egress-a","origin":"inherited","required_assurance":"cooperative"}` {
		t.Fatalf("selection JSON = %s", raw)
	}
}

const catalog = `schema = "relux-network-profiles-v1"
default = "egress-b"

[networks.egress-a]
kind         = "external-http-proxy"
endpoint     = "http://127.0.0.1:18081"
bypass_hosts = ["localhost", "127.0.0.1", "::1", "engine.example"]

[networks.egress-b]
kind         = "external-http-proxy"
endpoint     = "http://127.0.0.1:18082"
bypass_hosts = ["localhost", "127.0.0.1", "::1"]
`

func file(t *testing.T) *netprofile.File {
	t.Helper()
	f, err := netprofile.Parse([]byte(catalog))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// ledgerAll confirms every profile of f at its current digest.
func ledgerAll(f *netprofile.File) resolve.Confirmations {
	return resolve.ConfirmedFunc(func(name, digest string) bool {
		p, ok := f.Lookup(name)
		return ok && netprofile.Digest(p) == digest
	})
}

func TestResolveTable(t *testing.T) {
	t.Parallel()
	f := file(t)
	all := ledgerAll(f)
	cases := []struct {
		name      string
		file      *netprofile.File
		ledger    resolve.Confirmations
		req       resolve.Request
		unmanaged bool
		ref       string
		origin    resolve.Origin
		code      string
		detail    string
	}{
		{name: "explicit wins", file: f, ledger: all, req: resolve.Request{Explicit: "egress-a", RuntimeDefault: "egress-b", ProjectDefault: "egress-b"}, ref: "egress-a", origin: resolve.OriginExplicit},
		{name: "inherited wins over defaults", file: f, ledger: all, req: resolve.Request{Inherited: "egress-a", RuntimeDefault: "egress-b", ProjectDefault: "egress-b"}, ref: "egress-a", origin: resolve.OriginInherited},
		{name: "explicit wins over inherited", file: f, ledger: all, req: resolve.Request{Explicit: "egress-a", Inherited: "egress-b"}, ref: "egress-a", origin: resolve.OriginExplicit},
		{name: "invalid inherited name refused", file: f, ledger: all, req: resolve.Request{Inherited: " \t eg ress \n"}, code: refusal.CodeProfileUnknown},
		{name: "inherited name trimmed", file: f, ledger: all, req: resolve.Request{Inherited: " \t egress-a \n"}, ref: "egress-a", origin: resolve.OriginInherited},
		{name: "empty inherited falls through", file: f, ledger: all, req: resolve.Request{Inherited: "", RuntimeDefault: "egress-a"}, ref: "egress-a", origin: resolve.OriginRuntimeDefault},
		{name: "whitespace inherited falls through", file: f, ledger: all, req: resolve.Request{Inherited: " \t\n\u00a0", RuntimeDefault: "egress-a"}, ref: "egress-a", origin: resolve.OriginRuntimeDefault},
		{name: "unknown inherited is refused not skipped", file: f, ledger: all, req: resolve.Request{Inherited: "egress-z", RuntimeDefault: "egress-a"}, code: refusal.CodeProfileUnknown},
		{name: "inherited on missing host catalog", file: nil, ledger: all, req: resolve.Request{Inherited: "egress-a"}, code: refusal.CodeProfileUnknown},
		{name: "inherited unconfirmed is denied", file: f, ledger: resolve.None, req: resolve.Request{Inherited: "egress-a", RuntimeDefault: "egress-b"}, code: refusal.CodeProfileDenied, detail: "unconfirmed"},
		{name: "inherited confirmed only at parent digest is denied", file: f, ledger: resolve.ConfirmedFunc(func(name, digest string) bool { return name == "egress-a" && digest == "sha256:parent" }), req: resolve.Request{Inherited: "egress-a"}, code: refusal.CodeProfileDenied, detail: "unconfirmed"},
		{name: "allowed set admits inherited", file: f, ledger: all, req: resolve.Request{Inherited: "egress-a", Allowed: []string{" egress-a "}}, ref: "egress-a", origin: resolve.OriginInherited},
		{name: "allowed set denies inherited without fallback", file: f, ledger: all, req: resolve.Request{Inherited: "egress-a", RuntimeDefault: "egress-b", Allowed: []string{"egress-b"}}, code: refusal.CodeProfileDenied, detail: "allowed set"},
		{name: "empty allowed set denies inherited", file: f, ledger: all, req: resolve.Request{Inherited: "egress-a", Allowed: []string{}}, code: refusal.CodeProfileDenied, detail: "allowed set"},
		{name: "allowed inherited check precedes existence", file: f, ledger: all, req: resolve.Request{Inherited: "egress-z", Allowed: []string{"egress-a"}}, code: refusal.CodeProfileDenied, detail: "allowed set"},
		{name: "runtime default", file: f, ledger: all, req: resolve.Request{RuntimeDefault: "egress-a", ProjectDefault: "egress-b"}, ref: "egress-a", origin: resolve.OriginRuntimeDefault},
		{name: "project default", file: f, ledger: all, req: resolve.Request{ProjectDefault: "egress-a"}, ref: "egress-a", origin: resolve.OriginProjectDefault},
		{name: "operator default", file: f, ledger: all, req: resolve.Request{}, ref: "egress-b", origin: resolve.OriginOperatorDefault},
		{name: "whitespace is no selection", file: f, ledger: all, req: resolve.Request{Explicit: "  "}, ref: "egress-b", origin: resolve.OriginOperatorDefault},
		{name: "unmanaged without any selection", file: mustParse(t, "schema = \"relux-network-profiles-v1\"\n"), ledger: all, req: resolve.Request{}, unmanaged: true},
		{name: "unmanaged with missing file", file: nil, ledger: nil, req: resolve.Request{}, unmanaged: true},
		{name: "unknown with missing file", file: nil, ledger: nil, req: resolve.Request{Explicit: "egress-a"}, code: refusal.CodeProfileUnknown},
		{name: "unknown name", file: f, ledger: all, req: resolve.Request{Explicit: "egress-z"}, code: refusal.CodeProfileUnknown},
		{name: "unknown runtime default is refused not skipped", file: f, ledger: all, req: resolve.Request{RuntimeDefault: "egress-z", ProjectDefault: "egress-a"}, code: refusal.CodeProfileUnknown},
		{name: "allowed set admits", file: f, ledger: all, req: resolve.Request{Explicit: "egress-a", Allowed: []string{"egress-a"}}, ref: "egress-a", origin: resolve.OriginExplicit},
		{name: "allowed set denies explicit", file: f, ledger: all, req: resolve.Request{Explicit: "egress-a", Allowed: []string{"egress-b"}}, code: refusal.CodeProfileDenied, detail: "allowed set"},
		{name: "allowed set denies operator default", file: f, ledger: all, req: resolve.Request{Allowed: []string{"egress-a"}}, code: refusal.CodeProfileDenied},
		{name: "empty allowed set denies everything", file: f, ledger: all, req: resolve.Request{Explicit: "egress-a", Allowed: []string{}}, code: refusal.CodeProfileDenied},
		{name: "allowed check precedes existence", file: f, ledger: all, req: resolve.Request{Explicit: "egress-z", Allowed: []string{"egress-a"}}, code: refusal.CodeProfileDenied},
		{name: "unconfirmed is denied", file: f, ledger: resolve.None, req: resolve.Request{Explicit: "egress-a"}, code: refusal.CodeProfileDenied, detail: "unconfirmed"},
		{name: "nil ledger confirms nothing", file: f, ledger: nil, req: resolve.Request{Explicit: "egress-a"}, code: refusal.CodeProfileDenied, detail: "unconfirmed"},
		{name: "confirmed at an old digest is denied", file: f, ledger: resolve.ConfirmedFunc(func(name, digest string) bool { return name == "egress-a" && digest == "sha256:old" }), req: resolve.Request{Explicit: "egress-a"}, code: refusal.CodeProfileDenied, detail: "unconfirmed"},
		{name: "enforced refused", file: f, ledger: all, req: resolve.Request{Explicit: "egress-a", RequiredAssurance: "enforced"}, code: refusal.CodeScopeUnsupported, detail: "cooperative only"},
		{name: "bogus assurance refused", file: f, ledger: all, req: resolve.Request{Explicit: "egress-a", RequiredAssurance: "magic"}, code: refusal.CodeScopeUnsupported},
		{name: "engine hosts covered", file: f, ledger: all, req: resolve.Request{Explicit: "egress-a", EngineHosts: []string{"127.0.0.1", "LOCALHOST", "[::1]:11434", "Engine.Example"}}, ref: "egress-a", origin: resolve.OriginExplicit},
		{name: "engine host not covered", file: f, ledger: all, req: resolve.Request{Explicit: "egress-b", EngineHosts: []string{"127.0.0.1", "engine.example"}}, code: refusal.CodeConfigurationConflict, detail: "engine host engine.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := resolve.Resolve(tc.file, tc.ledger, tc.req)
			if tc.code != "" {
				if err == nil {
					t.Fatalf("expected %s, got result %+v", tc.code, res)
				}
				if c, _ := refusal.CodeOf(err); c != tc.code {
					t.Fatalf("code = %s (%v), want %s", c, err, tc.code)
				}
				if tc.detail != "" && !strings.Contains(err.Error(), tc.detail) {
					t.Fatalf("detail %q not in %v", tc.detail, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.unmanaged {
				if res.Managed || res.Selection.ProfileRef != "" || res.Digest != "" {
					t.Fatalf("expected unmanaged, got %+v", res)
				}
				if res.Selection.RequiredAssurance != "cooperative" {
					t.Fatalf("assurance = %q", res.Selection.RequiredAssurance)
				}
				return
			}
			if !res.Managed || res.Selection.ProfileRef != tc.ref || res.Selection.Origin != tc.origin {
				t.Fatalf("got %+v, want %s/%s", res.Selection, tc.ref, tc.origin)
			}
			if res.Profile.Name != tc.ref || res.Digest != netprofile.Digest(res.Profile) || res.Assurance != "cooperative" {
				t.Fatalf("result = %+v", res)
			}
		})
	}
}

func mustParse(t *testing.T, doc string) *netprofile.File {
	t.Helper()
	f, err := netprofile.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSelectOnly(t *testing.T) {
	t.Parallel()
	f := file(t)
	sel, ok := resolve.Select(f, resolve.Request{Explicit: "does-not-exist"})
	if !ok || sel.ProfileRef != "does-not-exist" || sel.Origin != resolve.OriginExplicit {
		t.Fatalf("Select = %+v, %v", sel, ok)
	}
	if sel, ok := resolve.Select(nil, resolve.Request{}); ok || sel.ProfileRef != "" {
		t.Fatalf("Select(nil) = %+v, %v", sel, ok)
	}
	if sel, ok := resolve.Select(f, resolve.Request{RequiredAssurance: "enforced"}); !ok || sel.RequiredAssurance != "enforced" || sel.Origin != resolve.OriginOperatorDefault {
		t.Fatalf("Select = %+v, %v", sel, ok)
	}
}
