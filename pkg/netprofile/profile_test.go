// SPDX-License-Identifier: Apache-2.0

package netprofile_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

const specFile = `schema = "relux-network-profiles-v1"

[networks.egress-a]
kind         = "external-http-proxy"
endpoint     = "http://127.0.0.1:18081"
bypass_hosts = ["localhost", "127.0.0.1", "::1"]

[networks.egress-b]
kind         = "external-http-proxy"
endpoint     = "http://127.0.0.1:18082"
bypass_hosts = ["localhost", "127.0.0.1", "::1"]
`

// The spec example's canonical bytes and digest, pinned by hand once and
// cross-checked against the code here; the contract appendix vectors are
// checked separately by internal/contract.
const (
	egressACanonical = `{"bypass_hosts":["127.0.0.1","::1","localhost"],"credential_mode":"none","endpoint":"http://127.0.0.1:18081","kind":"external-http-proxy","schema":"relux-network-profiles-v1"}`
)

func code(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	c, ok := refusal.CodeOf(err)
	if !ok {
		t.Fatalf("error is not a refusal: %v", err)
	}
	return c
}

func TestParseSpecExample(t *testing.T) {
	t.Parallel()
	f, err := netprofile.Parse([]byte(specFile))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := f.Names(); strings.Join(got, ",") != "egress-a,egress-b" {
		t.Fatalf("Names = %v", got)
	}
	a, ok := f.Lookup("egress-a")
	if !ok {
		t.Fatal("egress-a missing")
	}
	if a.Endpoint != "http://127.0.0.1:18081" || a.Kind != "external-http-proxy" || a.CredentialMode != "none" {
		t.Fatalf("egress-a = %+v", a)
	}
	if strings.Join(a.BypassHosts, ",") != "127.0.0.1,::1,localhost" {
		t.Fatalf("bypass = %v", a.BypassHosts)
	}
	if got := string(netprofile.Canonical(a)); got != egressACanonical {
		t.Fatalf("Canonical =\n%s\nwant\n%s", got, egressACanonical)
	}
	sum := sha256.Sum256([]byte(egressACanonical))
	if got, want := netprofile.Digest(a), "sha256:"+hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("Digest = %s, want %s", got, want)
	}
	if f.Default != "" {
		t.Fatalf("Default = %q", f.Default)
	}
	if _, ok := f.Lookup("egress-c"); ok {
		t.Fatal("egress-c found")
	}
	var nilFile *netprofile.File
	if _, ok := nilFile.Lookup("egress-a"); ok || nilFile.Names() != nil {
		t.Fatal("nil file has profiles")
	}
}

func TestParseTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		doc     string
		code    string
		subject string
		detail  string   // substring
		absent  []string // substrings that must not appear in the error
	}{
		{name: "empty document", doc: "", code: refusal.CodeProfileInvalid, subject: "network.toml", detail: "schema is required"},
		{name: "wrong schema", doc: "schema = \"relux-network-profiles-v2\"\n", code: refusal.CodeProfileInvalid, subject: "network.toml", detail: "schema must be"},
		{name: "only schema", doc: "schema = \"relux-network-profiles-v1\"\n"},
		{name: "syntax error", doc: "schema = \n", code: refusal.CodeFileUnreadable, subject: "network.toml", detail: "syntax error at line 1"},
		{name: "unknown top-level key", doc: "schema = \"relux-network-profiles-v1\"\nextra = 1\n", code: refusal.CodeProfileInvalid, subject: "network.toml", detail: "unknown key in catalog (count: 1)", absent: []string{"extra"}},
		{name: "unknown profile key", doc: "schema = \"relux-network-profiles-v1\"\n[networks.egress-a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\nproxy_password = \"hunter2\"\n", code: refusal.CodeProfileInvalid, subject: "egress-a", detail: "unknown key in [networks.egress-a] (count: 1)", absent: []string{"proxy_password", "hunter2"}},
		{name: "unknown secret top-level keys", doc: "schema = \"relux-network-profiles-v1\"\npw_secret = 1\npw_token = 2\n", code: refusal.CodeProfileInvalid, subject: "network.toml", detail: "unknown key in catalog (count: 2)", absent: []string{"pw"}},
		{name: "unknown key in unsafe profile name", doc: "schema = \"relux-network-profiles-v1\"\n[networks.\"u:pw@h\"]\npw_secret = 1\n", code: refusal.CodeProfileInvalid, subject: "network.toml", detail: "unknown key in catalog (count: 1)", absent: []string{"pw"}},
		{name: "multiple unknown keys in one profile", doc: "schema = \"relux-network-profiles-v1\"\n[networks.egress-a]\npw_secret = 1\npw_token = 2\n", code: refusal.CodeProfileInvalid, subject: "egress-a", detail: "unknown key in [networks.egress-a] (count: 2)", absent: []string{"pw"}},
		{name: "unknown keys across profiles", doc: "schema = \"relux-network-profiles-v1\"\n[networks.a]\npw_secret = 1\n[networks.b]\npw_token = 2\n", code: refusal.CodeProfileInvalid, subject: "network.toml", detail: "unknown key in catalog (count: 2)", absent: []string{"pw"}},
		{name: "type mismatch", doc: "schema = \"relux-network-profiles-v1\"\n[networks.egress-a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = \"localhost\"\n", code: refusal.CodeProfileInvalid, subject: "egress-a", detail: "networks.egress-a.bypass_hosts: wrong type"},
		{name: "bad name", doc: "schema = \"relux-network-profiles-v1\"\n[networks.Egress-A]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n", code: refusal.CodeProfileInvalid, subject: "Egress-A", detail: "name must match"},
		{name: "unknown kind", doc: "schema = \"relux-network-profiles-v1\"\n[networks.a]\nkind = \"socks5\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n", code: refusal.CodeProfileInvalid, subject: "a", detail: "kind is not supported"},
		{name: "missing kind", doc: "schema = \"relux-network-profiles-v1\"\n[networks.a]\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n", code: refusal.CodeProfileInvalid, subject: "a", detail: "kind is required"},
		{name: "credentials in endpoint never echoed", doc: "schema = \"relux-network-profiles-v1\"\n[networks.a]\nkind = \"external-http-proxy\"\nendpoint = \"http://alice:s3cret@127.0.0.1:1\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n", code: refusal.CodeProfileInvalid, subject: "a", detail: "userinfo", absent: []string{"s3cret"}},
		{name: "missing required bypass", doc: "schema = \"relux-network-profiles-v1\"\n[networks.a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\"]\n", code: refusal.CodeProfileInvalid, subject: "a", detail: "must include localhost, 127.0.0.1 and ::1"},
		{name: "star bypass", doc: "schema = \"relux-network-profiles-v1\"\n[networks.a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\", \"*\"]\n", code: refusal.CodeProfileInvalid, subject: "a", detail: "\"*\" is not allowed (it would disable the profile)"},
		{name: "default unknown", doc: "schema = \"relux-network-profiles-v1\"\ndefault = \"nope\"\n", code: refusal.CodeProfileInvalid, subject: "default", detail: "unknown profile"},
		{name: "default known", doc: "default = \"a\"\nschema = \"relux-network-profiles-v1\"\n[networks.a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n"},
		{name: "quoted dotted name", doc: "schema = \"relux-network-profiles-v1\"\n[networks.\"vpn.eu\"]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n"},
		{name: "probe target bad", doc: "schema = \"relux-network-profiles-v1\"\n[networks.a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\nprobe_target = \"nohost\"\n", code: refusal.CodeProfileInvalid, subject: "a", detail: "probe_target: must be host:port"},
		{name: "duplicate table", doc: "schema = \"relux-network-profiles-v1\"\n[networks.a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n[networks.a]\nkind = \"external-http-proxy\"\n", code: refusal.CodeProfileInvalid},
		{name: "networks not a table", doc: "schema = \"relux-network-profiles-v1\"\nnetworks = 1\n", code: refusal.CodeProfileInvalid, subject: "network.toml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, err := netprofile.Parse([]byte(tc.doc))
			if tc.code == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if f == nil {
					t.Fatal("nil file")
				}
				return
			}
			if f != nil {
				t.Fatalf("file returned beside error %v", err)
			}
			if got := code(t, err); got != tc.code {
				t.Fatalf("code = %s, want %s (%v)", got, tc.code, err)
			}
			r, _ := refusal.As(err)
			if tc.subject != "" && r.Subject != tc.subject {
				t.Errorf("subject = %q, want %q (%v)", r.Subject, tc.subject, err)
			}
			if tc.detail != "" && !strings.Contains(err.Error(), tc.detail) {
				t.Errorf("detail %q not in %q", tc.detail, err.Error())
			}
			for _, secret := range tc.absent {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("secret %q leaked into %q", secret, err.Error())
				}
			}
		})
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want, err string
	}{
		{"http://127.0.0.1:18081", "http://127.0.0.1:18081", ""},
		{"HTTP://LocalHost:8080/", "http://localhost:8080", ""},
		{"http://[2001:db8::1%25eth0]:18081", "", "IPv6 zones are not supported"},
		{"http://[::ffff:127.0.0.1]:18081", "http://127.0.0.1:18081", ""},
		{"http://[0:0:0:0:0:0:0:1]:3128", "http://[::1]:3128", ""},
		{"http://[::1]:3128", "http://[::1]:3128", ""},
		{"http://[2001:DB8::1]:3128/", "http://[2001:db8::1]:3128", ""},
		{"http://proxy.corp.invalid:03128", "http://proxy.corp.invalid:3128", ""},
		{"  http://127.0.0.1:1  ", "http://127.0.0.1:1", ""},
		{"", "", "endpoint is required"},
		{"127.0.0.1:18081", "", "scheme must be http"},
		{"https://127.0.0.1:18081", "", "scheme must be http"},
		{"socks5://127.0.0.1:1080", "", "scheme must be http"},
		{"http://127.0.0.1", "", "explicit port is required"},
		{"http://127.0.0.1:", "", "explicit port is required"},
		{"http://127.0.0.1:0", "", "port must be a number"},
		{"http://127.0.0.1:65536", "", "port must be a number"},
		{"http://127.0.0.1:abc", "", "not a valid URL"},
		{"http://user@127.0.0.1:1", "", "userinfo is not allowed"},
		{"http://user:pw@127.0.0.1:1", "", "userinfo is not allowed"},
		{"http://127.0.0.1:1/path", "", "path is not allowed"},
		{"http://127.0.0.1:1/?x=1", "", "query is not allowed"},
		{"http://127.0.0.1:1/#frag", "", "fragment is not allowed"},
		{"http://:1", "", "host is required"},
		{"http://bad_host:1", "", "host is not a valid host name"},
		{"http://-bad.example:1", "", "host is not a valid host name"},
		{"http://%zz:1", "", "not a valid URL"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := netprofile.NormalizeEndpoint(tc.in)
			if tc.err == "" {
				if err != nil || got != tc.want {
					t.Fatalf("NormalizeEndpoint(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("NormalizeEndpoint(%q) = %q, %v; want error %q", tc.in, got, err, tc.err)
			}
			if strings.Contains(err.Error(), "pw") && strings.Contains(tc.in, "pw@") {
				t.Fatalf("credential echoed: %v", err)
			}
		})
	}
}

func TestNormalizeBypassHosts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []string
		want string
		err  string
	}{
		{"spec order", []string{"localhost", "127.0.0.1", "::1"}, "127.0.0.1,::1,localhost", ""},
		{"case and dupes", []string{"LocalHost", "::1", "127.0.0.1", " localhost ", "Engine.Example"}, "127.0.0.1,::1,engine.example,localhost", ""},
		{"suffix, cidr, port", []string{".corp.invalid", "192.0.2.0/24", "[::1]:11434", "localhost", "127.0.0.1", "::1"}, ".corp.invalid,127.0.0.1,192.0.2.0/24,::1,[::1]:11434,localhost", ""},
		{"empty", []string{"localhost", ""}, "", "empty entry"},
		{"star", []string{"*"}, "", "\"*\" is not allowed (it would disable the profile)"},
		{"comma", []string{"a,b"}, "", "comma or whitespace"},
		{"inner space", []string{"a b"}, "", "comma or whitespace"},
		{"charset", []string{"a;b"}, "", "outside"},
		{"nil ok", nil, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := netprofile.NormalizeBypassHosts(tc.in)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, ",") != tc.want {
				t.Fatalf("got %v, want %s", got, tc.want)
			}
		})
	}
	with := netprofile.WithRequiredBypass([]string{"LOCALHOST", "engine.example"})
	if strings.Join(with, ",") != "LOCALHOST,engine.example,127.0.0.1,::1" {
		t.Fatalf("WithRequiredBypass = %v", with)
	}
	if got := netprofile.WithRequiredBypass(nil); strings.Join(got, ",") != "127.0.0.1,::1,localhost" {
		t.Fatalf("WithRequiredBypass(nil) = %v", got)
	}
}

func TestNormalizeProfile(t *testing.T) {
	t.Parallel()
	p, err := netprofile.Normalize("egress-a", netprofile.Input{
		Kind:        " external-http-proxy ",
		Endpoint:    "HTTP://127.0.0.1:18081/",
		BypassHosts: []string{"LocalHost", "::1", "127.0.0.1", "localhost"},
		ProbeTarget: "Probe.Invalid:443",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.ProbeTarget != "probe.invalid:443" || p.Endpoint != "http://127.0.0.1:18081" {
		t.Fatalf("profile = %+v", p)
	}
	if _, err := netprofile.Normalize("egress-a", netprofile.Input{Kind: "external-http-proxy", Endpoint: "http://127.0.0.1:1", BypassHosts: []string{"localhost", "127.0.0.1", "::1"}, ProbeTarget: "[::1]:443"}); err != nil {
		t.Fatalf("ipv6 probe target: %v", err)
	}
	for _, name := range []string{"", "A", "-a", "a b", strings.Repeat("a", 64), "a/b"} {
		if err := netprofile.ValidateName(name); err == nil {
			t.Errorf("ValidateName(%q) accepted", name)
		} else if c, _ := refusal.CodeOf(err); c != refusal.CodeProfileInvalid {
			t.Errorf("ValidateName(%q) code %s", name, c)
		}
	}
	for _, name := range []string{"a", "egress-a", "vpn.eu_1", strings.Repeat("a", 63), "0"} {
		if err := netprofile.ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v", name, err)
		}
	}
}

func TestDigestExclusions(t *testing.T) {
	t.Parallel()
	base := netprofile.Profile{Name: "egress-a", Kind: "external-http-proxy", Endpoint: "http://127.0.0.1:18081", BypassHosts: []string{"127.0.0.1", "::1", "localhost"}, CredentialMode: "none"}
	renamed := base
	renamed.Name = "other"
	probed := base
	probed.ProbeTarget = "probe.invalid:443"
	if netprofile.Digest(renamed) != netprofile.Digest(base) || netprofile.Digest(probed) != netprofile.Digest(base) {
		t.Fatal("name or probe_target changed the digest")
	}
	changed := base
	changed.Endpoint = "http://127.0.0.1:18082"
	if netprofile.Digest(changed) == netprofile.Digest(base) {
		t.Fatal("endpoint change kept the digest")
	}
	hosts := base
	hosts.BypassHosts = append([]string{"engine.example"}, base.BypassHosts...)
	if netprofile.Digest(hosts) == netprofile.Digest(base) {
		t.Fatal("bypass change kept the digest")
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(netprofile.Digest(base)) {
		t.Fatalf("digest form: %s", netprofile.Digest(base))
	}
	if got := netprofile.ShortDigest(netprofile.Digest(base)); len(got) != len("sha256:")+12 || !strings.HasPrefix(netprofile.Digest(base), got) {
		t.Fatalf("ShortDigest = %s", got)
	}
	if netprofile.ShortDigest("weird") != "weird" {
		t.Fatal("ShortDigest altered a malformed digest")
	}
	empty := netprofile.Profile{}
	if got := string(netprofile.Canonical(empty)); !strings.HasPrefix(got, `{"bypass_hosts":[],"credential_mode":"none",`) {
		t.Fatalf("empty canonical = %s", got)
	}
}

func TestHostKeyAndCovers(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"127.0.0.1": "127.0.0.1", "LOCALHOST": "localhost", "[::1]": "::1", "::1": "::1",
		"[::1]:11434": "::1", "localhost:11434": "localhost", " engine.example ": "engine.example", "": "",
	} {
		if got := netprofile.HostKey(in); got != want {
			t.Errorf("HostKey(%q) = %q, want %q", in, got, want)
		}
	}
	p := netprofile.Profile{BypassHosts: []string{"127.0.0.1", "::1", "localhost", ".corp.invalid"}}
	for host, want := range map[string]bool{
		"127.0.0.1": true, "LOCALHOST": true, "[::1]:11434": true, "::1": true,
		"engine.example": false, "x.corp.invalid": false, "": false, "127.0.0.2": false,
	} {
		if got := p.Covers(host); got != want {
			t.Errorf("Covers(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestRefusalsAreTyped(t *testing.T) {
	t.Parallel()
	_, err := netprofile.Parse([]byte("schema = 1\n"))
	var r *refusal.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("not a refusal: %v", err)
	}
}

func TestDecodeErrorsAreSanitized(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ doc, detail string }{
		{"schema = [\"private-value\"]\n", "schema: wrong type"},
		{strings.Replace(specFile, `endpoint     = "http://127.0.0.1:18081"`, `endpoint = ["private-value"]`, 1), "networks.egress-a.endpoint: wrong type"},
		{"schema = \"private-value\n", "syntax error at line 1"},
	} {
		_, err := netprofile.Parse([]byte(tc.doc))
		if err == nil || !strings.Contains(err.Error(), tc.detail) {
			t.Fatalf("error = %v, want %s", err, tc.detail)
		}
		for _, leak := range []string{"netprofile.raw", "struct field", "private-value"} {
			if strings.Contains(err.Error(), leak) {
				t.Fatalf("leak: %v", err)
			}
		}
	}
}
