// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/internal/store"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

const seeded = `# operator notes stay
schema = "relux-network-profiles-v1"   # trailing comment
default = "egress-a"

[networks.egress-a]   # the first egress
kind         = "external-http-proxy"
endpoint     = "http://127.0.0.1:18081"
bypass_hosts = ["localhost", "127.0.0.1", "::1"]

# a comment between tables

[networks.egress-b]
kind         = "external-http-proxy"
endpoint     = "http://127.0.0.1:18082"
bypass_hosts = ["localhost", "127.0.0.1", "::1"]
`

func paths(t *testing.T) store.Paths {
	t.Helper()
	home := t.TempDir()
	p, err := store.PathsFromEnv([]string{"PATH=/bin", "HOME=" + home})
	if err != nil {
		t.Fatal(err)
	}
	if p.Dir != filepath.Join(home, ".curator") || filepath.Base(p.File) != "network.toml" || filepath.Base(p.Backup) != "network.toml.bak" || filepath.Base(p.Ledger) != "network.confirmations.json" {
		t.Fatalf("paths = %+v", p)
	}
	return p
}

func seed(t *testing.T, p store.Paths, doc string) {
	t.Helper()
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.File, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

func profile(t *testing.T, name, endpoint string, hosts []string, target string) netprofile.Profile {
	t.Helper()
	p, err := netprofile.Normalize(name, netprofile.Input{Kind: "external-http-proxy", Endpoint: endpoint, BypassHosts: netprofile.WithRequiredBypass(hosts), ProbeTarget: target})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPathsNeedHome(t *testing.T) {
	t.Parallel()
	for _, env := range [][]string{nil, {"HOME="}, {"home=/x"}, {"HOME= "}} {
		_, err := store.PathsFromEnv(env)
		if c, _ := refusal.CodeOf(err); c != refusal.CodeFileUnreadable {
			t.Fatalf("env %v: %v", env, err)
		}
	}
}

func TestReadAbsentAndBroken(t *testing.T) {
	t.Parallel()
	p := paths(t)
	f, data, err := store.Read(p)
	if f != nil || data != nil || err != nil {
		t.Fatalf("absent: %v %v %v", f, data, err)
	}
	seed(t, p, "schema = \n")
	if _, _, err := store.Read(p); err == nil {
		t.Fatal("broken file read")
	} else if c, _ := refusal.CodeOf(err); c != refusal.CodeFileUnreadable {
		t.Fatalf("code = %s", c)
	}
	if err := os.Remove(p.File); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.File, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Read(p); err == nil {
		t.Fatal("directory read as a file")
	} else if c, _ := refusal.CodeOf(err); c != refusal.CodeFileUnreadable {
		t.Fatalf("code = %s (%v)", c, err)
	}
}

func TestAddCreatesFileWithModes(t *testing.T) {
	t.Parallel()
	p := paths(t)
	prof := profile(t, "egress-a", "http://127.0.0.1:18081", nil, "probe.invalid:443")
	if err := store.Add(p, prof); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p.File)
	if err != nil {
		t.Fatal(err)
	}
	want := "schema = \"relux-network-profiles-v1\"\n\n[networks.egress-a]\nkind         = \"external-http-proxy\"\nendpoint     = \"http://127.0.0.1:18081\"\nbypass_hosts = [\"127.0.0.1\", \"::1\", \"localhost\"]\nprobe_target = \"probe.invalid:443\"\n"
	if string(data) != want {
		t.Fatalf("file =\n%s\nwant\n%s", data, want)
	}
	di, _ := os.Stat(p.Dir)
	fi, _ := os.Stat(p.File)
	if di.Mode().Perm() != 0o700 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("modes dir=%v file=%v", di.Mode(), fi.Mode())
	}
	if _, err := os.Stat(p.Backup); !os.IsNotExist(err) {
		t.Fatal("backup written for a new file")
	}
	if err := store.Add(p, prof); err == nil {
		t.Fatal("duplicate add accepted")
	} else if c, _ := refusal.CodeOf(err); c != refusal.CodeConfigurationConflict {
		t.Fatalf("code = %s", c)
	}
	f, _, err := store.Read(p)
	if err != nil || len(f.Networks) != 1 {
		t.Fatalf("read back: %v %v", f, err)
	}
}

func TestAddPreservesBytesAndBacksUp(t *testing.T) {
	t.Parallel()
	p := paths(t)
	seed(t, p, seeded)
	prof := profile(t, "vpn.eu", "HTTP://[::1]:3128/", []string{"Engine.Example"}, "")
	if err := store.Add(p, prof); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p.File)
	if !strings.HasPrefix(string(data), seeded) {
		t.Fatalf("prefix changed:\n%s", data)
	}
	tail := strings.TrimPrefix(string(data), seeded)
	want := "\n[networks.\"vpn.eu\"]\nkind         = \"external-http-proxy\"\nendpoint     = \"http://[::1]:3128\"\nbypass_hosts = [\"127.0.0.1\", \"::1\", \"engine.example\", \"localhost\"]\n"
	if tail != want {
		t.Fatalf("appended =\n%q\nwant\n%q", tail, want)
	}
	bak, err := os.ReadFile(p.Backup)
	if err != nil || string(bak) != seeded {
		t.Fatalf("backup: %v %q", err, bak)
	}
	bi, _ := os.Stat(p.Backup)
	if bi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %v", bi.Mode())
	}
	f, _, err := store.Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := f.Lookup("vpn.eu"); !ok || got.Endpoint != "http://[::1]:3128" {
		t.Fatalf("vpn.eu = %+v, %v", got, ok)
	}
}

func TestAddWithoutTrailingNewline(t *testing.T) {
	t.Parallel()
	p := paths(t)
	seed(t, p, "schema = \"relux-network-profiles-v1\"")
	if err := store.Add(p, profile(t, "a", "http://127.0.0.1:1", nil, "")); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p.File)
	if !strings.HasPrefix(string(data), "schema = \"relux-network-profiles-v1\"\n\n[networks.a]\n") {
		t.Fatalf("file =\n%s", data)
	}
}

func TestAddRefusesBrokenFile(t *testing.T) {
	t.Parallel()
	p := paths(t)
	seed(t, p, "schema = \"relux-network-profiles-v1\"\nbogus = 1\n")
	err := store.Add(p, profile(t, "a", "http://127.0.0.1:1", nil, ""))
	if c, _ := refusal.CodeOf(err); c != refusal.CodeProfileInvalid {
		t.Fatalf("err = %v", err)
	}
	data, _ := os.ReadFile(p.File)
	if string(data) != "schema = \"relux-network-profiles-v1\"\nbogus = 1\n" {
		t.Fatal("broken file was rewritten")
	}
}

func TestRemovePreservesEverythingElse(t *testing.T) {
	t.Parallel()
	p := paths(t)
	seed(t, p, seeded)
	if err := store.Remove(p, "egress-b"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p.File)
	want := strings.TrimSuffix(seeded, "[networks.egress-b]\nkind         = \"external-http-proxy\"\nendpoint     = \"http://127.0.0.1:18082\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n")
	if string(data) != want {
		t.Fatalf("after remove =\n%q\nwant\n%q", data, want)
	}
	bak, _ := os.ReadFile(p.Backup)
	if string(bak) != seeded {
		t.Fatal("backup is not the previous bytes")
	}
	// Removing the first table keeps the comment block between tables.
	seed(t, p, seeded)
	if err := store.Remove(p, "egress-a"); err == nil {
		t.Fatal("removed the operator default")
	} else if c, _ := refusal.CodeOf(err); c != refusal.CodeConfigurationConflict {
		t.Fatalf("code = %s", c)
	}
	noDefault := strings.Replace(seeded, "default = \"egress-a\"\n", "", 1)
	seed(t, p, noDefault)
	if err := store.Remove(p, "egress-a"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(p.File)
	want = "# operator notes stay\nschema = \"relux-network-profiles-v1\"   # trailing comment\n\n\n# a comment between tables\n\n[networks.egress-b]\nkind         = \"external-http-proxy\"\nendpoint     = \"http://127.0.0.1:18082\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n"
	if string(data) != want {
		t.Fatalf("after removing the first table =\n%q\nwant\n%q", data, want)
	}
}

func TestRemoveRefusals(t *testing.T) {
	t.Parallel()
	p := paths(t)
	if err := store.Remove(p, "egress-a"); err == nil {
		t.Fatal("removed from an absent file")
	} else if c, _ := refusal.CodeOf(err); c != refusal.CodeProfileUnknown {
		t.Fatalf("code = %s", c)
	}
	seed(t, p, seeded)
	if err := store.Remove(p, "nope"); err == nil {
		t.Fatal("removed an unknown profile")
	} else if c, _ := refusal.CodeOf(err); c != refusal.CodeProfileUnknown {
		t.Fatalf("code = %s", c)
	}
	inline := "schema = \"relux-network-profiles-v1\"\n[networks]\nx = { kind = \"external-http-proxy\", endpoint = \"http://127.0.0.1:1\", bypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"] }\n"
	seed(t, p, inline)
	if err := store.Remove(p, "x"); err == nil {
		t.Fatal("removed an inline-table profile by guessing")
	} else if c, _ := refusal.CodeOf(err); c != refusal.CodeProfileInvalid {
		t.Fatalf("code = %s (%v)", c, err)
	}
	data, _ := os.ReadFile(p.File)
	if string(data) != inline {
		t.Fatal("file changed on a refused remove")
	}
}

func TestRemoveQuotedAndSpacedHeaders(t *testing.T) {
	t.Parallel()
	p := paths(t)
	doc := "schema = \"relux-network-profiles-v1\"\n[ networks . \"vpn.eu\" ] # eu\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n[networks.b]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:2\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n"
	seed(t, p, doc)
	if err := store.Remove(p, "vpn.eu"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p.File)
	if string(data) != "schema = \"relux-network-profiles-v1\"\n[networks.b]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:2\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n" {
		t.Fatalf("got %q", data)
	}
}
