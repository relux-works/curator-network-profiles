// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"os"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/internal/store"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

func TestBindingTextEdits(t *testing.T) {
	for _, table := range []string{"[bindings.profiles]", "[ 'bindings' . \"profiles\" ] # defaults"} {
		for _, key := range []string{"\"work.dev\"", "'work.dev'"} {
			p := paths(t)
			doc := seeded + "\n" + table + "\n# keep this comment\n" + key + " = 'egress-a' # keep inline\nother = \"egress-b\"\n"
			seed(t, p, doc)
			if err := store.Edit(p, func(e *store.Editor) error { return e.Bind("work.dev", "egress-b") }); err != nil {
				t.Fatal(err)
			}
			f, raw, err := store.Read(p)
			if err != nil || f.Bindings.Profiles["work.dev"] != "egress-b" || f.Bindings.Profiles["other"] != "egress-b" {
				t.Fatalf("bindings: %+v %v", f, err)
			}
			if !strings.HasPrefix(string(raw), seeded) || !strings.Contains(string(raw), "# keep this comment") || !strings.Contains(string(raw), "# keep inline") {
				t.Fatal("edit lost unrelated bytes or comments")
			}
			if err := store.Edit(p, func(e *store.Editor) error { return e.Unbind("work.dev") }); err != nil {
				t.Fatal(err)
			}
			f, raw, err = store.Read(p)
			if err != nil || len(f.Bindings.Profiles) != 1 || f.Bindings.Profiles["other"] != "egress-b" || !strings.Contains(string(raw), "# keep this comment") {
				t.Fatalf("unbind: %s %v", raw, err)
			}
		}
	}
}

func TestBindingEditsRefuseUnsupportedLayouts(t *testing.T) {
	for _, doc := range []string{
		"schema = \"relux-network-profiles-v1\"\nbindings = {profiles = {work = \"egress-a\"}}\n[networks.egress-a]\nkind = \"direct\"\n[networks.egress-b]\nkind = \"direct\"\n",
		"schema = \"relux-network-profiles-v1\"\nbindings = {profiles = {}}\n[networks.egress-b]\nkind = \"direct\"\n",
		"schema = \"relux-network-profiles-v1\"\nbindings = {}\n[networks.egress-b]\nkind = \"direct\"\n",
		seeded + "\n[bindings]\nprofiles = {}\n",
		"schema = \"relux-network-profiles-v1\"\nbindings.profiles = {}\n[networks.egress-b]\nkind = \"direct\"\n",
		seeded + "\n[bindings.profiles]\nwork = \"\"\"egress-a\"\"\"\n",
	} {
		p := paths(t)
		seed(t, p, doc)
		if _, _, err := store.Read(p); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{p.Backup, p.Ledger} {
			if err := os.WriteFile(path, []byte("preserve these bytes"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		err := store.Edit(p, func(e *store.Editor) error { return e.Bind("work", "egress-b") })
		if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileInvalid || !strings.Contains(err.Error(), "edit the file by hand") {
			t.Fatalf("unsupported layout: %v", err)
		}
		got, err := os.ReadFile(p.File)
		if err != nil || string(got) != doc {
			t.Fatal("unsupported layout was modified")
		}
		for _, path := range []string{p.Backup, p.Ledger} {
			got, err := os.ReadFile(path)
			if err != nil || string(got) != "preserve these bytes" {
				t.Fatal("unsupported layout changed backup or ledger")
			}
		}
	}
}
