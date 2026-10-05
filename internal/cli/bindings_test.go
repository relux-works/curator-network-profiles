// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/internal/cli"
	"github.com/relux-works/curator-network-profiles/internal/confirm"
	"github.com/relux-works/curator-network-profiles/internal/store"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
)

func bindingBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBindUnbindAtomicEditsAndListings(t *testing.T) {
	h := newHarness(t)
	h.writeFile(twoProfiles)
	h.confirmAll()
	h.terminal, h.stdin = true, "yes\n"
	p := confirmPaths(t, h)
	ledger := bindingBytes(t, p.Ledger)
	for _, tc := range []struct {
		args   []string
		target string
	}{
		{[]string{"bind", "work.dev", "egress-a", "--json"}, "egress-a"},
		{[]string{"bind", "work.dev", "egress-b", "--json"}, "egress-b"},
		{[]string{"unbind", "work.dev", "--json"}, ""},
	} {
		before := bindingBytes(t, p.File)
		inode, err := os.Stat(p.File)
		if err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := h.run(tc.args...)
		if code != 0 || !strings.Contains(stderr, "Type `yes`") {
			t.Fatalf("edit: %d %q %q", code, stdout, stderr)
		}
		var doc struct {
			Schema         string
			OK             bool
			CuratorProfile string `json:"curator_profile"`
			Network        string
		}
		if err := json.Unmarshal([]byte(stdout), &doc); err != nil || !doc.OK || doc.CuratorProfile != "work.dev" || doc.Network != tc.target {
			t.Fatalf("JSON = %s, %v", stdout, err)
		}
		if doc.Schema != "curator-network-"+tc.args[0]+"-v1" {
			t.Fatalf("schema = %s", doc.Schema)
		}
		after, err := os.Stat(p.File)
		if err != nil || os.SameFile(inode, after) || after.Mode().Perm() != 0600 {
			t.Fatalf("catalog was not atomically replaced at 0600: %v", err)
		}
		if !bytes.Equal(bindingBytes(t, p.Backup), before) {
			t.Fatal("backup did not preserve previous bytes")
		}
		if !bytes.Equal(bindingBytes(t, p.Ledger), ledger) {
			t.Fatal("binding edit changed digest confirmation ledger")
		}
		f, raw, err := store.Read(p)
		if err != nil || f.Bindings.Profiles["work.dev"] != tc.target || !bytes.HasPrefix(raw, []byte(twoProfiles)) {
			t.Fatalf("edited catalog = %s, %v", raw, err)
		}
		assertConfirmUnlocked(t, p)
		matches, err := filepath.Glob(filepath.Join(p.Dir, ".*.tmp"))
		if err != nil || len(matches) != 0 {
			t.Fatalf("temporary files left: %v %v", matches, err)
		}
		if tc.target == "" {
			continue
		}
		for _, args := range [][]string{{"list", "--json"}, {"show", tc.target, "--json"}} {
			code, stdout, stderr := h.run(args...)
			var listing struct{ Bindings netprofile.Bindings }
			if err := json.Unmarshal([]byte(stdout), &listing); code != 0 || stderr != "" || err != nil || listing.Bindings.Profiles["work.dev"] != tc.target {
				t.Fatalf("listing: %d %s %s %v", code, stdout, stderr, err)
			}
		}
		for _, args := range [][]string{{"list"}, {"show", tc.target}} {
			code, stdout, stderr := h.run(args...)
			if code != 0 || stderr != "" || !strings.Contains(stdout, "work.dev -> "+tc.target) {
				t.Fatalf("human listing: %d %q %q", code, stdout, stderr)
			}
		}
		other := "egress-a"
		if tc.target == other {
			other = "egress-b"
		}
		_, stdout, _ = h.run("show", other, "--json")
		if strings.Contains(stdout, "work.dev") {
			t.Fatal("show included another network's binding")
		}
	}
}

func TestBindingGuardsAndRefusalsLeaveFilesUntouched(t *testing.T) {
	for _, unbind := range []bool{false, true} {
		for _, tc := range []struct {
			name, answer string
			terminal     bool
			code         string
		}{
			{"no terminal", "yes\n", false, "network_confirm_refused"},
			{"declined", "no\n", true, "network_confirm_refused"},
			{"eof", "", true, "network_confirm_refused"},
			{"held lock", "yes\n", true, "network_configuration_conflict"},
			{"backup failure", "yes\n", true, "network_file_unreadable"},
			{"symlink", "yes\n", true, "network_file_unreadable"},
		} {
			t.Run(map[bool]string{false: "bind", true: "unbind"}[unbind]+"/"+tc.name, func(t *testing.T) {
				h := newHarness(t)
				h.writeFile(twoProfiles + "\n[bindings.profiles]\nwork = \"egress-a\"\n")
				h.confirmAll()
				h.terminal, h.stdin = tc.terminal, tc.answer
				p := confirmPaths(t, h)
				before, ledger := bindingBytes(t, p.File), bindingBytes(t, p.Ledger)
				if tc.name == "held lock" {
					if err := os.WriteFile(p.File+".lock", []byte("owner"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if tc.name == "backup failure" {
					if err := os.Mkdir(p.Backup, 0700); err != nil {
						t.Fatal(err)
					}
				}
				if tc.name == "symlink" {
					if err := os.Rename(p.File, p.File+".target"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(p.File+".target", p.File); err != nil {
						t.Fatal(err)
					}
				}
				args := []string{"bind", "work", "egress-b"}
				if unbind {
					args = []string{"unbind", "work"}
				}
				code, _, stderr := h.run(args...)
				if code != 1 || !strings.Contains(stderr, tc.code) {
					t.Fatalf("refusal: %d %q", code, stderr)
				}
				if tc.name == "no terminal" && !strings.Contains(stderr, "run `curator network "+args[0]+"` from an operator terminal") {
					t.Fatalf("wrong guard recovery command: %q", stderr)
				}
				if !bytes.Equal(bindingBytes(t, p.File), before) || !bytes.Equal(bindingBytes(t, p.Ledger), ledger) {
					t.Fatal("refusal changed operator files")
				}
				if tc.name == "held lock" {
					if string(bindingBytes(t, p.File+".lock")) != "owner" {
						t.Fatal("changed another editor's lock")
					}
				} else {
					assertConfirmUnlocked(t, p)
				}
			})
		}
		for _, marker := range confirm.Markers {
			t.Run(map[bool]string{false: "bind", true: "unbind"}[unbind]+"/"+marker, func(t *testing.T) {
				h := newHarness(t)
				h.env = append(h.env, marker+"=")
				h.terminal, h.stdin = true, "yes\n"
				args := []string{"bind", "work", "egress-a"}
				if unbind {
					args = []string{"unbind", "work"}
				}
				code, _, stderr := h.run(args...)
				if code != 1 || !strings.Contains(stderr, "network_confirm_refused") {
					t.Fatalf("agent guard: %d %q", code, stderr)
				}
				if !strings.Contains(stderr, "run `curator network "+args[0]+"` from an operator terminal") {
					t.Fatalf("wrong guard recovery command: %q", stderr)
				}
				if _, err := os.Stat(filepath.Join(h.home, ".curator")); !os.IsNotExist(err) {
					t.Fatalf("guard created namespace: %v", err)
				}
			})
		}
	}
}

func TestBindingCatalogChangesDuringPrompt(t *testing.T) {
	for _, unbind := range []bool{false, true} {
		for _, changed := range []string{twoProfiles + "\n# concurrent edit\n", "malformed", ""} {
			h := newHarness(t)
			h.writeFile(twoProfiles + "\n[bindings.profiles]\nwork = \"egress-a\"\n")
			p := confirmPaths(t, h)
			args := []string{"bind", "work", "egress-b"}
			if unbind {
				args = []string{"unbind", "work"}
			}
			var stdout, stderr bytes.Buffer
			code := cli.Run(context.Background(), args, cli.Deps{Env: h.env, IsTerminal: func() bool { return true }, Stdout: &stdout, Stderr: &stderr, Prober: h.prober,
				Stdin: &onConfirmRead{answer: strings.NewReader("yes\n"), edit: func() {
					assertConfirmUnlocked(t, p)
					if changed == "" {
						if err := os.Remove(p.File); err != nil {
							t.Fatal(err)
						}
					} else {
						h.writeFile(changed)
					}
				}},
			})
			if code != 1 || !strings.Contains(stderr.String(), "catalog changed during binding confirmation") {
				t.Fatalf("concurrent edit: %d %q", code, stderr.String())
			}
			if changed != "" && string(bindingBytes(t, p.File)) != changed {
				t.Fatal("overwrote concurrent catalog")
			}
			if _, err := os.Stat(p.Backup); !os.IsNotExist(err) {
				t.Fatalf("refusal wrote backup: %v", err)
			}
			assertConfirmUnlocked(t, p)
		}
	}
}

func TestBindingUnknownNamesAndUsage(t *testing.T) {
	for _, tc := range []struct {
		args       []string
		code       int
		diagnostic string
	}{
		{[]string{"bind", "work", "missing"}, 1, "network_profile_unknown"},
		{[]string{"unbind", "missing"}, 1, "network_profile_unknown"},
		{[]string{"bind", "Work", "egress-a"}, 1, "network_profile_invalid"},
		{[]string{"bind", "work", "bad name"}, 1, "network_profile_invalid"},
		{[]string{"bind", "work"}, 2, "missing operand"},
		{[]string{"unbind", "work", "secret-value"}, 2, "unexpected operand"},
	} {
		h := newHarness(t)
		h.writeFile(twoProfiles)
		h.terminal, h.stdin = true, "yes\n"
		p := confirmPaths(t, h)
		code, _, stderr := h.run(tc.args...)
		if code != tc.code || !strings.Contains(stderr, tc.diagnostic) || strings.Contains(stderr, "secret-value") {
			t.Fatalf("refusal: %d %q", code, stderr)
		}
		if string(bindingBytes(t, p.File)) != twoProfiles {
			t.Fatal("refusal changed catalog")
		}
		if _, err := os.Stat(p.Backup); !os.IsNotExist(err) {
			t.Fatalf("refusal wrote backup: %v", err)
		}
	}
}

func TestBindDoesNotConfirmTargetAndUnbindCanRemoveDanglingTarget(t *testing.T) {
	h := newHarness(t)
	h.writeFile(twoProfiles)
	h.terminal, h.stdin = true, "yes\n"
	p := confirmPaths(t, h)
	code, _, stderr := h.run("bind", "work", "egress-a")
	if code != 0 || stderr != "" {
		t.Fatalf("bind unconfirmed target: %d %q", code, stderr)
	}
	if _, err := os.Stat(p.Ledger); !os.IsNotExist(err) {
		t.Fatalf("bind wrote a confirmation ledger: %v", err)
	}
	h.writeFile(twoProfiles + "\n[bindings.profiles]\nwork = \"missing\"\n")
	code, _, stderr = h.run("unbind", "work")
	if code != 0 || stderr != "" {
		t.Fatalf("unbind dangling target: %d %q", code, stderr)
	}
	f, _, err := store.Read(p)
	if err != nil || len(f.Bindings.Profiles) != 0 {
		t.Fatalf("dangling binding remained: %+v %v", f, err)
	}
}

func TestBindingListingsAlwaysIncludeEmptyMapUnderV1Schemas(t *testing.T) {
	for _, args := range [][]string{{"list", "--json"}, {"show", "egress-a", "--json"}} {
		h := newHarness(t)
		h.writeFile(twoProfiles)
		code, stdout, stderr := h.run(args...)
		if code != 0 || stderr != "" {
			t.Fatalf("listing: %d %q %q", code, stdout, stderr)
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
			t.Fatal(err)
		}
		if string(doc["schema"]) != `"curator-network-`+args[0]+`-v1"` || string(doc["bindings"]) != `{"profiles":{}}` {
			t.Fatalf("unexpected schema or empty bindings: %s", stdout)
		}
		// A strict pre-binding consumer can accept every old output field
		// and still reject this document, even with no operator bindings.
		var legacy struct {
			Schema, OK, Default, Profiles, Profile, Digest, Confirmation, Patch json.RawMessage
		}
		dec := json.NewDecoder(strings.NewReader(stdout))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&legacy); err == nil || !strings.Contains(err.Error(), `unknown field "bindings"`) {
			t.Fatalf("strict legacy decoder unexpectedly accepted output: %v", err)
		}
	}
}

func TestBindingParseRefusalsAreSafeAndDoNotWrite(t *testing.T) {
	for _, suffix := range []string{
		"[Bindings.profiles]\n\"/private/canary\" = 1\n",
		"[bindings.Profiles]\n\"u:canary@host\" = 1\n",
		"[bindings.profiles]\n\"canary\\ncontrol\" = 1\n",
		"[bindings.profiles]\n\"/private/canary\" = \"egress-a\"\n\"/private/canary\" = \"egress-b\"\n",
		"[bindings.paths]\n\"/private/canary\" = \"egress-a\"\n\"/private/canary\" = \"egress-a\"\n",
		"[Bindings.profiles]\nwork = \"egress-a\"\n",
		"[bindings.Profiles]\nwork = \"egress-a\"\n",
		"[bindings.Paths]\n",
		"[bindings.profiles]\nwork = \"missing\"\n[Bindings.profiles]\nwork = \"egress-a\"\n",
		"[Bindings.profiles]\nwork = \"egress-a\"\n[bindings.profiles]\nwork = \"missing\"\n",
		"[bindings.profiles]\nwork = \"missing\"\n[bindings.Profiles]\nwork = \"egress-a\"\n",
		"[bindings.Profiles]\nwork = \"egress-a\"\n[bindings.profiles]\nwork = \"missing\"\n",
		"[bindings.profiles]\nwork = \"bad name\"\n[Bindings.profiles]\nwork = \"egress-a\"\n",
		"[bindings.profiles]\nwork = \"missing\"\nwork = \"egress-a\"\n",
		"[\"b\\u0130ndings\".profiles]\nwork = \"egress-a\"\n",
		"[bindings.profiles]\nwork = \"missing\"\n[\"b\\u0130ndings\".profiles]\nwork = \"egress-a\"\n",
		"[\"b\\u0130ndings\".profiles]\nwork = \"egress-a\"\n[bindings.profiles]\nwork = \"missing\"\n",
		"[bindings.profiles]\nwork = \"bad name\"\n[\"b\\u0130ndings\".profiles]\nwork = \"egress-a\"\n",
		"[\"b\\u0130ndings\".Profiles]\nwork = \"egress-a\"\n",
		"[bindings.profiles]\n\"wor\\u212A\" = \"egress-a\"\n",
		"[bindings.profiles]\nwork = \"missing\"\nWork = \"egress-a\"\n",
	} {
		for _, jsonOutput := range []bool{false, true} {
			for _, verb := range []string{"bind", "unbind"} {
				t.Run(verb+"/"+suffix+map[bool]string{false: "human", true: "json"}[jsonOutput], func(t *testing.T) {
					h := newHarness(t)
					h.writeFile(twoProfiles)
					h.confirmAll()
					h.terminal, h.stdin = true, "yes\n"
					p := confirmPaths(t, h)
					if err := os.WriteFile(p.Backup, []byte("preserve backup"), 0600); err != nil {
						t.Fatal(err)
					}
					ledger := bindingBytes(t, p.Ledger)
					doc := twoProfiles + "\n" + suffix
					h.writeFile(doc)
					args := []string{verb, "work"}
					if verb == "bind" {
						args = append(args, "egress-a")
					}
					if jsonOutput {
						args = append(args, "--json")
					}
					code, stdout, stderr := h.run(args...)
					if code != 1 || !strings.Contains(stdout+stderr, "network_profile_invalid") {
						t.Fatalf("refusal: %d %q %q", code, stdout, stderr)
					}
					if strings.Contains(stdout+stderr, "canary") || strings.Contains(stdout+stderr, "/private/") || strings.Contains(stdout+stderr, "Type `yes`") {
						t.Fatalf("unsafe output or prompt: %q %q", stdout, stderr)
					}
					if jsonOutput && !json.Valid([]byte(stdout)) {
						t.Fatalf("invalid JSON refusal: %q", stdout)
					}
					if string(bindingBytes(t, p.File)) != doc || string(bindingBytes(t, p.Backup)) != "preserve backup" || !bytes.Equal(bindingBytes(t, p.Ledger), ledger) {
						t.Fatal("parse refusal changed operator files")
					}
					assertConfirmUnlocked(t, p)
				})
			}
		}
	}
}

func TestBindEmptyInlineTablesGiveManualEditInstruction(t *testing.T) {
	for _, doc := range []string{
		"schema = \"relux-network-profiles-v1\"\nbindings = {profiles = {}}\n[networks.direct]\nkind = \"direct\"\n",
		"schema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\n[bindings]\nprofiles = {}\n",
	} {
		for _, jsonOutput := range []bool{false, true} {
			h := newHarness(t)
			h.writeFile(doc)
			h.terminal, h.stdin = true, "yes\n"
			p := confirmPaths(t, h)
			for _, path := range []string{p.Backup, p.Ledger} {
				if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"bind", "work", "direct"}
			if jsonOutput {
				args = append(args, "--json")
			}
			code, stdout, stderr := h.run(args...)
			if code != 1 || !strings.Contains(stdout+stderr, "network_profile_invalid") || !strings.Contains(stdout+stderr, "edit the file by hand") {
				t.Fatalf("layout refusal: %d %q %q", code, stdout, stderr)
			}
			if string(bindingBytes(t, p.File)) != doc || string(bindingBytes(t, p.Backup)) != "preserve" || string(bindingBytes(t, p.Ledger)) != "preserve" {
				t.Fatal("layout refusal changed operator files")
			}
			assertConfirmUnlocked(t, p)
		}
	}
}
