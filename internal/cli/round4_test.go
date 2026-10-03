// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/internal/confirm"
)

func TestRemoveConfirmedDefaultPreservesFiles(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "human", true: "json"}[jsonMode], func(t *testing.T) {
			h := newHarness(t)
			h.writeFile(twoProfiles)
			h.confirmAll()
			paths := []string{filepath.Join(h.home, ".curator", "network.toml"), filepath.Join(h.home, ".curator", "network.confirmations.json")}
			before := make([][]byte, len(paths))
			for i, path := range paths {
				var err error
				before[i], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"remove", "egress-b"}
			if jsonMode {
				args = append(args, "--json")
			}
			code, stdout, stderr := h.run(args...)
			if code != 1 || !strings.Contains(stderr, "network_configuration_conflict") {
				t.Fatalf("remove default: %d %q %q", code, stdout, stderr)
			}
			if jsonMode && decode(t, stdout)["error"].(map[string]any)["code"] != "network_configuration_conflict" {
				t.Fatal("wrong JSON refusal")
			}
			for i, path := range paths {
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before[i], after) {
					t.Errorf("remove default changed %s", filepath.Base(path))
				}
			}
		})
	}
}

func TestDoubleDashEndsVerbFlagParsing(t *testing.T) {
	for _, args := range [][]string{{"show", "--", "a", "--json"}, {"show", "a", "--", "--json"}} {
		h := newHarness(t)
		code, stdout, stderr := h.run(args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "show: unexpected operand") {
			t.Errorf("%q: %d %q %q", args, code, stdout, stderr)
		}
	}
}

func TestRemoveAbsentCatalogCreatesNothing(t *testing.T) {
	for _, existingDir := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent directory", true: "existing directory"}[existingDir], func(t *testing.T) {
			h := newHarness(t)
			dir := filepath.Join(h.home, ".curator")
			lock := filepath.Join(dir, "network.toml.lock")
			if existingDir {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				// A pre-existing lock must not be consulted or changed for a read-only refusal.
				if err := os.WriteFile(lock, []byte("held"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			code, stdout, stderr := h.run("remove", "absent", "--json")
			if code != 1 || !strings.Contains(stderr, "network_profile_unknown") || decode(t, stdout)["error"].(map[string]any)["code"] != "network_profile_unknown" {
				t.Fatalf("absent remove: %d %q %q", code, stdout, stderr)
			}
			if !existingDir {
				if _, err := os.Lstat(dir); !os.IsNotExist(err) {
					t.Fatalf("remove created catalog directory: %v", err)
				}
			} else {
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 1 || entries[0].Name() != "network.toml.lock" {
					t.Fatalf("remove created files: %v", entries)
				}
				data, err := os.ReadFile(lock)
				if err != nil || string(data) != "held" {
					t.Fatalf("remove changed existing lock: %q %v", data, err)
				}
			}
		})
	}
}

func TestExecSanitizesEntrypoint(t *testing.T) {
	for _, tc := range []struct{ command, want string }{
		{"/private/token/agent", "agent"},
		{"http://u:pw@h:1", "<command>"},
		{"u:pw@h:1", "<command>"},
		{"", "<command>"},
		{strings.Repeat("a", 81), "<command>"},
		{"agent\nsecret", "<command>"},
	} {
		for _, jsonMode := range []bool{false, true} {
			h := newHarness(t)
			h.writeFile(twoProfiles)
			h.confirmAll()
			args := []string{"exec", "egress-a", "--dry-run", "--", tc.command, "secret-argument", "another-argument"}
			if jsonMode {
				args = append([]string{"--json"}, args...)
			}
			code, stdout, stderr := h.run(args...)
			if code != 0 || stderr != "" {
				t.Fatalf("dry run: %d %q", code, stderr)
			}
			if strings.Contains(stdout, "secret") || strings.Contains(stdout, "pw") || strings.Contains(stdout, "/private") || strings.Contains(stdout, "another-argument") {
				t.Error("dry run leaked command vector")
			}
			if jsonMode {
				doc := decode(t, stdout)
				identity := doc["binding"].(map[string]any)["adapter_identity"].(map[string]any)
				if doc["argc"] != float64(3) || doc["entrypoint"] != tc.want || identity["entrypoint"] != tc.want {
					t.Errorf("wrong sanitized identity/count: %v", doc)
				}
				if _, ok := doc["command"]; ok {
					t.Error("JSON contains command vector")
				}
			} else if !strings.Contains(stdout, "would exec "+tc.want+" (+2 args)\n") || !strings.Contains(stdout, "entrypoint="+tc.want+"\n") {
				t.Errorf("wrong sanitized human output: %q", stdout)
			}
		}
	}
}

func TestRealExecKeepsSecretCommandOutOfSummary(t *testing.T) {
	h := newHarness(t)
	h.writeFile(twoProfiles)
	h.confirmAll()
	command := h.tool("agent@secret")
	h.prober = &fakeProber{}
	code, stdout, stderr := h.run("exec", "egress-a", "--", command, "secret-argument")
	if code != 0 || stdout != "" || strings.Contains(stderr, "secret") || strings.Contains(stderr, command) {
		t.Fatalf("real exec summary: %d %q %q", code, stdout, stderr)
	}
	if len(h.exec.calls) != 1 || h.exec.calls[0].path != command || h.exec.calls[0].argv[0] != command || h.exec.calls[0].argv[1] != "secret-argument" {
		t.Fatal("real exec did not preserve command vector")
	}
}

func TestRemoveMissingCatalogCleansStaleConfirmation(t *testing.T) {
	h := newHarness(t)
	h.writeFile(twoProfiles)
	h.confirmAll()
	dir := filepath.Join(h.home, ".curator")
	if err := os.Remove(filepath.Join(dir, "network.toml")); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := h.run("remove", "egress-a", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("stale cleanup: %d %q %q", code, stdout, stderr)
	}
	doc := decode(t, stdout)
	if doc["removed"] != false || doc["confirmation_dropped"] != true {
		t.Fatalf("cleanup facts: %v", doc)
	}
	ledger, err := confirm.Read(filepath.Join(dir, "network.confirmations.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ledger.Entry("egress-a"); ok {
		t.Error("stale entry retained")
	}
	if _, ok := ledger.Entry("egress-b"); !ok {
		t.Error("other entry removed")
	}
	for _, path := range []string{"network.toml", "network.toml.lock"} {
		if _, err := os.Lstat(filepath.Join(dir, path)); !os.IsNotExist(err) {
			t.Fatalf("cleanup left %s: %v", path, err)
		}
	}
}
