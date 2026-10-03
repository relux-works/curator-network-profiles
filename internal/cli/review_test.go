// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecInvalidNameDoesNotSelectDefault(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", " ", "egress-b ", "Egress-B"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.writeFile(twoProfiles)
			h.confirmAll()
			h.tool("agent")
			code, stdout, stderr := h.run("exec", name, "--", "agent")
			if code != 2 || stdout != "" || !strings.Contains(stderr, "usage: exec:") || len(h.exec.calls) != 0 {
				t.Fatalf("invalid name: %d %q %q", code, stdout, stderr)
			}
		})
	}
}

func TestExecMissingCommandDoesNotProbe(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"missing-tool", "", "/no/such/tool"} {
		t.Run(command, func(t *testing.T) {
			h := newHarness(t)
			h.writeFile(twoProfiles)
			h.confirmAll()
			code, _, stderr := h.run("exec", "egress-b", "--", command)
			if code != 2 || !strings.Contains(stderr, "usage: exec:") || len(h.exec.calls) != 0 {
				t.Fatalf("missing command: %d %q", code, stderr)
			}
		})
	}
}

func TestVersionJSONFlagOrders(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"--version", "--json"}, {"--json", "--version"}, {"-V", "--json"}, {"version", "--json"}} {
		h := newHarness(t)
		code, stdout, stderr := h.run(args...)
		if code != 0 || stderr != "" {
			t.Fatalf("%v: %d %q", args, code, stderr)
		}
		doc := decode(t, stdout)
		if doc["schema"] != "curator-network-version-v1" || doc["ok"] != true {
			t.Fatalf("%v: %v", args, doc)
		}
	}
}

func TestRemoveBrokenLedgerLeavesCatalogAndBackupUntouched(t *testing.T) {
	t.Parallel()
	for _, data := range []string{"{", `{"schema":"wrong","confirmed":{}}`} {
		h := newHarness(t)
		h.writeFile(twoProfiles)
		ledger := filepath.Join(h.home, ".curator", "network.confirmations.json")
		if err := os.WriteFile(ledger, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := h.run("remove", "egress-a")
		if code != 1 || !strings.Contains(stderr, "network_file_unreadable") {
			t.Fatalf("remove: %d %q", code, stderr)
		}
		got, err := os.ReadFile(filepath.Join(h.home, ".curator", "network.toml"))
		if err != nil || string(got) != twoProfiles {
			t.Fatalf("catalog changed: %v %q", err, got)
		}
		if _, err := os.Stat(filepath.Join(h.home, ".curator", "network.toml.bak")); !os.IsNotExist(err) {
			t.Fatal("backup changed before ledger validation")
		}
	}
}

func TestRemoveLedgerWriteFailureKeepsNarrowing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile(twoProfiles)
	h.confirmAll()
	path := filepath.Join(h.home, ".curator", "network.confirmations.json")
	target := path + ".target"
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	code, _, stderr := h.run("remove", "egress-a")
	if code != 1 || !strings.Contains(stderr, "network_file_unreadable: network.confirmations.json: cannot write") {
		t.Fatalf("remove write refusal: %d %q", code, stderr)
	}
	catalog, err := os.ReadFile(filepath.Join(h.home, ".curator", "network.toml"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := netprofile.Parse(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Lookup("egress-a"); ok {
		t.Fatal("catalog removal was rolled back")
	}
	after, err := os.ReadFile(target)
	if err != nil || string(after) != string(before) {
		t.Fatal("ledger target changed")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("ledger symlink replaced")
	}
	backup, err := os.ReadFile(filepath.Join(h.home, ".curator", "network.toml.bak"))
	if err != nil || string(backup) != twoProfiles {
		t.Fatal("backup missing")
	}
	if _, err := os.Stat(filepath.Join(h.home, ".curator", "network.toml.lock")); !os.IsNotExist(err) {
		t.Fatal("lock left after second-write failure")
	}
	h.tool("agent")
	code, _, stderr = h.run("exec", "egress-a", "--", "agent")
	if code != 1 || !strings.Contains(stderr, "network_profile_unknown") {
		t.Fatalf("stale entry authorized missing profile: %d %q", code, stderr)
	}
}
