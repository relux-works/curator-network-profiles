// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/internal/confirm"
)

func TestArgumentsNeverLeakInDiagnostics(t *testing.T) {
	const secret = "http://u:pw@h:1"
	cases := map[string][]string{
		"unknown verb":    {secret},
		"global option":   {"--" + secret},
		"version operand": {"--version", secret},
		"help operand":    {"help", secret},
	}
	for _, verb := range []string{"version", "list", "show", "add", "remove", "check", "confirm", "exec"} {
		args := []string{verb, secret}
		if verb == "add" {
			args = append(args, "--endpoint", "http://127.0.0.1:1")
		}
		if verb == "exec" {
			args = append(args, "--", "agent")
		}
		cases[verb+" operand"] = args
		extra := []string{verb, "egress-a", secret}
		if verb == "add" {
			extra = append(extra, "--endpoint", "http://127.0.0.1:1")
		}
		if verb == "exec" {
			extra = append(extra, "--", "agent")
		}
		cases[verb+" extra operand"] = extra
		cases[verb+" invalid json"] = []string{verb, "--json=pw"}
		cases[verb+" unknown flag"] = []string{verb, "--" + secret}
		if verb == "exec" {
			cases[verb+" invalid json"] = []string{verb, "--json=pw", "egress-a", "--", "agent"}
			cases[verb+" unknown flag"] = []string{verb, "--" + secret, "egress-a", "--", "agent"}
		}
	}
	for _, tc := range []struct{ verb, flag string }{
		{"add", "endpoint"}, {"add", "bypass"}, {"add", "probe-target"},
		{"check", "all"}, {"check", "probe"}, {"check", "target"}, {"check", "timeout"},
		{"exec", "preflight-timeout"}, {"exec", "dry-run"},
	} {
		for _, value := range []string{secret, "pw"} {
			args := []string{tc.verb, "--" + tc.flag + "=" + value}
			if tc.verb == "add" {
				args = append(args, "egress-c")
				if tc.flag != "endpoint" {
					args = append(args, "--endpoint", "http://127.0.0.1:1")
				}
				// A plain bypass host is valid; exercise it in an operand-count error.
				if tc.flag == "bypass" && value == "pw" {
					args = append(args, secret)
				}
			}
			if tc.verb == "exec" {
				args = append(args, "egress-a", "--", "agent")
			}
			cases[tc.verb+" "+tc.flag+" "+value] = args
		}
	}
	cases["exec missing command operand"] = []string{"exec", "egress-a", "--", secret}
	cases["exec dry run entrypoint"] = []string{"exec", "egress-a", "--dry-run", "--", secret, "argument"}
	cases["exec dry run argument"] = []string{"exec", "egress-a", "--dry-run", "--", "/private/pw/agent", secret}
	for name, args := range cases {
		for _, jsonMode := range []bool{false, true} {
			t.Run(name+map[bool]string{false: " human", true: " json"}[jsonMode], func(t *testing.T) {
				h := newHarness(t)
				h.writeFile(twoProfiles)
				h.confirmAll()
				h.terminal = true
				h.stdin = "yes\n"
				if jsonMode {
					args = append([]string{"--json"}, args...)
				}
				_, stdout, stderr := h.run(args...)
				for stream, output := range map[string]string{"stdout": stdout, "stderr": stderr} {
					for _, secret := range []string{"pw", "u:pw"} {
						if strings.Contains(output, secret) {
							t.Errorf("%s leaked %q", stream, secret)
						}
					}
				}
			})
		}
	}
}

func failedRemoval(t *testing.T) (*harness, string, string) {
	t.Helper()
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
	code, _, stderr := h.run("remove", "egress-a")
	if code != 1 || !strings.Contains(stderr, "cannot write") {
		t.Fatalf("remove: %d %s", code, stderr)
	}
	return h, path, target
}

func TestReaddAfterFailedLedgerWriteRequiresConfirmation(t *testing.T) {
	h, path, target := failedRemoval(t)
	// While cleanup still fails, re-add must not write the catalog.
	code, _, _ := h.run("add", "egress-a", "--endpoint", "http://127.0.0.1:18081", "--probe-target", "probe.invalid:443")
	if code != 1 {
		t.Errorf("re-add with unwritable ledger: exit %d, want 1", code)
	}
	data, err := os.ReadFile(filepath.Join(h.home, ".curator", "network.toml"))
	if err != nil || strings.Contains(string(data), "[networks.egress-a]") {
		t.Error("failed ledger cleanup widened the catalog")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(target, path); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := h.run("add", "egress-a", "--endpoint", "http://127.0.0.1:18081", "--probe-target", "probe.invalid:443")
	if code != 0 {
		t.Errorf("retry add: %d %s", code, stderr)
	}
	code, stdout, _ := h.run("show", "egress-a", "--json")
	if code != 0 || decode(t, stdout)["confirmation"].(map[string]any)["confirmed"] != false {
		t.Error("identical re-add reused stale confirmation")
	}
}

func TestRemoveCleansStaleConfirmation(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "human", true: "json"}[jsonMode], func(t *testing.T) {
			h, path, target := failedRemoval(t)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(target, path); err != nil {
				t.Fatal(err)
			}
			args := []string{"remove", "egress-a"}
			if jsonMode {
				args = append(args, "--json")
			}
			code, stdout, stderr := h.run(args...)
			if code != 0 || stderr != "" {
				t.Errorf("stale cleanup: %d %s", code, stderr)
			}
			if jsonMode && code == 0 {
				doc := decode(t, stdout)
				if doc["removed"] != false || doc["confirmation_dropped"] != true {
					t.Errorf("cleanup facts: %v", doc)
				}
			} else if !jsonMode && !strings.Contains(stdout, "dropped stale confirmation entry") {
				t.Errorf("unclear cleanup: %s", stdout)
			}
			ledger, err := confirm.Read(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := ledger.Entry("egress-a"); ok {
				t.Error("stale entry retained")
			}
			if _, ok := ledger.Entry("egress-b"); !ok {
				t.Error("other entry removed")
			}
		})
	}
}

func TestExecFailureDoesNotLeakCommandOrError(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		h := newHarness(t)
		h.writeFile(twoProfiles)
		h.confirmAll()
		h.tool("agent")
		h.prober = &fakeProber{}
		h.exec.err = fmt.Errorf("cannot execute http://u:pw@h:1")
		args := []string{"exec", "egress-a", "--", "agent"}
		if jsonMode {
			args = append([]string{"--json"}, args...)
		}
		code, stdout, stderr := h.run(args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "exec: cannot execute command") || strings.Contains(stderr, "pw") {
			t.Fatalf("unsanitized exec failure: exit %d", code)
		}
	}
}

func TestFlagErrorsUseRegisteredNames(t *testing.T) {
	for _, args := range [][]string{{"check", "--timeout", "pw"}, {"check", "--timeout=pw"}, {"check", "--timeout"}} {
		h := newHarness(t)
		code, stdout, stderr := h.run(args...)
		want := "invalid value for flag -timeout"
		if len(args) == 2 && args[1] == "--timeout" {
			want = "flag -timeout requires a value"
		}
		if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "curator-network: usage: check: "+want+"\n") {
			t.Fatalf("flag error: %d %q %q", code, stdout, stderr)
		}
	}
}

func TestAddCatalogFailureLeavesStaleConfirmationDeleted(t *testing.T) {
	h, path, target := failedRemoval(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(target, path); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(h.home, ".curator", "network.toml.bak")
	if err := os.Remove(backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(backup, 0700); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := h.run("add", "egress-a", "--endpoint", "http://127.0.0.1:18081", "--probe-target", "probe.invalid:443")
	if code != 1 || !strings.Contains(stderr, "cannot write the backup") {
		t.Fatalf("catalog failure: %d %s", code, stderr)
	}
	ledger, err := confirm.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ledger.Entry("egress-a"); ok {
		t.Error("catalog failure retained stale confirmation")
	}
	data, err := os.ReadFile(filepath.Join(h.home, ".curator", "network.toml"))
	if err != nil || strings.Contains(string(data), "[networks.egress-a]") {
		t.Error("failed catalog write added profile")
	}
}
