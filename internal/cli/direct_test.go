// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddDirectConflicts(t *testing.T) {
	for _, flag := range []string{"--endpoint=http://127.0.0.1:1", "--endpoint=", "--bypass=localhost", "--bypass=", "--probe-target=127.0.0.1:1", "--probe-target="} {
		t.Run(flag, func(t *testing.T) {
			h := newHarness(t)
			code, out, diag := h.run("--json", "add", "direct", "--direct", flag)
			if code != 2 || out != "" || !strings.Contains(diag, "--direct conflicts with") {
				t.Fatalf("code %d: %s %s", code, out, diag)
			}
			if _, err := os.Stat(filepath.Join(h.home, ".curator")); !os.IsNotExist(err) {
				t.Fatalf("conflict touched catalog: %v", err)
			}
		})
	}
}

func TestDirectCLI(t *testing.T) {
	h := newHarness(t)
	code, out, diag := h.run("add", "direct", "--direct", "--json")
	if code != 0 || !strings.Contains(out, `"pending_confirmation":true`) || !strings.Contains(out, `"kind":"direct"`) {
		t.Fatalf("add: %d %s %s", code, out, diag)
	}
	data, err := os.ReadFile(filepath.Join(h.home, ".curator", "network.toml"))
	if err != nil || string(data) != "schema = \"relux-network-profiles-v1\"\n\n[networks.direct]\nkind = \"direct\"\n" {
		t.Fatalf("file: %s, %v", data, err)
	}
	code, out, _ = h.run("exec", "direct", "--dry-run", "--json", "--", "tool")
	if code != 1 || !strings.Contains(out, "unconfirmed") {
		t.Fatalf("unconfirmed exec: %d %s", code, out)
	}
	for _, args := range [][]string{
		{"list", "--json"}, {"show", "direct", "--json"}, {"check", "direct", "--probe", "--json"},
		{"check", "direct", "--probe", "--target", "127.0.0.1:1", "--json"},
		{"list"}, {"show", "direct"}, {"check", "direct", "--probe"},
	} {
		code, out, diag = h.run(args...)
		if code != 0 || !strings.Contains(out, "direct") {
			t.Fatalf("%v: %d %s %s", args, code, out, diag)
		}
		if args[0] == "show" && strings.Contains(strings.Join(args, " "), "--json") && !strings.Contains(out, `"set":[]`) {
			t.Fatalf("show patch: %s", out)
		}
		if args[0] == "check" && (!strings.Contains(out, "skipped") || strings.Contains(out, `"tcp":"ok"`)) {
			t.Fatalf("check probe: %s", out)
		}
	}
	h.terminal, h.stdin = true, "yes\n"
	code, out, diag = h.run("confirm", "direct", "--json")
	if code != 0 || !strings.Contains(out, `"name":"direct"`) {
		t.Fatalf("confirm: %d %s %s", code, out, diag)
	}
	h.env = append(h.env, "HTTPS_PROXY=http://127.0.0.1:1", "http_proxy=http://127.0.0.1:1", "ALL_PROXY=wrong", "NO_PROXY=*", "FtP_PrOxY=wrong")
	h.tool("tool")
	for _, args := range [][]string{
		{"exec", "direct", "--dry-run", "--json", "--", "tool"},
		{"exec", "direct", "--json", "--", "tool"},
	} {
		code, out, diag = h.run(args...)
		if code != 0 {
			t.Fatalf("exec: %d %s %s", code, out, diag)
		}
		if strings.Contains(strings.Join(args, " "), "--dry-run") && (!strings.Contains(out, `"profile_ref":"direct"`) || !strings.Contains(out, `"origin":"explicit"`) || !strings.Contains(out, `"set":[]`) || !strings.Contains(out, `"tcp":"skipped","connect":"skipped","tls":"skipped"`)) {
			t.Fatalf("dry run: %s", out)
		}
	}
	if len(h.exec.calls) != 1 {
		t.Fatalf("exec calls: %d", len(h.exec.calls))
	}
	for _, e := range h.exec.calls[0].env {
		name, _, _ := strings.Cut(e, "=")
		if strings.HasSuffix(strings.ToLower(name), "_proxy") {
			t.Fatalf("proxy retained: %s", e)
		}
	}
	// A manual kind change is a widening; the old direct confirmation is invalid.
	h.writeFile("schema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n")
	code, out, _ = h.run("exec", "direct", "--json", "--", "tool")
	if code != 1 || !strings.Contains(out, "unconfirmed") || len(h.exec.calls) != 1 {
		t.Fatalf("changed direct: %d %s", code, out)
	}
}
