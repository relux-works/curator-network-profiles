// SPDX-License-Identifier: Apache-2.0

package confirm_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/curator-network-profiles/internal/confirm"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

func TestLedgerRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), ".curator", "network.confirmations.json")
	l, err := confirm.Read(path)
	if err != nil || len(l.Entries) != 0 || l.Schema != "relux-network-confirmations-v1" {
		t.Fatalf("absent ledger: %+v, %v", l, err)
	}
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.FixedZone("x", 3600))
	l.Set("egress-a", "sha256:aa", at)
	l.Set("egress-b", "sha256:bb", at)
	if err := confirm.Write(path, l); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"schema": "relux-network-confirmations-v1"`) || !strings.Contains(string(raw), `"confirmed_at": "2026-10-01T11:00:00Z"`) {
		t.Fatalf("ledger bytes:\n%s", raw)
	}
	back, err := confirm.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Confirmed("egress-a", "sha256:aa") || back.Confirmed("egress-a", "sha256:bb") || back.Confirmed("egress-c", "sha256:aa") || back.Confirmed("egress-a", "") {
		t.Fatal("Confirmed")
	}
	if e, ok := back.Entry("egress-b"); !ok || e.Digest != "sha256:bb" || !e.ConfirmedAt.Equal(at) {
		t.Fatalf("Entry = %+v, %v", e, ok)
	}
	if strings.Join(back.Names(), ",") != "egress-a,egress-b" {
		t.Fatalf("Names = %v", back.Names())
	}
	if !back.Delete("egress-a") || back.Delete("egress-a") || back.Confirmed("egress-a", "sha256:aa") {
		t.Fatal("Delete")
	}
	var nilLedger *confirm.Ledger
	if nilLedger.Confirmed("a", "b") || nilLedger.Delete("a") || nilLedger.Names() != nil {
		t.Fatal("nil ledger")
	}
	if _, ok := nilLedger.Entry("a"); ok {
		t.Fatal("nil ledger entry")
	}
}

func TestLedgerRefusals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"malformed.json": "{",
		"foreign.json":   `{"schema":"other","confirmed":{}}`,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := confirm.Read(path)
		if c, _ := refusal.CodeOf(err); c != refusal.CodeFileUnreadable {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(err.Error(), dir) {
			t.Fatalf("absolute path leaked: %v", err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "dir.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := confirm.Read(filepath.Join(dir, "dir.json")); err == nil {
		t.Fatal("directory read as a ledger")
	}
}

func TestGuardPerMarker(t *testing.T) {
	t.Parallel()
	markers := []string{"CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_ENTRYPOINT", "CODEX_THREAD_ID", "CODEX_SESSION", "CODEX_CI", "TASK_BOARD_RUN_ID", "A2A_AGENT"}
	if strings.Join(confirm.Markers, ",") != strings.Join(markers, ",") {
		t.Fatalf("Markers = %v", confirm.Markers)
	}
	for _, m := range markers {
		for _, value := range []string{"1", ""} {
			t.Run(m+"="+value, func(t *testing.T) {
				t.Parallel()
				err := confirm.Guard([]string{"PATH=/bin", m + "=" + value}, true)
				if c, _ := refusal.CodeOf(err); c != refusal.CodeConfirmRefused {
					t.Fatalf("marker %s=%q: %v", m, value, err)
				}
				if !strings.Contains(err.Error(), m) {
					t.Fatalf("subject: %v", err)
				}
			})
		}
	}
	if err := confirm.Guard([]string{"PATH=/bin", "CLAUDECODE_EXTRA=1", "claudecode=1"}, true); err != nil {
		t.Fatalf("near-miss names refused: %v", err)
	}
	if err := confirm.Guard([]string{"PATH=/bin"}, false); err == nil {
		t.Fatal("non-terminal accepted")
	} else if c, _ := refusal.CodeOf(err); c != refusal.CodeConfirmRefused || !strings.Contains(err.Error(), "not a terminal") {
		t.Fatalf("err = %v", err)
	}
	if err := confirm.Guard([]string{"PATH=/bin"}, true); err != nil {
		t.Fatalf("clean terminal refused: %v", err)
	}
}
