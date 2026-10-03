// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/curator-network-profiles/internal/cli"
	"github.com/relux-works/curator-network-profiles/internal/confirm"
	"github.com/relux-works/curator-network-profiles/internal/store"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
)

// onConfirmRead runs an edit exactly when the prompt consumes its answer.
// No goroutines, sleeps or real terminals are needed to exercise the window.
type onConfirmRead struct {
	answer io.Reader
	edit   func()
}

func (r *onConfirmRead) Read(p []byte) (int, error) {
	if r.edit != nil {
		r.edit()
		r.edit = nil
	}
	return r.answer.Read(p)
}

func runConfirm(t *testing.T, h *harness, edit func(), now func() time.Time) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := cli.Run(context.Background(), []string{"confirm", "egress-a"}, cli.Deps{
		Env: h.env, Stdin: &onConfirmRead{answer: strings.NewReader("yes\n"), edit: edit},
		Stdout: &stdout, Stderr: &stderr, IsTerminal: func() bool { return true },
		Prober: h.prober, Now: now,
	})
	return code, stdout.String(), stderr.String()
}

func confirmPaths(t *testing.T, h *harness) store.Paths {
	t.Helper()
	p, err := store.PathsFromEnv(h.env)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func assertConfirmUnlocked(t *testing.T, p store.Paths) {
	t.Helper()
	if _, err := os.Lstat(p.File + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("confirm left an edit lock: %v", err)
	}
	if err := store.WithCatalogLock(p, func() error { return nil }); err != nil {
		t.Fatalf("cannot acquire edit lock after confirm: %v", err)
	}
}

func assertConfirmLocked(t *testing.T, p store.Paths) {
	t.Helper()
	if _, err := os.Stat(p.File + ".lock"); err != nil {
		t.Errorf("confirm write does not hold catalog edit lock: %v", err)
	}
}

func TestConfirmSymlinkCatalog(t *testing.T) {
	h := newHarness(t)
	h.writeFile(twoProfiles)
	p := confirmPaths(t, h)
	target := p.File + ".target"
	if err := os.Rename(p.File, target); err != nil {
		t.Fatal(err)
	}
	linkTarget := filepath.Base(target)
	if err := os.Symlink(linkTarget, p.File); err != nil {
		t.Fatal(err)
	}
	beforeLink, err := os.Lstat(p.File)
	if err != nil {
		t.Fatal(err)
	}
	beforeTarget, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runConfirm(t, h, nil, func() time.Time {
		assertConfirmLocked(t, p)
		return h.now
	})
	if code != cli.ExitOK || stderr != "" {
		t.Fatalf("confirm symlink catalog: %d %q", code, stderr)
	}
	ledger, err := confirm.Read(p.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	file, err := netprofile.Parse([]byte(twoProfiles))
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := file.Lookup("egress-a")
	entry, ok := ledger.Entry("egress-a")
	if !ok || entry.Digest != netprofile.Digest(profile) || !entry.ConfirmedAt.Equal(h.now) {
		t.Fatalf("confirmed name/digest/time = %+v", entry)
	}
	afterLink, err := os.Lstat(p.File)
	if err != nil || afterLink.Mode()&os.ModeSymlink == 0 || !os.SameFile(beforeLink, afterLink) {
		t.Fatalf("catalog symlink replaced: %v", err)
	}
	if got, err := os.Readlink(p.File); err != nil || got != linkTarget {
		t.Fatalf("catalog symlink changed: %q %v", got, err)
	}
	afterTarget, err := os.Stat(target)
	if err != nil || !os.SameFile(beforeTarget, afterTarget) || beforeTarget.Mode() != afterTarget.Mode() || !beforeTarget.ModTime().Equal(afterTarget.ModTime()) {
		t.Fatalf("catalog target replaced or modified: %v", err)
	}
	if data, err := os.ReadFile(target); err != nil || !bytes.Equal(data, []byte(twoProfiles)) {
		t.Fatalf("catalog target bytes changed: %v", err)
	}
	if _, err := os.Lstat(p.Backup); !os.IsNotExist(err) {
		t.Fatalf("confirm created a catalog backup: %v", err)
	}
	assertConfirmUnlocked(t, p)
}

func TestConfirmHeldCatalogLock(t *testing.T) {
	h := newHarness(t)
	h.writeFile(twoProfiles)
	h.confirmAll()
	p := confirmPaths(t, h)
	before, err := os.ReadFile(p.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	// Make one digest pending while retaining a ledger that must not change.
	h.writeFile(strings.Replace(twoProfiles, "18081", "18083", 1))
	if err := os.WriteFile(p.File+".lock", []byte("other editor"), 0600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runConfirm(t, h, nil, func() time.Time { return h.now })
	wantDiag(t, stderr, "network_configuration_conflict", "network.toml")
	if code != 1 || !strings.Contains(stderr, "catalog edit is locked; retry after the other edit finishes") || strings.Contains(stdout, "confirmed egress-a at") {
		t.Errorf("held-lock confirm: %d %q %q", code, stdout, stderr)
	}
	after, err := os.ReadFile(p.Ledger)
	if err != nil || !bytes.Equal(before, after) {
		t.Error("held-lock confirm changed ledger")
	}
	owner, err := os.ReadFile(p.File + ".lock")
	if err != nil || string(owner) != "other editor" {
		t.Fatal("confirm changed another editor's lock")
	}
}

func TestConfirmCatalogChangedDuringPrompt(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"digest", strings.Replace(twoProfiles, "18081", "18083", 1)},
		{"comment", twoProfiles + "\n# manual edit\n"},
		{"malformed", "not valid TOML"},
		{"removed", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.writeFile(twoProfiles)
			h.confirmAll()
			p := confirmPaths(t, h)
			h.writeFile(strings.Replace(twoProfiles, "18081", "18084", 1))
			before, err := os.ReadFile(p.Ledger)
			if err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runConfirm(t, h, func() {
				assertConfirmUnlocked(t, p) // Human input must not hold the lock.
				if tc.name == "removed" {
					if err := os.Remove(p.File); err != nil {
						t.Fatal(err)
					}
				} else {
					h.writeFile(tc.doc)
				}
			}, func() time.Time { return h.now })
			if code != 1 || strings.Contains(stdout, "confirmed egress-a at") || stderr != "curator-network: network_configuration_conflict: network.toml: catalog changed during confirm; run confirm again\n" {
				t.Errorf("catalog-change confirm: %d %q %q", code, stdout, stderr)
			}
			after, err := os.ReadFile(p.Ledger)
			if err != nil || !bytes.Equal(before, after) {
				t.Error("catalog-change refusal changed ledger")
			}
			assertConfirmUnlocked(t, p)
		})
	}
}

func TestConfirmLockSuccessAndWriteFailure(t *testing.T) {
	for _, failWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "write_failure"}[failWrite], func(t *testing.T) {
			h := newHarness(t)
			h.writeFile(twoProfiles)
			p := confirmPaths(t, h)
			var before []byte
			if failWrite {
				h.confirmAll()
				h.writeFile(strings.Replace(twoProfiles, "18081", "18083", 1))
				var err error
				before, err = os.ReadFile(p.Ledger)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(p.Ledger, p.Ledger+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p.Ledger+".target", p.Ledger); err != nil {
					t.Fatal(err)
				}
			}
			code, _, stderr := runConfirm(t, h, func() { assertConfirmUnlocked(t, p) }, func() time.Time {
				assertConfirmLocked(t, p)
				return h.now
			})
			assertConfirmUnlocked(t, p)
			if failWrite {
				if code != 1 || !strings.Contains(stderr, "network_file_unreadable: network.confirmations.json: cannot write") {
					t.Fatalf("write failure: %d %q", code, stderr)
				}
				after, err := os.ReadFile(p.Ledger)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("write failure changed ledger target")
				}
				return
			}
			if code != 0 || stderr != "" {
				t.Fatalf("confirm success: %d %q", code, stderr)
			}
			ledger, err := confirm.Read(p.Ledger)
			profileFile, errParse := netprofile.Parse([]byte(twoProfiles))
			if err != nil || errParse != nil {
				t.Fatalf("read confirmed fixture: %v %v", err, errParse)
			}
			profile, _ := profileFile.Lookup("egress-a")
			entry, ok := ledger.Entry("egress-a")
			if !ok || entry.Digest != netprofile.Digest(profile) || !entry.ConfirmedAt.Equal(h.now) {
				t.Fatalf("confirmed name/digest/time = %+v", entry)
			}
		})
	}
}

func TestConfirmRereadsLedgerUnderLock(t *testing.T) {
	h := newHarness(t)
	h.writeFile(twoProfiles)
	p := confirmPaths(t, h)
	code, _, stderr := runConfirm(t, h, func() {
		// Simulate a cooperating editor updating another profile while the
		// operator answers. Its new entry must survive this confirmation.
		if err := store.WithCatalogLock(p, func() error {
			ledger := confirm.Empty()
			ledger.Set("egress-b", "other-editor-digest", h.now)
			return confirm.Write(p.Ledger, ledger)
		}); err != nil {
			t.Fatal(err)
		}
	}, func() time.Time { return h.now })
	if code != 0 || stderr != "" {
		t.Fatalf("confirm: %d %q", code, stderr)
	}
	ledger, err := confirm.Read(p.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := ledger.Entry("egress-b")
	if !ok || entry.Digest != "other-editor-digest" {
		t.Fatal("confirm overwrote concurrent ledger update")
	}
	assertConfirmUnlocked(t, p)
}

func TestConfirmLedgerReadRefusalReleasesLock(t *testing.T) {
	h := newHarness(t)
	h.writeFile(twoProfiles)
	p := confirmPaths(t, h)
	code, _, stderr := runConfirm(t, h, func() {
		if err := os.WriteFile(p.Ledger, []byte("malformed ledger"), 0600); err != nil {
			t.Fatal(err)
		}
	}, func() time.Time { return h.now })
	if code != 1 || !strings.Contains(stderr, "network_file_unreadable: network.confirmations.json: cannot parse") {
		t.Errorf("ledger re-read refusal: %d %q", code, stderr)
	}
	data, err := os.ReadFile(p.Ledger)
	if err != nil || string(data) != "malformed ledger" {
		t.Error("ledger read refusal wrote the ledger")
	}
	assertConfirmUnlocked(t, p)
}

func TestShowAndRemoveExplicitOperandSeparator(t *testing.T) {
	h := newHarness(t)
	h.writeFile(twoProfiles)
	code, stdout, stderr := h.run("show", "--", "egress-a")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "name:            egress-a\n") {
		t.Fatalf("show -- egress-a: %d %q %q", code, stdout, stderr)
	}
	h.writeFile(strings.Replace(twoProfiles, "egress-a", "x", 1))
	code, stdout, stderr = h.run("remove", "--", "x")
	if code != 0 || stderr != "" || stdout != "removed x\n" {
		t.Fatalf("remove -- x: %d %q %q", code, stdout, stderr)
	}
	data, err := os.ReadFile(filepath.Join(h.home, ".curator", "network.toml"))
	if err != nil || strings.Contains(string(data), "[networks.x]") {
		t.Fatal("remove -- x did not remove profile")
	}
}
