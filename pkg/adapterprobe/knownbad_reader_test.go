// SPDX-License-Identifier: Apache-2.0
package adapterprobe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// loadEvaluateUnreadable asserts a present-file failure propagates
// through Load → Evaluate as knownbad_unreadable.
func loadEvaluateUnreadable(t *testing.T, read KnownBadReadFunc, configRoot, explicitPath string) {
	t.Helper()
	set, err := LoadKnownBad(read, configRoot, explicitPath)
	assertKnownBadErr(t, err, "knownbad_unreadable")
	if set != nil {
		t.Fatal("failed load returned a set")
	}
	dec, err := Evaluate(context.Background(), claudeRequest(), Policy{KnownBadErr: err})
	assertDecision(t, dec, err, OutcomeRefused, "knownbad_unreadable", false)
}

func TestSafeKnownBadReadGenuineAbsence(t *testing.T) {
	dir := t.TempDir()
	// Production reader reports a genuinely absent path as NotExist.
	if _, err := SafeKnownBadRead(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent error=%v; want os.ErrNotExist", err)
	}
	// Optional default genuinely absent: embedded only, no read error.
	set, err := LoadKnownBad(SafeKnownBadRead, dir, "")
	if err != nil || set == nil || set.Contains(strings.Repeat("a", 64)) {
		t.Fatalf("absent default: %+v %v", set, err)
	}
	// Explicit absence refuses through Load → Evaluate.
	loadEvaluateUnreadable(t, SafeKnownBadRead, "", filepath.Join(dir, "missing.json"))
}

func TestSafeKnownBadReadDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	dangling := filepath.Join(dir, "dangling.json")
	if err := os.Symlink(filepath.Join(dir, "no-such-target.json"), dangling); err != nil {
		t.Fatal(err)
	}
	// A present dangling symlink is present-but-unusable, never absent.
	if _, err := SafeKnownBadRead(dangling); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling error=%v; want non-NotExist failure", err)
	}
	loadEvaluateUnreadable(t, SafeKnownBadRead, "", dangling)
	// The same refusal applies at the optional default location.
	defDir := t.TempDir()
	if err := os.Symlink(filepath.Join(defDir, "no-such-target.json"), filepath.Join(defDir, KnownBadFileName)); err != nil {
		t.Fatal(err)
	}
	loadEvaluateUnreadable(t, SafeKnownBadRead, defDir, "")
}

func TestSafeKnownBadReadSymlinkIsNeverFollowed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"schema":"relux-adapter-knownbad-v1","sha256":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	// Even a valid symlink refuses: links are never followed.
	if _, err := SafeKnownBadRead(link); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink error=%v; want non-NotExist failure", err)
	}
	loadEvaluateUnreadable(t, SafeKnownBadRead, "", link)
}

func TestSafeKnownBadReadDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := SafeKnownBadRead(dir); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory error=%v; want non-NotExist failure", err)
	}
	loadEvaluateUnreadable(t, SafeKnownBadRead, "", dir)
	// A directory at the optional default location also refuses.
	defDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(defDir, KnownBadFileName), 0700); err != nil {
		t.Fatal(err)
	}
	loadEvaluateUnreadable(t, SafeKnownBadRead, defDir, "")
}

func TestSafeKnownBadReadOversize(t *testing.T) {
	dir := t.TempDir()
	big := bytesRepeatForTest("a", MaxKnownBadBytes+1)
	path := filepath.Join(dir, "big.json")
	if err := os.WriteFile(path, big, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := SafeKnownBadRead(path); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversize error=%v; want non-NotExist failure", err)
	}
	loadEvaluateUnreadable(t, SafeKnownBadRead, "", path)
	defDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(defDir, KnownBadFileName), big, 0600); err != nil {
		t.Fatal(err)
	}
	loadEvaluateUnreadable(t, SafeKnownBadRead, defDir, "")
}

func bytesRepeatForTest(s string, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, s...)
	}
	return out[:n]
}

func TestSafeKnownBadReadValidFile(t *testing.T) {
	good := strings.Repeat("a", 64)
	dir := t.TempDir()
	path := filepath.Join(dir, KnownBadFileName)
	valid := []byte(`{"schema":"relux-adapter-knownbad-v1","sha256":["` + good + `"]}`)
	if err := os.WriteFile(path, valid, 0600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		// Fail-closed platform fallback: present files refuse without
		// a no-follow nonblocking open.
		loadEvaluateUnreadable(t, SafeKnownBadRead, dir, "")
		return
	}
	data, err := SafeKnownBadRead(path)
	if err != nil || string(data) != string(valid) {
		t.Fatalf("valid read: %d bytes %v", len(data), err)
	}
	set, err := LoadKnownBad(SafeKnownBadRead, dir, "")
	if err != nil || !set.Contains(good) {
		t.Fatalf("valid load: %+v %v", set, err)
	}
}

// TestSafeKnownBadReadInjectedFailures exercises permission failures
// and the inspection-to-open race with injected operations.
func TestSafeKnownBadReadInjectedFailures(t *testing.T) {
	dir := t.TempDir()
	probe := filepath.Join(dir, "probe.json")
	if err := os.WriteFile(probe, []byte(`{"schema":"relux-adapter-knownbad-v1","sha256":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	regular, err := os.Stat(probe)
	if err != nil {
		t.Fatal(err)
	}
	lstatOK := func(string) (os.FileInfo, error) { return regular, nil }
	openOK := func(string) (*os.File, error) { return os.Open(probe) }
	for _, tc := range []struct {
		name  string
		lstat func(string) (os.FileInfo, error)
		open  func(string) (*os.File, error)
	}{
		{"inspection permission failure", func(string) (os.FileInfo, error) { return nil, os.ErrPermission }, openOK},
		{"open permission failure", lstatOK, func(string) (*os.File, error) { return nil, os.ErrPermission }},
		{"deletion between inspection and open", lstatOK, func(string) (*os.File, error) { return nil, os.ErrNotExist }},
		{"symlink replacement between inspection and open", lstatOK, func(string) (*os.File, error) { return nil, errors.New("too many links") }},
		{"directory replacement between inspection and open", lstatOK, func(string) (*os.File, error) { return os.Open(dir) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := safeKnownBadRead(probe, tc.lstat, tc.open)
			if err == nil || errors.Is(err, os.ErrNotExist) {
				t.Fatalf("error=%v; want non-NotExist failure", err)
			}
			read := func(path string) ([]byte, error) { return safeKnownBadRead(path, tc.lstat, tc.open) }
			// Default location: must not read as optional absence.
			loadEvaluateUnreadable(t, read, dir, "")
			// Explicit location: same refusal.
			loadEvaluateUnreadable(t, read, "", probe)
		})
	}
	// Injected success still reads through the same path.
	data, err := safeKnownBadRead(probe, lstatOK, openOK)
	if err != nil || !strings.Contains(string(data), KnownBadSchema) {
		t.Fatalf("injected success: %d bytes %v", len(data), err)
	}
}

// A different regular file replacing the inspected entry between
// inspection and open must refuse: the replacement's bytes are never
// read, so an operator denial in A cannot be erased by an empty B.
// A sits at the actual requested pathname; the injected opener renames
// the separately created inert B over the received pathname after
// inspection, then calls the real production opener on that same
// pathname, exercising the actual flags as well as the identity check.
func TestSafeKnownBadReadRegularReplacementRefuses(t *testing.T) {
	_, digest := digestOf(t, claudeRequest())
	docA := []byte(`{"schema":"relux-adapter-knownbad-v1","sha256":["` + digest + `"]}`)
	docB := []byte(`{"schema":"relux-adapter-knownbad-v1","sha256":[]}`)
	// Fixture semantics: A denies the selected digest, B is a valid
	// empty list. Accepting B would evaluate unqualified instead of
	// refusing, so only refusal is correct.
	denying, err := ParseKnownBad(docA)
	if err != nil || !denying.Contains(digest) {
		t.Fatalf("fixture A must deny the digest: %+v %v", denying, err)
	}
	empty, err := ParseKnownBad(docB)
	if err != nil || empty.Contains(digest) {
		t.Fatalf("fixture B must be a valid empty list: %+v %v", empty, err)
	}
	t.Run("default", func(t *testing.T) {
		dir := t.TempDir()
		requested := filepath.Join(dir, KnownBadFileName)
		pathB := filepath.Join(dir, "b.json")
		if err := os.WriteFile(requested, docA, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pathB, docB, 0600); err != nil {
			t.Fatal(err)
		}
		openRename := func(received string) (*os.File, error) {
			if err := os.Rename(pathB, received); err != nil {
				t.Fatalf("rename B over requested path: %v", err)
				return nil, err
			}
			return openKnownBadFile(received)
		}
		data, err := safeKnownBadRead(requested, os.Lstat, openRename)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			t.Fatalf("replacement error=%v; want non-NotExist failure", err)
		}
		if data != nil {
			t.Fatal("replacement read returned bytes")
		}
		loadDir := t.TempDir()
		loadRequested := filepath.Join(loadDir, KnownBadFileName)
		loadB := filepath.Join(loadDir, "b.json")
		if err := os.WriteFile(loadRequested, docA, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(loadB, docB, 0600); err != nil {
			t.Fatal(err)
		}
		read := func(path string) ([]byte, error) {
			return safeKnownBadRead(path, os.Lstat, func(received string) (*os.File, error) {
				if err := os.Rename(loadB, received); err != nil {
					t.Fatalf("rename B over requested path: %v", err)
					return nil, err
				}
				return openKnownBadFile(received)
			})
		}
		loadEvaluateUnreadable(t, read, loadDir, "")
	})
	t.Run("explicit", func(t *testing.T) {
		dir := t.TempDir()
		requested := filepath.Join(dir, "explicit.json")
		pathB := filepath.Join(dir, "b.json")
		if err := os.WriteFile(requested, docA, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pathB, docB, 0600); err != nil {
			t.Fatal(err)
		}
		openRename := func(received string) (*os.File, error) {
			if err := os.Rename(pathB, received); err != nil {
				t.Fatalf("rename B over requested path: %v", err)
				return nil, err
			}
			return openKnownBadFile(received)
		}
		data, err := safeKnownBadRead(requested, os.Lstat, openRename)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			t.Fatalf("replacement error=%v; want non-NotExist failure", err)
		}
		if data != nil {
			t.Fatal("replacement read returned bytes")
		}
		loadDir := t.TempDir()
		loadRequested := filepath.Join(loadDir, "explicit.json")
		loadB := filepath.Join(loadDir, "b.json")
		if err := os.WriteFile(loadRequested, docA, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(loadB, docB, 0600); err != nil {
			t.Fatal(err)
		}
		read := func(path string) ([]byte, error) {
			return safeKnownBadRead(path, os.Lstat, func(received string) (*os.File, error) {
				if err := os.Rename(loadB, received); err != nil {
					t.Fatalf("rename B over requested path: %v", err)
					return nil, err
				}
				return openKnownBadFile(received)
			})
		}
		loadEvaluateUnreadable(t, read, "", loadRequested)
	})
}

// A non-regular inspected entry replaced by a regular file at open
// must still refuse: inspection requires a regular file before any
// open is attempted. The inspection seam captures the actual
// non-regular entry at the requested pathname, replaces that
// disposable entry with regular JSON, then returns its original
// FileInfo; the opener must never be invoked.
func TestSafeKnownBadReadNonRegularInspectedRefuses(t *testing.T) {
	regularDoc := []byte(`{"schema":"relux-adapter-knownbad-v1","sha256":[]}`)
	replaceWithRegular := func(t *testing.T, p string) (os.FileInfo, error) {
		t.Helper()
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if fi.Mode().IsRegular() {
			t.Errorf("inspection captured a regular entry; want non-regular")
		}
		if err := os.RemoveAll(p); err != nil {
			t.Fatalf("remove disposable non-regular entry: %v", err)
			return nil, err
		}
		if err := os.WriteFile(p, regularDoc, 0600); err != nil {
			t.Fatalf("write replacement regular file: %v", err)
			return nil, err
		}
		return fi, nil
	}
	t.Run("default", func(t *testing.T) {
		dir := t.TempDir()
		requested := filepath.Join(dir, KnownBadFileName)
		if err := os.Mkdir(requested, 0700); err != nil {
			t.Fatal(err)
		}
		called := false
		openTrack := func(p string) (*os.File, error) {
			called = true
			return openKnownBadFile(p)
		}
		data, err := safeKnownBadRead(requested, func(p string) (os.FileInfo, error) {
			return replaceWithRegular(t, p)
		}, openTrack)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			t.Fatalf("non-regular inspection error=%v; want non-NotExist failure", err)
		}
		if data != nil {
			t.Fatal("non-regular inspection returned bytes")
		}
		if called {
			t.Fatal("non-regular inspection opened the replacement")
		}
		loadDir := t.TempDir()
		loadRequested := filepath.Join(loadDir, KnownBadFileName)
		if err := os.Mkdir(loadRequested, 0700); err != nil {
			t.Fatal(err)
		}
		loadCalled := false
		read := func(path string) ([]byte, error) {
			return safeKnownBadRead(path, func(p string) (os.FileInfo, error) {
				return replaceWithRegular(t, p)
			}, func(p string) (*os.File, error) {
				loadCalled = true
				return openKnownBadFile(p)
			})
		}
		loadEvaluateUnreadable(t, read, loadDir, "")
		if loadCalled {
			t.Fatal("non-regular inspection opened the replacement")
		}
	})
	t.Run("explicit", func(t *testing.T) {
		dir := t.TempDir()
		requested := filepath.Join(dir, "explicit.json")
		if err := os.Mkdir(requested, 0700); err != nil {
			t.Fatal(err)
		}
		called := false
		openTrack := func(p string) (*os.File, error) {
			called = true
			return openKnownBadFile(p)
		}
		data, err := safeKnownBadRead(requested, func(p string) (os.FileInfo, error) {
			return replaceWithRegular(t, p)
		}, openTrack)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			t.Fatalf("non-regular inspection error=%v; want non-NotExist failure", err)
		}
		if data != nil {
			t.Fatal("non-regular inspection returned bytes")
		}
		if called {
			t.Fatal("non-regular inspection opened the replacement")
		}
		loadDir := t.TempDir()
		loadRequested := filepath.Join(loadDir, "explicit.json")
		if err := os.Mkdir(loadRequested, 0700); err != nil {
			t.Fatal(err)
		}
		loadCalled := false
		read := func(path string) ([]byte, error) {
			return safeKnownBadRead(path, func(p string) (os.FileInfo, error) {
				return replaceWithRegular(t, p)
			}, func(p string) (*os.File, error) {
				loadCalled = true
				return openKnownBadFile(p)
			})
		}
		loadEvaluateUnreadable(t, read, "", loadRequested)
		if loadCalled {
			t.Fatal("non-regular inspection opened the replacement")
		}
	})
}
