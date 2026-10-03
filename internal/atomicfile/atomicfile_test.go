// SPDX-License-Identifier: Apache-2.0

package atomicfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/curator-network-profiles/internal/atomicfile"
)

func TestWriteCreatesDirAndModes(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), ".curator")
	path := filepath.Join(dir, "network.toml")
	if err := atomicfile.Write(path, []byte("one\n")); err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(dir)
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v, %v", di.Mode(), err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v, %v", fi.Mode(), err)
	}
	if err := atomicfile.Backup(path, path+".bak"); err != nil {
		t.Fatal(err)
	}
	if err := atomicfile.Write(path, []byte("two\n")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	bak, _ := os.ReadFile(path + ".bak")
	if string(got) != "two\n" || string(bak) != "one\n" {
		t.Fatalf("got %q, backup %q", got, bak)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "network.toml" && e.Name() != "network.toml.bak" {
			t.Fatalf("leftover %s", e.Name())
		}
	}
	if err := atomicfile.Backup(filepath.Join(dir, "absent"), path+".bak2"); err != nil {
		t.Fatalf("Backup of an absent file: %v", err)
	}
	if _, err := os.Stat(path + ".bak2"); !os.IsNotExist(err) {
		t.Fatal("backup of an absent file was written")
	}
	if err := atomicfile.EnsureDir(path); err == nil {
		t.Fatal("EnsureDir accepted a file")
	}
}
