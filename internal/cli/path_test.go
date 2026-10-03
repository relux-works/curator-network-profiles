// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLookPathSkipsEmptyElements(t *testing.T) {
	local, err := os.CreateTemp(".", "empty-path-tool-")
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(local.Name())
	t.Cleanup(func() { _ = os.Remove(local.Name()) })
	if err := local.Chmod(0700); err != nil {
		t.Fatal(err)
	}
	if err := local.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	wanted := filepath.Join(dir, name)
	if err := os.WriteFile(wanted, []byte("tool"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{":" + dir, dir + ":", "::" + dir + "::"} {
		got, err := lookPath(name, []string{"PATH=" + path})
		if err != nil || got != wanted {
			t.Errorf("PATH %q: %q, %v; want %q", path, got, err, wanted)
		}
	}
	if _, err := lookPath(name, []string{"PATH=:"}); err == nil {
		t.Error("empty elements selected the working directory")
	}
	if got, err := lookPath(name, []string{"PATH=."}); err != nil || got != name {
		t.Errorf("explicit dot: %q %v", got, err)
	}
}
