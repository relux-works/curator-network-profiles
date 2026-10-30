// SPDX-License-Identifier: Apache-2.0
//go:build darwin || linux

package catalog_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/curator-network-profiles/pkg/catalog"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

// A catalog or ledger that is a FIFO refuses network_file_unreadable at
// once instead of blocking the load, whichever caller (explicit selection or
// default lookup) reads it. The regular catalog and ledger in the same home
// are the control.
func TestLoadRefusesSpecialFilesWithoutBlocking(t *testing.T) {
	t.Parallel()
	for _, special := range []string{"network.toml", "network.confirmations.json"} {
		t.Run(special, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, ".curator")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "network.toml"), []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := catalog.Load([]string{"HOME=" + home}); err != nil {
				t.Fatalf("control: %v", err)
			}
			path := filepath.Join(dir, special)
			os.Remove(path)
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := catalog.Load([]string{"HOME=" + home}); done <- err }()
			select {
			case err := <-done:
				if code, _ := refusal.CodeOf(err); err == nil || code != refusal.CodeFileUnreadable {
					t.Fatalf("err = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the load blocked on a FIFO")
			}
		})
	}
}
