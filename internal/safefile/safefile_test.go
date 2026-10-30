// SPDX-License-Identifier: Apache-2.0
//go:build darwin || linux

package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A regular file, also behind a final symbolic link, is read; genuine
// absence is fs.ErrNotExist. These are the controls for the refusals below.
func TestReadRegularAndAbsent(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.toml")
	if err := os.WriteFile(file, []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.toml")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{file, link} {
		data, err := Read(p, 64)
		if err != nil || string(data) != "x = 1\n" {
			t.Fatalf("%s: %q %v", p, data, err)
		}
	}
	if _, err := Read(filepath.Join(dir, "absent"), 64); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("absent: %v", err)
	}
}

// A FIFO, a device, a directory, a dangling link and an oversized file each
// refuse as ErrNotRegular, never as absence, and the FIFO and device are
// refused without blocking.
func TestReadRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	device := filepath.Join(dir, "device")
	if err := os.Symlink("/dev/zero", device); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "gone"), dangling); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, 65), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fifo, device, dir, dangling, big} {
		done := make(chan error, 1)
		go func() { _, err := Read(p, 64); done <- err }()
		select {
		case err := <-done:
			if !errors.Is(err, ErrNotRegular) {
				t.Fatalf("%s: %v", p, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the read blocked", p)
		}
	}
}

// A file replaced between inspection and open (here: the opened descriptor
// is another file) refuses; the same open without replacement is the
// control. A FIFO swapped in at that moment refuses without blocking.
func TestReadRefusesReplacementAfterInspection(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.toml")
	other := filepath.Join(dir, "b.toml")
	fifo := filepath.Join(dir, "fifo")
	for _, p := range []string{file, other} {
		if err := os.WriteFile(p, []byte("x = 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := read(file, 64, open); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, swapped := range []string{other, fifo} {
		replaced := func(string) (*os.File, error) { return open(swapped) }
		if _, err := read(file, 64, replaced); !errors.Is(err, ErrNotRegular) {
			t.Fatalf("%s: %v", swapped, err)
		}
	}
}
