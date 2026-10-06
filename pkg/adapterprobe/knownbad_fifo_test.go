// SPDX-License-Identifier: Apache-2.0
//go:build darwin || linux

package adapterprobe

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO at the operator path must refuse without blocking: the
// no-follow nonblocking open succeeds so the descriptor type check can
// refuse it, instead of blocking in open.
func TestSafeKnownBadReadFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.json")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := SafeKnownBadRead(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, os.ErrNotExist) {
			t.Fatalf("fifo error=%v; want non-NotExist failure", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SafeKnownBadRead blocked opening a FIFO")
	}
	loadEvaluateUnreadable(t, SafeKnownBadRead, "", fifo)
	defDir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(defDir, KnownBadFileName), 0600); err != nil {
		t.Fatal(err)
	}
	loadEvaluateUnreadable(t, SafeKnownBadRead, defDir, "")
}

// A regular file replaced by a FIFO between inspection and open must
// still refuse without blocking.
func TestSafeKnownBadReadFIFOReplacementRace(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "probe.json")
	if err := os.WriteFile(regular, []byte(`{"schema":"relux-adapter-knownbad-v1","sha256":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(regular)
	if err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "pipe.json")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	lstatOK := func(string) (os.FileInfo, error) { return info, nil }
	openFIFO := func(string) (*os.File, error) {
		fd, err := syscall.Open(fifo, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), fifo), nil
	}
	done := make(chan error, 1)
	go func() { _, err := safeKnownBadRead(regular, lstatOK, openFIFO); done <- err }()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, os.ErrNotExist) {
			t.Fatalf("replacement error=%v; want non-NotExist failure", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("replacement read blocked on a FIFO")
	}
	read := func(path string) ([]byte, error) { return safeKnownBadRead(path, lstatOK, openFIFO) }
	loadEvaluateUnreadable(t, read, dir, "")
	loadEvaluateUnreadable(t, read, "", regular)
}
