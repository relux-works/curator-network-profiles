// SPDX-License-Identifier: Apache-2.0

// Package atomicfile writes operator files atomically: a temporary file
// in the destination directory, mode 0600, fsync, rename; the directory
// is created 0700 when absent and fsynced after the rename on a best
// effort basis.
package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
)

// EnsureDir creates dir with mode 0700 when it does not exist. An
// existing directory keeps its mode: it may be shared with other
// Curator files and is not tightened silently.
func EnsureDir(dir string) error {
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return errors.New("not a directory")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(dir, 0o700)
}

// Write replaces path with data atomically, mode 0600. A symlink destination
// is refused rather than silently replaced or followed.
func Write(path string, data []byte) error {
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("cannot replace a symlink")
	}
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Backup copies the current bytes of path to backupPath (mode 0600)
// when path exists; an absent path is not an error.
func Backup(path, backupPath string) error {
	prev, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return Write(backupPath, prev)
}
