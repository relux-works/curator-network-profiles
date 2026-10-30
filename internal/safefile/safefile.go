// SPDX-License-Identifier: Apache-2.0

// Package safefile reads small operator files without blocking on a special
// file: a FIFO, a device or a directory at the path refuses instead of being
// opened for a blocking read. A final symbolic link is followed only to a
// regular file. A read that stalls inside the kernel on a regular file (a
// hung network filesystem) is not interruptible here.
package safefile

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

// ErrNotRegular is returned for a present path that is not a readable
// regular file: a special file, a directory, a dangling link, a file
// replaced between inspection and open, or one larger than the limit.
var ErrNotRegular = errors.New("not a readable regular file")

// Read returns the contents of the regular file at path, at most limit
// bytes. Genuine absence (no directory entry) is fs.ErrNotExist; any other
// failure wraps fs.ErrPermission when that is the cause, else is
// ErrNotRegular.
func Read(path string, limit int64) ([]byte, error) {
	return read(path, limit, open)
}

func read(path string, limit int64, openFile func(string) (*os.File, error)) ([]byte, error) {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, classify(err)
	}
	target, err := os.Stat(path)
	if err != nil {
		return nil, classify(err)
	}
	if !target.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	f, err := openFile(path)
	if err != nil {
		return nil, classify(err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(target, opened) {
		return nil, ErrNotRegular
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, classify(err)
	}
	if int64(len(data)) > limit {
		return nil, ErrNotRegular
	}
	return data, nil
}

func classify(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fs.ErrPermission
	}
	return ErrNotRegular
}
