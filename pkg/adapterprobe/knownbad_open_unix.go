// SPDX-License-Identifier: Apache-2.0
//go:build darwin || linux

package adapterprobe

import (
	"os"
	"syscall"
)

// openKnownBadFile opens the operator file without following symlinks
// and without blocking on FIFOs. O_NOFOLLOW turns a symlink replacement
// into ELOOP; O_NONBLOCK lets a FIFO open succeed so the caller can
// refuse it by descriptor type instead of blocking. O_CLOEXEC keeps the
// descriptor out of any future child.
func openKnownBadFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
