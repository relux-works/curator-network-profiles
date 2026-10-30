// SPDX-License-Identifier: Apache-2.0
//go:build darwin || linux

package safefile

import (
	"os"
	"syscall"
)

// open opens without blocking: O_NONBLOCK lets a FIFO swapped in after the
// inspection open at once, so the descriptor check refuses it. O_CLOEXEC
// keeps the descriptor out of any child.
func open(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
