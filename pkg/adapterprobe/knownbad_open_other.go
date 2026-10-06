// SPDX-License-Identifier: Apache-2.0
//go:build !darwin && !linux

package adapterprobe

import (
	"errors"
	"os"
)

// openKnownBadFile fails closed where a no-follow nonblocking open is
// unavailable: present files refuse without being read. Genuine absence
// is still reported by the Lstat inspection before this open is
// attempted, so the embedded-only default keeps working.
func openKnownBadFile(path string) (*os.File, error) {
	return nil, errors.New("known-bad file reading requires a no-follow nonblocking open")
}
