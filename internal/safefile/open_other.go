// SPDX-License-Identifier: Apache-2.0
//go:build !darwin && !linux

package safefile

import (
	"errors"
	"os"
)

// open refuses where a nonblocking open is not implemented.
func open(string) (*os.File, error) {
	return nil, errors.New("safe reading requires a nonblocking open")
}
