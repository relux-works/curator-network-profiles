// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import "syscall"

// execve replaces the process: signals and the exit status are the
// child's from here on.
func execve(path string, argv []string, env []string) error {
	return syscall.Exec(path, argv, env)
}
