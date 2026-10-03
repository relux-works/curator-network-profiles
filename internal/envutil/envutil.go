// SPDX-License-Identifier: Apache-2.0

// Package envutil reads an explicit environment slice. Nothing in this
// module consults os.Getenv: the process environment is injected by main
// and by tests alike.
package envutil

import "strings"

// Lookup returns the value of name in env. The first occurrence wins,
// as in the Go runtime's own environment copy.
func Lookup(env []string, name string) (string, bool) {
	for _, entry := range env {
		if k, v, ok := strings.Cut(entry, "="); ok && k == name {
			return v, true
		}
	}
	return "", false
}

// Has reports whether name is set in env, whatever its value.
func Has(env []string, name string) bool {
	_, ok := Lookup(env, name)
	return ok
}
