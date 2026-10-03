// SPDX-License-Identifier: Apache-2.0

package envutil_test

import (
	"testing"

	"github.com/relux-works/curator-network-profiles/internal/envutil"
)

func TestLookup(t *testing.T) {
	t.Parallel()
	env := []string{"HOME=/first", "EMPTY=", "NOEQ", "HOME=/second"}
	if v, ok := envutil.Lookup(env, "HOME"); !ok || v != "/first" {
		t.Fatalf("HOME = %q, %v", v, ok)
	}
	if v, ok := envutil.Lookup(env, "EMPTY"); !ok || v != "" {
		t.Fatalf("EMPTY = %q, %v", v, ok)
	}
	if envutil.Has(env, "NOEQ") || envutil.Has(env, "home") || envutil.Has(nil, "HOME") {
		t.Fatal("Has matched a name that is not set")
	}
	if !envutil.Has(env, "EMPTY") {
		t.Fatal("set-ness ignores the value")
	}
}
