// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"github.com/relux-works/curator-network-profiles/internal/store"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"os"
	"strings"
	"testing"
)

func TestStoreDirect(t *testing.T) {
	for _, name := range []string{"direct", "egress.direct"} {
		t.Run(name, func(t *testing.T) {
			paths := paths(t)
			seed(t, paths, seeded)
			p, err := netprofile.Normalize(name, netprofile.Input{Kind: "direct"})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Add(paths, p); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(paths.File)
			if err != nil {
				t.Fatal(err)
			}
			key := name
			if strings.Contains(name, ".") {
				key = `"` + name + `"`
			}
			if string(data) != seeded+"\n[networks."+key+"]\nkind = \"direct\"\n" {
				t.Fatalf("catalog = %s", data)
			}
			if err := store.Remove(paths, name); err != nil {
				t.Fatal(err)
			}
			_, _, err = store.Read(paths)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
