// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"os"
	"testing"

	"github.com/relux-works/curator-network-profiles/internal/store"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

func TestRemoveAbsentCatalogDoesNotCreateNamespace(t *testing.T) {
	p, err := store.PathsFromEnv([]string{"HOME=" + t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Remove(p, "absent")
	if code, _ := refusal.CodeOf(err); code != refusal.CodeProfileUnknown {
		t.Fatalf("remove absent: %v", err)
	}
	if _, err := os.Lstat(p.Dir); !os.IsNotExist(err) {
		t.Fatalf("remove created namespace: %v", err)
	}
}
