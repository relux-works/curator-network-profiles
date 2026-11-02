// SPDX-License-Identifier: Apache-2.0
package adapterprobe

import (
	"context"
	"testing"
)

// Native-container snapshots of the observed executable size and the inclusive
// 512 MiB ceiling retain the independently computed full-byte digest. This is
// snapshot identity evidence, not executable or transport qualification.
func TestNativeArtifactSizeBoundary(t *testing.T) {
	const maximum = 512 << 20
	data := make([]byte, maximum+1)
	copy(data, []byte{0xcf, 0xfa, 0xed, 0xfe})
	for _, tc := range []struct {
		name   string
		size   int
		digest string
	}{
		{"observed-size", 310114176, "9066a0e515b89d9d390693da6c689392eccbc756f9a9796aff7186faf6507530"},
		{"inclusive-limit", maximum, "ab762f62190191cf7b4e1237308fcab666748de39aeaccbdfb3349f450359f4d"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data[tc.size-1] = 0xa5
			defer func() { data[tc.size-1] = 0 }()
			req := request()
			req.Artifact = data[:tc.size]
			res, err := identify(context.Background(), req)
			if err != nil {
				t.Fatalf("valid native snapshot of %d bytes refused: %v", tc.size, err)
			}
			if res.BinarySHA256 != tc.digest || res.BuildID != "sha256-"+tc.digest {
				t.Fatalf("full-byte identity mismatch: %+v", res)
			}
		})
	}
	// A single byte above the ceiling must produce the intended refusal; the
	// pure identity operation neither stages nor launches an executable.
	req := request()
	req.Artifact = data
	res, err := identify(context.Background(), req)
	assertFailure(t, res, err, "artifact_too_large")
}
