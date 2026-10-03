// SPDX-License-Identifier: Apache-2.0

package version

import (
	"runtime/debug"
	"testing"
)

func TestResolveOrder(t *testing.T) {
	t.Parallel()
	bi := &debug.BuildInfo{Main: debug.Module{Version: "v0.2.0"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abcdef"}, {Key: "vcs.modified", Value: "true"}}}
	cases := []struct {
		name          string
		v, rev, dirty string
		info          *debug.BuildInfo
		ok            bool
		want          Info
		line          string
	}{
		{"ldflags win", "v1.0.0", "deadbeef", "false", bi, true, Info{"v1.0.0", "deadbeef", false, Contract}, "curator-network v1.0.0 (revision deadbeef; contract relux-network-profiles-v1)"},
		{"ldflags dirty", "v1.0.0", "deadbeef", "true", bi, true, Info{"v1.0.0", "deadbeef", true, Contract}, "curator-network v1.0.0 (revision deadbeef, dirty; contract relux-network-profiles-v1)"},
		{"build info fallback", "", "", "", bi, true, Info{"v0.2.0", "abcdef", true, Contract}, "curator-network v0.2.0 (revision abcdef, dirty; contract relux-network-profiles-v1)"},
		{"devel is not a version", "", "", "", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, Info{"dev", "unknown", false, Contract}, "curator-network dev (revision unknown; contract relux-network-profiles-v1)"},
		{"no build info", "", "", "", nil, false, Info{"dev", "unknown", false, Contract}, "curator-network dev (revision unknown; contract relux-network-profiles-v1)"},
		{"partial ldflags", "", "rev1", "", bi, true, Info{"v0.2.0", "rev1", true, Contract}, "curator-network v0.2.0 (revision rev1, dirty; contract relux-network-profiles-v1)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resolve(tc.v, tc.rev, tc.dirty, tc.info, tc.ok)
			if got != tc.want {
				t.Fatalf("resolve = %+v, want %+v", got, tc.want)
			}
			if l := got.Line("curator-network"); l != tc.line {
				t.Fatalf("Line = %q, want %q", l, tc.line)
			}
		})
	}
	if got := Get(); got.Version == "" || got.Revision == "" || got.Contract != "relux-network-profiles-v1" {
		t.Fatalf("Get = %+v", got)
	}
}
