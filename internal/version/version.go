// SPDX-License-Identifier: Apache-2.0

// Package version reports the provider's build: the ldflags values when
// injected, else the module build information, else "dev".
package version

import (
	"runtime/debug"

	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
)

// Set at build time through
// -ldflags "-X .../internal/version.version=v0.1.0 -X .../internal/version.revision=abc -X .../internal/version.dirty=true".
var (
	version  = ""
	revision = ""
	dirty    = ""
)

// Contract is the normative contract this build implements.
const Contract = netprofile.Schema

// Info is the resolved build description.
type Info struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
	Dirty    bool   `json:"dirty"`
	Contract string `json:"contract"`
}

// Get resolves the build description: ldflags first, then
// debug.ReadBuildInfo (Main.Version, vcs.revision, vcs.modified), then
// "dev".
func Get() Info {
	info, ok := debug.ReadBuildInfo()
	return resolve(version, revision, dirty, info, ok)
}

func resolve(v, rev, dirtyFlag string, info *debug.BuildInfo, ok bool) Info {
	out := Info{Version: v, Revision: rev, Dirty: dirtyFlag == "true", Contract: Contract}
	if ok && info != nil {
		if out.Version == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			out.Version = info.Main.Version
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if out.Revision == "" {
					out.Revision = s.Value
				}
			case "vcs.modified":
				if dirtyFlag == "" {
					out.Dirty = s.Value == "true"
				}
			}
		}
	}
	if out.Version == "" {
		out.Version = "dev"
	}
	if out.Revision == "" {
		out.Revision = "unknown"
	}
	return out
}

// Line renders `<name> <version> (revision <rev>[, dirty]; contract <contract>)`.
func (i Info) Line(name string) string {
	s := name + " " + i.Version + " (revision " + i.Revision
	if i.Dirty {
		s += ", dirty"
	}
	return s + "; contract " + i.Contract + ")"
}
