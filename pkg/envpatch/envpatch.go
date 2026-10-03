// SPDX-License-Identifier: Apache-2.0

// Package envpatch implements the environment patch of
// spec/network-profiles.md N3/N5 and spec/contract-appendix.md §2: two
// ordered operations, `unset` then `set`, applied by the host that
// creates the child process to that child's private environment.
//
// The package is pure. Apply never calls os.Setenv, never reads the
// process environment and never mutates its input; it returns a new
// slice. The only adapter of slice A is the generic environment adapter
// generic-env-v1; a harness adapter that adds verified variables
// (ALL_PROXY, websocket settings) implements Adapter beside it.
package envpatch

import (
	"strings"

	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
)

// AdapterGeneric is the adapter identifier reported by Generic.
const AdapterGeneric = "generic-env-v1"

// unsetNames is the reserved proxy family in both canonical spellings
// (the same set curator's scriptworker reserves). Apply matches these
// names case-insensitively, so Http_Proxy is removed as well.
var unsetNames = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy",
}

// Pair is one `set` entry.
type Pair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Patch is `unset` then `set`. An empty patch is the unmanaged outcome:
// Apply returns the input unchanged (a copy).
type Patch struct {
	// Unset lists canonical variable names; Apply removes every inherited
	// entry whose name equals one of them case-insensitively.
	Unset []string `json:"unset"`
	// Set is applied in order after Unset; a name set here cannot survive
	// twice in the result.
	Set []Pair `json:"set"`
}

// Adapter builds the patch for a profile. Identity is the adapter part of
// binding.AdapterIdentity.
type Adapter interface {
	Identity() string
	Patch(p netprofile.Profile) Patch
}

// Generic is generic-env-v1: the coherent set of spec N5 and nothing else.
type Generic struct{}

// Identity returns AdapterGeneric.
func (Generic) Identity() string { return AdapterGeneric }

// Patch returns unset = the reserved family, set = HTTP_PROXY,
// HTTPS_PROXY, http_proxy, https_proxy = endpoint and NO_PROXY, no_proxy
// = bypass_hosts joined by "," in normalized order. ALL_PROXY, websocket
// variables and runtime settings are never set by the generic adapter.
// Direct profiles use the same unset family with an empty set.
func (Generic) Patch(p netprofile.Profile) Patch {
	if p.Kind == netprofile.KindDirect {
		return Patch{Unset: UnsetNames(), Set: []Pair{}}
	}
	bypass := strings.Join(p.BypassHosts, ",")
	return Patch{
		Unset: UnsetNames(),
		Set: []Pair{
			{"HTTP_PROXY", p.Endpoint},
			{"HTTPS_PROXY", p.Endpoint},
			{"http_proxy", p.Endpoint},
			{"https_proxy", p.Endpoint},
			{"NO_PROXY", bypass},
			{"no_proxy", bypass},
		},
	}
}

// Unmanaged is the patch of a launch with no selection: empty, so the
// child keeps today's environment untouched.
func Unmanaged() Patch { return Patch{} }

// UnsetNames returns a copy of the reserved proxy family, the `unset`
// half of every generic patch.
func UnsetNames() []string {
	out := make([]string, len(unsetNames))
	copy(out, unsetNames)
	return out
}

// Empty reports whether the patch changes nothing.
func (p Patch) Empty() bool { return len(p.Unset) == 0 && len(p.Set) == 0 }

// SetLiterals returns a copy of the `set` half: the owned literals a
// tracked transport carries as env_literals (spec N9).
func (p Patch) SetLiterals() []Pair {
	out := make([]Pair, len(p.Set))
	copy(out, p.Set)
	return out
}

// UnsetNames returns a copy of the `unset` half.
func (p Patch) UnsetNames() []string {
	out := make([]string, len(p.Unset))
	copy(out, p.Unset)
	return out
}

// Apply returns a new environment: every entry whose name matches an
// Unset name case-insensitively or a Set name exactly is removed, the
// order of the remaining entries is preserved, then the Set pairs are
// appended in order. Entries without "=" have no name; they are kept
// as they are. The input slice is never modified.
func (p Patch) Apply(env []string) []string {
	out := make([]string, 0, len(env)+len(p.Set))
	for _, entry := range env {
		name, _, ok := strings.Cut(entry, "=")
		if ok && (p.unsets(name) || p.sets(name)) {
			continue
		}
		out = append(out, entry)
	}
	for _, kv := range p.Set {
		out = append(out, kv.Name+"="+kv.Value)
	}
	return out
}

func (p Patch) unsets(name string) bool {
	for _, u := range p.Unset {
		if strings.EqualFold(name, u) {
			return true
		}
	}
	return false
}

func (p Patch) sets(name string) bool {
	for _, kv := range p.Set {
		if kv.Name == name {
			return true
		}
	}
	return false
}
