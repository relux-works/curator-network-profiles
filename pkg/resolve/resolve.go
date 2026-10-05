// SPDX-License-Identifier: Apache-2.0

// Package resolve implements the selection precedence of
// spec/network-profiles.md N4 and the resolution of a selection against
// the machine's catalog: allowed set, existence, assurance, confirmation
// and engine coverage (N12). It is a lookup, never a probe (N13).
package resolve

import (
	"strings"

	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

// Origin is where the selected profile reference came from (spec N3).
type Origin string

const (
	OriginExplicit        Origin = "explicit"
	OriginInherited       Origin = "inherited"
	OriginRuntimeDefault  Origin = "runtime-default"
	OriginProfileBinding  Origin = "profile-binding"
	OriginProjectDefault  Origin = "project-default"
	OriginOperatorDefault Origin = "operator-default"
)

// Selection is what the caller asked (spec N3 NetworkSelection).
type Selection struct {
	ProfileRef        string `json:"profile_ref"`
	Origin            Origin `json:"origin"`
	RequiredAssurance string `json:"required_assurance"`
}

// Request carries the candidate references in precedence order and the
// caller's constraints. The operator default is read from the file; inherited
// references are supplied by the process owner, never discovered from env.
type Request struct {
	// Explicit is `--network <name>`.
	Explicit string
	// Inherited is the parent's resolved reference persisted by the process
	// owner at reservation. Resolve looks it up afresh on the child's host;
	// proxy values and the parent's environment never supply this reference.
	Inherited string
	// RuntimeDefault is the runtime binding's `network` (LP-D2).
	RuntimeDefault string
	// CuratorProfile is the optional profile name to look up in the operator's
	// [bindings.profiles]. The binding is never supplied by a project or profile.
	CuratorProfile string
	// ProjectDefault is the project's `spawn.network.default`.
	ProjectDefault string
	// RequiredAssurance is cooperative when empty. Slice A refuses
	// enforced (spec N4).
	RequiredAssurance string
	// Allowed is the host lock or allowed set: nil allows every profile,
	// an empty non-nil set allows none.
	Allowed []string
	// EngineHosts are the loopback engine hosts of this launch (spec N12);
	// each must be covered by a proxy profile's bypass_hosts. Direct has
	// no proxy and therefore nothing to bypass.
	EngineHosts []string
}

// Confirmations answers whether a profile is confirmed at a digest.
type Confirmations interface {
	Confirmed(name, digest string) bool
}

// ConfirmedFunc adapts a function to Confirmations.
type ConfirmedFunc func(name, digest string) bool

// Confirmed calls f.
func (f ConfirmedFunc) Confirmed(name, digest string) bool { return f(name, digest) }

// None confirms nothing; it is the ledger of a machine without one.
var None Confirmations = ConfirmedFunc(func(string, string) bool { return false })

// Result is a resolved selection. Managed=false is the unmanaged
// outcome: no selection at all, today's behaviour, an empty patch.
type Result struct {
	Managed   bool
	Selection Selection
	Profile   netprofile.Profile
	Digest    string
	Assurance string
}

// Select applies the N4 reference precedence only: explicit → inherited →
// runtime default → profile binding → project default → operator default. Resolve enforces
// host locks and the allowed set on the selected reference. It reports
// ok=false when nothing selects a profile. It is the lookup a router's
// CandidateResolver needs (spec N13) and performs no validation.
func Select(file *netprofile.File, req Request) (Selection, bool) {
	assurance := req.RequiredAssurance
	if assurance == "" {
		assurance = binding.AssuranceCooperative
	}
	for _, c := range []struct {
		ref    string
		origin Origin
	}{
		{req.Explicit, OriginExplicit},
		{req.Inherited, OriginInherited},
		{req.RuntimeDefault, OriginRuntimeDefault},
		{profileBinding(file, req.CuratorProfile), OriginProfileBinding},
		{req.ProjectDefault, OriginProjectDefault},
		{fileDefault(file), OriginOperatorDefault},
	} {
		if ref := strings.TrimSpace(c.ref); ref != "" {
			return Selection{ProfileRef: ref, Origin: c.origin, RequiredAssurance: assurance}, true
		}
	}
	return Selection{RequiredAssurance: assurance}, false
}

func profileBinding(file *netprofile.File, name string) string {
	if file == nil || name == "" {
		return ""
	}
	return file.Bindings.Profiles[name]
}

func fileDefault(file *netprofile.File) string {
	if file == nil {
		return ""
	}
	return file.Default
}

// Resolve selects by N4 and checks the selection: the allowed set
// (network_profile_denied), existence (network_profile_unknown; a nil
// file has no profiles), the assurance level (network_scope_unsupported
// for enforced), confirmation at the current digest
// (network_profile_denied, detail "unconfirmed") and engine coverage
// (network_configuration_conflict). No selection is the unmanaged
// result, never an error. A file that could not be read must be refused
// by the caller before Resolve; a read failure is never headroom.
func Resolve(file *netprofile.File, ledger Confirmations, req Request) (*Result, error) {
	sel, ok := Select(file, req)
	if !ok {
		return &Result{Managed: false, Selection: sel}, nil
	}
	name := sel.ProfileRef
	if req.Allowed != nil && !allowed(req.Allowed, name) {
		return nil, refusal.New(refusal.CodeProfileDenied, name, "not in the allowed set of this host")
	}
	profile, found := file.Lookup(name)
	if !found {
		return nil, refusal.New(refusal.CodeProfileUnknown, name, "no such network profile on this machine")
	}
	switch sel.RequiredAssurance {
	case binding.AssuranceCooperative:
	case binding.AssuranceEnforced:
		// TODO(decision): spec N4 refuses an enforced request on a
		// cooperative-only machine but names no code; scope_unsupported
		// is the closest (the launch shape cannot provide the scope).
		return nil, refusal.New(refusal.CodeScopeUnsupported, name, "enforced assurance is not available; this machine provides cooperative only")
	default:
		return nil, refusal.New(refusal.CodeScopeUnsupported, name, "unknown assurance level requested")
	}
	digest := netprofile.Digest(profile)
	if ledger == nil {
		ledger = None
	}
	if !ledger.Confirmed(name, digest) {
		return nil, refusal.New(refusal.CodeProfileDenied, name, "unconfirmed: run `curator network confirm "+name+"` from a terminal")
	}
	for _, host := range req.EngineHosts {
		if profile.Kind != netprofile.KindDirect && !profile.Covers(host) {
			return nil, refusal.New(refusal.CodeConfigurationConflict, name, "engine host "+netprofile.HostKey(host)+" is not in bypass_hosts")
		}
	}
	return &Result{
		Managed:   true,
		Selection: sel,
		Profile:   profile,
		Digest:    digest,
		Assurance: binding.AssuranceCooperative,
	}, nil
}

func allowed(set []string, name string) bool {
	for _, s := range set {
		if strings.TrimSpace(s) == name {
			return true
		}
	}
	return false
}
