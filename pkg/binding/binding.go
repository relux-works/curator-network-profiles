// SPDX-License-Identifier: Apache-2.0

// Package binding defines the applied network binding of
// spec/network-profiles.md N3, the manifest-safe Record, binding
// equality, and the reattach/resume transitions of N7.
package binding

import (
	"time"

	"github.com/relux-works/curator-network-profiles/pkg/envpatch"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

// SchemaRecord versions the manifest-safe binding record.
const SchemaRecord = "relux-network-binding-record-v1"

// Assurance levels. Slice A publishes cooperative only (spec N4).
const (
	AssuranceCooperative = "cooperative"
	AssuranceEnforced    = "enforced"
)

// AdapterIdentity is the launch-shape tuple support is verified for
// (spec N7): the adapter, the harness, its build and its entrypoint.
// Two identities are equal when all four strings are equal.
type AdapterIdentity struct {
	Adapter    string `json:"adapter"`
	Harness    string `json:"harness"`
	Build      string `json:"build"`
	Entrypoint string `json:"entrypoint"`
}

// Equal reports member-wise equality.
func (a AdapterIdentity) Equal(b AdapterIdentity) bool { return a == b }

// Binding is what a process owner applies immediately before spawn.
type Binding struct {
	ProfileRef       string
	ProfileDigest    string
	AdapterIdentity  AdapterIdentity
	Assurance        string
	ResolvedEndpoint string
	EnvPatch         envpatch.Patch
}

// ProbeRecord is the probe outcome a manifest keeps: three facts and
// when they were observed. Values are "ok", "failed" or "skipped".
type ProbeRecord struct {
	TCP       string    `json:"tcp"`
	Connect   string    `json:"connect"`
	TLS       string    `json:"tls"`
	CheckedAt time.Time `json:"checked_at"`
}

// Record is the manifest-safe subset of a binding: never the
// environment, never an endpoint, never a credential.
type Record struct {
	Schema          string          `json:"schema"`
	ProfileRef      string          `json:"profile_ref"`
	ProfileDigest   string          `json:"profile_digest"`
	AdapterIdentity AdapterIdentity `json:"adapter_identity"`
	Assurance       string          `json:"assurance"`
	Origin          string          `json:"origin"`
	Probe           ProbeRecord     `json:"probe"`
}

// Record builds the manifest record of b with the selection origin and
// the probe outcome of this launch. Origins are explicit, inherited,
// runtime-default, profile-binding, project-default and operator-default (spec N3).
func (b Binding) Record(origin string, probe *ProbeRecord) Record {
	pr := ProbeRecord{TCP: "skipped", Connect: "skipped", TLS: "skipped"}
	if probe != nil {
		pr = *probe
	}
	normalize := func(s string) string {
		switch s {
		case "":
			return "skipped"
		case "ok", "skipped", "failed":
			return s
		default:
			return "failed"
		}
	}
	pr.TCP, pr.Connect, pr.TLS = normalize(pr.TCP), normalize(pr.Connect), normalize(pr.TLS)
	return Record{
		Schema:          SchemaRecord,
		ProfileRef:      b.ProfileRef,
		ProfileDigest:   b.ProfileDigest,
		AdapterIdentity: b.AdapterIdentity,
		Assurance:       b.Assurance,
		Origin:          origin,
		Probe:           pr,
	}
}

// Equal is spec N3 binding equality: profile_digest, adapter_identity
// and assurance. profile_ref, resolved_endpoint, the patch, probe
// results, lease and generation are excluded.
func Equal(a, b Binding) bool {
	return equal(a.ProfileDigest, a.AdapterIdentity, a.Assurance, b.ProfileDigest, b.AdapterIdentity, b.Assurance)
}

// RecordEqual compares a recorded binding with a fresh one by the same
// three members.
func RecordEqual(r Record, b Binding) bool {
	return equal(r.ProfileDigest, r.AdapterIdentity, r.Assurance, b.ProfileDigest, b.AdapterIdentity, b.Assurance)
}

func equal(d1 string, a1 AdapterIdentity, s1 string, d2 string, a2 AdapterIdentity, s2 string) bool {
	return d1 != "" && d1 == d2 && a1.Equal(a2) && s1 == s2
}

// Event is the N7 situation being decided.
type Event string

const (
	// EventNewLaunch is a fresh process: resolve, bind, launch.
	EventNewLaunch Event = "new-launch"
	// EventNewAssignment is a new assignment placed on an already
	// running host (an app-server, a daemon).
	EventNewAssignment Event = "new-assignment"
	// EventReattach is a reattach or resume of an existing run.
	EventReattach Event = "reattach"
)

// Outcome is the N7 verdict when nothing is refused.
type Outcome string

const (
	OutcomeLaunch        Outcome = "launch"
	OutcomeAttach        Outcome = "attach"
	OutcomeSetPerSession Outcome = "set-per-session"
	OutcomeReattach      Outcome = "reattach"
)

// CheckReattach implements the N7 transition table. recorded is the
// host's or run's recorded binding, fresh the resolution made now,
// perSessionRoute whether the adapter can set the route per session.
//
//	new launch                                        → launch
//	new assignment, equal                             → attach
//	new assignment, differs, per-session route        → set-per-session
//	new assignment, differs, no per-session route     → network_scope_unsupported
//	reattach, equal                                   → reattach
//	reattach, same ref, different digest              → network_profile_drift
//	reattach, other difference                        → network_scope_unsupported
//
// Profile missing or denied is decided earlier by resolve and never
// reaches this function. TODO(decision): N7 has no row for a resume
// whose adapter identity or assurance differs, or that selects another
// profile; both are refused as network_scope_unsupported (a session-level
// profile change is not in the MVP) rather than re-routed.
func CheckReattach(recorded Record, fresh Binding, event Event, perSessionRoute bool) (Outcome, error) {
	switch event {
	case EventNewLaunch:
		return OutcomeLaunch, nil
	case EventNewAssignment:
		if RecordEqual(recorded, fresh) {
			return OutcomeAttach, nil
		}
		if perSessionRoute {
			return OutcomeSetPerSession, nil
		}
		return "", refusal.New(refusal.CodeScopeUnsupported, fresh.ProfileRef,
			"the running host is bound to a different network profile and the adapter cannot route per session")
	case EventReattach:
		if RecordEqual(recorded, fresh) {
			return OutcomeReattach, nil
		}
		if recorded.ProfileRef == fresh.ProfileRef && recorded.ProfileDigest != fresh.ProfileDigest {
			return "", refusal.New(refusal.CodeProfileDrift, fresh.ProfileRef,
				"the profile content changed since the run was recorded; restore the profile or start a new launch")
		}
		return "", refusal.New(refusal.CodeScopeUnsupported, fresh.ProfileRef,
			"the recorded binding differs from the fresh resolution; changing the network binding of an existing run is not supported")
	default:
		return "", refusal.New(refusal.CodeScopeUnsupported, fresh.ProfileRef, "unknown reattach event")
	}
}
