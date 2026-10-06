// SPDX-License-Identifier: Apache-2.0
package adapterprobe

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/envpatch"
)

// Outcome is the policy verdict of Evaluate.
type Outcome string

const (
	// OutcomeQualified is an exact allowlisted or evidenced build. A
	// content pin alone never qualifies: it proves identity, not proxy
	// conformance.
	OutcomeQualified Outcome = "qualified"
	// OutcomeUnqualified is a known vendor line without evidence. The
	// consumer MUST show Provenance.OperatorText at launch and store
	// the provenance in the session record.
	OutcomeUnqualified Outcome = "unqualified"
	// OutcomeRefused stops the launch with a typed reason.
	OutcomeRefused Outcome = "refused"
)

// ProvenanceSchema versions the unqualified-build provenance record.
const ProvenanceSchema = "relux-adapter-provenance-v1"

// Provenance is the typed unqualified-build record. Consumers MUST show
// OperatorText to the operator at launch and store this record in the
// session record, not only in a log.
type Provenance struct {
	Schema       string   `json:"schema"`
	Adapter      Identity `json:"adapter"`
	BuildID      string   `json:"build_id"`
	BinarySHA256 string   `json:"binary_sha256"`
	Recipe       string   `json:"recipe"`
	Scope        string   `json:"scope"`
	Outcome      string   `json:"outcome"`
}

// OperatorText is the EXACT operator-facing text for an unqualified
// build. Consumers show it verbatim.
func (p Provenance) OperatorText() string {
	return fmt.Sprintf("Unqualified build: %s %s/%s build %s (recipe %s) has no conformance evidence. Traffic may escape the proxy on this unproven build. This is a policy gap, not credential exposure.",
		p.Adapter.Harness, p.Adapter.Adapter, p.Adapter.Entrypoint, p.BuildID, p.Recipe)
}

// Decision is the result of Evaluate. Provenance is set only for
// OutcomeUnqualified. Refusals carry the same typed reason as the
// returned error.
type Decision struct {
	Outcome       Outcome
	Reason        string
	EffectiveMode Mode
	BuildID       string
	BinarySHA256  string
	Adapter       Identity
	Recipe        string
	Provenance    *Provenance
}

// BoundIdentity converts an admitted Decision (qualified or unqualified)
// to the durable consumer tuple. It is independent of conformance
// evidence: unqualified builds are admitted with visible provenance, not
// silently promoted to evidence. Refused decisions fail, as do malformed
// identities. Child/host authorization remains a separate gate.
func (d Decision) BoundIdentity() (binding.AdapterIdentity, error) {
	build, err := BuildID(d.BinarySHA256)
	if err != nil || d.BuildID != build || d.Adapter.Adapter != envpatch.AdapterGeneric || !identityRE.MatchString(d.Adapter.Harness) || !identityRE.MatchString(d.Adapter.Entrypoint) || !recipeRE.MatchString(d.Recipe) {
		return binding.AdapterIdentity{}, &Unsupported{Reason: "invalid_evidence"}
	}
	switch d.Outcome {
	case OutcomeQualified:
		if d.Reason != "allowlisted" && d.Reason != "proxy_attempt_observed" {
			return binding.AdapterIdentity{}, &Unsupported{Reason: "invalid_evidence"}
		}
		if d.Provenance != nil {
			return binding.AdapterIdentity{}, &Unsupported{Reason: "invalid_evidence"}
		}
	case OutcomeUnqualified:
		if d.Reason != "unqualified_build" || d.Provenance == nil {
			return binding.AdapterIdentity{}, &Unsupported{Reason: "invalid_evidence"}
		}
		p := d.Provenance
		if p.Schema != ProvenanceSchema || p.Outcome != "unqualified_build" || p.Scope != TransportScope || p.Adapter != d.Adapter || p.BuildID != d.BuildID || p.BinarySHA256 != d.BinarySHA256 || p.Recipe != d.Recipe {
			return binding.AdapterIdentity{}, &Unsupported{Reason: "invalid_evidence"}
		}
	default:
		return binding.AdapterIdentity{}, &Unsupported{Reason: "invalid_evidence"}
	}
	return binding.AdapterIdentity{Adapter: d.Adapter.Adapter, Harness: d.Adapter.Harness, Build: build, Entrypoint: d.Adapter.Entrypoint}, nil
}

// EffectiveMode resolves the policy mode for a profile: pinned stays
// pinned, an explicit strict or a sensitive_egress declaration selects
// strict, anything else is optimistic. A sensitive declaration cannot
// be downgraded to optimistic by the mode flag.
func EffectiveMode(policy Policy) Mode {
	switch policy.Mode {
	case Pinned:
		return Pinned
	case Strict:
		return Strict
	case Optimistic:
		if policy.SensitiveEgress {
			return Strict
		}
		return Optimistic
	default:
		return policy.Mode
	}
}

// KnownVendorLine reports whether the identity names a known vendor
// line: the generic adapter with a harness that owns at least one
// registered recipe revision. Unknown adapters and unknown harnesses
// refuse; a known line is necessary but not sufficient for launch,
// since consumers retain their exact-tuple allowlists.
func KnownVendorLine(id Identity) bool {
	if id.Adapter != envpatch.AdapterGeneric {
		return false
	}
	for _, recipe := range recipes {
		if recipe.Harness == id.Harness {
			return true
		}
	}
	return false
}

func knownBadReason(err error) string {
	var unsupported *Unsupported
	if errors.As(err, &unsupported) {
		switch unsupported.Reason {
		case "knownbad_corrupt", "knownbad_version_unsupported", "knownbad_unreadable":
			return unsupported.Reason
		}
	}
	return "knownbad_unreadable"
}

func refused(req Request, policy Policy, reason string) Decision {
	return Decision{Outcome: OutcomeRefused, Reason: reason, EffectiveMode: EffectiveMode(policy), Adapter: req.Adapter, Recipe: req.Recipe}
}

func qualified(res Result, req Request, policy Policy, reason string) Decision {
	return Decision{Outcome: OutcomeQualified, Reason: reason, EffectiveMode: EffectiveMode(policy), BuildID: res.BuildID, BinarySHA256: res.BinarySHA256, Adapter: req.Adapter, Recipe: req.Recipe}
}

func interruptedDecision(ctx context.Context, res Result, req Request, policy Policy) (Decision, error) {
	reason := "cancelled"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		reason = "deadline_exceeded"
	}
	d := refused(req, policy, reason)
	d.BuildID, d.BinarySHA256 = res.BuildID, res.BinarySHA256
	return d, &Unsupported{Reason: reason}
}

// Evaluate applies the option-C launch policy to a caller-supplied
// artifact snapshot. It performs no execution, opens no paths, reads no
// operator configuration, Keychain or tokens, and writes no state. It is
// the only consumer path for admission: plans, direct profiles, real
// launches and reattach all evaluate here, never via Lookup.
//
// Order: a failed known-bad list refuses before anything else; policy
// validity; snapshot identity; known-bad membership (embedded always
// enforced); known vendor line; recipe binding; the content-pin
// admission constraint; exact allowlist; then the effective mode. A
// missing or different pin refuses with pinned_miss before every
// positive return, including allowlist and evidence hits. An allowlist
// establishes conformance only after the pin matches. A pin alone never
// qualifies: only an independently allowlisted or evidenced build is
// qualified. Strict (including sensitive profiles) refuses unknown
// builds; pinned non-sensitive consults scoped evidence and otherwise
// returns the build as unqualified with its provenance; optimistic does
// the same without a pin.
//
// The optimistic evidence lookup is the seam for central qualification:
// a future signed-evidence source plugs in where the process-local
// cache is consulted today, ahead of the unqualified fallback.
func Evaluate(ctx context.Context, req Request, policy Policy) (Decision, error) {
	if policy.KnownBadErr != nil {
		reason := knownBadReason(policy.KnownBadErr)
		return refused(req, policy, reason), &Unsupported{Reason: reason}
	}
	if policy.NegativeTTL < 0 {
		return refused(req, policy, "invalid_policy"), &Unsupported{Reason: "invalid_policy"}
	}
	switch policy.Mode {
	case Optimistic, Strict, Pinned:
	default:
		return refused(req, policy, "invalid_policy"), &Unsupported{Reason: "invalid_policy"}
	}
	ctx, cancel := bounded(ctx, req)
	defer cancel()
	res, err := identify(ctx, req)
	if err != nil {
		d := refused(req, policy, res.Reason)
		d.BuildID, d.BinarySHA256 = res.BuildID, res.BinarySHA256
		return d, err
	}
	// The embedded list is non-optional: it is always enforced, even
	// when the caller supplies an empty or non-matching operator set.
	known := EmbeddedKnownBad().Union(policy.KnownBad)
	if known.Contains(res.BinarySHA256) {
		d := refused(req, policy, "known_bad_build")
		d.BuildID, d.BinarySHA256 = res.BuildID, res.BinarySHA256
		return d, &Unsupported{Reason: "known_bad_build"}
	}
	if !KnownVendorLine(req.Adapter) {
		d := refused(req, policy, "vendor_line_unsupported")
		d.BuildID, d.BinarySHA256 = res.BuildID, res.BinarySHA256
		return d, &Unsupported{Reason: "vendor_line_unsupported"}
	}
	recipe, ok := recipes[req.Recipe]
	if !ok || recipe.Harness != req.Adapter.Harness || recipe.Entrypoint != req.Adapter.Entrypoint {
		d := refused(req, policy, "recipe_unsupported")
		d.BuildID, d.BinarySHA256 = res.BuildID, res.BinarySHA256
		return d, &Unsupported{Reason: "recipe_unsupported"}
	}
	// recipe.Unavailable governs automatic qualification, which option C
	// never attempts; it does not block the policy decision.
	// The pin is an admission constraint, not a qualification: it is
	// validated before every positive return.
	if policy.Mode == Pinned && policy.PinnedBuild != res.BuildID {
		d := refused(req, policy, "pinned_miss")
		d.BuildID, d.BinarySHA256 = res.BuildID, res.BinarySHA256
		return d, &Unsupported{Reason: "pinned_miss"}
	}
	for _, allowed := range policy.Allowlist {
		if ctx.Err() != nil {
			return interruptedDecision(ctx, res, req, policy)
		}
		if allowed.Adapter == req.Adapter && allowed.BuildID == res.BuildID && allowed.Recipe == req.Recipe && allowed.Platform == runtime.GOOS && allowed.Scope == TransportScope {
			if ctx.Err() != nil {
				return interruptedDecision(ctx, res, req, policy)
			}
			return qualified(res, req, policy, "allowlisted"), nil
		}
	}
	switch EffectiveMode(policy) {
	case Strict:
		d := refused(req, policy, "strict_miss")
		d.BuildID, d.BinarySHA256 = res.BuildID, res.BinarySHA256
		return d, &Unsupported{Reason: "strict_miss"}
	case Pinned:
		// Pin matched and no allowlist hit. A sensitive profile
		// admits only exact allowlisted builds: an identity-only pin
		// never qualifies and never yields unqualified here.
		if policy.SensitiveEgress {
			d := refused(req, policy, "strict_miss")
			d.BuildID, d.BinarySHA256 = res.BuildID, res.BinarySHA256
			return d, &Unsupported{Reason: "strict_miss"}
		}
		// Non-sensitive pinned: fall through to the scoped-evidence
		// check below; without evidence the exact pin runs as
		// unqualified with its provenance, never as qualified.
	default:
	}
	if req.Cache != nil {
		cached, ok, err := req.Cache.lookup(ctx, req, res, policy)
		if ctx.Err() != nil {
			return interruptedDecision(ctx, res, req, policy)
		}
		if err != nil {
			d := refused(req, policy, "cache_integrity_failed")
			d.BuildID, d.BinarySHA256 = res.BuildID, res.BinarySHA256
			return d, &Unsupported{Reason: "cache_integrity_failed"}
		}
		if ok {
			if !cached.Verified {
				d := refused(req, policy, cached.Reason)
				d.BuildID, d.BinarySHA256 = cached.BuildID, cached.BinarySHA256
				return d, &Unsupported{Reason: cached.Reason}
			}
			if ctx.Err() != nil {
				return interruptedDecision(ctx, res, req, policy)
			}
			return qualified(cached, req, policy, cached.Reason), nil
		}
	}
	if ctx.Err() != nil {
		return interruptedDecision(ctx, res, req, policy)
	}
	return Decision{
		Outcome:       OutcomeUnqualified,
		Reason:        "unqualified_build",
		EffectiveMode: EffectiveMode(policy),
		BuildID:       res.BuildID,
		BinarySHA256:  res.BinarySHA256,
		Adapter:       req.Adapter,
		Recipe:        req.Recipe,
		Provenance: &Provenance{
			Schema:       ProvenanceSchema,
			Adapter:      req.Adapter,
			BuildID:      res.BuildID,
			BinarySHA256: res.BinarySHA256,
			Recipe:       req.Recipe,
			Scope:        res.Scope,
			Outcome:      "unqualified_build",
		},
	}, nil
}
