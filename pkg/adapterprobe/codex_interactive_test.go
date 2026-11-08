// SPDX-License-Identifier: Apache-2.0
package adapterprobe

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

// An exact allowlisted synthetic container admits only the canonical interactive
// tuple. This policy test executes no Codex and makes no transport qualification.
func TestCodexInteractiveRecipe(t *testing.T) {
	req := Request{Adapter: Identity{Adapter: "generic-env-v1", Harness: "codex-cli", Entrypoint: "interactive"}, Artifact: []byte("\x7fELFcodex-native-snapshot"), Recipe: "codex-interactive-v1"}
	build, digest := digestOf(t, req)
	allow := AllowedBuild{Adapter: req.Adapter, BuildID: build, Recipe: req.Recipe, Platform: runtime.GOOS, Scope: TransportScope}
	cases := []struct {
		name   string
		mutate func(*Request, *Policy)
		want   Outcome
		reason string
	}{
		{"exact", nil, OutcomeQualified, "allowlisted"},
		{"absent", func(r *Request, p *Policy) { p.Allowlist = nil }, OutcomeRefused, "strict_miss"},
		{"different-bytes", func(r *Request, p *Policy) { r.Artifact = []byte("\x7fELFdifferent") }, OutcomeRefused, "strict_miss"},
		{"exec-row", func(r *Request, p *Policy) {
			p.Allowlist[0].Adapter.Entrypoint = "exec"
			p.Allowlist[0].Recipe = "codex-exec-v1"
		}, OutcomeRefused, "strict_miss"},
		{"wrong-recipe", func(r *Request, p *Policy) { r.Recipe = "codex-exec-v1" }, OutcomeRefused, "recipe_unsupported"},
		{"exec-with-interactive-recipe", func(r *Request, p *Policy) { r.Adapter.Entrypoint = "exec" }, OutcomeRefused, "recipe_unsupported"},
		{"hosted-with-interactive-recipe", func(r *Request, p *Policy) { r.Adapter.Entrypoint = "app-server" }, OutcomeRefused, "recipe_unsupported"},
		{"no-system-alias", func(r *Request, p *Policy) { r.Adapter.Harness = "codex" }, OutcomeRefused, "vendor_line_unsupported"},
		{"known-bad", func(r *Request, p *Policy) { p.KnownBad = knownBadWith(t, digest) }, OutcomeRefused, "known_bad_build"},
		{"pin-mismatch", func(r *Request, p *Policy) { p.Mode = Pinned; p.PinnedBuild = "sha256-" + strings.Repeat("a", 64) }, OutcomeRefused, "pinned_miss"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := req
			p := Policy{Mode: Strict, Allowlist: []AllowedBuild{allow}}
			if tc.mutate != nil {
				tc.mutate(&r, &p)
			}
			d, err := Evaluate(context.Background(), r, p)
			assertDecision(t, d, err, tc.want, tc.reason, false)
		})
	}
}

// Without qualification evidence, this synthetic interactive build is admitted
// only by optimistic or matching non-sensitive pinned policy, with provenance.
// Sensitive and strict policy refuse it; no Codex process or transport is tested.
func TestCodexInteractiveUnqualifiedPolicy(t *testing.T) {
	req := Request{Adapter: Identity{Adapter: "generic-env-v1", Harness: "codex-cli", Entrypoint: "interactive"}, Artifact: []byte("\x7fELFcodex-native-snapshot"), Recipe: "codex-interactive-v1"}
	build, digest := digestOf(t, req)
	for _, tc := range []struct {
		name   string
		policy Policy
		want   Outcome
		reason string
		mode   Mode
	}{
		{"optimistic-no-allowlist", Policy{Mode: Optimistic}, OutcomeUnqualified, "unqualified_build", Optimistic},
		{"pinned-non-sensitive-no-allowlist", Policy{Mode: Pinned, PinnedBuild: build}, OutcomeUnqualified, "unqualified_build", Pinned},
		{"optimistic-sensitive-no-allowlist", Policy{Mode: Optimistic, SensitiveEgress: true}, OutcomeRefused, "strict_miss", Strict},
		{"pinned-sensitive-no-allowlist", Policy{Mode: Pinned, PinnedBuild: build, SensitiveEgress: true}, OutcomeRefused, "strict_miss", Pinned},
		{"strict-no-allowlist", Policy{Mode: Strict}, OutcomeRefused, "strict_miss", Strict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Evaluate(context.Background(), req, tc.policy)
			assertDecision(t, d, err, tc.want, tc.reason, tc.want == OutcomeUnqualified)
			if d.EffectiveMode != tc.mode || d.Adapter != req.Adapter || d.Recipe != req.Recipe || d.BuildID != build || d.BinarySHA256 != digest {
				t.Fatalf("decision identity or mode changed: %+v", d)
			}
			if tc.want == OutcomeUnqualified {
				want := Provenance{Schema: ProvenanceSchema, Adapter: req.Adapter, BuildID: build, BinarySHA256: digest, Recipe: req.Recipe, Scope: TransportScope, Outcome: "unqualified_build"}
				if *d.Provenance != want {
					t.Fatalf("provenance=%+v; want %+v", *d.Provenance, want)
				}
				if !strings.Contains(d.Provenance.OperatorText(), "Unqualified build: codex-cli generic-env-v1/interactive build "+build+" (recipe codex-interactive-v1)") {
					t.Fatalf("missing interactive build warning: %s", d.Provenance.OperatorText())
				}
			}
		})
	}
}

// Adding the policy tuple supplies no automatic credential-free probe, executable
// fallback or credentials: Probe still refuses the declared unavailable recipe.
func TestCodexInteractiveAutomaticProbeUnavailable(t *testing.T) {
	req := Request{Adapter: Identity{Adapter: "generic-env-v1", Harness: "codex-cli", Entrypoint: "interactive"}, Artifact: []byte("\x7fELFcodex-native-snapshot"), Recipe: "codex-interactive-v1"}
	_, err := Probe(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "credential_free_recipe_unavailable") {
		t.Fatalf("automatic recipe unexpectedly available: %v", err)
	}
}
