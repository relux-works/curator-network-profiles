// SPDX-License-Identifier: Apache-2.0
package adapterprobe

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

func claudeRequest() Request {
	return Request{Adapter: Identity{Adapter: "generic-env-v1", Harness: "claude-code", Entrypoint: "exec"}, Artifact: []byte("\x7fELFclaude-native-snapshot"), Recipe: "claude-exec-v1"}
}

func digestOf(t *testing.T, req Request) (buildID, digest string) {
	t.Helper()
	res, err := identify(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return res.BuildID, res.BinarySHA256
}

func knownBadWith(t *testing.T, digests ...string) *KnownBad {
	t.Helper()
	quoted := make([]string, 0, len(digests))
	for _, d := range digests {
		quoted = append(quoted, `"`+d+`"`)
	}
	k, err := ParseKnownBad([]byte(`{"schema":"relux-adapter-knownbad-v1","sha256":[` + strings.Join(quoted, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func assertDecision(t *testing.T, dec Decision, err error, outcome Outcome, reason string, wantProvenance bool) {
	t.Helper()
	var unsupported *Unsupported
	code, _ := refusal.CodeOf(err)
	if dec.Outcome != outcome || dec.Reason != reason {
		t.Fatalf("decision=%+v; want outcome=%s reason=%s", dec, outcome, reason)
	}
	if (dec.Provenance != nil) != wantProvenance {
		t.Fatalf("decision=%+v; want provenance=%v", dec, wantProvenance)
	}
	if outcome == OutcomeRefused {
		if err == nil || !errors.Is(err, ErrUnsupported) || !errors.As(err, &unsupported) || unsupported.Reason != reason || code != refusal.CodeScopeUnsupported {
			t.Fatalf("decision=%+v error=%v; want refused %s", dec, err, reason)
		}
	} else if err != nil {
		t.Fatalf("decision=%+v error=%v; want nil error", dec, err)
	}
}

func TestEvaluateDecisions(t *testing.T) {
	req := claudeRequest()
	build, digest := digestOf(t, req)
	allow := AllowedBuild{Adapter: req.Adapter, BuildID: build, Recipe: req.Recipe, Platform: runtime.GOOS, Scope: TransportScope}
	otherDigest := strings.Repeat("c", 64)
	for _, tc := range []struct {
		name    string
		change  func(*Request)
		policy  func() Policy
		outcome Outcome
		reason  string
		mode    Mode
	}{
		{"optimistic unknown build is unqualified", nil, func() Policy { return Policy{} }, OutcomeUnqualified, "unqualified_build", Optimistic},
		{"optimistic allowlisted build is qualified", nil, func() Policy { return Policy{Allowlist: []AllowedBuild{allow}} }, OutcomeQualified, "allowlisted", Optimistic},
		{"strict allowlisted build is qualified", nil, func() Policy { return Policy{Mode: Strict, Allowlist: []AllowedBuild{allow}} }, OutcomeQualified, "allowlisted", Strict},
		{"strict unknown build refuses", nil, func() Policy { return Policy{Mode: Strict} }, OutcomeRefused, "strict_miss", Strict},
		{"sensitive egress defaults to strict", nil, func() Policy { return Policy{SensitiveEgress: true} }, OutcomeRefused, "strict_miss", Strict},
		{"sensitive allowlisted build is qualified", nil, func() Policy { return Policy{SensitiveEgress: true, Allowlist: []AllowedBuild{allow}} }, OutcomeQualified, "allowlisted", Strict},
		{"sensitive pin without evidence refuses", nil, func() Policy { return Policy{Mode: Pinned, PinnedBuild: build, SensitiveEgress: true} }, OutcomeRefused, "strict_miss", Pinned},
		{"sensitive pin with allowlist is qualified", nil, func() Policy {
			return Policy{Mode: Pinned, PinnedBuild: build, SensitiveEgress: true, Allowlist: []AllowedBuild{allow}}
		}, OutcomeQualified, "allowlisted", Pinned},
		{"pinned exact without evidence is unqualified", nil, func() Policy { return Policy{Mode: Pinned, PinnedBuild: build} }, OutcomeUnqualified, "unqualified_build", Pinned},
		{"pinned exact with allowlist is qualified", nil, func() Policy { return Policy{Mode: Pinned, PinnedBuild: build, Allowlist: []AllowedBuild{allow}} }, OutcomeQualified, "allowlisted", Pinned},
		{"pinned other build refuses", nil, func() Policy { return Policy{Mode: Pinned, PinnedBuild: "sha256-" + otherDigest} }, OutcomeRefused, "pinned_miss", Pinned},
		{"pinned empty pin refuses", nil, func() Policy { return Policy{Mode: Pinned} }, OutcomeRefused, "pinned_miss", Pinned},
		{"allowlist does not bypass a different pin", nil, func() Policy {
			return Policy{Mode: Pinned, PinnedBuild: "sha256-" + otherDigest, Allowlist: []AllowedBuild{allow}}
		}, OutcomeRefused, "pinned_miss", Pinned},
		{"allowlist does not bypass an empty pin", nil, func() Policy { return Policy{Mode: Pinned, Allowlist: []AllowedBuild{allow}} }, OutcomeRefused, "pinned_miss", Pinned},
		{"allowlist does not bypass a different pin when sensitive", nil, func() Policy {
			return Policy{Mode: Pinned, PinnedBuild: "sha256-" + otherDigest, SensitiveEgress: true, Allowlist: []AllowedBuild{allow}}
		}, OutcomeRefused, "pinned_miss", Pinned},
		{"known-bad match refuses", nil, func() Policy { return Policy{KnownBad: knownBadWith(t, digest)} }, OutcomeRefused, "known_bad_build", Optimistic},
		{"known-bad match refuses even when allowlisted", nil, func() Policy {
			return Policy{Allowlist: []AllowedBuild{allow}, KnownBad: knownBadWith(t, digest)}
		}, OutcomeRefused, "known_bad_build", Optimistic},
		{"known-bad without match passes through", nil, func() Policy { return Policy{KnownBad: knownBadWith(t, otherDigest)} }, OutcomeUnqualified, "unqualified_build", Optimistic},
		{"unreadable list refuses", nil, func() Policy { return Policy{KnownBadErr: errors.New("read failed")} }, OutcomeRefused, "knownbad_unreadable", Optimistic},
		{"corrupt list refuses", nil, func() Policy { return Policy{KnownBadErr: &Unsupported{Reason: "knownbad_corrupt"}} }, OutcomeRefused, "knownbad_corrupt", Optimistic},
		{"unknown-version list refuses", nil, func() Policy {
			return Policy{KnownBadErr: &Unsupported{Reason: "knownbad_version_unsupported"}}
		}, OutcomeRefused, "knownbad_version_unsupported", Optimistic},
		{"unexpected list error refuses without leaking", nil, func() Policy {
			return Policy{KnownBadErr: &Unsupported{Reason: "private-canary"}}
		}, OutcomeRefused, "knownbad_unreadable", Optimistic},
		{"list failure precedes request validation", func(r *Request) { r.Artifact = nil }, func() Policy {
			return Policy{KnownBadErr: errors.New("read failed")}
		}, OutcomeRefused, "knownbad_unreadable", Optimistic},
		{"unknown harness refuses", func(r *Request) { r.Adapter.Harness = "unknown-vendor" }, func() Policy { return Policy{} }, OutcomeRefused, "vendor_line_unsupported", Optimistic},
		{"unknown harness refuses under sensitive egress", func(r *Request) { r.Adapter.Harness = "unknown-vendor" }, func() Policy {
			return Policy{SensitiveEgress: true}
		}, OutcomeRefused, "vendor_line_unsupported", Strict},
		{"unknown adapter refuses", func(r *Request) { r.Adapter.Adapter = "codex-env-v1" }, func() Policy { return Policy{} }, OutcomeRefused, "adapter_unsupported", Optimistic},
		{"recipe mismatch refuses", func(r *Request) { r.Adapter.Entrypoint = "app-server" }, func() Policy { return Policy{} }, OutcomeRefused, "recipe_unsupported", Optimistic},
		{"unknown recipe refuses", func(r *Request) { r.Recipe = "claude-exec-v9" }, func() Policy { return Policy{} }, OutcomeRefused, "recipe_unsupported", Optimistic},
		{"invalid mode refuses", nil, func() Policy { return Policy{Mode: "unknown"} }, OutcomeRefused, "invalid_policy", "unknown"},
		{"negative TTL refuses", nil, func() Policy { return Policy{NegativeTTL: -1} }, OutcomeRefused, "invalid_policy", Optimistic},
		{"missing snapshot refuses", func(r *Request) { r.Artifact = nil }, func() Policy { return Policy{} }, OutcomeRefused, "artifact_snapshot_required", Optimistic},
		{"script snapshot refuses", func(r *Request) { r.Artifact = []byte("#!/bin/sh\nexec /mutable/program") }, func() Policy { return Policy{} }, OutcomeRefused, "runtime_closure_unsupported", Optimistic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := req
			if tc.change != nil {
				tc.change(&r)
			}
			dec, err := Evaluate(context.Background(), r, tc.policy())
			assertDecision(t, dec, err, tc.outcome, tc.reason, tc.outcome == OutcomeUnqualified)
			if dec.EffectiveMode != tc.mode {
				t.Fatalf("effective mode=%q; want %q", dec.EffectiveMode, tc.mode)
			}
			if tc.outcome == OutcomeUnqualified {
				if dec.Provenance.Adapter != r.Adapter || dec.Provenance.BuildID != build || dec.Provenance.BinarySHA256 != digest || dec.Provenance.Recipe != r.Recipe || dec.Provenance.Scope != TransportScope || dec.Provenance.Schema != ProvenanceSchema || dec.Provenance.Outcome != "unqualified_build" {
					t.Fatalf("provenance=%+v", dec.Provenance)
				}
			}
		})
	}
}

func TestEvaluateCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dec, err := Evaluate(ctx, claudeRequest(), Policy{})
	assertDecision(t, dec, err, OutcomeRefused, "cancelled", false)
	expired, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	dec, err = Evaluate(expired, claudeRequest(), Policy{})
	assertDecision(t, dec, err, OutcomeRefused, "deadline_exceeded", false)
}

func TestEvaluateCachedEvidence(t *testing.T) {
	// The fake line is a known vendor line with an available recipe, so
	// private cache fixtures exercise the evidence seam end to end.
	c := testCache(t)
	req := request()
	req.Cache = c
	good := conformance(t, req, true)
	store(t, c, req, good, time.Now())
	dec, err := Evaluate(context.Background(), req, Policy{})
	assertDecision(t, dec, err, OutcomeQualified, "proxy_attempt_observed", false)
	negative := conformance(t, req, false)
	store(t, c, req, negative, time.Now())
	dec, err = Evaluate(context.Background(), req, Policy{})
	assertDecision(t, dec, err, OutcomeRefused, "operation_no_proxy_attempt", false)
	entry := c.entries[good.BinarySHA256]
	entry.Result.Reason = "private-body-canary"
	c.entries[good.BinarySHA256] = entry
	dec, err = Evaluate(context.Background(), req, Policy{})
	assertDecision(t, dec, err, OutcomeRefused, "cache_integrity_failed", false)
}

func TestOperatorTextIsExact(t *testing.T) {
	digest := strings.Repeat("a", 64)
	prov := Provenance{
		Schema:       ProvenanceSchema,
		Adapter:      Identity{Adapter: "generic-env-v1", Harness: "claude-code", Entrypoint: "exec"},
		BuildID:      "sha256-" + digest,
		BinarySHA256: digest,
		Recipe:       "claude-exec-v1",
		Scope:        TransportScope,
		Outcome:      "unqualified_build",
	}
	want := "Unqualified build: claude-code generic-env-v1/exec build sha256-" + digest + " (recipe claude-exec-v1) has no conformance evidence. Traffic may escape the proxy on this unproven build. This is a policy gap, not credential exposure."
	if got := prov.OperatorText(); got != want {
		t.Fatalf("operator text:\n%s\nwant:\n%s", got, want)
	}
	dec, err := Evaluate(context.Background(), claudeRequest(), Policy{})
	if err != nil || dec.Outcome != OutcomeUnqualified {
		t.Fatalf("%+v %v", dec, err)
	}
	if got := dec.Provenance.OperatorText(); got != "Unqualified build: claude-code generic-env-v1/exec build "+dec.BuildID+" (recipe claude-exec-v1) has no conformance evidence. Traffic may escape the proxy on this unproven build. This is a policy gap, not credential exposure." {
		t.Fatalf("live operator text: %s", got)
	}
	data, err := json.Marshal(dec.Provenance)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema", "adapter", "build_id", "binary_sha256", "recipe", "scope", "outcome"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("provenance JSON lacks %s: %s", key, data)
		}
	}
}

func TestEffectiveMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy Policy
		want   Mode
	}{
		{"default is optimistic", Policy{}, Optimistic},
		{"sensitive defaults to strict", Policy{SensitiveEgress: true}, Strict},
		{"explicit strict", Policy{Mode: Strict}, Strict},
		{"explicit strict with sensitive", Policy{Mode: Strict, SensitiveEgress: true}, Strict},
		{"pinned", Policy{Mode: Pinned}, Pinned},
		{"pinned with sensitive stays pinned", Policy{Mode: Pinned, SensitiveEgress: true}, Pinned},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EffectiveMode(tc.policy); got != tc.want {
				t.Fatalf("EffectiveMode(%+v) = %q, want %q", tc.policy, got, tc.want)
			}
		})
	}
}

func TestKnownVendorLine(t *testing.T) {
	for _, tc := range []struct {
		id   Identity
		want bool
	}{
		{Identity{Adapter: "generic-env-v1", Harness: "claude-code", Entrypoint: "exec"}, true},
		{Identity{Adapter: "generic-env-v1", Harness: "codex-cli", Entrypoint: "exec"}, true},
		{Identity{Adapter: "generic-env-v1", Harness: "muse", Entrypoint: "exec"}, true},
		// Synthetic test-only line from recipes_test.go; production
		// carries only real vendor lines.
		{Identity{Adapter: "generic-env-v1", Harness: "fake-harness", Entrypoint: "exec"}, true},
		{Identity{Adapter: "generic-env-v1", Harness: "unknown-vendor", Entrypoint: "exec"}, false},
		{Identity{Adapter: "codex-env-v1", Harness: "codex-cli", Entrypoint: "exec"}, false},
		{Identity{}, false},
	} {
		if got := KnownVendorLine(tc.id); got != tc.want {
			t.Fatalf("KnownVendorLine(%+v) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

func TestParseKnownBad(t *testing.T) {
	good := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	k, err := ParseKnownBad([]byte(`{"schema":"relux-adapter-knownbad-v1","sha256":["` + good + `","` + other + `","` + good + `"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !k.Contains(good) || !k.Contains(other) || k.Contains(strings.Repeat("c", 64)) {
		t.Fatal("membership wrong")
	}
	empty, err := ParseKnownBad([]byte(`{"schema":"relux-adapter-knownbad-v1","sha256":[]}`))
	if err != nil || empty.Contains(good) {
		t.Fatalf("%+v %v", empty, err)
	}
	for _, tc := range []struct {
		name   string
		data   string
		reason string
	}{
		{"empty", "", "knownbad_corrupt"},
		{"blank", "  \n ", "knownbad_corrupt"},
		{"not JSON", "{bad", "knownbad_corrupt"},
		{"null", "null", "knownbad_corrupt"},
		{"missing schema", `{"sha256":[]}`, "knownbad_corrupt"},
		{"missing list", `{"schema":"relux-adapter-knownbad-v1"}`, "knownbad_corrupt"},
		{"null list", `{"schema":"relux-adapter-knownbad-v1","sha256":null}`, "knownbad_corrupt"},
		{"null schema", `{"schema":null,"sha256":[]}`, "knownbad_corrupt"},
		{"empty schema", `{"schema":"","sha256":[]}`, "knownbad_corrupt"},
		{"unknown version", `{"schema":"relux-adapter-knownbad-v2","sha256":[]}`, "knownbad_version_unsupported"},
		{"unknown version with null element", `{"schema":"relux-adapter-knownbad-v2","sha256":[null]}`, "knownbad_corrupt"},
		{"unknown version with invalid digest", `{"schema":"relux-adapter-knownbad-v2","sha256":["not-a-digest"]}`, "knownbad_corrupt"},
		{"unknown version with uppercase digest", `{"schema":"relux-adapter-knownbad-v2","sha256":["` + strings.Repeat("A", 64) + `"]}`, "knownbad_corrupt"},
		{"unknown version with empty digest", `{"schema":"relux-adapter-knownbad-v2","sha256":[""]}`, "knownbad_corrupt"},
		{"escaped duplicate schema", `{"schema":"relux-adapter-knownbad-v1","sha256":[],"` + "\\u0073" + `chema":"relux-adapter-knownbad-v1"}`, "knownbad_corrupt"},
		{"escaped duplicate schema reversed", `{"` + "\\u0073" + `chema":"relux-adapter-knownbad-v1","schema":"relux-adapter-knownbad-v1","sha256":[]}`, "knownbad_corrupt"},
		{"escaped duplicate list", `{"schema":"relux-adapter-knownbad-v1","sha256":[],"sha25` + "\\u0036" + `":[]}`, "knownbad_corrupt"},
		{"escaped duplicate list reversed", `{"schema":"relux-adapter-knownbad-v1","sha25` + "\\u0036" + `":[],"sha256":[]}`, "knownbad_corrupt"},
		{"unknown key", `{"schema":"relux-adapter-knownbad-v1","sha256":[],"extra":1}`, "knownbad_corrupt"},
		{"trailing data", `{"schema":"relux-adapter-knownbad-v1","sha256":[]} []`, "knownbad_corrupt"},
		{"short digest", `{"schema":"relux-adapter-knownbad-v1","sha256":["abc"]}`, "knownbad_corrupt"},
		{"uppercase digest", `{"schema":"relux-adapter-knownbad-v1","sha256":["` + strings.Repeat("A", 64) + `"]}`, "knownbad_corrupt"},
		{"non-hex digest", `{"schema":"relux-adapter-knownbad-v1","sha256":["` + strings.Repeat("z", 64) + `"]}`, "knownbad_corrupt"},
		{"build ID form", `{"schema":"relux-adapter-knownbad-v1","sha256":["sha256-` + good + `"]}`, "knownbad_corrupt"},
		{"wrong type", `{"schema":"relux-adapter-knownbad-v1","sha256":"` + good + `"}`, "knownbad_corrupt"},
		{"null element", `{"schema":"relux-adapter-knownbad-v1","sha256":[null]}`, "knownbad_corrupt"},
		{"number element", `{"schema":"relux-adapter-knownbad-v1","sha256":[1]}`, "knownbad_corrupt"},
		{"duplicate list erases denial", `{"schema":"relux-adapter-knownbad-v1","sha256":["` + good + `"],"sha256":[]}`, "knownbad_corrupt"},
		{"duplicate list erases denial reversed", `{"schema":"relux-adapter-knownbad-v1","sha256":[],"sha256":["` + good + `"]}`, "knownbad_corrupt"},
		{"duplicate schema hides version", `{"schema":"relux-adapter-knownbad-v2","schema":"relux-adapter-knownbad-v1","sha256":[]}`, "knownbad_corrupt"},
		{"duplicate schema hides version reversed", `{"schema":"relux-adapter-knownbad-v1","schema":"relux-adapter-knownbad-v2","sha256":[]}`, "knownbad_corrupt"},
		{"case alias list", `{"schema":"relux-adapter-knownbad-v1","SHA256":[]}`, "knownbad_corrupt"},
		{"case alias schema", `{"Schema":"relux-adapter-knownbad-v1","sha256":[]}`, "knownbad_corrupt"},
		{"case alias with canonical", `{"schema":"relux-adapter-knownbad-v1","sha256":["` + good + `"],"SHA256":[]}`, "knownbad_corrupt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseKnownBad([]byte(tc.data))
			var unsupported *Unsupported
			code, _ := refusal.CodeOf(err)
			if err == nil || !errors.Is(err, ErrUnsupported) || !errors.As(err, &unsupported) || unsupported.Reason != tc.reason || code != refusal.CodeScopeUnsupported {
				t.Fatalf("error=%v; want %s", err, tc.reason)
			}
		})
	}
}

func TestKnownBadSets(t *testing.T) {
	if EmbeddedKnownBad().Contains(strings.Repeat("a", 64)) {
		t.Fatal("shipped list is not empty")
	}
	operator := knownBadWith(t, strings.Repeat("b", 64))
	merged := EmbeddedKnownBad().Union(operator)
	if !merged.Contains(strings.Repeat("b", 64)) || merged.Contains(strings.Repeat("a", 64)) {
		t.Fatal("union wrong")
	}
	if operator.Contains(strings.Repeat("a", 64)) {
		t.Fatal("union mutated the operator set")
	}
	var nilSet *KnownBad
	if nilSet.Contains(strings.Repeat("b", 64)) || nilSet.Union(nil).Contains(strings.Repeat("b", 64)) {
		t.Fatal("nil set is not empty")
	}
}

func TestEvaluateCacheKeyIsDigestOnly(t *testing.T) {
	req := request()
	res, err := identify(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	first := req
	first.Binary = "/releases/1.0/binary"
	first.Timeout = time.Second
	second := req
	second.Binary = "/releases/2.0/binary"
	if cacheKey(first, res) != res.BinarySHA256 || cacheKey(second, res) != res.BinarySHA256 {
		t.Fatal("cache key is not the binary digest")
	}
	// The same artifact under version-like paths shares one entry: paths
	// and version labels never address the cache.
	c := testCache(t)
	first.Cache = c
	store(t, c, first, conformance(t, first, true), time.Now())
	second.Cache = c
	got, err := Lookup(context.Background(), second, Policy{})
	if err != nil || !got.Verified {
		t.Fatalf("%+v %v", got, err)
	}
}
