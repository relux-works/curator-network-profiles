// SPDX-License-Identifier: Apache-2.0
package adapterprobe

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/catalog"
	"github.com/relux-works/curator-network-profiles/pkg/hosted"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

// F1: a pin mismatch refuses before allowlist and cached evidence, for
// both sensitivity values.
func TestPinAdmissionConstraintWithEvidence(t *testing.T) {
	req := claudeRequest()
	build, _ := digestOf(t, req)
	allow := AllowedBuild{Adapter: req.Adapter, BuildID: build, Recipe: req.Recipe, Platform: runtime.GOOS, Scope: TransportScope}
	other := "sha256-" + strings.Repeat("d", 64)
	// Pinned tests use the fake line for cache fixtures; the pin logic is
	// identical and the fake line is a known vendor line in tests.
	cachedReq := request()
	cachedBuild, _ := digestOf(t, cachedReq)
	cachedAllow := AllowedBuild{Adapter: cachedReq.Adapter, BuildID: cachedBuild, Recipe: cachedReq.Recipe, Platform: runtime.GOOS, Scope: TransportScope}
	for _, sensitive := range []bool{false, true} {
		c := testCache(t)
		r := cachedReq
		r.Cache = c
		store(t, c, r, conformance(t, r, true), time.Now())
		for _, tc := range []struct {
			name   string
			policy Policy
		}{
			{"different pin with allowlist", Policy{Mode: Pinned, PinnedBuild: other, Allowlist: []AllowedBuild{cachedAllow}, SensitiveEgress: sensitive}},
			{"empty pin with allowlist", Policy{Mode: Pinned, Allowlist: []AllowedBuild{cachedAllow}, SensitiveEgress: sensitive}},
			{"different pin with cached evidence", Policy{Mode: Pinned, PinnedBuild: other, SensitiveEgress: sensitive}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dec, err := Evaluate(context.Background(), r, tc.policy)
				assertDecision(t, dec, err, OutcomeRefused, "pinned_miss", false)
			})
		}
		// Matching pin with allowlist qualifies for both sensitivities.
		dec, err := Evaluate(context.Background(), req, Policy{Mode: Pinned, PinnedBuild: build, Allowlist: []AllowedBuild{allow}, SensitiveEgress: sensitive})
		assertDecision(t, dec, err, OutcomeQualified, "allowlisted", false)
	}
}

// F2: an exact pin with no evidence never qualifies; sensitive refuses,
// non-sensitive runs unqualified with provenance. A cached negative is
// never bypassed by a pin.
func TestPinNeverQualifiesWithoutEvidence(t *testing.T) {
	req := claudeRequest()
	build, _ := digestOf(t, req)
	dec, err := Evaluate(context.Background(), req, Policy{Mode: Pinned, PinnedBuild: build})
	assertDecision(t, dec, err, OutcomeUnqualified, "unqualified_build", true)
	if dec.Provenance == nil || !strings.Contains(dec.Provenance.OperatorText(), "Traffic may escape the proxy on this unproven build. This is a policy gap, not credential exposure.") {
		t.Fatalf("missing mandatory provenance: %+v", dec.Provenance)
	}
	dec, err = Evaluate(context.Background(), req, Policy{Mode: Pinned, PinnedBuild: build, SensitiveEgress: true})
	assertDecision(t, dec, err, OutcomeRefused, "strict_miss", false)
	// Pinned non-sensitive with a cached negative refuses with the cached
	// reason instead of running unqualified.
	c := testCache(t)
	r := request()
	r.Cache = c
	store(t, c, r, conformance(t, r, false), time.Now())
	res, resErr := identify(context.Background(), r)
	if resErr != nil {
		t.Fatal(resErr)
	}
	dec, err = Evaluate(context.Background(), r, Policy{Mode: Pinned, PinnedBuild: res.BuildID})
	assertDecision(t, dec, err, OutcomeRefused, "operation_no_proxy_attempt", false)
	// Pinned non-sensitive with a cached positive qualifies via evidence.
	c2 := testCache(t)
	r2 := request()
	r2.Cache = c2
	store(t, c2, r2, conformance(t, r2, true), time.Now())
	dec, err = Evaluate(context.Background(), r2, Policy{Mode: Pinned, PinnedBuild: res.BuildID})
	assertDecision(t, dec, err, OutcomeQualified, "proxy_attempt_observed", false)
}

// F3: Lookup enforces the option-C guards even though it is not the
// admission path.
func TestLookupEnforcesOptionCGuards(t *testing.T) {
	req := claudeRequest()
	build, digest := digestOf(t, req)
	allow := AllowedBuild{Adapter: req.Adapter, BuildID: build, Recipe: req.Recipe, Platform: runtime.GOOS, Scope: TransportScope}
	strict := Policy{Mode: Strict, Allowlist: []AllowedBuild{allow}}
	for _, tc := range []struct {
		name   string
		policy Policy
		reason string
	}{
		{"known-bad denial survives a strict allowlist", Policy{Mode: Strict, Allowlist: []AllowedBuild{allow}, KnownBad: knownBadWith(t, digest)}, "known_bad_build"},
		{"unreadable list refuses before an allowlist", Policy{Mode: Strict, Allowlist: []AllowedBuild{allow}, KnownBadErr: errors.New("read failed")}, "knownbad_unreadable"},
		{"corrupt list refuses before an allowlist", Policy{Mode: Strict, Allowlist: []AllowedBuild{allow}, KnownBadErr: &Unsupported{Reason: "knownbad_corrupt"}}, "knownbad_corrupt"},
		{"unknown version refuses before an allowlist", Policy{Mode: Strict, Allowlist: []AllowedBuild{allow}, KnownBadErr: &Unsupported{Reason: "knownbad_version_unsupported"}}, "knownbad_version_unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Lookup(context.Background(), req, tc.policy)
			assertFailure(t, res, err, tc.reason)
			dec, err := Evaluate(context.Background(), req, tc.policy)
			assertDecision(t, dec, err, OutcomeRefused, tc.reason, false)
		})
	}
	// Unknown vendor/recipe never approve from an allowlist.
	unknownReq := req
	unknownReq.Adapter.Harness = "unknown-vendor"
	unknownAllow := AllowedBuild{Adapter: unknownReq.Adapter, BuildID: build, Recipe: unknownReq.Recipe, Platform: runtime.GOOS, Scope: TransportScope}
	res, err := Lookup(context.Background(), unknownReq, Policy{Mode: Strict, Allowlist: []AllowedBuild{unknownAllow}})
	assertFailure(t, res, err, "vendor_line_unsupported")
	mismatchReq := req
	mismatchReq.Adapter.Entrypoint = "app-server"
	mismatchAllow := AllowedBuild{Adapter: mismatchReq.Adapter, BuildID: build, Recipe: mismatchReq.Recipe, Platform: runtime.GOOS, Scope: TransportScope}
	res, err = Lookup(context.Background(), mismatchReq, Policy{Mode: Strict, Allowlist: []AllowedBuild{mismatchAllow}})
	assertFailure(t, res, err, "recipe_unsupported")
	// Sensitive optimistic Lookup requires an allowlist and ignores a
	// process-local positive.
	c := testCache(t)
	r := request()
	r.Cache = c
	store(t, c, r, conformance(t, r, true), time.Now())
	res, err = Lookup(context.Background(), r, Policy{SensitiveEgress: true})
	assertFailure(t, res, err, "strict_miss")
	// Strict allowlist still qualifies through Lookup's low-level path.
	res, err = Lookup(context.Background(), req, strict)
	if err != nil || !res.Verified || res.Reason != "allowlisted" {
		t.Fatalf("%+v %v", res, err)
	}
	_ = build
}

// F3: an unqualified launch followed by an equal reattach succeeds
// through Evaluate; Lookup alone has no successful path for it.
func TestUnqualifiedLaunchReattachFlow(t *testing.T) {
	req := claudeRequest()
	dec, err := Evaluate(context.Background(), req, Policy{})
	assertDecision(t, dec, err, OutcomeUnqualified, "unqualified_build", true)
	id, err := dec.BoundIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fresh := binding.Binding{ProfileRef: "egress-a", ProfileDigest: "sha256:" + strings.Repeat("e", 64), AdapterIdentity: id, Assurance: binding.AssuranceCooperative}
	recorded := fresh.Record("explicit", nil)
	// Re-evaluate the unchanged snapshot for reattach: same unqualified
	// admission, same identity, equal binding.
	dec2, err := Evaluate(context.Background(), req, Policy{})
	assertDecision(t, dec2, err, OutcomeUnqualified, "unqualified_build", true)
	id2, err := dec2.BoundIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id {
		t.Fatalf("reattach identity changed: %+v vs %+v", id2, id)
	}
	if out, err := binding.CheckReattach(recorded, fresh, binding.EventReattach, false); err != nil || out != binding.OutcomeReattach {
		t.Fatalf("%v %v", out, err)
	}
	// The low-level evidence path has no success for this unqualified
	// build and must not invent any.
	res, err := Lookup(context.Background(), req, Policy{})
	assertFailure(t, res, err, "evidence_missing")
}

// F4: an earlier matching denial in a duplicate-member document cannot be
// discarded: parsing refuses and evaluation fails closed.
func TestDuplicateKnownBadDenialFailsClosed(t *testing.T) {
	req := claudeRequest()
	_, digest := digestOf(t, req)
	dup := `{"schema":"relux-adapter-knownbad-v1","sha256":["` + digest + `"],"sha256":[]}`
	_, err := ParseKnownBad([]byte(dup))
	var unsupported *Unsupported
	if err == nil || !errors.As(err, &unsupported) || unsupported.Reason != "knownbad_corrupt" {
		t.Fatalf("error=%v; want knownbad_corrupt", err)
	}
	dec, err := Evaluate(context.Background(), req, Policy{KnownBadErr: err})
	assertDecision(t, dec, err, OutcomeRefused, "knownbad_corrupt", false)
}

// F4: unknown schemas with invalid elements refuse as corrupt (never
// as an unsupported version), and escaped duplicates refuse; every
// failure propagates Parse → Evaluate with the exact reason.
func TestUnknownSchemaInvalidListFailsClosed(t *testing.T) {
	req := claudeRequest()
	good := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name   string
		data   string
		reason string
	}{
		{"unknown schema with null element", `{"schema":"relux-adapter-knownbad-v2","sha256":[null]}`, "knownbad_corrupt"},
		{"unknown schema with invalid digest", `{"schema":"relux-adapter-knownbad-v2","sha256":["not-a-digest"]}`, "knownbad_corrupt"},
		{"unknown schema with uppercase digest", `{"schema":"relux-adapter-knownbad-v2","sha256":["` + strings.Repeat("A", 64) + `"]}`, "knownbad_corrupt"},
		{"unknown schema with empty digest", `{"schema":"relux-adapter-knownbad-v2","sha256":[""]}`, "knownbad_corrupt"},
		{"escaped duplicate schema", `{"schema":"relux-adapter-knownbad-v1","sha256":[],"` + "\\u0073" + `chema":"relux-adapter-knownbad-v1"}`, "knownbad_corrupt"},
		{"escaped duplicate schema reversed", `{"` + "\\u0073" + `chema":"relux-adapter-knownbad-v1","schema":"relux-adapter-knownbad-v1","sha256":[]}`, "knownbad_corrupt"},
		{"escaped duplicate list", `{"schema":"relux-adapter-knownbad-v1","sha256":["` + good + `"],"sha25` + "\\u0036" + `":[]}`, "knownbad_corrupt"},
		{"escaped duplicate list reversed", `{"schema":"relux-adapter-knownbad-v1","sha25` + "\\u0036" + `":[],"sha256":["` + good + `"]}`, "knownbad_corrupt"},
		{"well-formed unknown schema keeps its reason", `{"schema":"relux-adapter-knownbad-v2","sha256":[]}`, "knownbad_version_unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, parseErr := ParseKnownBad([]byte(tc.data))
			var unsupported *Unsupported
			if parseErr == nil || !errors.As(parseErr, &unsupported) || unsupported.Reason != tc.reason {
				t.Fatalf("error=%v; want %s", parseErr, tc.reason)
			}
			dec, evalErr := Evaluate(context.Background(), req, Policy{KnownBadErr: parseErr})
			assertDecision(t, dec, evalErr, OutcomeRefused, tc.reason, false)
			res, lookupErr := Lookup(context.Background(), req, Policy{KnownBadErr: parseErr})
			assertFailure(t, res, lookupErr, tc.reason)
		})
	}
}

// F6: the shared loader owns absent/unreadable semantics; the embedded
// list is non-optional.
func TestLoadKnownBadSemantics(t *testing.T) {
	good := strings.Repeat("a", 64)
	valid := []byte(`{"schema":"relux-adapter-knownbad-v1","sha256":["` + good + `"]}`)
	// Optional default genuinely absent: embedded only.
	absent := func(path string) ([]byte, error) { return nil, os.ErrNotExist }
	k, err := LoadKnownBad(absent, "/operator/.curator", "")
	if err != nil || k.Contains(good) {
		t.Fatalf("%+v %v", k, err)
	}
	// No root and no explicit path: embedded only without any read.
	called := false
	never := func(path string) ([]byte, error) { called = true; return nil, os.ErrNotExist }
	k, err = LoadKnownBad(never, "", "")
	if err != nil || called {
		t.Fatalf("%+v %v called=%v", k, err, called)
	}
	// Explicitly configured file missing: unreadable.
	k, err = LoadKnownBad(absent, "", "/operator/custom.json")
	assertKnownBadErr(t, err, "knownbad_unreadable")
	if k != nil {
		t.Fatal("failed load returned a set")
	}
	// Present but unreadable, directory, or policy violation: unreadable.
	for _, readErr := range []error{errors.New("permission denied"), os.ErrPermission} {
		_, err = LoadKnownBad(func(path string) ([]byte, error) { return nil, readErr }, "/operator/.curator", "")
		assertKnownBadErr(t, err, "knownbad_unreadable")
	}
	// Empty, malformed, ambiguous: corrupt. Unknown version preserved.
	for _, tc := range []struct {
		name   string
		data   string
		reason string
	}{
		{"empty file", "", "knownbad_corrupt"},
		{"malformed", "{bad", "knownbad_corrupt"},
		{"duplicate", `{"schema":"relux-adapter-knownbad-v1","sha256":[],"sha256":[]}`, "knownbad_corrupt"},
		{"unknown version", `{"schema":"relux-adapter-knownbad-v2","sha256":[]}`, "knownbad_version_unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadKnownBad(func(path string) ([]byte, error) { return []byte(tc.data), nil }, "/operator/.curator", "")
			assertKnownBadErr(t, err, tc.reason)
		})
	}
	// Valid file merges with embedded.
	k, err = LoadKnownBad(func(path string) ([]byte, error) {
		if !strings.HasSuffix(path, KnownBadFileName) {
			t.Fatalf("loader used a non-fixed path: %s", path)
		}
		return valid, nil
	}, "/operator/.curator", "")
	if err != nil || !k.Contains(good) {
		t.Fatalf("%+v %v", k, err)
	}
	// Nil reader fails closed.
	_, err = LoadKnownBad(nil, "/operator/.curator", "")
	assertKnownBadErr(t, err, "knownbad_unreadable")
}

func assertKnownBadErr(t *testing.T, err error, reason string) {
	t.Helper()
	var unsupported *Unsupported
	code, _ := refusal.CodeOf(err)
	if err == nil || !errors.Is(err, ErrUnsupported) || !errors.As(err, &unsupported) || unsupported.Reason != reason || code != refusal.CodeScopeUnsupported {
		t.Fatalf("error=%v; want %s", err, reason)
	}
	if strings.Contains(err.Error(), "/operator") || strings.Contains(err.Error(), ".curator") {
		t.Fatalf("refusal leaks a path: %v", err)
	}
}

// F6: a synthetic embedded denial survives an empty or non-matching
// operator set.
func TestEmbeddedDenialsAreNonOptional(t *testing.T) {
	req := claudeRequest()
	_, digest := digestOf(t, req)
	prev := embeddedKnownBadSHA256
	embeddedKnownBadSHA256 = []string{digest}
	defer func() { embeddedKnownBadSHA256 = prev }()
	// Empty operator list still refuses the embedded denial.
	empty, err := ParseKnownBad([]byte(`{"schema":"relux-adapter-knownbad-v1","sha256":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Evaluate(context.Background(), req, Policy{KnownBad: empty})
	assertDecision(t, dec, err, OutcomeRefused, "known_bad_build", false)
	// Non-matching operator list still refuses.
	other := knownBadWith(t, strings.Repeat("f", 64))
	dec, err = Evaluate(context.Background(), req, Policy{KnownBad: other})
	assertDecision(t, dec, err, OutcomeRefused, "known_bad_build", false)
	// Nil operator list still refuses.
	dec, err = Evaluate(context.Background(), req, Policy{})
	assertDecision(t, dec, err, OutcomeRefused, "known_bad_build", false)
	// Lookup enforces the same union.
	res, err := Lookup(context.Background(), req, Policy{KnownBad: empty})
	assertFailure(t, res, err, "known_bad_build")
}

// F7: admitted Decisions convert to the canonical tuple; refused
// decisions and fabricated evidence do not.
func TestDecisionBoundIdentity(t *testing.T) {
	req := claudeRequest()
	build, _ := digestOf(t, req)
	allow := AllowedBuild{Adapter: req.Adapter, BuildID: build, Recipe: req.Recipe, Platform: runtime.GOOS, Scope: TransportScope}
	qualified, err := Evaluate(context.Background(), req, Policy{Allowlist: []AllowedBuild{allow}})
	if err != nil {
		t.Fatal(err)
	}
	qid, err := qualified.BoundIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if qid.Adapter != "generic-env-v1" || qid.Harness != "claude-code" || qid.Build != build || qid.Entrypoint != "exec" {
		t.Fatalf("%+v", qid)
	}
	unqualified, err := Evaluate(context.Background(), req, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	uid, err := unqualified.BoundIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if uid != qid {
		t.Fatalf("qualified %+v vs unqualified %+v", qid, uid)
	}
	// A refused decision never converts.
	refused, err := Evaluate(context.Background(), req, Policy{Mode: Strict})
	if err == nil {
		t.Fatal("strict unknown admitted")
	}
	if _, err := refused.BoundIdentity(); err == nil {
		t.Fatal("refused decision converted")
	}
	// A pure decision never becomes Verified evidence: the evidence-only
	// converter rejects unqualified and pinned reasons.
	forged := Result{Verified: true, BuildID: build, BinarySHA256: unqualified.BinarySHA256, Adapter: req.Adapter, Recipe: req.Recipe, Scope: TransportScope, Reason: "unqualified_build", Observed: []Observation{{Kind: "absolute-URI", Target: "probe.invalid:80"}}}
	if _, err := forged.BoundIdentity(); err == nil {
		t.Fatal("unqualified reason converted as evidence")
	}
	pinned := forged
	pinned.Reason = "pinned"
	if _, err := pinned.BoundIdentity(); err == nil {
		t.Fatal("pinned reason converted as evidence")
	}
}

// F7: session envelope retains Record plus typed provenance with a
// closed-decoder round-trip.
func TestSessionEnvelopeRoundTrip(t *testing.T) {
	req := claudeRequest()
	build, _ := digestOf(t, req)
	allow := AllowedBuild{Adapter: req.Adapter, BuildID: build, Recipe: req.Recipe, Platform: runtime.GOOS, Scope: TransportScope}
	for _, tc := range []struct {
		name   string
		policy Policy
	}{
		{"qualified", Policy{Allowlist: []AllowedBuild{allow}}},
		{"unqualified", Policy{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := Evaluate(context.Background(), req, tc.policy)
			if err != nil && dec.Outcome != OutcomeRefused {
				t.Fatal(err)
			}
			id, err := dec.BoundIdentity()
			if err != nil {
				t.Fatal(err)
			}
			record := binding.Binding{ProfileRef: "egress-a", ProfileDigest: "sha256:" + strings.Repeat("e", 64), AdapterIdentity: id, Assurance: binding.AssuranceCooperative}.Record("explicit", nil)
			type envelope struct {
				Network           binding.Record `json:"network"`
				AdapterProvenance *Provenance    `json:"adapter_provenance,omitempty"`
			}
			env := envelope{Network: record, AdapterProvenance: dec.Provenance}
			data, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			dec2 := json.NewDecoder(strings.NewReader(string(data)))
			dec2.DisallowUnknownFields()
			var restored envelope
			if err := dec2.Decode(&restored); err != nil {
				t.Fatal(err)
			}
			if restored.Network != record {
				t.Fatalf("%+v vs %+v", restored.Network, record)
			}
			if (restored.AdapterProvenance == nil) != (dec.Provenance == nil) {
				t.Fatalf("provenance presence changed: %+v", restored.AdapterProvenance)
			}
			if dec.Provenance != nil && *restored.AdapterProvenance != *dec.Provenance {
				t.Fatalf("%+v vs %+v", restored.AdapterProvenance, dec.Provenance)
			}
		})
	}
}

// F7: a sensitive destination profile flows through the hosted boundary
// without falling back to Lookup.
func TestHostedSensitiveProfileUsesEvaluate(t *testing.T) {
	profileDoc := "schema = \"relux-network-profiles-v1\"\n[networks.egress-a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:18081\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\nsensitive_egress = true\n"
	file, err := netprofile.Parse([]byte(profileDoc))
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := file.Lookup("egress-a")
	if !profile.SensitiveEgress {
		t.Fatal("fixture lost its sensitivity")
	}
	req := claudeRequest()
	build, _ := digestOf(t, req)
	allow := AllowedBuild{Adapter: req.Adapter, BuildID: build, Recipe: req.Recipe, Platform: runtime.GOOS, Scope: TransportScope}
	// Unknown sensitive build refuses through the profile-aware callback.
	carrier := hosted.Carrier{Schema: hosted.Schema, SchemaVersion: hosted.SchemaVersion, Ref: "egress-a", Origin: hosted.OriginExplicit, ExpectedDigest: netprofile.Digest(profile)}
	decide := func(sensitive bool) (Decision, error) {
		return Evaluate(context.Background(), req, Policy{SensitiveEgress: sensitive})
	}
	opts := hosted.Options{OperatorHome: t.TempDir(), Identity: binding.AdapterIdentity{Adapter: "generic-env-v1", Harness: "claude-code", Build: build, Entrypoint: "exec"},
		LoadCatalog: func(context.Context, string) (*catalog.Catalog, error) { return &catalog.Catalog{File: file}, nil },
		LoadLedger: func(context.Context, string) (resolve.Confirmations, error) {
			return fixtureConfirmation{digest: carrier.ExpectedDigest}, nil
		},
		VerifyAdapterWithProfile: func(ctx context.Context, tuple binding.AdapterIdentity, assurance string, resolved netprofile.Profile) error {
			if !resolved.SensitiveEgress {
				return errors.New("hosted callback lost the resolved sensitivity")
			}
			dec, err := decide(resolved.SensitiveEgress)
			if err != nil {
				return err
			}
			id, err := dec.BoundIdentity()
			if err != nil || id != tuple {
				return errors.New("decision identity mismatch")
			}
			return nil
		},
	}
	if _, _, err := hosted.ResolveForHost(context.Background(), carrier, opts); err == nil {
		t.Fatal("sensitive unknown build admitted through hosted")
	}
	// The same sensitive destination admits the exact allowlisted build.
	opts.Identity = binding.AdapterIdentity{Adapter: "generic-env-v1", Harness: "claude-code", Build: build, Entrypoint: "exec"}
	opts.VerifyAdapterWithProfile = func(ctx context.Context, tuple binding.AdapterIdentity, assurance string, resolved netprofile.Profile) error {
		dec, err := Evaluate(context.Background(), req, Policy{SensitiveEgress: resolved.SensitiveEgress, Allowlist: []AllowedBuild{allow}})
		if err != nil {
			return err
		}
		id, err := dec.BoundIdentity()
		if err != nil || id != tuple {
			return errors.New("decision identity mismatch")
		}
		return nil
	}
	fresh, record, err := hosted.ResolveForHost(context.Background(), carrier, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := hosted.CheckReattach(record, fresh); err != nil {
		t.Fatal(err)
	}
}

// F5 integration: a parsed sensitive profile flows into policy as strict.
func TestParsedSensitiveProfileFlowsIntoPolicy(t *testing.T) {
	for _, doc := range []string{
		"schema = \"relux-network-profiles-v1\"\n[networks.egress-a]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:18081\"\nbypass_hosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\nsensitive_egress = true\n",
		"schema = \"relux-network-profiles-v1\"\n[networks.direct]\nkind = \"direct\"\nsensitive_egress = true\n",
	} {
		file, err := netprofile.Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		var profile netprofile.Profile
		for _, name := range file.Names() {
			profile, _ = file.Lookup(name)
		}
		if !profile.SensitiveEgress {
			t.Fatal("parsed profile lost sensitivity")
		}
		dec, err := Evaluate(context.Background(), claudeRequest(), Policy{SensitiveEgress: profile.SensitiveEgress})
		assertDecision(t, dec, err, OutcomeRefused, "strict_miss", false)
	}
}

// F8: every remaining refusal row.
func TestRemainingRefusals(t *testing.T) {
	req := claudeRequest()
	for _, tc := range []struct {
		name   string
		change func(*Request)
		policy Policy
		reason string
	}{
		{"negative timeout", func(r *Request) { r.Timeout = -time.Second }, Policy{}, "invalid_request"},
		{"invalid harness syntax", func(r *Request) { r.Adapter.Harness = "bad harness!" }, Policy{}, "invalid_request"},
		{"invalid entrypoint syntax", func(r *Request) { r.Adapter.Entrypoint = "" }, Policy{}, "invalid_request"},
		{"invalid recipe syntax", func(r *Request) { r.Recipe = "BadRecipe" }, Policy{}, "invalid_request"},
		{"raw args", func(r *Request) { r.Args = []string{"--config"} }, Policy{}, "unversioned_invocation"},
		{"oversized artifact", func(r *Request) { r.Artifact = make([]byte, (256<<20)+1); copy(r.Artifact, "\x7fELF") }, Policy{}, "artifact_too_large"},
		{"non-native artifact", func(r *Request) { r.Artifact = []byte("MZ-not-native-padding........") }, Policy{}, "runtime_closure_unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := req
			tc.change(&r)
			dec, err := Evaluate(context.Background(), r, tc.policy)
			assertDecision(t, dec, err, OutcomeRefused, tc.reason, false)
			res, err := Lookup(context.Background(), r, tc.policy)
			assertFailure(t, res, err, tc.reason)
			res, err = Probe(context.Background(), r)
			assertFailure(t, res, err, tc.reason)
			res, err = Verified(context.Background(), r, "", tc.policy)
			assertFailure(t, res, err, tc.reason)
		})
	}
	if _, err := BuildID("not-a-digest"); err == nil {
		t.Fatal("invalid digest accepted")
	} else {
		var unsupported *Unsupported
		if !errors.As(err, &unsupported) || unsupported.Reason != "invalid_digest" {
			t.Fatalf("error=%v; want invalid_digest", err)
		}
	}
	if _, err := NewCache([32]byte{}); err == nil {
		t.Fatal("zero cache secret accepted")
	} else {
		var unsupported *Unsupported
		if !errors.As(err, &unsupported) || unsupported.Reason != "cache_secret_required" {
			t.Fatalf("error=%v; want cache_secret_required", err)
		}
	}
	// A zero Cache refuses instead of blocking or approving.
	zero := &Cache{}
	dec, err := Evaluate(context.Background(), Request{Adapter: claudeRequest().Adapter, Artifact: claudeRequest().Artifact, Recipe: claudeRequest().Recipe, Cache: zero}, Policy{})
	assertDecision(t, dec, err, OutcomeRefused, "cache_integrity_failed", false)
	res, err := Lookup(context.Background(), Request{Adapter: request().Adapter, Artifact: request().Artifact, Recipe: request().Recipe, Cache: zero}, Policy{})
	assertFailure(t, res, err, "cache_integrity_failed")
	// Literal "optimistic" is not the API constant; Optimistic is empty.
	dec, err = Evaluate(context.Background(), req, Policy{Mode: "optimistic"})
	assertDecision(t, dec, err, OutcomeRefused, "invalid_policy", false)
}

// F8: a negative timeout is invalid input, but known-bad and policy
// guards still precede request validation in Evaluate, Lookup and
// Verified.
func TestNegativeTimeoutPreservesGuardPrecedence(t *testing.T) {
	req := claudeRequest()
	req.Timeout = -time.Second
	for _, tc := range []struct {
		name   string
		policy Policy
		reason string
	}{
		{"known-bad failure precedes invalid timeout", Policy{KnownBadErr: errors.New("read failed")}, "knownbad_unreadable"},
		{"corrupt list precedes invalid timeout", Policy{KnownBadErr: &Unsupported{Reason: "knownbad_corrupt"}}, "knownbad_corrupt"},
		{"invalid mode precedes invalid timeout", Policy{Mode: "unknown"}, "invalid_policy"},
		{"negative TTL precedes invalid timeout", Policy{NegativeTTL: -1}, "invalid_policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := Evaluate(context.Background(), req, tc.policy)
			assertDecision(t, dec, err, OutcomeRefused, tc.reason, false)
			res, err := Lookup(context.Background(), req, tc.policy)
			assertFailure(t, res, err, tc.reason)
			res, err = Verified(context.Background(), req, "", tc.policy)
			assertFailure(t, res, err, tc.reason)
		})
	}
	// Probe has no policy guards, so the invalid timeout itself refuses.
	res, err := Probe(context.Background(), req)
	assertFailure(t, res, err, "invalid_request")
}

// F8: Verified enforces the same guards as Evaluate and Lookup, and a
// sensitive pinned policy never qualifies from cached evidence.
func TestVerifiedGuardParityAndSensitivePinnedEvidence(t *testing.T) {
	req := claudeRequest()
	build, digest := digestOf(t, req)
	allow := AllowedBuild{Adapter: req.Adapter, BuildID: build, Recipe: req.Recipe, Platform: runtime.GOOS, Scope: TransportScope}
	for _, tc := range []struct {
		name   string
		policy Policy
		reason string
	}{
		{"known-bad denial", Policy{Mode: Strict, Allowlist: []AllowedBuild{allow}, KnownBad: knownBadWith(t, digest)}, "known_bad_build"},
		{"unreadable list", Policy{Mode: Strict, Allowlist: []AllowedBuild{allow}, KnownBadErr: errors.New("read failed")}, "knownbad_unreadable"},
		{"pinned miss", Policy{Mode: Pinned, PinnedBuild: "sha256-" + strings.Repeat("d", 64), Allowlist: []AllowedBuild{allow}}, "pinned_miss"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Verified(context.Background(), req, "", tc.policy)
			assertFailure(t, res, err, tc.reason)
			dec, err := Evaluate(context.Background(), req, tc.policy)
			assertDecision(t, dec, err, OutcomeRefused, tc.reason, false)
		})
	}
	// Strict allowlist still qualifies through Verified's lookup-only path.
	res, err := Verified(context.Background(), req, "", Policy{Mode: Strict, Allowlist: []AllowedBuild{allow}})
	if err != nil || !res.Verified || res.Reason != "allowlisted" {
		t.Fatalf("%+v %v", res, err)
	}
	// Sensitive pinned with a cached positive still refuses: only an
	// exact allowlist admits a sensitive profile, never evidence.
	c := testCache(t)
	r := request()
	r.Cache = c
	store(t, c, r, conformance(t, r, true), time.Now())
	cached, err := identify(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	pinned := Policy{Mode: Pinned, PinnedBuild: cached.BuildID, SensitiveEgress: true}
	dec, err := Evaluate(context.Background(), r, pinned)
	assertDecision(t, dec, err, OutcomeRefused, "strict_miss", false)
	res, err = Lookup(context.Background(), r, pinned)
	assertFailure(t, res, err, "strict_miss")
	res, err = Verified(context.Background(), r, "", pinned)
	assertFailure(t, res, err, "strict_miss")
}

// F8: synchronized in-flight cancellation at the held cache gate. The
// test observes the goroutine reaching the acquisition boundary inside
// the cache before cancelling, so the already-cancelled branch cannot
// satisfy the assertion without hashing or reaching the held gate.
func TestEvaluateCancellationAtCacheGate(t *testing.T) {
	c := testCache(t)
	req := request()
	req.Cache = c
	store(t, c, req, conformance(t, req, true), time.Now())
	before := snapshotCacheEntries(t, c)
	c.gate <- struct{}{}
	defer func() { <-c.gate }()
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	c.acquireHook = func() { close(entered) }
	done := make(chan struct {
		dec Decision
		err error
	}, 1)
	go func() {
		dec, err := Evaluate(ctx, req, Policy{})
		done <- struct {
			dec Decision
			err error
		}{dec, err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Evaluate never reached the cache gate")
	}
	c.acquireHook = nil
	cancel()
	select {
	case out := <-done:
		assertDecision(t, out.dec, out.err, OutcomeRefused, "cancelled", false)
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled Evaluate outlived cancellation")
	}
	assertCacheEntriesUnchanged(t, c, before)
}

// A live Evaluate that reaches the held cache gate and whose deadline
// then expires must refuse with a timely typed deadline_exceeded,
// before the gate is released. Entry is established through the
// acquisition hook reporting a live context; expiration is established
// after that acknowledgement; no scheduling sleep orders the test.
func TestEvaluateDeadlineAtCacheGate(t *testing.T) {
	c := testCache(t)
	req := request()
	req.Cache = c
	store(t, c, req, conformance(t, req, true), time.Now())
	before := snapshotCacheEntries(t, c)
	c.gate <- struct{}{}
	defer func() { <-c.gate }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	entered := make(chan error, 1)
	c.acquireHook = func() { entered <- ctx.Err() }
	done := make(chan struct {
		dec Decision
		err error
	}, 1)
	go func() {
		dec, err := Evaluate(ctx, req, Policy{})
		done <- struct {
			dec Decision
			err error
		}{dec, err}
	}()
	select {
	case hookErr := <-entered:
		if hookErr != nil {
			t.Fatalf("acquisition entered with expired context: %v", hookErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Evaluate never reached the cache gate")
	}
	c.acquireHook = nil
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("deadline never expired after live entry")
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("context error=%v; want context.DeadlineExceeded", ctx.Err())
	}
	select {
	case out := <-done:
		assertDecision(t, out.dec, out.err, OutcomeRefused, "deadline_exceeded", false)
	case <-time.After(5 * time.Second):
		t.Fatal("Evaluate outlived its expired deadline")
	}
	assertCacheEntriesUnchanged(t, c, before)
}
