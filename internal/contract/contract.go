// SPDX-License-Identifier: Apache-2.0

// Package contract defines the test vectors of spec/contract-appendix.md
// and computes their outputs with the library, so the appendix, the
// vectors file testdata/contract/vectors.json and the code cannot drift
// apart: the vectors file is generated from Vectors(), and the appendix
// embeds each vector as a fenced block `json vector=<id>` that the guard
// test compares with the generated one.
package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/envpatch"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

// Schema is the contract version the vectors belong to.
const Schema = netprofile.Schema

// DigestVector shows the normalization and digest of one profile.
type DigestVector struct {
	ID         string   `json:"id"`
	Note       string   `json:"note"`
	Name       string   `json:"name"`
	Input      input    `json:"input"`
	Normalized normed   `json:"normalized"`
	Canonical  string   `json:"canonical"`
	Digest     string   `json:"digest"`
	SameAs     []string `json:"same_digest_as,omitempty"`
}

type input struct {
	Kind        string   `json:"kind"`
	Endpoint    string   `json:"endpoint"`
	BypassHosts []string `json:"bypass_hosts"`
	ProbeTarget string   `json:"probe_target,omitempty"`
}

type normed struct {
	Kind           string   `json:"kind"`
	Endpoint       string   `json:"endpoint"`
	BypassHosts    []string `json:"bypass_hosts"`
	ProbeTarget    string   `json:"probe_target,omitempty"`
	CredentialMode string   `json:"credential_mode"`
}

// EnvVector applies the generic patch of a profile (or the unmanaged
// patch) to an inherited environment.
type EnvVector struct {
	ID      string          `json:"id"`
	Note    string          `json:"note"`
	Profile string          `json:"profile"` // a DigestVector id, or "unmanaged"
	Env     []string        `json:"env"`
	Result  []string        `json:"result"`
	Patch   *envpatch.Patch `json:"patch,omitempty"`
}

// EqualityVector compares a recorded binding with a fresh one and runs
// the N7 table for an event.
type EqualityVector struct {
	ID              string         `json:"id"`
	Note            string         `json:"note"`
	Recorded        binding.Record `json:"recorded"`
	Fresh           fresh          `json:"fresh"`
	Equal           bool           `json:"equal"`
	Event           string         `json:"event"`
	PerSessionRoute bool           `json:"per_session_route"`
	Outcome         string         `json:"outcome,omitempty"`
	Refusal         string         `json:"refusal,omitempty"`
}

type fresh struct {
	ProfileRef      string                  `json:"profile_ref"`
	ProfileDigest   string                  `json:"profile_digest"`
	AdapterIdentity binding.AdapterIdentity `json:"adapter_identity"`
	Assurance       string                  `json:"assurance"`
}

// EngineVector checks a loopback engine host against a profile's
// bypass list (spec N12).
type EngineVector struct {
	ID         string `json:"id"`
	Note       string `json:"note"`
	Profile    string `json:"profile"`
	EngineHost string `json:"engine_host"`
	Covered    bool   `json:"covered"`
	Refusal    string `json:"refusal,omitempty"`
}

// RecordVector shows the complete manifest-safe record.
type RecordVector struct {
	ID     string         `json:"id"`
	Note   string         `json:"note"`
	Record binding.Record `json:"record"`
}

// ResolveVector selects and validates references against the child's catalog.
type ResolveVector struct {
	ID        string             `json:"id"`
	Note      string             `json:"note"`
	Input     resolveInput       `json:"input"`
	Selection *resolve.Selection `json:"selection,omitempty"`
	Digest    string             `json:"digest,omitempty"`
	Refusal   string             `json:"refusal,omitempty"`
}

type resolveInput struct {
	Explicit        string   `json:"explicit"`
	Inherited       string   `json:"inherited"`
	RuntimeDefault  string   `json:"runtime_default"`
	ProjectDefault  string   `json:"project_default"`
	OperatorDefault string   `json:"operator_default"`
	Allowed         []string `json:"allowed"` // null allows all, [] allows none
	Confirmed       bool     `json:"confirmed"`
}

// Set is every vector of the appendix.
type Set struct {
	Schema      string           `json:"schema"`
	Generator   string           `json:"generator"`
	Record      []RecordVector   `json:"record"`
	Resolve     []ResolveVector  `json:"resolve"`
	Digest      []DigestVector   `json:"digest"`
	EnvPatch    []EnvVector      `json:"envpatch"`
	Equality    []EqualityVector `json:"equality"`
	EngineHosts []EngineVector   `json:"engine_hosts"`
}

var (
	specBypass = []string{"localhost", "127.0.0.1", "::1"}
	identity   = binding.AdapterIdentity{Adapter: envpatch.AdapterGeneric, Harness: "exec", Build: "", Entrypoint: "codex"}
	identityB  = binding.AdapterIdentity{Adapter: envpatch.AdapterGeneric, Harness: "exec", Build: "2.1.0", Entrypoint: "codex"}
)

// Vectors computes the set.
func Vectors() (Set, error) {
	s := Set{Schema: Schema, Generator: "go run ./internal/contract/cmd/contract-vectors"}
	profiles := map[string]netprofile.Profile{}
	digestIn := []struct {
		id, note, name string
		in             input
	}{
		{"D1", "the specification's egress-a", "egress-a", input{"external-http-proxy", "http://127.0.0.1:18081", specBypass, ""}},
		{"D2", "the specification's egress-b", "egress-b", input{"external-http-proxy", "http://127.0.0.1:18082", specBypass, ""}},
		{"D3", "normalization: scheme and host case, trailing slash, whitespace, case and duplicates in bypass_hosts", "egress-a-alt", input{"external-http-proxy", "HTTP://127.0.0.1:18081/", []string{"LocalHost", "::1", " 127.0.0.1 ", "localhost"}, ""}},
		{"D4", "a host-name endpoint, an engine host and a suffix entry in bypass_hosts", "corp", input{"external-http-proxy", "http://proxy.corp.invalid:3128", []string{"localhost", "127.0.0.1", "::1", "engine.example", ".corp.invalid"}, ""}},
		{"D5", "the profile name and probe_target are not part of the digest", "egress-a-copy", input{"external-http-proxy", "http://127.0.0.1:18081", specBypass, "probe.invalid:443"}},
		{"D6", "IPv4-mapped IPv6 is unmapped to canonical IPv4", "mapped", input{"external-http-proxy", "http://[::ffff:127.0.0.1]:18081", specBypass, ""}},
		{"D7", "expanded IPv6 is compressed and bracketed", "ipv6", input{"external-http-proxy", "http://[0:0:0:0:0:0:0:1]:18081", specBypass, ""}},
		{"D8", "hexadecimal IPv4-mapped IPv6 also becomes IPv4", "mapped-hex", input{"external-http-proxy", "http://[::FFFF:7F00:1]:18081/", specBypass, ""}},
		{"D9", "named direct: no endpoint, bypass_hosts or probe_target", "direct", input{Kind: netprofile.KindDirect}},
	}
	for _, d := range digestIn {
		p, err := netprofile.Normalize(d.name, netprofile.Input{Kind: d.in.Kind, Endpoint: d.in.Endpoint, BypassHosts: d.in.BypassHosts, ProbeTarget: d.in.ProbeTarget})
		if err != nil {
			return Set{}, fmt.Errorf("%s: %w", d.id, err)
		}
		profiles[d.id] = p
		s.Digest = append(s.Digest, DigestVector{
			ID: d.id, Note: d.note, Name: d.name, Input: d.in,
			Normalized: normed{Kind: p.Kind, Endpoint: p.Endpoint, BypassHosts: p.BypassHosts, ProbeTarget: p.ProbeTarget, CredentialMode: p.CredentialMode},
			Canonical:  string(netprofile.Canonical(p)),
			Digest:     netprofile.Digest(p),
		})
	}
	for i := range s.Digest {
		for j := range s.Digest {
			if i != j && s.Digest[i].Digest == s.Digest[j].Digest {
				s.Digest[i].SameAs = append(s.Digest[i].SameAs, s.Digest[j].ID)
			}
		}
	}

	patchOf := func(id string) envpatch.Patch {
		if id == "unmanaged" {
			return envpatch.Unmanaged()
		}
		return envpatch.Generic{}.Patch(profiles[id])
	}
	boundToA := patchOf("D1").Apply([]string{"PATH=/usr/bin:/bin", "HOME=/home/user"})
	envIn := []struct {
		id, note, profile string
		env               []string
	}{
		{"E1", "a clean inherited environment", "D1", []string{"PATH=/usr/bin:/bin", "HOME=/home/user"}},
		{"E2", "lowercase, uppercase and mixed-case conflicts never override the profile", "D1", []string{"http_proxy=http://wrong.invalid:3128", "HTTPS_PROXY=http://wrong.invalid:3128", "Http_Proxy=http://odd.invalid:3128", "PATH=/usr/bin"}},
		{"E3", "ambient NO_PROXY=* is replaced by the bypass list", "D1", []string{"NO_PROXY=*", "no_proxy=*", "PATH=/usr/bin"}},
		{"E4", "a conflicting variable present only on the host is removed and not re-set", "D1", []string{"ALL_PROXY=socks5://host-only.invalid:1080", "all_proxy=socks5://host-only.invalid:1080", "FTP_PROXY=http://host-only.invalid:3128", "PATH=/usr/bin"}},
		{"E5", "idempotence: applying the patch to an already patched environment changes nothing", "D1", boundToA},
		{"E6", "the order of untouched entries is kept; an entry without '=' has no name and is kept", "D1", []string{"Z=1", "NOEQUALS", "A=2", "https_proxy=http://wrong.invalid:1", "B=3"}},
		{"E7", "unmanaged: no selection at all leaves the environment untouched, ambient proxies included", "unmanaged", []string{"HTTPS_PROXY=http://ambient.invalid:3128", "NO_PROXY=*", "PATH=/usr/bin"}},
		{"E8", "a parent bound to egress-a spawns a child on egress-b: by reference and re-resolution, never by copying", "D2", boundToA},
		{"E9", "direct removes hostile ambient proxies, including mixed case, and sets nothing", "D9", []string{"PATH=/usr/bin", "HTTPS_PROXY=http://127.0.0.1:1", "http_proxy=http://127.0.0.1:1", "all_proxy=http://127.0.0.1:1", "NO_PROXY=*", "FtP_PrOxY=http://127.0.0.1:1", "Http_Proxy=http://127.0.0.1:1"}},
		{"E10", "a parent bound to egress-a explicitly selects direct for its child", "D9", boundToA},
	}
	for _, e := range envIn {
		v := EnvVector{ID: e.id, Note: e.note, Profile: e.profile, Env: e.env, Result: patchOf(e.profile).Apply(e.env)}
		if e.profile == "D9" {
			patch := patchOf(e.profile)
			v.Patch = &patch
		}
		s.EnvPatch = append(s.EnvPatch, v)
	}

	boundA := binding.Binding{ProfileRef: "egress-a", ProfileDigest: s.Digest[0].Digest, AdapterIdentity: identity, Assurance: binding.AssuranceCooperative}
	recordA := boundA.Record("explicit", nil)
	s.Record = []RecordVector{
		{"R1", "a real preflight with a fixed observation time", boundA.Record("explicit", &binding.ProbeRecord{TCP: "ok", Connect: "ok", TLS: "ok", CheckedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)})},
		{"R2", "no probe supplied: all steps skipped and the time is zero", recordA},
		{"R3", "an inherited reference re-resolved on the child's host, with no proxy values in the record", boundA.Record(string(resolve.OriginInherited), nil)},
	}
	direct := binding.Binding{ProfileRef: "direct", ProfileDigest: netprofile.Digest(profiles["D9"]), AdapterIdentity: identity, Assurance: binding.AssuranceCooperative, EnvPatch: patchOf("D9")}
	s.Record = append(s.Record, RecordVector{"R4", "managed direct keeps its named reference and digest; all probes skipped", direct.Record("explicit", nil)})
	resolveIn := []struct {
		id, note string
		in       resolveInput
	}{
		{"S1", "inherited beats runtime, project and operator defaults; the inherited reference is trimmed", resolveInput{Inherited: " egress-a ", RuntimeDefault: "egress-b", ProjectDefault: "egress-b", OperatorDefault: "egress-b", Confirmed: true}},
		{"S2", "explicit beats inherited", resolveInput{Explicit: "egress-b", Inherited: "egress-a", Confirmed: true}},
		{"S3", "an inherited reference unknown on the child's host is refused, without falling back", resolveInput{Inherited: "missing", RuntimeDefault: "egress-b", Confirmed: true}},
		{"S4", "an inherited reference unconfirmed on the child's host is denied", resolveInput{Inherited: "egress-a", RuntimeDefault: "egress-b"}},
		{"S5", "the child's allowed set denies the inherited reference, without falling back", resolveInput{Inherited: "egress-a", RuntimeDefault: "egress-b", Allowed: []string{"egress-b"}, Confirmed: true}},
		{"S6", "the child's allowed set admits the inherited reference", resolveInput{Inherited: "egress-a", Allowed: []string{"egress-a"}, Confirmed: true}},
		{"S7", "explicit direct overrides a profiled parent within the allowed set", resolveInput{Explicit: "direct", Inherited: "egress-a", Allowed: []string{"direct"}, Confirmed: true}},
		{"S8", "direct is a widening entry requiring confirmation", resolveInput{Explicit: "direct"}},
		{"S9", "direct obeys the host allowed set", resolveInput{Explicit: "direct", Allowed: []string{"egress-a"}, Confirmed: true}},
	}
	for _, r := range resolveIn {
		f := &netprofile.File{Schema: Schema, Default: r.in.OperatorDefault, Networks: map[string]netprofile.Profile{"egress-a": profiles["D1"], "egress-b": profiles["D2"], "direct": profiles["D9"]}}
		ledger := resolve.ConfirmedFunc(func(name, digest string) bool {
			p, ok := f.Lookup(name)
			return r.in.Confirmed && ok && digest == netprofile.Digest(p)
		})
		res, err := resolve.Resolve(f, ledger, resolve.Request{Explicit: r.in.Explicit, Inherited: r.in.Inherited, RuntimeDefault: r.in.RuntimeDefault, ProjectDefault: r.in.ProjectDefault, Allowed: r.in.Allowed})
		v := ResolveVector{ID: r.id, Note: r.note, Input: r.in}
		if err != nil {
			code, ok := refusal.CodeOf(err)
			if !ok {
				return Set{}, fmt.Errorf("%s: %w", r.id, err)
			}
			v.Refusal = code
		} else {
			v.Selection, v.Digest = &res.Selection, res.Digest
		}
		s.Resolve = append(s.Resolve, v)
	}
	eqIn := []struct {
		id, note string
		fresh    fresh
		event    binding.Event
		perSess  bool
	}{
		{"Q1", "equal content under another name is the same binding", fresh{"egress-a-copy", s.Digest[0].Digest, identity, "cooperative"}, binding.EventReattach, false},
		{"Q2", "changed content under an unchanged name: resume is refused as drift, never re-routed", fresh{"egress-a", s.Digest[1].Digest, identity, "cooperative"}, binding.EventReattach, true},
		{"Q3", "a new assignment on a running host bound to another profile, no per-session route", fresh{"egress-b", s.Digest[1].Digest, identity, "cooperative"}, binding.EventNewAssignment, false},
		{"Q4", "the same assignment when the adapter routes per session", fresh{"egress-b", s.Digest[1].Digest, identity, "cooperative"}, binding.EventNewAssignment, true},
		{"Q5", "a different harness build is a different launch shape", fresh{"egress-a", s.Digest[0].Digest, identityB, "cooperative"}, binding.EventReattach, true},
		{"Q6", "a fresh process never compares: new launch", fresh{"egress-b", s.Digest[1].Digest, identity, "cooperative"}, binding.EventNewLaunch, false},
	}
	for _, q := range eqIn {
		fb := binding.Binding{ProfileRef: q.fresh.ProfileRef, ProfileDigest: q.fresh.ProfileDigest, AdapterIdentity: q.fresh.AdapterIdentity, Assurance: q.fresh.Assurance}
		v := EqualityVector{ID: q.id, Note: q.note, Recorded: recordA, Fresh: q.fresh, Equal: binding.RecordEqual(recordA, fb), Event: string(q.event), PerSessionRoute: q.perSess}
		out, err := binding.CheckReattach(recordA, fb, q.event, q.perSess)
		if err != nil {
			code, ok := refusal.CodeOf(err)
			if !ok {
				return Set{}, fmt.Errorf("%s: %w", q.id, err)
			}
			v.Refusal = code
		} else {
			v.Outcome = string(out)
		}
		s.Equality = append(s.Equality, v)
	}
	for _, tc := range []struct {
		id, note string
		fresh    binding.Binding
	}{
		{"Q7", "a different direct name with the same digest is equal", binding.Binding{ProfileRef: "other-direct", ProfileDigest: direct.ProfileDigest, AdapterIdentity: identity, Assurance: binding.AssuranceCooperative}},
		{"Q8", "resume cannot silently switch from direct to a proxy under the same name", binding.Binding{ProfileRef: "direct", ProfileDigest: boundA.ProfileDigest, AdapterIdentity: identity, Assurance: binding.AssuranceCooperative}},
	} {
		recorded := direct.Record("explicit", nil)
		v := EqualityVector{ID: tc.id, Note: tc.note, Recorded: recorded, Fresh: fresh{tc.fresh.ProfileRef, tc.fresh.ProfileDigest, tc.fresh.AdapterIdentity, tc.fresh.Assurance}, Equal: binding.RecordEqual(recorded, tc.fresh), Event: string(binding.EventReattach)}
		out, err := binding.CheckReattach(recorded, tc.fresh, binding.EventReattach, false)
		if err != nil {
			v.Refusal, _ = refusal.CodeOf(err)
		} else {
			v.Outcome = string(out)
		}
		s.Equality = append(s.Equality, v)
	}

	engIn := []struct{ id, note, profile, host string }{
		{"G1", "a loopback engine on 127.0.0.1 is covered by the required set", "D1", "127.0.0.1"},
		{"G2", "brackets and a port are stripped before the exact match", "D1", "[::1]:11434"},
		{"G3", "an engine host absent from bypass_hosts is a configuration conflict", "D1", "engine.example"},
		{"G4", "coverage is case-insensitive", "D4", "ENGINE.EXAMPLE"},
		{"G5", "a suffix entry does not cover by inclusion; coverage is exact", "D4", "api.corp.invalid"},
	}
	for _, g := range engIn {
		covered := profiles[g.profile].Covers(g.host)
		v := EngineVector{ID: g.id, Note: g.note, Profile: g.profile, EngineHost: g.host, Covered: covered}
		if !covered {
			v.Refusal = refusal.CodeConfigurationConflict
		}
		s.EngineHosts = append(s.EngineHosts, v)
	}
	return s, nil
}

// JSON renders the set as the vectors file.
func (s Set) JSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Block is one vector rendered as an appendix block.
type Block struct {
	ID   string
	JSON string
}

// Blocks renders every vector as indented JSON, in set order.
func (s Set) Blocks() ([]Block, error) {
	var out []Block
	add := func(id string, v any) error {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return err
		}
		out = append(out, Block{ID: id, JSON: strings.TrimSuffix(buf.String(), "\n")})
		return nil
	}
	for _, v := range s.Digest {
		if err := add(v.ID, v); err != nil {
			return nil, err
		}
	}
	for _, v := range s.EnvPatch {
		if err := add(v.ID, v); err != nil {
			return nil, err
		}
	}
	for _, v := range s.Record {
		if err := add(v.ID, v); err != nil {
			return nil, err
		}
	}
	for _, v := range s.Resolve {
		if err := add(v.ID, v); err != nil {
			return nil, err
		}
	}
	for _, v := range s.Equality {
		if err := add(v.ID, v); err != nil {
			return nil, err
		}
	}
	for _, v := range s.EngineHosts {
		if err := add(v.ID, v); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Markdown renders the blocks as fenced code blocks tagged with their id.
func (s Set) Markdown() (string, error) {
	blocks, err := s.Blocks()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, bl := range blocks {
		b.WriteString("```json vector=" + bl.ID + "\n" + bl.JSON + "\n```\n\n")
	}
	return b.String(), nil
}

var fence = regexp.MustCompile("(?s)```json vector=([A-Za-z0-9_-]+)\n(.*?)\n```")

// ParseBlocks extracts the tagged fenced blocks of an appendix.
func ParseBlocks(doc string) (map[string]string, error) {
	out := map[string]string{}
	for _, m := range fence.FindAllStringSubmatch(doc, -1) {
		if _, dup := out[m[1]]; dup {
			return nil, errors.New("duplicate vector block " + m[1])
		}
		out[m[1]] = m[2]
	}
	return out, nil
}

// SameJSON reports whether two JSON documents are equal as values.
func SameJSON(a, b string) bool {
	var va, vb any
	if err := json.Unmarshal([]byte(a), &va); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &vb); err != nil {
		return false
	}
	ca, _ := json.Marshal(va)
	cb, _ := json.Marshal(vb)
	return bytes.Equal(ca, cb)
}
