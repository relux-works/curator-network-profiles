// SPDX-License-Identifier: Apache-2.0

// Package netprofile holds the network-profile data model of
// spec/network-profiles.md N3: the operator catalog `~/.curator/network.toml`
// (schema relux-network-profiles-v1), its strict decoding, the
// normalization every profile goes through, validation, and the profile
// digest of the contract appendix (spec/contract-appendix.md §1).
//
// The package is pure: it reads no files, touches no network and never
// consults the process environment. Errors are *refusal.Refusal values
// whose messages carry key paths and fixed phrases, never values from the
// document (an endpoint with credentials is refused without being echoed).
package netprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

const (
	// Schema is the only accepted value of the top-level `schema` key and
	// the schema version named inside every digest.
	Schema = "relux-network-profiles-v1"
	// KindExternalHTTPProxy is an
	// operator-configured HTTP proxy with CONNECT (spec N6).
	KindExternalHTTPProxy = "external-http-proxy"
	// KindDirect clears inherited proxy variables without supplying a proxy.
	KindDirect = "direct"
	// CredentialModeNone is the only credential mode of slice A. It is
	// part of the digest so a later mode changes the digest.
	CredentialModeNone = "none"
	// FileName is the catalog basename, the only path element a refusal
	// may mention.
	FileName = "network.toml"
)

// RequiredBypassHosts must appear in every proxy profile's bypass_hosts
// (spec N12: loopback engines never go through the proxy). Byte order.
var RequiredBypassHosts = []string{"127.0.0.1", "::1", "localhost"}

// Profile is one normalized, validated network profile.
type Profile struct {
	// Name is the catalog key; it is not part of the digest.
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Endpoint is `http://host:port`, lowercase, explicit port, no
	// userinfo, path, query or fragment; IPv6 hosts in brackets.
	Endpoint string `json:"endpoint"`
	// BypassHosts is trimmed, lowercased, deduplicated and sorted in byte
	// order; proxy profiles contain RequiredBypassHosts; direct has none.
	BypassHosts []string `json:"bypass_hosts"`
	// ProbeTarget is an optional `host:port` used by `check --probe` and
	// the launch preflight for the CONNECT+TLS steps. Not in the digest.
	//
	// TODO(decision): the spec's file example has no probe_target key; it
	// is added so a CONNECT+TLS probe has an agreed target without the
	// caller inventing one (spec N10 "the agreed target").
	ProbeTarget string `json:"probe_target,omitempty"`
	// CredentialMode is always CredentialModeNone in slice A.
	CredentialMode string `json:"credential_mode"`
}

// File is a decoded, normalized and validated catalog. It is valid as a
// whole or not at all: Parse refuses the entire file when any profile is
// invalid, so a reader never sees a partially trusted catalog.
//
// TODO(decision): one invalid profile refuses every selection (the spec
// only says a file that cannot be read or parsed does); the alternative,
// per-profile validity, would let a launch proceed next to a broken
// entry and hide the breakage until the operator selects it.
type File struct {
	Schema   string
	Default  string
	Networks map[string]Profile
	Bindings Bindings
}

// Bindings are operator-local defaults. Path bindings are reserved and unsupported.
type Bindings struct {
	Profiles map[string]string `json:"profiles"`
}

// Names returns the profile names in byte order.
func (f *File) Names() []string {
	if f == nil {
		return nil
	}
	names := make([]string, 0, len(f.Networks))
	for n := range f.Networks {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Lookup returns the named profile. A nil file has no profiles.
func (f *File) Lookup(name string) (Profile, bool) {
	if f == nil {
		return Profile{}, false
	}
	p, ok := f.Networks[name]
	return p, ok
}

// Input is a profile as typed by the operator or read from the file,
// before normalization.
type Input struct {
	Kind        string
	Endpoint    string
	BypassHosts []string
	ProbeTarget string
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidateName enforces the profile-name grammar `^[a-z0-9][a-z0-9._-]{0,62}$`.
func ValidateName(name string) error {
	if nameRE.MatchString(name) {
		return nil
	}
	return refusal.New(refusal.CodeProfileInvalid, name, "name must match ^[a-z0-9][a-z0-9._-]{0,62}$")
}

// asciiLower folds ASCII A-Z to a-z and leaves every other byte unchanged.
// It never applies Unicode case mapping, so lookalikes stay distinct.
func asciiLower(s string) string {
	lower := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower[i] = c
	}
	return string(lower)
}

// asciiFoldEqual reports whether a and b match under ASCII-only folding.
func asciiFoldEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// Normalize validates and normalizes one profile. It does not insert the
// required bypass hosts: a profile read from the file must already carry
// them (validate refuses otherwise); `add` inserts them before calling
// Normalize (see WithRequiredBypass).
func Normalize(name string, in Input) (Profile, error) {
	if err := ValidateName(name); err != nil {
		return Profile{}, err
	}
	invalid := func(detail string) error {
		return refusal.New(refusal.CodeProfileInvalid, name, detail)
	}
	kind := strings.TrimSpace(in.Kind)
	switch kind {
	case "":
		return Profile{}, invalid("kind is required")
	case KindDirect:
		if in.Endpoint != "" || in.BypassHosts != nil || in.ProbeTarget != "" {
			return Profile{}, invalid("direct forbids endpoint, bypass_hosts and probe_target")
		}
		return Profile{Name: name, Kind: kind, CredentialMode: CredentialModeNone}, nil
	case KindExternalHTTPProxy:
	default:
		return Profile{}, invalid("kind is not supported; expected external-http-proxy or direct")
	}
	endpoint, err := NormalizeEndpoint(in.Endpoint)
	if err != nil {
		return Profile{}, invalid("endpoint: " + err.Error())
	}
	bypass, err := NormalizeBypassHosts(in.BypassHosts)
	if err != nil {
		return Profile{}, invalid("bypass_hosts: " + err.Error())
	}
	for _, req := range RequiredBypassHosts {
		if !contains(bypass, req) {
			return Profile{}, invalid("bypass_hosts must include localhost, 127.0.0.1 and ::1")
		}
	}
	target := ""
	if strings.TrimSpace(in.ProbeTarget) != "" {
		target, err = NormalizeProbeTarget(in.ProbeTarget)
		if err != nil {
			return Profile{}, invalid("probe_target: " + err.Error())
		}
	}
	return Profile{
		Name:           name,
		Kind:           kind,
		Endpoint:       endpoint,
		BypassHosts:    bypass,
		ProbeTarget:    target,
		CredentialMode: CredentialModeNone,
	}, nil
}

// NormalizeEndpoint accepts `http://host:port` only: scheme http,
// explicit numeric port, no userinfo (credential mode is none; the value
// is never echoed), no path other than empty or "/", no query, no
// fragment. The scheme and host are lowercased, an IPv6 host is
// bracketed and a trailing "/" is dropped. IP literals use netip canonical
// spelling; IPv4-mapped IPv6 is unmapped to IPv4. Errors are plain phrases.
func NormalizeEndpoint(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("endpoint is required")
	}
	if !strings.Contains(s, "://") {
		return "", errors.New("scheme must be http (use http://host:port)")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", errors.New("not a valid URL")
	}
	if u.Scheme != "http" {
		return "", errors.New("scheme must be http")
	}
	if u.Opaque != "" {
		return "", errors.New("not a valid URL")
	}
	if u.User != nil {
		return "", errors.New("userinfo is not allowed (credential mode is none)")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", errors.New("query is not allowed")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return "", errors.New("fragment is not allowed")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("path is not allowed")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("host is required")
	}
	port, err := normalizePort(u.Port())
	if err != nil {
		return "", err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", errors.New("IPv6 zones are not supported")
		}
		host = ip.Unmap().String()
	} else if !validHostname(host) {
		return "", errors.New("host is not a valid host name")
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

func normalizePort(port string) (string, error) {
	if port == "" {
		return "", errors.New("explicit port is required")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("port must be a number between 1 and 65535")
	}
	return strconv.Itoa(n), nil
}

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !labelRE.MatchString(label) {
			return false
		}
	}
	return true
}

var bypassRE = regexp.MustCompile(`^[a-z0-9._:\[\]/-]+$`)

// NormalizeBypassHosts trims, lowercases, deduplicates and sorts the
// entries in byte order. An empty entry, an entry containing "," or
// whitespace, a "*" (it would disable the profile) or an entry outside
// the character set [a-z0-9._:[]/-] is refused. The required hosts are
// checked by Normalize, not here.
func NormalizeBypassHosts(raw []string) ([]string, error) {
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		h := strings.ToLower(strings.TrimSpace(r))
		switch {
		case h == "":
			return nil, errors.New("empty entry")
		// This specific check precedes bypassRE so the refusal explains why.
		case h == "*":
			return nil, errors.New("\"*\" is not allowed (it would disable the profile)")
		case strings.ContainsAny(h, ", \t\r\n"):
			return nil, errors.New("entry contains a comma or whitespace")
		case len(h) > 253 || !bypassRE.MatchString(h):
			return nil, errors.New("entry contains characters outside [a-z0-9._:[]/-]")
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out, nil
}

// WithRequiredBypass returns hosts plus RequiredBypassHosts (deduplicated,
// lowercased where already valid). It is what `add` applies before
// Normalize so a new profile always carries the loopback set.
func WithRequiredBypass(hosts []string) []string {
	out := make([]string, 0, len(hosts)+len(RequiredBypassHosts))
	out = append(out, hosts...)
	for _, req := range RequiredBypassHosts {
		found := false
		for _, h := range hosts {
			if strings.ToLower(strings.TrimSpace(h)) == req {
				found = true
				break
			}
		}
		if !found {
			out = append(out, req)
		}
	}
	return out
}

// NormalizeProbeTarget accepts `host:port` (IPv6 in brackets), lowercases
// the host and renders it with net.JoinHostPort.
func NormalizeProbeTarget(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return "", errors.New("must be host:port")
	}
	host = strings.ToLower(host)
	port, err = normalizePort(port)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip == nil && !validHostname(host) {
		return "", errors.New("host is not a valid host name")
	}
	return net.JoinHostPort(host, port), nil
}

// HostKey reduces a host reference to the form bypass coverage is decided
// on: lowercased, trimmed, a port removed when present, surrounding
// brackets removed. `[::1]:11434`, `[::1]` and `::1` all map to `::1`.
func HostKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
		s = h
	}
	return strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
}

// Covers reports whether host (an engine endpoint host, N12) is in the
// profile's bypass list: an exact match of HostKey(host) against the
// HostKey of each entry. Suffix and CIDR entries do not match by
// inclusion; coverage is exact by design so the contract stays simple.
func (p Profile) Covers(host string) bool {
	key := HostKey(host)
	if key == "" {
		return false
	}
	for _, b := range p.BypassHosts {
		if HostKey(b) == key {
			return true
		}
	}
	return false
}

// canonical is the digest input of spec/contract-appendix.md §1: keys in
// byte order, no whitespace, no HTML escaping. Name, probe_target and
// every runtime fact are excluded.
type canonical struct {
	BypassHosts    []string `json:"bypass_hosts"`
	CredentialMode string   `json:"credential_mode"`
	Endpoint       string   `json:"endpoint"`
	Kind           string   `json:"kind"`
	Schema         string   `json:"schema"`
}

// Canonical returns the exact bytes the digest is computed over.
func Canonical(p Profile) []byte {
	hosts := p.BypassHosts
	if hosts == nil {
		hosts = []string{}
	}
	mode := p.CredentialMode
	if mode == "" {
		mode = CredentialModeNone
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	var value any = canonical{
		BypassHosts:    hosts,
		CredentialMode: mode,
		Endpoint:       p.Endpoint,
		Kind:           p.Kind,
		Schema:         Schema,
	}
	if p.Kind == KindDirect {
		value = struct {
			CredentialMode string `json:"credential_mode"`
			Kind           string `json:"kind"`
			Schema         string `json:"schema"`
		}{mode, p.Kind, Schema}
	}
	if err := enc.Encode(value); err != nil {
		// The struct holds only strings and a string slice; encoding
		// cannot fail. A panic is the honest report of a broken build.
		panic("netprofile: canonical encoding failed: " + err.Error())
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// Digest returns "sha256:" + lowercase hex SHA-256 of Canonical(p).
func Digest(p Profile) string {
	sum := sha256.Sum256(Canonical(p))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ShortDigest returns the first 12 hex digits of a digest, for human
// output; a malformed digest is returned unchanged.
func ShortDigest(digest string) string {
	if strings.HasPrefix(digest, "sha256:") && len(digest) == len("sha256:")+64 {
		return digest[:len("sha256:")+12]
	}
	return digest
}

// rawFile and rawProfile mirror the TOML document; unknown keys are refused.
type rawFile struct {
	Schema   string                `toml:"schema"`
	Default  string                `toml:"default"`
	Networks map[string]rawProfile `toml:"networks"`
	Bindings rawBindings           `toml:"bindings"`
}

type rawBindings struct {
	Profiles map[string]string `toml:"profiles"`
	Paths    any               `toml:"paths"`
}

type rawProfile struct {
	Kind        string   `toml:"kind"`
	Endpoint    *string  `toml:"endpoint"`
	BypassHosts []string `toml:"bypass_hosts"`
	ProbeTarget *string  `toml:"probe_target"`
}

// Parse decodes a catalog strictly (unknown keys refused), normalizes
// every profile and validates the whole. A TOML syntax error is
// network_file_unreadable (the file exists but cannot be parsed); every
// content problem is network_profile_invalid with the profile name or
// the file basename as subject.
func Parse(data []byte) (*File, error) {
	// Struct decoding folds key case (ASCII folding for ASCII keys,
	// Unicode lowercasing for non-ASCII keys). Check the binding
	// namespace through a map first, so aliases cannot merge or hide
	// invalid targets. Every spelling the typed decoder could recognize
	// as bindings must be exactly "bindings".
	var document map[string]any
	if err := toml.Unmarshal(data, &document); err != nil {
		return nil, classifyDecodeError(err)
	}
	for key, value := range document {
		if key != "bindings" && !asciiFoldEqual(key, "bindings") && strings.ToLower(key) != "bindings" {
			continue
		}
		if key != "bindings" {
			return nil, refusal.New(refusal.CodeProfileInvalid, FileName, "binding namespace must use exact lowercase keys")
		}
		if table, ok := value.(map[string]any); ok {
			for field := range table {
				if field != "profiles" && field != "paths" {
					return nil, refusal.New(refusal.CodeProfileInvalid, FileName, "unknown key in bindings")
				}
			}
		}
	}
	var raw rawFile
	dec := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, classifyDecodeError(err)
	}
	fileInvalid := func(detail string) error {
		return refusal.New(refusal.CodeProfileInvalid, FileName, detail)
	}
	switch raw.Schema {
	case Schema:
	case "":
		return nil, fileInvalid("schema is required (\"" + Schema + "\")")
	default:
		return nil, fileInvalid("schema must be \"" + Schema + "\"")
	}
	f := &File{Schema: raw.Schema, Default: strings.TrimSpace(raw.Default), Networks: map[string]Profile{}}
	if raw.Bindings.Paths != nil {
		return nil, refusal.New(refusal.CodeScopeUnsupported, FileName, "[bindings.paths] is reserved and unsupported")
	}
	names := make([]string, 0, len(raw.Bindings.Profiles))
	for name := range raw.Bindings.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := make(map[string]string, len(names))
	for _, name := range names {
		folded := asciiLower(name)
		if first, ok := seen[folded]; ok && first != name {
			return nil, refusal.New(refusal.CodeProfileInvalid, FileName, "conflicting duplicate binding")
		}
		if _, ok := seen[folded]; !ok {
			seen[folded] = name
		}
	}
	for _, name := range names {
		if err := ValidateName(name); err != nil {
			return nil, err
		}
		if err := ValidateName(raw.Bindings.Profiles[name]); err != nil {
			return nil, err
		}
	}
	f.Bindings.Profiles = raw.Bindings.Profiles
	for _, name := range sortedKeys(raw.Networks) {
		rp := raw.Networks[name]
		// Pointers retain field presence: even an empty forbidden key is invalid.
		if strings.TrimSpace(rp.Kind) == KindDirect && (rp.Endpoint != nil || rp.BypassHosts != nil || rp.ProbeTarget != nil) {
			return nil, refusal.New(refusal.CodeProfileInvalid, name, "direct forbids endpoint, bypass_hosts and probe_target")
		}
		var endpoint, target string
		if rp.Endpoint != nil {
			endpoint = *rp.Endpoint
		}
		if rp.ProbeTarget != nil {
			target = *rp.ProbeTarget
		}
		p, err := Normalize(name, Input{Kind: rp.Kind, Endpoint: endpoint, BypassHosts: rp.BypassHosts, ProbeTarget: target})
		if err != nil {
			return nil, err
		}
		f.Networks[name] = p
	}
	if f.Default != "" {
		if _, ok := f.Networks[f.Default]; !ok {
			return nil, refusal.New(refusal.CodeProfileInvalid, "default", "default names an unknown profile")
		}
	}
	return f, nil
}

func classifyDecodeError(err error) error {
	var strict *toml.StrictMissingError
	if errors.As(err, &strict) {
		// Never echo unknown keys: their names are untrusted file contents.
		// Identify a single owning profile only under the plain-subject rule.
		name := ""
		for i, missing := range strict.Errors {
			key := missing.Key()
			if len(key) < 2 || key[0] != "networks" || !refusal.PlainSubject(key[1]) {
				name = ""
				break
			}
			if i == 0 {
				name = key[1]
			} else if name != key[1] {
				name = ""
				break
			}
		}
		subject, location := FileName, "catalog"
		if name != "" {
			subject, location = name, "[networks."+name+"]"
		}
		return refusal.New(refusal.CodeProfileInvalid, subject,
			fmt.Sprintf("unknown key in %s (count: %d)", location, len(strict.Errors)))
	}
	var de *toml.DecodeError
	if errors.As(err, &de) {
		row, _ := de.Position()
		if key := de.Key(); len(key) > 0 {
			// Duplicate errors may carry only a leaf key. Never copy arbitrary
			// decoder metadata, even when the owning table is unavailable.
			return refusal.New(refusal.CodeProfileInvalid, subjectForKey(key),
				decodeFieldLabel(key)+": wrong type")
		}
		return refusal.New(refusal.CodeFileUnreadable, FileName,
			fmt.Sprintf("syntax error at line %d", row))
	}
	return refusal.New(refusal.CodeFileUnreadable, FileName, "cannot parse")
}

// decodeFieldLabel exposes only known fields and validated identifiers.
func decodeFieldLabel(key toml.Key) string {
	if asciiFoldEqual(key[0], "bindings") || strings.ToLower(key[0]) == "bindings" {
		return "bindings"
	}
	if len(key) == 1 {
		switch key[0] {
		case "schema", "default", "networks":
			return key[0]
		}
	}
	if len(key) == 3 && key[0] == "networks" && nameRE.MatchString(key[1]) {
		switch key[2] {
		case "kind", "endpoint", "bypass_hosts", "probe_target":
			return "networks." + key[1] + "." + key[2]
		}
	}
	return "catalog field"
}

// subjectForKey names the profile a key belongs to, else the file.
func subjectForKey(key toml.Key) string {
	if len(key) >= 2 && key[0] == "networks" && nameRE.MatchString(key[1]) {
		return key[1]
	}
	return FileName
}

func sortedKeys(m map[string]rawProfile) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
