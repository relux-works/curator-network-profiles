// SPDX-License-Identifier: Apache-2.0

// Package refusal defines the closed set of network-profile refusal codes
// (spec/network-profiles.md N10) and the typed, sanitized error that
// carries one of them.
//
// A refusal message never contains TOML contents, absolute paths, raw
// environment values or credentials: Subject is a profile name, a role
// word or a file basename, and Detail is a fixed phrase chosen by the
// raising package. The code, not the prose, is the contract.
//
// Exit rule (provider CLI): every refusal exits 1; usage errors are not
// refusals and exit 2.
package refusal

import (
	"errors"
	"regexp"
)

// Codes of spec N10, in specification order.
const (
	CodeProfileUnknown        = "network_profile_unknown"
	CodeProfileDenied         = "network_profile_denied"
	CodeScopeUnsupported      = "network_scope_unsupported"
	CodeConfigurationConflict = "network_configuration_conflict"
	CodeProxyUnreachable      = "network_proxy_unreachable"
	CodeProxyAuthFailed       = "network_proxy_auth_failed"
	CodeProfileDrift          = "network_profile_drift"
)

// Codes added by the implementation (each one a TODO(decision), see
// docs/architecture.md "Error taxonomy"):
//
//   - CodeProfileInvalid: TODO(decision) the spec has no code for a
//     malformed profile or file content (unknown key, bad endpoint,
//     missing schema); a refusal is needed because a malformed catalog
//     refuses every selection and "invalid" is not "unknown".
//   - CodeFileUnreadable: TODO(decision) the spec has no code for a
//     catalog or ledger that cannot be read, parsed, encoded or written; a read failure
//     is never headroom, so it needs its own code distinct from
//     "unknown" (absent) and "invalid" (well-formed but wrong).
//   - CodeConfirmRefused: TODO(decision) the spec says `confirm` refuses
//     to run in an agent session (trust §10) but names no code for it.
const (
	CodeProfileInvalid = "network_profile_invalid"
	CodeFileUnreadable = "network_file_unreadable"
	CodeConfirmRefused = "network_confirm_refused"
)

// Codes returns the closed code set: the spec N10 codes in specification
// order followed by the implementation additions.
func Codes() []string {
	return []string{
		CodeProfileUnknown,
		CodeProfileDenied,
		CodeScopeUnsupported,
		CodeConfigurationConflict,
		CodeProxyUnreachable,
		CodeProxyAuthFailed,
		CodeProfileDrift,
		CodeProfileInvalid,
		CodeFileUnreadable,
		CodeConfirmRefused,
	}
}

var valid = func() map[string]bool {
	m := make(map[string]bool, 10)
	for _, c := range Codes() {
		m[c] = true
	}
	return m
}()

// Valid reports whether code is a member of the closed set.
func Valid(code string) bool { return valid[code] }

// Refusal is a typed, sanitized refusal. Code is a member of Codes();
// Subject identifies what was refused (a profile name, a file basename,
// a role word) and Detail is a short fixed phrase. None of the three ever
// carries a secret, an absolute path or file contents.
type Refusal struct {
	Code    string
	Subject string
	Detail  string
}

// New builds a refusal. Callers pass a code from the closed set; an
// unknown code is kept verbatim so a caller bug stays visible rather
// than being silently renamed.
func New(code, subject, detail string) *Refusal {
	if subject != "" {
		subject = safeSubject(subject)
	}
	return &Refusal{Code: code, Subject: subject, Detail: detail}
}

// Error renders `<code>: <subject>: <detail>`; an empty subject or
// detail is omitted with its separator.
func (r *Refusal) Error() string {
	if r == nil {
		return "network refusal"
	}
	s := r.Code
	if r.Subject != "" {
		s += ": " + safeSubject(r.Subject)
	}
	if r.Detail != "" {
		s += ": " + r.Detail
	}
	return s
}

// Is makes errors.Is(err, &Refusal{Code: c}) match on the code alone.
func (r *Refusal) Is(target error) bool {
	t, ok := target.(*Refusal)
	if !ok || r == nil || t == nil {
		return false
	}
	return r.Code == t.Code && (t.Subject == "" || t.Subject == r.Subject)
}

// CodeOf returns the refusal code carried anywhere in err's wrap chain.
func CodeOf(err error) (code string, ok bool) {
	var r *Refusal
	if errors.As(err, &r) && r != nil {
		return r.Code, true
	}
	return "", false
}

// As returns the refusal carried anywhere in err's wrap chain.
func As(err error) (*Refusal, bool) {
	var r *Refusal
	if errors.As(err, &r) && r != nil {
		return r, true
	}
	return nil, false
}

var plainSubject = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$`)

// PlainSubject reports whether s may appear verbatim as a diagnostic identifier.
func PlainSubject(s string) bool { return plainSubject.MatchString(s) }

// safeSubject keeps a well-formed identifier and replaces every other
// subject with a fixed placeholder, so invalid names cannot leak credentials.
func safeSubject(s string) string {
	if PlainSubject(s) {
		return s
	}
	return "<invalid name>"
}
