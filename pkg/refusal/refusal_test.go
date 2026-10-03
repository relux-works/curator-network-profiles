// SPDX-License-Identifier: Apache-2.0

package refusal_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

// TestCodeLiterals pins every code literal: the spec N10 set in order,
// then the implementation additions. A renamed constant fails here.
func TestCodeLiterals(t *testing.T) {
	t.Parallel()
	want := []string{
		"network_profile_unknown",
		"network_profile_denied",
		"network_scope_unsupported",
		"network_configuration_conflict",
		"network_proxy_unreachable",
		"network_proxy_auth_failed",
		"network_profile_drift",
		"network_profile_invalid",
		"network_file_unreadable",
		"network_confirm_refused",
	}
	got := refusal.Codes()
	if len(got) != len(want) {
		t.Fatalf("Codes() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Codes()[%d] = %q, want %q", i, got[i], want[i])
		}
		if !refusal.Valid(want[i]) {
			t.Errorf("Valid(%q) = false", want[i])
		}
	}
	pins := map[string]string{
		refusal.CodeProfileUnknown:        "network_profile_unknown",
		refusal.CodeProfileDenied:         "network_profile_denied",
		refusal.CodeScopeUnsupported:      "network_scope_unsupported",
		refusal.CodeConfigurationConflict: "network_configuration_conflict",
		refusal.CodeProxyUnreachable:      "network_proxy_unreachable",
		refusal.CodeProxyAuthFailed:       "network_proxy_auth_failed",
		refusal.CodeProfileDrift:          "network_profile_drift",
		refusal.CodeProfileInvalid:        "network_profile_invalid",
		refusal.CodeFileUnreadable:        "network_file_unreadable",
		refusal.CodeConfirmRefused:        "network_confirm_refused",
	}
	for c, lit := range pins {
		if c != lit {
			t.Errorf("constant %q != literal %q", c, lit)
		}
	}
	for _, bad := range []string{"", "usage", "NETWORK_PROFILE_UNKNOWN", "network_profile_unknown "} {
		if refusal.Valid(bad) {
			t.Errorf("Valid(%q) = true", bad)
		}
	}
}

func TestErrorRendering(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		r    *refusal.Refusal
		want string
	}{
		{"full", refusal.New(refusal.CodeProfileUnknown, "egress-x", "no such network profile"), "network_profile_unknown: egress-x: no such network profile"},
		{"no subject", refusal.New(refusal.CodeFileUnreadable, "", "HOME is not set"), "network_file_unreadable: HOME is not set"},
		{"no detail", refusal.New(refusal.CodeProfileDrift, "egress-a", ""), "network_profile_drift: egress-a"},
		{"invalid subject", refusal.New(refusal.CodeProfileUnknown, "bad name\nnext", "x"), "network_profile_unknown: <invalid name>: x"},
		{"nil", nil, "network refusal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.r.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
	long := refusal.New(refusal.CodeProfileUnknown, strings.Repeat("x y", 60), "")
	if s := long.Error(); s != "network_profile_unknown: <invalid name>" {
		t.Errorf("long subject not replaced: %q", s)
	}
}

func TestCodeOfAndIs(t *testing.T) {
	t.Parallel()
	inner := refusal.New(refusal.CodeProxyAuthFailed, "egress-a", "407")
	wrapped := fmt.Errorf("preflight: %w", inner)
	code, ok := refusal.CodeOf(wrapped)
	if !ok || code != refusal.CodeProxyAuthFailed {
		t.Fatalf("CodeOf = %q,%v", code, ok)
	}
	if _, ok := refusal.CodeOf(errors.New("plain")); ok {
		t.Fatal("CodeOf(plain) matched")
	}
	if !errors.Is(wrapped, &refusal.Refusal{Code: refusal.CodeProxyAuthFailed}) {
		t.Fatal("errors.Is by code failed")
	}
	if errors.Is(wrapped, &refusal.Refusal{Code: refusal.CodeProxyUnreachable}) {
		t.Fatal("errors.Is matched a different code")
	}
	if errors.Is(wrapped, &refusal.Refusal{Code: refusal.CodeProxyAuthFailed, Subject: "other"}) {
		t.Fatal("errors.Is matched a different subject")
	}
	r, ok := refusal.As(wrapped)
	if !ok || r != inner {
		t.Fatal("As did not return the inner refusal")
	}
	var typedNil *refusal.Refusal
	if _, ok := refusal.CodeOf(typedNil); ok {
		t.Fatal("typed nil classified")
	}
}

func TestInvalidSubjectsAreReplaced(t *testing.T) {
	for _, subject := range []string{"http://u:pw@h:1", "bad name\nnext", strings.Repeat("x", 81)} {
		r := refusal.New(refusal.CodeProfileUnknown, subject, "unknown")
		if r.Subject != "<invalid name>" || r.Error() != "network_profile_unknown: <invalid name>: unknown" {
			t.Errorf("invalid subject was retained")
		}
		direct := &refusal.Refusal{Code: refusal.CodeProfileUnknown, Subject: subject}
		if direct.Error() != "network_profile_unknown: <invalid name>" {
			t.Error("direct refusal echoed invalid subject")
		}
	}
}
