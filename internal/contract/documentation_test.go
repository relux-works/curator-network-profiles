// SPDX-License-Identifier: Apache-2.0

package contract_test

import (
	"strings"
	"testing"
)

// Required text guards ignore prose wrapping while preserving the words.
func normalizeWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func containsRequiredText(doc, required string) bool {
	return strings.Contains(normalizeWhitespace(doc), normalizeWhitespace(required))
}

func TestNormalizeWhitespace(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"empty", "", ""},
		{"only whitespace", " \t\r\n\v\f\u00a0\u2003 ", ""},
		{"unchanged", "no CLI cleanup", "no CLI cleanup"},
		{"wrapped prose", "  no\tCLI\r\n  cleanup\n", "no CLI cleanup"},
		{"unicode whitespace", "no\u00a0CLI\u2003cleanup", "no CLI cleanup"},
		{"preserve non-whitespace", " `CLI`\ncleanup: TODO(decision) ", "`CLI` cleanup: TODO(decision)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeWhitespace(tc.input); got != tc.want {
				t.Fatalf("normalizeWhitespace(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestContainsRequiredText(t *testing.T) {
	for _, tc := range []struct {
		name, doc, required string
		want                bool
	}{
		{"wrapped document", "A crash-stale lock has no CLI\n  cleanup: ask the operator.", "no CLI cleanup", true},
		{"wrapped needle", "A crash-stale lock has no CLI cleanup.", "no\tCLI\ncleanup", true},
		{"both wrapped", "A lock has no\nCLI\tcleanup.", "no\r\n CLI\u00a0cleanup", true},
		{"missing phrase", "A crash-stale lock needs manual removal.", "no CLI cleanup", false},
		{"missing word", "A crash-stale lock has no cleanup.", "no CLI cleanup", false},
		{"changed case", "A lock has no cli cleanup.", "no CLI cleanup", false},
		{"changed punctuation", "A lock has no CLI-cleanup.", "no CLI cleanup", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsRequiredText(tc.doc, tc.required); got != tc.want {
				t.Fatalf("containsRequiredText(%q, %q) = %v, want %v", tc.doc, tc.required, got, tc.want)
			}
		})
	}
}
