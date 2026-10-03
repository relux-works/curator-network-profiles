// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

func TestUnexpectedFailureUsesClosedSanitizedCode(t *testing.T) {
	body := bodyOf(errors.New("private path /operator/secret"))
	if !refusal.Valid(body.Code) || strings.Contains(body.Message+body.Subject, "secret") {
		t.Fatalf("unclosed or unsanitized error: %+v", body)
	}
	if body.Subject != "" || body.Message != body.Code+": internal operation failed" {
		t.Fatalf("unexpected internal failure detail: %+v", body)
	}
}

func TestJSONBodySanitizesDirectRefusalSubjects(t *testing.T) {
	body := bodyOf(&refusal.Refusal{Code: refusal.CodeProfileUnknown, Subject: "http://u:pw@h:1", Detail: "unknown"})
	if body.Subject != "<invalid name>" || body.Message != "network_profile_unknown: <invalid name>: unknown" {
		t.Error("direct refusal leaked into JSON body")
	}
}
