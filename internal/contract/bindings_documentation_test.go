// SPDX-License-Identifier: Apache-2.0

package contract_test

import (
	"strings"
	"testing"
)

func TestBindingMigrationDocumentation(t *testing.T) {
	for _, file := range []string{"README.md", "docs/integration-contract.md"} {
		doc := repoFile(t, file)
		for _, required := range []string{
			"`resolve.Request` and `netprofile.File` gain fields",
			"keyed literals for both exported structs",
			"strict `list --json` and `show --json` decoders",
			"existing v1 schemas", "reject the whole catalog",
			"remove the entire bindings table",
			"empty header left after the last `unbind`",
			"current `hosted.Carrier` v1 has no `profile-binding` origin",
			"separately specified, versioned integration",
			"`operator` or `explicit`", "Record fields",
		} {
			if !strings.Contains(strings.ToLower(normalizeWhitespace(doc)), strings.ToLower(normalizeWhitespace(required))) {
				t.Errorf("%s lacks binding migration requirement %q", file, required)
			}
		}
	}
	changelog := repoFile(t, "CHANGELOG.md")
	for _, required := range []string{"keyed `resolve.Request` and `netprofile.File` literals", "strict `list` / `show` JSON decoders", "always-present `bindings`", "destination operator catalog", "including empty headers", "README.md#upgrading-for-operator-profile-bindings"} {
		if !containsRequiredText(changelog, required) {
			t.Errorf("changelog lacks %q", required)
		}
	}
}

func TestBindingDesignAndArchitectureDocumentation(t *testing.T) {
	for _, file := range []string{"spec/network-profiles.md", "spec/network-profiles.ru.md"} {
		doc := repoFile(t, file)
		if !containsRequiredText(doc, "origin ∈ {explicit, inherited, runtime-default, profile-binding, project-default, operator-default}") {
			t.Errorf("%s has stale origin vocabulary", file)
		}
		for _, required := range []string{"[bindings.profiles]", "~/.curator/network.toml", "resolve.Request.CuratorProfile", "contract-appendix.md#37-selection-and-inheritance-spec-n3-n4-n8"} {
			if !containsRequiredText(doc, required) {
				t.Errorf("%s lacks operator binding source %q", file, required)
			}
		}
		start := strings.Index(doc, "### N4 ")
		if start < 0 {
			t.Fatalf("%s lacks N4", file)
		}
		end := strings.Index(doc[start:], "### N5 ")
		if end < 0 {
			t.Fatalf("%s lacks N5", file)
		}
		section := doc[start : start+end]
		order := "runtime-binding default → operator profile binding (`profile-binding`) → project default"
		if strings.HasSuffix(file, ".ru.md") {
			order = "значение по умолчанию привязки среды выполнения → привязка профиля оператора (`profile-binding`) → значение по умолчанию проекта"
		}
		if !containsRequiredText(section, order) {
			t.Errorf("%s has stale N4 ordering", file)
		}
	}
	doc := repoFile(t, "docs/architecture.md")
	for _, required := range []string{"explicit → inherited → runtime-default → profile-binding → project-default → operator-default", "resolve.OriginProfileBinding", "Request.CuratorProfile", "[bindings.profiles]", "never project/profile files or environment selectors", "contract-appendix.md#37-selection-and-inheritance-spec-n3-n4-n8"} {
		if !containsRequiredText(doc, required) {
			t.Errorf("architecture lacks %q", required)
		}
	}
	doc = repoFile(t, "docs/integration-contract.md")
	for _, required := range []string{"Primary sessions require authenticated session-record lookup or explicit child selection", "| Inheritance and selection precedence | Adopted: `inherited` origin;"} {
		if !containsRequiredText(doc, required) {
			t.Errorf("integration guidance lacks public description %q", required)
		}
	}
}
