// SPDX-License-Identifier: Apache-2.0
package adapterprobe

// Recipes bind the adapter's exact stimulus to an intended observation, not to
// incidental startup traffic. Real vendor operations are intentionally marked
// unavailable until a credential-free recipe and immutable runtime are audited.
// Fixture paths may refer only to supervisor-created private directories; no
// operator HOME, authentication symlink, token or configuration may be supplied.
type recipe struct {
	Harness, Entrypoint string
	Argv                []string
	Expected            Observation
	Unavailable         string
}

var recipes = map[string]recipe{
	"claude-exec-v1": {Harness: "claude-code", Entrypoint: "exec", Unavailable: "credential_free_recipe_unavailable"},
	// The interactive terminal session of the same harness. Like exec, it is
	// admitted only through an exact allowlisted build in strict mode; no
	// automatic qualification exists for it.
	"claude-interactive-v1": {Harness: "claude-code", Entrypoint: "interactive", Unavailable: "credential_free_recipe_unavailable"},
	"codex-interactive-v1":  {Harness: "codex-cli", Entrypoint: "interactive", Unavailable: "credential_free_recipe_unavailable"},
	"codex-exec-v1":         {Harness: "codex-cli", Entrypoint: "exec", Unavailable: "runtime_closure_unsupported"},
	"muse-exec-v1":          {Harness: "muse", Entrypoint: "exec", Unavailable: "credential_free_recipe_unavailable"},
	"codex-hosted-v1":       {Harness: "codex-cli", Entrypoint: "app-server", Unavailable: "protocol_recipe_unsupported"},
}
