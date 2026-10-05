# Integration contract: how the process owners apply a network profile

Status: **ADOPTED by Ivan 2026-10-02 (operator decision); DRAFT until implemented by the consumers** (rev 2, D1). Repository owners retain approval of implementation in their repositories.

Normative inputs: `spec/network-profiles.md` (N1–N14) and the implemented `spec/contract-appendix.md` (digest, EnvPatch, equality, Record and refusals). **The appendix wins on bytes.** The inherited-origin amendment (D2) is implemented in this library; consumer changes remain DRAFT until implemented.

Source pins checked locally on 2026-10-02; citations use these aliases (short filenames retain the stated directory):

| Alias | Repository / path | Commit |
| --- | --- | --- |
| N | this repository, N-A implementation/spec baseline | `bf6d514` |
| A | skill-agents-management | `400f5377` |
| B | skill-project-management / `tools/board-cli` | `110270d9` |
| R / H | B / `internal/spawnruntime` / `internal/sessionmanager` | same as B |
| L | curator-agent-launcher | `1ac7eafb` |
| S | curator-spec | `e41c561b` |
| C | curator | `2cb29dac` |
| X | agent-session-host | `2c6cd39d` |

Advice item numbers below retain the adopted numbering within §2.2 and §2.3 (operator decision, 2026-10-02); all nine objections were assessed. Only that owner replied by the deadline. Roadmap context comes from the project roadmap.

## 1. What the library gives every consumer

The Go module `github.com/relux-works/curator-network-profiles` exposes `pkg/`, creates no processes, runs no daemon and imports no callers (N2). The process owner prepares a binding **on the destination host immediately before spawn or resume**:

```text
Selection → resolve/validate → conditional preflight → bind → patch.Apply(final childEnv) → spawn → record
ref+origin      N4/N3/N12              N10              N3             N5                         N8
```

| Operation | Input / result | Refusals |
| --- | --- | --- |
| resolve/validate | caller's explicit/inherited/runtime/project refs and optional Curator profile name; host catalog, confirmations, allowed set, assurance and engine hosts → normalized profile and origin, or unmanaged | `network_profile_unknown`, `network_profile_denied`, `network_file_unreadable`, `network_profile_invalid`, `network_configuration_conflict`, `network_scope_unsupported` |
| preflight | direct or plan/dry run → no probe, `ProbeRecord` tcp/connect/tls = `skipped`; otherwise endpoint, optional target, deadline → TCP/CONNECT/TLS facts | `network_proxy_unreachable`, `network_proxy_auth_failed` |
| bind / patch / record | verified adapter tuple → Binding; direct unsets only (empty set), proxy unsets then sets final env; sanitized managed Record | no new refusal codes |
| reattach / resume | recorded Record, freshly resolved binding, event → full equality check | `network_profile_drift`, `network_scope_unsupported`; resolve's unknown/denied comes first |

These are conceptual stages, not separate public methods: `catalog.Load` and `Catalog.Resolve` perform catalog/ledger loading and validation (N/pkg/catalog/catalog.go:28–70; pkg/resolve/resolve.go:116–157). The appendix already implements the added file/profile codes, retaining their TODO(decision) labels. **Unmanaged means no selection, an empty patch and unchanged ambient routing; it does not mean direct.**

Apply the patch **after filtering and every overlay**, updating full Env and owned literals. For direct, unset the proxy family from both Env and owned literals and set nothing. A proxy patch's `set` half travels as `env_literals`, never `env_names` (N5; S/decisions/0013-execution-ownership-and-launch-plans.md:193–206). Later overlays must refuse proxy-family names case-insensitively (`network_configuration_conflict`) when managed. Reapply the same patch after the final overlay if cleanliness cannot be proved; idempotence does not protect against later writes or different bindings. Relevant late overlays are B/internal/spawn/launch_plan.go:479 and L/internal/composition/composition.go:91–110. A/pkg/vendorplugin/vendors/local-models/spawn.go:54 merges **before** BuildPlan (A/pkg/vendorplugin/spawn.go:249–315).

Advice §2.2(5): “The `set` half can carry proxy userinfo.” Raw structs can, but normalized profiles refuse it (N/pkg/netprofile/profile.go:202–203). Only normalized, confirmed resolution may produce a patch; serialize **Record only**, never Binding/Patch, endpoint or env. Owned literals are recorded/replayed and must be non-secret (0013:232–235,304–313). V1 permits credential mode `none`; future secrets stay in a gateway, behind a loopback endpoint (N6/N11).

Plans/dry runs resolve, validate, bind and patch, skip network preflight, and record tcp/connect/tls as `skipped` (N10). Direct also skips all three probes, including `check --probe`, and uses an unset-only patch with no set values. Only real proxy launches probe the destination; a targetless probe proves TCP only.

### Record and equality (N3, N7, N8)

```json
{"network":{"schema":"relux-network-binding-record-v1","profile_ref":"egress-a","origin":"explicit","profile_digest":"sha256:…","adapter_identity":{"adapter":"generic-env-v1","harness":"codex","build":"0.x.y","entrypoint":"exec"},"assurance":"cooperative","probe":{"tcp":"ok","connect":"skipped","tls":"skipped","checked_at":"RFC3339"}}}
```

Absent key means unmanaged. The illustrative Record omits endpoint, env and credentials. Equality compares **digest + adapter identity + assurance**, not name. Resume re-resolves the recorded ref on that host; unknown/denied precedes comparison (N/spec/contract-appendix.md:757).

| Event | Outcome |
| --- | --- |
| fresh process | new launch with its own binding |
| existing-run resume/restore, full equality | reattach |
| existing-run resume/restore, same ref but changed digest | `network_profile_drift` |
| existing-run resume/restore, other inequality | `network_scope_unsupported` |
| new assignment on a live host, equal binding | attach |
| new assignment, unequal binding, no per-session route | `network_scope_unsupported` |
| new assignment, unequal binding, verified per-session route | N7 permits set-per-session; deferred for first-release live hosts (§2.3) |

A changed profile requires restoration or a genuinely new launch, never silent rerouting of the existing run. Retry has the separate proposed policy in §2.2.

### 1.3 Selection precedence and operator-local bindings

Selection precedence is **explicit → inherited → runtime-default → profile-binding → project-default → operator-default**; no selection is unmanaged. Host locks and the allowed set constrain whichever reference wins. A selected unknown target refuses with `network_profile_unknown` without falling back.

The caller passes the optional Curator profile name in `resolve.Request.CuratorProfile`. The resolver looks up that exact identifier only in the destination operator catalog, `~/.curator/network.toml`:

```toml
[bindings.profiles]
work = "egress-a"
"work.dev" = "direct"
```

Both keys and targets follow the existing identifier grammar. Namespace keys must be exactly `bindings`, `profiles` and the reserved `paths`; case aliases and duplicate mappings are refused without merging. Quoted or escaped keys that decode to those exact names are accepted. Unknown keys are refused. `[bindings.paths]` is reserved and refused with `network_scope_unsupported`, including an empty table. Bindings MUST NOT be read from a project or a Curator profile. Projects may continue supplying `spawn.network.default`; runtime defaults remain higher priority than profile bindings.

`curator network bind <curator-profile> <network>` sets or replaces a binding; `unbind <curator-profile>` removes one. Both require the existing agent-session guard, operator terminal and an explicit `yes` before the atomic catalog edit. A catalog change during the prompt refuses; the target's digest still needs its separate confirmation. `list` includes every binding; `show <network>` includes the bindings targeting that network. JSON uses the additive `bindings.profiles` map in both documents.

The selected origin is `profile-binding` in Selection and Record. Bindings are excluded from profile digests and binding equality; record schema and resume/drift semantics stay unchanged. All catalog consumers must accept this additive origin and catalog table before operators add bindings. CLI editing preserves unrelated catalog bytes and supports ordinary single-line entries in `[bindings.profiles]`; other TOML layouts require manual editing.

Source and strict-decoder compatibility require an explicit migration:
`resolve.Request` and `netprofile.File` gain fields, so use keyed literals for
both exported structs. Strict `list --json` and `show --json` decoders must
accept the always-present `bindings` field, including empty maps, under the
existing v1 schemas. Pre-binding catalog readers reject the whole catalog;
upgrade every reader before adding bindings. Rollback must remove the entire
bindings table, including an empty header left after the last `unbind`.

The current `hosted.Carrier` v1 has no `profile-binding` origin. Preserving
provenance across that boundary requires a separately specified, versioned
integration, never relabeling the origin as `operator` or `explicit`.
These rollout requirements are separate from the unchanged profile digests,
binding equality and Record fields/schema. See the
[binding migration notes](../README.md#upgrading-for-operator-profile-bindings).

## 2. Per consumer: where, who, what

### 2.1 Launch plane: `skill-agents-management`

**Lands in:** optional N-B hook migration / N-C1a. **Q1 — decided (operator decision D4, typed launch-plane hook):** typed `Network{Patch,Record}` request data on `agentic.LaunchRequest` and `vendorplugin.SpawnRequest`, rather than arbitrary callbacks. Apply purely after `ChildEnv` (A/pkg/agentic/plan.go:459–463), including the separately filtered owned snapshot (:482–489; type :267–273). `LaunchRequest.Env` is the parent env (A/pkg/agentic/system.go:560); preserve existing engine provenance when adding network provenance. The module still owns no exec.

Decision 0019 is **adopted** (S/decisions/0019-fragment-consumers-and-one-construction-site.md:5), but :117–120,172–175 leave environment composition with consumers pending a separate decision. Compose-first N-B remains viable. Keep owner-side final application until every later overlay rejects proxy names and final Env/OwnedEnv parity is proved.

**Q7 — decided (operator decision D8):** support only verified exact harness/build/entrypoint/adapter tuples. Generic env support does not certify every claude/codex/qwen/pi/pinative/gemini/agy release. Verified harness-specific websocket/native overrides belong to that adapter, not the generic one (N5).

A tuple is supported only once its **R0–R5 (+R6 where a model client exists)** rows pass under the method in [harness verification](harness-verification.md) and the result is recorded here. Child rows must pass with the required adapter's mitigation applied; a generic-patch failure is not a pass. The launch plane's allowlist mirrors this table, including its scope limits and pending adapters; blocked or unverified scopes remain `network_scope_unsupported`.

| Harness / build | Entrypoint | Required adapter | Launch-plane status / task |
| --- | --- | --- | --- |
| `claude-code` **2.1.287** | `exec`, verified as `claude -p` | `generic-env-v1` | Allowlisted for the observed scope, **Claude transport support**; login-gated scopes below remain unverified |
| `codex-cli` **0.159.0** | `exec`, verified as `codex exec` | **`codex-env-v1` REQUIRED** | Until the adapter exists, `--network` refuses Codex with `network_scope_unsupported`; **Codex adapter**, under the operator's priority |
| `muse` **1.4.1-R4503.1 / 1.4.2-R4684.1** | `exec` / launcher, as recorded below | `muse-env-v1` | D8 = (A), supported with the required adapter; **Muse adapter** |
| `pi`, `qwen`, `gemini`, `agy` (all builds) | Unverified | Unverified | Refused until each runs [harness verification](harness-verification.md) and its exact tuple's passing results are recorded here |

- **Claude evidence (2026-10-02, sink + SIGKILL sandbox; `REPORT-hv-r2.md`:31–54):** R0 checked startup/version only. R1 recorded one `CONNECT api.anthropic.com:443`, proving API-target routing rather than an authenticated model request. R3 lowercase, uppercase and `ALL_PROXY` variants reached that target. MCP stdio children **inherit all six exact values** (R4 PASS; R4b explicit env also PASS). All turn rows exited 1 at the login gate; R2 had zero sink requests and no transport-refusal message. No sandbox SIGKILL or non-loopback socket was observed (R5: 22 samples), including R2, but authenticated turn/fallback, hooks and tool scopes remain unverified (N11 scope). The verified entrypoint is `claude -p`; this evidence does not cover interactive mode. The launch-plane allowlist is **Claude transport support**.
- **Codex evidence (2026-10-02, same method; `REPORT-hv-r2.md`:56–98):** R0 checked startup/version only. R1 and R3 route the model client over WebSockets and HTTPS through the proxy (`api.openai.com:443`); its WS→HTTPS fallback stays on that proxy. Startup CONNECTs also target `chatgpt.com:443`, `github.com:443` and `api.github.com:443`. R2 returned connection-refused errors and retried with zero sink requests, no observed direct fallback or sandbox SIGKILL within **30 s**; all turn rows ended at the supervisor timeout with **SIGTERM/143**, not a natural terminal error exit. R5 observed zero non-loopback sockets over 315 samples; later retries are not certified. MCP stdio children **do not inherit any of the six values** (R4 FAIL; hostile values also absent), while explicit server `env` blocks deliver all six exactly (R4b PASS). **`codex-env-v1` = the generic patch + its set half injected into each MCP server entry's `env`**, in launch-private materialised configuration, never shared MCP configuration. This is the same proposed injection mechanism as Muse's adapter, but Muse's R4b demonstrates only two values on one build. Implementation is **Codex adapter**, under the operator's priority. Code-mode companion, hook and tool-child scopes remain unverified. Until this adapter exists, `--network` refuses Codex with `network_scope_unsupported`.

- **Status — D8 = (A), Ivan, 2026-10-02 05:44Z:** Muse **1.4.1-R4503.1** and **1.4.2-R4684.1** are **SUPPORTED with `muse-env-v1`**. This decision requires the adapter below and retains the evidence limits; it does not certify the generic patch alone or unverified child scopes.
- **Evidence sources:** the integration owner on the verification runner, authoritative `D8-muse-results-R7.md`, verification event the recorded verification event, and `D8-muse-R6-sigkill-msg.txt`, verification event the recorded verification event (2026-10-02T05:33:20Z). These supersede conflicting text in `D8-muse-results.md`, `D8-muse-results-R6.md` and the stale round-2 Muse import. The per-build R6 table and row attribution are recorded in [harness verification](harness-verification.md#imported-final-d8-muse--muse-exec-and-launcher).
- **Adapter and child evidence:** `muse-env-v1` is the generic patch plus injection of its **set half into each MCP server entry's `env` block**, plus hook-command wrapping during profile materialisation. R4 fails on **both builds**: MCP stdio children get `HOME LANG LOGNAME MUSE_SESSION_ID PATH PWD SHELL SHLVL TERM TMPDIR USER`, without any of the six proxy values or hostile values. R4b demonstrates explicit **`HTTPS_PROXY` and `NO_PROXY` on 1.4.1-R4503.1 only**, not a six-value/per-build mitigation dump. R7a's detailed **1.4.1** SessionStart hook run receives `HOME LANG LOGNAME PATH PWD SHELL SHLVL SSH_AUTH_SOCK TERM TMPDIR USER`, without proxy or hostile values; the Claude-compatible object schema has no per-hook `env` field. No separate 1.4.2 hook run is reported. Wrap **each** hook command as `env <set half> <cmd>`; this is a required mitigation, with no verified wrapping run in these sources.
- **Control and launcher evidence:** R0, R1 and R2 are per build for **1.4.1-R4503.1 and 1.4.2-R4684.1**: Echo control exits 0 with no requests; update through the sink exits 1 with two `CONNECT api.meta.ai:443`; update through `127.0.0.1:9` exits 1 with connection refusal and no direct fallback. All three have zero non-loopback sockets. R3's detailed lowercase-only, uppercase-only and ALL_PROXY-only rows are **1.4.1 only**, each exit 1 with two sink requests and zero non-loopback sockets, testing the launcher's curl. The later message summarizes R3 as passing on both without separate 1.4.2 variant rows. R5 is **aggregate across both builds' R0–R4**, with zero sampled non-loopback sockets; sampling alone does not rule out a blocked direct attempt.
- **R6 model-client evidence, per build:** the binary's own model catalog fetch, `https://api.meta.ai/muse-code/models`, sends exactly **one `CONNECT api.meta.ai:443`**, exits **1** with a transport error on 502, and has no retry/second attempt or non-loopback socket. This is reported for **1.4.1-R4503.1**, with **1.4.2-R4684.1 explicitly identical**. With proxy at `127.0.0.1:9`, each build exits **1**, with zero sink requests/sockets and the plain transport error. This verifies the catalog path, not completion of a model turn.
- **R6 unreachable-proxy closure, per build:** the later message calibrates the SIGKILL detector: `nc` to `1.1.1.1:443` and direct `curl` to `api.meta.ai` exit **137**; `curl` through the dead proxy exits **7**; loopback is unaffected. **1.4.1-R4503.1 rc 1, no SIGKILL; 1.4.2-R4684.1 rc 1, no SIGKILL**, both with the proxy at `127.0.0.1:9`. the integration owner therefore closes R6 as no direct fallback attempt on this path, superseding the results file's initial detector limitation. These imported controls add no SIGKILL measurements to R0–R5 or hooks.
- **Exclusion:** control-plane bridges are excluded from the adapter and configure their own transport explicitly (N11).
- **Placement / owner:** the adapter lives in the launch plane's Muse plugin, **Muse adapter**, after D4 (**typed launch-plane hook (D4)**). Shared MCP config is never rewritten.
- **Open gap:** R7b, shell/tool children, was not reachable offline. Track R7b shell/tool-child verification and the integration owner **R7b shell/tool-child verification**, blocked on the session-host owner's PTY support. D8 = (A) retains this gap explicitly.

### 2.2 task-board spawn and runner: `skill-project-management`

**Lands in:** N-C1a explicit subagent selection / N-C2 defaults. Per **operator decision, 2026-10-02 07:21Z**, N-C1 integration is split into **N-C1a**, subagent spawn, needing **typed launch-plane hook (D4) + v0.2.0 only**, and **N-C1b**, session hosts, after **M3 / LP Phase 0** (§2.3). Network-profile consumers get priority after the operator's higher-priority items; N-B is the launcher milestone. `--network <name>` selects an id with explicit origin; later `runtimes.toml network` and `spawn.network.default` supply defaults. The detached runner inherits the orchestrator env (R/runtime.go:4764–4766); it is the destination host responsible for child unsets.

- **Preparation/application — advice §2.2(1), partly accepted:** “also serves the dry run” is correct; “does no I/O” is not (B/internal/spawn/launch_plan.go:202 calls catalog-reading `localModelsPeek`). Resolve/validate after slot claim (R/runtime.go:1905), then prepare, persist Record and refresh patch before every attempt at :2024. Carry only an ephemeral Config `EnvPatch` (`json:"-"`) to the composer. Apply last after `RuntimeControlEnvironment`, before B/internal/spawn/launch_plan.go:488, updating owned literals too. Real `planCommand` (spawn.go:1063–1071) and dry-run `BuildArgs` (:1414, call :1418) share it; plans skip probes. The launch-plane owner lands final application through D4; N-C1a no longer waits for M2/M3 (operator decision). Other runner/cmd changes stay outside that zone. Earlier `/goal` probes (B/cmd/spawn.go:2343 → cmd/spawn_runtime.go:850–870) need resolution/patching **before their own spawn**, then freshness checks after the slot. A future BuildPlan hook replaces the final call only under §1's overlay proof.
- **Manifest/rollback — advice §2.2(4):** “old binaries drop unknown keys silently” (R/runtime.go:4870–4875). Add Record beside `runtime_provenance` (:337; manifest :325–436), copy through `newSpawnRunManifest` (:803,840), `spawnConfigFromManifest` (:3205–3259), and `cloneSpawnRunSuccessor` (R/directives.go:743,892–979). `NetworkAccess` (:403) remains the codex sandbox flag. Require implementation round-trip coverage across all three paths and prohibit rollback of profiled runs to unaware binaries: they lose managed provenance and inherit ambient routing; a schema field cannot protect an old decoder.
- **Suites — advice §2.2(3):** “Make both paths build the env the same way.” Do not apply harness patches to validation suites; share suite-environment construction. R/changerequest.go:271 → B/internal/changerequest/validation.go:189 strips selectors; B/internal/integration/validation.go:423 does not. Neither strips proxies, so different egress is possible, not inevitable. Inherited-route evidence is decided (operator decision D5): suite evidence records the route as ref and digest, or `ambient`, never proxy values. Keep raw-environment integration milestone within its existing scope.
- **Control plane — advice §2.2(2), subsidiary claim REJECTED:** “The runner's own HTTP to board-server also picks up that proxy”. B/internal/remote/client.go:87–95 installs an explicit `http.Transport` with nil `Proxy`; that client does not consult inherited proxy variables. Preserve this separation and explicitly configured helper transports (N11).
- **Managed goal launches** (B/cmd/codex_goal_spawn.go:152) carry a selector envelope to the session host, which resolves and applies locally (§2.3); never send an endpoint or source-host patch.

#### Inherited selection: Q2

**Decided (operator decision D2): option (a), inherited origin; N3/N4 amended before N-C1.** Advice §2.2(2), “an inherited binding is a mandatory default”, identifies real leakage: an empty patch under a profiled parent retains ambient proxies without provenance. Use durable reference inheritance, not a new ambient `TASK_BOARD_NETWORK` contract or inference from proxy values. Advice Q2, “Use the existing plumbing”, needs qualification: existing goal lookup (B/cmd/spawn_goal_launch.go:70–90) loads state/goal, is queued-only (cmd/spawn.go:1679–1685), and returns nil for non-goal parents (cmd/spawn_goal_launch.go:129–131).

Persist **parent identity plus resolved reference** during reservation (B/cmd/spawn.go:2804); restore through `QueuedPreparation` (:3089–3127), and copy through R/runtime.go:3205, R/limit_retry.go:413 and R/directives.go:870–979. Review fan-out re-enters the pipeline (B/cmd/spawn_review_fanout.go:180). Retries bypass parent lookup (R/runtime.go:2021–2063): rebuild managed retry envelopes (R/limit_retry.go:447,524,575) and rebind successor envelopes (R/directives.go:875). Validate manifest/control identity and allowed sets; mutable `TASK_BOARD_RUN_ID` alone is not authorization (A/pkg/agentic/runcontext.go:31–44 is vendored at v0.5.30, B/go.mod:10).

Primary sessions require authenticated session-record lookup or explicit child selection; ambient session markers alone do not authorize inheritance. Non-board profiled parents need an explicit carrier contract too. Use `Request.Inherited` and `OriginInherited`, with precedence **explicit → inherited → runtime-default → profile-binding → project-default → operator-default**; N3/N4 and Record's closed origin vocabulary now include `inherited`. The library never discovers the reference from the environment. Origin and transport are independent. A parent on A can explicitly select B for a child, subject to host authorization.

#### Retry and recovery: Q3

**Decided (operator decision D1):** advice Q3, “Do not return it as a launch error”. Resolve unknown/denied first; changed digest is terminal `network_profile_drift` before each attempt, queue release, successor launch and managed retry preflight. Ordinary launch errors enter recovery (R/runtime.go:2086–2099), so drift must bypass it. Preserve reference/digest/assurance across provider reselection; deliberately changed adapters get new attempt Records only with unchanged digest. Add a retry-specific check: ordinary `CheckReattach` rejects adapter changes (N/pkg/binding/binding.go:165–174). Recovery/resume still uses full event-appropriate equality.

#### Explicit direct

**Decided (operator decision D3): option (b), v0.2.0, named `kind = "direct"`.** A profiled parent can choose its own profile, another profile, or a named direct profile for any child, as an external decision module chooses. Direct is one more profile id in the host's allowed set; it retains the actual reference and origin. Absence remains unmanaged and preserves ambient env.

A direct profile forbids endpoint, bypass hosts and probe target, needs confirmation like every widening entry, and has a canonical digest of schema + kind + credential mode. Its patch is unset-only; its managed Record retains ref, digest, cooperative assurance and skipped TCP/CONNECT/TLS probes. Host authorization and confirmation still apply. Direct does not guarantee OS-level directness (N11). Binding equality and drift rules are unchanged.

### 2.3 the session host: `skill-project-management`

**Lands in:** N-C1b (N-C1 integration), after M3 / LP Phase 0 (operator decision). Hosts build from daemon `os.Environ()` (H/codex_host.go:161–187,261–268; claude_host.go:700–727,2427–2450). Apply one shared helper **last** to `command.Env`, after TMPDIR at codex :178–179 and claude :710–711.

- **Carrier — advice §2.3(2):** “Send the ref, the origin and the expected digest”. Use that credential-free selector envelope in `OwnerRunContext` (H/launch_plan.go:123–136) and `PrimarySessionLaunchPlan` / `CodexSessionLaunch` (:74–86,138). The daemon re-resolves against its own catalog, confirmations, allowed set and verified tuple, checks the expected digest and uses §1's preflight branch locally: no probe for direct or plans/dry runs (all three steps `skipped`); otherwise probe. Strict decoders (:172,189,441; claude_host.go:426) fail closed. Bump `controlProtocolVersion` from 8 (H/types.go:31) and use client.go:71–100 restart diagnostics.
- **Record/reuse — advice §2.3(1):** the live-host check was already proposed; add startup reconciliation too. Store Record in `ProviderHostRecord.Opaque` snapshots (H/claude_host.go:840; codex_host.go:336). Check before all `ensureHostLocked` paths (H/manager.go:1584): live fast path :1589–1604, Restore :1625, Launch :1678–1690; also before `restoreAndReconcileLocked` calls Restore at :1981 (:1964–1981). Existing unmanaged hosts refuse profiled assignments. Stop-only Restore paths (:918,2035) remain usable.
- **Q4 — decided (operator decision D1):** advice Q4, “the session host starts one app-server per session”. Fresh sessions get independent bindings (H/manager.go:1589,1751; codex_host.go:341); the legacy B/cmd/codex.go:189–252 shares an app-server. First-release live-host attach/restore requires equal binding or refusal; existing-run Restore is `EventReattach`, not automatically `EventNewAssignment`, so drift and full equality apply.
- **Daemon startup — advice §2.3(3):** refuse startup from an identified profiled run **before stripping its identity**. B/cmd/session.go:591–592,653–673 strips run ids, not proxies; H/detached_launch.go:72–76 retains the starter env. Blanket stripping ordinary operator proxies would break unmanaged compatibility. Each managed session still patches last.
- **Auxiliary harnesses — advice §2.3(4):** “must use the session's patch.” Pass the same resolved session context to Claude preflight (H/claude_host.go:2416–2420) and assay (claude_context_assay.go:580–582); refusals stop those subprocesses too. Audit codex context (codex_context.go:1376–1382), legacy codex (B/cmd/codex.go:189,238–252), visible clients (:431–436; cmd/codex_manager.go:270–272), Claude goal probe (B/internal/spawn/claude_goal.go:94–123) and Antigravity preflight (agy_preflight.go:90). Every exec must apply the session context or have evidence it is outside harness routing.

Also audit launcher release probes (L/cmd/curator-run/main.go:334,353 → A/internal/toolprobe), engine-status subprocess (A/pkg/localruntime/client.go:54) and the daemon intermediate above. Version probes need evidence of no network work or their resolved patch. Preparation/composition subprocesses (B/cmd/claude_manager.go:230, codex_manager.go:215; L/internal/fragment/resolve.go:98) remain outside harness routing (N5); `curator network exec` follows the same final application rule.

### 2.4 curator-run: `curator-agent-launcher`

**Lands in:** N-B. The Curator and launcher owners coordinate N-B; the launcher owner leads its implementation; consumer representatives advise. Ownership is unchanged (operator decisions).

- Add `--network <name>` to L/internal/cli/cli.go `Invocation` (:162–195), `valueFlags` (:223–231), and SPEC §3; accept identifiers, not URLs.
- Resolve/validate after admitted `plan.Build` (L/cmd/curator-run/main.go:255), before `ComposeAdmittedPlan` (:288), using the original operator env. Probe only a real supported launch in untracked mode using a proxy profile; `kind = "direct"` skips probes. Refusals stop launch without fallback; tracked managed selection refuses before a source-host probe.
- In `Compose`, after all overlays (:91–110), before materializing Env (L/internal/composition/composition.go:113), delete unset names case-insensitively from both env and literals, add set to both, reject managed proxy EnvNames/overlays, and recheck disjointness. Direct exec uses the patched env (L/internal/execution/execution.go:154); emit sanitized Record provenance.
- Tracked mode carries only set literals and a proposed `works.relux.curator.network` Record extension (execution.go:52–58). **Refuse every managed tracked selection, including defaults, with `network_scope_unsupported` until §2.5's destination capability exists** (N9). No fallback or silent loss of tracking. Curator preparation (env resolve/install/repair) remains outside this patch (N5).

### 2.5 ax launch plan and session host

**Q5 — D6 DEFERRED, Ivan, 2026-10-02 05:36Z:** deferred until ax implements session launch. The destination session-launch capability (ax) milestone tracks carrier options, destination duties and refusal until then. Tracked `--network` keeps refusing (N9). Keep the Record extension (S/decisions/0013-execution-ownership-and-launch-plans.md:208–213), but require a negotiated, versioned network capability at the destination. Ax implementation owners enforce it; session-host owners own any bridge. X/README.md:5–7 is specification-only; ax proper (§5.1/§14.1) is absent from the supplied clones. Extension preservation alone proves no enforcement.

The destination resolves/authorizes locally, compares expected digest and verifies its adapter tuple. It uses §1's preflight branch: direct or plans/dry runs skip all three steps; only real proxy launches probe. It applies the patch to its final env (direct unsets only, with no set; proxy unsets then applies fresh set) and persists Record. Audit start/resume/fork/re-adoption; reject unsupported schemas or unaware hosts. Suppress conflicting old proxy literals before fresh application: 0013:304–313 otherwise replays them verbatim. Resume drift refuses `network_profile_drift` (environment-drift precedent :635–645); attach/resume uses full equality.

Set literals are non-secret and disjoint from `env_names` (0013:193–206). Canonical proxy spellings are reserved (C/internal/contextpkg/contextpkg.go:427; S/schemas/v1/agent-mcp-v1.schema.json:59); consumers must reject **mixed-case** proxy names too. N9 stays closed until destination conformance proves these rules.

### 2.6 Curator umbrella and trust

`curator network …` dispatches to `curator-network` (C/cmd/curator/umbrella.go:120; S/protocol/environments.md §11, :3377). Distinguish revision A, PATH selection with an outside-roots warning, from revision B, roots-only selection (:3414–3420). No provider-selection flags are required; N-A implements `--json` and a real `--version`. Provider installs follow the provider-installation milestones in curator-spec and curator.

Presence-key signing for `confirm` (curator-trust §10) is not available. N-A already implements a local digest-bound confirmations ledger and agent-session refusal; its interim policy remains TODO(decision) in the implemented appendix/API. When curator-trust lands, replace the ledger with the trust store.

## 3. Ownership and order

| Piece | Owner role / repository | Milestone | Depends on |
| --- | --- | --- | --- |
| library, provider, appendix | library owner / this repo | N-A, landed slice A | none |
| typed launch-plane hook (§2.1), D4 | launch-plane owner / skill-agents-management | optional N-B migration / N-C1a | N-A tag (D10); environment decision under adopted Decision 0019 |
| Muse `muse-env-v1` adapter | launch-plane owner / skill-agents-management, Muse plugin | D8 = (A) (§2.1) | D4 |
| direct `curator run --network` | launcher owner / curator-agent-launcher | N-B | N-A tag; Compose-first allowed; remove final Compose patch only after overlay/parity proof |
| tracked network | launcher + ax implementation owners; session-host bridge owner | D6 deferred until ax session launch | after N-B; destination unset, resolution, drift and negotiated capability; tracked selection keeps refusing (N9), destination session-launch capability (ax) |
| task-board subagent spawn / runner, N-C1 | spawn-runtime owner / skill-project-management | N-C1a | D4 + v0.2.0 only (operator decision); inherited N3/N4 amendment (D2) included in v0.2.0 |
| session hosts, N-C1 | session-plane owner / skill-project-management | N-C1b | M3 / LP Phase 0 (operator decision) |
| runtime/project/operator defaults | selection + launch-plane owners | N-C2 | M4 operator layer and bindings catalog |
| trust-store confirm | trust owner / curator-trust | after N-A | curator-trust §10 |
| managed gateway | library/gateway owner / this repo | N-D | N-A; no N-B/C dependency |

Consume the library **by tag**, never `replace` or `go.work`; `v0.2.0` is the first public release; v0.1.0 is retired (operator decision, 2026-10-02). Before adopting v0.2.0, follow [the migration requirements](../README.md#upgrading-to-v020): upgrade every catalog reader before adding direct, remove direct entries before downgrading, use keyed `resolve.Request` literals, admit `inherited` origins and allow the additive `check --json` `kind` field. The contract schema strings remain v1 for these pre-1.0 additive vocabulary changes. **Q6 — decided (operator decision D7):** role-based ownership stays unchanged; the Curator and launcher owners coordinate N-B; the launcher owner leads its implementation; consumer representatives advise (operator decisions).

## 4. Invariants every consumer keeps

1. Apply last on the process-creating host, to final child env; never `os.Setenv`, shell profiles, shared tmux env, user settings or system proxy.
2. Set values are owned non-secret literals; proxy names never travel as env_names, including mixed case.
3. Selection carries an authorized id, never a proxy URL; resolve locally and never infer a ref from ambient proxy values.
4. Refusals stop workload spawn/preflight. No hidden fallback to direct, another profile/account or automatic recovery on drift; mid-run drops go to the run owner.
5. Manifests/logs keep Record only, never Binding/Patch, env, credentials, endpoints or request bodies.
6. Control-plane helpers (stdio MCP, Apiary bridge, board-server client) configure transport explicitly, outside inherited harness proxies (N11).
7. No selection preserves today's unmanaged behavior exactly. It does not guarantee direct egress or authorize opting out of inherited selection.

## 5. Decision card after advice

Rev 2 is adopted as D1. Consumer implementation remains DRAFT; the following decisions are recorded from operator decision and Ivan's 2026-10-02 updates via the integration owner:

| Item | Status / outcome |
| --- | --- |
| D1 | decided (operator decision D1): integration contract rev 2 ADOPTED; DRAFT until implemented by consumers |
| Inheritance and selection precedence | Adopted: `inherited` origin; durable reference plus re-resolution on the child's host; explicit → inherited → runtime-default → profile-binding → project-default → operator-default, subject to host locks / allowed set |
| D3 / explicit direct | decided (operator decision D3, 2026-10-02 05:26Z): option (b), named `kind = "direct"`, shipped in v0.2.0 (§2.2) |
| D4 / Q1 | decided (operator decision D4): typed `Network{Patch, Record}` fields, not callbacks (§2.1) |
| D5 / suites | decided (operator decision D5): evidence records route ref and digest, or `ambient`, never proxy values (§2.2) |
| D6 / Q5 | DEFERRED (Ivan, 2026-10-02 05:36Z) until ax implements session launch; tracked `--network` keeps refusing (N9); destination session-launch capability (§2.5) |
| D7 / Q6 | decided (operator decision D7): role-based ownership unchanged (§3) |
| D8 / Q7 | decided (A) (Ivan, 2026-10-02 05:44Z): Muse 1.4.1-R4503.1 and 1.4.2-R4684.1 SUPPORTED with `muse-env-v1`; R7b shell/tool-child gap remains tracked in R7b shell/tool-child verification (§2.1) |
| D9 | decided (operator decision D9): Decision 0019 adopted-status erratum fixed in both language specs and README |
| D10 | decided (operator decision D10): v0.2.0 is the first public release; v0.1.0 is retired; consumers use tags (§3) |

Q3 terminal retry drift and Q4 independent fresh sessions / equal-or-refuse live hosts are part of adopted rev 2 (D1).

### Changes in rev 2

- Corrected/pinned drifted anchors and added exec audits; Decision 0019 is adopted, with environment ownership still open (§1/§2.1–§2.6).
- Moved preparation/persistence to the runner, covered early probes, durable inheritance and terminal retries; qualified existing plumbing and rejected the board-client HTTP proxy claim with nil-Proxy evidence (advice §2.2(1–2), Q2–Q3).
- Added suite separation/evidence decision and rollback/round-trip requirements; retained normalized credential refusal and Record-only serialization (advice §2.2(3–5)).
- Added reconciliation, local selector resolution/protocol bump, profiled-startup refusal and session-patched preflight/assay; corrected the fresh-session premise (advice §2.3(1–4), Q4).
- Replaced unanswered questions with the recommendations adopted by operator decision, 2026-10-02, initially deferred explicit direct (superseded by D3 below), corrected mixed-case reservation, trust dispatch, N-A status, overlay migration and N-D dependency; replaced the ownership-transfer assumption with unchanged role ownership (Q1, Q5–Q7).
- Recorded adoption and decisions operator decision D1, D2, D4, D5, D7–D10 on 2026-10-02; subsequent D6 and D8 outcomes are recorded below.
- Recorded D3 decided option (b), named direct shipped in v0.2.0 (2026-10-02 05:26Z).
- Recorded D6 deferred until ax session launch (05:36Z), destination session-launch capability (ax) and continued tracked-mode refusal (N9).
- Recorded D8 = (A) (05:44Z): both exact Muse builds supported with `muse-env-v1`, per-server MCP env injection and hook-command wrapping; acceptance rows and calibrated SIGKILL evidence; N11 exclusions, Muse-plugin ownership and the open R7b gap (R7b shell/tool-child verification).
- Split N-C1 into N-C1a (D4 + v0.2.0 only) and N-C1b (after M3 / LP Phase 0), per operator decision (07:21Z); recorded N-C1, N-B and D4 milestone names and consumer priority after the operator's higher-priority items.
