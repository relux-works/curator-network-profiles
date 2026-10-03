# Local agent network profiles: specification

Status: **DRAFT** (decided design, pre-implementation). Written 2026-09-22 from the proposal "самостоятельный эпик локальных сетевых профилей" and its enriched copy, which the operator keeps as Russian working notes outside the repositories, aligned with `skill-project-management/.specs/drafts/launch-profiles.md` (referenced below as *LP*, decisions LP-D1…D16). Working names are marked *proposed*. Facts marked *docs-confidence* were not verified on installed binaries and become errata before goldens.

> **Notes 2026-09-23.** Sequenced as roadmap milestone M7, after agents-infra is archived (`spec/track.md`). The library gets its own public repository `curator-network-profiles`. Defaults come from the operator layer of agent selection (`skill-project-management/.specs/drafts/agent-selection.md`) in addition to runtime bindings and the project. The patch reaches argv and env through the agents-management module (adopted Decision 0019).

> **Notes 2026-09-27 (the command-line shape).** The operator adopted one command-line shape for the ecosystem (`command-line shape decision, 2026-09-27`). For this module:
> - the flag is `--network <name>` everywhere (was `--network-profile`);
> - the operator file is `~/.curator/network.toml` (was `$XDG_CONFIG_HOME/curator-network-profiles/network.json`; moved by curator-playbook `spec/process-configuration.md` §2.3);
> - the proposed `netrun` wrapper becomes the Curator provider `curator-network`: `curator network list|show|add|remove|check [--probe]|confirm|exec <name> -- <command>`;
> - adding a network profile is a widening entry, confirmed with `curator network confirm`;
> - a runtime binding's key is `network` (was `network_profile`);
> - the prose keeps "network profile", and the bare word `profile` names only the Curator profile.
>
> §7 is the change log.

---

## 0. Goal

Several native harnesses run on one machine at the same time. Each launch must reach the network through its own application-level proxy, without changing the orchestrator, sibling agents or the operating system:

```text
codex A  ─► proxy :18081 ─► VPN / upstream A
claude B ─► proxy :18082 ─► VPN / upstream B
pi C     ─► proxy :18081 ─► VPN / upstream A
orchestrator and everything else ─► the machine's ordinary network
```

The launch keeps its environment, credentials, runtime binding, model and working directory; the network profile changes only how supported connections are made. The first release is **cooperative proxy routing of supported clients**, not enforced isolation of a process tree, so it is called *network profiles*, never *network sandbox*. A later enforced sandbox reuses the same profile as its egress description.

---

## 1. Platform facts (verified unless marked)

| Fact | Where |
| --- | --- |
| Three process owners exist and each starts harness processes from values it composes: `curator-run` (interactive), task-board `internal/spawn` (tracked children), the session host (board primary sessions, codex app-server host, claude PTY) | LP §3.3, LP-D5, LP-D6 |
| `curator-run` composes plan argv → prompt flags → MCP flags → native tail and applies the four environment layers; its tracked transport carries only owned literals, `env_names`, `argv_suffix`, stdin | launcher README "Environment and transport"; SPEC 0.4.0-draft §4.5–4.6 |
| Module plugins filter the child environment: codex strips eleven exact keys (`CODEX_*`, task-board endpoint pointers) and sanitizes `PATH`; claude strips only `CLAUDECODE`; pi passes the parent env through | module `internal/runtimeenv`, `systems/claude/env.go`, `systems/pi/env.go` |
| ax launch-plan request: `env_literals` (values) and `env_names` (destination-local lookups); a name that also appears in literals is dropped from the allowlist with a warning | ax spec §14.1; curator-spec Decision 0013 D6.3 |
| Claude Code documents `HTTP_PROXY`/`HTTPS_PROXY` (and `NO_PROXY`) and does not support SOCKS; background agents are served by a shared per-user supervisor that may keep the environment of the first shell that started it | Claude Code docs (docs-confidence for the supervisor detail) |
| OpenCode documents proxy env and the need to bypass the proxy for its local TUI server | opencode docs (docs-confidence) |
| Codex websocket dialer handles standard proxy env and proxy routes | codex source read (docs-confidence for the installed build) |
| `curl` reads lowercase `http_proxy` only; `NO_PROXY=*` disables proxying; clients disagree on case and precedence | curl docs |
| Local engines under `curator-inference-manager` listen on loopback; Direct has no proxy and nothing to bypass, so its engine-host coverage check does not apply. SSH-mode engine profiles connect to remote boxes by their own channel | LP-D7, LP-D8; agents-infra `model-harness` `mode = local\|ssh` |

---

## 2. Decisions

### N1 Five independent launch settings

| Setting | Decides | Owner |
| --- | --- | --- |
| Environment profile (Curator) | context, home, skills, MCP, account boundary | Curator |
| Credential selection | which login the home uses (`shared`/`isolated`) | Curator |
| Runtime binding (LP-D1) | which harness reaches which provider or engine | task-board config + module catalog |
| **Network profile** | through which application proxy supported connections go | `curator-network-profiles` + the process owner |
| Execution profile | where and under which limits tools run | execution environment |

The network module never copies logins, changes provider homes, chooses an account or resets quota accounting; a different route is never a new quota domain. CLI vocabulary follows the command-line shape of 2026-09-27, which replaces LP-D12's: `--runtime <id>` (alias `--agent`) for the binding, `--profile <name>` for the Curator profile in task-board and `curator run` alike, and **`--network <name>`** for the network profile. The bare word `profile` means only the Curator profile; a network profile is never selected with `--profile`.

### N2 One library, three process owners

A Go module named **`curator-network-profiles`** (name decided on 2026-09-24): `resolve → validate → conditional probe → patch` (direct and plans/dry runs skip all probes). It imports neither task-board, nor `curator-model-router`, nor ax storage; those are its callers. It creates no processes and owns no daemon.

Every process owner applies the binding immediately before spawn on every process-creation path it owns: `curator-run` (interactive), task-board `internal/spawn` (children, retries, recursive worker launches, resume), the session host (primary sessions, including the codex app-server host and claude PTY host, at launch and at resume). `curator-inference-manager` is a fourth process owner whose processes are engines, not harnesses: engine networking is out of this epic (N12).

### N3 Data model

`NetworkSelection` (what the caller asked): `profile_ref`, `origin ∈ {explicit, inherited, runtime-default, project-default, operator-default}`, `required_assurance ∈ {cooperative, enforced}`.

`inherited` means the process owner supplies the parent's resolved reference persisted at reservation, for fresh resolution on the child's host; the library never discovers it from the environment or proxy values.

`NetworkProfile` (what the machine has), operator-owned file `~/.curator/network.toml`, one machine-owned catalog per plane, kept with the operator's other files under `~/.curator/`; the launcher and task-board never keep two copies. It was proposed as `$XDG_CONFIG_HOME/curator-network-profiles/network.json`; curator-playbook `spec/process-configuration.md` §2.3 moved it, in TOML because people edit it by hand. The table name `networks` is *proposed*: the word `profile` names only the Curator profile.

```toml
schema = "relux-network-profiles-v1"

[networks.egress-a]
kind         = "external-http-proxy"
endpoint     = "http://127.0.0.1:18081"
bypass_hosts = ["localhost", "127.0.0.1", "::1"]

[networks.egress-b]
kind         = "external-http-proxy"
endpoint     = "http://127.0.0.1:18082"
bypass_hosts = ["localhost", "127.0.0.1", "::1"]
```

Kinds are `external-http-proxy` and `direct`. A named `kind = "direct"` profile has no `endpoint`, `bypass_hosts` or `probe_target`; these keys MUST be refused if present, even empty.

```toml
[networks.direct]
kind = "direct"
```

The file is edited through `curator network add|remove` or by hand. Adding or changing any network profile, including direct, is a widening entry, because it reroutes traffic: it takes effect only after `curator network confirm`, which refuses to run in an agent session (relux-works/curator-trust `spec/trust.md` §10).

`NetworkBinding` (what is applied): `profile_ref`, `profile_digest`, `adapter_identity` (harness build + entrypoint + plugin), `resolved_endpoint`, `assurance`, `env_patch`; later `lease_id`, `generation` for a managed gateway. Run manifests keep `profile_ref`, `profile_digest`, `adapter_identity`, `assurance` and the probe result; never the full environment or an endpoint carrying credentials. A digest binds the configuration, not the external proxy's actual egress.

`env_patch` is two ordered operations, `unset` then `set`: `unset` removes every proxy-family variable the adapter knows, in both spellings, from the environment of the host that creates the process, and `set` writes the coherent proxy set of N5 (empty for direct); a patch is never only additions. `profile_digest` is computed over the normalized effective profile (schema version, kind, endpoint, sorted `bypass_hosts`, credential *mode* without any secret; direct includes only schema, kind and credential mode), never over probe results, lease ids or timestamps. Two bindings are **equal** when `profile_digest`, `adapter_identity` and `assurance` are equal; an equal profile name proves nothing.

A `runtimes.toml` entry (LP-D2) MAY carry `network = "<name>"` as the default for that binding, and project configuration MAY carry `spawn.network.default = "<name>"` (decided 2026-09-22 after review): both are stable profile ids resolved on each machine and refused as `network_profile_unknown` where the machine has no such profile. An explicit `--network` overrides both.

### N4 Precedence and assurance

Host locks and the allowed profile set → explicit selection → inherited selection → runtime-binding default → project default → operator default (the machine's own default entry in `network.toml`). No selection at all keeps today's behaviour, reported as `unmanaged`, never as "direct". An explicit choice of a named direct profile is managed, authorized through the allowed set, confirmed, and recorded with its actual `profile_ref` and digest. A request for `enforced` on a machine that only has a cooperative backend is refused; the first release publishes `assurance = cooperative`.

### N5 Applying the patch without side effects

The patch goes into the child's private environment only. Never `os.Setenv`, shell profiles, the system proxy, a shared tmux environment or a user `settings.json` rewrite. Order: remove every conflicting inherited proxy variable, then set the coherent set:

```text
HTTP_PROXY=<endpoint>   HTTPS_PROXY=<endpoint>
http_proxy=<endpoint>   https_proxy=<endpoint>
NO_PROXY=<bypass list>  no_proxy=<bypass list>
```

For `direct`, the patch is **unset-only**: remove the same proxy family case-insensitively and set nothing. A direct child sees no inherited proxy variables; unmanaged retains the ambient environment.

`ALL_PROXY`, websocket-specific variables and runtime settings are added only by the harness adapter in the module once verified; nothing sets a dozen variables on faith. If native tool settings override env, the adapter applies a supported per-launch override or refuses `network_configuration_conflict`; it never rewrites shared configuration. Proxy variables are **owned literals** of the process owner, exactly like `ANTHROPIC_BASE_URL` in the claude `env-bundle` transport (LP-D3); in the ax document they travel as `env_literals`, never `env_names`. Curator's own preparation (`curator env resolve`, install, repair) is not proxied by default; proxying preparation is a separate explicit requirement.

### N6 Gateway shape

Common surface: **HTTP proxy with CONNECT**, because Claude Code supports HTTP/HTTPS proxy env and not SOCKS. Behind it: an upstream HTTP proxy, a SOCKS upstream, or a WireGuard endpoint. First managed backend candidate: sing-box with a `mixed` loopback listener, `set_system_proxy: false`, no TUN, WireGuard without a system interface, pinned to a supported version. In slice A the gateway is operator-configured; the library only reads the profile and probes proxy endpoints (direct skips probing), and the process owner or `curator network exec` launches. This is a network tunnel, not an LLM gateway: model API, prompts, model ids and credentials are untouched; TLS verification stays on; corporate TLS inspection is a separate explicit mode.

### N7 Harness support is per launch shape

Support is verified for the tuple `harness build + entrypoint + adapter + configuration profile`, not for "claude in general". The MVP supports a **fresh harness process per launch**. Attaching to an already running app-server or daemon is allowed only when its binding equals the request or the adapter can set the route per session; otherwise `network_scope_unsupported`. Claude `--bg` through the shared supervisor is explicitly unsupported. the session host checks binding equality for its hosts at launch and at resume. Two events are distinguished: a **new assignment** placed on an already running host, and a **reattach or resume** of an existing run. The transitions are fixed:

| Event | Situation | Outcome |
| --- | --- | --- |
| new launch | fresh process | resolve, bind, launch |
| new assignment on a running host | host binding equal (N3) to the resolved one | attach |
| new assignment on a running host | binding differs, adapter can set the route per session | set per session, record the binding |
| new assignment on a running host | binding differs, no per-session route | refuse `network_scope_unsupported` |
| reattach or resume of an existing run | recorded binding equals the fresh resolution | reattach / resume |
| reattach or resume of an existing run | same profile name, different digest | refuse `network_profile_drift`; per-session re-routing is not a workaround; the operator restores the profile or starts a new launch |
| reattach or resume of an existing run | profile missing or denied | `network_profile_unknown` / `network_profile_denied` |

A session-level "change network profile" operation is not in the MVP; it arrives with gateway generations (N14). New harness paths that enter the matrix as they land: exec-mode `pi-native` (LP-D8) and the opencode plugin (LP-D3); the matrix is re-run on every pinned tool release.

### N8 Integration surfaces

- `curator run <runtime> --profile <p> --network egress-a -- <args>`: resolve, validate compatibility, bounded preflight for proxy profiles only, patch after the ordinary environment composition; admission and late checks unchanged.
- `task-board spawn … --network egress-a` and `spawn.network.default` / per-binding `network`: the orchestrator selects a profile id from the allowed set, never a raw proxy URL. Inheritance by a child is **by reference plus re-resolution**, with `origin = inherited`, never by copying the orchestrator's environment; a parent on A may spawn a child on B.
- Manifests: beside `RuntimeProvenance` and the Curator `profile.name`/`lock_sha256` (LP-D11), `network.profile_ref`, `profile_digest`, `adapter_identity`, `assurance`.

### N9 Tracked sessions (ax)

The tracked transport serializes owned literals only, so a proxy set on the outermost process is not enough for a durable resume. The network reference and digest travel in a versioned contract. The actual process host resolves the binding immediately before spawn or resume and rebuilds the child environment from it. The `unset` half of the patch runs against the host's own inherited environment, so a conflicting variable present only on the host is removed there; the literals carried by the transport are the `set` half only. Until that exists, tracked mode with a mandatory network profile refuses; direct mode ships independently.

### N10 Lifecycle, checks, errors

`resolve → validate profile + adapter → conditional bounded proxy preflight → prepare binding → spawn → record outcome`. Direct and plans/dry runs skip preflight; their `ProbeRecord` tcp/connect/tls fields are `skipped`. No scheduler, no daemon registration, no lease model in slice A. `curator network show` and a plan are read-only; `curator network check` validates without a network call, and `check --probe` for proxy profiles is the explicit network call (the proposed `netrun doctor`); the launch preflight is deadline-bounded and uses no model credentials. Three distinct facts: an open TCP port; a successful CONNECT and TLS to the agreed target; an observed external IP for that test only. Failure codes: `network_profile_unknown`, `network_profile_denied`, `network_scope_unsupported`, `network_configuration_conflict`, `network_proxy_unreachable`, `network_proxy_auth_failed`, `network_profile_drift`. A missing, denied, unsupported or unreachable profile means the agent does not start; there is no hidden direct fallback and no automatic VPN or account switch; refusing to start is not an OS kill switch. A mid-run drop is reported to the run owner, who decides; nothing restarts the task unconditionally.

For direct, preflight and `check --probe` skip all three steps (`tcp`, `connect`, `tls` = `skipped`); no endpoint is dialed.

### N11 Coverage boundary and secrets

Direct is cooperative too: clearing proxy variables is not an OS guarantee of directness.

The profile applies to the harness's supported network clients, which may include auth refresh, HTTP MCP and other requests, not only inference. Child commands may inherit the variables but their compliance is client behaviour, not an OS guarantee. A helper process the harness starts (a stdio MCP server, a tool bridge) inherits the patch like any child. When such a process must reach a control plane by its own route, its outgoing client is configured explicitly, never from the inherited proxy variables. That way the harness's egress and the bridge's transport are verified together, and a failing inference proxy never takes the control channel down with it. Outside the guarantee: a separately opened OAuth browser, already running services, raw sockets and UDP, tools executing on a remote EnvironmentHost. Upstream proxy passwords and WireGuard keys live in the gateway; the agent receives a loopback endpoint. A loopback listener without client authentication is not isolation between local processes. Logs record run/attempt, profile id, digest, adapter/build, probe result; never raw env, tokens, `Authorization`, `Proxy-Authorization` or request bodies.

### N12 Engines

Local `curator-inference-manager` endpoints are loopback and MUST appear in every proxy profile's `bypass_hosts`, otherwise a harness reaches its local model through the proxy. SSH-mode engine profiles connect through the engine provider's own channel and are not covered by the harness's proxy env. A future enforced sandbox treats a loopback engine as a local service to be allowed explicitly, not as "the internet".

### N13 Routing

`curator-model-router` decides what to launch; `curator-network-profiles` decides which allowed route it connects through. The router may treat compatibility with a mandatory network profile as a constraint and never switches VPNs, credentials or quota domains. A runtime binding whose catalog default names another profile is not a route switch performed by the router. Before scoring, the caller's CandidateResolver resolves every candidate's dependent settings (network profile, Curator profile, home) by the N4 precedence. It fixes an explicitly requested profile across all candidates and excludes a candidate whose resolved value differs from a fixed one, unless the routing policy's free-field mask frees that member (routing spec R7). That resolution is a lookup, never a proxy probe; the N10 preflight stays a separate launch step. A network failure is not evidence about model quality and never lowers a coding score. The assessor backend has explicitly assigned credentials, egress and data policy of its own.

### N14 Future: managed gateway

Adds `acquire / inspect / release`; the lease belongs to the owner of the actual runtime, not to a short-lived launcher that handed the session on; one agent finishing must not stop the others' proxy; a configuration change creates a new gateway generation and never moves active sessions silently. The enforced execution sandbox is a separate epic and reuses the profile as its egress description.

---

## 3. Phases and acceptance

| Slice | Delivers | Value |
| --- | --- | --- |
| A. Common mechanism | profile schema and file, resolver, `EnvPatch`, external HTTP proxy backend, and the Curator provider `curator-network`: `curator network exec <name> -- <cmd>`, `check [--probe]`, `list`, `show`, `add`, `remove`, `confirm` (replacing the proposed `netrun --profile X -- <cmd>` and `netrun doctor X`) | independent manual launches without global `export` |
| B. Launcher | `curator run --network`, verified entrypoints, manifests | environment + network in one launch |
| C1. Orchestration, explicit profile | task-board `internal/spawn` and the session host on every real process-creation path (spawn, retry, resume, recursive children) with an explicit `--network`, run metadata | the orchestrator runs local sub-agents through different egresses |
| C2. Orchestration, defaults | per-binding defaults from `runtimes.toml`, the project default, their `origin` provenance | defaults without a flag on every spawn |
| D. Managed gateway | optional sing-box backend, runtime-owned leases, generations | automatic proxy/WireGuard provisioning |
| Separate epic | enforced execution sandbox | bypass prevention and isolation |

A does not wait for D; C does not wait for the remote pool, an own harness or a distributed journal. C1 waits for LP Phase 0 only where the session host composes its own plans (the patch has to land in that composer); C2 waits for LP Phase 1 (the catalog exists). The contract appendix of §5 is a deliverable of A.

Acceptance:

| Check | Expected |
| --- | --- |
| Parallelism | two processes of one harness use two egresses at once without touching the parent or siblings |
| Composition | lowercase/uppercase conflicts and ambient `NO_PROXY=*` never override an explicit profile |
| Compatibility | real HTTPS, streaming, the websocket in use and local service connections verified per entrypoint on pinned versions |
| Refusal | unknown/denied/unreachable/unsupported refuses before launch; no hidden direct fallback |
| Orchestration | the binding is applied in the actual child, including declared retry and resume paths |
| Credentials | the module changes no account and leaks no secret into configuration, manifests or logs |
| Compatibility with existing runs | launches without a selection behave as before; admission and terminal lifecycle are not bypassed |
| Honest assurance | `assurance = cooperative` is published; an `enforced` request cannot receive a cooperative launch |
| Engines | loopback engine endpoints are in the bypass list of every profile |
| Unset at the boundary | a conflicting proxy variable present only on the host that creates the child is absent from the child's environment |
| Binding equality | a reattach or resume of an existing run whose profile content changed under the same name is refused with `network_profile_drift`, never re-routed per session; a new assignment on a running host with a different binding is `network_scope_unsupported` unless the adapter routes per session |

---

## 4. Rules and non-goals

- Never `os.Setenv`, never a system proxy change, never a shared config rewrite; the patch lives in the child's environment.
- Never a raw proxy URL from the orchestrator; only profile ids from the allowed set.
- Never a hidden fallback to direct, to another VPN or to another account.
- Never proxy variables as `env_names`; they are owned literals.
- Not an LLM gateway, not a sandbox, not a VPN orchestrator, not a second process supervisor.

## 5. Contract appendix (deliverable of slice A)

A short appendix with test vectors, written with the code, fixes what this document only names:

| Area | What it defines |
| --- | --- |
| Profile digest | the normalized content (N3), canonical JSON with sorted keys and an explicit schema version, SHA-256 over those bytes |
| `EnvPatch` | the exact `unset` set and `set` set per adapter, both spellings, `ALL_PROXY` and websocket variables only where verified |
| Binding equality | the member list (N3) and what is excluded: probe time, lease, generation |
| Vectors | case conflicts, ambient `NO_PROXY=*`, a conflicting variable present only on the host, changed content under an unchanged name, a loopback engine in and out of the bypass list |

## 6. Closed decisions and remaining choices

Closed by this document: flag name `--network-profile`; file location pattern (`$XDG_CONFIG_HOME/curator-network-profiles/network.json`); HTTP CONNECT as the common surface; fresh process per launch in the MVP; Curator preparation not proxied by default; loopback engines in bypass. Added 2026-09-22 after the independent review: `spawn.network.default` accepted with the N4 precedence and `origin = project-default`; `EnvPatch` is `unset` then `set`, executed by the host that creates the process; binding equality is digest + adapter identity + assurance; a resume whose profile content changed is refused as `network_profile_drift`; dependent defaults are resolved by the caller before routing, never switched by the router; slice C is split into C1 (explicit profile) and C2 (defaults). After the second review: N7 distinguishes a new assignment on a running host from a reattach or resume of an existing run, and a helper process's own transport is configured explicitly (N11).

*Superseded on 2026-09-27 by the adopted command-line shape:* the flag is `--network`, the file is `~/.curator/network.toml`, and the proposed `netrun` is `curator network exec|check` (§7).

Remaining for the implementing session (record why when choosing): the first managed backend (sing-box is the candidate).

## 7. Change log

**2026-10-02 (operator decision).** D3 decided (b), v0.2.0: a named `kind = "direct"` with confirmation, an unset-only patch, managed Record and skipped probes (N3–N5, N10–N12). D2 decided (a): add `origin = inherited` for caller-supplied, persisted parent references re-resolved on the child's host, between explicit selection and runtime defaults (N3, N4, N8). D9 erratum: Decision 0019 is adopted, replacing the stale proposed status in the header notes.

**2026-09-27.** Applied the command-line shape the operator adopted on 2026-09-27 (`command-line shape decision, 2026-09-27`):

| Before | After | Where |
| --- | --- | --- |
| `--network-profile <name>` | `--network <name>` | N1, N3, N8, §3 |
| `--context-profile <name>` for the Curator profile in task-board | `--profile <name>`, in task-board and `curator run` alike; `--runtime <id>` with the alias `--agent` | N1 |
| `$XDG_CONFIG_HOME/curator-network-profiles/network.json`, object `profiles` | `~/.curator/network.toml`, tables `[networks.<name>]` (the table name proposed) | N3, N4, §6 |
| per-binding `network_profile` | per-binding `network` | N3, N8 |
| `netrun --profile X -- <cmd>`, `netrun doctor X` | the provider `curator-network`: `curator network exec <name> -- <cmd>`, `curator network check [--probe] <name>`, with `list`, `show`, `add`, `remove` and `confirm` | N6, N10, §3 |
| adding a profile took effect at once | adding a network profile is a widening entry confirmed with `curator network confirm` | N3 |
