# Integration contract: how the process owners apply a network profile

Status: **ADOPTED by Ivan 2026-10-02 (operator decision); DRAFT until implemented by the consumers** (rev 2, D1). Repository owners retain approval of implementation in their repositories.

Normative inputs: `spec/network-profiles.md` (N1–N14) and the implemented `spec/contract-appendix.md` (digest, EnvPatch, equality, Record and refusals). **The appendix wins on bytes.** The inherited-origin amendment (D2) is implemented in this library; consumer changes remain DRAFT until implemented.

Consumer repositories below are named by their public product names
(`skill-agents-management`, `skill-project-management`, `curator-agent-launcher`,
`curator-spec`, `curator`, `agent-session-host`). §2 states self-contained
interface and lifecycle obligations each process owner implements —
resolve and authorize on the destination, apply the patch last on every
process path, retain and compare the durable identity, refuse drift and
unsupported capabilities, and keep control-plane transport separate.

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
| bind / patch / record | admitted adapter tuple → Binding; direct unsets only (empty set), proxy unsets then sets final env; sanitized managed Record | no new refusal codes |
| reattach / resume | recorded Record, freshly resolved binding, event → full equality check | `network_profile_drift`, `network_scope_unsupported`; resolve's unknown/denied comes first |

These are conceptual stages, not separate public methods: `catalog.Load` and `Catalog.Resolve` perform catalog/ledger loading and validation. The appendix already implements the added file/profile codes, retaining their TODO(decision) labels. **Unmanaged means no selection, an empty patch and unchanged ambient routing; it does not mean direct.**

Apply the patch **after filtering and every overlay**, updating full Env and owned literals. For direct, unset the proxy family from both Env and owned literals and set nothing. A proxy patch's `set` half travels as `env_literals`, never `env_names` (N5; execution-ownership decision). Later overlays must refuse proxy-family names case-insensitively (`network_configuration_conflict`) when managed. Reapply the same patch after the final overlay if cleanliness cannot be proved; idempotence does not protect against later writes or different bindings.

Advice §2.2(5): “The `set` half can carry proxy userinfo.” Raw structs can, but normalized profiles refuse it. Only normalized, confirmed resolution may produce a patch; serialize **Record only**, never Binding/Patch, endpoint or env. Owned literals are recorded/replayed and must be non-secret. V1 permits credential mode `none`; future secrets stay in a gateway, behind a loopback endpoint (N6/N11).

Plans/dry runs resolve, validate, bind and patch, skip network preflight, and record tcp/connect/tls as `skipped` (N10). Direct also skips all three probes, including `check --probe`, and uses an unset-only patch with no set values. Only real proxy launches probe the destination; a targetless probe proves TCP only.

### Record and equality (N3, N7, N8)

```json
{"network":{"schema":"relux-network-binding-record-v1","profile_ref":"egress-a","origin":"explicit","profile_digest":"sha256:…","adapter_identity":{"adapter":"generic-env-v1","harness":"codex","build":"0.x.y","entrypoint":"exec"},"assurance":"cooperative","probe":{"tcp":"ok","connect":"skipped","tls":"skipped","checked_at":"RFC3339"}}}
```

Absent key means unmanaged. The illustrative Record omits endpoint, env and credentials. Equality compares **digest + adapter identity + assurance**, not name. Resume re-resolves the recorded ref on that host; unknown/denied precedes comparison. The session envelope adds the sibling `adapter_provenance` member for unqualified builds (§1.4).

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

### 1.4 Adapter build policy (option C)

New builds of a known vendor line (the same adapter id and harness, for
example `claude-code` with `generic-env-v1`) run optimistically, labelled
"unqualified build", with a known-bad check. Unknown vendor lines and
unknown adapters still refuse with `network_scope_unsupported`. Exact
allowlisted builds are "qualified". Option C is the interim default; the
owner may still select central qualification (A) instead. A local
sandbox (B) stays out.

`pkg/adapterprobe` hashes caller-supplied immutable native artifact
snapshots and evaluates policy over that identity. `Evaluate` and evidence
evaluation never open a binary path, start a process, read operator
configuration, Keychain or tokens, or write state; the only filesystem
read in the package is the explicit known-bad loader's narrowly supplied
operator path (fixed `adapter-knownbad.json` under the caller-supplied
root, or an explicitly configured path), read with a no-follow
nonblocking regular-file bounded read that never follows symlinks.
`Request.Args` must be empty; `Request.Binary`
and `Request.Sandbox` are ignored legacy fields that new code leaves
zero. Scripts and mutable runtime closures refuse. The process owner
must execute exactly the approved bytes from immutable/private staging.

Canonical adapter BuildID is `sha256-<64 lowercase hex>`, distinct from
the `sha256:` profile digest. Use `Decision.BoundIdentity` for the shared
adapter tuple for every admission (qualified and unqualified); do not
silently migrate old vendor-label or colon-prefixed adapter records.
Recipe revisions bind the fixed operation and intended observation;
there are no automatic real-vendor recipes, and option C never attempts
automatic qualification. Only `generic-env-v1` is implemented; decisions
carry that adapter identity and `generic-proxy-transport-v1` scope and
do not approve specialized adapters, MCP servers, hooks, tools or hosted
routing.

Use `adapterprobe.Evaluate` for every consumer event: plans, direct
profiles, dry runs, real launches and live reattach. It returns
qualified (allowlisted or evidenced), unqualified (with the typed
provenance record below), or refused with a typed reason; every refusal
carries `network_scope_unsupported`. No event starts a probe or invents
evidence: plans and dry runs evaluate and record the decision without
network preflight; direct profiles evaluate (sensitivity still applies)
with an unset-only patch; reattach re-evaluates the unchanged snapshot
and checks binding equality, so an unqualified launch reattaches as the
same unqualified identity. `Lookup` and `Verified` are low-level,
non-authorizing helpers, not launch verifiers. Endpoint `Preflight`
does not authorize a harness process or a cache write. Build
qualification here is distinct from the content pin (an admission
constraint on the selected bytes) and from the launch plane's
independent adapter, entrypoint and child-scope ceiling.

Consumer sequence: load the operator known-bad file with
`LoadKnownBad` (fixed `adapter-knownbad.json` under the supplied
operator root, or an explicitly configured path); resolve the profile
and take its `sensitive_egress` value; evaluate the immutable snapshot
with that sensitivity and loaded list state; enforce the independent
scope ceiling; show the exact provenance text for unqualified builds;
execute exactly the admitted bytes; store the network `Record` plus the
sibling `adapter_provenance` in the session envelope. The hosted
boundary passes its own resolved profile snapshot to
`VerifyAdapterWithProfile` so the same snapshot is evaluated without a
second catalog read.

Three binding conditions apply:

1. **Provenance is visible.** Consumers MUST show the exact operator
   text at launch and MUST store the typed provenance record
   (`relux-adapter-provenance-v1`) in the session record, not only in
   a log. The text states the risk: traffic may escape the proxy on
   an unproven build; this is a policy gap, not credential exposure.
   Consumers show `Provenance.OperatorText` verbatim:

   ```text
   Unqualified build: claude-code generic-env-v1/exec build sha256-<64 hex> (recipe claude-exec-v1) has no conformance evidence. Traffic may escape the proxy on this unproven build. This is a policy gap, not credential exposure.
   ```

   The session envelope retains the existing network `Record` plus the
   typed record as a sibling `adapter_provenance` member (omitted when
   qualified). Strict session decoders MUST allow the additive member.

2. **Strict is one flag away.** Policy modes are optimistic (default),
   strict and pinned. Strict is the DEFAULT for any network profile
   that declares `sensitive_egress = true`; that declaration cannot
   be downgraded to optimistic by the mode flag. A sensitive profile
   refuses unknown builds with `strict_miss`; only exact allowlisted
   builds run, and an identity-only pin never qualifies there. A pin
   alone never qualifies anywhere: only an independently allowlisted or
   evidenced build is qualified. A missing or different pin refuses
   with `pinned_miss` before every allowlist or evidence hit. The
   declaration is digested when true and needs `confirm` like any
   profile change. The operator catalog schema is strict: upgrade every
   catalog reader before adding the field, allow the additive
   `sensitive_egress` key in strict `show --json` decoders, use keyed
   literals for the extended `netprofile.Input` and
   `netprofile.Profile` structs, and remove the field before rollback.
   See the [migration notes](../README.md#upgrading-for-sensitive-egress).

3. **The known-bad list is checked by binary SHA-256 and fails
   closed.** The library ships an embedded list (currently empty,
   always enforced) and loads an optional operator file
   (`adapter-knownbad.json` under the supplied operator root, or an
   explicitly configured path; schema `relux-adapter-knownbad-v1`, see
   the appendix). A SHA-256 match refuses with `known_bad_build`. A
   configured or present list that is unreadable, corrupt or of an
   unknown version refuses (`knownbad_unreadable`, `knownbad_corrupt`
   or `knownbad_version_unsupported`), never silently passes. A
   genuinely absent optional default means the embedded set only.

The optimistic evidence lookup is the seam for central qualification:
a future signed-evidence source plugs in ahead of the unqualified
fallback. Cache keys are exactly the binary SHA-256, never a version
string. A changed adapter identity requires a new launch; existing
runs retain their exact recorded identity.

## 2. Per consumer: where, who, what

### 2.1 Launch plane: `skill-agents-management`

**Lands in:** optional N-B hook migration / N-C1a. **Q1 — decided (operator decision D4, typed launch-plane hook):** typed `Network{Patch,Record}` request data on launch and spawn requests, rather than arbitrary callbacks. Apply purely after child-environment composition, including the separately filtered owned snapshot. Preserve existing engine provenance when adding network provenance. The module still owns no exec.

Decision 0019 is **adopted**, but environment composition stays with consumers pending a separate decision. Compose-first N-B remains viable. Keep owner-side final application until every later overlay rejects proxy names and final environment parity is proved.

**Q7 — decided (operator decision D8):** support only admitted harness, adapter, entrypoint and child-scope combinations. Generic env support does not certify every release. Verified harness-specific overrides belong to that adapter, not the generic one (N5).

A combination is supported only once its rows pass under the method in [harness verification](harness-verification.md) and the result is recorded here. Child rows must pass with the required adapter's mitigation applied; a generic-patch failure is not a pass. Blocked or unverified scopes remain `network_scope_unsupported`.

Under option C (§1.4) the launch plane keeps its independent adapter, entrypoint and child-scope ceiling: adapter policy is necessary, not sufficient, for launch. New builds of a known vendor line run as unqualified with the provenance shown and recorded; unknown vendor lines still refuse. The historical rows below are an evidence index, not digest approvals: no artifact SHA-256 provenance is available there, and they cannot populate an allowlist until the exact selected artifact is independently qualified. An exact-build ceiling that rejects every new build would defeat option C.

| Harness | Entrypoint | Required adapter | Launch-plane status |
| --- | --- | --- | --- |
| `claude-code` | `exec`, observed as `claude -p` | `generic-env-v1` | Transport scope observed; login-gated and interactive scopes remain unverified |
| `codex-cli` | `exec`, observed as `codex exec` | **`codex-env-v1` REQUIRED** | Until the adapter exists, `--network` refuses Codex with `network_scope_unsupported` |
| `muse` | `exec` / launcher | `muse-env-v1` | Supported with the required adapter; shell/tool-child scope remains an open gap |
| `pi`, `qwen`, `gemini`, `agy` (all builds) | Unverified | Unverified | Refused until each runs [harness verification](harness-verification.md) and its passing results are recorded here |

- **Claude scope (sink method):** API-target routing observed, including lowercase, uppercase and `ALL_PROXY` variants; MCP stdio children inherit the proxy values. All model-turn rows stopped at the login gate; authenticated turns, fallback, hooks and tool scopes remain unverified. The observed entrypoint is `claude -p`; interactive mode is not covered. See [historical transport evidence](harness-verification.md#historical-transport-evidence) for limits.
- **Codex scope (sink method):** model WS/HTTPS routing through the proxy observed, with proxy-preserving fallback. MCP stdio children do not inherit the values; explicit server `env` blocks deliver them. `codex-env-v1` is the generic patch plus its set half injected into each MCP server entry's `env` in launch-private materialised configuration, never shared configuration. Companion, hook and tool-child scopes remain unverified. Until this adapter exists, `--network` refuses Codex with `network_scope_unsupported`.
- **Muse scope:** supported with `muse-env-v1`, which is the generic patch plus per-server `env` injection and hook-command wrapping. MCP inheritance fails without the adapter; the mitigation demonstration covers only part of the matrix. Shell/tool-child verification remains an open gap. Control-plane bridges are excluded from the adapter and configure their own transport explicitly (N11). Shared configuration is never rewritten.

### 2.2 task-board spawn and runner: `skill-project-management`

**Lands in:** N-C1a explicit subagent selection / N-C2 defaults. Per **operator decision, 2026-10-02 07:21Z**, N-C1 integration is split into **N-C1a**, subagent spawn, needing **typed launch-plane hook (D4) + v0.2.0 only**, and **N-C1b**, session hosts, after **M3 / LP Phase 0** (§2.3). Network-profile consumers get priority after the operator's higher-priority items; N-B is the launcher milestone. `--network <name>` selects an id with explicit origin; later runtime and spawn defaults supply defaults. The detached runner inherits the orchestrator env; it is the destination host responsible for child unsets.

- **Preparation/application — advice §2.2(1), partly accepted:** “also serves the dry run” is correct; “does no I/O” is not (preparation reads the catalog). Resolve and validate on the destination after slot claim, then prepare, persist the Record and refresh the patch before every attempt. Carry only an ephemeral patch to the composer; never persist it. Apply last, after final environment composition and runtime control additions, updating owned literals too. Real plan commands and dry-run builds share the same preparation; plans skip probes. The launch-plane owner lands final application through D4; N-C1a no longer waits for M2/M3 (operator decision). Early goal probes need resolution and patching **before their own spawn**, then freshness checks after the slot. A future plan hook replaces the final call only under §1's overlay proof.
- **Manifest/rollback — advice §2.2(4):** old binaries drop unknown keys silently. Retain the Record beside runtime provenance in run manifests, copy it through manifest creation, config restoration and successor cloning, and keep the existing sandbox flag separate. Require implementation round-trip coverage across all three paths and prohibit rollback of profiled runs to unaware binaries: they lose managed provenance and inherit ambient routing; a schema field cannot protect an old decoder.
- **Suites — advice §2.2(3):** “Make both paths build the env the same way.” Do not apply harness patches to validation suites; share suite-environment construction. Inherited-route evidence is decided (operator decision D5): suite evidence records the route as ref and digest, or `ambient`, never proxy values. Keep raw-environment integration milestone within its existing scope.
- **Control plane — advice §2.2(2), subsidiary claim REJECTED:** “The runner's own HTTP to board-server also picks up that proxy”. Control-plane board-server and helper clients MUST use explicitly configured transports that do not consult inherited harness proxy variables (N11).
- **Managed goal launches** carry a credential-free selector envelope to the session host, which resolves and applies locally (§2.3); never send an endpoint or source-host patch.

#### Inherited selection: Q2

**Decided (operator decision D2): option (a), inherited origin; N3/N4 amended before N-C1.** An inherited binding is a mandatory default: an empty patch under a profiled parent retains ambient proxies without provenance. Consumers MUST use durable reference inheritance, never a new ambient contract or inference from proxy values, and MUST authenticate and preserve the parent selection across every eligible launch path, including launches whose parent is not a board goal.

Persist **parent identity plus resolved reference** during reservation and preserve it across preparation, runtime config, retry limits, successor directives and review fan-out. Every retry MUST rebuild its managed envelope from the preserved parent selection, and every successor envelope MUST be rebound to it, rather than inheriting ambient state. Validate manifest/control identity and allowed sets; a mutable run id alone is not authorization.

Primary sessions require authenticated session-record lookup or explicit child selection; ambient session markers alone do not authorize inheritance. Non-board profiled parents need an explicit carrier contract too. Use `Request.Inherited` and `OriginInherited`, with precedence **explicit → inherited → runtime-default → profile-binding → project-default → operator-default**; N3/N4 and Record's closed origin vocabulary now include `inherited`. The library never discovers the reference from the environment. Origin and transport are independent. A parent on A can explicitly select B for a child, subject to host authorization.

#### Retry and recovery: Q3

**Decided (operator decision D1):** advice Q3, “Do not return it as a launch error”. Resolve unknown/denied first; changed digest is terminal `network_profile_drift` before each attempt, queue release, successor launch and managed retry preflight. Ordinary launch errors enter recovery, so drift must bypass it. Preserve reference/digest/assurance across provider reselection; deliberately changed adapters get new attempt Records only with unchanged digest. Add a retry-specific check: ordinary `CheckReattach` rejects adapter changes. Recovery/resume still uses full event-appropriate equality.

#### Explicit direct

**Decided (operator decision D3): option (b), v0.2.0, named `kind = "direct"`.** A profiled parent can choose its own profile, another profile, or a named direct profile for any child, as an external decision module chooses. Direct is one more profile id in the host's allowed set; it retains the actual reference and origin. Absence remains unmanaged and preserves ambient env.

A direct profile forbids endpoint, bypass hosts and probe target, needs confirmation like every widening entry, and has a canonical digest of schema + kind + credential mode plus `sensitive_egress` only when true (§1.4, appendix §1). Its patch is unset-only; its managed Record retains ref, digest, cooperative assurance and skipped TCP/CONNECT/TLS probes. Host authorization and confirmation still apply. Direct does not guarantee OS-level directness (N11). Binding equality and drift rules are unchanged.

### 2.3 the session host: `skill-project-management`

**Lands in:** N-C1b (N-C1 integration), after M3 / LP Phase 0 (operator decision). Hosts build child environments from the daemon environment. Apply one shared helper **last** to each child env, after temporary-directory setup.

- **Carrier — advice §2.3(2):** “Send the ref, the origin and the expected digest”. Use that credential-free selector envelope in the run-context and session-launch plans. The daemon re-resolves against its own catalog, confirmations, allowed set and admitted tuple, checks the expected digest and uses §1's preflight branch locally: no probe for direct or plans/dry runs (all three steps `skipped`); otherwise probe. Strict decoders fail closed. The destination MUST refuse envelopes with an unsupported schema or an unnegotiated capability.
- **Record/reuse — advice §2.3(1):** compare the durable binding before every reuse, restore and start, and reconcile at startup too. The host MUST check the stored Record against the freshly resolved binding on every host-reuse path, including live reuse, restore and launch. Existing unmanaged hosts refuse profiled assignments. Stop-only restore paths remain usable.
- **Q4 — decided (operator decision D1):** advice Q4, “the session host starts one app-server per session”. Fresh sessions get independent bindings; the legacy shared app-server path is excluded. First-release live-host attach/restore requires equal binding or refusal; existing-run restore is `EventReattach`, not automatically `EventNewAssignment`, so drift and full equality apply.
- **Daemon startup — advice §2.3(3):** a daemon MUST NOT start from an identified profiled run: refuse that startup before the run identity is detached. Do not strip ordinary operator proxies at startup; blanket stripping would break unmanaged compatibility. Each managed session still applies the session patch last.
- **Auxiliary harnesses — advice §2.3(4):** “must use the session's patch.” Pass the same resolved session context to preflight and assay subprocesses; refusals stop those subprocesses too. Audit every other harness-adjacent exec (context builders, legacy launchers, visible clients, goal probes, third-party preflights). Every exec must apply the session context or have evidence it is outside harness routing.

Also audit launcher release probes, engine-status subprocesses and the daemon intermediate above. Version probes need evidence of no network work or their resolved patch. Preparation/composition subprocesses remain outside harness routing (N5); `curator network exec` follows the same final application rule.

### 2.4 curator-run: `curator-agent-launcher`

**Lands in:** N-B. The Curator and launcher owners coordinate N-B; the launcher owner leads its implementation; consumer representatives advise. Ownership is unchanged (operator decisions).

- Add `--network <name>` to the CLI invocation and value flags; accept profile identifiers, not URLs.
- Resolve and validate after the admitted plan build, before composing the admitted plan, using the original operator env. Probe only a real supported launch in untracked mode using a proxy profile; `kind = "direct"` skips probes. Refusals stop launch without fallback; tracked managed selection refuses before a source-host probe.
- In composition, after all overlays and before materializing env, delete unset names case-insensitively from both env and literals, add set to both, reject managed proxy env names/overlays, and recheck disjointness. Direct exec uses the patched env; emit sanitized Record provenance.
- Tracked mode carries only set literals and a proposed `works.relux.curator.network` Record extension. **Refuse every managed tracked selection, including defaults, with `network_scope_unsupported` until §2.5's destination capability exists** (N9). No fallback or silent loss of tracking. Curator preparation (env resolve/install/repair) remains outside this patch (N5).

### 2.5 ax launch plan and session host

**Q5 — D6 DEFERRED, Ivan, 2026-10-02 05:36Z:** deferred until ax implements session launch. The destination session-launch capability (ax) milestone tracks carrier options, destination duties and refusal until then. Tracked `--network` keeps refusing (N9). Keep the Record extension, but require a negotiated, versioned network capability at the destination. Ax implementation owners enforce it; session-host owners own any bridge. The ax host readme is specification-only; session launch proper is absent. Extension preservation alone proves no enforcement.

The destination resolves and authorizes locally, compares the expected digest and verifies its adapter tuple. It uses §1's preflight branch: direct or plans/dry runs skip all three steps; only real proxy launches probe. It applies the patch to its final env (direct unsets only, with no set; proxy unsets then applies fresh set) and persists the Record. Audit start/resume/fork/re-adoption; reject unsupported schemas or unaware hosts. Suppress conflicting old proxy literals before fresh application, otherwise they replay verbatim. Resume drift refuses `network_profile_drift`; attach/resume uses full equality.

Set literals are non-secret and disjoint from `env_names`. Canonical proxy spellings are reserved; consumers must reject **mixed-case** proxy names too. N9 stays closed until destination conformance proves these rules.

### 2.6 Curator umbrella and trust

`curator network …` dispatches to `curator-network` (umbrella dispatch). Distinguish revision A, PATH selection with an outside-roots warning, from revision B, roots-only selection. No provider-selection flags are required; N-A implements `--json` and a real `--version`. Provider installs follow the provider-installation milestones in curator-spec and curator.

Presence-key signing for `confirm` is not available. N-A already implements a local digest-bound confirmations ledger and agent-session refusal; its interim policy remains TODO(decision) in the implemented appendix/API. When curator-trust lands, replace the ledger with the trust store.

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
| trust-store confirm | trust owner / curator-trust | after N-A | trust-store confirmations capability |
| managed gateway | library/gateway owner / this repo | N-D | N-A; no N-B/C dependency |

Consume the library **by tag**, never `replace` or `go.work`; `v0.2.0` is the first public release; v0.1.0 is retired (operator decision, 2026-10-02). Before adopting v0.2.0, follow [the migration requirements](../README.md#upgrading-to-v020): upgrade every catalog reader before adding direct, remove direct entries before downgrading, use keyed `resolve.Request` literals, admit `inherited` origins and allow the additive `check --json` `kind` field. The contract schema strings remain v1 for these pre-1.0 additive vocabulary changes. **Q6 — decided (operator decision D7):** role-based ownership stays unchanged; the Curator and launcher owners coordinate N-B; the launcher owner leads its implementation; consumer representatives advise (operator decisions).

## 4. Invariants every consumer keeps

1. Apply last on the process-creating host, to final child env; never `os.Setenv`, shell profiles, shared tmux env, user settings or system proxy.
2. Set values are owned non-secret literals; proxy names never travel as env_names, including mixed case.
3. Selection carries an authorized id, never a proxy URL; resolve locally and never infer a ref from ambient proxy values.
4. Refusals stop workload spawn/preflight. No hidden fallback to direct, another profile/account or automatic recovery on drift; mid-run drops go to the run owner.
5. The managed network member keeps Record only, never Binding/Patch, env, credentials, endpoints or request bodies; the session envelope additionally retains the sibling `adapter_provenance` for unqualified builds (§1.4).
6. Control-plane helpers (stdio MCP, Apiary bridge, board-server client) configure transport explicitly, outside inherited harness proxies (N11).
7. No selection preserves today's unmanaged behavior exactly. It does not guarantee direct egress or authorize opting out of inherited selection.
8. Unqualified builds show their exact provenance text at launch and store the typed provenance in the session record (§1.4). Sensitive-egress profiles evaluate strict; the known-bad list fails closed.

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
| Option C | interim default: new builds of known vendor lines run unqualified with visible provenance and a fail-closed known-bad check (§1.4); the owner may still select central qualification (A) instead |

Q3 terminal retry drift and Q4 independent fresh sessions / equal-or-refuse live hosts are part of adopted rev 2 (D1).

### Changes in rev 2

- Corrected cross-references and added exec audits; Decision 0019 is adopted, with environment ownership still open (§1/§2.1–§2.6).
- Moved preparation/persistence to the runner; required early-probe preparation, durable inheritance preserved across launches, retries and successors, and terminal retry drift; kept the board-client transport explicitly configured (advice §2.2(1–2), Q2–Q3).
- Added suite separation/evidence decision and rollback/round-trip requirements; retained normalized credential refusal and Record-only serialization (advice §2.2(3–5)).
- Added startup reconciliation, local selector resolution with refusal of unsupported envelopes, profiled-startup refusal and session-patched preflight/assay; corrected the fresh-session premise (advice §2.3(1–4), Q4).
- Replaced unanswered questions with the recommendations adopted by operator decision, 2026-10-02, initially deferred explicit direct (superseded by D3 below), corrected mixed-case reservation, trust dispatch, N-A status, overlay migration and N-D dependency; replaced the ownership-transfer assumption with unchanged role ownership (Q1, Q5–Q7).
- Recorded adoption and decisions operator decision D1, D2, D4, D5, D7–D10 on 2026-10-02; subsequent D6 and D8 outcomes are recorded below.
- Recorded D3 decided option (b), named direct shipped in v0.2.0 (2026-10-02 05:26Z).
- Recorded D6 deferred until ax session launch (05:36Z), destination session-launch capability (ax) and continued tracked-mode refusal (N9).
- Recorded D8 = (A) (05:44Z): both exact Muse builds supported with `muse-env-v1`, per-server MCP env injection and hook-command wrapping; acceptance rows and calibrated SIGKILL evidence; N11 exclusions, Muse-plugin ownership and the open R7b gap (R7b shell/tool-child verification).
- Split N-C1 into N-C1a (D4 + v0.2.0 only) and N-C1b (after M3 / LP Phase 0), per operator decision (07:21Z); recorded N-C1, N-B and D4 milestone names and consumer priority after the operator's higher-priority items.
