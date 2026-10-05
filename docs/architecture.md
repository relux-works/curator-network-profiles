# Architecture: curator-network-profiles (slice A)

Status: describes the code on branch `n-a/library` (track step N-A). The design
is `spec/network-profiles.md` (DRAFT, decisions N1–N14); the normative contract
is `spec/contract-appendix.md` (`relux-network-profiles-v1`). Items marked
TODO(decision) are choices the specification does not settle; they are listed
at the end.

No Russian translation of this document or of the appendix exists yet (the
Russian files under `spec/` cover the design and the track only).

## 1. What slice A is

A Go module, `github.com/relux-works/curator-network-profiles`, with two halves:

- `pkg/…`, the importable library: `resolve → validate → conditional probe → bind → patch`.
  It creates no processes, runs no daemon, never calls `os.Setenv`, never reads
  `os.Getenv`, and imports none of its callers.
- `cmd/curator-network` + `internal/…`, the Curator provider behind
  `curator network <verb> …`: `list`, `show`, `add`, `remove`, `check [--probe]`,
  `confirm`, `exec <name> -- <command>`. Only `exec` starts anything, and it
  does so by replacing itself (`syscall.Exec`), so signals and the exit status
  are the child's.

Dependencies: the standard library and `github.com/pelletier/go-toml/v2`.

## Upgrading to v0.2.0

The contract schema strings stay v1 (`relux-network-profiles-v1` and
`relux-network-binding-record-v1`): these are additive vocabulary changes
before 1.0, with the following compatibility requirements.

- Upgrade **every catalog reader on the machine** (`curator-network`,
  `curator-run`, task-board, the session host, …) to v0.2.0 **before adding a direct
  profile**. A v0.1.0 reader rejects the **whole catalog** once any
  `kind = "direct"` entry exists, even when the selection names a different
  proxy profile. Remove all direct entries before downgrading.
- `resolve.Request` gained `Inherited`, which breaks positional (unkeyed)
  struct literals. Use keyed literals, for example
  `resolve.Request{Explicit: "egress-a", Inherited: persistedParentRef}`.
- Consumers with a closed origin set must admit `inherited` before exchanging
  Records. The Record schema id remains `relux-network-binding-record-v1`.
- `check --json` adds a `kind` field per profile. This is additive; strict
  decoders must allow the field.

## 2. Packages

| Package | Responsibility | Depends on |
| --- | --- | --- |
| `pkg/refusal` | the closed code set (spec N10 + three additions), typed `*Refusal{Code, Subject, Detail}`; messages never carry file contents, absolute paths, env values or credentials | — |
| `pkg/netprofile` | schema `relux-network-profiles-v1`, strict TOML decode (unknown keys refused), normalization, validation, canonical JSON and `Digest`, `HostKey`/`Covers` for engine hosts | refusal, go-toml |
| `pkg/envpatch` | `Patch{Unset, Set}`, the `Adapter` interface, the generic adapter `generic-env-v1`, pure `Apply(env) []string`, `SetLiterals()`/`UnsetNames()` | netprofile |
| `pkg/binding` | `AdapterIdentity`, `Binding`, manifest-safe `Record`, `Equal`, the N7 table `CheckReattach` | envpatch, refusal |
| `pkg/resolve` | `Selection{profile_ref, origin, required_assurance}`, N4 precedence (`Select`), `Resolve` with allowed set, existence, assurance, confirmation and engine coverage; the `unmanaged` result | netprofile, binding, refusal |
| `pkg/probe` | bounded preflight: TCP → CONNECT → TLS (verification on, injectable roots), the `Prober` boundary | refusal |
| `pkg/gateway` | `Backend` interface; `External` (external-http-proxy: returns the configured endpoint); `Direct` (direct: no endpoint); `Managed` interface reserved for N-D | netprofile, refusal |
| `pkg/catalog` | read-only facade for process owners: `Load(env)` = catalog + ledger, implements `resolve.Confirmations` | internal/store, internal/confirm |
| `internal/store` | paths from the injected `HOME`, read, comment-preserving `Add`/`Remove` as text edits, re-parse before write, atomic write with backup | atomicfile, envutil, netprofile |
| `internal/confirm` | the confirmation ledger and the agent-session guardrail | atomicfile, envutil |
| `internal/atomicfile`, `internal/envutil` | temp+fsync+rename writes (0600, dir 0700 when created); `Lookup`/`Has` on an env slice | — |
| `internal/cli` | `Run(ctx, args, Deps) int`; every verb; `Deps` carries Env, Stdin/Stdout/Stderr, IsTerminal, Exec, Prober, Now (no package-level seams) | everything above |
| `internal/version` | ldflags → `debug.ReadBuildInfo` → `dev` | netprofile |
| `internal/testproxy` (+ `cmd/egress-client`, `cmd/loopback-proxy`) | loopback CONNECT proxy for tests and the demo; answers `.invalid` GETs itself, dials only mapped loopback targets; modes 407 and hang; a TLS upstream with its own root | — |
| `internal/contract` (+ `cmd/contract-vectors`) | the appendix vectors computed by the code; the drift guard | pkg/* |

Test placement: every package has table-driven tests beside it; the milestone
test (two concurrent launches through two egresses, real binaries) is
`cmd/curator-network/exec_e2e_test.go`.

## 3. Data flow

```text
 caller (curator-run / task-board / the session host / curator-network exec)
   │
   │  env []string (injected), Selection inputs, Allowed, EngineHosts
   ▼
 catalog.Load(env) ──── ~/.curator/network.toml ──► netprofile.Parse (strict, normalize, validate)
   │                └── ~/.curator/network.confirmations.json ──► confirm.Ledger
   ▼
 resolve.Resolve(file, ledger, req)
   │  explicit → inherited → runtime-default → profile-binding → project-default → operator-default; else UNMANAGED (empty patch)
   │  allowed set → exists → assurance → confirmed at digest → engine hosts covered (proxy only)
   ▼
 preflight branch
   ├─ kind == direct ──► no probe; ProbeRecord tcp/connect/tls = skipped
   ├─ else plan/dry run ► no probe; ProbeRecord tcp/connect/tls = skipped
   └─ otherwise ───────► probe.Dialer.Probe(ctx, {endpoint, probe_target, timeout})
   │                    tcp → CONNECT → TLS (with target, verification on); refuse on failure
   ▼
 binding.Binding{profile_ref, profile_digest, adapter_identity, assurance, resolved_endpoint, env_patch}
   │  env_patch = envpatch.Generic{}.Patch(profile)
   ▼
 patch.Apply(inheritedEnv) → child env
   │  direct: unset the proxy family; set nothing
   │  proxy: unset the proxy family, then set the coherent six
   │
   ▼
 (caller) spawn / syscall.Exec (real launch only) ──► no fallback to direct on any failure
   │
   ▼
 binding.Record{schema, profile_ref, profile_digest, adapter_identity, assurance, origin, probe}  → manifests, logs
```

Direct, a plan or a dry run never calls the prober and records all three
`ProbeRecord` fields (`tcp`, `connect`, `tls`) as `skipped`. Direct still gets
a managed binding, with an unset-only patch and an empty set. Unmanaged keeps
an empty patch and no network Record. A managed Record always has schema
`relux-network-binding-record-v1` and a non-null `probe` object. An absent
`network` manifest key means unmanaged (appendix §3.4).

The library stops at the patch. The host that creates the process applies it to
that process's private environment; nothing is exported, no shell profile, no
system proxy, no shared configuration is touched (spec N5).

## 4. The operator files

`~/.curator/network.toml` (HOME from the injected environment):

```toml
schema = "relux-network-profiles-v1"
default = "egress-a"                          # optional: origin operator-default

[networks.egress-a]
kind         = "external-http-proxy"
endpoint     = "http://127.0.0.1:18081"
bypass_hosts = ["localhost", "127.0.0.1", "::1"]
probe_target = "example-probe.invalid:443"    # optional, TODO(decision)
```

- Names: `^[a-z0-9][a-z0-9._-]{0,62}$`. A name with a dot is written as a quoted
  key `[networks."vpn.eu"]` because TOML would otherwise nest tables.
- Proxy endpoint: `http://host:port` only, explicit port, no userinfo (the value is
  never echoed), no path but `/`, no query or fragment; lowercased; IPv6 in
  brackets; IP literals are canonicalized with `netip`, and IPv4-mapped IPv6
  is unmapped to IPv4. `bypass_hosts` must contain `localhost`, `127.0.0.1`,
  `::1`; entries are trimmed, lowercased, deduplicated, sorted; `*`, empty, commas and
  whitespace are refused.
- The file is valid as a whole or refused as a whole. Absent = no profiles
  (a selection is `network_profile_unknown`; no selection is `unmanaged`).
  Unreadable or unparsable = every selection refused, including "no selection"
  (the operator default cannot be known): a read failure is never headroom.
- `add` appends a block at the end. The removed block is the table's own
  leading comment block (contiguous `#` lines directly above its header,
  no blank line in between), its header, and its body up to the last non-blank,
  non-comment line before the next header or EOF. Comments and blank lines
  that precede the next header (or trail at EOF) stay; every other byte stays.
  The result is parsed and validated before writing; the write is temp +
  fsync + rename with mode 0600, the previous bytes go to `network.toml.bak`,
  and the directory is created 0700 when absent (an existing `~/.curator`
  keeps its mode: it is shared with other Curator files).
- Catalog mutation (`add`/`remove`) refuses a symlinked catalog before reading
  or backing it up; atomic writes also refuse symlink destinations, including
  backups and ledgers. Read-only catalog loads, including `confirm`, may follow
  symlinks. `confirm` writes only the separate ledger and leaves the catalog
  link and target unchanged. Refusal never replaces a link or modifies its target.
- `store.WithCatalogLock` holds the advisory `network.toml.lock` (O_CREATE|O_EXCL,
  0600) across its callback. `store.Edit` uses it for catalog read/edit/write and
  CLI add/remove ledger operations; CLI `confirm` uses it for read-only catalog
  access and ledger writes. `Add`/`Remove` and CLI `confirm` use this same lock.
  A held catalog edit lock refuses immediately as `network_configuration_conflict`;
  every normal return removes the acquired lock. A crash-stale lock has no CLI
  cleanup: after checking no edit is running,
  the operator deletes `network.toml.lock` by hand. TODO(decision): whether to
  add a cleanup command.
- CLI `confirm` prompts before taking the catalog edit lock. After `yes`,
  `store.WithCatalogLock` holds the lock from re-reading the catalog and ledger
  through the atomic ledger write. A held lock uses the same immediate
  `network_configuration_conflict` refusal as add/remove. The catalog bytes
  must still match the preview; any change (including comments, deletion or
  invalid TOML) refuses with `network_configuration_conflict` and sanitized
  detail `catalog changed during confirm; run confirm again`, without writing
  the ledger. A fresh ledger read preserves other edits made during the prompt.
  Prompting first avoids holding a lock while a human waits or abandons the
  terminal, reducing the risk of a crash-stale lock; the trade-off is that an
  edit or held lock can require another confirm after the operator answers.
  Lock cleanup runs on success, refusal and write failure through
  `store.WithCatalogLock`.
  Manual edits do not participate in this advisory lock and must not race the
  locked read/write interval.
- CLI `add` refuses an existing name before touching its confirmation. It reads
  and validates the ledger, deletes any entry for the new name and writes that
  cleanup before writing the catalog, all under `store.Edit`. A ledger failure
  leaves the catalog and backup untouched. If the subsequent catalog write
  fails, the stale entry stays deleted; retrying the add still needs `confirm`.
  Re-adding identical content never reuses an old confirmation.
- CLI `remove` with an absent catalog and no stale confirmation refuses
  without creating `.curator` or acquiring an edit lock. Stale entries still
  require locked cleanup; removing a confirmed operator default refuses
  without changing either the catalog or ledger.
- CLI `remove` first reads and validates the ledger, then writes the catalog,
  then drops the entry and writes the ledger. A ledger read/validation failure
  leaves the catalog and backup untouched. These are two ordered atomic
  writes, not a cross-file transaction: if the ledger write fails, removal
  remains applied, its old entry remains in the ledger, and the CLI exits 1
  with `network_file_unreadable`. An absent profile cannot launch; the backup
  contains the prior catalog. After correcting the write failure, retry
  `remove`: an absent profile with a stale entry drops that entry and exits 0
  with a clear cleanup message (`removed=false`, `confirmation_dropped=true`
  in JSON). If neither profile nor entry exists, it is `network_profile_unknown`.

`~/.curator/network.confirmations.json` (`relux-network-confirmations-v1`) maps
a profile name to the digest it was confirmed at and when. A profile whose
content changed under the same name is unconfirmed again until the operator
re-runs `confirm`. Nothing in either file is a secret.

## 5. Error taxonomy

Refusals are typed `*refusal.Refusal` values with a code from the closed set.
The CLI prints `curator-network: <code>: <detail>` on stderr and exits 1; with
`--json` it also prints `{"schema":"curator-network-error-v1","ok":false,
"error":{"code","message","subject"}}` on stdout. Usage errors are not
refusals: `curator-network: usage: <detail>` plus the synopsis, exit 2, no JSON.
In usage diagnostics, operands and flag values are never echoed. This rule
also covers the command vector in dry runs and real-exec diagnostics. Only a sanitized entrypoint is
shown: `basename(argv[0])` when it passes the plain-subject rule
(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$`), otherwise `<command>`. The binding's
`adapter_identity.entrypoint` uses that same value. Human dry runs print
`would exec <entrypoint> (+N args)`, where N excludes the entrypoint. JSON dry
runs replace `command` with integer `argc` (including the entrypoint) and
sanitized `entrypoint`; no command arguments or entrypoint directory appear.
The flag package's own output is suppressed; messages use only fixed phrases and known
flag names, such as `invalid value for flag -timeout`. Refusal subjects that
fail the plain identifier rule become `<invalid name>` in both human and JSON
errors.

| Code | When | Raised by | Exit |
| --- | --- | --- | --- |
| `network_profile_unknown` | the selected name is not in the catalog (or the catalog is absent) | resolve, store.Remove, cli show/check/confirm | 1 |
| `network_profile_denied` | the name is outside the allowed set; or known but not confirmed at its current digest (detail `unconfirmed`) | resolve | 1 |
| `network_scope_unsupported` | `enforced` assurance requested (TODO(decision)); a running host bound differently with no per-session route; a resume whose binding differs otherwise than by drift | resolve, binding.CheckReattach, gateway | 1 |
| `network_configuration_conflict` | an engine host is not in `bypass_hosts`; `add` of an existing name; `remove` of the operator default (both TODO(decision)); a held catalog edit lock; catalog changed during confirm | resolve, store, cli confirm | 1 |
| `network_proxy_unreachable` | TCP dial failed or timed out; CONNECT answered non-2xx other than 407; TLS handshake failed; the facts are in the probe result | probe | 1 |
| `network_proxy_auth_failed` | CONNECT answered 407 | probe | 1 |
| `network_profile_drift` | resume of an existing run: same profile name, different digest | binding.CheckReattach | 1 |
| `network_profile_invalid` (addition) | malformed content: unknown key, wrong schema, bad endpoint, missing required bypass, dangling `default`, an edit that does not round-trip | netprofile.Parse, store | 1 |
| `network_file_unreadable` (addition) | HOME unset; the catalog or the ledger exists but cannot be read or parsed; cannot read or write (including write, encode, directory or lock failures) | store, confirm, catalog | 1 |
| `network_confirm_refused` (addition) | `confirm` under an agent-session marker, without a terminal, or answered with anything but `yes` | confirm.Guard, cli confirm | 1 |
| usage (not a code) | bad verb, flag or operand; `exec` command not found or not executable | cli | 2 |

Unknown-key refusals report a count and, only for keys in one profile whose
name passes the plain-subject rule, `[networks.<name>]`. Unknown key names
and unsafe profile names are never echoed.

Unexpected non-refusal failures map to `network_configuration_conflict` with
fixed detail `internal operation failed` (TODO(decision)); the CLI never emits
an unlisted `internal` code or raw Go errors. TOML type errors carry only
`<key>: wrong type`; syntax errors carry only `syntax error at line N`.

The literal of every code is pinned by `pkg/refusal` tests; the appendix lists
the same set and the drift guard checks it.

## 6. The provider CLI

`curator-network <verb> …` is what the umbrella runs for `curator network <verb> …`.
Every verb accepts `--json` (also before the verb) and prints a versioned
document `curator-network-<verb>-v1` on success.

| Verb | Network | Writes | Notes |
| --- | --- | --- | --- |
| `--version` | no | no | `curator-network <v> (revision <r>[, dirty]; contract relux-network-profiles-v1)` |
| `list` | no | no | name, kind, endpoint, digest (short; full in JSON), confirmed, default marker |
| `show <name>` | no | no | normalized profile, digest, confirmation state, the patch (unset names, set pairs) |
| `add <name> --endpoint URL [--bypass h1,h2] [--probe-target h:p]` | no | catalog | inserts the required bypass hosts; refuses an existing name; prints the pending-confirmation notice |
| `add <name> --direct` | no | catalog | named direct, kind-only table, unset-only patch; conflicts with endpoint/bypass/probe-target; requires confirmation |
| `remove <name>` | no | catalog, ledger | narrowing, applies at once; drops the ledger entry |
| `check [<name>|--all] [--probe] [--target h:p] [--timeout 3s]` | proxy profiles with `--probe` only | no | direct skips tcp/connect/tls even with `--probe`; without `--probe` the prober is never called (a test injects a prober that fails the suite if called) |
| `confirm [<name>…]` | no | ledger | guardrail: any of `CLAUDECODE, CLAUDE_CODE_SESSION_ID, CLAUDE_CODE_ENTRYPOINT, CODEX_THREAD_ID, CODEX_SESSION, CODEX_CI, TASK_BOARD_RUN_ID, A2A_AGENT` set, or stdin not a terminal, refuses; then lists pending digests and asks for `yes`; locks, revalidates the catalog and re-reads the ledger before writing |
| `exec <name> [--preflight-timeout 3s] [--dry-run] -- <cmd> [args]` | real proxy launches only | no | validate the name and require explicit managed resolution; resolve → validate → command lookup → preflight (proxy TCP; CONNECT+TLS with `probe_target`; direct skips all steps) → bind → `Apply` → `syscall.Exec`; `--dry-run` skips lookup and preflight and prints the Record and patch with tcp/connect/tls skipped; lookup uses inherited `PATH`, skips empty elements and honors an explicit `.` |

`Deps` is the only boundary: production main wires `os.Environ()`, the standard
streams, the char-device test on stdin, `syscall.Exec`, `probe.Dialer` and
`time.Now`; tests inject fakes and a temporary HOME. `check --json` reports a
failed probe inside the check document (`ok:false`, per-profile `error`) so the
three probe facts are not lost (TODO(decision)).

## 7. Safety properties

- No `os.Setenv`, no `os.Getenv`, no system proxy, no DNS or hosts changes, no
  TUN, no VPN client control anywhere in the module.
- Tests bind only `127.0.0.1:0`; `internal/testproxy` refuses any other listen
  address and dials only loopback targets from an explicit map. Test host names
  use the reserved `.invalid` TLD and are answered by the proxy itself; the
  egress client exits 3 rather than dial directly when no proxy is configured.
  Direct uses `--dump-proxy-env`, which prints proxy-family variables and exits
  without parsing a target or dialing. The concurrent E2E covers A, B and direct.
- Tests run with a temporary HOME (and XDG dirs) passed through `Deps.Env` or
  the child's `cmd.Env`; no test uses `t.Setenv`, sleeps or `t.Skip`.
- Refusals carry no TOML contents, absolute paths, environment values or
  credentials; the Record carries no environment and no endpoint.
- The probe keeps TLS verification on; a test proves that the system roots
  reject the loopback upstream unless its root is injected.

## 8. Extension points

**N-B, `curator run --network`.** After the ordinary environment composition
and before spawn: `cat, err := catalog.Load(env)`; refuse on error;
`res, err := cat.Resolve(resolve.Request{Explicit: flag, Inherited: persistedParentRef, RuntimeDefault: …,
ProjectDefault: …, Allowed: hostSet, EngineHosts: engines})`; on
error, refuse. If `!res.Managed`, keep the ambient environment and omit the
network Record. For a managed result, prepare a `binding.ProbeRecord` named
`pr` and branch before preflight:

- `res.Profile.Kind == netprofile.KindDirect`: no probe; use
  `binding.ProbeRecord{TCP: "skipped", Connect: "skipped", TLS: "skipped"}`
  and an unset-only patch (empty set).
- Otherwise, a dry run or plan: no probe; use the same skipped ProbeRecord.
- Otherwise: call `probe.Dialer{}.Probe`; refuse on error and copy its facts
  into the ProbeRecord.

Build the `binding.Binding` with the launcher's verified
`AdapterIdentity{Adapter: envpatch.AdapterGeneric, Harness: "claude",
Build: toolRelease, Entrypoint: …}` and `envpatch.Generic{}.Patch(res.Profile)`.
Apply `env = b.EnvPatch.Apply(env)` after the final overlay, spawn only for a
real launch, and keep `b.Record(string(res.Selection.Origin), &pr)` beside
`RuntimeProvenance`. The set values travel as owned literals (`env_literals`):
`b.EnvPatch.SetLiterals()`, empty for direct. Apply unsets on the destination
host to both the final environment and owned literals.

**N-C1 / N-C2, task-board `internal/spawn` and the session host.** Same call on
every process-creation path (spawn, retry, resume, recursive children). Use
the same preflight branch: direct gets no probe and an unset-only patch with
no set; plans/dry runs get no probe; both record tcp/connect/tls as `skipped`.
Only real proxy launches call the prober. Apply the patch after the final
overlay on the child's host. At resume or reattach: `binding.CheckReattach(recorded, fresh, binding.EventReattach,
perSessionRoute)` refuses drift and scope changes per N7; on a running host,
`binding.EventNewAssignment`. Run manifests keep `binding.Record`.
`resolve.OriginInherited` is the parent reference persisted by the process owner
at reservation and passed as `Request.Inherited`; it is re-resolved on the
child's host, subject to that host's allowed set and confirmations, never
inferred from env or proxy values (operator decision D2). Explicit selection
overrides inheritance; inheritance overrides all defaults. Origins for
C2 are `resolve.OriginRuntimeDefault` (per-binding `network`),
`resolve.OriginProfileBinding` (operator `[bindings.profiles]` lookup using
`Request.CuratorProfile`) and `resolve.OriginProjectDefault` (`spawn.network.default`); the file's `default`
is `operator-default`. Profile bindings come only from the destination operator's
`~/.curator/network.toml`, never project/profile files or environment selectors.
See [appendix §3.7](../spec/contract-appendix.md#37-selection-and-inheritance-spec-n3-n4-n8)
for the table and origin contract. A router's CandidateResolver uses `resolve.Select` (a
lookup, never a probe; spec N13).

**N-D, managed gateway.** `gateway.Managed` adds `Acquire(ctx, profile, owner)`,
`Inspect(ctx, leaseID)`, `Release(ctx, leaseID)` returning `gateway.Lease{ID,
Owner, Generation, Endpoint}`; the lease owner is the runtime owner, one agent
finishing must not stop the others' proxy, and a configuration change creates
a new generation instead of moving sessions (spec N14). A managed backend
returns the lease endpoint from `Endpoint`; `Binding` grows `lease_id` and
`generation`, which stay outside equality and the digest.

**Harness adapters beyond generic.** Implement `envpatch.Adapter`: `Identity()`
returns the adapter id recorded in `AdapterIdentity.Adapter`, and `Patch`
returns the generic proxy set plus the verified additions for that harness
(`ALL_PROXY`, websocket variables, a per-launch runtime override); for direct,
keep the patch unset-only with no set values. Additions
enter only after the entrypoint is verified on a pinned release (spec N5, N7);
muse's closed allowlist is such an adapter, not a change to the generic one.

## 9. TODO(decision) list

1. `network_profile_invalid`, `network_file_unreadable`, `network_confirm_refused`
   are added to the spec's code set (`pkg/refusal`).
2. An `enforced` assurance request is refused as `network_scope_unsupported`
   (`pkg/resolve`); the spec names no code.
3. The ledger stands in for curator-trust §10 presence-key signing; any content
   change needs re-confirmation, a narrowing edit gets no shortcut (`internal/confirm`).
4. `probe_target` is an optional profile key beyond the spec's example, so
   CONNECT+TLS probes have an agreed target (`pkg/netprofile`).
5. The catalog is valid as a whole or refused as a whole (`pkg/netprofile.File`).
6. `add` of an existing name and `remove` of the operator default are
   `network_configuration_conflict` (`internal/store`).
7. `check --json` failures use the check document with `ok:false`, not the
   error envelope (`internal/cli`).
8. A resume whose adapter identity or assurance differs, or that selects
   another profile, is `network_scope_unsupported` (`pkg/binding.CheckReattach`);
   N7 has no row for it.
9. `pkg/catalog` is a public read-only facade over `internal/store` and
   `internal/confirm` so external callers do not re-implement the paths.
10. `exec` with a command that is not found or not executable is a usage
    error (exit 2); the closed set has no exec-failure code.
11. CI runs on GitHub-hosted runners only, as recorded in the project roadmap
    (2026-09-24).
12. The module is Apache-2.0 licensed ([LICENSE](../LICENSE),
    [NOTICE](../NOTICE)); the earlier pending-licence note (2026-09-24) is
    superseded.
13. Unexpected internal failures use the existing `network_configuration_conflict`
    code with a fixed sanitized detail instead of extending the closed set.
    `network_file_unreadable` covers cannot read or write, not just reads.
