# Harness network verification

Evidence is specific to an artifact, platform, applied adapter, entrypoint,
recipe revision and transport scope. An HTTP sink observation does not establish
model authentication, child inheritance, websocket support or absence of fallback.
Under strict policy (including sensitive profiles) and in low-level evidence
inspection, missing evidence refuses with `network_scope_unsupported`. Under the
default optimistic option-C policy, a known vendor line without evidence runs as
unqualified with its visible provenance (see below), not as a refusal. The
authoritative precedence is the option-C table in
[the integration contract](integration-contract.md#14-adapter-build-policy-option-c)
and appendix §3.8.

## Automatic adapter probe

`pkg/adapterprobe` now fails closed for fresh execution. The previous launcher
could not enforce credential isolation, close inherited descriptors, contain
processes escaping their group, or bound filesystem I/O and cleanup. It has been
removed. `Evaluate` and evidence evaluation perform no `os/exec`, harness
launch, calibration subprocess, filesystem read, temporary directory or
persistent-cache operation. The only filesystem read in the package is the
explicit known-bad loader: `LoadKnownBad` reads a single narrowly supplied
operator path (the fixed `adapter-knownbad.json` under the caller-supplied
root, or an explicitly configured path) with a no-follow nonblocking
regular-file bounded read; symlinks are never followed, and present-but-
unusable paths refuse as `knownbad_unreadable` instead of reading as absent.

`Probe` returns a typed `*adapterprobe.Unsupported`, compatible with
`errors.Is(err, adapterprobe.ErrUnsupported)` and `refusal.CodeOf`. On macOS its
native execution reason is `secure_supervisor_required`; on Linux it is
`namespace_supervisor_required`; other platforms use `platform_unsupported`.
Request validation and recipe refusals can precede these reasons. A populated
cache cannot enable an unavailable supervisor in `Verified`.

This is an unavailable qualification capability, not working automatic isolation.
No passing test should be presented as proof of native sandbox enforcement.

`Evaluate` is the only consumer path for admission: plans, direct
profiles, dry runs, real launches and reattach all evaluate here. It accepts an
immutable caller-supplied native artifact snapshot, hashes it in bounded chunks,
and checks cancellation during hashing, cache contention and immediately before
approval. It never opens `Request.Binary`, including FIFOs, symlinks or
credential paths. Without a snapshot it returns `artifact_snapshot_required`.
Literal caller args return `unversioned_invocation`; scripts return
`runtime_closure_unsupported`. A native file header identifies a container
format, not a resolved dependency closure. Fresh qualification still requires a
supervisor's runtime audit. `Lookup` and `Verified` are low-level,
non-authorizing helpers that enforce the same guards but never admit an
unqualified build.

The canonical adapter BuildID is `sha256-` followed by 64 lowercase hex digits.
`BuildID` validates this encoding and `Decision.BoundIdentity` constructs the
shared `binding.AdapterIdentity` for every admission (qualified and
unqualified). This encoding satisfies the existing hosted identity alphabet.
Profile digests retain their existing `sha256:` encoding. Old vendor labels and
obsolete colon-prefixed adapter BuildIDs are never silently rewritten on
resume; equality refuses a changed identity. Upgrade through a new launch.

A strict example uses a registered vendor line with independently qualified
artifact bytes and provenance (the snapshot and approval below are external
inputs from independent qualification, never derived from a version label):

```go
req := adapterprobe.Request{
    Adapter: adapterprobe.Identity{
        Adapter: "generic-env-v1", Harness: "claude-code", Entrypoint: "exec",
    },
    Artifact: approvedNativeSnapshot, // independently qualified bytes, immutable during the call
    Recipe: "claude-exec-v1",
}
policy := adapterprobe.Policy{
    Mode: adapterprobe.Strict,
    Allowlist: []adapterprobe.AllowedBuild{{
        Adapter: req.Adapter, BuildID: approvedContentBuildID, // exact digest approval from independent qualification
        Recipe: req.Recipe, Platform: approvedPlatform,
        Scope: adapterprobe.TransportScope,
    }},
}
decision, err := adapterprobe.Evaluate(ctx, req, policy)
```

The allowlist is a trusted host input. Its digest must identify the actual
independently qualified artifact. Hashing a currently installed binary and
attaching a historical version's evidence does not create an approval. A real
launch must execute the same approved snapshot from protected staging or an
immutable descriptor; rehashing a pathname alone does not bind hash to exec.

The default policy is optimistic option C: a known vendor line without
evidence runs as unqualified with its visible provenance and fail-closed
known-bad check, not as a refusal awaiting fresh qualification. Strict
(including sensitive profiles) refuses unknown builds and never consults a
cache for a positive. A pin is an admission constraint, not a qualification:
a missing or different pin refuses before every allowlist or evidence hit,
and a matching pin alone never qualifies. All refusals prohibit unmanaged
fallback.

## Recipes and adapter attribution

A recipe is a shared, revisioned capability contract, not arbitrary argv.
It binds harness and entrypoint, fixed literal stimulus, intended request kind
and target, and any safe private fixtures. A revision changes when stimulus,
fixtures, applied patch or scope changes. Private fixtures may contain synthetic
values only and refer solely to newly created runtime paths. Operator auth,
configuration and symlinks into the operator HOME are prohibited.

The production registry carries only real vendor lines; distinct fake HTTP
and CONNECT recipes exist only in tests to exercise the evidence seam end to
end. Authentication-gated vendor recipes return
`credential_free_recipe_unavailable`, unresolved runtime layouts return
`runtime_closure_unsupported`, and hosted protocol stimuli return
`protocol_recipe_unsupported`. These are inconclusive setup outcomes. No
supported automatic recipe for a real vendor harness is claimed.

Only `generic-env-v1` is accepted. Specialized or arbitrary adapter names return
`adapter_unsupported`; a generic observation cannot approve `codex-env-v1` or
`muse-env-v1`. Results carry the applied adapter tuple, recipe and the narrow
`generic-proxy-transport-v1` scope. Specialized adapter, hook, MCP and hosted
child authorization remain separate mandatory gates.

## Evidence cache and sink

The legacy disk-cache argument returns `persistent_cache_unsupported` before
opening or modifying anything (strict policy ignores it). Arbitrary storage
cannot generically promise deadline-bounded reads, fsync, owner checks and
protection from same-user probes. No implicit state directory is used.

The bounded process-local `Cache` uses **only binary SHA-256 as its primary key**.
Adapter, recipe, platform, containment revision and negative-probe budget are
checked as evidence constraints. Each entry is HMAC authenticated with a fresh
caller-supplied synthetic cache secret; fields and observation semantics are
validated independently. There is no public insertion or deserialization API.
The current probe issues no cache evidence; cache mechanics are exercised only
with private test fixtures, pending a trusted supervisor.

Positive transport evidence has no TTL. Only a completed intended operation
with no proxy attempt can be negative conformance evidence, with a default TTL
of one minute. Early exit, auth gates, start/calibration/isolation/cleanup errors,
caller cancellation and all deadline failures are never cached. Negative reuse
requires the same recipe, platform, containment and budget. Expired negatives
are compacted; bounded eviction admits new artifacts without permanent cache
capacity failure. Cache locks are instance-local and cancellable. Evaluation
never mutates entries and returns a copy of observations.

The internal sink requires a fresh 256-bit per-probe secret through
Proxy-Authorization before recording anything. It additionally matches the
recipe's exact intended request, excluding startup telemetry. A future supervisor
must keep that secret inaccessible through argv, logs, process inspection and
untrusted cache state. Requests get 407 without the secret or 502 with it; no
upstream connection or tunnel exists. Observations retain only CONNECT or
absolute-URI kind and a validated host:port. Paths, bodies, headers, query,
credentials, argv and output never enter evidence. The handler does not inspect
bodies; the HTTP server may buffer or discard input while closing connections.

Fake clients reject all destinations except the exact supplied numeric loopback
endpoint **before DNS**. Missing proxy settings and bypass rules therefore fail
without direct egress. Tests start no harness processes and access no Keychain.

## Requirements for a future execution backend

A native supervisor is required before any fresh harness execution is enabled:

- Enforce child descriptor closure before exec; retain only intentional stdio
  and internal launch handles, with CLOEXEC. Never close arbitrary parent FDs.
- Copy and hash the executable in a private 0700 staging directory, make the
  verified object immutable to the child, and execute that object. Resolve and
  identify runtime dependencies; otherwise return Unsupported.
- On macOS use default-deny file and IPC permissions. Deny real-home reads,
  user/system Keychain stores, and all credential broker Mach services, including
  `com.apple.SecurityServer`, `com.apple.securityd.xpc` and
  `com.apple.securityd.systemkeychain`. The source contains a restrictive profile
  specification, not a calibrated native implementation. No real-home executable
  or Python installation read exception is acceptable.
- On Linux require a verified user/mount namespace with no operator HOME,
  credential mounts, ambient process interfaces or inherited sockets, plus IPC
  and network confinement. An environment change or network namespace alone is
  insufficient. Namespace setup is outside this package; absent it, refuse.
- Permit outbound traffic only to the numeric sink endpoint. Deny other loopback
  relays, DNS and brokered egress. No host network configuration or sudo.
- Own process-tree identity through termination and reap. Disallow detachment
  or contain all descendants. Never signal a numeric PGID after its ownership is
  released. Finish and check cleanup before issuing evidence.
- Bound every open/read/write, calibration, launch, wait, contention and cleanup
  step. Return sanitized cleanup failures and never cache a positive after them.
- Calibrate using disposable fixtures and injectable controls. A malformed or
  ineffective profile must fail tests, not become a conditional skip. Do not
  retrieve real Keychain data or contact external services for calibration.

These prerequisites have not been implemented by the generic Go launcher.

## Historical transport evidence

The following records are a historical evidence index, **not a digest allowlist**.
No artifact SHA-256 provenance is available here. They cannot populate
`AllowedBuild` until the exact selected artifact is independently qualified.
The older manual methodology is not an approved credential-free automatic
recipe. No new real harness runs were performed for this rework.

| Historical artifact label / entrypoint | Observed scope | Remaining limits |
| --- | --- | --- |
| Claude Code 2.1.287 / `claude -p` | API-target CONNECT routing; lowercase/uppercase proxy variants; six-value MCP inheritance and explicit env | All model-turn rows stopped at login; authenticated turns, fallback, hooks and tools unverified. Socket sampling observed zero non-loopback sockets in 22 samples. |
| codex-cli 0.159.0 / `codex exec` | Model WS/HTTPS routing and proxy-preserving WS fallback; explicit six-value MCP env | Automatic MCP inheritance failed; requires `codex-env-v1`. Turn rows timed out after 30 seconds; later retries, companion runtime, hooks and tools unverified. 315 samples observed no non-loopback sockets. |
| Muse 1.4.1-R4503.1 and 1.4.2-R4684.1 / exec and launcher | Launcher update proxy routing and model-catalog CONNECT routing, separately per build | MCP inheritance failed on both; `muse-env-v1` requires per-server env injection and hook wrapping. Two-value MCP mitigation and detailed hook evidence cover only 1.4.1; shell/tool scope remains unverified. |

Muse model-catalog observations are not completed model turns. Historical rows
using authentication fixtures cannot establish an empty-HOME credential-free
recipe. Socket sampling does not rule out short-lived or blocked direct attempts.
Imported external-denial controls are historical observations, not instructions
to repeat external probes. All broader unverified scopes remain refused.
