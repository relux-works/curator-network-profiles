# Hosted network bindings

`pkg/hosted` is a read-only, exec-free boundary using the standard library and
existing module packages. It does not advertise hosted support. The host must
negotiate enforcement and independently verify the exact adapter/harness/build/
entrypoint and child scope; existing Claude exec evidence does not cover PTY/RC.

The managed `network` member has exactly five required strings: `schema` =
`urn:relux:task-board:network-binding`, `schema_version` = `1.0.0`, `ref`,
`origin` = `explicit|inherited|runtime|project|operator`, and `expected_digest`
= `sha256:` plus 64 lowercase hex digits. References satisfy netprofile and
pinned Curator identifier rules (lowercase, ≤63 bytes, no trailing dot or DOS
device name). `DecodeCarrier` accepts at most 2048 bytes, including whitespace.
It checks JSON syntax, duplicates (including nested objects), UTF-8 and EOF
before dispatching on required, nonempty schema/version string identifiers
(printable ASCII without spaces). Unsupported identifiers refuse before shape
validation; the recognized schema rejects unknown fields, nulls and wrong types.
`EncodeCarrier` emits compact JSON with keys in byte order. JSON methods use
these same checks. An outer `*Carrier` represents `network:null` as nil; skip
resolution for unmanaged launches. Constants version only the network member.
Outer payload `1.0.0` remains frozen and requires `network:null`; carrying a
non-null member requires a separately published, pinned and negotiated outer
revision with the corresponding control-version and capability changes.
Outer `1.1.0` and capabilities `launch-plan/1.1.0` and `network-binding/1.0.0`
are proposals, not currently supported values.

`ResolveForHost(ctx, carrier, Options)` returns a volatile `binding.Binding`
and sanitized `binding.Record`. Supply trusted absolute `OperatorHome`,
`Identity` and mandatory `VerifyAdapter`; never use child HOME or caller tuple.
`LoadCatalog` defaults to `catalog.Load` with only this HOME; `LoadLedger` can
supply a separate trusted confirmation store. Nil `Allowlist` allows catalog
entries; empty non-nil denies all. `RequiredAssurance` defaults to cooperative;
enforced refuses. Supply independently verified `EngineHosts` and `EnvNames`.
The adapter defaults to Generic and must match Identity. Tuple members are
nonempty tokens of ≤128 letters/digits/dot/underscore/plus/hyphen.

The carried ref is authorized without destination-default substitution, then
digest, adapter and env conflicts are checked before optional preflight. Record
origins translate to existing `*-default` vocabulary. Set `Preflight=true` only
for real starts/restarts; direct always skips. The default is `probe.Dialer`,
with a three-second timeout capped at 30 seconds and the earlier caller deadline.
Custom dependencies must honor context. Targetless proxies prove TCP only;
targets require CONNECT and verified TLS. Record keeps only statuses and UTC
time; raw endpoint/target/detail/status code/patch never enter it. Refusals
return zero outputs with existing network codes and fixed diagnostic prose.

Reject reserved mixed-case proxy names with `ValidateEnvNames` for all managed
replay/overlays. Suppress stale owned proxy literals and check literal/name
disjointness in the host. Apply `ApplyFinal` immediately before every child,
client, preflight and assay start, after all overlays/home rewrites. It removes
HTTP/HTTPS/ALL/FTP/NO_PROXY in every case, preserves untouched order and appends
the fresh set LAST. Direct sets nothing; zero Binding preserves unmanaged env.
Never overlay afterward. Persist only Record; inputs/global env are unchanged.

For live attach/restore/startup reconciliation, re-resolve the original stored
ref with current authorization, disable preflight, then `CheckReattach`.
Equality uses digest, all four tuple members and assurance, excluding aliases,
origin and probe facts. The existing EventReattach contract refuses same-ref
digest drift as `network_profile_drift` and other differences as
`network_scope_unsupported`; no rerouting or managed/unmanaged adoption occurs.

Transport owners map malformed carriers, including missing, empty or malformed
dispatch identifiers (`network_configuration_conflict` here), to
`launch_plan_invalid`, and unsupported schema/version
(`network_scope_unsupported` here) to `session_host_protocol_unsupported`.
Exit codes belong to transport. Transport specifications currently disagree on
drift exit 1 versus 16; reconcile the authoritative registry before activation.
Host allocation/lifecycle gates, startup guard, closed durable
record decoding, final native-boundary verification and capability
advertisement remain the daemon's responsibility.
