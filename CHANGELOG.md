# Changelog

## v0.3.1 (2026-10-06)

- Add `pkg/adapterprobe` policy evaluation over caller-supplied native
  snapshots, compatible content BuildIDs, versioned recipe and adapter
  scope, authenticated loopback sink primitives and bounded
  process-local evidence. Fresh execution and persistent caches return
  typed Unsupported until a trusted supervisor can enforce credential,
  descriptor, runtime and cleanup isolation.
- Add option-C adapter build policy: `Evaluate` is the only consumer
  path for admission and returns qualified for exact allowlisted or
  evidenced builds, unqualified with a typed provenance record for new
  builds of known vendor lines, and refused with a typed reason
  otherwise. A content pin is an admission constraint, never a
  qualification on its own. Consumers must show the exact operator text
  at launch and store the provenance beside the network record in the
  session envelope.
- Add the optional profile declaration `sensitive_egress = true`:
  adapter policy defaults to strict for such profiles with no
  downgrade to optimistic; only exact allowlisted builds run. The
  declaration is digested when true and needs `confirm`; explicit
  false is identical to absence and digests without the declaration are
  unchanged. Strict catalog readers reject a catalog carrying the field
  until upgraded; strict `show --json` decoders must allow the additive
  key; use keyed `netprofile.Input` and `netprofile.Profile` literals.
  See the [migration notes](README.md#upgrading-for-sensitive-egress).
- Add the fail-closed known-bad check by binary SHA-256: a shipped
  embedded list (currently empty, always enforced) plus a shared loader
  for the optional operator file `adapter-knownbad.json`
  (`relux-adapter-knownbad-v1`). Matches refuse with `known_bad_build`;
  an unreadable, corrupt or unknown-version list refuses instead of
  passing. Cache keys stay binary-SHA-256-only.
- Add `Decision.BoundIdentity` for admitted decisions and the
  profile-aware hosted verifier `VerifyAdapterWithProfile`, so the
  destination evaluates its own resolved profile snapshot without a
  second catalog read. `hosted.Options` gains the new callback field,
  breaking positional struct literals: use keyed literals. `Lookup` and
  `Verified` are low-level, non-authorizing helpers. Document consumer
  duties and exact artifact provenance; preserve historical vendor
  evidence without treating version labels as digest approvals.

## v0.3.0 (2026-10-05)

- Add strict operator-local `[bindings.profiles]` defaults and optional
  `resolve.Request.CuratorProfile`; selection now orders explicit, inherited,
  runtime default, profile binding, project default and operator default.
  Records include the additive `profile-binding` origin with unchanged
  profile digests, binding equality and schema identifiers. Reserved path
  bindings refuse as unsupported; unknown targets fail without fallback.
- Add guarded `bind` / `unbind` operator commands with confirmation prompts,
  catalog locking, atomic writes and backups; include bindings in `list` and
  `show` human/JSON output. Add parsing, precedence, provenance and atomicity
  coverage and generated contract vectors.
- Migration: use keyed `resolve.Request` and `netprofile.File` literals;
  update strict `list` / `show` JSON decoders for the always-present `bindings`
  field under the existing v1 schemas. Bindings come only from the destination
  operator catalog. Upgrade all readers before adding them; rollback requires
  removing the entire bindings table, including empty headers. The current
  `hosted.Carrier` v1 cannot carry `profile-binding`; preserving that origin
  requires a separately specified, versioned integration. See the
  [binding migration notes](README.md#upgrading-for-operator-profile-bindings).

- Add `pkg/hosted` with a closed, bounded network carrier and canonical encoder,
  destination resolution and digest checks, mandatory local adapter verification,
  optional bounded preflight, sanitized binding records, final environment
  application and strict reattach checks. Existing public APIs are unchanged.
- Document host integration duties and the continuing hosted capability gate in
  `docs/hosted.md`, including frozen outer payload `1.0.0` with `network:null`
  and separately negotiated revisions; reuse existing environment golden vectors
  and cover decoder, authorization, direct profiles, drift, adapter equality and
  loopback preflight.
- Validate carrier lexical bounds before schema/version dispatch and recognized
  shape checks; distinguish malformed dispatch from unsupported identifiers.
  Cover dispatch ordering and the inclusive 2048-byte input limit.
