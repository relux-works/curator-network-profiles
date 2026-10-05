# Changelog

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
