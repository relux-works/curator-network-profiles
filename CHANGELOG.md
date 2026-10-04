# Changelog

## Unreleased

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
