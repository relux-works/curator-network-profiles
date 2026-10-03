# Track: network profiles

Status: **DRAFT**, 2026-09-27 (command names updated to the adopted command-line shape). Specification: `spec/network-profiles.md` (draft, N1–N14, two independent reviews folded in). Roadmap: milestone M7, after agents-infra is archived (operator decision 2026-09-23: network after launch profiles).

## Why

Several agents on one machine must reach the network through different application-level egresses (VPN A, VPN B, a corporate proxy). None of this may change the orchestrator, sibling agents or the operating system.

## What we are building

- A library `curator-network-profiles` (own public repository; consumed by task-board and the public `curator-run`): resolve → validate → conditional probe → patch; direct and plans/dry runs skip all probes (tcp/connect/tls = `skipped`).
- `--network <name>` on `curator run` and `task-board spawn` (`task-board claude|codex` are aliases of `curator run`); defaults from the operator layer (agent selection) and runtime bindings; the machine's network profiles in `~/.curator/network.toml`, managed with the Curator provider `curator-network` (`curator network list|show|add|remove|check [--probe]|confirm|exec`).
- The patch is applied by the host that creates the process (`unset` then `set` for proxy profiles; direct is unset-only with no set), never through a shared environment; bindings are compared by digest; a resume under a changed profile is refused.

## Milestones

| Step | Delivers | Done when | Tracking |
| --- | --- | --- | --- |
| N-A | library, the file `~/.curator/network.toml`, the provider `curator-network` with `curator network exec <name> -- <cmd>` and `check --probe`, contract appendix (digest, `EnvPatch`, equality) | two manual launches use two egresses | landed (slice A, 2026-10-01) |
| N-B | `curator run --network` | the launcher applies the patch through this library | N-B |
| N-C1a | explicit profile on task-board subagent spawn paths, run manifests; depends on D4 + v0.2.0 only | a child uses the profile, including retry and resume | N-C1a; D4 |
| N-C1b | explicit profile on session-host process paths; after M3 / LP Phase 0 | a board session uses the profile, including resume and host reuse | N-C1b |
| N-C2 | defaults from the operator layer, runtime bindings and the project | spawns get their egress without a flag | N-C2 |
| N-D | managed gateway (sing-box), then the enforced sandbox epic | automatic proxy provisioning | N-D |

## Integration

How each process owner applies the patch, where the binding is recorded, and how a resume under a changed profile is refused: `docs/integration-contract.md` (rev 2 adopted 2026-10-02; consumer implementation remains DRAFT; review closed 2026-10-01T16:00Z). The normative digest, `EnvPatch` and equality rules are in `spec/contract-appendix.md`, delivered with N-A.

## Dependencies

Per the operator decision (2026-10-02 07:21Z), N-C1 is split: N-C1a (subagent spawn) needs the typed launch-plane hook (D4) + v0.2.0 only; N-C1b (session hosts) follows M3 / LP Phase 0. Network-profile consumers get priority after the operator's higher-priority items. N-C2 needs M4 (operator layer and bindings). The Apiary tool bridge must keep its own transport outside the harness's profile (NP-N11).

Launch-plane tracking for N-B / N-C1a (exact tuples and scope limits: `docs/integration-contract.md` §2.1):

- **Claude transport support:** allowlist `claude-code` 2.1.287 / exec (`claude -p`) with `generic-env-v1`; authenticated turns, hooks, tool children and interactive mode remain unverified.
- **Codex adapter:** implement required `codex-env-v1` for `codex-cli` 0.159.0 / exec: generic patch plus per-server MCP env injection, under the operator's priority; until it exists, `--network` refuses Codex (`network_scope_unsupported`).
- **Muse adapter:** implement `muse-env-v1` for Muse 1.4.1-R4503.1 / 1.4.2-R4684.1 after the typed launch-plane hook (D4): per-server MCP env injection and hook-command wrapping; shell/tool-child gap remains R7b shell/tool-child verification.

## Repository

This repository, `curator-network-profiles` (created 2026-09-24, renamed from curator-network the same day; prepared for public release as v0.2.0 with a fresh history). The draft specification is `spec/network-profiles.md`.
