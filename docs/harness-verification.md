# Harness network verification

Verification is specific to **(harness, build, entrypoint)**. A launcher using curl
does not certify the harness's model client, MCP servers, hooks, or tool children.
Record each reachable transport separately. Missing evidence leaves that scope
`network_scope_unsupported`; a blocked row is neither a pass nor a failure.

## Safety and detector

Never change the host network: no networksetup, scutil, route, ifconfig, pfctl,
DNS/hosts edits, sudo, system proxy, TUN, VPN, WireGuard, or sing-box operations.
No external probes, forwarding proxies, real credentials, login, or keychain
access. Detector calibration uses only the local sink; no external destination
is probed, even under the sandbox.
Stop an authentication-gated row as **needs login (Ivan's approval)**. Do not
work around authentication. Do not push, post, or spawn agents.

Use a new temporary HOME, CLAUDE_CONFIG_DIR, CODEX_HOME, all XDG directories,
TMPDIR, and working directory for every row. Construct the environment from an
allowlist; do not inherit credential variables, SSH sockets, or runtime settings.
Never read/write the operator's `.claude`, `.codex`, `.curator`, `.config`, or
other configuration. Executing the installed binary inside `.codex/packages`
is allowed: only that literal executable gets a read exception. File rules deny
all writes to the operator HOME and all other reads there, except Python's code
installation if needed. Keychain files and securityd access are denied too.

Supply the prebuilt `internal/testproxy/cmd/loopback-proxy` binary with
`--sink <absolute path>`. The helper performs no build and uses no build lock.
Start with `--id S --addr-file <temp>/sink.addr`,
**without any `--target`**. It binds `127.0.0.1:0`, records method/target on
stderr, returns 502 for CONNECT and ordinary upstream requests, and answers
absolute-URI `.invalid` GETs locally. With no target map it never forwards,
including to a fake upstream. Run it under the sandbox as an extra safeguard.

The complete profile template used by the helper follows. Substitute the three
file paths; omit the Python allowance when Python is outside the operator HOME.
The helper archives the exact rendered profile for every attempt.

```scheme
(version 1)
(allow default)
(deny network-outbound (with send-signal SIGKILL))
(allow network-outbound (remote ip "localhost:*"))
(allow network-outbound (remote unix-socket))
(deny network-outbound (literal "/private/var/run/mDNSResponder") (with send-signal SIGKILL))
(deny network-outbound (literal "/var/run/mDNSResponder") (with send-signal SIGKILL))
(deny mach-lookup (global-name "com.apple.securityd"))
(deny file-read* file-write* (subpath "<operator HOME>"))
(allow file-read* (literal "<resolved harness executable>"))
(allow file-read* (subpath "<Python code installation>"))
(deny file-read* file-write* (subpath "/Library/Keychains"))
```

First activate the profile with `sandbox-exec -f <profile> /usr/bin/true`
and start the prebuilt sink. For the negative control, append this rule to a
**separate calibration profile**, using the sink's ephemeral port:

```scheme
(deny network-outbound (remote ip "localhost:<sink port>") (with send-signal SIGKILL))
```

Run `nc -n -z -w 2 127.0.0.1 <sink port>` under that calibration profile;
it must die with SIGKILL (137, Python returncode -9). Run the same loopback
command under the original profile; it must exit 0. Archive both profiles.
This checks signal delivery and loopback permission without probing a real
network host. It does not empirically calibrate an external destination; the
original profile's blanket outbound deny provides that confinement.

Any other result stops verification before a harness is launched. Unified-log
denials were invisible on this host; their absence is not evidence. The new
detector's signal is the killed process, not a denial count. Distinguish sandbox
SIGKILL from a supervisor killing an overlong row. Check child-death messages as
well as the root exit: a parent can survive a killed child. Socket sampling can
miss short-lived children; no observed socket alone never certifies confinement.

## Patch and rows

After constructing the clean environment, seed hostile ambient values, including
`HTTPS_PROXY=http://127.0.0.1:9`, `NO_PROXY=*`, and mixed-case HTTP/FTP/ALL_PROXY
spellings. Apply generic-env-v1 **after** this seed:

1. Remove every name equal, case-insensitively, to HTTP_PROXY, HTTPS_PROXY,
   ALL_PROXY, FTP_PROXY, or NO_PROXY.
2. Set HTTP_PROXY, HTTPS_PROXY, http_proxy, https_proxy to the sink URL.
3. Set NO_PROXY and no_proxy to `127.0.0.1,::1,localhost`.

ALL_PROXY and FTP_PROXY are not set. Compare the six values literally in the
parent and child dumps; reject additional reserved spellings or surviving
hostile values. Keep the proxy pointed at the sink for every harness launch.

| Row | Setup | Pass criteria / interpretation |
|---|---|---|
| R0 | Offline/no-provider control, patched, sandboxed | Control completes with no observed SIGKILL or non-loopback sockets and normally zero sink requests. `--version` checks startup only; it does not replace an offline turn control. |
| R1 | A reachable own-client operation; live sink | Own-client request appears at sink, no observed SIGKILL/non-loopback sockets. Record handling of 502. Record API-target routing separately from an authenticated model operation; auth refusal leaves that model scope unverified. |
| R2 | Same operation as R1; stop the sink and use 127.0.0.1:9 | Client reports connection refusal, with no observed SIGKILL/non-loopback sockets: no observed direct fallback on this path. If R1 did not exercise the client, R2 cannot certify fallback behavior. |
| R3 | Informative variable coverage: lowercase-only, uppercase-only, ALL_PROXY-only | After scrubbing hostile values, retain only the variant's proxy variables, all pointing at the same sink, plus loopback-only NO_PROXY/no_proxy. Record which variants reach the sink. A client requiring ALL_PROXY needs an adapter beyond generic-env-v1. |
| R4 | MCP stdio env-dumping stub; inherited environment | Stub starts and receives all six exact values, no extra reserved spellings/hostile values. No dump is blocked/unverified, not an inheritance failure. |
| R4b | Same stub with all six values in its server `env` block | Explicit values arrive; report this mitigation separately from R4. Do not treat it as evidence of automatic inheritance. |
| R5 | lsof samples of harness and descendants, about every 0.5 s | No observed non-loopback sockets; record sampling gaps/errors. Combine with calibrated sandbox and signal evidence. |
| R7 | Hooks and tool children where reachable without login | Separate env dump and transport evidence for each child type; MCP results do not cover them. |

## Helper and evidence

`scripts/verify-harness.sh` runs one command per invocation. It starts the
prebuilt sink, calibrates on loopback, applies the patch, creates MCP fixtures,
and launches the installed executable under sandbox-exec. There is no build,
shared lock, or operator-config access in the run path.

Examples (use a **new** evidence directory each time):

```sh
scripts/verify-harness.sh --sink "$SINK" \
  --output-dir "$EVIDENCE/claude-R4" --mcp-mode inherit -- \
  "$(command -v claude)" -p 'say hi' \
  --mcp-config '{mcp_json}' --strict-mcp-config

scripts/verify-harness.sh --sink "$SINK" \
  --output-dir "$EVIDENCE/codex-R4b" --mcp-mode explicit -- \
  "$(command -v codex)" exec --skip-git-repo-check 'say hi'
```

`{mcp_json}` is replaced with the private Claude configuration path. The helper
writes Codex's private `CODEX_HOME/config.toml`. The tiny stdio MCP script writes
its full environment before answering initialize/tools/list; its dump filename
is embedded in the script, so an env allowlist cannot hide the destination.
`--mcp-mode explicit` adds all six patch values to the server entry. R2 uses
`--proxy-state unreachable`, which stops the sink and sets the proxy to
`http://127.0.0.1:9`, as required for round 2.
R3 uses `--proxy-vars lowercase`, `uppercase`, or `all`; the default is `generic`.
Coverage variants cannot be combined with MCP inheritance rows.
`--timeout` bounds the row (default 30 s); auth messages stop it immediately.
`VERIFY_PYTHON=/safe/path/python3` selects an existing interpreter if the system
Python launcher is unavailable. The shell does not source operator profiles.

Signal handlers and `finally` cleanup terminate supervised processes and remove
private HOME/configs and the runtime tree; the supplied sink binary is retained.
The evidence directory is retained with mode 0700; all env dumps originate from the clean allowlist.
The helper's nonzero exit may be a **helper/prerequisite error**, not a harness
exit. Check `summary.json` before interpreting it.

Record:

- UTC time, resolved binary/build (`--version` under the same protection), full
  argv/entrypoint, adapter, and exact sandbox/calibration result.
- Seed and applied patch, parent env, MCP configs, full stub env and verdict.
- Harness stdout/stderr and exit; helper errors and auth/timeout stops separately.
- Sink method/target lines and counts, root/child SIGKILL evidence and any
  supervisor-generated SIGKILL separately.
- Sampled descendant PIDs, lsof lines, non-loopback observations, and sampling
  gaps; use **not observed** only after a row actually ran.
- One-line behavior and pass/fail/blocked status for every row, including rows
  that need Ivan's login approval. No row below authorizes a real egress check.

## Results, round 2, 2026-10-02

Executed 16 sandboxed commands from **08:50:15Z to 08:55:52Z**: two version
checks and seven requested rows per harness. Every loopback deny control exited
137 and every allow control exited 0. No helper, cleanup, or lsof sampling errors
occurred. There were **337 lsof samples**, no observed non-loopback sockets,
no root sandbox SIGKILL, and no child-death messages. Sampling is observational;
the sandbox protects descendants even when their lifetime escapes a sample.

Raw evidence is retained privately outside Git, with one directory per table row. Each contains full argv, UTC start,
parent env, patch seed/result, MCP configs, profiles, stdout/stderr, sink lines,
and lsof samples; R4/R4b also contain the full child env dump.

### Claude Code 2.1.287 / `claude -p`

Confirmed by sandboxed `--version`: `2.1.287 (Claude Code)`. Installed launcher
resolved to `<install dir>`.
Entrypoint: `claude -p "say hi" --mcp-config <temp json> --strict-mcp-config`.
All turn rows stopped on `Not logged in · Please run /login` with exit 1;
no login was attempted. The configured stdio MCP stub starts before that gate.

| Row | Exit | Sink lines | Sandbox SIGKILL | Non-loopback sockets / samples | Env dump | Verdict / behavior |
|---|---|---|---|---|---|---|
| R0 startup | 0 | 0 | No | 0 observed / 2 | N/A | PASS startup/version only. |
| R4 | 1 | 1 × `CONNECT api.anthropic.com:443` | No | 0 observed / 6 | PASS | PASS inheritance; login stop. |
| R4b | 1 | 1 × `CONNECT api.anthropic.com:443` | No | 0 observed / 4 | PASS | PASS explicit env; login stop. |
| R1 | 1 | 1 × `CONNECT api.anthropic.com:443` | No | 0 observed / 3 | PASS (extra stub) | PASS API-target proxy routing; model turn needs login. |
| R2 | 1 | 0 | No | 0 observed / 1 | PASS (extra stub) | Login exit; no observed fallback, transport refusal unverified. |
| R3-lowercase | 1 | 1 × `CONNECT api.anthropic.com:443` | No | 0 observed / 2 | variant PASS | PASS variable coverage; login stop. |
| R3-uppercase | 1 | 1 × `CONNECT api.anthropic.com:443` | No | 0 observed / 2 | variant PASS | PASS variable coverage; login stop. |
| R3-all | 1 | 1 × `CONNECT api.anthropic.com:443`<br>1 × `POST https://api.anthropic.com/api/event_logging/v2/batch` | No | 0 observed / 2 | variant PASS | PASS variable coverage; login stop. |
| R5 aggregate | — | — | None observed | 0 observed / 22 | N/A | PASS sampled sockets; short-lived children can be missed. |

Proposal: **generic-env-v1 OK** for the observed API-target transport and stdio
MCP inheritance. A sink CONNECT proves routing to the API target, not an
authenticated model request. R2 did not expose a transport-refusal message;
authenticated turn/fallback and hook/tool scopes remain unverified.

### codex-cli 0.159.0 / `codex exec`

Confirmed by sandboxed `--version`: `codex-cli 0.159.0`. Installed launcher
resolved to `<install dir>`.
Entrypoint: `codex exec --skip-git-repo-check "say hi"`; the extra flag permits
the fresh temporary working directory. Only R4/R4b define the temporary
`CODEX_HOME/config.toml` MCP server. No authentication or operator config is
inherited, and no login prompt was observed.

| Row | Exit | Sink lines | Sandbox SIGKILL | Non-loopback sockets / samples | Env dump | Verdict / behavior |
|---|---|---|---|---|---|---|
| R0 startup | 0 | 0 | No | 0 observed / 1 | N/A | PASS startup/version only. |
| R4 | 143 | 2 × `CONNECT chatgpt.com:443`<br>1 × `CONNECT github.com:443`<br>1 × `CONNECT api.github.com:443`<br>20 × `CONNECT api.openai.com:443` | No | 0 observed / 45 | FAIL | FAIL inheritance: all six absent; hostile values absent too. |
| R4b | 143 | 2 × `CONNECT chatgpt.com:443`<br>1 × `CONNECT github.com:443`<br>1 × `CONNECT api.github.com:443`<br>19 × `CONNECT api.openai.com:443` | No | 0 observed / 45 | PASS | PASS explicit env; retry timeout. |
| R1 | 143 | 2 × `CONNECT chatgpt.com:443`<br>1 × `CONNECT github.com:443`<br>1 × `CONNECT api.github.com:443`<br>20 × `CONNECT api.openai.com:443` | No | 0 observed / 44 | N/A | PASS model WS/HTTPS routing; 502 retries, supervisor timeout. |
| R2 | 143 | 0 | No | 0 observed / 45 | N/A | Plain connection-refused errors; no observed fallback through 30 s, supervisor timeout. |
| R3-lowercase | 143 | 2 × `CONNECT chatgpt.com:443`<br>1 × `CONNECT github.com:443`<br>1 × `CONNECT api.github.com:443`<br>20 × `CONNECT api.openai.com:443` | No | 0 observed / 44 | N/A | PASS variable coverage; 502 retries, supervisor timeout. |
| R3-uppercase | 143 | 2 × `CONNECT chatgpt.com:443`<br>1 × `CONNECT github.com:443`<br>1 × `CONNECT api.github.com:443`<br>20 × `CONNECT api.openai.com:443` | No | 0 observed / 46 | N/A | PASS variable coverage; 502 retries, supervisor timeout. |
| R3-all | 143 | 2 × `CONNECT chatgpt.com:443`<br>1 × `CONNECT github.com:443`<br>1 × `CONNECT api.github.com:443`<br>21 × `CONNECT api.openai.com:443` | No | 0 observed / 45 | N/A | PASS variable coverage; 502 retries, supervisor timeout. |
| R5 aggregate | — | — | None observed | 0 observed / 315 | N/A | PASS sampled sockets; short-lived children can be missed. |

The native model client reports `wss://api.openai.com/v1/responses` proxy 502s,
then falls back from WebSockets to HTTPS **through the same proxy**. This is a
transport fallback, not evidence of direct egress. R2 reports `Connection refused
(os error 61)` and keeps retrying. All turns stop at the 30 s supervisor timeout
with SIGTERM/143; no natural terminal error exit was obtained. The bounded R2
observation does not certify retries beyond that interval.

R4's six mismatches are all null; no hostile/reserved extras survived. R4b's six
values match exactly. The first R4/R4b supervisor recorded SIGKILL *attempts* on
already exited zombie roots; actual wait status was SIGTERM/143. The runner now
excludes zombies from descendant sampling and names forced-kill attempts
explicitly. These supervisor attempts are not sandbox-denial evidence.

All Codex turns also warn that the code-mode companion executable could not be
started. Only the selected Codex executable is exempted from operator HOME
reads, so the companion path is inaccessible; this warning does not verify its
presence or absence. Code-mode and tool-child paths are unverified.

Proposal: **needs adapter `codex-env-v1`** (proposed identity): explicit six-value
MCP server env injection. Generic-env-v1 routes the observed model WS/HTTPS and
startup clients; automatic MCP inheritance fails. Hook/tool scopes remain
unverified.

### Imported final D8: Muse / `muse exec` and launcher

Credit: **the verification runner**. Ivan's final decision is **D8 = (A): supported
with `muse-env-v1`**. No Muse process was rerun here.

Source reconciliation (review round 3): the authoritative verification-runner results are
`D8-muse-results-R7.md` and the later R6 SIGKILL
closure in `D8-muse-R6-sigkill-msg.txt` (2026-10-02T05:33:20Z).
The supplied `D8-muse-results.md` and `D8-muse-results-R6.md` are superseded
where they conflict. The round-2 import used stale evidence; its statements
that R6 lacked a per-build split, model target, or numeric exit are superseded.
All results below are imported observations, with no new harness run.

R0, R1, R2 and R4 are reported per build for **1.4.1-R4503.1** and
**1.4.2-R4684.1**; the latter's R0/R1/R2 row is explicitly identical to 1.4.1.
R6 has its own per-build table below. R3's detailed variants and R4b's explicit
MCP env demonstration are on **1.4.1-R4503.1** only. R5 is aggregate across
both builds' R0–R4 observations. R7a's detailed hook setup is **1.4.1** only;
there is no separate 1.4.2 hook run in the file. The SIGKILL message summarizes
R3 as passing on both, but supplies no separate 1.4.2 variant rows; its aggregate
hook failure summary does not extend the detailed hook coverage to 1.4.2.

| Row | Coverage / result | Evidence / mitigation |
|---|---|---|
| R0 | Both builds, PASS | Echo control: exit 0, zero sink requests and non-loopback sockets. |
| R1 | Both builds, PASS | Launcher update: exit 1, two `CONNECT api.meta.ai:443`, zero non-loopback sockets. Curl uses the sink for launcher self-update and the channel manifest; synchronous mode exits on 502. |
| R2 | Both builds, PASS | Launcher update with proxy at `127.0.0.1:9`: exit 1, zero sink requests and non-loopback sockets; curl connection refusal, no direct fallback. |
| R3 | Detailed 1.4.1 variants, PASS; later summary says both PASS | Lowercase-only, uppercase-only and ALL_PROXY-only each reach the sink: exit 1, two requests, zero non-loopback sockets. This tests the launcher's curl, not the binary model client. |
| R4 | Both builds, FAIL as written | MCP child uses `HOME LANG LOGNAME MUSE_SESSION_ID PATH PWD SHELL SHLVL TERM TMPDIR USER`; none of the six set proxy values or hostile ambient values inherit. Exit 0, zero sink requests and non-loopback sockets. |
| R4b | 1.4.1, mitigation demonstrated | Explicit MCP server `env` delivers `HTTPS_PROXY` and `NO_PROXY`. Exit 0, zero sink requests and non-loopback sockets. This is not a six-value dump or a separate 1.4.2 mitigation run. |
| R5 | Aggregate, both builds' R0–R4 | Zero non-loopback sockets sampled; Echo rows have no connection from the Muse binary itself. Sampling and invisible denial logs alone do not prove absence of an attempted direct dial. |
| R7a | Detailed 1.4.1 SessionStart hook, FAIL as written | Offline Echo hook ran with `HOME LANG LOGNAME PATH PWD SHELL SHLVL SSH_AUTH_SOCK TERM TMPDIR USER`; no proxy or hostile values. Claude-compatible object schema has no per-hook `env`; flat `hooks: [...]` is rejected. Hook-command wrapping is required by the adapter, with no verified wrapping run in these sources. |
| R7b | Open, unverified | Echo calls no tools; meta requires a real round trip blocked by the sink. No scripted/replay provider in 1.4.1 or 1.4.2. The TUI `!` escape is a proposed PTY verification path, pending **R7b shell/tool-child verification**; an inferred shell allowlist is not evidence. |

R6 exercises the **binary's own HTTPS client**, with auto-update disabled,
`exec --provider meta --reasoning-effort low`, the same patch and sandbox, and
an isolated XDG tree. The imported run used a temporary auth symlink (removed
after each run); no credential-mutating command was used. The reachable request
is a **model catalog fetch**, `https://api.meta.ai/muse-code/models`; it does not
establish completion of a model turn.

| Build | R6 proxy variant | Exit | Sink | Non-loopback sockets | Result |
|---|---|---|---|---|---|
| 1.4.1-R4503.1 | Reachable sink | 1 | 1 × `CONNECT api.meta.ai:443` | 0 | Model catalog uses the proxy; 502 yields `failed to fetch model catalog: transport error`, no retry or second attempt. |
| 1.4.1-R4503.1 | Unreachable, `127.0.0.1:9` | 1 | 0 | 0 | Plain transport error; later calibrated closure reports no SIGKILL. |
| 1.4.2-R4684.1 | Reachable sink | 1 | 1 × `CONNECT api.meta.ai:443` | 0 | Results file says identical to 1.4.1: model catalog, transport error, no retry. |
| 1.4.2-R4684.1 | Unreachable, `127.0.0.1:9` | 1 | 0 | 0 | Results file says identical to 1.4.1; later calibrated closure reports no SIGKILL. |

**R6 unreachable closure per build:** the results file initially limited this
variant because generic transport errors and invisible denial logs could not
rule out a blocked direct attempt. The later message calibrates the SIGKILL
detector: `nc` to `1.1.1.1:443` exited **137**, direct `curl` to `api.meta.ai`
exited **137**, and `curl` through the dead proxy exited **7**; loopback was
unaffected. With the proxy at `127.0.0.1:9`, **1.4.1-R4503.1 exited 1 with no
SIGKILL**, and **1.4.2-R4684.1 exited 1 with no SIGKILL**, both with the plain
transport error. the integration owner closes R6 as no direct fallback attempt on this path.
These are historical imported controls, not instructions to repeat external
probes. This calibrated closure applies to R6; it does not add SIGKILL
measurements to the other rows.

Proposal: **needs adapter `muse-env-v1`**, as accepted by Ivan: inject the generic
patch's set half into each MCP server's launch-private env and wrap each hook
command with that patch. R4b demonstrates two injected values on 1.4.1, and hook
wrapping remains a required mitigation rather than an observed pass. D8 = (A)
retains these coverage limits and the open shell/tool scope; unverified child
scopes remain `network_scope_unsupported`.
