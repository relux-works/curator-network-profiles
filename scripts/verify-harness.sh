#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# macOS only. One row, one non-forwarding sink, fresh HOME/configs.
# Python supervises descendants and records evidence before removing runtime state.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "${VERIFY_PYTHON:-/usr/bin/python3}" - "$ROOT" "$@" <<'PY'
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

root = Path(sys.argv[1])
parser = argparse.ArgumentParser(description="Run one harness row in a calibrated loopback-only SIGKILL sandbox.")
parser.add_argument("--sink", required=True, type=Path, help="Existing non-forwarding loopback-proxy binary; never built here")
parser.add_argument("--output-dir", required=True, type=Path, help="New directory for credential-free evidence")
parser.add_argument("--timeout", type=float, default=30)
parser.add_argument("--proxy-state", choices=("reachable", "unreachable"), default="reachable")
parser.add_argument("--proxy-vars", choices=("generic", "lowercase", "uppercase", "all"), default="generic",
                    help="R3 coverage variant; every configured proxy still points at the sink")
parser.add_argument("--mcp-mode", choices=("inherit", "explicit"))
parser.add_argument("command", nargs=argparse.REMAINDER, help="After --: absolute executable and arguments")
args = parser.parse_args(sys.argv[2:])
command = args.command[1:] if args.command[:1] == ["--"] else args.command
if not command or not Path(command[0]).is_absolute() or args.timeout <= 0:
    parser.error("Supply an absolute row executable after -- and a positive timeout")
if sys.platform != "darwin":
    parser.error("This helper requires macOS sandbox-exec")
command[0] = str(Path(command[0]).resolve())
python = str(Path(sys.executable).resolve())
if args.mcp_mode and args.proxy_vars != "generic":
    parser.error("MCP inheritance rows require the six-value generic patch")

operator_home = Path(os.environ["HOME"]).resolve()
protected = [operator_home / name for name in (".claude", ".codex", ".curator", ".config")]
protected += [operator_home / ".claude.json", operator_home / "Library/Keychains", Path("/Library/Keychains")]
def below(path, directory):
    return path == directory or directory in path.parents
for path in (args.output_dir.resolve(), args.sink.resolve()):
    if any(below(path, directory) for directory in protected):
        parser.error("Refusing evidence or sink in an operator config/keychain tree")
if not args.sink.is_file() or not os.access(args.sink, os.X_OK):
    parser.error("--sink must be an existing executable; no build is performed")
if args.output_dir.exists():
    parser.error("--output-dir must be a new directory")
args.output_dir.mkdir(parents=True, mode=0o700)
out = args.output_dir.resolve()
runtime = Path(tempfile.mkdtemp(prefix="harness-verification-", dir=os.environ.get("TMPDIR")))
sink = None
row = None
known_pids = set()
summary = {"command": command, "proxy_state": args.proxy_state, "mcp_mode": args.mcp_mode,
           "proxy_vars": args.proxy_vars, "sink_binary": str(args.sink.resolve()),
           "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}

def save_summary():
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

def processes():
    try:
        result = subprocess.run(["/bin/ps", "-axo", "pid=,ppid=,pgid=,stat="], capture_output=True, text=True, timeout=2)
    except subprocess.TimeoutExpired:
        summary.setdefault("sampling_errors", []).append("ps timed out")
        return []
    if result.returncode:
        summary.setdefault("sampling_errors", []).append("ps exit %s" % result.returncode)
        return []
    return [tuple(map(int, fields[:3])) for line in result.stdout.splitlines()
            if len(fields := line.split()) == 4 and not fields[3].startswith("Z")]

def row_pids():
    if row is None:
        return set()
    table = processes()
    current = {pid for pid, ppid, pgid in table if pgid == row.pid or pid == row.pid}
    # Retain descendants even if they detach after an earlier sample.
    current.update(pid for pid, ppid, pgid in table if pid in known_pids)
    while True:
        expanded = current | {pid for pid, ppid, pgid in table if ppid in current}
        if expanded == current:
            break
        current = expanded
    known_pids.update(current)
    return current

def terminate_row():
    if row is None:
        return
    pids = row_pids()
    try:
        os.killpg(row.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 2
    while row_pids() and time.monotonic() < deadline:
        time.sleep(0.05)
    remaining = row_pids()
    if remaining:
        summary["supervisor_sigkill_attempt_pids"] = sorted(remaining)
        for pid in remaining:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    row.wait()

def cleanup():
    terminate_row()
    if sink is not None:
        sink.terminate()
        try:
            sink.wait(timeout=2)
        except subprocess.TimeoutExpired:
            sink.kill()
            sink.wait()
    shutil.rmtree(runtime)

def interrupted(signum, frame):
    raise KeyboardInterrupt

signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
try:
    for name in ("home", "claude", "codex", "config", "cache", "data", "state", "tmp", "work"):
        (runtime / name).mkdir(mode=0o700)
    # No inherited auth variables, agent settings, SSH sockets, or runtime options.
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8",
           "HOME": str(runtime / "home"), "CLAUDE_CONFIG_DIR": str(runtime / "claude"),
           "CODEX_HOME": str(runtime / "codex"), "XDG_CONFIG_HOME": str(runtime / "config"),
           "XDG_CACHE_HOME": str(runtime / "cache"), "XDG_DATA_HOME": str(runtime / "data"),
           "XDG_STATE_HOME": str(runtime / "state"), "TMPDIR": str(runtime / "tmp") + "/"}
    # Executing the installed binary is allowed, including ~/.codex/packages.
    # Only that literal file is exempted from the operator HOME read denial.
    # No operator file is exempted from the write denial.
    profile = '''(version 1)
(allow default)
(deny network-outbound (with send-signal SIGKILL))
(allow network-outbound (remote ip "localhost:*"))
(allow network-outbound (remote unix-socket))
(deny network-outbound (literal "/private/var/run/mDNSResponder") (with send-signal SIGKILL))
(deny network-outbound (literal "/var/run/mDNSResponder") (with send-signal SIGKILL))
(deny mach-lookup (global-name "com.apple.securityd"))
'''
    profile += "(deny file-read* file-write* (subpath " + json.dumps(str(operator_home)) + "))\n"
    profile += "(allow file-read* (literal " + json.dumps(str(Path(command[0]).resolve())) + "))\n"
    # When VERIFY_PYTHON selects a user-installed interpreter, permit its code
    # installation (not the operator's configs) for the MCP stub's stdlib imports.
    if below(Path(sys.base_prefix).resolve(), operator_home):
        if any(below(Path(sys.base_prefix).resolve(), directory) for directory in protected):
            raise RuntimeError("Python code installation is in a protected operator directory")
        profile += "(allow file-read* (subpath " + json.dumps(str(Path(sys.base_prefix).resolve())) + "))\n"
    profile += '(deny file-read* file-write* (subpath "/Library/Keychains"))\n'
    sb = runtime / "loopback-only.sb"
    sb.write_text(profile)
    (out / "loopback-only.sb").write_text(profile)
    sandbox = ["/usr/bin/sandbox-exec", "-f", str(sb)]
    # Parse/activate the profile before the one deliberate, blocked external dial.
    activated = subprocess.run(sandbox + ["/usr/bin/true"], env=env, capture_output=True)
    if activated.returncode:
        raise RuntimeError("Sandbox activation failed: " + activated.stderr.decode(errors="replace"))
    with (out / "sink.stdout").open("wb") as stdout, (out / "sink.log").open("wb") as stderr:
        # No --target: CONNECT always gets 502; no upstream is ever dialled.
        sink = subprocess.Popen(sandbox + [str(args.sink.resolve()), "--id", "S", "--addr-file", str(runtime / "sink.addr")],
                                env=env, stdout=stdout, stderr=stderr)
    deadline = time.monotonic() + 5
    while not (runtime / "sink.addr").exists():
        if sink.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError("Sink failed to become ready")
        time.sleep(0.05)
    endpoint = (runtime / "sink.addr").read_text().strip()
    if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", endpoint):
        raise RuntimeError("Sink endpoint is not loopback")
    # Exercise SIGKILL entirely on loopback. The control adds a deny for the
    # sink port to the otherwise identical profile. No external probe is used.
    port = endpoint.rsplit(":", 1)[1]
    calibration_profile = profile + '(deny network-outbound (remote ip "localhost:' + port + '") (with send-signal SIGKILL))\n'
    calibration_sb = runtime / "calibration.sb"
    calibration_sb.write_text(calibration_profile)
    (out / "calibration.sb").write_text(calibration_profile)
    calibration = subprocess.run(["/usr/bin/sandbox-exec", "-f", str(calibration_sb),
                                  "/usr/bin/nc", "-n", "-z", "-w", "2", "127.0.0.1", port],
                                 env=env, capture_output=True, timeout=5)
    summary["calibration_exit"] = 128 - calibration.returncode if calibration.returncode < 0 else calibration.returncode
    summary["calibration_target"] = "127.0.0.1:" + port
    (out / "calibration.stderr").write_bytes(calibration.stderr)
    if calibration.returncode != -signal.SIGKILL:
        raise RuntimeError("Unsafe detector: loopback deny control must die with SIGKILL (137); no row started")
    allowed = subprocess.run(sandbox + ["/usr/bin/nc", "-n", "-z", "-w", "2", "127.0.0.1", port],
                             env=env, capture_output=True, timeout=5)
    summary["loopback_allow_control_exit"] = allowed.returncode
    if allowed.returncode:
        raise RuntimeError("Loopback allow control failed; no row started")
    # R2 uses the brief's closed loopback port, after stopping the sink.
    if args.proxy_state == "unreachable":
        sink.terminate()
        sink.wait(timeout=2)
        endpoint = "http://127.0.0.1:9"
    summary["endpoint"] = endpoint
    reserved = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY"}
    hostile = {"HTTPS_PROXY": "http://127.0.0.1:9", "NO_PROXY": "*", "Http_Proxy": "http://127.0.0.1:9",
               "all_proxy": "http://127.0.0.1:9", "FtP_PrOxY": "http://127.0.0.1:9"}
    env.update(hostile)
    env = {key: value for key, value in env.items() if key.upper() not in reserved}
    proxy_names = {"generic": ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"),
                   "lowercase": ("http_proxy", "https_proxy"), "uppercase": ("HTTP_PROXY", "HTTPS_PROXY"),
                   "all": ("ALL_PROXY",)}
    patch = {key: endpoint for key in proxy_names[args.proxy_vars]}
    patch.update({key: "127.0.0.1,::1,localhost" for key in ("NO_PROXY", "no_proxy")})
    env.update(patch)
    (out / "patch.json").write_text(json.dumps({"hostile_before": hostile, "set_after": patch}, indent=2) + "\n")
    (out / "parent-env.json").write_text(json.dumps(env, indent=2, sort_keys=True) + "\n")
    stub = runtime / "mcp-stub.py"
    stub.write_text('''import json, os, sys
with open(''' + repr(str(runtime / "mcp-env.json")) + ''', "w") as f:
    json.dump(dict(os.environ), f, indent=2, sort_keys=True)
for line in sys.stdin:
    try:
        message = json.loads(line)
    except ValueError:
        continue
    if "id" not in message:
        continue
    method = message.get("method")
    if method == "initialize":
        result = {"protocolVersion": message.get("params", {}).get("protocolVersion", "2024-11-05"),
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "env-stub", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": []}
    elif method == "ping":
        result = {}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "Method not found"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
''')
    server = {"command": python, "args": [str(stub)]}
    if args.mcp_mode == "explicit":
        server["env"] = patch
    mcp_json = runtime / "mcp.json"
    mcp_json.write_text(json.dumps({"mcpServers": {"stub": server}}, indent=2) + "\n")
    config = "[mcp_servers.stub]\ncommand = " + json.dumps(python) + "\nargs = [" + json.dumps(str(stub)) + "]\n"
    if args.mcp_mode == "explicit":
        config += "[mcp_servers.stub.env]\n" + "".join(key + " = " + json.dumps(value) + "\n" for key, value in patch.items())
    if args.mcp_mode:
        (runtime / "codex/config.toml").write_text(config)
    (out / "mcp.json").write_text(mcp_json.read_text())
    (out / "mcp-config.toml").write_text(config)
    command = [arg.replace("{mcp_json}", str(mcp_json)).replace("{stub}", str(stub)) for arg in command]
    summary["command"] = command
    login = re.compile(r"not logged in|please (?:run .*|log in|login)|(?:missing|no) (?:an? )?(?:api key|authentication)|run (?:/login|codex login)|(?:api key|authentication|login).*(?:is required|required to)|invalid api key.*(?:login|fix external api key)|keychain|securityd", re.I)
    non_loopback = []
    sample_count = 0
    with (out / "row.stdout").open("wb") as stdout, (out / "row.stderr").open("wb") as stderr, (out / "lsof.log").open("w") as sockets:
        row = subprocess.Popen(sandbox + command, cwd=runtime / "work", env=env,
                               stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
        summary["row_pid"] = row.pid
        started = time.monotonic()
        while True:
            pids = row_pids()
            if pids:
                sample_count += 1
                try:
                    sample = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-p", ",".join(map(str, sorted(pids))), "-i"],
                                            capture_output=True, text=True, timeout=2)
                except subprocess.TimeoutExpired:
                    summary.setdefault("sampling_errors", []).append("lsof timed out")
                    sample = subprocess.CompletedProcess([], 1, "", "lsof timed out")
                if sample.stderr:
                    summary.setdefault("sampling_errors", []).append(sample.stderr.strip())
                sockets.write("t=%.3f pids=%s\n%s" % (time.monotonic() - started, sorted(pids), sample.stdout))
                sockets.flush()
                for line in sample.stdout.splitlines()[1:]:
                    # Include listeners/wildcards as unexpected; filter only explicit loopback endpoints.
                    addresses = re.findall(r"(?:\[[^]]+\]|[0-9.]+|\*):[0-9*]+", line)
                    if not addresses or any(not address.startswith(("127.", "[::1]:")) for address in addresses):
                        non_loopback.append(line)
            output = (out / "row.stdout").read_text(errors="replace") + (out / "row.stderr").read_text(errors="replace")
            if login.search(output):
                summary["needs_login"] = True
                summary["stop_reason"] = "needs login (Ivan's approval)"
                break
            if row.poll() is not None:
                break
            if time.monotonic() - started >= args.timeout:
                summary["stop_reason"] = "supervisor timeout"
                break
            time.sleep(0.5)
    if row.poll() is None:
        terminate_row()
    returncode = row.wait()
    summary["exit"] = 128 - returncode if returncode < 0 else returncode
    summary["root_sigkill"] = returncode == -signal.SIGKILL
    summary["duration_seconds"] = round(time.monotonic() - started, 3)
    summary["lsof_sample_count"] = sample_count
    summary["child_death_messages"] = [line for line in output.splitlines() if re.search(r"SIGKILL|signal.?9|killed", line, re.I)]
    summary["non_loopback_socket_samples"] = sorted(set(non_loopback))
    summary["sink_requests"] = (out / "sink.log").read_text().splitlines()
    dump = runtime / "mcp-env.json"
    if dump.exists():
        child_env = json.loads(dump.read_text())
        shutil.copyfile(dump, out / "mcp-env.json")
        mismatch = {key: child_env.get(key) for key, value in patch.items() if child_env.get(key) != value}
        unexpected = {key: value for key, value in child_env.items() if key.upper() in reserved and key not in patch}
        summary["env_verdict"] = "PASS" if not mismatch and not unexpected else "FAIL"
        summary["env_mismatches"] = mismatch
        summary["unexpected_proxy_variables"] = unexpected
    else:
        summary["env_verdict"] = "no MCP env dump"
    summary["sampled_pids"] = sorted(known_pids)
    # The sandbox remains the protection for any descendant too short-lived to sample.
except (Exception, KeyboardInterrupt) as error:
    summary["helper_error"] = str(error) or "interrupted"
finally:
    try:
        cleanup()
    except Exception as error:
        summary["cleanup_error"] = str(error)
    save_summary()
    print(json.dumps(summary, indent=2))
sys.exit(1 if "helper_error" in summary or "cleanup_error" in summary else summary.get("exit", 1))
PY
