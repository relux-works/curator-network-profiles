#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Demo of track step N-A, "two manual launches use two egresses".
#
# Loopback only: three proxies on 127.0.0.1 (A, B and a WRONG one that
# stands for hostile ambient proxy variables), a temporary HOME, no
# operator file touched, no DNS name resolved (the client asks the proxy
# for http://egress.invalid/ and the proxy answers it itself).
#
# The confirmation ledger is seeded as a FIXTURE: `curator network
# confirm` refuses to run inside an agent session or without a terminal
# by design, so a script cannot confirm; the operator does that once from
# a terminal. The fixture stands in for that step.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/curator-network-demo.XXXXXX")"
PIDS=()
cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

BIN="$TMP/bin"
DEMO_HOME="$TMP/home"
mkdir -p "$BIN" "$DEMO_HOME"

# Scrub every spelling of *_PROXY before even querying the warm Go caches.
while IFS='=' read -r name _; do
  case "$name" in *_[Pp][Rr][Oo][Xx][Yy]) unset "$name" ;; esac
done < <(env)
export GOENV=off
export GOPROXY=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local
export GONOPROXY=none GOPRIVATE=none GOSUMDB=off
CACHE_DIRS="$(cd "$ROOT" && go env GOCACHE GOMODCACHE)"
export GOCACHE="${CACHE_DIRS%%$'\n'*}" GOMODCACHE="${CACHE_DIRS#*$'\n'}"
# Both builds and launches get a private HOME and all three XDG directories.
export HOME="$DEMO_HOME"
export XDG_CONFIG_HOME="$TMP/xdg-config" XDG_CACHE_HOME="$TMP/xdg-cache" XDG_DATA_HOME="$TMP/xdg-data"
export GOENV=off
mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME"
export PATH="$BIN:$PATH"

echo "== build (into $BIN, offline)"
(cd "$ROOT" && make build BIN="$BIN/curator-network" \
  && go build -p 1 -o "$BIN/egress-client" ./internal/testproxy/cmd/egress-client \
  && go build -p 1 -o "$BIN/loopback-proxy" ./internal/testproxy/cmd/loopback-proxy)

start_proxy() { # <id>; readiness is the URL sent through the FIFO
  local id="$1" ready="$TMP/proxy-$1.ready" url
  mkfifo "$ready"
  "$BIN/loopback-proxy" --id "$id" >"$ready" 2>"$TMP/proxy-$id.log" &
  PIDS+=("$!")
  if ! IFS= read -r -t 10 url <"$ready"; then echo "proxy $id did not start" >&2; exit 1; fi
  case "$url" in http://127.0.0.1:*) ;; *) echo "proxy $id did not bind loopback" >&2; exit 1 ;; esac
  printf '%s\n' "$url" >"$TMP/proxy-$id.addr"
  rm "$ready"
}

echo "== start three loopback proxies"
start_proxy A; A_URL="$(cat "$TMP/proxy-A.addr")"
start_proxy B; B_URL="$(cat "$TMP/proxy-B.addr")"
start_proxy WRONG; WRONG_URL="$(cat "$TMP/proxy-WRONG.addr")"
echo "proxy A:     $A_URL"
echo "proxy B:     $B_URL"
echo "proxy WRONG: $WRONG_URL (ambient, must never be used)"

echo
echo "== curator-network --version"
curator-network --version

echo
echo "== add A, B and direct profiles (comment-preserving edits of \$HOME/.curator/network.toml)"
curator-network add egress-a --endpoint "$A_URL"
curator-network add egress-b --endpoint "$B_URL"
curator-network add direct --direct

echo
echo "== the operator file"
cat "$HOME/.curator/network.toml"

echo
echo "== list (unconfirmed: nothing takes effect yet)"
curator-network list

echo
echo "== exec before confirmation is refused"
set +e
curator-network exec egress-a -- egress-client
echo "exit status: $?"
set -e

echo
echo "== seed the confirmation ledger (FIXTURE standing in for 'curator network confirm' at an operator terminal)"
digest_of() { curator-network show "$1" --json | grep -o '"digest":"sha256:[0-9a-f]*"' | head -1 | cut -d'"' -f4; }
DA="$(digest_of egress-a)"
DB="$(digest_of egress-b)"
DD="$(digest_of direct)"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat >"$HOME/.curator/network.confirmations.json" <<LEDGER
{"schema":"relux-network-confirmations-v1","confirmed":{"egress-a":{"digest":"$DA","confirmed_at":"$NOW"},"egress-b":{"digest":"$DB","confirmed_at":"$NOW"},"direct":{"digest":"$DD","confirmed_at":"$NOW"}}}
LEDGER
chmod 600 "$HOME/.curator/network.confirmations.json"
curator-network list

echo
echo "== check --all --probe (TCP only: the profiles carry no probe_target)"
curator-network check --all --probe

echo
echo "== hostile ambient environment for the launches"
export HTTPS_PROXY="$WRONG_URL" http_proxy="$WRONG_URL" all_proxy="$WRONG_URL" NO_PROXY='*'
env | grep -i proxy | sort | tee "$TMP/parent-proxy-before"

echo
echo "== A, B and direct launches at the same time"
curator-network exec egress-a -- egress-client >"$TMP/out-a" 2>"$TMP/err-a" &
PA=$!
curator-network exec egress-b -- egress-client >"$TMP/out-b" 2>"$TMP/err-b" &
PB=$!
curator-network exec direct -- egress-client --dump-proxy-env >"$TMP/out-direct" 2>"$TMP/err-direct" &
PD=$!
PIDS+=("$PA" "$PB" "$PD")
wait "$PA"; wait "$PB"; wait "$PD"
test "$(cat "$TMP/out-direct")" = "[]"
test "$(cat "$TMP/out-a")" = "egress=A"
test "$(cat "$TMP/out-b")" = "egress=B"
test ! -s "$TMP/proxy-WRONG.log"
echo "launch A printed: $(cat "$TMP/out-a")   (stderr: $(cat "$TMP/err-a"))"
echo "launch B printed: $(cat "$TMP/out-b")   (stderr: $(cat "$TMP/err-b"))"
echo "direct proxy env: $(cat "$TMP/out-direct")   (stderr: $(cat "$TMP/err-direct"))"

echo
echo "== a refusal before exec: unknown profile"
set +e
curator-network exec egress-zzz -- egress-client
echo "exit status: $?"
set -e

echo
echo "== request logs of each proxy"
for id in A B WRONG; do
  echo "-- proxy $id:"
  if [ -s "$TMP/proxy-$id.log" ]; then cat "$TMP/proxy-$id.log"; else echo "(no requests)"; fi
done

echo
echo "== the parent environment is untouched"
env | grep -i proxy | sort | tee "$TMP/parent-proxy-after"
cmp "$TMP/parent-proxy-before" "$TMP/parent-proxy-after"
echo "parent proxy environment comparison: identical"
echo "done"
