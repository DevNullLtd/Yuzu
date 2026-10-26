#!/usr/bin/env bash
# Measure the gateway's memory per idle agent connection: the `idle_memory`
# case of the gateway scale suite (yuzu_gw_scale_SUITE). For each transport
# (TLS with the shipped agent-listener options, then plaintext, by default)
# and each N of the sweep (0, 1000, 5000, 10000 by default), N simulated agents
# register, hold their Subscribe stream open and heartbeat every 30 s with the
# agent's status tags and a fleet snapshot; the gateway is then sampled and
# the marginal cost per connection, (M(N) - M(0)) / N, is reported.
#
# Usage (from the repo root):
#   scripts/test/gateway-idle-mem.sh [results-dir]
#
# Writes yuzu_gw_idle_mem-<run>.json (everything) and .txt (the summary, also
# printed) to results-dir (default ~/yuzu-idle-mem). Every setting is an
# environment variable read by the suite; see docs/testing/gateway-scale-tests.md,
# "Idle memory per connection". The ones most often changed:
#   YUZU_GW_IDLEMEM_SWEEP=0,1000,5000,10000   the N points
#   YUZU_GW_IDLEMEM_TRANSPORTS=tls,plain      tls | mtls | plain, in order
#   YUZU_GW_IDLEMEM_SNAPSHOT_BYTES=150000     fleet snapshot size (0 = none)
#   YUZU_GW_SCALE_GATE=1                      fail on a per-conn ceiling breach
#
# A full default run takes about 45 minutes: each point waits for a steady
# state. Linux is the platform the 8 KiB goal is judged on; macOS numbers are
# for development.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-$HOME/yuzu-idle-mem}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# A sourced script sees this script's arguments as its own unless they are
# cleared: ensure-erlang.sh would read the results dir as an OTP version.
set --
# shellcheck source=/dev/null
source "$ROOT/scripts/ensure-erlang.sh" >/dev/null
if ! python3 "$ROOT/scripts/erlang_toolchain.py" find-otp >/dev/null; then
    echo "gateway-idle-mem: no Erlang/OTP passing the pin is active (see docs/erlang-gateway-build.md)" >&2
    exit 1
fi
command -v rebar3 >/dev/null || { echo "gateway-idle-mem: rebar3 not found" >&2; exit 1; }

# Each agent holds one socket in the gateway node and one in the load
# generator node; the suite raises each node's soft limit itself, up to the
# hard limit of this shell.
largest=$(echo "${YUZU_GW_IDLEMEM_SWEEP:-0,1000,5000,10000}" | tr ',' '\n' | sort -n | tail -1)
need=$((2 * largest + 4096))
hard=$(ulimit -Hn)
if [ "$hard" != "unlimited" ] && [ "$hard" -lt "$need" ]; then
    echo "gateway-idle-mem: the hard file-descriptor limit is $hard; N=$largest needs $need (raise ulimit -Hn)" >&2
    exit 1
fi

count() { find "$OUT" -maxdepth 1 -name 'yuzu_gw_idle_mem-*.txt' | wc -l; }
before=$(count)
cd "$ROOT/gateway"
YUZU_GW_SCALE_RESULTS_DIR="$OUT" \
    rebar3 ct --dir apps/yuzu_gw/test/ct --suite yuzu_gw_scale_SUITE --case idle_memory
after=$(count)
if [ "$after" -le "$before" ]; then
    echo "gateway-idle-mem: the run wrote no summary to $OUT (see the Common Test log under gateway/_build/test/logs)" >&2
    exit 1
fi
# Names are yuzu_gw_idle_mem-<UTC timestamp>-<tag>.txt: the newest sorts last.
latest=$(find "$OUT" -maxdepth 1 -name 'yuzu_gw_idle_mem-*.txt' | sort | tail -1)
echo
cat "$latest"
echo
echo "JSON: ${latest%.txt}.json"
