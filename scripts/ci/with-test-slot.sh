#!/usr/bin/env bash
# with-test-slot.sh — run a command while holding one of N machine-wide "heavy
# test" slots, so at most N concurrent CI jobs execute their test phase at once.
#
# WHY (used on both Big Tam/Linux and Wee Tam/Windows): each box runs 4 CCD-
# pinned GitHub Actions runners on ONE physical machine. CPU affinity partitions
# cores between runners, but not everything a heavy test phase contends for.
#
# Wee Tam: not the shared DRAM bandwidth, the single disk, or the Windows
# Defender minifilter — so every heavy unit-test suite's wall time scales with
# how many Windows jobs run their test phase concurrently (measured server
# ~[pg]: c0 289s -> c4 603s, i.e. a guaranteed timeout at >=4).
#
# Big Tam: originally believed to "scale flat" and need no gate at all — false.
# Its dominant contention turned out to be WITHIN-job meson fan-out (fixed by
# --num-processes 2 on the flake-retry.py invocation in ci.yml, proved via
# back-computed shard start times landing within ~0.01s of each other), but
# that alone left cross-job contention unmeasured (#3443 AC4). Now confirmed
# real: a single push to dev launches its own 4-way Linux matrix simultaneously,
# saturating all 4 Big Tam runners by itself, and a concurrently-queued PR's
# Linux job was observed waiting 35 minutes for a free runner while shard E
# timed out at exactly 600.01s under that same load — the box was never
# actually scaling flat, it just needed both fixes, same as Wee Tam.
#
# This gate caps concurrent *test phases* per box; the build stays 4-wide
# (unaffected) on both platforms.
# Full diagnosis: docs/ci-architecture.md + the tests/meson.build server-shard
# comment.
#
# KNOWN LIMITATION: a lock-file `exec` failure (e.g. `$lockdir` existing but
# unwritable — wrong owner, read-only mount) is swallowed by the per-slot
# `|| continue` below and reported as an ordinary "slots busy" timeout, not a
# distinct error. Lower-risk on Big Tam specifically, where all 4 runner
# agents share one OS identity (CLAUDE.md), but not impossible (e.g. a
# root-owned leftover, an unusual /tmp mount). Not hardened here; a fail-fast
# writability check on `$lockdir` would close this if it ever bites.
#
# CRASH-SAFE: a slot is an flock on a per-slot file, held via an open fd for the
# lifetime of THIS process. If the job is killed (120-min timeout / cancel-in-
# progress), the OS closes the fd and releases the lock — a dead job never leaks
# a slot. (This is why a counter/semaphore file would be wrong: it could not be
# decremented by a killed holder.) Verified on Wee Tam MSYS2 bash: flock -x
# serialises across the separate runner bash processes.
#
# Usage:  with-test-slot.sh <max_slots> -- <cmd> [args...]
# Env:    YUZU_TEST_SLOT_DIR      lock directory (default: $RUNNER_TOOL_CACHE/yuzu-test-slots
#                                 or /d/ci/yuzu-test-slots — this default is only genuinely
#                                 box-wide on Wee Tam, whose RUNNER_TOOL_CACHE is shared;
#                                 Big Tam's is PER-AGENT, so its ci.yml caller sets this
#                                 explicitly, or the gate would silently no-op there)
#         YUZU_TEST_SLOT_NAME     slot base name (default: yuzu-weetam-heavy; Big Tam's
#                                 caller sets its own to keep the two platforms' slot
#                                 namespaces distinct in logs)
#         YUZU_TEST_SLOT_TIMEOUT_MIN  max wait for a slot (default: 115)
#         YUZU_TEST_SLOT_DISABLE=1    bypass the gate entirely (run the command directly)
#
# NOT set -e: flock -n failure is control flow, and the wrapped command's exit
# code must be captured and propagated, not aborted on.
set -uo pipefail

max="${1:?with-test-slot: <max_slots> required}"; shift
[[ "${1:-}" == "--" ]] && shift
[[ $# -ge 1 ]] || { echo "::error::with-test-slot: no command given (expected: <max_slots> -- cmd ...)"; exit 2; }

# Escape hatch: to disable the gate (any host) just run the command directly.
if [[ "${YUZU_TEST_SLOT_DISABLE:-0}" == "1" || "$max" -le 0 ]]; then
  echo "with-test-slot: gate disabled (YUZU_TEST_SLOT_DISABLE/max<=0) — running ungated"
  "$@"; exit $?
fi

name="${YUZU_TEST_SLOT_NAME:-yuzu-weetam-heavy}"
timeout_min="${YUZU_TEST_SLOT_TIMEOUT_MIN:-115}"

lockdir="${YUZU_TEST_SLOT_DIR:-}"
if [[ -z "$lockdir" ]]; then
  base="${RUNNER_TOOL_CACHE:-/d/ci}"
  command -v cygpath >/dev/null 2>&1 && base="$(cygpath -u "$base" 2>/dev/null || echo "$base")"
  lockdir="${base}/yuzu-test-slots"
fi
mkdir -p "$lockdir" 2>/dev/null || { echo "::error::with-test-slot: cannot create lock dir $lockdir"; exit 2; }

# Poll each slot non-blocking; hold the first free one on fd 200. Poll (not
# flock-blocking) because bash flock cannot wait-on-any-of-N.
start=$(date +%s)
deadline=$(( start + timeout_min * 60 ))
slot=""
while :; do
  for (( i = 1; i <= max; i++ )); do
    exec 200>"$lockdir/${name}-${i}.lock" || continue
    if flock -n 200; then slot="$i"; break; fi
    exec 200>&-   # not ours — drop the fd and try the next slot
  done
  [[ -n "$slot" ]] && break
  if (( $(date +%s) > deadline )); then
    echo "::error::with-test-slot: no '${name}' slot free after ${timeout_min} min (${max} slots busy)"
    exit 1
  fi
  echo "with-test-slot: all ${max} slots busy, waiting... ($(( $(date +%s) - start ))s)"
  sleep 5
done

echo "with-test-slot: acquired '${name}' slot ${slot}/${max} after $(( $(date +%s) - start ))s"

# Run the command with the lock fd CLOSED in the child (200>&-), so THIS process
# is the sole lock holder. fd 200 stays open here for the command's whole
# duration (lock held), but the command and its descendants never inherit it —
# so a hard-kill / job-timeout / cancel of this process frees the slot
# immediately via OS fd-close, even if the wrapped command orphans a child.
# (Without 200>&-, a surviving orphaned test process holds the inherited lock and
# leaks the slot until it exits — verified failure mode on Wee Tam.)
"$@" 200>&-
rc=$?
echo "with-test-slot: command exited ${rc} (releasing slot ${slot})"
exit $rc
