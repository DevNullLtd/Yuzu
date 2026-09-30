#!/usr/bin/env bash
# test_agent_ota_wiring_lexical.sh -- #2182 static lexical gate over agents/core/src/agent.cpp.
#
# The #2182 primitives (OtaUpdateThread stop-then-join, CtxSlot's post-publish stop_seen()) are
# unit-tested in isolation, but nothing exercises AgentImpl::run() (no seam, #1492), so a
# refactor could silently stop CALLING them. This gate pins the call sites lexically, the same
# way test_log_handoff_wiring_lexical.sh pins the log-handoff wiring. Invariants:
#
#   1. The reconnect teardown joins the OTA thread through
#      `update_thread_.stop_and_join(updater())` (stop THEN join, one tested place).
#   2. The update thread is spawned through `update_thread_.start(`.
#   3. Each of the four post-publish sites (heartbeat, Register, Subscribe, sync sender) builds
#      its CtxSlot with the predicate ctor (`CtxSlot NAME{ctx_mu_, SLOT, &ctx, ...}`) and then
#      gates a break/return on `NAME.stop_seen()` afterwards.
#   4. Every teardown sets the stop flag BEFORE cancel_ctx() of the matching context:
#      heartbeat_stop_ -> cancel_ctx(heartbeat_ctx_) (reconnect teardown + quiesce_run_workers),
#      sync_stop_ -> cancel_ctx(sync_ctx_) (same two), and stop() cancels heartbeat, sync and
#      register contexts in sequence. quiesce_run_workers() additionally must call
#      `u->stop()` between the heartbeat flag and its cancel, and must end by joining
#      `update_thread_.join()` after the sync thread. The post-publish predicate is only sound because of this
#      flag-then-cancel order.
#
# Robustness: comments are stripped and whitespace is collapsed before matching, so line
# wrapping, re-indentation and comment text mentioning a token cannot satisfy or break a
# check. Patterns anchor on distinctive tokens, never line numbers.
#
# Lexical only: it cannot see a relocation that keeps the tokens but changes control flow
# (review-enforced). A built-in negative control (--self-test, run by default too) applies
# one deletion per invariant to a temp copy of agent.cpp and requires the gate to FAIL on each.
#
# Usage: test_agent_ota_wiring_lexical.sh [--self-test-only] ; AGENT_CPP=<path> overrides the file.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
AGENT_CPP="${AGENT_CPP:-$ROOT/agents/core/src/agent.cpp}"

# normalise FILE: strip // comments, join lines, collapse whitespace.
normalise() {
  sed 's,//.*$,,' "$1" | tr '\n' ' ' | tr -s '[:space:]' ' '
}

# count_re TEXT REGEX : number of non-overlapping matches.
count_re() {
  printf '%s' "$1" | grep -oE -- "$2" | wc -l
}

# check FILE : prints one ::error:: per violated invariant, returns 1 if any.
HINT=" (this gate pins the #2182 wiring; if agent.cpp was legitimately restructured or renamed, update tests/shell/test_agent_ota_wiring_lexical.sh)"

check() {
  local f="$1" t rc=0 slot
  [ -f "$f" ] || { echo "::error::test_agent_ota_wiring_lexical: $f not found" >&2; return 1; }
  t="$(normalise "$f")"

  if [ "$(count_re "$t" 'update_thread_\.stop_and_join\( ?updater\(\) ?\)')" -lt 1 ]; then
    echo "::error::test_agent_ota_wiring_lexical: agent.cpp no longer calls update_thread_.stop_and_join(updater()) in the reconnect teardown (#2182)$HINT" >&2; rc=1
  fi
  if [ "$(count_re "$t" 'update_thread_\.start\(')" -lt 1 ]; then
    echo "::error::test_agent_ota_wiring_lexical: agent.cpp no longer starts the update thread via update_thread_.start( (#2182)$HINT" >&2; rc=1
  fi

  # name:context-slot for the four post-publish sites.
  for slot in hb_slot:heartbeat_ctx_ register_slot:register_ctx_ sub_slot:subscribe_ctx_ sync_slot:sync_ctx_; do
    local name="${slot%%:*}" ctxm="${slot##*:}"
    # predicate ctor: fourth constructor argument present after `&ctx`/`&sub_ctx`.
    if ! printf '%s' "$t" | grep -qE -- "CtxSlot $name ?\{ ?ctx_mu_, ?$ctxm, ?&[a-z_]*ctx, ?[^}]"; then
      echo "::error::test_agent_ota_wiring_lexical: $name is no longer built with CtxSlot's predicate constructor (CtxSlot $name{ctx_mu_, $ctxm, &ctx, <stop predicate>}) (#2182)$HINT" >&2; rc=1
    fi
    # stop_seen() consulted after the declaration (order: declaration first).
    if ! printf '%s' "$t" | grep -qE -- "CtxSlot $name ?\{.*if \($name\.stop_seen\(\)\) ?(break|return)"; then
      echo "::error::test_agent_ota_wiring_lexical: $name.stop_seen() no longer gates a break/return after publishing (#2182)$HINT" >&2; rc=1
    fi
  done

  # flag-then-cancel at reconnect teardown + quiesce_run_workers (two sites each).
  if [ "$(count_re "$t" 'heartbeat_stop_\.store\(true, ?std::memory_order_release\); ?(if \(auto u = updater\(\)\) u->stop\(\); ?)?cancel_ctx\(heartbeat_ctx_\);')" -lt 2 ]; then
    echo "::error::test_agent_ota_wiring_lexical: expected heartbeat_stop_.store(true) immediately followed by cancel_ctx(heartbeat_ctx_) at both the reconnect teardown and quiesce_run_workers (#2182)$HINT" >&2; rc=1
  fi
  if [ "$(count_re "$t" 'sync_stop_\.store\(true, ?std::memory_order_release\); ?cancel_ctx\(sync_ctx_\);')" -lt 2 ]; then
    echo "::error::test_agent_ota_wiring_lexical: expected sync_stop_.store(true) immediately followed by cancel_ctx(sync_ctx_) at both the reconnect teardown and quiesce_run_workers (#2182)$HINT" >&2; rc=1
  fi
  # quiesce_run_workers(): the OTA stop() sits between the heartbeat flag and its cancel, and
  # the OTA thread is joined last (after the sync thread). Reconnect teardown differs
  # (stop_and_join, pinned above), so this is a separate check.
  if ! printf '%s' "$t" | grep -qE -- 'quiesce_run_workers\(\) noexcept \{.{0,400}heartbeat_stop_\.store\(true, ?std::memory_order_release\); ?if \(auto u = updater\(\)\) ?u->stop\(\); ?cancel_ctx\(heartbeat_ctx_\);'; then
    echo "::error::test_agent_ota_wiring_lexical: quiesce_run_workers() no longer calls u->stop() between heartbeat_stop_.store(true) and cancel_ctx(heartbeat_ctx_) (#2182)$HINT" >&2; rc=1
  fi
  if ! printf '%s' "$t" | grep -qE -- 'cancel_ctx\(sync_ctx_\); ?if \(sync_thread_\.joinable\(\)\) ?\{? ?sync_thread_\.join\(\); ?\}? ?update_thread_\.join\(\); ?\}'; then
    echo "::error::test_agent_ota_wiring_lexical: quiesce_run_workers() no longer ends with update_thread_.join() after the sync thread join (#2182)$HINT" >&2; rc=1
  fi
  # stop(): heartbeat, sync, register cancels in sequence (stop_requested_ is set earlier in stop()).
  if ! printf '%s' "$t" | grep -qE -- 'cancel_ctx\(heartbeat_ctx_\); ?cancel_ctx\(sync_ctx_\); ?cancel_ctx\(register_ctx_\);'; then
    echo "::error::test_agent_ota_wiring_lexical: stop() no longer cancels heartbeat, sync and register contexts in sequence (#2182)$HINT" >&2; rc=1
  fi
  return $rc
}

# selftest: each mutation removes one invariant from a temp copy; check() must FAIL on it.
selftest() {
  local dir; dir="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_ota_lexical.XXXXXX")" || return 1
  trap 'rm -rf "$dir"' RETURN
  local rc=0 i=0
  # each entry: sed expression (applied to the real file)
  local -a muts=(
    's/update_thread_\.stop_and_join(updater());/update_thread_.join();/'
    's/update_thread_\.start(/update_thread_.begin(/'
    's/hb_slot\.stop_seen()/false/'
    's/CtxSlot register_slot{ctx_mu_, register_ctx_, &ctx, \[this\] {/CtxSlot register_slot{ctx_mu_, register_ctx_, \&ctx}; { /'
    's/sub_slot\.stop_seen()/false/'
    's/sync_slot\.stop_seen()/false/'
    's/^\( *\)cancel_ctx(register_ctx_);/\1(void)0;/'
    's/^\( *\)cancel_ctx(sync_ctx_); \/\/ unblock an in-flight ReportInventory before joining/\1(void)0;/'
    # quiesce_run_workers: delete u->stop(); delete update_thread_.join()
    '/^ *if (auto u = updater())$/{N;/u->stop();/d}'
    's/^\( *\)update_thread_\.join();/\1(void)0;/'
    # reorder: heartbeat flag store AFTER its cancel_ctx at the reconnect teardown
    '/^ *heartbeat_stop_\.store(true, std::memory_order_release);$/{N;s/\(.*\)\n\(.*cancel_ctx(heartbeat_ctx_);\)/\2\n\1/}'
  )
  # multi-line mutations (perl -0): predicate ctor reverted to the 3-arg form.
  local -a pmuts=(
    's/(CtxSlot hb_slot\{ctx_mu_, heartbeat_ctx_, &ctx),\s*\[&should_stop\] \{ return should_stop\(\); \}\}/$1}/'
    's/(CtxSlot sub_slot\{ctx_mu_, subscribe_ctx_, &sub_ctx),\s*\[this\] \{.*?\}\}/$1}/s'
    's/(CtxSlot sync_slot\{ctx_mu_, sync_ctx_, &ctx),\s*\[this\] \{.*?\}\}/$1}/s'
  )
  local m
  for m in "${muts[@]}" "${pmuts[@]}"; do
    i=$((i + 1))
    if [ "$i" -gt "${#muts[@]}" ]; then
      perl -0pe "$m" "$AGENT_CPP" > "$dir/agent_$i.cpp"
    else
      sed "$m" "$AGENT_CPP" > "$dir/agent_$i.cpp"
    fi
    if cmp -s "$AGENT_CPP" "$dir/agent_$i.cpp"; then
      echo "::error::test_agent_ota_wiring_lexical: selftest mutation $i changed nothing (stale mutation pattern; update it to match the current agent.cpp): $m" >&2; rc=1; continue
    fi
    if check "$dir/agent_$i.cpp" >/dev/null 2>&1; then
      echo "::error::test_agent_ota_wiring_lexical: selftest mutation $i was NOT detected by the gate: $m" >&2; rc=1
    else
      echo "selftest mutation $i: gate FAILED as required (RED)"
    fi
  done
  return $rc
}

if [ "${1:-}" != "--self-test-only" ]; then
  check "$AGENT_CPP" || { echo "test_agent_ota_wiring_lexical: FAIL" >&2; exit 1; }
fi
selftest || { echo "test_agent_ota_wiring_lexical: SELFTEST FAIL" >&2; exit 1; }
echo "test_agent_ota_wiring_lexical: OK -- agent.cpp still wires OtaUpdateThread and the CtxSlot post-publish re-check at all four sites; negative controls all RED"
