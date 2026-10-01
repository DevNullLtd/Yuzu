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
# Portability (GNU + BSD/macOS, bash 3.2): the gate must give the same answer everywhere. Every
# regex is POSIX ERE with no repetition bound over 255 (BSD RE_DUP_MAX; linted below), a regex
# ERROR (grep rc>=2) is reported loudly and fails the gate with a distinct message instead of
# reading as "invariant missing", and the self-test mutations use perl (identical on GNU and BSD)
# rather than sed. No sed -i, no \b \s \w in grep, no grep -P, no mapfile, no ${var,,}.
#
# Usage: test_agent_ota_wiring_lexical.sh [--self-test-only] ; AGENT_CPP=<path> overrides the file.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
AGENT_CPP="${AGENT_CPP:-$ROOT/agents/core/src/agent.cpp}"

# Scratch dir (yuzu_test_ prefix), removed on EVERY exit path; holds the regex-error flag file.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_ota_lexical.XXXXXX")" || exit 1
trap 'rm -rf "$WORK"' EXIT
trap 'exit 1' HUP INT TERM
REGEX_ERR_FLAG="$WORK/regex_error"
TAG="test_agent_ota_wiring_lexical"

# A grep exit status of 2 or more is a pattern/IO error, never "no match". Record it in a flag
# FILE (count_re runs in a command substitution, so a shell variable would be lost).
note_regex_error() { # RC PATTERN ERRTEXT
  echo "::error::$TAG: grep regex error (rc=$1) for pattern: $2 ($3)" >&2
  : > "$REGEX_ERR_FLAG"
}

# gre TEXT PATTERN : grep -qE on TEXT. Returns 0 match, 1 no match, 2 regex error (loud).
gre() {
  local err rc
  err="$(grep -qE -- "$2" <<<"$1" 2>&1)"; rc=$?
  if [ "$rc" -ge 2 ]; then
    note_regex_error "$rc" "$2" "$err"
  elif [ -n "$err" ]; then
    echo "::warning::$TAG: grep diagnostic for pattern: $2 ($err)" >&2
  fi
  return "$rc"
}

# normalise FILE: strip // comments, join lines, collapse whitespace.
normalise() {
  sed 's,//.*$,,' "$1" | tr '\n' ' ' | tr -s '[:space:]' ' '
}

# count_re TEXT REGEX : number of non-overlapping matches (0 on a regex error, which is loud).
count_re() {
  local out err rc n
  out="$(grep -oE -- "$2" <<<"$1" 2>"$WORK/count_err")"; rc=$?
  err="$(cat "$WORK/count_err")"
  if [ "$rc" -ge 2 ]; then
    note_regex_error "$rc" "$2" "$err"
    echo 0; return 0
  fi
  [ -n "$err" ] && echo "::warning::$TAG: grep diagnostic for pattern: $2 ($err)" >&2
  if [ -z "$out" ]; then echo 0; else n="$(printf '%s\n' "$out" | wc -l | tr -d ' ')"; echo "$n"; fi
}

# lint_bounds FILE : every regex repetition bound on a grep -E / gre / count_re line must be
# <= 255 (BSD RE_DUP_MAX; BSD grep rejects larger bounds with rc 2). Prints the line, returns 1.
lint_bounds() {
  local f="$1" n=0 rc=0 line stripped tok num
  while IFS= read -r line; do
    n=$((n + 1))
    stripped="${line#"${line%%[![:space:]]*}"}"
    case "$stripped" in
      '#'*) continue ;;
      *'grep -'*E* | *'gre '* | *count_re' '*) ;;
      *) continue ;;
    esac
    for tok in $(printf '%s\n' "$line" | grep -oE '\{[0-9]+(,[0-9]*)?\}'); do
      for num in $(printf '%s' "$tok" | tr -c '0-9' ' '); do
        if [ "$((10#$num))" -gt 255 ]; then
          echo "::error::$TAG: line $n has regex bound $tok > 255 (BSD RE_DUP_MAX); use .* or split the pattern: $line" >&2; rc=1
        fi
      done
    done
  done < "$f"
  return $rc
}

# check FILE : prints one ::error:: per violated invariant, returns 1 if any.
HINT=" (this gate pins the #2182 wiring; if agent.cpp was legitimately restructured or renamed, update tests/shell/test_agent_ota_wiring_lexical.sh)"

check() {
  local f="$1" t rc=0 slot
  [ -f "$f" ] || { echo "::error::$TAG: $f not found" >&2; return 1; }
  t="$(normalise "$f")"

  if [ "$(count_re "$t" 'update_thread_\.stop_and_join\( ?updater\(\) ?\)')" -lt 1 ]; then
    echo "::error::$TAG: agent.cpp no longer calls update_thread_.stop_and_join(updater()) in the reconnect teardown (#2182)$HINT" >&2; rc=1
  fi
  if [ "$(count_re "$t" 'update_thread_\.start\(')" -lt 1 ]; then
    echo "::error::$TAG: agent.cpp no longer starts the update thread via update_thread_.start( (#2182)$HINT" >&2; rc=1
  fi

  # name:context-slot for the four post-publish sites.
  for slot in hb_slot:heartbeat_ctx_ register_slot:register_ctx_ sub_slot:subscribe_ctx_ sync_slot:sync_ctx_; do
    local name="${slot%%:*}" ctxm="${slot##*:}"
    # predicate ctor: fourth constructor argument present after `&ctx`/`&sub_ctx`.
    if ! gre "$t" "CtxSlot $name ?\{ ?ctx_mu_, ?$ctxm, ?&[a-z_]*ctx, ?[^}]"; then
      echo "::error::$TAG: $name is no longer built with CtxSlot's predicate constructor (CtxSlot $name{ctx_mu_, $ctxm, &ctx, <stop predicate>}) (#2182)$HINT" >&2; rc=1
    fi
    # stop_seen() consulted after the declaration (order: declaration first).
    if ! gre "$t" "CtxSlot $name ?\{.*if \($name\.stop_seen\(\)\) ?(break|return)"; then
      echo "::error::$TAG: $name.stop_seen() no longer gates a break/return after publishing (#2182)$HINT" >&2; rc=1
    fi
  done

  # flag-then-cancel at reconnect teardown + quiesce_run_workers (two sites each).
  if [ "$(count_re "$t" 'heartbeat_stop_\.store\(true, ?std::memory_order_release\); ?(if \(auto u = updater\(\)\) u->stop\(\); ?)?cancel_ctx\(heartbeat_ctx_\);')" -lt 2 ]; then
    echo "::error::$TAG: expected heartbeat_stop_.store(true) immediately followed by cancel_ctx(heartbeat_ctx_) at both the reconnect teardown and quiesce_run_workers (#2182)$HINT" >&2; rc=1
  fi
  if [ "$(count_re "$t" 'sync_stop_\.store\(true, ?std::memory_order_release\); ?cancel_ctx\(sync_ctx_\);')" -lt 2 ]; then
    echo "::error::$TAG: expected sync_stop_.store(true) immediately followed by cancel_ctx(sync_ctx_) at both the reconnect teardown and quiesce_run_workers (#2182)$HINT" >&2; rc=1
  fi
  # quiesce_run_workers(): the OTA stop() sits between the heartbeat flag and its cancel, and
  # the OTA thread is joined last (after the sync thread). Reconnect teardown differs
  # (stop_and_join, pinned above), so this is a separate check. The gap between the function
  # head and the heartbeat store is [^}]* (no closing brace), so the match cannot run past the
  # function's first inner block into another copy of the sequence.
  if ! gre "$t" 'quiesce_run_workers\(\) noexcept \{[^}]*heartbeat_stop_\.store\(true, ?std::memory_order_release\); ?if \(auto u = updater\(\)\) ?u->stop\(\); ?cancel_ctx\(heartbeat_ctx_\);'; then
    echo "::error::$TAG: quiesce_run_workers() no longer calls u->stop() between heartbeat_stop_.store(true) and cancel_ctx(heartbeat_ctx_) (#2182)$HINT" >&2; rc=1
  fi
  if ! gre "$t" 'cancel_ctx\(sync_ctx_\); ?if \(sync_thread_\.joinable\(\)\) ?\{? ?sync_thread_\.join\(\); ?\}? ?update_thread_\.join\(\); ?\}'; then
    echo "::error::$TAG: quiesce_run_workers() no longer ends with update_thread_.join() after the sync thread join (#2182)$HINT" >&2; rc=1
  fi
  # stop(): heartbeat, sync, register cancels in sequence (stop_requested_ is set earlier in stop()).
  if ! gre "$t" 'cancel_ctx\(heartbeat_ctx_\); ?cancel_ctx\(sync_ctx_\); ?cancel_ctx\(register_ctx_\);'; then
    echo "::error::$TAG: stop() no longer cancels heartbeat, sync and register contexts in sequence (#2182)$HINT" >&2; rc=1
  fi
  return $rc
}

# selftest: each mutation removes one invariant from a temp copy; check() must FAIL on it.
# Every mutation is a perl -0 program (perl behaves identically on GNU and BSD systems).
selftest() {
  local rc=0 i=0 m out msg

  # Negative control for the gate's own plumbing: an invalid pattern must be reported as a regex
  # ERROR (rc 2 + flag), never as "no match", so it cannot masquerade as a wiring violation.
  rm -f "$REGEX_ERR_FLAG"
  gre "x" '(' 2>/dev/null; local grc=$?
  if [ "$grc" -eq 2 ] && [ -f "$REGEX_ERR_FLAG" ]; then
    echo "selftest regex-error: invalid pattern reported as a regex error (RED)"
  else
    echo "::error::$TAG: selftest regex-error: an invalid pattern was NOT reported as a regex error (rc=$grc)" >&2; rc=1
  fi
  rm -f "$REGEX_ERR_FLAG"

  # Negative control for the >255 bound lint (bound built from parts so this file's own lint
  # does not see a literal over-limit bound on this line).
  local big=400 ok=255
  printf 'gre "$t" %s\n' "'a.{0,${big}}b'" > "$WORK/lint_bad.sh"
  printf 'gre "$t" %s\n' "'a.{0,${ok}}b'" > "$WORK/lint_ok.sh"
  if lint_bounds "$WORK/lint_bad.sh" 2>/dev/null && true; then
    echo "::error::$TAG: selftest bound-lint: a bound over 255 was NOT rejected" >&2; rc=1
  elif ! lint_bounds "$WORK/lint_ok.sh" 2>/dev/null; then
    echo "::error::$TAG: selftest bound-lint: a bound of exactly 255 was wrongly rejected" >&2; rc=1
  else
    echo "selftest bound-lint: bound over 255 rejected, 255 accepted (RED/GREEN)"
  fi

  local -a muts=(
    's/update_thread_\.stop_and_join\(updater\(\)\);/update_thread_.join();/g'
    's/update_thread_\.start\(/update_thread_.begin(/g'
    's/hb_slot\.stop_seen\(\)/false/g'
    's/CtxSlot register_slot\{ctx_mu_, register_ctx_, &ctx, \[this\] \{/CtxSlot register_slot{ctx_mu_, register_ctx_, &ctx}; { /g'
    's/sub_slot\.stop_seen\(\)/false/g'
    's/sync_slot\.stop_seen\(\)/false/g'
    's/^( *)cancel_ctx\(register_ctx_\);/${1}(void)0;/mg'
    's!^( *)cancel_ctx\(sync_ctx_\); // unblock an in-flight ReportInventory before joining!${1}(void)0;!mg'
    # quiesce_run_workers + reconnect: delete u->stop(); delete update_thread_.join()
    's/^ *if \(auto u = updater\(\)\)\n *u->stop\(\);\n//mg'
    's/^( *)update_thread_\.join\(\);/${1}(void)0;/mg'
    # reorder: heartbeat flag store AFTER its cancel_ctx at the reconnect teardown
    's/^( *)(heartbeat_stop_\.store\(true, std::memory_order_release\);)\n( *cancel_ctx\(heartbeat_ctx_\);)$/${3}\n${1}${2}/mg'
    # predicate ctor reverted to the 3-arg form (hb, sub, sync)
    's/(CtxSlot hb_slot\{ctx_mu_, heartbeat_ctx_, &ctx),\s*\[&should_stop\] \{ return should_stop\(\); \}\}/$1}/'
    's/(CtxSlot sub_slot\{ctx_mu_, subscribe_ctx_, &sub_ctx),\s*\[this\] \{.*?\}\}/$1}/s'
    's/(CtxSlot sync_slot\{ctx_mu_, sync_ctx_, &ctx),\s*\[this\] \{.*?\}\}/$1}/s'
  )
  for m in "${muts[@]}"; do
    i=$((i + 1))
    if ! perl -0pe "$m" "$AGENT_CPP" > "$WORK/agent_$i.cpp" 2>"$WORK/perl_err"; then
      echo "::error::$TAG: selftest mutation $i: perl failed: $(cat "$WORK/perl_err"): $m" >&2; rc=1; continue
    fi
    if cmp -s "$AGENT_CPP" "$WORK/agent_$i.cpp"; then
      echo "::error::$TAG: selftest mutation $i changed nothing (stale mutation pattern; update it to match the current agent.cpp): $m" >&2; rc=1; continue
    fi
    if out="$(check "$WORK/agent_$i.cpp" 2>&1 >/dev/null)"; then
      echo "::error::$TAG: selftest mutation $i was NOT detected by the gate: $m" >&2; rc=1
    else
      msg="$(printf '%s\n' "$out" | head -n 1)"; msg="${msg#::error::$TAG: }"; msg="${msg%% (#2182)*}"
      echo "selftest mutation $i: gate FAILED as required (RED): $msg"
    fi
  done
  # a pattern error inside any mutant check would read as a (false) RED: refuse that.
  if [ -f "$REGEX_ERR_FLAG" ]; then
    echo "::error::$TAG: SELFTEST: a gate regex raised a grep error while checking mutants" >&2; rc=1
  fi
  return $rc
}

if [ "${1:-}" != "--self-test-only" ]; then
  lint_bounds "$0" || { echo "$TAG: FAIL (regex bound over 255 is not portable to BSD grep)" >&2; exit 1; }
  check "$AGENT_CPP"; crc=$?
  if [ -f "$REGEX_ERR_FLAG" ]; then
    echo "$TAG: GATE PATTERN ERROR (a grep regex was rejected; this is a defect in the gate, NOT a wiring violation)" >&2
    exit 3
  fi
  [ "$crc" -eq 0 ] || { echo "$TAG: FAIL" >&2; exit 1; }
fi
selftest || { echo "$TAG: SELFTEST FAIL" >&2; exit 1; }
echo "$TAG: OK -- agent.cpp still wires OtaUpdateThread and the CtxSlot post-publish re-check at all four sites; negative controls all RED"
