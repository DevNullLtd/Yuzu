#!/usr/bin/env bash
# sanitizer-gate.sh — Phase 6 of the /test pipeline (PR2).
#
# Dispatches .github/workflows/sanitizer-tests.yml on the yuzu-bigtam-linux
# self-hosted runner pool, polls for completion, downloads the logs, and parses
# ASan+UBSan and TSan results into two gate rows in the test-runs DB:
#
#   gate_name="Sanitizers (ASan+UBSan)"   phase=6
#   gate_name="Sanitizers (TSan)"         phase=6
#
# Local sanitizer runs would take ~15 min of pure compile time on the
# operator's dev box and pin the machine; dispatching to the always-on
# WSL2 runner means /test --full stays usable.
#
# Required arguments:
#   --run-id ID      — /test run ID (DB foreign key)
#
# Optional arguments:
#   --ref SHA        — git ref to dispatch against (default: HEAD)
#   --out-dir DIR    — artifact cache (default: /tmp/yuzu-test-${RUN_ID}/sanitizer)
#   --timeout-minutes N (default: 90 — covers queued + build + test time)
#   --suite asan|tsan|both (default: both)
#
# Exit codes:
#   0  both sanitizer gates PASS
#   1  at least one sanitizer FAIL (findings in the log)
#   2  runner unavailable / dispatch timed out (WARN, not FAIL)
#
# WARN behaviour: when the runner is offline the gate rows are still
# written but with status=WARN and notes explaining the operator retry path.
# The /test orchestrator treats WARN as continue, so the rest of the run
# proceeds.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

RUN_ID=""
REF=""
OUT_DIR=""
TIMEOUT_MINUTES=90
SUITE="both"

usage() {
    cat <<EOF
usage: $0 --run-id ID [options]

Required:
  --run-id ID

Optional:
  --ref REF                git ref to dispatch against (default: current
                           branch name from \`git rev-parse --abbrev-ref
                           HEAD\`). MUST be a branch or tag name —
                           GitHub's workflow_dispatch API rejects bare
                           commit SHAs with "No ref found for: <SHA>"
                           even when the SHA is on origin. Branch
                           dispatch resolves to the branch's tip, so
                           push your changes before running this gate.
  --out-dir DIR            (default: /tmp/yuzu-test-\${RUN_ID}/sanitizer)
  --timeout-minutes N      (default: 90)
  --suite asan|tsan|both   (default: both)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-id)           RUN_ID="$2"; shift 2 ;;
        --ref)              REF="$2"; shift 2 ;;
        --out-dir)          OUT_DIR="$2"; shift 2 ;;
        --timeout-minutes)  TIMEOUT_MINUTES="$2"; shift 2 ;;
        --suite)            SUITE="$2"; shift 2 ;;
        -h|--help)          usage; exit 0 ;;
        *)                  echo "sanitizer-gate: unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$RUN_ID" ]]; then
    echo "sanitizer-gate: --run-id required" >&2
    exit 2
fi

# Validate RUN_ID before it's interpolated into any filesystem path.
# Reject path-traversal (UP-9), shell metachars, whitespace. Allow only
# [A-Za-z0-9._-] which matches the PR1 convention "$(date +%s)-$$".
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ || "$RUN_ID" == "." || "$RUN_ID" == ".." ]]; then
    echo "sanitizer-gate: invalid --run-id (allowed: A-Z a-z 0-9 . _ -)" >&2
    exit 2
fi

# GitHub's workflow_dispatch API only accepts branch/tag names for `--ref`,
# not commit SHAs (HTTP 422 "No ref found"). Default to the current branch
# name; the workflow runs against whatever the branch's tip is at dispatch
# time. Operators must push before running this gate; if local HEAD is
# ahead of origin, dispatch-runner-job's run-discovery filter
# (headSha == TARGET_SHA on local) will fail to find the run since the
# remote branch tip differs from local HEAD.
REF="${REF:-$(git -C "$YUZU_ROOT" rev-parse --abbrev-ref HEAD)}"
OUT_DIR="${OUT_DIR:-/tmp/yuzu-test-${RUN_ID}/sanitizer}"
mkdir -p "$OUT_DIR"

LOG_DIR="$HOME/.local/share/yuzu/test-runs/$RUN_ID"
mkdir -p "$LOG_DIR"

echo ""
echo "Phase 6 — Sanitizers (run $RUN_ID)"
echo "=================================="
echo "  ref=$REF suite=$SUITE timeout=${TIMEOUT_MINUTES}m"
echo "  artifacts → $OUT_DIR"
echo "  logs → $LOG_DIR"
echo ""

# ── Dispatch ────────────────────────────────────────────────────────────

DISPATCH_START=$(date +%s)
DISPATCH_LOG="$LOG_DIR/sanitizer-dispatch.log"

# Build the --inputs JSON (suite + run_id). The workflow uses run_id only
# for artifact naming; suite controls which job(s) run.
INPUTS_JSON=$(printf '{"suite":"%s","run_id":"%s"}' "$SUITE" "$RUN_ID")

set +e
bash "$HERE/dispatch-runner-job.sh" \
    --workflow sanitizer-tests.yml \
    --ref "$REF" \
    --out-dir "$OUT_DIR" \
    --inputs "$INPUTS_JSON" \
    --timeout-minutes "$TIMEOUT_MINUTES" \
    --expect-runner yuzu-bigtam-linux \
    >"$DISPATCH_LOG" 2>&1
DISPATCH_RC=$?
set -e

DISPATCH_DUR=$(( $(date +%s) - DISPATCH_START ))
echo "sanitizer-gate: dispatch exit=$DISPATCH_RC duration=${DISPATCH_DUR}s"
echo "sanitizer-gate: dispatch log tail:"
tail -20 "$DISPATCH_LOG" 2>/dev/null | sed 's/^/  /'

write_gate() {
    local name="$1" status="$2" duration="$3" notes="$4" log_rel="$5"
    bash "$HERE/test-db-write.sh" gate \
        --run-id "$RUN_ID" \
        --phase 6 \
        --gate "$name" \
        --status "$status" \
        --duration "$duration" \
        --log "$log_rel" \
        --notes "$notes"
}

# ── Dispatch outcome routing ─────────────────────────────────────────────
#
# dispatch-runner-job.sh exit codes:
#   0 success (artifacts downloaded)
#   1 hard error (gh missing, bad args, workflow file not found on ref,
#                 --inputs newline injection, jq missing)
#   2 workflow RAN but concluded failure/timed_out/cancelled/action_required
#   3 runner unavailable / dispatch timed out before run appeared
#
# Mapping to sanitizer gate status:
#   rc=0 → parse artifacts (below); may still produce FAIL if findings
#   rc=1 → WARN with "workflow config error" note (distinguishable from offline)
#   rc=2 → FAIL directly — workflow ran and failed, artifacts (if any)
#          were produced in a degraded state so parsing them is unsafe
#          (UP-6 + UP-7 false-PASS cluster fix)
#   rc=3 → WARN with "runner offline" note

NOTE=""
case $DISPATCH_RC in
    0)  ;;  # fall through to parse
    1)
        NOTE="dispatch config error rc=1 — check workflow file exists on ref, gh+jq installed, --inputs valid (see sanitizer-dispatch.log)"
        echo "sanitizer-gate: dispatch config error → WARN"
        if [[ "$SUITE" == "asan" || "$SUITE" == "both" ]]; then
            write_gate "Sanitizers (ASan+UBSan)" WARN "$DISPATCH_DUR" "$NOTE" "sanitizer-dispatch.log"
        fi
        if [[ "$SUITE" == "tsan" || "$SUITE" == "both" ]]; then
            write_gate "Sanitizers (TSan)" WARN "$DISPATCH_DUR" "$NOTE" "sanitizer-dispatch.log"
        fi
        exit 2
        ;;
    2)
        NOTE="workflow concluded failure — NOT parsing possibly-degraded artifacts (see GHA run on github.com)"
        echo "sanitizer-gate: workflow failed → FAIL"
        if [[ "$SUITE" == "asan" || "$SUITE" == "both" ]]; then
            write_gate "Sanitizers (ASan+UBSan)" FAIL "$DISPATCH_DUR" "$NOTE" "sanitizer-dispatch.log"
        fi
        if [[ "$SUITE" == "tsan" || "$SUITE" == "both" ]]; then
            write_gate "Sanitizers (TSan)" FAIL "$DISPATCH_DUR" "$NOTE" "sanitizer-dispatch.log"
        fi
        exit 1
        ;;
    3)
        NOTE="runner offline or dispatch timed out — retry with /test --full when the yuzu-bigtam-linux pool is back"
        echo "sanitizer-gate: runner unavailable → WARN"
        if [[ "$SUITE" == "asan" || "$SUITE" == "both" ]]; then
            write_gate "Sanitizers (ASan+UBSan)" WARN "$DISPATCH_DUR" "$NOTE" "sanitizer-dispatch.log"
        fi
        if [[ "$SUITE" == "tsan" || "$SUITE" == "both" ]]; then
            write_gate "Sanitizers (TSan)" WARN "$DISPATCH_DUR" "$NOTE" "sanitizer-dispatch.log"
        fi
        exit 2
        ;;
    *)
        NOTE="unknown dispatch exit code $DISPATCH_RC — treating as WARN"
        echo "sanitizer-gate: unknown dispatch exit → WARN"
        if [[ "$SUITE" == "asan" || "$SUITE" == "both" ]]; then
            write_gate "Sanitizers (ASan+UBSan)" WARN "$DISPATCH_DUR" "$NOTE" "sanitizer-dispatch.log"
        fi
        if [[ "$SUITE" == "tsan" || "$SUITE" == "both" ]]; then
            write_gate "Sanitizers (TSan)" WARN "$DISPATCH_DUR" "$NOTE" "sanitizer-dispatch.log"
        fi
        exit 2
        ;;
esac

# ── Parse artifacts ─────────────────────────────────────────────────────
#
# dispatch-runner-job.sh downloads each artifact into its own subdirectory
# under OUT_DIR. The workflow uploads them as:
#
#   sanitizer-asan[-<run_id>]/
#     sanitizer-asan.log
#     sanitizer-asan-build.log
#     build-linux-asan/meson-logs/testlog.junit.xml
#   sanitizer-tsan[-<run_id>]/
#     ...
#
# Failures we care about:
#   - ASan: "ERROR: AddressSanitizer", "ERROR: LeakSanitizer", "runtime error:"
#   - TSan: "WARNING: ThreadSanitizer", "FATAL: ThreadSanitizer"
#   - meson test failures (any Catch2 test returning non-zero)
#
# We DON'T parse the JUnit XML — the .log file captures stderr interleaved
# with the test harness output, which is what a human would grep. The XML
# only shows the test-level pass/fail, not the sanitizer findings.

parse_sanitizer() {
    local label="$1"            # asan or tsan
    local gate_name="$2"        # "Sanitizers (ASan+UBSan)" / "Sanitizers (TSan)"
    local fail_patterns="$3"    # egrep pattern for fatal findings

    local art_dir log_src log_rel notes status finding_count test_fail_count
    art_dir=""
    # Match the artifact directory by prefix — tolerate the -${run_id} suffix.
    for candidate in "$OUT_DIR"/sanitizer-"$label"*/; do
        if [[ -d "$candidate" ]]; then
            art_dir="$candidate"
            break
        fi
    done

    if [[ -z "$art_dir" ]]; then
        write_gate "$gate_name" WARN "$DISPATCH_DUR" \
            "artifact sanitizer-$label not found in $OUT_DIR — check workflow log on GitHub" \
            "sanitizer-dispatch.log"
        return 2
    fi

    log_src="$art_dir/sanitizer-$label.log"
    if [[ ! -f "$log_src" ]]; then
        # Build may have failed before the test step wrote its log.
        # Fall back to the build log so the operator sees the compile error.
        if [[ -f "$art_dir/sanitizer-$label-build.log" ]]; then
            log_src="$art_dir/sanitizer-$label-build.log"
        else
            write_gate "$gate_name" WARN "$DISPATCH_DUR" \
                "no sanitizer-$label.log in artifact — dispatch completed but no output" \
                "sanitizer-dispatch.log"
            return 2
        fi
    fi

    # UP-6 empty-log guard: a runner-disk-full or upload-truncation scenario
    # produces an empty or near-empty log file. Running the findings parser
    # on an empty file would return 0 findings and report PASS — a silent
    # false PASS that lets a real regression ship. Require the log to be
    # non-empty AND contain at least one meson test harness marker ("Ok:",
    # "Fail:", "Expected Fail:", or the "X/Y suite" test summary format).
    # If neither marker is present we treat it as a broken artifact → WARN.
    if [[ ! -s "$log_src" ]]; then
        write_gate "$gate_name" WARN "$DISPATCH_DUR" \
            "empty sanitizer-$label.log (${log_src##*/}) — runner disk full or upload truncated; check GHA run" \
            "sanitizer-dispatch.log"
        return 2
    fi
    if ! grep -qE '(^|[[:space:]])(Ok:|Fail:|Expected Fail:|[0-9]+/[0-9]+[[:space:]])' "$log_src"; then
        write_gate "$gate_name" WARN "$DISPATCH_DUR" \
            "sanitizer-$label.log missing meson test markers — log may be truncated; check GHA run" \
            "sanitizer-dispatch.log"
        return 2
    fi

    # Copy into the run log dir so test-db-query --latest can find it via
    # the log_rel path (log paths are relative to the test-runs DB dir).
    if ! cp "$log_src" "$LOG_DIR/sanitizer-$label.log" 2>/dev/null; then
        write_gate "$gate_name" WARN "$DISPATCH_DUR" \
            "could not copy $log_src into log dir — disk full or permissions" \
            "sanitizer-dispatch.log"
        return 2
    fi
    log_rel="sanitizer-$label.log"

    # Count sanitizer findings and meson test failures.
    #
    # ca-B1 / UP-1: `grep -cE ... || echo 0` is a broken idiom — grep -c
    # already prints 0 to stdout on no match and exits 1, so the `|| echo 0`
    # appends a second 0 via command substitution, producing "0\n0" which
    # breaks `(( n > 0 ))` arithmetic. Correct pattern: capture grep's
    # output (which is always a single integer) and ignore its exit code.
    # Using `|| true` on the arithmetic-bound assignment is also safe since
    # grep -c never fails to print a count.
    finding_count=$(grep -cE "$fail_patterns" "$log_src" 2>/dev/null; true)
    finding_count=${finding_count:-0}
    # Strip any stray whitespace (defensive against locale oddities).
    finding_count=${finding_count//[[:space:]]/}
    # hp-S2: `\<FAIL\>` is a GNU-grep extension; use POSIX `[[:space:]]FAIL`
    # so the pattern is portable across grep implementations (ERE-only).
    test_fail_count=$(grep -cE '^[[:space:]]*[0-9]+/[0-9]+.*[[:space:]]FAIL([[:space:]]|$)' "$log_src" 2>/dev/null; true)
    test_fail_count=${test_fail_count:-0}
    test_fail_count=${test_fail_count//[[:space:]]/}

    if (( finding_count > 0 )); then
        notes="${finding_count} sanitizer findings, ${test_fail_count} meson FAILs"
        status=FAIL
    elif (( test_fail_count > 0 )); then
        notes="0 sanitizer findings, ${test_fail_count} meson FAILs (non-sanitizer)"
        status=FAIL
    else
        notes="clean (0 findings, 0 test FAILs)"
        status=PASS
    fi

    write_gate "$gate_name" "$status" "$DISPATCH_DUR" "$notes" "$log_rel"
    [[ "$status" == "PASS" ]]
    return $?
}

ASAN_RC=0
TSAN_RC=0

if [[ "$SUITE" == "asan" || "$SUITE" == "both" ]]; then
    parse_sanitizer asan "Sanitizers (ASan+UBSan)" \
        "ERROR: AddressSanitizer|ERROR: LeakSanitizer|runtime error:" || ASAN_RC=$?
fi

if [[ "$SUITE" == "tsan" || "$SUITE" == "both" ]]; then
    parse_sanitizer tsan "Sanitizers (TSan)" \
        "WARNING: ThreadSanitizer|FATAL: ThreadSanitizer|ThreadSanitizer: data race" || TSAN_RC=$?
fi

# Overall rc: FAIL if any sanitizer FAIL, WARN (2) if any artifact missing,
# PASS otherwise.
if (( ASAN_RC == 1 || TSAN_RC == 1 )); then
    exit 1
fi
if (( ASAN_RC == 2 || TSAN_RC == 2 )); then
    exit 2
fi
exit 0
