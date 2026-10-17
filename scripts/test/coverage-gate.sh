#!/usr/bin/env bash
# coverage-gate.sh — Phase 7 coverage gate for /test (PR2).
#
# Sets up a dedicated build-linux-coverage/ dir (separate from the main
# build-linux/ to avoid cross-contamination), runs meson test, runs gcovr
# with the same filter set as .github/workflows/ci.yml, parses the branch
# coverage percentage, compares against tests/coverage-baseline.json, and
# writes a Phase 7 gate row + branch_coverage_overall metric to the DB.
#
# Two modes:
#   default           — fail if branch coverage drops > 0.5 pp below baseline
#   --capture-baselines — run full pipeline, then REWRITE tests/coverage-baseline.json
#                         with the current numbers. Operator must commit the
#                         updated JSON in the same change that earned the new
#                         baseline. Exits PASS after capture.
#
# Required arguments:
#   --run-id ID       — /test run ID (DB foreign key)
#
# Optional arguments:
#   --build-dir DIR   — coverage build directory (default: build-linux-coverage)
#   --baseline PATH   — baseline JSON (default: tests/coverage-baseline.json)
#   --slack-pp F      — pp tolerance for regression (default: 0.5)
#   --capture-baselines — rewrite baseline from current run
#   --report-only     — parse + record metric, don't enforce baseline
#
# Exit codes:
#   0  coverage measured and within tolerance (or --report-only)
#   1  coverage regressed beyond slack
#   2  internal failure (build/test/gcovr failed; runs as WARN)
#
# Implementation notes:
#
# - We use gcovr's JSON summary mode (`--json-summary`) to get structured
#   per-file + overall coverage without having to text-parse the XML or HTML.
#   The same --filter / --exclude set as ci.yml so operator runs match
#   what Codecov sees post-merge.
#
# - The baseline JSON schema is documented in tests/coverage-baseline.json
#   itself (inline comments not allowed in JSON, so read the file header).
#
# - build-linux-coverage/ is separate from build-linux/ on purpose: -Db_coverage
#   embeds profiling artifacts into every object file, which invalidates the
#   non-coverage build's ccache entries. Keeping it separate preserves
#   cross-run ccache hit rate.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

RUN_ID=""
BUILD_DIR=""
BASELINE=""
SLACK_PP="0.5"
CAPTURE=0
REPORT_ONLY=0

usage() {
    cat <<EOF
usage: $0 --run-id ID [options]

Required:
  --run-id ID

Optional:
  --build-dir DIR        (default: build-linux-coverage)
  --baseline PATH        (default: tests/coverage-baseline.json)
  --slack-pp F           (default: 0.5)
  --capture-baselines    rewrite baseline from current run (then PASS)
  --report-only          parse + record metric, don't enforce baseline
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-id)             RUN_ID="$2"; shift 2 ;;
        --build-dir)          BUILD_DIR="$2"; shift 2 ;;
        --baseline)           BASELINE="$2"; shift 2 ;;
        --slack-pp)           SLACK_PP="$2"; shift 2 ;;
        --capture-baselines)  CAPTURE=1; shift ;;
        --report-only)        REPORT_ONLY=1; shift ;;
        -h|--help)            usage; exit 0 ;;
        *)                    echo "coverage-gate: unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$RUN_ID" ]]; then
    echo "coverage-gate: --run-id required" >&2
    exit 2
fi

# Validate RUN_ID before it's interpolated into filesystem paths (UP-9).
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ || "$RUN_ID" == "." || "$RUN_ID" == ".." ]]; then
    echo "coverage-gate: invalid --run-id (allowed: A-Z a-z 0-9 . _ -)" >&2
    exit 2
fi

BUILD_DIR="${BUILD_DIR:-$YUZU_ROOT/build-linux-coverage}"
BASELINE="${BASELINE:-$YUZU_ROOT/tests/coverage-baseline.json}"

# Validate BUILD_DIR — the reconfigure-failure path does `rm -rf "$BUILD_DIR"`,
# so an operator passing `--build-dir /` or `--build-dir $HOME` would be
# catastrophic (sec-M1). Require BUILD_DIR to resolve to a `build-*` segment
# under YUZU_ROOT, or an explicit absolute path clearly scoped to build work
# (e.g. /tmp/build-*).
BUILD_DIR_ABS=$(readlink -f "$BUILD_DIR" 2>/dev/null || echo "$BUILD_DIR")
case "$BUILD_DIR_ABS" in
    "$YUZU_ROOT"/build-*|/tmp/build-*|/tmp/yuzu-test-*)
        ;;
    *)
        echo "coverage-gate: refusing --build-dir '$BUILD_DIR' (resolved '$BUILD_DIR_ABS') — must be under \$YUZU_ROOT/build-* or /tmp/build-*" >&2
        exit 2
        ;;
esac

LOG_DIR="$HOME/.local/share/yuzu/test-runs/$RUN_ID"
mkdir -p "$LOG_DIR"

GATE_LOG="$LOG_DIR/coverage.log"
: > "$GATE_LOG"

echo ""
echo "Phase 7 — Coverage (run $RUN_ID)"
echo "================================"
echo "  build-dir: $BUILD_DIR"
echo "  baseline:  $BASELINE"
echo "  slack-pp:  $SLACK_PP"
echo "  capture:   $CAPTURE  report-only: $REPORT_ONLY"
echo ""

GATE_START=$(date +%s)

write_gate() {
    local status="$1" duration="$2" notes="$3"
    bash "$HERE/test-db-write.sh" gate \
        --run-id "$RUN_ID" \
        --phase 7 \
        --gate "Coverage" \
        --status "$status" \
        --duration "$duration" \
        --log "coverage.log" \
        --notes "$notes"
}

write_metric() {
    local name="$1" value="$2" unit="$3"
    bash "$HERE/test-db-write.sh" metric \
        --run-id "$RUN_ID" \
        --name "$name" \
        --value "$value" \
        --unit "$unit"
}

tool_check() {
    # Exit code discipline:
    #   --full / enforce mode: exit 2 so the caller sees a hard failure it
    #     can choose to bubble up. The WARN row is already recorded.
    #   --report-only (default-mode caller): exit 0 so the caller's `|| …`
    #     fallback doesn't fire and double-write a gate row. The WARN row
    #     from this function is authoritative and sufficient.
    #   --capture-baselines: exit 2 (same as enforce) — a missing tool here
    #     would otherwise silently capture a zero-coverage baseline.
    local tool_miss_exit=2
    if (( REPORT_ONLY )) && ! (( CAPTURE )); then
        tool_miss_exit=0
    fi

    if ! command -v gcovr >/dev/null 2>&1; then
        echo "coverage-gate: gcovr not on PATH (pip install gcovr)" | tee -a "$GATE_LOG"
        write_gate WARN 0 "gcovr missing — install with 'pip3 install --user gcovr' and re-run"
        exit "$tool_miss_exit"
    fi
    if ! command -v meson >/dev/null 2>&1; then
        echo "coverage-gate: meson not on PATH" | tee -a "$GATE_LOG"
        write_gate WARN 0 "meson missing"
        exit "$tool_miss_exit"
    fi
}

tool_check

# ── Configure build-linux-coverage with -Db_coverage ──────────────────

if [[ -d "$BUILD_DIR" ]]; then
    echo "coverage-gate: reconfiguring existing $BUILD_DIR" | tee -a "$GATE_LOG"
    meson setup "$BUILD_DIR" \
        --reconfigure \
        -Dbuild_tests=true \
        -Db_coverage=true \
        >> "$GATE_LOG" 2>&1 || {
            echo "coverage-gate: reconfigure failed — wiping and retrying" | tee -a "$GATE_LOG"
            rm -rf "$BUILD_DIR"
        }
fi

if [[ ! -d "$BUILD_DIR" ]]; then
    echo "coverage-gate: fresh meson setup $BUILD_DIR" | tee -a "$GATE_LOG"
    # bci-S5: apply a Linux native file so the C++ standard matches CI.
    # linux-gcc13.ini sets only cpp_std (no [binaries], no linker), so the
    # compiler is whatever CC/CXX or the host default resolves to — the
    # nightly coverage job (nightly.yml "Coverage (GCC 15)") uses GCC 15,
    # the supported floor, so run this gate with gcc-15 for comparable
    # numbers. The file's name is historical. linux-gcc15.ini is NOT used
    # here because it forces -fuse-ld=mold, which a dev box may lack.
    MESON_SETUP_EXTRA=()
    # On macOS applying the Linux native-file resolves grpc/grpc++ against
    # the wrong pkg-config tree and the configure step fails. Only apply on
    # Linux. (#1009)
    if [[ "$(uname -s)" == "Linux" ]]; then
        NATIVE_FILE="$YUZU_ROOT/meson/native/linux-gcc13.ini"
        if [[ -f "$NATIVE_FILE" ]]; then
            MESON_SETUP_EXTRA+=(--native-file "$NATIVE_FILE")
            echo "coverage-gate: using native-file $NATIVE_FILE (matches ci.yml coverage job)" | tee -a "$GATE_LOG"
        fi
    else
        echo "coverage-gate: host $(uname -s) — skipping linux-gcc13 native-file, using host default compiler" | tee -a "$GATE_LOG"
    fi
    # Propagate the vcpkg install root so fresh `build-linux-coverage/`
    # can find grpc/protobuf/sqlite3/etc. Without this `meson setup` fails
    # on a bare checkout because the coverage build dir doesn't inherit
    # the cmake_prefix_path from the sibling `build-linux/`.
    # Per the governance Round 1 fix and issue #460, the install tree
    # lives per-OS; use the Linux path here.
    # Pick the per-host vcpkg install tree. (#1009)
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)  VCPKG_TRIPLET="x64-linux" ;;
        Linux-aarch64) VCPKG_TRIPLET="arm64-linux" ;;
        Darwin-arm64)  VCPKG_TRIPLET="arm64-osx" ;;
        Darwin-x86_64) VCPKG_TRIPLET="x64-osx" ;;
        *)             VCPKG_TRIPLET="x64-linux" ;;
    esac
    VCPKG_INSTALLED="$YUZU_ROOT/vcpkg_installed/$VCPKG_TRIPLET"
    if [[ -d "$VCPKG_INSTALLED" ]]; then
        MESON_SETUP_EXTRA+=(-Dcmake_prefix_path="$VCPKG_INSTALLED")
        echo "coverage-gate: using cmake_prefix_path=$VCPKG_INSTALLED" | tee -a "$GATE_LOG"
    fi
    if ! meson setup "$BUILD_DIR" \
        "${MESON_SETUP_EXTRA[@]}" \
        --buildtype=debug \
        -Dbuild_tests=true \
        -Db_coverage=true \
        >> "$GATE_LOG" 2>&1
    then
        GATE_DUR=$(( $(date +%s) - GATE_START ))
        write_gate WARN "$GATE_DUR" "meson setup failed — see coverage.log"
        exit 2
    fi
fi

# ── Compile ────────────────────────────────────────────────────────────

echo "coverage-gate: compiling $BUILD_DIR" | tee -a "$GATE_LOG"
if ! meson compile -C "$BUILD_DIR" >> "$GATE_LOG" 2>&1; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "coverage build failed — see coverage.log"
    exit 2
fi

# ── Run tests ──────────────────────────────────────────────────────────

echo "coverage-gate: running meson test" | tee -a "$GATE_LOG"
# --no-rebuild because meson compile already covered it.
# Even a single test failure shouldn't prevent the coverage calculation —
# partial coverage is still informative. Capture the test exit code
# separately and note it, but proceed to gcovr regardless.
TEST_RC=0
meson test -C "$BUILD_DIR" --no-rebuild --print-errorlogs \
    >> "$GATE_LOG" 2>&1 || TEST_RC=$?
if [[ $TEST_RC -ne 0 ]]; then
    echo "coverage-gate: meson test exit=$TEST_RC (coverage will still be computed from partial data)" \
        | tee -a "$GATE_LOG"
fi

# ── Run gcovr ──────────────────────────────────────────────────────────
#
# Filter set mirrors .github/workflows/ci.yml coverage job (lines 584-593
# as of 2026-04-13). Any drift between here and CI causes local/CI
# coverage deltas that look like regressions but aren't.

echo "coverage-gate: running gcovr" | tee -a "$GATE_LOG"
GCOVR_JSON="$BUILD_DIR/coverage-summary.json"
GCOVR_XML="$BUILD_DIR/coverage.xml"
GCOVR_HTML_DIR="$BUILD_DIR/coverage-html"
mkdir -p "$GCOVR_HTML_DIR"

GCOVR_RC=0
(
    cd "$YUZU_ROOT"
    gcovr \
        --root "$YUZU_ROOT" \
        --filter 'server/' --filter 'agents/' --filter 'sdk/' --filter 'tests/' \
        --exclude '.*\.pb\.(h|cc)$' \
        --branches \
        --gcov-ignore-parse-errors=negative_hits.warn \
        --json-summary "$GCOVR_JSON" \
        --xml "$GCOVR_XML" \
        --html --html-details -o "$GCOVR_HTML_DIR/index.html" \
        >> "$GATE_LOG" 2>&1
) || GCOVR_RC=$?

if [[ $GCOVR_RC -ne 0 || ! -f "$GCOVR_JSON" ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "gcovr failed (rc=$GCOVR_RC) — see coverage.log"
    exit 2
fi

# ── Parse branch and line coverage percentages ────────────────────────
#
# UP-2: gcovr --json-summary schema varies across versions.
#   gcovr 6.x/7.x top-level: branch_percent, line_percent, branches_covered,
#                            branches_valid, lines_covered, lines_valid
#   gcovr 5.x top-level:     branches_covered, branches_valid (no percent)
#   gcovr 7.x w/ root:       {"root": {branch_percent, ...}}
#   very old:                branch_covered/branch_total (wrong in our old code)
# Return None if no recognized shape is found so we WARN loudly instead
# of silently defaulting to 0 (which would anchor a false baseline).

PARSE_RC=0
COVERAGE_JSON=$(python3 - "$GCOVR_JSON" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception as e:
    print(json.dumps({"error": f"json.load failed: {e}"}))
    sys.exit(1)

# Unwrap gcovr 7.x+ {"root": ...} wrapper if present.
root = data.get("root") if isinstance(data.get("root"), dict) else data

def pct_from(d, p_key, num_keys, den_keys):
    v = d.get(p_key)
    if v is not None:
        return float(v)
    for num, den in zip(num_keys, den_keys):
        n, t = d.get(num), d.get(den)
        if n is not None and t not in (None, 0):
            return 100.0 * float(n) / float(t)
    return None

branch = pct_from(root,
    "branch_percent",
    ["branches_covered", "branch_covered"],
    ["branches_valid",   "branch_total"])
line = pct_from(root,
    "line_percent",
    ["lines_covered", "line_covered"],
    ["lines_valid",   "line_total"])

if branch is None:
    print(json.dumps({
        "error": "no recognized branch-coverage key",
        "top_level_keys": sorted(list(root.keys()))[:30],
    }))
    sys.exit(1)
print(json.dumps({
    "branch_percent": round(branch, 2),
    "line_percent":   round(line if line is not None else 0.0, 2),
    "line_resolved":  line is not None,
}))
PY
) || PARSE_RC=$?

if [[ $PARSE_RC -ne 0 || -z "$COVERAGE_JSON" ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "could not parse gcovr output: $COVERAGE_JSON"
    exit 2
fi

BRANCH_PCT=$(echo "$COVERAGE_JSON" | python3 -c "import json, sys; print(json.load(sys.stdin)['branch_percent'])")
LINE_PCT=$(echo "$COVERAGE_JSON" | python3 -c "import json, sys; print(json.load(sys.stdin)['line_percent'])")
LINE_RESOLVED=$(echo "$COVERAGE_JSON" | python3 -c "import json, sys; print(json.load(sys.stdin).get('line_resolved', False))")

echo "coverage-gate: branch=$BRANCH_PCT% line=$LINE_PCT% (line_resolved=$LINE_RESOLVED)" | tee -a "$GATE_LOG"

write_metric branch_coverage_overall "$BRANCH_PCT" "%"
write_metric line_coverage_overall "$LINE_PCT" "%"

# qa-S4: if the test run was partial, mark the metric notes so future
# trend analysis can identify contaminated data points.
PARTIAL_NOTE=""
if [[ $TEST_RC -ne 0 ]]; then
    PARTIAL_NOTE=" (partial: meson test exit=$TEST_RC)"
fi

# ── Capture mode: rewrite baseline and exit ─────────────────────────────

if [[ $CAPTURE -eq 1 ]]; then
    # UP-18 / co-2 / sre-3: refuse to capture a baseline from a broken env.
    # A capture that succeeds on partial data permanently anchors a false
    # low coverage number and silently disables the gate for the audit
    # window. Require meson test to have passed (TEST_RC=0) before we
    # write. Operator must `--capture-baselines` on a known-clean tree.
    if [[ $TEST_RC -ne 0 ]]; then
        GATE_DUR=$(( $(date +%s) - GATE_START ))
        NOTE="refused --capture-baselines: meson test exit=$TEST_RC — run 'meson test -C $BUILD_DIR' to green before capturing"
        echo "coverage-gate: $NOTE" | tee -a "$GATE_LOG"
        write_gate FAIL "$GATE_DUR" "$NOTE"
        exit 1
    fi

    # Diff old vs new if a prior baseline exists (hp-S1).
    # sec-h-1: pass $BASELINE via sys.argv, not string interpolation —
    # an operator-controlled path containing a single quote would break
    # out of the Python literal and execute arbitrary code.
    OLD_BRANCH=""
    OLD_LINE=""
    if [[ -f "$BASELINE" ]]; then
        OLD_BRANCH=$(python3 - "$BASELINE" 2>/dev/null <<'PY' || echo "?"
import json, sys
try:
    with open(sys.argv[1]) as f:
        print(json.load(f).get("branch_percent", "?"))
except Exception:
    print("?")
PY
)
        OLD_LINE=$(python3 - "$BASELINE" 2>/dev/null <<'PY' || echo "?"
import json, sys
try:
    with open(sys.argv[1]) as f:
        print(json.load(f).get("line_percent", "?"))
except Exception:
    print("?")
PY
)
        echo "coverage-gate: diff branch $OLD_BRANCH% → $BRANCH_PCT%, line $OLD_LINE% → $LINE_PCT%" | tee -a "$GATE_LOG"
    fi

    echo "coverage-gate: --capture-baselines set — rewriting $BASELINE"
    python3 - "$BASELINE" "$GCOVR_JSON" "$BRANCH_PCT" "$LINE_PCT" "$YUZU_ROOT" <<'PY'
import json, os, subprocess, sys, time
path, summary_path, branch_pct, line_pct, repo = sys.argv[1:]
try:
    commit = subprocess.check_output(
        ["git", "-C", repo, "rev-parse", "HEAD"], text=True
    ).strip()
except Exception:
    commit = "unknown"
baseline = {
    "__schema": "coverage-baseline/v1",
    "__doc": (
        "Locked branch coverage baseline enforced by "
        "scripts/test/coverage-gate.sh. Regenerate with "
        "'bash scripts/test/coverage-gate.sh --run-id manual --capture-baselines' "
        "then commit this file alongside the change that earned the new baseline. "
        "Hardware fingerprint deliberately omitted — line-level coverage is "
        "compiler-deterministic, unlike perf timings."
    ),
    "captured_at": int(time.time()),
    "captured_commit": commit,
    "branch_percent": float(branch_pct),
    "line_percent": float(line_pct),
    "slack_pp": 0.5,
}
# Pretty-print to keep git diffs readable.
with open(path, "w") as f:
    json.dump(baseline, f, indent=2, sort_keys=True)
    f.write("\n")
print(f"coverage-gate: wrote baseline to {path}")
PY
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate PASS "$GATE_DUR" "captured baseline at ${BRANCH_PCT}% branch / ${LINE_PCT}% line"
    exit 0
fi

# ── Compare against baseline ───────────────────────────────────────────

if [[ ! -f "$BASELINE" ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "no baseline at $BASELINE — run with --capture-baselines to create one"
    exit 2
fi

# UP-10 / co-2 / sre-2: honor the __seed sentinel. A seed baseline is a
# placeholder shipped with PR2 to make the gates' first run trivially
# pass on a fresh clone. It has slack_pp=100 and branch_percent=0, which
# means EVERY coverage value passes. That's intentional for the first-ship
# semantics, but it's CRITICAL that operators see a WARN rather than a
# misleading green PASS while the seed is in place — otherwise an unwary
# operator (or auditor) thinks enforcement is active when it isn't.
# Detect __seed and return WARN with a clear message.
# sec-h-1: $BASELINE is operator-controlled — pass via sys.argv, not
# string interpolation, to block code injection via path names with
# embedded single quotes.
SEED_FLAG=$(python3 - "$BASELINE" 2>/dev/null <<'PY' || echo "false"
import json, sys
try:
    with open(sys.argv[1]) as f:
        print("true" if json.load(f).get("__seed") else "false")
except Exception:
    print("false")
PY
)
if [[ "$SEED_FLAG" == "true" ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    NOTE="seed baseline active (${BRANCH_PCT}% measured) — enforcement disabled until 'coverage-gate.sh --capture-baselines'${PARTIAL_NOTE}"
    echo "coverage-gate: $NOTE" | tee -a "$GATE_LOG"
    write_gate WARN "$GATE_DUR" "$NOTE"
    exit 2
fi

COMPARE_RC=0
RESULT=$(python3 - "$BASELINE" "$BRANCH_PCT" "$SLACK_PP" <<'PY'
import json, math, sys
baseline_path, branch_pct, slack_pp = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
with open(baseline_path) as f:
    baseline = json.load(f)
b = float(baseline.get("branch_percent", 0.0))
# sec-L4: guard against pathological baselines. A negative or NaN
# baseline can't be compared; a zero baseline with non-seed metadata
# is almost certainly a broken capture and should be rejected.
if not math.isfinite(b) or b < 0:
    print(f"WARN baseline branch_percent={b} is not finite/non-negative — re-capture")
    sys.exit(2)
if b == 0.0:
    print(f"WARN baseline branch_percent=0 without __seed flag — suspicious, re-capture")
    sys.exit(2)
effective_slack = float(baseline.get("slack_pp", slack_pp))
if not math.isfinite(effective_slack) or effective_slack < 0 or effective_slack > 50:
    print(f"WARN baseline slack_pp={effective_slack} out of [0,50] — suspicious, re-capture")
    sys.exit(2)
floor = b - effective_slack
if branch_pct + 1e-9 < floor:
    print(f"FAIL {branch_pct:.2f} vs {b:.2f} (floor {floor:.2f}, slack {effective_slack})")
    sys.exit(1)
print(f"PASS {branch_pct:.2f} vs {b:.2f} (floor {floor:.2f}, slack {effective_slack})")
PY
) || COMPARE_RC=$?
echo "coverage-gate: $RESULT" | tee -a "$GATE_LOG"

GATE_DUR=$(( $(date +%s) - GATE_START ))

if [[ $REPORT_ONLY -eq 1 ]]; then
    write_gate PASS "$GATE_DUR" "report-only: ${BRANCH_PCT}% branch ($RESULT)${PARTIAL_NOTE}"
    exit 0
fi

# Compare python exits: 0 PASS, 1 FAIL (regression), 2 WARN (pathological baseline).
case $COMPARE_RC in
    0)
        write_gate PASS "$GATE_DUR" "$RESULT${PARTIAL_NOTE}"
        exit 0
        ;;
    2)
        write_gate WARN "$GATE_DUR" "$RESULT${PARTIAL_NOTE}"
        exit 2
        ;;
    *)
        write_gate FAIL "$GATE_DUR" "$RESULT${PARTIAL_NOTE}"
        exit 1
        ;;
esac
