#!/usr/bin/env bash
# test_pr2_gates.sh — Chaos regression harness for /test skill PR2 gates.
#
# Covers the P0 chaos scenarios identified in Gate 5 of the PR2
# governance run. Each scenario injects a specific fault into a mocked
# environment, invokes the gate, and asserts the observable post-condition
# (DB gate row status, exit code, notes content).
#
# Scenarios:
#   CH-1  — clean log + workflow conclusion=failure → sanitizer-gate FAIL
#   CH-2  — grep -cE on zero-match → arithmetic doesn't break, correct count
#   CH-3  — coverage --capture-baselines refuses when TEST_RC != 0
#   CH-4  — gcovr root-wrapper schema → WARN, not silent 0%
#   CH-6  — perf-gate parser drift (no metrics) → WARN with clear message
#   CH-8  — coverage __seed sentinel honored → WARN, not silent PASS
#          (perf half removed 2026-05-03 with the perf gate's regression logic)
#   CH-15 — empty/whitespace/traversal --run-id rejected
#   CH-17 — direct test_db.py vivify stderr sanitizes control chars
#   CH-18 — coverage-gate pkg_config_path, timeout multiplier, stale gcda (#5803)
#   CH-19 — coverage-gate build-dir lock (#6112)
#   CH-20 — coverage-gate inconclusive runs / unknown line figure (#6113)
#   CH-21 — coverage-gate truncated counters / failed DB writes (#6114)
#
# Usage:
#   bash tests/shell/test_pr2_gates.sh             # run all scenarios
#   bash tests/shell/test_pr2_gates.sh CH-1 CH-2   # run specific scenarios
#
# Exit codes: 0 all scenarios passed; 1 one or more failed; 2 harness error.
#
# The harness uses isolated fixtures under a mktemp-created /tmp/yuzu-test-pr2-chaos-* dir, a temporary
# HOME, and a per-harness YUZU_TEST_DB so it cannot contaminate the
# operator's real test-runs DB or log root.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

CHAOS_ROOT="$(mktemp -d /tmp/yuzu-test-pr2-chaos-XXXXXX)"
# A failed `mktemp` under `set -uo pipefail` (no -e) leaves CHAOS_ROOT empty,
# which would root-anchor the paths below ($CHAOS_HOME -> /home, the per-harness
# YUZU_TEST_DB -> /test-runs.db) and run the suite against the operator's real
# HOME/DB. Refuse to continue unless we got a real directory (gov UP-1 / chaos CH-20).
[[ -n "$CHAOS_ROOT" && -d "$CHAOS_ROOT" ]] || { echo "test_pr2_gates: mktemp -d failed" >&2; exit 2; }
CHAOS_HOME="$CHAOS_ROOT/home"
export YUZU_TEST_DB="$CHAOS_ROOT/test-runs.db"
mkdir -p "$CHAOS_HOME" "$CHAOS_ROOT" "$CHAOS_ROOT/mockbin"
export HOME="$CHAOS_HOME"

cleanup() {
    rm -rf "$CHAOS_ROOT" 2>/dev/null || true
}
trap cleanup EXIT

# ── Mock environment ────────────────────────────────────────────────────

MOCKBIN="$CHAOS_ROOT/mockbin"

cat > "$MOCKBIN/meson" <<'EOF'
#!/usr/bin/env bash
# Mock meson — always succeeds, creates build-dir on setup.
if [[ "$1" == "setup" ]]; then
    mkdir -p "$2"
fi
exit "${YUZU_MOCK_MESON_RC:-0}"
EOF

cat > "$MOCKBIN/erl" <<'EOF'
#!/usr/bin/env bash
echo "Erlang/OTP 28"
exit 0
EOF

cat > "$MOCKBIN/rebar3" <<'EOF'
#!/usr/bin/env bash
# Mock rebar3 — prints scripted output from YUZU_MOCK_CT_OUTPUT
# and exits with YUZU_MOCK_CT_RC.
printf '%s\n' "${YUZU_MOCK_CT_OUTPUT:-}"
exit "${YUZU_MOCK_CT_RC:-0}"
EOF

chmod +x "$MOCKBIN"/*

# Prepend mockbin to PATH so these mocks beat real tools.
export PATH="$MOCKBIN:$PATH"

# ── Assertion helpers ───────────────────────────────────────────────────

PASS_COUNT=0
FAIL_COUNT=0
FAILED_SCENARIOS=()

say() { printf '  %s\n' "$*"; }
ok()  { PASS_COUNT=$((PASS_COUNT+1)); printf '  PASS: %s\n' "$*"; }
bad() {
    FAIL_COUNT=$((FAIL_COUNT+1))
    FAILED_SCENARIOS+=("$1")
    printf '  FAIL: %s: %s\n' "$1" "$2"
}

init_db() {
    # Fresh DB per scenario so we don't see cross-pollution.
    rm -f "$YUZU_TEST_DB" "$YUZU_TEST_DB-wal" "$YUZU_TEST_DB-shm"
    bash "$YUZU_ROOT/scripts/test/test-db-init.sh" >/dev/null 2>&1 || return 1
}

db_gate_status() {
    local run_id="$1" gate_name="$2"
    # sec-h-3: pass values via argv, not shell interpolation into
    # python source. Same anti-pattern as sec-h-1; fixing here so the
    # harness teaches the right pattern to future contributors.
    python3 - "$YUZU_TEST_DB" "$run_id" "$gate_name" <<'PY'
import sqlite3, sys
db, rid, gname = sys.argv[1], sys.argv[2], sys.argv[3]
c = sqlite3.connect(db)
row = c.execute("SELECT status FROM test_gates WHERE run_id=? AND gate_name=?",
                (rid, gname)).fetchone()
print(row[0] if row else "MISSING")
PY
}

db_gate_notes() {
    local run_id="$1" gate_name="$2"
    python3 - "$YUZU_TEST_DB" "$run_id" "$gate_name" <<'PY'
import sqlite3, sys
db, rid, gname = sys.argv[1], sys.argv[2], sys.argv[3]
c = sqlite3.connect(db)
row = c.execute("SELECT notes FROM test_gates WHERE run_id=? AND gate_name=?",
                (rid, gname)).fetchone()
print(row[0] if row else "")
PY
}

start_run() {
    local run_id="$1"
    bash "$YUZU_ROOT/scripts/test/test-db-write.sh" run-start \
        --run-id "$run_id" --commit "pr2chaos" --branch "dev" --mode full \
        >/dev/null 2>&1
}

# ── CH-2: grep -cE arithmetic on zero-match ────────────────────────────

scenario_CH_2() {
    echo ""
    echo "=== CH-2: grep -cE arithmetic doesn't break on zero findings ==="
    init_db || { bad "CH-2" "db init failed"; return; }

    # Test the pattern directly: grep -cE ... on a file with no matches
    # must yield a single integer 0, not "0\n0".
    local f="$CHAOS_ROOT/empty-match.log"
    cat > "$f" <<EOF
Ok: 42
Fail: 0
Expected Fail: 0
Summary of results: 42 / 42 tests passed.
EOF

    local count
    count=$(grep -cE "ERROR: AddressSanitizer|ERROR: LeakSanitizer|runtime error:" "$f" 2>/dev/null; true)
    count=${count:-0}
    count=${count//[[:space:]]/}

    if [[ "$count" == "0" ]]; then
        ok "CH-2: grep returned single integer '0'"
    else
        bad "CH-2" "grep returned '$count' (expected '0')"
        return
    fi

    # And the arithmetic comparison must work.
    if (( count > 0 )); then
        bad "CH-2" "arithmetic (( count > 0 )) wrongly evaluated true on count=$count"
    else
        ok "CH-2: arithmetic (( count > 0 )) correctly evaluated false"
    fi
}

# ── CH-3: coverage --capture-baselines refuses on TEST_RC != 0 ─────────

scenario_CH_3() {
    echo ""
    echo "=== CH-3: coverage --capture-baselines refuses broken env ==="
    init_db || { bad "CH-3" "db init failed"; return; }
    local run_id="ch3"
    start_run "$run_id"

    # Mock gcovr to emit valid JSON.
    cat > "$MOCKBIN/gcovr" <<'EOF'
#!/usr/bin/env bash
JSON=""
while [[ $# -gt 0 ]]; do
    case "$1" in --json-summary) JSON="$2"; shift 2 ;; *) shift ;; esac
done
[[ -n "$JSON" ]] && printf '{"branch_percent":65.5,"line_percent":72.0}' > "$JSON"
exit 0
EOF
    chmod +x "$MOCKBIN/gcovr"

    # Mock meson: succeeds setup+compile, FAILS on `test` subcommand.
    cat > "$MOCKBIN/meson" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    setup|compile) mkdir -p "${2:-}"; exit 0 ;;
    test) exit 3 ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$MOCKBIN/meson"

    local out
    local build_dir="$CHAOS_ROOT/build-ch3"
    out=$(bash "$YUZU_ROOT/scripts/test/coverage-gate.sh" \
        --run-id "$run_id" \
        --build-dir "$build_dir" \
        --baseline "$CHAOS_ROOT/ch3-baseline.json" \
        --capture-baselines 2>&1) || true

    # Expect exit != 0 AND gate status FAIL AND baseline file NOT written.
    local status notes
    status=$(db_gate_status "$run_id" "Coverage")
    notes=$(db_gate_notes "$run_id" "Coverage")

    if [[ "$status" != "FAIL" ]]; then
        bad "CH-3" "expected gate FAIL on broken env capture, got '$status'"
    elif [[ -f "$CHAOS_ROOT/ch3-baseline.json" ]]; then
        bad "CH-3" "baseline file was written despite TEST_RC != 0"
    elif [[ "$notes" != *"refused --capture-baselines"* ]]; then
        bad "CH-3" "notes missing 'refused --capture-baselines': $notes"
    else
        ok "CH-3: gate FAIL, baseline not written, notes: $notes"
    fi

    rm -rf "$build_dir" 2>/dev/null || true
}

# ── CH-4: gcovr root-wrapper schema → WARN not silent 0% ────────────────

scenario_CH_4() {
    echo ""
    echo "=== CH-4: gcovr root-wrapper schema tolerated, not silent 0 ==="
    init_db || { bad "CH-4" "db init failed"; return; }
    local run_id="ch4"
    start_run "$run_id"

    # Mock gcovr to emit the nested {"root": {...}} shape.
    cat > "$MOCKBIN/gcovr" <<'EOF'
#!/usr/bin/env bash
JSON=""
while [[ $# -gt 0 ]]; do
    case "$1" in --json-summary) JSON="$2"; shift 2 ;; *) shift ;; esac
done
[[ -n "$JSON" ]] && printf '{"root":{"branches_covered":150,"branches_valid":200,"lines_covered":800,"lines_valid":1000}}' > "$JSON"
exit 0
EOF
    chmod +x "$MOCKBIN/gcovr"

    # Mock meson: succeed everything.
    cat > "$MOCKBIN/meson" <<'EOF'
#!/usr/bin/env bash
case "$1" in setup|compile) mkdir -p "${2:-}"; exit 0 ;; test) exit 0 ;; *) exit 0 ;; esac
EOF
    chmod +x "$MOCKBIN/meson"

    local build_dir="$CHAOS_ROOT/build-ch4"
    bash "$YUZU_ROOT/scripts/test/coverage-gate.sh" \
        --run-id "$run_id" \
        --build-dir "$build_dir" \
        --baseline "$CHAOS_ROOT/ch4-baseline.json" \
        --report-only >/dev/null 2>&1 || true

    # Expect branch_coverage_overall metric ≈ 75.0 (150/200) and status PASS.
    local branch
    branch=$(python3 - "$YUZU_TEST_DB" "$run_id" <<'PY'
import sqlite3, sys
db, rid = sys.argv[1], sys.argv[2]
c = sqlite3.connect(db)
r = c.execute("SELECT metric_value FROM test_metrics WHERE run_id=? AND metric_name=?",
              (rid, "branch_coverage_overall")).fetchone()
print(r[0] if r else "MISSING")
PY
)
    if [[ "$branch" == "MISSING" ]]; then
        bad "CH-4" "branch_coverage_overall metric missing"
    elif python3 -c "import sys; sys.exit(0 if abs(float('$branch') - 75.0) < 0.1 else 1)"; then
        ok "CH-4: parsed branch=$branch% from nested root schema"
    else
        bad "CH-4" "branch=$branch (expected ~75.0 from root.branches_covered/valid)"
    fi

    rm -rf "$build_dir" 2>/dev/null || true
}

# ── CH-6: perf parser drift → FAIL not silent WARN ─────────────────────

scenario_CH_6() {
    echo ""
    echo "=== CH-6: perf parser drift surfaces as WARN ==="
    init_db || { bad "CH-6" "db init failed"; return; }
    local run_id="ch6"
    start_run "$run_id"

    # Simulate a CT run that passes but uses totally different label names
    # (parser drift) so the parser extracts ZERO metrics. With the gate
    # in measure-and-report mode (2026-05-03), parser drift is a WARN
    # rather than a FAIL — the gate no longer enforces and the WARN
    # surfaces the drift signal without blocking the rest of the run.
    YUZU_MOCK_CT_RC=0 \
    YUZU_MOCK_CT_OUTPUT="%%% yuzu_gw_perf_SUITE:
Registratiun: 5000 ops in 613 ms (8157 op/s)
Heartbit queue: 20000 ops in 83 ms (240964 op/s)
All 9 tests passed." \
    bash "$YUZU_ROOT/scripts/test/perf-gate.sh" \
        --run-id "$run_id" >/dev/null 2>&1 || true

    local status notes
    status=$(db_gate_status "$run_id" "Perf")
    notes=$(db_gate_notes "$run_id" "Perf")

    if [[ "$status" == "WARN" ]] && [[ "$notes" == *"0 metrics parsed"* ]]; then
        ok "CH-6: parser drift → WARN, notes: $notes"
    else
        bad "CH-6" "expected WARN with '0 metrics parsed', got status='$status' notes='$notes'"
    fi
}

# ── CH-8: __seed sentinel honored, not silent PASS ─────────────────────

scenario_CH_8() {
    echo ""
    echo "=== CH-8: __seed sentinel → WARN not silent PASS ==="
    init_db || { bad "CH-8" "db init failed"; return; }
    local run_id="ch8"
    start_run "$run_id"

    # Seed baseline with __seed: true and slack_pp=100 (PR2 ship state).
    cat > "$CHAOS_ROOT/ch8-coverage-baseline.json" <<'EOF'
{
  "__schema": "coverage-baseline/v1",
  "__seed": true,
  "branch_percent": 0.0,
  "line_percent": 0.0,
  "slack_pp": 100.0,
  "captured_at": 0,
  "captured_commit": "seed"
}
EOF

    # Mock gcovr to produce a plausible coverage value.
    cat > "$MOCKBIN/gcovr" <<'EOF'
#!/usr/bin/env bash
JSON=""
while [[ $# -gt 0 ]]; do
    case "$1" in --json-summary) JSON="$2"; shift 2 ;; *) shift ;; esac
done
[[ -n "$JSON" ]] && printf '{"branch_percent":72.5,"line_percent":81.3}' > "$JSON"
exit 0
EOF
    chmod +x "$MOCKBIN/gcovr"

    cat > "$MOCKBIN/meson" <<'EOF'
#!/usr/bin/env bash
case "$1" in setup|compile) mkdir -p "${2:-}"; exit 0 ;; test) exit 0 ;; *) exit 0 ;; esac
EOF
    chmod +x "$MOCKBIN/meson"

    local build_dir="$CHAOS_ROOT/build-ch8"
    bash "$YUZU_ROOT/scripts/test/coverage-gate.sh" \
        --run-id "$run_id" \
        --build-dir "$build_dir" \
        --baseline "$CHAOS_ROOT/ch8-coverage-baseline.json" >/dev/null 2>&1 || true

    local status notes
    status=$(db_gate_status "$run_id" "Coverage")
    notes=$(db_gate_notes "$run_id" "Coverage")

    if [[ "$status" == "WARN" ]] && [[ "$notes" == *"seed"* ]]; then
        ok "CH-8: seed → WARN with seed note: $notes"
    else
        bad "CH-8" "expected WARN with 'seed' in notes, got status='$status' notes='$notes'"
    fi

    # Perf half of CH-8 was removed 2026-05-03 along with the perf gate's
    # baseline-comparison logic. The perf gate no longer reads a baseline
    # file or honors a __seed sentinel — there's nothing to test on that
    # axis. CH-6 still exercises the parser-drift WARN path which is the
    # only remaining "perf gate doesn't silently green-pass" guarantee.

    rm -rf "$build_dir" 2>/dev/null || true
}

# ── CH-16: sec-h-1 regression — malicious --baseline path cannot inject python ──

scenario_CH_16() {
    echo ""
    echo "=== CH-16: sec-h-1 regression — --baseline path cannot inject python ==="
    init_db || { bad "CH-16" "db init failed"; return; }
    local run_id="ch16"
    start_run "$run_id"

    # Craft a baseline file with a filename that, if interpolated
    # unsafely, would have broken out of the Python string literal and
    # run os.system. The fix passes $BASELINE via sys.argv, so this
    # filename just gets read as a path.
    local evil_dir="$CHAOS_ROOT/ch16-'evil"
    mkdir -p "$evil_dir"
    local evil_baseline="$evil_dir/ch16.json"
    cat > "$evil_baseline" <<'EOF'
{
  "__schema": "coverage-baseline/v1",
  "__seed": true,
  "branch_percent": 0,
  "line_percent": 0,
  "slack_pp": 100,
  "captured_at": 0,
  "captured_commit": "seed"
}
EOF

    # Mock gcovr + meson so the gate reaches the __seed check.
    cat > "$MOCKBIN/gcovr" <<'EOF'
#!/usr/bin/env bash
JSON=""
while [[ $# -gt 0 ]]; do
    case "$1" in --json-summary) JSON="$2"; shift 2 ;; *) shift ;; esac
done
[[ -n "$JSON" ]] && printf '{"branch_percent":72.5,"line_percent":81.3}' > "$JSON"
exit 0
EOF
    chmod +x "$MOCKBIN/gcovr"
    cat > "$MOCKBIN/meson" <<'EOF'
#!/usr/bin/env bash
case "$1" in setup|compile) mkdir -p "${2:-}"; exit 0 ;; test) exit 0 ;; *) exit 0 ;; esac
EOF
    chmod +x "$MOCKBIN/meson"

    # Also create a sentinel the injection would touch.
    local sentinel="$CHAOS_ROOT/ch16-should-not-exist"
    rm -f "$sentinel"

    local build_dir="$CHAOS_ROOT/build-ch16"
    bash "$YUZU_ROOT/scripts/test/coverage-gate.sh" \
        --run-id "$run_id" \
        --build-dir "$build_dir" \
        --baseline "$evil_baseline" >/dev/null 2>&1 || true

    # The sentinel must not have been created by injected code, AND
    # the __seed check must have run normally (WARN from seed detection).
    if [[ -e "$sentinel" ]]; then
        bad "CH-16" "sentinel file exists — python injection succeeded"
        return
    fi

    local status
    status=$(db_gate_status "$run_id" "Coverage")
    if [[ "$status" == "WARN" ]]; then
        ok "CH-16: --baseline with single-quote handled safely (status=WARN via seed)"
    else
        bad "CH-16" "expected seed WARN, got status='$status' (gate may have failed to read apostrophed path)"
    fi

    rm -rf "$build_dir" "$evil_dir" 2>/dev/null || true
}

# ── CH-15: empty/whitespace/traversal --run-id rejected ────────────────

scenario_CH_15() {
    echo ""
    echo "=== CH-15: invalid --run-id rejected ==="

    local bad_ids=(
        ""
        " "
        "../../../tmp/evil"
        "."
        ".."
        "foo/bar"
        $'has\nnewline'
        "has space"
    )

    local all_ok=1
    for rid in "${bad_ids[@]}"; do
        for gate in coverage-gate.sh perf-gate.sh sanitizer-gate.sh; do
            # Each should exit 2 with "required" or "invalid" message.
            local out rc
            out=$(bash "$YUZU_ROOT/scripts/test/$gate" --run-id "$rid" 2>&1)
            rc=$?
            if (( rc == 0 )); then
                bad "CH-15" "$gate accepted invalid --run-id '$rid'"
                all_ok=0
                break 2
            fi
            if [[ "$out" != *"required"* && "$out" != *"invalid"* ]]; then
                bad "CH-15" "$gate rejected '$rid' without clear message: $out"
                all_ok=0
                break 2
            fi
        done
    done
    if (( all_ok )); then
        ok "CH-15: all invalid run-ids rejected across 3 gates"
    fi

    for gate in coverage-gate.sh perf-gate.sh sanitizer-gate.sh; do
        local out
        out=$(bash "$YUZU_ROOT/scripts/test/$gate" --run-id $'\e[2J' 2>&1 || true)
        if [[ "$out" == *$'\e'* ]]; then
            bad "CH-15" "$gate echoed raw ESC in invalid --run-id rejection"
            return
        fi
    done
    ok "CH-15: invalid run-id rejections do not echo raw ESC"
}

# ── CH-17: direct test_db.py vivify stderr sanitizes control chars ──────

scenario_CH_17() {
    echo ""
    echo "=== CH-17: direct test_db.py rejects unsafe run_id ==="
    init_db || { bad "CH-17" "db init failed"; return; }

    local bad_ids=($'\e[2J' "." "..")
    local rid out rc
    for rid in "${bad_ids[@]}"; do
        out=$(python3 "$YUZU_ROOT/scripts/test/test_db.py" gate \
            --run-id "$rid" \
            --phase 7 \
            --gate Probe \
            --status PASS \
            --duration 0 2>&1 >/dev/null)
        rc=$?
        if (( rc == 0 )); then
            bad "CH-17" "direct test_db.py accepted unsafe run_id '$rid'"
            return
        fi

        if [[ "$out" == *$'\e'* ]]; then
            bad "CH-17" "rejection stderr contained a raw ESC byte"
            return
        fi
        if [[ "$out" != *"invalid --run-id"* ]]; then
            bad "CH-17" "rejection stderr did not explain invalid run_id: $out"
            return
        fi
    done

    local stored
    stored=$(python3 - "$YUZU_TEST_DB" <<'PY'
import sqlite3, sys
db = sys.argv[1]
c = sqlite3.connect(db)
row = c.execute("SELECT COUNT(*) FROM test_runs").fetchone()
print(row[0])
PY
)
    if [[ "$stored" != "0" ]]; then
        bad "CH-17" "invalid run_id created test_runs rows"
        return
    fi

    python3 - "$YUZU_TEST_DB" <<'PY'
import sqlite3, sys, time
db = sys.argv[1]
c = sqlite3.connect(db)
now = int(time.time())
c.execute(
    "INSERT INTO test_runs "
    "(run_id, started_at, commit_sha, branch, mode, overall_status) "
    "VALUES (?, ?, 'legacy', 'dev', 'manual', 'MANUAL')",
    ("safe-keep", now),
)
c.execute(
    "INSERT INTO test_runs "
    "(run_id, started_at, commit_sha, branch, mode, overall_status) "
    "VALUES (?, ?, 'legacy', 'dev', 'manual', 'MANUAL')",
    # One day older than safe-keep so `--prune 1` deterministically keeps
    # safe-keep and deletes "..". `now - 1` risked a same-second tie where
    # SQLite's ORDER BY started_at DESC ordering is undefined, which could
    # keep ".." instead and pass the skip-assertion vacuously (gov QA SHOULD).
    ("..", now - 86400),
)
c.commit()
PY

    local prune_out
    prune_out=$(python3 "$YUZU_ROOT/scripts/test/test_db.py" query \
        --include-manual --prune 1 2>&1)
    if [[ "$prune_out" != *"skipped unsafe log dir for run_id=.."* ]]; then
        bad "CH-17" "prune did not report unsafe legacy run_id skip: $prune_out"
        return
    fi

    ok "CH-17: direct test_db.py rejects unsafe run_ids and prune skips legacy unsafe dirs"
}

# ── CH-18: coverage-gate local-host hardening (#5803) ───────────────────
#
# The gate resolves its repo root from its own location, so the scenario
# copies the gate into a fake root whose vcpkg_installed tree it controls.
# Asserts: pkg_config_path reaches BOTH a fresh setup and a --reconfigure of
# an existing dir; the timeout multiplier defaults to 3, honours the env var,
# and a bad value is refused before any build; stale .gcda counters are
# deleted before the tests run; gcovr is never given --branches.

scenario_CH_18() {
    echo ""
    echo "=== CH-18: coverage-gate pkg_config_path, timeout multiplier, stale gcda ==="
    init_db || { bad "CH-18" "db init failed"; return; }

    # Physical path: the gate resolves --build-dir with readlink -f and compares it
    # to $YUZU_ROOT/build-*, and on macOS /tmp is a symlink to /private/tmp, so a
    # logical /tmp/... root would be refused as "outside" once the dir exists.
    local fake triplet
    fake="$(cd "$CHAOS_ROOT" && pwd -P)/ch18root"
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)  triplet="x64-linux" ;;
        Linux-aarch64) triplet="arm64-linux" ;;
        Darwin-arm64)  triplet="arm64-osx" ;;
        Darwin-x86_64) triplet="x64-osx" ;;
        *)             triplet="x64-linux" ;;
    esac
    mkdir -p "$fake/scripts/test" "$fake/vcpkg_installed/$triplet/lib/pkgconfig"
    cp "$YUZU_ROOT"/scripts/test/{coverage-gate.sh,test-db-write.sh,test_db.py} "$fake/scripts/test/"
    local pkgdir="$fake/vcpkg_installed/$triplet/lib/pkgconfig"

    # Private mock dir, prepended only for this scenario, so the shared
    # $MOCKBIN mocks (and YUZU_MOCK_MESON_RC support) are left untouched.
    local bin="$CHAOS_ROOT/ch18bin" saved_path="$PATH"
    mkdir -p "$bin"
    local mlog="$CHAOS_ROOT/ch18-meson.log" glog="$CHAOS_ROOT/ch18-gcovr.log"
    cat > "$bin/meson" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "$mlog"
case "\$1" in setup) mkdir -p "\$2" ;; esac
exit 0
EOF
    cat > "$bin/gcovr" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "$glog"
JSON=""
while [[ \$# -gt 0 ]]; do
    case "\$1" in --json-summary) JSON="\$2"; shift 2 ;; *) shift ;; esac
done
[[ -n "\$JSON" ]] && printf '{"branch_percent":65.5,"line_percent":72.0}' > "\$JSON"
exit 0
EOF
    chmod +x "$bin/meson" "$bin/gcovr"
    export PATH="$bin:$PATH"

    local build="$fake/build-ch18"
    run_gate() {  # run_id build_dir [env assignments...]
        local rid="$1" bd="$2"; shift 2
        start_run "$rid"
        env "$@" bash "$fake/scripts/test/coverage-gate.sh" --run-id "$rid" \
            --build-dir "$bd" --baseline "$CHAOS_ROOT/ch18-baseline.json" \
            --report-only >/dev/null 2>&1 || true
    }

    # A: fresh dir, default multiplier.
    : > "$mlog"; : > "$glog"; rm -rf "$build"
    run_gate ch18a "$build" YUZU_COVERAGE_TIMEOUT_MULT=
    if ! grep -q "^setup .*-Dpkg_config_path=$pkgdir" "$mlog"; then
        bad "CH-18" "fresh setup did not pass -Dpkg_config_path=$pkgdir: $(cat "$mlog")"
    elif ! grep -q "^test .*--timeout-multiplier 3\( \|$\)" "$mlog"; then
        bad "CH-18" "default multiplier is not 3: $(grep '^test' "$mlog")"
    elif grep -q -- "--branches" "$glog"; then
        bad "CH-18" "gcovr was given --branches: $(cat "$glog")"
    else
        ok "CH-18: fresh setup carries pkg_config_path; default multiplier 3; no --branches"
    fi

    # B: existing dir with a stale gcda, env override.
    : > "$mlog"
    mkdir -p "$build/sub"; echo stale > "$build/sub/old.gcda"
    run_gate ch18b "$build" YUZU_COVERAGE_TIMEOUT_MULT=5
    if ! grep -q "^setup .*--reconfigure .*-Dpkg_config_path=$pkgdir" "$mlog"; then
        bad "CH-18" "--reconfigure did not pass -Dpkg_config_path: $(cat "$mlog")"
    elif ! grep -q "^test .*--timeout-multiplier 5\( \|$\)" "$mlog"; then
        bad "CH-18" "YUZU_COVERAGE_TIMEOUT_MULT=5 not honoured: $(grep '^test' "$mlog")"
    elif [[ -e "$build/sub/old.gcda" ]]; then
        bad "CH-18" "stale .gcda survived into the test run"
    else
        ok "CH-18: --reconfigure carries pkg_config_path; override honoured; stale gcda removed"
    fi

    # C: a --build-dir that is a symlink still gets its stale gcda removed.
    : > "$mlog"
    mkdir -p "$fake/build-ch18real/sub"; echo stale > "$fake/build-ch18real/sub/old.gcda"
    ln -sfn "$fake/build-ch18real" "$fake/build-ch18link"
    run_gate ch18s "$fake/build-ch18link" YUZU_COVERAGE_TIMEOUT_MULT=
    if [[ -e "$fake/build-ch18real/sub/old.gcda" ]]; then
        bad "CH-18" "stale .gcda survived under a symlinked --build-dir"
    elif ! grep -q "^test " "$mlog"; then
        bad "CH-18" "symlinked --build-dir run never reached meson test: $(cat "$mlog")"
    else
        ok "CH-18: stale gcda removed under a symlinked --build-dir"
    fi

    # D: valid decimals reach meson test; bad multipliers are refused before any
    # meson call AND for the right reason (the gate row says so), not merely
    # because something else wrote a WARN.
    local v rid n=0 allok=1 notes
    for v in 1.5 12 1; do
        n=$((n+1)); rid="ch18d$n"
        : > "$mlog"
        run_gate "$rid" "$build" "YUZU_COVERAGE_TIMEOUT_MULT=$v"
        if ! grep -q "^test .*--timeout-multiplier $v\( \|$\)" "$mlog"; then
            bad "CH-18" "valid multiplier '$v' did not reach meson test: $(cat "$mlog")"
            allok=0
        fi
    done
    (( allok )) && ok "CH-18: valid multipliers 1.5, 12 and 1 are accepted"

    allok=1
    for v in abc 0 0.0 0.5 -1 1e3 3. .5 1234567 "1 --foo"; do
        n=$((n+1)); rid="ch18e$n"
        : > "$mlog"
        run_gate "$rid" "$build" "YUZU_COVERAGE_TIMEOUT_MULT=$v"
        notes=$(db_gate_notes "$rid" "Coverage")
        if [[ -s "$mlog" ]] || [[ "$(db_gate_status "$rid" "Coverage")" != "WARN" ]] \
           || [[ "$notes" != *"invalid YUZU_COVERAGE_TIMEOUT_MULT"* ]]; then
            bad "CH-18" "multiplier '$v' not refused up front for the right reason (notes='$notes', meson calls: $(cat "$mlog"))"
            allok=0
        fi
    done
    (( allok )) && ok "CH-18: invalid multipliers refused before any meson call, with the validation note"

    export PATH="$saved_path"
    rm -rf "$fake" 2>/dev/null || true
}

# ── CH-19..21: coverage-gate integrity (#6112 lock, #6113 inconclusive, #6114 disk/DB) ──
#
# Shared fixture: a fake repo root (physical path, see CH-18) holding a copy of
# the gate and a vcpkg tree, and a private mock dir whose meson/gcovr are driven
# by environment variables so each scenario can inject one fault.

ch_fixture() {  # sets FK_ROOT FK_BIN FK_MLOG FK_GLOG FK_SAVED_PATH FK_OUT FK_RC; prepends PATH
    local tag="$1" triplet
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)  triplet="x64-linux" ;;
        Linux-aarch64) triplet="arm64-linux" ;;
        Darwin-arm64)  triplet="arm64-osx" ;;
        Darwin-x86_64) triplet="x64-osx" ;;
        *)             triplet="x64-linux" ;;
    esac
    FK_ROOT="$(cd "$CHAOS_ROOT" && pwd -P)/$tag"
    mkdir -p "$FK_ROOT/scripts/test" "$FK_ROOT/vcpkg_installed/$triplet/lib/pkgconfig"
    cp "$YUZU_ROOT"/scripts/test/{coverage-gate.sh,test_db.py} "$FK_ROOT/scripts/test/"
    cp "$YUZU_ROOT/scripts/test/test-db-write.sh" "$FK_ROOT/scripts/test/test-db-write.real.sh"
    # Wrapper so a scenario can fail ONE DB subcommand (gate or metric) on demand.
    cat > "$FK_ROOT/scripts/test/test-db-write.sh" <<'EOW'
#!/usr/bin/env bash
if [[ "$1" == "${YUZU_MOCK_DB_FAIL:-}" ]]; then echo "mock db failure for $1" >&2; exit 2; fi
exec bash "$(dirname "$0")/test-db-write.real.sh" "$@"
EOW
    FK_BIN="$CHAOS_ROOT/$tag-bin"; mkdir -p "$FK_BIN"
    FK_MLOG="$CHAOS_ROOT/$tag-meson.log"; FK_GLOG="$CHAOS_ROOT/$tag-gcovr.log"; : > "$FK_MLOG"; : > "$FK_GLOG"
    cat > "$FK_BIN/meson" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "$FK_MLOG"
dir=""; prev=""
for a in "\$@"; do [[ "\$prev" == "-C" ]] && dir="\$a"; prev="\$a"; done
case "\$1" in
    setup) if [[ -n "\${YUZU_MOCK_RECONF_FAIL:-}" && " \$* " == *" --reconfigure "* ]]; then exit 1; fi; mkdir -p "\$2" ;;
    test)
        # Record who holds the lock as seen from inside the test run, and the pid
        # of the gate that launched us, so tests can assert they are the same.
        echo "LOCK-OWNER \$(readlink "\${dir%/}.lock" 2>/dev/null) GATE-PID \$PPID" >> "$FK_MLOG"
        [[ -n "\${YUZU_MOCK_PIDFILE:-}" ]] && echo "\$\$" > "\$YUZU_MOCK_PIDFILE"
        # Signal mask this meson inherited (INT=bit1, QUIT=bit2 of SigIgn): the gate must hand it a clean one.
        echo "STDIN \$(readlink /proc/self/fd/0 2>/dev/null)" >> "$FK_MLOG"
        [[ -r /proc/self/status ]] && echo "SIGIGN \$(awk '/^SigIgn/ {print \$2}' /proc/self/status)" >> "$FK_MLOG"
        mkdir -p "\$dir/meson-logs"
        printf 'ok\n%s\n' "\${YUZU_MOCK_TESTLOG_LINE:-}" > "\$dir/meson-logs/testlog.txt"
        if [[ -n "\${YUZU_MOCK_IGNORE_TERM:-}" ]]; then
            trap '' TERM
            # A test child in its OWN session and process group, exactly like meson's tests
            # (mtest.py calls setsid in preexec): a process-group kill cannot reach it.
            if [[ -n "\${YUZU_MOCK_CHILDFILE:-}" ]]; then
                python3 -c 'import os,sys; os.setsid(); open(sys.argv[1],"w").write(str(os.getpid())); os.execvp("sleep",["sleep","40"])' "\$YUZU_MOCK_CHILDFILE" &
            fi
            sleep "\${YUZU_MOCK_TEST_SLEEP:-20}"; exit 0
        fi
        if [[ -n "\${YUZU_MOCK_TREE_MODE:-}" ]]; then
            case "\$YUZU_MOCK_TREE_MODE" in
              grandchild) python3 -c 'import os,sys
os.setsid()
pid=os.fork()
if pid==0:
    open(sys.argv[1],"w").write(str(os.getpid()))
    os.execvp("sleep",["sleep","40"])
os.waitpid(pid,0)' "\$YUZU_MOCK_CHILDFILE" & ;;
              slowexit) python3 -c 'import os,sys; os.setsid(); open(sys.argv[1],"w").write(str(os.getpid())); os.execvp("bash",["bash","-c","sleep 2; : > "+sys.argv[2]])' "\$YUZU_MOCK_CHILDFILE" "\$YUZU_MOCK_DONEFILE" & ;;
              zombie) python3 -c 'import os,sys,time
os.setsid()
mp=os.getppid()
open(sys.argv[1],"w").write(str(os.getpid()))
if os.fork()==0: os._exit(0)
while os.getppid()==mp: time.sleep(0.02)
time.sleep(0.3)' "\$YUZU_MOCK_CHILDFILE" & ;;
              noch) mkfifo "\$YUZU_MOCK_DONEFILE.f"; exec 9<> "\$YUZU_MOCK_DONEFILE.f"; echo \$\$ > "\$YUZU_MOCK_CHILDFILE"; trap '' TERM; read -t 25 -u 9; exit 0 ;;
              leave) python3 -c 'import os,sys; os.setsid(); open(sys.argv[1],"w").write(str(os.getpid())); os.execvp("sleep",["sleep","40"])' "\$YUZU_MOCK_CHILDFILE" & ;;
            esac
            trap 'exit 143' TERM
            while :; do sleep 0.2 & wait \$!; done
        fi
        if [[ -n "\${YUZU_MOCK_EXIT_ON_TERM_LEAVE_CHILD:-}" ]]; then
            # meson that obeys TERM promptly but leaves a setsid'd test child behind.
            python3 -c 'import os,sys; os.setsid(); open(sys.argv[1],"w").write(str(os.getpid())); os.execvp("sleep",["sleep","40"])' "\$YUZU_MOCK_CHILDFILE" &
            trap 'exit 143' TERM
            while :; do sleep 0.2; done
        fi
        if [[ -n "\${YUZU_MOCK_TEST_SLEEP:-}" ]]; then
            sleep "\$YUZU_MOCK_TEST_SLEEP" & sp=\$!
            # On TERM, record whether the gate still holds the lock (it must until we are gone), then take a moment to die.
            trap 'echo "LOCK-AT-TERM \$(readlink "\${dir%/}.lock" 2>/dev/null)" >> "$FK_MLOG"; kill \$sp 2>/dev/null; sleep 1; exit 143' TERM
            wait \$sp
        fi
        exit "\${YUZU_MOCK_TEST_RC:-0}" ;;
esac
exit 0
EOF
    cat > "$FK_BIN/gcovr" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "$FK_GLOG"
[[ -n "\${YUZU_MOCK_GCOVR_RC:-}" ]] && exit "\$YUZU_MOCK_GCOVR_RC"
[[ -n "\${YUZU_MOCK_GCOVR_NOWRITE:-}" ]] && exit 0
JSON=""
while [[ \$# -gt 0 ]]; do
    case "\$1" in --json-summary) JSON="\$2"; shift 2 ;; *) shift ;; esac
done
# The lock must still be held by the gate while gcovr runs.
[[ -n "\$JSON" ]] && echo "LOCK-AT-GCOVR \$(readlink "\$(dirname "\$JSON").lock" 2>/dev/null) GATE-PID \$PPID" >> "$FK_MLOG"
if [[ -n "\$JSON" ]]; then
    if [[ -n "\${YUZU_MOCK_BAD_JSON:-}" ]]; then printf 'not json' > "\$JSON"
    elif [[ -n "\${YUZU_MOCK_NO_LINE:-}" ]]; then printf '{"branch_percent":65.5}' > "\$JSON"
    else printf '{"branch_percent":65.5,"line_percent":72.0}' > "\$JSON"; fi
fi
exit 0
EOF
    # ps stub: lets a scenario stall ONE gate between reading a stale holder and acting on it.
    cat > "$FK_BIN/ps" <<EOF
#!/usr/bin/env bash
if [[ -n "\${YUZU_MOCK_LSTART_FLIP:-}" && " \$* " == *" lstart= "* && " \$* " == *" -p "* ]]; then
    echo "Thu Jan  1 00:00:00 1970"; exit 0
fi
if [[ -n "\${YUZU_MOCK_NO_LSTART:-}" && " \$* " == *" lstart= "* ]]; then exit 1; fi
if [[ -n "\${YUZU_MOCK_DESC_DELAY:-}" && " \$* " == *" ppid= "* ]]; then : > "\$YUZU_MOCK_DESC_MARK"; sleep "\$YUZU_MOCK_DESC_DELAY"; fi
if [[ -n "\${YUZU_MOCK_PS_DELAY:-}" ]]; then : > "\$YUZU_MOCK_PS_MARK"; sleep "\$YUZU_MOCK_PS_DELAY"; fi
exec $(command -v ps) "\$@"
EOF
    chmod +x "$FK_BIN/meson" "$FK_BIN/gcovr" "$FK_BIN/ps"
    FK_SAVED_PATH="$PATH"; export PATH="$FK_BIN:$PATH"
    printf '{"branch_percent":60.0,"line_percent":70.0,"slack_pp":0.5}' > "$CHAOS_ROOT/$tag-baseline.json"
    FK_BASE="$CHAOS_ROOT/$tag-baseline.json"
}

ch_run() {  # run_id build_dir [extra gate args --] [env...]; sets FK_RC FK_OUT
    local rid="$1" bd="$2"; shift 2
    local gate_args=()
    while [[ $# -gt 0 && "$1" != "--" ]]; do gate_args+=("$1"); shift; done
    [[ "${1:-}" == "--" ]] && shift
    start_run "$rid"
    FK_OUT=$(env "$@" bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id "$rid" \
        --build-dir "$bd" --baseline "$FK_BASE" ${gate_args[@]+"${gate_args[@]}"} 2>&1) && FK_RC=0 || FK_RC=$?
}

db_metric() {  # run_id metric_name -> value or MISSING
    python3 - "$YUZU_TEST_DB" "$1" "$2" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
r = c.execute("SELECT metric_value FROM test_metrics WHERE run_id=? AND metric_name=?", (sys.argv[2], sys.argv[3])).fetchone()
print(r[0] if r else "MISSING")
PY
}

scenario_CH_19() {
    echo ""
    echo "=== CH-19: coverage-gate refuses to share a build dir (#6112) ==="
    init_db || { bad "CH-19" "db init failed"; return; }
    ch_fixture ch19
    local build="$FK_ROOT/build-ch19" lock="$FK_ROOT/build-ch19.lock"

    # A: a normal run holds the lock under its own pid and releases it, even on failure.
    ch_run ch19a "$build" -- YUZU_COVERAGE_TIMEOUT_MULT=
    local owner_line; owner_line=$(grep "^LOCK-OWNER " "$FK_MLOG" | head -1)
    local gcovr_line; gcovr_line=$(grep "^LOCK-AT-GCOVR " "$FK_MLOG" | head -1)
    if [[ -e "$lock" || -L "$lock" ]]; then bad "CH-19" "lock left behind after a normal run"
    elif [[ -z "$gcovr_line" || "$(echo "$gcovr_line" | awk '{print $2}')" != "$(echo "$owner_line" | awk '{print $2}')" ]]; then
        # (gcovr runs in a subshell, so its own parent pid is not the gate's: compare with the owner seen at meson test time)
        bad "CH-19" "the lock was not held by the same gate while gcovr ran: gcovr='$gcovr_line' test='$owner_line'"
    elif [[ "$owner_line" != "LOCK-OWNER "[0-9]*" GATE-PID "[0-9]* ]] \
         || [[ "$(echo "$owner_line" | awk '{print $2}')" != "$(echo "$owner_line" | awk '{print $4}')" ]]; then
        bad "CH-19" "the running gate did not record its own pid in the lock: '$owner_line'"
    else
        ch_run ch19b "$build" -- YUZU_MOCK_TEST_RC=3
        if [[ -e "$lock" || -L "$lock" ]]; then bad "CH-19" "lock left behind after a failing run"
        else ok "CH-19: the lock holds the gate's own pid while it runs and is released after a normal and a failing run"; fi
    fi

    # B: a lock held by a live process refuses the run before any meson call.
    : > "$FK_MLOG"
    sleep 30 & local holder=$!; ln -s "$holder" "$lock"
    ch_run ch19c "$build" --
    kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null
    if [[ -s "$FK_MLOG" ]]; then bad "CH-19" "run proceeded despite a live lock: $(cat "$FK_MLOG")"
    elif [[ "$(db_gate_status ch19c Coverage)" != "WARN" || "$(db_gate_notes ch19c Coverage)" != *"another coverage-gate run (pid $holder)"* ]]; then
        bad "CH-19" "live-lock refusal not recorded: status=$(db_gate_status ch19c Coverage) notes=$(db_gate_notes ch19c Coverage)"
    elif [[ "$(readlink "$lock")" != "$holder" ]]; then bad "CH-19" "refused run disturbed the OTHER run's lock"
    else ok "CH-19: a live lock refuses the run (WARN row names the holder) and is left intact"; fi
    rm -f "$lock"

    # C: a lock whose holder is gone is cleared, the run proceeds under ITS pid.
    : > "$FK_MLOG"
    sleep 0 & local dead=$!; wait "$dead" 2>/dev/null
    ln -s "$dead" "$lock"
    ch_run ch19d "$build" --
    owner_line=$(grep "^LOCK-OWNER " "$FK_MLOG" | head -1)
    if [[ -z "$owner_line" ]]; then bad "CH-19" "stale lock was not cleared: $FK_OUT"
    elif [[ "$(echo "$owner_line" | awk '{print $2}')" == "$dead" || "$(echo "$owner_line" | awk '{print $2}')" != "$(echo "$owner_line" | awk '{print $4}')" ]]; then
        bad "CH-19" "after clearing a stale lock the run did not hold the lock itself: '$owner_line'"
    elif [[ -e "$lock" || -L "$lock" ]]; then bad "CH-19" "lock left behind after clearing a stale one"
    elif [[ -e "$lock.takeover" || -L "$lock.takeover" ]]; then bad "CH-19" "takeover guard left behind after a successful takeover"
    else ok "CH-19: a stale lock (dead holder) is cleared and the run proceeds holding the lock under its own pid"; fi

    # D: a lock that is not a pid is never treated as stale.
    : > "$FK_MLOG"
    ln -s "not-a-pid" "$lock"
    ch_run ch19g "$build" --
    if [[ -s "$FK_MLOG" || "$(db_gate_status ch19g Coverage)" != "WARN" ]]; then
        bad "CH-19" "an unreadable/non-pid lock was cleared or ignored: meson='$(cat "$FK_MLOG")' status=$(db_gate_status ch19g Coverage)"
    else ok "CH-19: a lock that does not name a pid is refused, not cleared"; fi
    rm -f "$lock"

    # E: real overlap - a second run started while the first is inside meson test.
    : > "$FK_MLOG"; rm -rf "$build"
    start_run ch19e
    ( env YUZU_MOCK_TEST_SLEEP=4 bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19e \
        --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    local first=$! i
    for i in $(seq 1 100); do grep -q "^LOCK-OWNER " "$FK_MLOG" && break; sleep 0.1; done
    ch_run ch19f "$build" --report-only --
    local second_calls; second_calls=$(grep -c "^setup \|^compile " "$FK_MLOG")
    wait "$first" 2>/dev/null
    if [[ "$(db_gate_notes ch19f Coverage)" != *"another coverage-gate run"* ]]; then
        bad "CH-19" "overlapping second run was not refused: rc=$FK_RC notes=$(db_gate_notes ch19f Coverage) out=$(printf '%s' "$FK_OUT" | tail -5)"
    elif [[ "$second_calls" != "2" ]]; then
        bad "CH-19" "second run touched the build dir (setup+compile calls=$second_calls, expected only the first run's 2)"
    elif [[ "$(db_gate_status ch19e Coverage)" != "PASS" ]]; then
        bad "CH-19" "first run did not finish normally: $(db_gate_status ch19e Coverage)"
    else ok "CH-19: an overlapping second run is refused and never touches the build dir; the first finishes"; fi

    # F: several runs racing to take over the SAME stale lock - never more than one may
    # win (safety, asserted strictly). A round where every racer refuses is a liveness
    # hiccup under load, not a safety failure: it is retried (twice) before it counts.
    local round r winners tries allok=1
    for round in 1 2 3 4 5; do
        for tries in 1 2 3; do
            : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
            sleep 0 & dead=$!; wait "$dead" 2>/dev/null
            ln -s "$dead" "$lock"
            # Run rows first (sequentially), then launch all racers together, with a test
            # long enough that a slow-starting racer still overlaps the winner.
            for r in 1 2 3 4; do start_run "ch19r${round}t${tries}x$r"; done
            for r in 1 2 3 4; do
                ( env YUZU_MOCK_TEST_SLEEP=3 bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id "ch19r${round}t${tries}x$r" \
                    --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
            done
            wait
            winners=$(grep -c "^LOCK-OWNER " "$FK_MLOG")
            [[ "$winners" != "0" ]] && break
        done
        if [[ "$winners" != "1" ]]; then
            bad "CH-19" "round $round: $winners of 4 racing runs ran meson test against one stale lock (expected exactly 1)"
            allok=0; break
        fi
    done
    (( allok )) && ok "CH-19: of 4 runs racing for one stale lock exactly one wins, in each of 5 rounds"

    # G: SIGTERM to the gate alone terminates its meson test child before the lock is released.
    : > "$FK_MLOG"; rm -rf "$build" "$lock"
    local pidfile="$CHAOS_ROOT/ch19-test.pid"; rm -f "$pidfile"
    start_run ch19s
    ( env YUZU_MOCK_TEST_SLEEP=20 YUZU_MOCK_PIDFILE="$pidfile" bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19s \
        --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    local gate=$!
    for i in $(seq 1 100); do [[ -s "$pidfile" ]] && break; sleep 0.1; done
    local mock_pid; mock_pid=$(cat "$pidfile" 2>/dev/null)
    local gate_real; gate_real=$(readlink "$lock" 2>/dev/null)
    [[ -n "$gate_real" ]] && kill -TERM "$gate_real" 2>/dev/null
    for i in $(seq 1 60); do kill -0 "$gate" 2>/dev/null || break; sleep 0.1; done
    local gate_still=no; kill -0 "$gate" 2>/dev/null && gate_still=yes
    [[ "$gate_still" == "yes" ]] && kill -TERM "$mock_pid" 2>/dev/null
    local g_rc=0; wait "$gate" 2>/dev/null; g_rc=$?
    local alive=no; [[ -n "$mock_pid" ]] && kill -0 "$mock_pid" 2>/dev/null && alive=yes
    if [[ -z "$mock_pid" || -z "$gate_real" ]]; then bad "CH-19" "signal test setup failed (mock pid '$mock_pid', gate pid '$gate_real')"
    elif [[ "$gate_still" == "yes" ]]; then bad "CH-19" "SIGTERM did not end the gate within 6 s (it waited for its meson test child instead of terminating it)"
    elif [[ "$alive" == "yes" ]]; then
        kill "$mock_pid" 2>/dev/null
        bad "CH-19" "SIGTERM to the gate left its meson test (pid $mock_pid) running"
    elif [[ -e "$lock" || -L "$lock" ]]; then bad "CH-19" "lock left behind after SIGTERM"
    elif [[ "$g_rc" != "143" ]]; then bad "CH-19" "SIGTERM did not give exit status 143 (got $g_rc)"
    elif ! grep -q "^LOCK-AT-TERM [0-9]" "$FK_MLOG"; then bad "CH-19" "the lock was released before the terminating meson test had exited: $(grep LOCK-AT-TERM "$FK_MLOG")"
    else ok "CH-19: SIGTERM to the gate ends its meson test child and releases the lock"; fi

    # H: deterministic interleave for the re-check under the takeover guard. Run B reads the
    # stale holder, then stalls (ps stub); run A takes over completely and starts its tests;
    # B resumes, wins the (now free) guard and must NOT clear A's live lock.
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    local mark="$CHAOS_ROOT/ch19-ps.mark"; rm -f "$mark"
    sleep 0 & dead=$!; wait "$dead" 2>/dev/null; ln -s "$dead" "$lock"
    start_run ch19hb; start_run ch19ha
    ( env YUZU_MOCK_PS_DELAY=2 YUZU_MOCK_PS_MARK="$mark" YUZU_MOCK_TEST_SLEEP=1 bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19hb \
        --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    for _ in $(seq 1 100); do [[ -e "$mark" ]] && break; sleep 0.1; done
    ( env YUZU_MOCK_TEST_SLEEP=4 bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19ha \
        --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    wait
    local h_owners; h_owners=$(grep -c "^LOCK-OWNER " "$FK_MLOG")
    # A must still hold its lock when ITS gcovr runs (B may not have cleared or replaced it).
    local h_own h_at; h_own=$(grep "^LOCK-OWNER " "$FK_MLOG" | head -1 | awk '{print $2}')
    h_at=$(grep "^LOCK-AT-GCOVR " "$FK_MLOG" | head -1 | awk '{print $2}')
    if [[ ! -e "$mark" ]]; then bad "CH-19" "interleave test setup failed: the stalled run never reached ps"
    elif [[ "$h_owners" != "1" ]]; then bad "CH-19" "a stalled contender cleared a LIVE lock it had judged stale earlier: $h_owners runs ran meson test (expected 1)"
    elif [[ -z "$h_own" || "$h_own" != "$h_at" ]]; then bad "CH-19" "the live lock was disturbed by a stalled contender (owner at meson test '$h_own', at gcovr '$h_at')"
    elif [[ "$(db_gate_status ch19hb Coverage)" != "PASS" && "$(db_gate_status ch19hb Coverage)" != "WARN" ]]; then bad "CH-19" "stalled run left no row"
    else ok "CH-19: a contender that judged the lock stale before another took it over refuses on re-check"; fi

    # I: a surviving `meson test` on this build dir (left by a SIGKILL'd gate) refuses the run.
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    ( exec -a "meson test -C $build" sleep 30 ) & local orphan=$!
    sleep 0.3
    ch_run ch19i "$build" --
    kill "$orphan" 2>/dev/null; wait "$orphan" 2>/dev/null
    if [[ -s "$FK_MLOG" ]]; then bad "CH-19" "run proceeded next to a surviving meson test: $(cat "$FK_MLOG")"
    elif [[ "$(db_gate_notes ch19i Coverage)" != *"a meson test is already running"* ]]; then
        bad "CH-19" "orphan refusal not recorded: $(db_gate_notes ch19i Coverage)"
    elif [[ -e "$lock" || -L "$lock" ]]; then bad "CH-19" "refused-for-orphan run left the lock behind"
    else ok "CH-19: a surviving meson test on the build dir refuses the run and releases the lock"; fi

    # J: a symlink-to-directory planted at the lock path is a refusal, not a link created inside the directory.
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    mkdir -p "$FK_ROOT/planted"; ln -s "$FK_ROOT/planted" "$lock"
    ch_run ch19j "$build" --
    if [[ -s "$FK_MLOG" ]]; then bad "CH-19" "gate ran with a planted directory symlink at its lock path"
    elif [[ -n "$(ls -A "$FK_ROOT/planted")" ]]; then bad "CH-19" "the gate created something inside the planted directory: $(ls "$FK_ROOT/planted")"
    elif [[ "$(db_gate_notes ch19j Coverage)" != *"another coverage-gate run"*"$lock"* ]]; then bad "CH-19" "planted-symlink refusal has the wrong reason: $(db_gate_notes ch19j Coverage)"
    elif [[ "$(readlink "$lock")" != "$FK_ROOT/planted" ]]; then bad "CH-19" "the planted link was removed or replaced"
    else ok "CH-19: a symlink-to-directory planted at the lock path is refused and nothing is written through it"; fi
    rm -f "$lock"; rm -rf "$FK_ROOT/planted"

    # K: a non-printable lock target is never echoed raw into the terminal, log or DB note.
    ln -s $'evil\033[31mX\nFAKE-PASS' "$lock"
    ch_run ch19k "$build" --
    if printf '%s' "$FK_OUT$(db_gate_notes ch19k Coverage)" | grep -q $'\033'; then bad "CH-19" "an escape character from a planted lock reached the output or the DB note"
    elif [[ "$(db_gate_notes ch19k Coverage | wc -l)" -gt 1 || "$(db_gate_notes ch19k Coverage)" != *"evil?"* ]]; then bad "CH-19" "a newline from a planted lock reached the DB note"
    else ok "CH-19: control characters in a planted lock target are neutralised in output and DB note"; fi
    rm -f "$lock"

    # L: the orphan matcher is exact: a meson test on ANOTHER directory (or one whose path merely
    # starts like ours, or has regex metacharacters) neither blocks nor is confused with this run.
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    ( exec -a "meson test -C ${build}2" sleep 30 ) & local other=$!
    ( exec -a "meson test -C $FK_ROOT/other-dir" sleep 30 ) & local other2=$!
    sleep 0.3
    ch_run ch19l "$build" --
    kill "$other" "$other2" 2>/dev/null; wait "$other" "$other2" 2>/dev/null
    if ! grep -q "^LOCK-OWNER " "$FK_MLOG"; then bad "CH-19" "a meson test on a different/prefix-sharing directory wrongly refused the run: $(db_gate_notes ch19l Coverage)"
    else ok "CH-19: a meson test on another directory, or one sharing our path as a prefix, does not block the run"; fi

    # M: the orphan is found whatever way the build dir is spelled (trailing slash), and a path with
    # regex metacharacters is matched literally (an unescaped '+' used to make the check fail open).
    local plus="$FK_ROOT/build-p+1(a)"
    : > "$FK_MLOG"; rm -rf "$plus" "$lock" "$lock.takeover" "$plus.lock"
    ( exec -a "meson test -C $build" sleep 30 ) & local orphan2=$!
    ( exec -a "meson test -C $plus" sleep 30 ) & local orphan3=$!
    sleep 0.3
    ch_run ch19m1 "$build/" --
    ch_run ch19m2 "$plus" --
    kill "$orphan2" "$orphan3" 2>/dev/null; wait "$orphan2" "$orphan3" 2>/dev/null
    if [[ -s "$FK_MLOG" ]]; then bad "CH-19" "a run proceeded next to a surviving meson test (trailing slash or regex-metacharacter path): $(cat "$FK_MLOG")"
    elif [[ "$(db_gate_notes ch19m1 Coverage)" != *"a meson test is already running"* || "$(db_gate_notes ch19m2 Coverage)" != *"a meson test is already running"* ]]; then
        bad "CH-19" "orphan refusals not recorded: '$(db_gate_notes ch19m1 Coverage)' / '$(db_gate_notes ch19m2 Coverage)'"
    else ok "CH-19: a surviving meson test is found through a trailing slash and a metacharacter-laden path"; fi
    rm -rf "$plus" "$plus.lock"

    # N: a stale lock with a leaked takeover guard names the guard in the refusal.
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    sleep 0 & dead=$!; wait "$dead" 2>/dev/null
    ln -s "$dead" "$lock"; ln -s "$dead" "$lock.takeover"
    ch_run ch19n "$build" --
    if [[ -s "$FK_MLOG" || "$(db_gate_notes ch19n Coverage)" != *"takeover guard"* ]]; then
        bad "CH-19" "a leaked takeover guard was not named in the refusal: $(db_gate_notes ch19n Coverage)"
    else ok "CH-19: a stale lock behind a leaked takeover guard is refused with the guard named"; fi
    rm -f "$lock" "$lock.takeover"

    # O: an unwritable lock directory is reported as such, not as 'another run holds the lock'.
    : > "$FK_MLOG"; mkdir -p "$build"; chmod 555 "$FK_ROOT"
    ch_run ch19o "$build" --
    chmod 755 "$FK_ROOT"
    if [[ -s "$FK_MLOG" ]] || [[ "$(db_gate_notes ch19o Coverage)" != *"cannot create the lock"* ]]; then
        # (a root user can write anyway: then the run simply proceeds, which is also fine)
        if [[ "$(id -u)" == "0" ]]; then ok "CH-19: (running as root: unwritable-directory case not applicable)"
        else bad "CH-19" "an unwritable lock directory was not reported as such: $(db_gate_notes ch19o Coverage) meson=$(cat "$FK_MLOG")"; fi
    else ok "CH-19: an unwritable lock directory is reported as such"; fi

    # P: a meson that ignores TERM is killed after the grace period instead of hanging the gate.
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    pidfile="$CHAOS_ROOT/ch19-ign.pid"; rm -f "$pidfile"
    start_run ch19p
    ( env YUZU_MOCK_IGNORE_TERM=1 YUZU_MOCK_TEST_SLEEP=25 YUZU_MOCK_PIDFILE="$pidfile" YUZU_COVERAGE_KILL_GRACE_SECS=2 \
        bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19p --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    local gate2=$!
    for i in $(seq 1 100); do [[ -s "$pidfile" ]] && break; sleep 0.1; done
    mock_pid=$(cat "$pidfile" 2>/dev/null); gate_real=$(readlink "$lock" 2>/dev/null)
    [[ -n "$gate_real" ]] && kill -TERM "$gate_real" 2>/dev/null
    for i in $(seq 1 100); do kill -0 "$gate2" 2>/dev/null || break; sleep 0.1; done
    local stuck=no; kill -0 "$gate2" 2>/dev/null && stuck=yes
    [[ "$stuck" == "yes" ]] && kill -KILL "$gate_real" "$mock_pid" 2>/dev/null
    wait "$gate2" 2>/dev/null
    if [[ -z "$mock_pid" || -z "$gate_real" ]]; then bad "CH-19" "TERM-ignoring-meson test setup failed"
    elif [[ "$stuck" == "yes" ]]; then bad "CH-19" "a meson that ignores TERM kept the gate (and its lock) alive past the grace period"
    elif kill -0 "$mock_pid" 2>/dev/null; then kill -KILL "$mock_pid" 2>/dev/null; bad "CH-19" "the TERM-ignoring meson was left running"
    elif [[ -e "$lock" || -L "$lock" ]]; then bad "CH-19" "lock left behind after killing a TERM-ignoring meson"
    else ok "CH-19: a meson that ignores TERM is SIGKILLed after the grace period and the lock released"; fi

    # X: with `readlink -f` unavailable (old macOS) the gate still resolves the path (python realpath
    # fallback): a symlink spelling shares the real directory's lock, and a `..` spelling that would
    # match build-* lexically but leads outside the tree is refused, never acted on.
    local realreadlink; realreadlink=$(command -v readlink)
    cat > "$FK_BIN/readlink" <<EOF
#!/usr/bin/env bash
[[ "\$1" == "-f" ]] && exit 1
exec "$realreadlink" "\$@"
EOF
    chmod +x "$FK_BIN/readlink"
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover" "$FK_ROOT/build-lnk2"
    ln -s "$build" "$FK_ROOT/build-lnk2"
    ( env YUZU_MOCK_TEST_SLEEP=4 bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19xa \
        --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    for _ in $(seq 1 100); do grep -q "^LOCK-OWNER " "$FK_MLOG" && break; sleep 0.1; done
    local xb_before; xb_before=$(grep -c "^LOCK-OWNER " "$FK_MLOG")
    start_run ch19xb
    env bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19xb --build-dir "$FK_ROOT/build-lnk2" \
        --baseline "$FK_BASE" --report-only >/dev/null 2>&1
    local xb_after; xb_after=$(grep -c "^LOCK-OWNER " "$FK_MLOG")
    wait
    # (outside every allowed prefix: the chaos root itself is under /tmp/yuzu-test-*, which the guard allows)
    local victim="/tmp/yuzu-ch19-victim-$$"; mkdir -p "$victim"; : > "$victim/keep"
    start_run ch19xc
    env bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19xc --build-dir "$FK_ROOT/build-real/../../../yuzu-ch19-victim-$$" \
        --baseline "$FK_BASE" --report-only >"$CHAOS_ROOT/ch19xc.out" 2>&1
    local xc_rc=$?
    if [[ "$xb_before" != "1" ]]; then bad "CH-19" "readlink-f-missing test setup failed"
    elif [[ "$xb_after" != "1" ]]; then bad "CH-19" "without readlink -f a symlink spelling took its own lock and ran concurrently"
    elif [[ "$xc_rc" == "0" ]] || ! grep -q "refusing --build-dir" "$CHAOS_ROOT/ch19xc.out" || [[ ! -e "$victim/keep" ]]; then
        bad "CH-19" "a '..' spelling leading outside the tree was not refused without readlink -f (rc=$xc_rc): $(head -2 "$CHAOS_ROOT/ch19xc.out")"
    else ok "CH-19: without readlink -f, spellings still share one lock and a '..' escape is refused"; fi
    # X2: with BOTH resolvers failing the run is refused (never falls back to the typed spelling).
    local realpython; realpython=$(command -v python3)
    cat > "$FK_BIN/python3" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do [[ "\$a" == *os.path.realpath* ]] && exit 1; done
exec "$realpython" "\$@"
EOF
    chmod +x "$FK_BIN/python3"
    : > "$FK_MLOG"
    start_run ch19x2
    env bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19x2 --build-dir "$build" \
        --baseline "$FK_BASE" --report-only >"$CHAOS_ROOT/ch19x2.out" 2>&1
    local x2_rc=$?
    if [[ -s "$FK_MLOG" || "$x2_rc" == "0" ]] || ! grep -q "could not resolve" "$CHAOS_ROOT/ch19x2.out"; then
        bad "CH-19" "with no way to resolve the path the run was not refused (rc=$x2_rc): $(head -2 "$CHAOS_ROOT/ch19x2.out")"
    else ok "CH-19: with no way to resolve the build dir the run is refused"; fi
    rm -f "$FK_BIN/readlink" "$FK_BIN/python3" "$FK_ROOT/build-lnk2"; rm -rf "$victim"

    # R: a SECOND signal while the handler is still waiting for a TERM-ignoring meson must not abort
    # the cleanup (it would leak the lock and leave meson running).
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    pidfile="$CHAOS_ROOT/ch19-two.pid"; rm -f "$pidfile"
    start_run ch19r
    ( env YUZU_MOCK_IGNORE_TERM=1 YUZU_MOCK_TEST_SLEEP=25 YUZU_MOCK_PIDFILE="$pidfile" YUZU_COVERAGE_KILL_GRACE_SECS=3 \
        bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19r --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    local gate3=$!
    for i in $(seq 1 100); do [[ -s "$pidfile" ]] && break; sleep 0.1; done
    mock_pid=$(cat "$pidfile" 2>/dev/null); gate_real=$(readlink "$lock" 2>/dev/null)
    if [[ -n "$gate_real" ]]; then kill -TERM "$gate_real" 2>/dev/null; sleep 0.5; kill -TERM "$gate_real" 2>/dev/null; sleep 0.3; kill -HUP "$gate_real" 2>/dev/null; fi
    for i in $(seq 1 100); do kill -0 "$gate3" 2>/dev/null || break; sleep 0.1; done
    stuck=no; kill -0 "$gate3" 2>/dev/null && stuck=yes
    [[ "$stuck" == "yes" ]] && kill -KILL "$gate_real" "$mock_pid" 2>/dev/null
    wait "$gate3" 2>/dev/null
    if [[ -z "$mock_pid" || -z "$gate_real" ]]; then bad "CH-19" "double-signal test setup failed"
    elif kill -0 "$mock_pid" 2>/dev/null; then kill -KILL "$mock_pid" 2>/dev/null; bad "CH-19" "a second signal aborted the cleanup and left meson running"
    elif [[ -e "$lock" || -L "$lock" ]]; then bad "CH-19" "a second signal aborted the cleanup and leaked the lock"
    else ok "CH-19: repeated TERM/HUP during cleanup do not abort it (meson killed, lock released)"; fi

    # Q: meson is handed clean INT/QUIT dispositions (bash >= 4.4; /proc needed to observe it).
    if [[ -r /proc/self/status ]] && (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )); then
        : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
        ch_run ch19q "$build" --
        local sig; sig=$(grep "^SIGIGN " "$FK_MLOG" | head -1 | awk '{print $2}')
        # INT is bit 2 (0x2), QUIT bit 3 (0x4) in the SigIgn mask.
        if [[ -z "$sig" ]]; then bad "CH-19" "the mock meson recorded no SigIgn mask"
        elif (( (16#$sig & 6) != 0 )); then bad "CH-19" "meson inherited ignored INT/QUIT (SigIgn=$sig)"
        else ok "CH-19: meson is started with INT and QUIT restored"; fi
    fi


    # S: the real spelling and a symlink spelling of one build dir share ONE lock (and one orphan match).
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover" "$FK_ROOT/build-lnk" "$FK_ROOT/build-lnk.lock"
    mkdir -p "$build"; ln -s "$build" "$FK_ROOT/build-lnk"
    start_run ch19sa; start_run ch19sb
    ( env YUZU_MOCK_TEST_SLEEP=4 bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19sa \
        --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    for _ in $(seq 1 100); do grep -q "^LOCK-OWNER " "$FK_MLOG" && break; sleep 0.1; done
    local before_b; before_b=$(grep -c "^LOCK-OWNER " "$FK_MLOG")
    env bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19sb --build-dir "$FK_ROOT/build-lnk" \
        --baseline "$FK_BASE" --report-only >/dev/null 2>&1
    local after_b; after_b=$(grep -c "^LOCK-OWNER " "$FK_MLOG")
    wait
    if [[ "$before_b" != "1" ]]; then bad "CH-19" "symlink-spelling test setup failed (first gate never reached its meson test)"
    elif [[ "$after_b" != "1" ]]; then bad "CH-19" "a run through a symlink spelling of a locked build dir proceeded ($after_b meson tests)"
    elif [[ "$(db_gate_notes ch19sb Coverage)" != *"another coverage-gate run"* ]]; then bad "CH-19" "symlink-spelling refusal has the wrong reason: $(db_gate_notes ch19sb Coverage)"
    else ok "CH-19: a symlink spelling of a locked build dir is refused by the same lock"; fi
    rm -f "$FK_ROOT/build-lnk"

    # T: a malformed YUZU_COVERAGE_KILL_GRACE_SECS is refused up front (before any build or lock),
    # never evaluated in arithmetic inside the EXIT handler (where it would abort the cleanup, and
    # `a[$(cmd)]` would even run a command).
    local bad_grace marker="$CHAOS_ROOT/ch19-grace-ran"
    for bad_grace in "abc" "1.5" "1 2" 'a[$(touch '"$marker"')]' "-3" "12345"; do
        : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover" "$marker"
        ch_run ch19t "$build" -- YUZU_COVERAGE_KILL_GRACE_SECS="$bad_grace"
        if [[ -s "$FK_MLOG" ]]; then bad "CH-19" "KILL_GRACE_SECS='$bad_grace' was not refused up front: $(cat "$FK_MLOG")"
        elif [[ -e "$marker" ]]; then bad "CH-19" "KILL_GRACE_SECS='$bad_grace' executed a command"
        elif [[ "$(db_gate_notes ch19t Coverage)" != *"invalid YUZU_COVERAGE_KILL_GRACE_SECS"* ]]; then
            bad "CH-19" "KILL_GRACE_SECS='$bad_grace' refusal has the wrong reason: $(db_gate_notes ch19t Coverage)"
        elif [[ -e "$lock" || -L "$lock" ]]; then bad "CH-19" "lock left behind after refusing KILL_GRACE_SECS='$bad_grace'"
        else ok "CH-19: KILL_GRACE_SECS='${bad_grace:0:24}' is refused before anything runs"; fi
    done

    # T2: the KILL after the grace period takes meson's TEST CHILDREN with it, even though (like real
    # meson's tests) they sit in their OWN session and process group.
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    pidfile="$CHAOS_ROOT/ch19-t2.pid"; local childfile="$CHAOS_ROOT/ch19-t2.child"; rm -f "$pidfile" "$childfile"
    start_run ch19t2
    ( env YUZU_MOCK_IGNORE_TERM=1 YUZU_MOCK_TEST_SLEEP=25 YUZU_MOCK_PIDFILE="$pidfile" YUZU_MOCK_CHILDFILE="$childfile" YUZU_COVERAGE_KILL_GRACE_SECS=2 \
        bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19t2 --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    local gate5=$!
    for _ in $(seq 1 100); do [[ -s "$childfile" ]] && break; sleep 0.1; done
    mock_pid=$(cat "$pidfile" 2>/dev/null); local child_pid; child_pid=$(cat "$childfile" 2>/dev/null)
    gate_real=$(readlink "$lock" 2>/dev/null)
    [[ -n "$gate_real" ]] && kill -TERM "$gate_real" 2>/dev/null
    for _ in $(seq 1 120); do kill -0 "$gate5" 2>/dev/null || break; sleep 0.1; done
    wait "$gate5" 2>/dev/null
    if [[ -z "$mock_pid" || -z "$child_pid" || -z "$gate_real" ]]; then bad "CH-19" "descendant-kill test setup failed (meson '$mock_pid', child '$child_pid', gate '$gate_real')"
    elif kill -0 "$child_pid" 2>/dev/null; then kill -KILL "$child_pid" "$mock_pid" 2>/dev/null; bad "CH-19" "the grace-period KILL left meson's test child (pid $child_pid) running"
    else ok "CH-19: the grace-period KILL takes meson's test children with it (they are in their own session)"; fi

    # T3: meson obeys TERM promptly but leaves a test child in its own session behind: the child is
    # still found (snapshot taken BEFORE the TERM) and killed once the grace period is over.
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    pidfile="$CHAOS_ROOT/ch19-t3.pid"; childfile="$CHAOS_ROOT/ch19-t3.child"; rm -f "$pidfile" "$childfile"
    start_run ch19t3
    ( env YUZU_MOCK_EXIT_ON_TERM_LEAVE_CHILD=1 YUZU_MOCK_PIDFILE="$pidfile" YUZU_MOCK_CHILDFILE="$childfile" YUZU_COVERAGE_KILL_GRACE_SECS=2 \
        bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19t3 --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    local gate6=$!
    for _ in $(seq 1 100); do [[ -s "$childfile" && -s "$pidfile" ]] && break; sleep 0.1; done
    mock_pid=$(cat "$pidfile" 2>/dev/null); child_pid=$(cat "$childfile" 2>/dev/null); gate_real=$(readlink "$lock" 2>/dev/null)
    [[ -n "$gate_real" ]] && kill -TERM "$gate_real" 2>/dev/null
    for _ in $(seq 1 120); do kill -0 "$gate6" 2>/dev/null || break; sleep 0.1; done
    wait "$gate6" 2>/dev/null
    if [[ -z "$mock_pid" || -z "$child_pid" || -z "$gate_real" ]]; then bad "CH-19" "orphan-child test setup failed (meson '$mock_pid', child '$child_pid', gate '$gate_real')"
    elif kill -0 "$child_pid" 2>/dev/null; then kill -KILL "$child_pid" 2>/dev/null; bad "CH-19" "a test child left behind by a meson that exited on TERM (pid $child_pid) survived the gate"
    else ok "CH-19: a test child left behind by a meson that exited on TERM is killed too"; fi

    # Y: a SIGHUP aimed at the gate's whole process GROUP (terminal close, ssh drop, a wrapper killing
    # the group) must not strand meson's test processes: meson is in its own group (set -m), so the
    # HUP reaches only the gate, which then terminates meson and the tree. Without set -m meson dies
    # at once, its snapshot is just itself, and its setsid'd tests are orphaned.
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    pidfile="$CHAOS_ROOT/ch19-y.pid"; childfile="$CHAOS_ROOT/ch19-y.child"; rm -f "$pidfile" "$childfile"
    start_run ch19y
    local yres
    yres=$(python3 - "$FK_ROOT" "$build" "$FK_BASE" "$pidfile" "$childfile" <<'PY'
import os, signal, subprocess, sys, time
root, build, base, pidfile, childfile = sys.argv[1:6]
env = dict(os.environ, YUZU_MOCK_IGNORE_TERM="1", YUZU_MOCK_TEST_SLEEP="25", YUZU_MOCK_PIDFILE=pidfile,
           YUZU_MOCK_CHILDFILE=childfile, YUZU_COVERAGE_KILL_GRACE_SECS="2")
def pre():
    os.setsid()                                  # its own session and group, like a terminal job
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGHUP, signal.SIG_DFL)
p = subprocess.Popen(["bash", f"{root}/scripts/test/coverage-gate.sh", "--run-id", "ch19y", "--build-dir", build,
                      "--baseline", base, "--report-only"], preexec_fn=pre, env=env,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(150):
    if os.path.exists(childfile) and os.path.getsize(childfile) and os.path.exists(pidfile) and os.path.getsize(pidfile):
        break
    time.sleep(0.1)
else:
    print("SETUP_FAILED"); p.kill(); sys.exit(0)
child = int(open(childfile).read()); mock = int(open(pidfile).read())
os.killpg(os.getpgid(p.pid), signal.SIGHUP)      # the whole group
try:
    rc = p.wait(timeout=20)
except subprocess.TimeoutExpired:
    rc = "TIMEOUT"; p.kill()
time.sleep(0.5)
def alive(x):
    try: os.kill(x, 0); return True
    except OSError: return False
print(f"RESULT rc={rc} child_alive={int(alive(child))} meson_alive={int(alive(mock))} child={child}")
for x in (child, mock):
    try: os.kill(x, signal.SIGKILL)
    except OSError: pass
PY
)
    if [[ "$yres" == *SETUP_FAILED* || "$yres" != RESULT* ]]; then bad "CH-19" "group-HUP test setup failed: $yres"
    elif [[ "$yres" != *"child_alive=0"* ]]; then bad "CH-19" "a SIGHUP to the gate's process group stranded meson's test child: $yres"
    elif [[ "$yres" != *"meson_alive=0"* ]]; then bad "CH-19" "a SIGHUP to the gate's process group left meson running: $yres"
    elif [[ "$yres" != *"rc=129"* ]]; then bad "CH-19" "a SIGHUP to the gate's group did not give exit 129: $yres"
    elif [[ -e "$lock" || -L "$lock" ]]; then bad "CH-19" "lock left behind after a group SIGHUP"
    else ok "CH-19: a SIGHUP to the gate's whole process group ends meson and its test children (exit 129, lock released)"; fi

    # ---- EXT tests (qe round) ----
    # helper: run a gate in bg with tree-mode, TERM it, wait.
    ext_tree() {  # tag mode grace [extra env...]; sets X_MOCK X_CHILD X_GATE X_T
        local tag="$1" mode="$2" gr="$3"; shift 3
        : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
        local pf="$CHAOS_ROOT/$tag.pid" cf="$CHAOS_ROOT/$tag.child"; rm -f "$pf" "$cf" "$CHAOS_ROOT/$tag.done"
        start_run "$tag"
        ( env YUZU_MOCK_TREE_MODE="$mode" YUZU_MOCK_PIDFILE="$pf" YUZU_MOCK_CHILDFILE="$cf" YUZU_MOCK_DONEFILE="$CHAOS_ROOT/$tag.done" YUZU_COVERAGE_KILL_GRACE_SECS="$gr" "$@" \
            bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id "$tag" --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
        local g=$!
        for _ in $(seq 1 100); do [[ -s "$cf" && -s "$pf" ]] && break; sleep 0.1; done
        X_MOCK=$(cat "$pf" 2>/dev/null); X_CHILD=$(cat "$cf" 2>/dev/null); X_GATE=$(readlink "$lock" 2>/dev/null)
        local t0=$SECONDS
        [[ -n "$X_GATE" ]] && kill -TERM "$X_GATE" 2>/dev/null
        for _ in $(seq 1 400); do kill -0 "$g" 2>/dev/null || break; sleep 0.1; done
        X_T=$(( SECONDS - t0 ))
        wait "$g" 2>/dev/null
    }
    # X1 grandchild (depth 2) must be killed
    ext_tree x1 grandchild 2
    if [[ -z "$X_MOCK" || -z "$X_CHILD" ]]; then bad "CH-19x" "X1 setup"
    elif kill -0 "$X_CHILD" 2>/dev/null; then kill -KILL "$X_CHILD" 2>/dev/null; bad "CH-19x" "X1 grandchild survived"
    else ok "CH-19x: X1 grandchild killed"; fi
    # X2 slow-exiting child gets the grace (not KILLed early)
    ext_tree x2 slowexit 10
    if [[ ! -e "$CHAOS_ROOT/x2.done" ]]; then kill -KILL "$X_CHILD" 2>/dev/null; bad "CH-19x" "X2 child was killed before finishing its work (grace not honoured)"
    else ok "CH-19x: X2 child finished within grace"; fi
    # X3 pid-reuse: lstart flips -> child must NOT be killed
    ext_tree x3 leave 2 YUZU_MOCK_LSTART_FLIP="$CHAOS_ROOT/x3.flip"
    if [[ -z "$X_CHILD" ]]; then bad "CH-19x" "X3 setup"
    elif kill -0 "$X_CHILD" 2>/dev/null; then kill -KILL "$X_CHILD" 2>/dev/null; ok "CH-19x: X3 differing start time => not killed"
    else bad "CH-19x" "X3 process with a different start time was killed"; fi
    # X4 prompt exit, big grace => gate returns fast
    ext_tree x4 none 30 YUZU_MOCK_TEST_SLEEP=30
    if (( X_T > 12 )); then bad "CH-19x" "X4 gate took ${X_T}s after TERM with prompt-exiting meson"; else ok "CH-19x: X4 prompt exit ${X_T}s"; fi
    # X5 stdin of meson is /dev/null even if gate's stdin is a file (Linux only: reads /proc/self/fd/0)
    if [[ "$(uname -s)" == Linux ]]; then
        : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"; echo hi > "$CHAOS_ROOT/stdin.txt"; start_run x5
        env bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id x5 --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 < "$CHAOS_ROOT/stdin.txt"
        if [[ "$(grep '^STDIN ' "$FK_MLOG" | head -1)" == "STDIN /dev/null" ]]; then ok "CH-19x: X5 stdin /dev/null"; else bad "CH-19x" "X5 stdin: $(grep '^STDIN ' "$FK_MLOG")"; fi
    fi
    # X6 second TERM/HUP while the snapshot is being taken must not abort cleanup
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"; pf="$CHAOS_ROOT/x6.pid"; rm -f "$pf" "$CHAOS_ROOT/x6.mark"; start_run x6
    ( env YUZU_MOCK_TEST_SLEEP=30 YUZU_MOCK_PIDFILE="$pf" YUZU_MOCK_DESC_DELAY=3 YUZU_MOCK_DESC_MARK="$CHAOS_ROOT/x6.mark" \
        bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id x6 --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    g6=$!
    for _ in $(seq 1 100); do [[ -s "$pf" ]] && break; sleep 0.1; done
    mock_pid=$(cat "$pf" 2>/dev/null); gate_real=$(readlink "$lock" 2>/dev/null)
    [[ -n "$gate_real" ]] && kill -TERM "$gate_real" 2>/dev/null
    for _ in $(seq 1 50); do [[ -e "$CHAOS_ROOT/x6.mark" ]] && break; sleep 0.05; done
    [[ -n "$gate_real" ]] && { kill -TERM "$gate_real" 2>/dev/null; kill -HUP "$gate_real" 2>/dev/null; }
    for _ in $(seq 1 200); do kill -0 "$g6" 2>/dev/null || break; sleep 0.1; done
    st6=no; kill -0 "$g6" 2>/dev/null && st6=yes; [[ $st6 == yes ]] && kill -KILL "$gate_real" 2>/dev/null
    wait "$g6" 2>/dev/null
    if [[ -z "$mock_pid" || -z "$gate_real" || ! -e "$CHAOS_ROOT/x6.mark" ]]; then bad "CH-19x" "X6 setup"
    elif kill -0 "$mock_pid" 2>/dev/null; then kill -KILL "$mock_pid" 2>/dev/null; bad "CH-19x" "X6 signal during snapshot aborted cleanup, meson left running"
    elif [[ -e "$lock" || -L "$lock" ]]; then bad "CH-19x" "X6 lock leaked"
    else ok "CH-19x: X6 signals during snapshot do not abort cleanup"; fi
    # X7 zombie snapshot members (non-reaping subreaper, like a container PID 1): prompt, not full grace
    ext_tree_sub() {  # like ext_tree but gate runs under a non-reaping subreaper
        local tag="$1" mode="$2" gr="$3"; shift 3
        : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
        local pf="$CHAOS_ROOT/$tag.pid" cf="$CHAOS_ROOT/$tag.child"; rm -f "$pf" "$cf"
        start_run "$tag"
        ( env YUZU_MOCK_TREE_MODE="$mode" YUZU_MOCK_PIDFILE="$pf" YUZU_MOCK_CHILDFILE="$cf" YUZU_MOCK_DONEFILE="$CHAOS_ROOT/$tag.done" YUZU_COVERAGE_KILL_GRACE_SECS="$gr" "$@" \
            python3 -c 'import ctypes,subprocess,sys; ctypes.CDLL(None).prctl(36,1,0,0,0); sys.exit(subprocess.Popen(sys.argv[1:]).wait())' \
            bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id "$tag" --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
        local g=$!
        for _ in $(seq 1 100); do [[ -s "$cf" && -s "$pf" ]] && break; sleep 0.1; done
        X_MOCK=$(cat "$pf" 2>/dev/null); X_CHILD=$(cat "$cf" 2>/dev/null); X_GATE=$(readlink "$lock" 2>/dev/null)
        local t0=$SECONDS
        [[ -n "$X_GATE" ]] && kill -TERM "$X_GATE" 2>/dev/null
        for _ in $(seq 1 400); do kill -0 "$g" 2>/dev/null || break; sleep 0.1; done
        X_T=$(( SECONDS - t0 ))
        wait "$g" 2>/dev/null
    }
    if [[ "$(uname -s)" == Linux ]]; then   # needs prctl(PR_SET_CHILD_SUBREAPER)
        ext_tree_sub x7 zombie 30
        if [[ -z "$X_GATE" ]]; then bad "CH-19x" "X7 setup"
        elif (( X_T > 12 )); then bad "CH-19x" "X7 gate waited ${X_T}s for zombies (grace 30)"; else ok "CH-19x: X7 zombies not waited for (${X_T}s)"; fi
    fi
    # X8 meson ignores TERM and has NO child: root must be KILLed after grace
    ext_tree x8 noch 2
    if [[ -z "$X_GATE" ]]; then bad "CH-19x" "X8 setup"
    elif kill -0 "$X_MOCK" 2>/dev/null || (( X_T > 10 )); then kill -KILL "$X_MOCK" 2>/dev/null; bad "CH-19x" "X8 childless TERM-ignoring meson not KILLed at the grace (gate took ${X_T}s)"
    else ok "CH-19x: X8 childless meson killed (${X_T}s)"; fi
    # X10 strong T3: meson exits on TERM at once; child still killed
    ext_tree x10 leave 2
    if [[ -z "$X_CHILD" ]]; then bad "CH-19x" "X10 setup"
    elif kill -0 "$X_CHILD" 2>/dev/null; then kill -KILL "$X_CHILD" 2>/dev/null; bad "CH-19x" "X10 child survived"
    else ok "CH-19x: X10 child killed after immediate-exit meson"; fi
    # X9 ps cannot report start times: a pid whose identity cannot be proven should not be KILLed
    ext_tree x9 leave 2 YUZU_MOCK_NO_LSTART=1
    if [[ -z "$X_CHILD" ]]; then bad "CH-19x" "X9 setup"
    elif kill -0 "$X_CHILD" 2>/dev/null; then kill -KILL "$X_CHILD" 2>/dev/null; ok "CH-19x: X9 no lstart => unprovable pid not killed"
    else bad "CH-19x" "X9 with no start time available the pid was KILLed on an unproven identity"; fi

    # Z: when ps cannot give a start time (busybox-style), a descendant cannot be PROVEN to be the same
    # process, so it is NOT killed (never a reused pid); meson itself, our own child, still is.
    # resolve the real ps with the fixture bin off PATH (an earlier scenario may have left a stub there,
    # and a stub that exec's itself prints nothing - the snapshot would then hold only the root)
    rm -f "$FK_BIN/ps"
    local realps; realps=$(PATH="${PATH//$FK_BIN:/}" command -v ps)
    cat > "$FK_BIN/ps" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do [[ "\$a" == lstart=* ]] && exit 1; done
exec "$realps" "\$@"
EOF
    chmod +x "$FK_BIN/ps"
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    pidfile="$CHAOS_ROOT/ch19-z.pid"; childfile="$CHAOS_ROOT/ch19-z.child"; rm -f "$pidfile" "$childfile"
    start_run ch19z
    ( env YUZU_MOCK_IGNORE_TERM=1 YUZU_MOCK_TEST_SLEEP=25 YUZU_MOCK_PIDFILE="$pidfile" YUZU_MOCK_CHILDFILE="$childfile" YUZU_COVERAGE_KILL_GRACE_SECS=1 \
        bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19z --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    local gate8=$!
    for _ in $(seq 1 100); do [[ -s "$childfile" && -s "$pidfile" ]] && break; sleep 0.1; done
    mock_pid=$(cat "$pidfile" 2>/dev/null); child_pid=$(cat "$childfile" 2>/dev/null); gate_real=$(readlink "$lock" 2>/dev/null)
    [[ -n "$gate_real" ]] && kill -TERM "$gate_real" 2>/dev/null
    for _ in $(seq 1 100); do kill -0 "$gate8" 2>/dev/null || break; sleep 0.1; done
    wait "$gate8" 2>/dev/null
    local z_child=dead z_mock=dead
    kill -0 "$child_pid" 2>/dev/null && z_child=alive; kill -0 "$mock_pid" 2>/dev/null && z_mock=alive
    kill -KILL "$child_pid" "$mock_pid" 2>/dev/null
    rm -f "$FK_BIN/ps"
    if [[ -z "$mock_pid" || -z "$child_pid" || -z "$gate_real" ]]; then bad "CH-19" "no-start-time test setup failed"
    elif [[ "$z_mock" == "alive" ]]; then bad "CH-19" "without start times the gate left meson itself running"
    elif [[ "$z_child" == "dead" ]]; then bad "CH-19" "without a start time the gate killed a descendant it could not identify"
    else ok "CH-19: with no start time available a descendant is never killed, meson itself still is"; fi

    # P3: a zero-padded grace (08) is decimal: the KILL escalation still happens (the 10# in the arithmetic).
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    pidfile="$CHAOS_ROOT/ch19-p3.pid"; rm -f "$pidfile"
    start_run ch19p3
    ( env YUZU_MOCK_IGNORE_TERM=1 YUZU_MOCK_TEST_SLEEP=40 YUZU_MOCK_PIDFILE="$pidfile" YUZU_COVERAGE_KILL_GRACE_SECS=08 \
        bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19p3 --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    local gate7=$!
    for _ in $(seq 1 100); do [[ -s "$pidfile" ]] && break; sleep 0.1; done
    mock_pid=$(cat "$pidfile" 2>/dev/null); gate_real=$(readlink "$lock" 2>/dev/null)
    [[ -n "$gate_real" ]] && kill -TERM "$gate_real" 2>/dev/null
    for _ in $(seq 1 200); do kill -0 "$gate7" 2>/dev/null || break; sleep 0.1; done
    local stuck3=no; kill -0 "$gate7" 2>/dev/null && stuck3=yes
    [[ "$stuck3" == "yes" ]] && kill -KILL "$gate_real" "$mock_pid" 2>/dev/null
    wait "$gate7" 2>/dev/null
    if [[ -z "$mock_pid" || -z "$gate_real" ]]; then bad "CH-19" "grace=08 test setup failed"
    elif [[ "$stuck3" == "yes" ]] || kill -0 "$mock_pid" 2>/dev/null; then kill -KILL "$mock_pid" 2>/dev/null; bad "CH-19" "KILL_GRACE_SECS=08 did not escalate to KILL within 20 s (octal misread?)"
    else ok "CH-19: KILL_GRACE_SECS=08 is read as decimal and the KILL escalation happens"; fi

    # W: a refused run whose own pid equals the holder's must not delete the lock it never took
    # (pid reuse / another PID namespace). A stand-in: the lock names the pid the gate will have.
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    # (bash -c: $$ is the pid that survives the exec; BASHPID does not exist in bash 3.2)
    bash -c 'ln -s "$$" "$1"; shift; exec "$@"' _ "$lock" env bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19w \
        --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1
    if [[ -s "$FK_MLOG" ]]; then bad "CH-19" "the gate ran although the lock named its own pid"
    elif [[ ! -L "$lock" ]]; then bad "CH-19" "a refused run deleted a lock it never took"
    else ok "CH-19: a refused run leaves a lock it never took alone"; fi
    rm -f "$lock"

    # U: no pgrep on PATH -> the run proceeds and the skipped check is announced.
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover"
    local farm="$CHAOS_ROOT/nopgrep-bin"; rm -rf "$farm"; mkdir -p "$farm"
    local d f; for d in $(echo "$FK_SAVED_PATH" | tr ':' ' '); do
        [[ -d "$d" ]] || continue
        for f in "$d"/*; do [[ -x "$f" && -f "$f" || -L "$f" ]] || continue; [[ "${f##*/}" == "pgrep" ]] && continue
            [[ -e "$farm/${f##*/}" ]] || ln -s "$f" "$farm/${f##*/}"; done
    done
    ch_run ch19u "$build" -- PATH="$FK_BIN:$farm"
    if command -v pgrep >/dev/null && PATH="$FK_BIN:$farm" command -v pgrep >/dev/null 2>&1; then bad "CH-19" "test setup: pgrep still reachable"
    elif ! grep -q "^LOCK-OWNER " "$FK_MLOG"; then bad "CH-19" "a missing pgrep stopped the run: $FK_OUT"
    elif ! grep -q "pgrep not found" <<<"$FK_OUT"; then bad "CH-19" "a missing pgrep was not announced"
    else ok "CH-19: a missing pgrep is announced and does not stop the run"; fi
    rm -rf "$farm"

    # V: reconfigure failure through a symlinked build dir wipes the real dir and leaves the link valid.
    : > "$FK_MLOG"; rm -rf "$build" "$lock" "$lock.takeover" "$FK_ROOT/build-lnk"
    mkdir -p "$build"; : > "$build/stale-sentinel"; ln -s "$build" "$FK_ROOT/build-lnk"
    ch_run ch19v "$FK_ROOT/build-lnk" -- YUZU_MOCK_RECONF_FAIL=1
    if [[ -e "$build/stale-sentinel" ]]; then bad "CH-19" "reconfigure failure did not wipe the stale dir: $FK_OUT"
    elif [[ ! -L "$FK_ROOT/build-lnk" || ! -d "$FK_ROOT/build-lnk" ]]; then bad "CH-19" "symlinked build dir: link replaced or dangling after wipe"
    else ok "CH-19: a reconfigure failure through a symlinked build dir wipes the real dir and keeps the link"; fi
    rm -f "$FK_ROOT/build-lnk"

    export PATH="$FK_SAVED_PATH"
    rm -rf "$FK_ROOT" 2>/dev/null || true
}

scenario_CH_20() {
    echo ""
    echo "=== CH-20: coverage-gate reports incomplete runs as inconclusive (#6113) ==="
    init_db || { bad "CH-20" "db init failed"; return; }
    ch_fixture ch20
    local build="$FK_ROOT/build-ch20"

    # A: clean run records both metrics.
    ch_run ch20a "$build" -- YUZU_COVERAGE_TIMEOUT_MULT=
    if [[ "$(db_metric ch20a branch_coverage_overall)" == "MISSING" || "$(db_metric ch20a line_coverage_overall)" == "MISSING" ]]; then
        bad "CH-20" "clean run did not record both metrics (rc=$FK_RC): $FK_OUT"
    else ok "CH-20: a clean run records branch and line metrics"; fi

    # B: failing tests, enforce -> WARN, exit 2, no metric, no comparison.
    ch_run ch20b "$build" -- YUZU_MOCK_TEST_RC=3
    if [[ "$FK_RC" != "2" || "$(db_gate_status ch20b Coverage)" != "WARN" || "$(db_gate_notes ch20b Coverage)" != "inconclusive:"* ]]; then
        bad "CH-20" "failing tests (enforce) not inconclusive: rc=$FK_RC status=$(db_gate_status ch20b Coverage) notes=$(db_gate_notes ch20b Coverage)"
    elif [[ "$(db_metric ch20b branch_coverage_overall)" != "MISSING" || "$(db_metric ch20b line_coverage_overall)" != "MISSING" ]]; then
        bad "CH-20" "an inconclusive run still recorded an ordinary metric"
    else ok "CH-20: failing tests -> WARN, exit 2, no metric, no baseline comparison"; fi

    # C: same, --report-only -> WARN row (not PASS), exit 0, no metric.
    ch_run ch20c "$build" --report-only -- YUZU_MOCK_TEST_RC=3
    if [[ "$FK_RC" != "0" || "$(db_gate_status ch20c Coverage)" != "WARN" || "$(db_metric ch20c branch_coverage_overall)" != "MISSING" ]]; then
        bad "CH-20" "failing tests (report-only) not inconclusive: rc=$FK_RC status=$(db_gate_status ch20c Coverage) metric=$(db_metric ch20c branch_coverage_overall)"
    else ok "CH-20: failing tests under --report-only -> WARN row (not PASS), exit 0, no metric"; fi

    # D: capture is refused on an inconclusive run and writes nothing.
    rm -f "$FK_BASE"
    ch_run ch20d "$build" --capture-baselines -- YUZU_MOCK_TEST_RC=3
    if [[ "$FK_RC" != "1" || "$(db_gate_status ch20d Coverage)" != "FAIL" || -e "$FK_BASE" ]]; then
        bad "CH-20" "capture on an inconclusive run: rc=$FK_RC status=$(db_gate_status ch20d Coverage) baseline_written=$([[ -e "$FK_BASE" ]] && echo yes || echo no)"
    else ok "CH-20: --capture-baselines is refused on an inconclusive run and writes no baseline"; fi
    printf '{"branch_percent":60.0,"line_percent":70.0,"slack_pp":0.5}' > "$FK_BASE"

    # E: gcovr reports no line figure -> no fabricated 0.0, branch still recorded, capture refused.
    ch_run ch20e "$build" -- YUZU_MOCK_NO_LINE=1
    if [[ "$(db_metric ch20e line_coverage_overall)" != "MISSING" ]]; then
        bad "CH-20" "an unknown line figure was recorded as $(db_metric ch20e line_coverage_overall)"
    elif [[ "$(db_metric ch20e branch_coverage_overall)" == "MISSING" ]]; then
        bad "CH-20" "branch metric missing when only the line figure is unknown"
    else
        rm -f "$FK_BASE"
        ch_run ch20f "$build" --capture-baselines -- YUZU_MOCK_NO_LINE=1
        if [[ "$FK_RC" != "1" || -e "$FK_BASE" ]]; then bad "CH-20" "capture with an unknown line figure: rc=$FK_RC"
        else ok "CH-20: an unknown line figure is never recorded as 0.0, and capture refuses to anchor it"; fi
    fi

    # G: a clean --capture-baselines still captures (the path whose ordering moved).
    rm -f "$FK_BASE"
    ch_run ch20g "$build" --capture-baselines --
    if [[ "$FK_RC" != "0" || "$(db_gate_status ch20g Coverage)" != "PASS" || ! -s "$FK_BASE" ]] \
       || ! python3 - "$FK_BASE" <<'PY'
import json, sys
b = json.load(open(sys.argv[1]))
sys.exit(0 if abs(b["branch_percent"] - 65.5) < 0.01 and abs(b["line_percent"] - 72.0) < 0.01 else 1)
PY
    then bad "CH-20" "clean capture: rc=$FK_RC status=$(db_gate_status ch20g Coverage) baseline=$(cat "$FK_BASE" 2>/dev/null)"
    else ok "CH-20: a clean --capture-baselines writes the measured branch and line figures"; fi
    printf '{"branch_percent":60.0,"line_percent":70.0,"slack_pp":0.5}' > "$FK_BASE"

    # H: when gcovr itself fails on an already-inconclusive run, the WARN row keeps both reasons.
    ch_run ch20h "$build" -- YUZU_MOCK_TEST_RC=3 YUZU_MOCK_GCOVR_RC=1
    if [[ "$(db_gate_status ch20h Coverage)" != "WARN" || "$(db_gate_notes ch20h Coverage)" != *"gcovr failed"* \
          || "$(db_gate_notes ch20h Coverage)" != *"meson test exit=3"* ]]; then
        bad "CH-20" "gcovr failure dropped the inconclusive reasons: status=$(db_gate_status ch20h Coverage) notes=$(db_gate_notes ch20h Coverage)"
    else ok "CH-20: a gcovr failure on an inconclusive run still names the test failure"; fi

    # J: a summary file left by an earlier run is never taken for this run's (gcovr that writes nothing).
    printf '{"branch_percent":99.0,"line_percent":99.0}' > "$build/coverage-summary.json"
    ch_run ch20j "$build" -- YUZU_MOCK_GCOVR_NOWRITE=1
    if [[ "$(db_gate_status ch20j Coverage)" != "WARN" || "$(db_gate_notes ch20j Coverage)" != *"gcovr failed"* \
          || "$(db_metric ch20j branch_coverage_overall)" != "MISSING" ]]; then
        bad "CH-20" "a stale coverage-summary.json was used: status=$(db_gate_status ch20j Coverage) notes=$(db_gate_notes ch20j Coverage) metric=$(db_metric ch20j branch_coverage_overall)"
    else ok "CH-20: a stale coverage-summary.json from an earlier run is removed, not parsed"; fi

    # K: a spelling of the build dir relative to the current directory does not leave the summary outside it.
    ( cd "$build" && env bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch20k --build-dir . \
        --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) || true
    start_run ch20k2
    if [[ -e "$FK_ROOT/coverage-summary.json" ]]; then bad "CH-20" "gcovr summary written outside the build dir (cwd-relative --build-dir)"
    elif ! grep -q '"branch_percent":65.5' "$build/coverage-summary.json" 2>/dev/null; then bad "CH-20" "the --build-dir . run never produced this run's summary inside the build dir (gate refused early?)"
    else ok "CH-20: --build-dir . keeps every gcovr output inside the build dir"; fi

    # L: a truncated baseline is reported as unreadable (WARN, exit 2), not as a coverage regression.
    printf '{"branch_perc' > "$FK_BASE"
    ch_run ch20l "$build" --
    if [[ "$FK_RC" != "2" || "$(db_gate_status ch20l Coverage)" != "WARN" || "$(db_gate_notes ch20l Coverage)" != *"unreadable"* ]]; then
        bad "CH-20" "a truncated baseline: rc=$FK_RC status=$(db_gate_status ch20l Coverage) notes=$(db_gate_notes ch20l Coverage)"
    else ok "CH-20: a truncated baseline is reported as unreadable, not as a regression"; fi
    printf '{"branch_percent":60.0,"line_percent":70.0,"slack_pp":0.5}' > "$FK_BASE"

    # L2: the same truncated baseline under --report-only is a WARN row (exit 0), never a PASS row.
    printf '{"branch_perc' > "$FK_BASE"
    ch_run ch20l2 "$build" --report-only --
    if [[ "$FK_RC" != "0" || "$(db_gate_status ch20l2 Coverage)" != "WARN" ]]; then
        bad "CH-20" "a truncated baseline under --report-only: rc=$FK_RC status=$(db_gate_status ch20l2 Coverage)"
    else ok "CH-20: a truncated baseline under --report-only is a WARN row, not a PASS"; fi
    printf '{"branch_percent":60.0,"line_percent":70.0,"slack_pp":0.5}' > "$FK_BASE"

    # M: a capture leaves no temp file behind and the baseline is complete JSON.
    rm -f "$FK_BASE"; ch_run ch20m "$build" --capture-baselines --
    if [[ -n "$(ls "$FK_BASE".tmp* 2>/dev/null)" ]] || ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$FK_BASE" 2>/dev/null; then
        bad "CH-20" "capture left a temp file or an invalid baseline: $(ls "$FK_BASE"* 2>&1)"
    else ok "CH-20: baseline capture is atomic (no temp file, valid JSON)"; fi
    printf '{"branch_percent":60.0,"line_percent":70.0,"slack_pp":0.5}' > "$FK_BASE"

    # P2: a capture whose final rename fails (the baseline path is a directory) is a FAIL row and
    # leaves no temp file behind.
    local bdir="$CHAOS_ROOT/ch20-bdir"; rm -rf "$bdir"; mkdir -p "$bdir"
    start_run ch20p2
    FK_OUT=$(env bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch20p2 --build-dir "$build" \
        --baseline "$bdir" --capture-baselines 2>&1) && FK_RC=0 || FK_RC=$?
    if [[ "$FK_RC" != "1" || "$(db_gate_status ch20p2 Coverage)" != "FAIL" ]]; then
        bad "CH-20" "capture over an unwritable baseline path: rc=$FK_RC status=$(db_gate_status ch20p2 Coverage)"
    elif [[ -n "$(ls -d "$bdir".tmp* 2>/dev/null)" ]]; then bad "CH-20" "a failed capture left a temp file: $(ls -d "$bdir".tmp*)"
    else ok "CH-20: a capture that cannot rename its baseline fails and leaves no temp file"; fi
    rm -rf "$bdir"

    # I: same when gcovr succeeds but its summary cannot be parsed.
    ch_run ch20i "$build" -- YUZU_MOCK_TEST_RC=3 YUZU_MOCK_BAD_JSON=1
    if [[ "$(db_gate_notes ch20i Coverage)" != *"could not parse"* || "$(db_gate_notes ch20i Coverage)" != *"meson test exit=3"* ]]; then
        bad "CH-20" "a parse failure dropped the inconclusive reasons: $(db_gate_notes ch20i Coverage)"
    else ok "CH-20: a parse failure on an inconclusive run still names the test failure"; fi


    # N: capturing over a truncated OLD baseline works and leaves valid JSON.
    printf '{"branch_perc' > "$FK_BASE"
    ch_run ch20n "$build" --capture-baselines --
    if [[ "$FK_RC" != "0" ]] || ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$FK_BASE" 2>/dev/null; then
        bad "CH-20" "capture over a truncated baseline: rc=$FK_RC base=$(cat "$FK_BASE")"
    else ok "CH-20: capture over a truncated old baseline succeeds"; fi
    printf '{"branch_percent":60.0,"line_percent":70.0,"slack_pp":0.5}' > "$FK_BASE"

    # O: the capture replaces the baseline by rename: a second hard link keeps the OLD bytes.
    rm -f "$FK_BASE.link"; ln "$FK_BASE" "$FK_BASE.link"
    ch_run ch20o "$build" --capture-baselines --
    if [[ "$(cat "$FK_BASE.link")" != '{"branch_percent":60.0,"line_percent":70.0,"slack_pp":0.5}' ]]; then
        bad "CH-20" "capture rewrote the baseline IN PLACE (a hard link saw the new bytes): $(head -c 80 "$FK_BASE.link")"
    else ok "CH-20: capture replaces the baseline by rename, not in place"; fi
    rm -f "$FK_BASE.link"; printf '{"branch_percent":60.0,"line_percent":70.0,"slack_pp":0.5}' > "$FK_BASE"

    # P: a capture that cannot write the baseline must not report PASS.
    mkdir -p "$CHAOS_ROOT/ro-base"; cp "$FK_BASE" "$CHAOS_ROOT/ro-base/b.json"; chmod 555 "$CHAOS_ROOT/ro-base"
    local save_base="$FK_BASE"; FK_BASE="$CHAOS_ROOT/ro-base/b.json"
    ch_run ch20p "$build" --capture-baselines --
    FK_BASE="$save_base"; chmod 755 "$CHAOS_ROOT/ro-base"
    if [[ "$(id -u)" == "0" ]]; then ok "CH-20: (root: unwritable-baseline case not applicable)"
    elif [[ "$(db_gate_status ch20p Coverage)" == "PASS" || "$FK_RC" == "0" ]]; then
        bad "CH-20" "a capture that could not write the baseline reported success: rc=$FK_RC status=$(db_gate_status ch20p Coverage) notes=$(db_gate_notes ch20p Coverage)"
    else ok "CH-20: a capture that cannot write the baseline does not report success"; fi
    rm -rf "$CHAOS_ROOT/ro-base"

    export PATH="$FK_SAVED_PATH"
    rm -rf "$FK_ROOT" 2>/dev/null || true
}

scenario_CH_21() {
    echo ""
    echo "=== CH-21: coverage-gate detects truncated counters and failed DB writes (#6114) ==="
    init_db || { bad "CH-21" "db init failed"; return; }
    ch_fixture ch21
    local build="$FK_ROOT/build-ch21"

    # A: libgcov error lines in the test log -> inconclusive, no metric.
    ch_run ch21a "$build" -- "YUZU_MOCK_TESTLOG_LINE=profiling:/x/y.gcda:Cannot create directory"
    if [[ "$(db_gate_status ch21a Coverage)" != "WARN" || "$(db_gate_notes ch21a Coverage)" != *"libgcov reported 1 profiling error"* \
          || "$(db_metric ch21a branch_coverage_overall)" != "MISSING" ]]; then
        bad "CH-21" "libgcov error line not treated as inconclusive: status=$(db_gate_status ch21a Coverage) notes=$(db_gate_notes ch21a Coverage)"
    else ok "CH-21: libgcov profiling errors in the test log make the run inconclusive"; fi

    # A2: libgcov writes at exit with no leading newline, and has a second message family.
    local line n=0
    for line in "noeolprofiling:/x/y.gcda:Cannot create directory" "libgcov profiling error:/x/y.gcda:Error writing"; do
        n=$((n+1))
        ch_run "ch21a$n" "$build" -- "YUZU_MOCK_TESTLOG_LINE=$line"
        if [[ "$(db_gate_status ch21a$n Coverage)" != "WARN" || "$(db_gate_notes ch21a$n Coverage)" != *"libgcov reported"* ]]; then
            bad "CH-21" "libgcov line not detected: '$line' -> $(db_gate_notes ch21a$n Coverage)"
        fi
    done
    [[ "$(db_gate_notes ch21a2 Coverage)" == *"libgcov reported"* ]] && ok "CH-21: an unterminated line before the libgcov message, and the 'libgcov profiling error' family, are both detected"

    # B: not enough free space after the run -> inconclusive.
    ch_run ch21b "$build" -- YUZU_COVERAGE_MIN_FREE_KB=999999999999
    if [[ "$(db_gate_status ch21b Coverage)" != "WARN" || "$(db_gate_notes ch21b Coverage)" != *"KB free on the build filesystem"* \
          || "$(db_metric ch21b branch_coverage_overall)" != "MISSING" ]]; then
        bad "CH-21" "low free space not treated as inconclusive: status=$(db_gate_status ch21b Coverage) notes=$(db_gate_notes ch21b Coverage)"
    else ok "CH-21: too little free space after the run makes it inconclusive"; fi

    # B2: a leading zero in the threshold is decimal, not octal (and not an arithmetic error).
    ch_run ch21b2 "$build" -- YUZU_COVERAGE_MIN_FREE_KB=0999999999
    if [[ "$(db_gate_notes ch21b2 Coverage)" != *"KB free on the build filesystem"* ]]; then
        bad "CH-21" "a zero-padded threshold was not honoured: $(db_gate_notes ch21b2 Coverage)"
    else ok "CH-21: a zero-padded YUZU_COVERAGE_MIN_FREE_KB is read as decimal"; fi

    # C: bad free-space threshold is refused before any meson call.
    : > "$FK_MLOG"
    ch_run ch21c "$build" -- YUZU_COVERAGE_MIN_FREE_KB=abc
    if [[ -s "$FK_MLOG" || "$(db_gate_notes ch21c Coverage)" != *"invalid YUZU_COVERAGE_MIN_FREE_KB"* ]]; then
        bad "CH-21" "bad YUZU_COVERAGE_MIN_FREE_KB not refused up front: notes=$(db_gate_notes ch21c Coverage) meson=$(cat "$FK_MLOG")"
    else ok "CH-21: an invalid free-space threshold is refused before any build"; fi

    # D: a failed metric write, and separately a failed gate-row write, each turn a
    # would-be success into exit 2 with an ERROR (the DB row IS the gate's result).
    local what d_ok=1
    for what in metric gate; do
        start_run "ch21d$what"
        FK_OUT=$(YUZU_MOCK_DB_FAIL=$what bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id "ch21d$what" \
            --build-dir "$build" --baseline "$FK_BASE" 2>&1) && FK_RC=0 || FK_RC=$?
        if [[ "$FK_RC" != "2" || "$FK_OUT" != *"ERROR could not record"* ]]; then
            bad "CH-21" "a failed $what DB write did not fail the gate: rc=$FK_RC out=$(printf '%s' "$FK_OUT" | tail -3)"
            d_ok=0
        fi
    done
    (( d_ok )) && ok "CH-21: a failed gate-row or metric DB write is reported and the gate exits 2 instead of 0"

    # D2: a DB write failure never masks a regression: exit 1 stays 1.
    printf '{"branch_percent":99.0,"line_percent":70.0,"slack_pp":0.5}' > "$FK_BASE"
    start_run ch21e
    FK_OUT=$(YUZU_MOCK_DB_FAIL=metric bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch21e \
        --build-dir "$build" --baseline "$FK_BASE" 2>&1) && FK_RC=0 || FK_RC=$?
    if [[ "$FK_RC" != "1" ]]; then bad "CH-21" "a regression exit (1) was changed by a DB failure: rc=$FK_RC"
    else ok "CH-21: a failed DB write does not change a regression's exit code 1"; fi

    export PATH="$FK_SAVED_PATH"
    rm -rf "$FK_ROOT" 2>/dev/null || true
}


# ── Scenario dispatch ───────────────────────────────────────────────────

SCENARIOS=(CH-2 CH-3 CH-4 CH-6 CH-8 CH-15 CH-16 CH-17 CH-18 CH-19 CH-20 CH-21)

# CH-1 (clean-log + workflow-failure → FAIL) requires a live gh CLI mock
# which is more involved — defer to a dedicated PR2.1 harness pass once
# the dispatch-runner-job.sh mocking story is settled. All other P0
# scenarios are covered here.

if [[ $# -gt 0 ]]; then
    SCENARIOS=("$@")
fi

for s in "${SCENARIOS[@]}"; do
    case "$s" in
        CH-2)  scenario_CH_2 ;;
        CH-3)  scenario_CH_3 ;;
        CH-4)  scenario_CH_4 ;;
        CH-6)  scenario_CH_6 ;;
        CH-8)  scenario_CH_8 ;;
        CH-15) scenario_CH_15 ;;
        CH-16) scenario_CH_16 ;;
        CH-17) scenario_CH_17 ;;
        CH-18) scenario_CH_18 ;;
        CH-19) scenario_CH_19 ;;
        CH-20) scenario_CH_20 ;;
        CH-21) scenario_CH_21 ;;
        *)     echo "unknown scenario: $s" >&2; exit 2 ;;
    esac
done

echo ""
echo "=============================="
echo "  PR2 chaos harness results"
echo "  PASS: $PASS_COUNT  FAIL: $FAIL_COUNT"
if (( FAIL_COUNT > 0 )); then
    echo "  failed: ${FAILED_SCENARIOS[*]}"
    exit 1
fi
exit 0
