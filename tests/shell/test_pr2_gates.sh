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
    setup) mkdir -p "\$2" ;;
    test)
        mkdir -p "\$dir/meson-logs"
        printf 'ok\n%s\n' "\${YUZU_MOCK_TESTLOG_LINE:-}" > "\$dir/meson-logs/testlog.txt"
        [[ -n "\${YUZU_MOCK_TEST_SLEEP:-}" ]] && sleep "\$YUZU_MOCK_TEST_SLEEP"
        exit "\${YUZU_MOCK_TEST_RC:-0}" ;;
esac
exit 0
EOF
    cat > "$FK_BIN/gcovr" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "$FK_GLOG"
JSON=""
while [[ \$# -gt 0 ]]; do
    case "\$1" in --json-summary) JSON="\$2"; shift 2 ;; *) shift ;; esac
done
if [[ -n "\$JSON" ]]; then
    if [[ -n "\${YUZU_MOCK_NO_LINE:-}" ]]; then printf '{"branch_percent":65.5}' > "\$JSON"
    else printf '{"branch_percent":65.5,"line_percent":72.0}' > "\$JSON"; fi
fi
exit 0
EOF
    chmod +x "$FK_BIN/meson" "$FK_BIN/gcovr"
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

    # A: a normal run takes the lock and releases it, even when it fails.
    ch_run ch19a "$build" -- YUZU_COVERAGE_TIMEOUT_MULT=
    if [[ -e "$lock" ]]; then bad "CH-19" "lock left behind after a normal run"
    else
        ch_run ch19b "$build" -- YUZU_MOCK_TEST_RC=3
        if [[ -e "$lock" ]]; then bad "CH-19" "lock left behind after a failing run"
        else ok "CH-19: lock is released after a normal run and after a failing run"; fi
    fi

    # B: a lock held by a live process refuses the run before any meson call.
    : > "$FK_MLOG"
    mkdir -p "$lock"; sleep 30 & local holder=$!; echo "$holder" > "$lock/pid"
    ch_run ch19c "$build" --
    kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null
    if [[ -s "$FK_MLOG" ]]; then bad "CH-19" "run proceeded despite a live lock: $(cat "$FK_MLOG")"
    elif [[ "$(db_gate_status ch19c Coverage)" != "WARN" || "$(db_gate_notes ch19c Coverage)" != *"another coverage-gate run (pid $holder)"* ]]; then
        bad "CH-19" "live-lock refusal not recorded: status=$(db_gate_status ch19c Coverage) notes=$(db_gate_notes ch19c Coverage)"
    elif [[ ! -d "$lock" ]]; then bad "CH-19" "refused run removed the OTHER run's lock"
    else ok "CH-19: a live lock refuses the run (WARN row names the holder) and is left intact"; fi
    rm -rf "$lock"

    # C: a lock whose holder is gone is cleared and the run proceeds.
    : > "$FK_MLOG"
    sleep 0 & local dead=$!; wait "$dead" 2>/dev/null
    mkdir -p "$lock"; echo "$dead" > "$lock/pid"
    ch_run ch19d "$build" --
    if ! grep -q "^test " "$FK_MLOG"; then bad "CH-19" "stale lock was not cleared: $FK_OUT"
    elif [[ -e "$lock" ]]; then bad "CH-19" "lock left behind after clearing a stale one"
    else ok "CH-19: a stale lock (dead holder) is cleared and the run proceeds"; fi

    # D: real overlap - a second run started while the first is inside meson test.
    : > "$FK_MLOG"; rm -rf "$build"
    start_run ch19e
    ( env YUZU_MOCK_TEST_SLEEP=4 bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id ch19e \
        --build-dir "$build" --baseline "$FK_BASE" --report-only >/dev/null 2>&1 ) &
    local first=$! i
    for i in $(seq 1 100); do [[ -d "$lock" ]] && grep -q "^test " "$FK_MLOG" && break; sleep 0.1; done
    ch_run ch19f "$build" --report-only --
    local second_calls; second_calls=$(grep -c "^setup \|^compile " "$FK_MLOG")
    wait "$first" 2>/dev/null
    if [[ "$(db_gate_notes ch19f Coverage)" != *"another coverage-gate run"* ]]; then
        bad "CH-19" "overlapping second run was not refused: rc=$FK_RC notes=$(db_gate_notes ch19f Coverage)"
    elif [[ "$second_calls" != "2" ]]; then
        bad "CH-19" "second run touched the build dir (setup+compile calls=$second_calls, expected only the first run's 2)"
    elif [[ "$(db_gate_status ch19e Coverage)" != "PASS" ]]; then
        bad "CH-19" "first run did not finish normally: $(db_gate_status ch19e Coverage)"
    else ok "CH-19: an overlapping second run is refused and never touches the build dir; the first finishes"; fi

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

    # B: not enough free space after the run -> inconclusive.
    ch_run ch21b "$build" -- YUZU_COVERAGE_MIN_FREE_KB=999999999999
    if [[ "$(db_gate_status ch21b Coverage)" != "WARN" || "$(db_gate_notes ch21b Coverage)" != *"KB free on the build filesystem"* \
          || "$(db_metric ch21b branch_coverage_overall)" != "MISSING" ]]; then
        bad "CH-21" "low free space not treated as inconclusive: status=$(db_gate_status ch21b Coverage) notes=$(db_gate_notes ch21b Coverage)"
    else ok "CH-21: too little free space after the run makes it inconclusive"; fi

    # C: bad free-space threshold is refused before any meson call.
    : > "$FK_MLOG"
    ch_run ch21c "$build" -- YUZU_COVERAGE_MIN_FREE_KB=abc
    if [[ -s "$FK_MLOG" || "$(db_gate_notes ch21c Coverage)" != *"invalid YUZU_COVERAGE_MIN_FREE_KB"* ]]; then
        bad "CH-21" "bad YUZU_COVERAGE_MIN_FREE_KB not refused up front: notes=$(db_gate_notes ch21c Coverage) meson=$(cat "$FK_MLOG")"
    else ok "CH-21: an invalid free-space threshold is refused before any build"; fi

    # D: a failed metric write, and separately a failed gate-row write, each turn a
    # would-be success into exit 2 with an ERROR (the DB row IS the gate's result).
    local what
    for what in metric gate; do
        start_run "ch21d$what"
        FK_OUT=$(YUZU_MOCK_DB_FAIL=$what bash "$FK_ROOT/scripts/test/coverage-gate.sh" --run-id "ch21d$what" \
            --build-dir "$build" --baseline "$FK_BASE" 2>&1) && FK_RC=0 || FK_RC=$?
        if [[ "$FK_RC" != "2" || "$FK_OUT" != *"ERROR could not record"* ]]; then
            bad "CH-21" "a failed $what DB write did not fail the gate: rc=$FK_RC out=$(printf '%s' "$FK_OUT" | tail -3)"
        fi
    done
    [[ "$FK_RC" == "2" ]] && ok "CH-21: a failed gate-row or metric DB write is reported and the gate exits 2 instead of 0"

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
