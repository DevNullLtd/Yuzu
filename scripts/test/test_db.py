#!/usr/bin/env python3
"""
test_db.py — Yuzu /test results database (SQLite).

Single source of truth for the test-runs DB schema and operations. Bash
wrappers in this directory delegate to this module via subcommand args.

Schema v1: local /test runs. Schema v2: coarse CI run rows. Schema v3:
per-runner/per-attempt CI jobs, Meson suite timings and recovered flake events,
plus a schema_meta table for forward-compatible migrations.

Default DB location: ~/.local/share/yuzu/test-runs.db
Override with: YUZU_TEST_DB=path
Log files live alongside under: ~/.local/share/yuzu/test-runs/<run_id>/

Schema invariants (preserve against future regression):
  - schema_meta MUST be created in the same DDL block as v1 tables, before
    any version check. The `schema_version()` query at line ~135 handles
    "table missing" by returning None, which triggers a fresh-DB path that
    runs SCHEMA_V1 inline. Future v2+ migrations must run AFTER the version
    check confirms the DB is at v1.
  - All bash callers must go through the wrappers (test-db-init.sh,
    test-db-write.sh, test-db-query.sh) rather than executing this module
    directly. The wrappers are the stable CLI surface.
  - `gate_name` must be unique within a run; (run_id, gate_name) is the
    test_gates primary key. Duplicate writes silently overwrite via
    INSERT OR REPLACE — caller must not assume otherwise.

The stable CLI remains the bash wrappers; the cross-platform CI recorder calls
this module's CLI directly because Windows cannot rely on a bash wrapper.

This module has outgrown its original ~1000-line split threshold. Keep future
unrelated features out; do a dedicated schema/ops/query split as separate
maintenance work rather than hiding that refactor inside CI telemetry changes.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, Optional

SCHEMA_VERSION = 3

SCHEMA_V1 = """
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    store       TEXT PRIMARY KEY,
    version     INTEGER NOT NULL,
    upgraded_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS test_runs (
    run_id                 TEXT PRIMARY KEY,
    started_at             INTEGER NOT NULL,
    finished_at            INTEGER,
    commit_sha             TEXT NOT NULL,
    branch                 TEXT NOT NULL,
    mode                   TEXT NOT NULL,
    overall_status         TEXT NOT NULL,
    total_duration_seconds INTEGER,
    fail_count             INTEGER NOT NULL DEFAULT 0,
    warn_count             INTEGER NOT NULL DEFAULT 0,
    pass_count             INTEGER NOT NULL DEFAULT 0,
    skip_count             INTEGER NOT NULL DEFAULT 0,
    hostname               TEXT,
    hardware_fingerprint   TEXT,
    notes                  TEXT
);

CREATE TABLE IF NOT EXISTS test_gates (
    run_id           TEXT NOT NULL REFERENCES test_runs(run_id) ON DELETE CASCADE,
    phase            INTEGER NOT NULL,
    gate_name        TEXT NOT NULL,
    status           TEXT NOT NULL,
    duration_seconds INTEGER NOT NULL,
    log_path         TEXT,
    notes            TEXT,
    PRIMARY KEY (run_id, gate_name)
);

CREATE TABLE IF NOT EXISTS test_timings (
    run_id      TEXT NOT NULL REFERENCES test_runs(run_id) ON DELETE CASCADE,
    gate_name   TEXT NOT NULL,
    step_name   TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    PRIMARY KEY (run_id, gate_name, step_name)
);

CREATE TABLE IF NOT EXISTS test_metrics (
    run_id       TEXT NOT NULL REFERENCES test_runs(run_id) ON DELETE CASCADE,
    metric_name  TEXT NOT NULL,
    metric_value REAL NOT NULL,
    metric_unit  TEXT,
    PRIMARY KEY (run_id, metric_name)
);

CREATE INDEX IF NOT EXISTS idx_test_runs_started_at ON test_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_test_runs_branch     ON test_runs(branch);
CREATE INDEX IF NOT EXISTS idx_test_runs_commit     ON test_runs(commit_sha);
CREATE INDEX IF NOT EXISTS idx_test_gates_status    ON test_gates(status);
CREATE INDEX IF NOT EXISTS idx_test_timings_gate    ON test_timings(gate_name, step_name);
CREATE INDEX IF NOT EXISTS idx_test_metrics_name    ON test_metrics(metric_name);
"""

# Schema v2 (PR-9 of CI overhaul plan): ci_runs table tracks CI invocations
# from .github/workflows/ci.yml. Joined to test_runs via commit_sha when both
# exist for a given commit. Populated by `ci-ingest` (pulls from `gh run
# list --json`) on demand or as a periodic operator task; query via
# `ci-stats` for cache-hit / wall-time / failure-rate aggregates.
#
# Additive migration: v1 tables are untouched.
SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS ci_runs (
    workflow_id      TEXT NOT NULL,        -- e.g. "ci.yml" / "release.yml"
    run_id           INTEGER NOT NULL,     -- GitHub Actions run database ID
    job_name         TEXT NOT NULL,        -- e.g. "Linux gcc-13 debug"
    triplet          TEXT,                 -- vcpkg triplet, NULL for non-vcpkg jobs
    runner           TEXT,                 -- e.g. "yuzu-wsl2-linux"
    commit_sha       TEXT NOT NULL,
    branch           TEXT NOT NULL,
    started_at       INTEGER NOT NULL,
    finished_at      INTEGER,
    duration_seconds INTEGER,
    conclusion       TEXT NOT NULL,        -- success/failure/cancelled/skipped/timed_out
    vcpkg_cache_hit  INTEGER,              -- 1 hit, 0 miss/from-source, NULL unknown
    ccache_hit_ratio REAL,                 -- 0.0-1.0; NULL if not measured
    notes            TEXT,
    PRIMARY KEY (workflow_id, run_id, job_name)
);

CREATE INDEX IF NOT EXISTS idx_ci_runs_started_at ON ci_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_ci_runs_branch     ON ci_runs(branch);
CREATE INDEX IF NOT EXISTS idx_ci_runs_commit     ON ci_runs(commit_sha);
CREATE INDEX IF NOT EXISTS idx_ci_runs_triplet    ON ci_runs(triplet);
CREATE INDEX IF NOT EXISTS idx_ci_runs_conclusion ON ci_runs(conclusion);
"""

# Schema v3 makes the runner-local database useful as CI telemetry rather than
# merely a workflow-level import cache:
#
#   * run_attempt is part of the key, so a rerun is evidence rather than an
#     overwrite;
#   * platform + event_name make Windows/Linux and PR/push comparisons direct;
#   * ci_test_suites persists Meson's per-entry wall time, result and timeout;
#   * ci_flake_events persists known flakes that recovered on isolated retry.
#
# Existing v2 rows are retained as attempt 1 with unknown platform/event.
SCHEMA_V3_CI_RUNS = """
CREATE TABLE ci_runs_v3 (
    workflow_id      TEXT NOT NULL,
    run_id           INTEGER NOT NULL,
    run_attempt      INTEGER NOT NULL DEFAULT 1,
    job_name         TEXT NOT NULL,
    triplet          TEXT,
    platform         TEXT,
    runner           TEXT,
    event_name       TEXT,
    commit_sha       TEXT NOT NULL,
    branch           TEXT NOT NULL,
    started_at       INTEGER NOT NULL,
    finished_at      INTEGER,
    duration_seconds INTEGER,
    conclusion       TEXT NOT NULL,
    vcpkg_cache_hit  INTEGER,
    ccache_hit_ratio REAL,
    notes            TEXT,
    PRIMARY KEY (workflow_id, run_id, run_attempt, job_name)
);

INSERT INTO ci_runs_v3
    (workflow_id, run_id, run_attempt, job_name, triplet, platform, runner,
     event_name, commit_sha, branch, started_at, finished_at, duration_seconds,
     conclusion, vcpkg_cache_hit, ccache_hit_ratio, notes)
SELECT workflow_id, run_id, 1, job_name, triplet, NULL, runner, NULL,
       commit_sha, branch, started_at, finished_at, duration_seconds,
       conclusion, vcpkg_cache_hit, ccache_hit_ratio, notes
FROM ci_runs;

DROP TABLE ci_runs;
ALTER TABLE ci_runs_v3 RENAME TO ci_runs;
"""

SCHEMA_V3_TABLES = """
CREATE INDEX IF NOT EXISTS idx_ci_runs_started_at ON ci_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_ci_runs_branch     ON ci_runs(branch);
CREATE INDEX IF NOT EXISTS idx_ci_runs_commit     ON ci_runs(commit_sha);
CREATE INDEX IF NOT EXISTS idx_ci_runs_triplet    ON ci_runs(triplet);
CREATE INDEX IF NOT EXISTS idx_ci_runs_platform   ON ci_runs(platform);
CREATE INDEX IF NOT EXISTS idx_ci_runs_runner     ON ci_runs(runner);
CREATE INDEX IF NOT EXISTS idx_ci_runs_conclusion ON ci_runs(conclusion);

CREATE TABLE IF NOT EXISTS ci_test_suites (
    workflow_id      TEXT NOT NULL,
    run_id           INTEGER NOT NULL,
    run_attempt      INTEGER NOT NULL,
    job_name         TEXT NOT NULL,
    suite_name       TEXT NOT NULL,
    status           TEXT NOT NULL,
    duration_seconds REAL NOT NULL,
    timeout_seconds  REAL,
    recorded_at      INTEGER NOT NULL,
    PRIMARY KEY (workflow_id, run_id, run_attempt, job_name, suite_name),
    FOREIGN KEY (workflow_id, run_id, run_attempt, job_name)
      REFERENCES ci_runs(workflow_id, run_id, run_attempt, job_name)
      ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ci_test_suites_name
  ON ci_test_suites(suite_name, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_ci_test_suites_status
  ON ci_test_suites(status, recorded_at DESC);

CREATE TABLE IF NOT EXISTS ci_flake_events (
    workflow_id      TEXT NOT NULL,
    run_id           INTEGER NOT NULL,
    run_attempt      INTEGER NOT NULL,
    job_name         TEXT NOT NULL,
    case_name        TEXT NOT NULL,
    retry_attempts   INTEGER NOT NULL,
    cross_platform   INTEGER NOT NULL DEFAULT 0,
    recorded_at      INTEGER NOT NULL,
    PRIMARY KEY (workflow_id, run_id, run_attempt, job_name, case_name),
    FOREIGN KEY (workflow_id, run_id, run_attempt, job_name)
      REFERENCES ci_runs(workflow_id, run_id, run_attempt, job_name)
      ON DELETE CASCADE
);
"""

VALID_STATUS = {"PASS", "FAIL", "WARN", "SKIP", "RUNNING", "ABORTED"}
VALID_CI_CONCLUSIONS = {
    "in_progress", "success", "failure", "cancelled", "skipped", "timed_out",
    "neutral", "action_required",
}
VALID_CI_PLATFORMS = {"linux", "windows", "macos"}
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


# --- DB plumbing ----------------------------------------------------------


def db_path() -> Path:
    p = os.environ.get("YUZU_TEST_DB")
    if p:
        return Path(p).expanduser()
    return Path.home() / ".local" / "share" / "yuzu" / "test-runs.db"


def log_root() -> Path:
    return db_path().parent / "test-runs"


def validate_run_id(run_id: str) -> bool:
    return bool(RUN_ID_RE.fullmatch(run_id)) and run_id not in {".", ".."}


def display_run_id(run_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "?", run_id)


def safe_run_log_dir(run_id: str) -> Optional[Path]:
    """Return the per-run log dir for run_id, or None if it would escape log_root.

    The returned Path is always fully resolved (``.resolve()``), which is what the
    containment check below compares against. Callers must not mix the return
    value with an unresolved ``log_root() / run_id`` string: on macOS the two
    differ (``/tmp`` vs ``/private/tmp``), though they reference the same dir via
    the platform symlink.
    """
    if not validate_run_id(run_id):
        return None
    root = log_root().resolve()
    candidate = (root / run_id).resolve()
    if candidate == root or root not in candidate.parents:
        return None
    return candidate


@contextlib.contextmanager
def connect(create_dirs: bool = False):
    p = db_path()
    if create_dirs:
        p.parent.mkdir(parents=True, exist_ok=True)
        log_root().mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), timeout=10.0, isolation_level=None)
    try:
        # Per-connection resilience PRAGMAs (#1146): SCHEMA_V1 set these only
        # on the fresh-init path, so a DB initialised before WAL landed (or a
        # connection racing a concurrent writer — nightly + PR run sharing
        # YUZU_TEST_DB on one runner box) ran without them. busy_timeout FIRST
        # so the journal_mode switch itself retries under contention, and at
        # 10000 to match the driver-level `timeout=10.0` above — a smaller
        # value here would silently SHORTEN the effective timeout.
        # WAL means recent commits live in the -wal sidecar until checkpoint:
        # anything archiving/copying this DB must take .db + -wal + -shm
        # together (or run PRAGMA wal_checkpoint(TRUNCATE) first), else the
        # copy silently reads OLDER data with no error (gov up-4).
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
    finally:
        conn.close()


def schema_version(conn: sqlite3.Connection) -> Optional[int]:
    try:
        row = conn.execute(
            "SELECT version FROM schema_meta WHERE store='test_runs_db'"
        ).fetchone()
        return row[0] if row else None
    except sqlite3.OperationalError as e:
        # Only the missing-table probe means "fresh DB" (#1146); a
        # busy/locked timeout here is a real concurrency failure and must
        # surface through the main() handler, not read as version=None
        # (which would send callers down the schema-init path).
        if "no such table" in str(e).lower():
            return None
        raise


def stamp_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO schema_meta (store, version, upgraded_at) "
        "VALUES ('test_runs_db', ?, ?)",
        (version, int(time.time())),
    )


def _execute_statements(conn: sqlite3.Connection, script: str) -> None:
    """Execute a SQL script statement-by-statement in the current transaction.

    sqlite3.Connection.executescript() commits a pending transaction before it
    runs. Migrations that acquire their lock before checking the schema version
    therefore use this helper so the re-check and DDL remain under one lock.
    """
    pending = ""
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            conn.execute(pending)
            pending = ""
    if pending.strip():
        raise ValueError("incomplete SQL statement in schema migration")


def _migrate_v2_to_v3(conn: sqlite3.Connection) -> int:
    """Atomically replace v2's CI table after a lock-protected re-check."""
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = schema_version(conn)
        if current != 2:
            if current is None:
                raise RuntimeError("schema version disappeared during v2 migration")
            conn.commit()
            return current
        conn.execute("DROP TABLE IF EXISTS ci_runs_v3")
        _execute_statements(conn, SCHEMA_V3_CI_RUNS)
        _execute_statements(conn, SCHEMA_V3_TABLES)
        stamp_version(conn, 3)
        conn.commit()
        return 3
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


def _upgrade_schema(conn: sqlite3.Connection, existing: Optional[int]) -> int:
    """Bring a fresh or older database to SCHEMA_VERSION."""
    version = existing
    if version is None:
        conn.executescript(SCHEMA_V1)
        version = 1
        stamp_version(conn, version)
    if version == 1:
        conn.executescript(SCHEMA_V2)
        version = 2
        stamp_version(conn, version)
    if version == 2:
        version = _migrate_v2_to_v3(conn)
    if version == 3:
        # Idempotently restore indexes/tables if an operator repaired a DB by
        # hand but left the schema-version stamp intact.
        conn.executescript(SCHEMA_V3_TABLES)
    return version


# --- subcommands ----------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    p = db_path()
    if args.check:
        if not p.exists():
            print(f"test_db: {p} does not exist", file=sys.stderr)
            return 1
        with connect() as conn:
            v = schema_version(conn)
        if v != SCHEMA_VERSION:
            print(
                f"test_db: schema version mismatch (have={v} want={SCHEMA_VERSION})",
                file=sys.stderr,
            )
            return 1
        print(f"test_db: ok ({p} at v{v})")
        return 0

    with connect(create_dirs=True) as conn:
        existing = schema_version(conn)
        if existing is None:
            upgraded = _upgrade_schema(conn, existing)
            print(f"test_db: initialized {p} at schema v{SCHEMA_VERSION}")
            if upgraded != SCHEMA_VERSION:
                return 1
        elif existing < SCHEMA_VERSION:
            upgraded = _upgrade_schema(conn, existing)
            print(f"test_db: migrated {p} from v{existing} to v{upgraded}")
        elif existing > SCHEMA_VERSION:
            print(
                f"test_db: {p} at v{existing}, this client knows only v{SCHEMA_VERSION}",
                file=sys.stderr,
            )
            return 1
        else:
            _upgrade_schema(conn, existing)
    return 0


def _hardware_fingerprint() -> str:
    parts = []
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    parts.append(line.split(":", 1)[1].strip())
                    break
    except OSError:
        pass
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    parts.append(f"{kb // 1024 // 1024}GB")
                    break
    except OSError:
        pass
    return " | ".join(parts) if parts else "unknown"


def cmd_run_start(args: argparse.Namespace) -> int:
    # Resolve the per-run log dir up front — before the INSERT — so path
    # containment is enforced at the construction site (not only by the main()
    # arg-validation gate), and so a refusal can never leave an orphan test_runs
    # row with no dir (gov consistency SHOULD-1 / chaos CH-25). run-start is in
    # main()'s validated set, so for any id reaching here this returns a real
    # path; the None branch is belt-and-suspenders against a future caller.
    run_dir = safe_run_log_dir(args.run_id)
    if run_dir is None:
        print(
            f"test_db: refusing unsafe run_id={display_run_id(args.run_id)}",
            file=sys.stderr,
        )
        return 2
    with connect(create_dirs=True) as conn:
        _ensure_schema_initialized(conn)
        conn.execute(
            """
            INSERT INTO test_runs
                (run_id, started_at, commit_sha, branch, mode, overall_status,
                 hostname, hardware_fingerprint, notes)
            VALUES (?, ?, ?, ?, ?, 'RUNNING', ?, ?, ?)
            """,
            (
                args.run_id,
                int(time.time()),
                args.commit,
                args.branch,
                args.mode,
                socket.gethostname(),
                _hardware_fingerprint(),
                args.notes or "",
            ),
        )
        # Create the per-run log directory (containment-checked above).
        run_dir.mkdir(parents=True, exist_ok=True)
    print(f"test_db: started run {args.run_id}")
    return 0


def cmd_run_finish(args: argparse.Namespace) -> int:
    with connect() as conn:
        # Aggregate gate counts.
        counts = {row[0]: row[1] for row in conn.execute(
            "SELECT status, COUNT(*) FROM test_gates WHERE run_id=? GROUP BY status",
            (args.run_id,),
        )}
        fail = counts.get("FAIL", 0)
        warn = counts.get("WARN", 0)
        pass_ = counts.get("PASS", 0)
        skip = counts.get("SKIP", 0)

        # Overall status: any FAIL → FAIL; else any WARN → WARN; else PASS.
        # If args.status is provided, use it (lets the caller override).
        if args.status:
            overall = args.status
        elif fail > 0:
            overall = "FAIL"
        elif warn > 0:
            overall = "WARN"
        elif pass_ + skip > 0:
            overall = "PASS"
        else:
            overall = "ABORTED"

        # Compute total duration from started_at.
        row = conn.execute(
            "SELECT started_at FROM test_runs WHERE run_id=?",
            (args.run_id,),
        ).fetchone()
        if not row:
            print(f"test_db: run {args.run_id} not found", file=sys.stderr)
            return 1
        started = row[0]
        finished = int(time.time())
        total = finished - started

        conn.execute(
            """
            UPDATE test_runs
               SET finished_at=?,
                   overall_status=?,
                   total_duration_seconds=?,
                   fail_count=?,
                   warn_count=?,
                   pass_count=?,
                   skip_count=?
             WHERE run_id=?
            """,
            (finished, overall, total, fail, warn, pass_, skip, args.run_id),
        )
    print(
        f"test_db: finished run {args.run_id} status={overall} "
        f"duration={total}s pass={pass_} fail={fail} warn={warn} skip={skip}"
    )
    return 0


def _ensure_schema_initialized(conn: sqlite3.Connection) -> None:
    # Idempotent schema bootstrap. SCHEMA_V1 + V2 use CREATE TABLE IF NOT
    # EXISTS so concurrent callers can't conflict on table creation.
    # stamp_version uses INSERT OR REPLACE so it's also race-safe.
    v = schema_version(conn)
    upgraded = _upgrade_schema(conn, v)
    if upgraded != SCHEMA_VERSION:
        raise sqlite3.OperationalError(
            f"unsupported test-runs DB schema v{upgraded}; want v{SCHEMA_VERSION}"
        )


def _ensure_run_exists(conn: sqlite3.Connection, run_id: str) -> None:
    # Auto-vivify a stub test_runs row when an operator-invoked write
    # (gate/timing/metric) targets a run_id that /test never created via
    # run-start. Without this, child-table FKs fail and the write is
    # silently dropped — taking trend data with it. See #528.
    #
    # Behavior summary:
    #   - existing row, mode != 'manual' → no-op (real /test run, leave alone).
    #   - existing row, mode == 'manual' → refresh started_at / commit_sha /
    #     branch so a re-capture of baselines under the same --run-id
    #     attributes the new metrics to the current commit (HP-1).
    #   - missing row → INSERT OR IGNORE a stub with mode='manual',
    #     overall_status='MANUAL'. The OR IGNORE absorbs the race where
    #     two concurrent invocations both passed the SELECT and both
    #     attempt the INSERT (UP-3 / QE-3). Emit a stderr line on actual
    #     creation so a /test pipeline whose run-start silently failed
    #     produces a visible signal (UP-18).
    #
    # MANUAL is a test_runs lifecycle sentinel for the overall_status
    # column; it is NOT a gate-status value (cmd_gate validates against
    # VALID_STATUS, which deliberately excludes MANUAL — gate rows
    # always carry PASS/FAIL/WARN/SKIP).
    _ensure_schema_initialized(conn)
    row = conn.execute(
        "SELECT mode FROM test_runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if row is not None:
        if row[0] == "manual":
            commit_sha = _git_oneshot(["rev-parse", "HEAD"]) or "unknown"
            branch = (
                _git_oneshot(["rev-parse", "--abbrev-ref", "HEAD"]) or "unknown"
            )
            conn.execute(
                """
                UPDATE test_runs
                   SET started_at=?, commit_sha=?, branch=?
                 WHERE run_id=? AND mode='manual'
                """,
                (int(time.time()), commit_sha, branch, run_id),
            )
        return
    commit_sha = _git_oneshot(["rev-parse", "HEAD"]) or "unknown"
    branch = _git_oneshot(["rev-parse", "--abbrev-ref", "HEAD"]) or "unknown"
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO test_runs
            (run_id, started_at, commit_sha, branch, mode, overall_status,
             hostname, hardware_fingerprint, notes)
        VALUES (?, ?, ?, ?, 'manual', 'MANUAL', ?, ?, ?)
        """,
        (
            run_id,
            int(time.time()),
            commit_sha,
            branch,
            socket.gethostname(),
            _hardware_fingerprint(),
            "auto-vivified by gate/timing/metric write (no prior run-start)",
        ),
    )
    if cur.rowcount > 0:
        # Stub row freshly created. Visible signal so a /test pipeline
        # whose run-start failed silently doesn't ship a green-looking
        # run with mode='manual' rows. Operator-capture paths
        # (--run-id manual) will see this on first call per DB and
        # never again.
        run_id_safe = display_run_id(run_id)
        print(
            f"test_db: vivified stub test_runs row for run_id={run_id_safe} "
            f"(mode='manual') — if this is a /test pipeline run, "
            f"check that run-start succeeded",
            file=sys.stderr,
        )


def _git_oneshot(args: list[str]) -> str | None:
    # Pin cwd to the test_db.py file's repo root so a caller cd'd
    # outside the repo (CI helpers, sourced env scripts) doesn't get
    # commit_sha='unknown' silently. UP-5.
    try:
        out = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=str(Path(__file__).resolve().parent),
        )
        if out.returncode == 0:
            return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def cmd_gate(args: argparse.Namespace) -> int:
    if args.status not in VALID_STATUS:
        print(f"test_db: invalid status '{args.status}'", file=sys.stderr)
        return 2
    with connect() as conn:
        _ensure_run_exists(conn, args.run_id)
        conn.execute(
            """
            INSERT OR REPLACE INTO test_gates
                (run_id, phase, gate_name, status, duration_seconds, log_path, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                args.run_id,
                args.phase,
                args.gate,
                args.status,
                args.duration,
                args.log or "",
                args.notes or "",
            ),
        )
    return 0


def cmd_timing(args: argparse.Namespace) -> int:
    with connect() as conn:
        _ensure_run_exists(conn, args.run_id)
        conn.execute(
            """
            INSERT OR REPLACE INTO test_timings
                (run_id, gate_name, step_name, duration_ms)
            VALUES (?, ?, ?, ?)
            """,
            (args.run_id, args.gate, args.step, args.ms),
        )
    return 0


def cmd_metric(args: argparse.Namespace) -> int:
    with connect() as conn:
        _ensure_run_exists(conn, args.run_id)
        conn.execute(
            """
            INSERT OR REPLACE INTO test_metrics
                (run_id, metric_name, metric_value, metric_unit)
            VALUES (?, ?, ?, ?)
            """,
            (args.run_id, args.name, args.value, args.unit or ""),
        )
    return 0


# --- queries --------------------------------------------------------------


def cmd_ci_record(args: argparse.Namespace) -> int:
    """Insert (or replace) one ci_runs row.

    Idempotent on (workflow_id, run_id, run_attempt, job_name). A start write
    records in_progress; the always() finish step updates that same row without
    deleting child suite/flake telemetry. A GitHub rerun has a new run_attempt
    and therefore remains visible as separate evidence.
    """
    if args.conclusion not in VALID_CI_CONCLUSIONS:
        print(
            f"test_db: invalid conclusion '{args.conclusion}', "
            f"want one of {sorted(VALID_CI_CONCLUSIONS)}",
            file=sys.stderr,
        )
        return 2
    if args.run_attempt < 1:
        print("test_db: --run-attempt must be >= 1", file=sys.stderr)
        return 2
    if args.platform is not None and args.platform not in VALID_CI_PLATFORMS:
        print(
            f"test_db: invalid platform '{args.platform}', "
            f"want one of {sorted(VALID_CI_PLATFORMS)}",
            file=sys.stderr,
        )
        return 2
    with connect(create_dirs=True) as conn:
        _ensure_schema_initialized(conn)
        finished = args.finished_at
        duration = None
        if finished is not None:
            duration = max(0, finished - args.started_at)
        row = conn.execute(
            """
            INSERT INTO ci_runs
                (workflow_id, run_id, run_attempt, job_name, triplet, platform,
                 runner, event_name, commit_sha, branch, started_at, finished_at,
                 duration_seconds, conclusion, vcpkg_cache_hit,
                 ccache_hit_ratio, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workflow_id, run_id, run_attempt, job_name) DO UPDATE SET
                triplet=excluded.triplet,
                platform=excluded.platform,
                runner=excluded.runner,
                event_name=excluded.event_name,
                commit_sha=excluded.commit_sha,
                branch=excluded.branch,
                started_at=ci_runs.started_at,
                finished_at=excluded.finished_at,
                duration_seconds=CASE
                    WHEN excluded.finished_at IS NULL THEN excluded.duration_seconds
                    ELSE MAX(0, excluded.finished_at - ci_runs.started_at)
                END,
                conclusion=excluded.conclusion,
                vcpkg_cache_hit=COALESCE(excluded.vcpkg_cache_hit, ci_runs.vcpkg_cache_hit),
                ccache_hit_ratio=COALESCE(excluded.ccache_hit_ratio, ci_runs.ccache_hit_ratio),
                notes=excluded.notes
            RETURNING duration_seconds
            """,
            (
                args.workflow, args.run_id, args.run_attempt, args.job_name,
                args.triplet, args.platform, args.runner, args.event_name,
                args.commit, args.branch, args.started_at, finished, duration,
                args.conclusion, args.vcpkg_cache_hit, args.ccache_hit_ratio,
                args.notes or "",
            ),
        ).fetchone()
        duration = row[0] if row is not None else duration
    duration_text = f"{duration}s" if duration is not None else "in progress"
    print(
        f"test_db: ci_runs <- {args.workflow}#{args.run_id}."
        f"{args.run_attempt}/{args.job_name} "
        f"({args.conclusion}, {duration_text})"
    )
    return 0


def _meson_test_metadata(builddir: Path) -> dict[str, dict]:
    intro = builddir / "meson-info" / "intro-tests.json"
    if not intro.exists():
        return {}
    data = json.loads(intro.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{intro}: expected a JSON array")
    return {
        row["name"]: row
        for row in data
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }


def _match_meson_test_name(junit_name: str, metadata: dict[str, dict]) -> str:
    matches = [name for name in metadata if name and name in junit_name]
    return max(matches, key=len) if matches else junit_name


def _junit_status(testcase: ET.Element) -> str:
    failure = testcase.find("failure")
    error = testcase.find("error")
    if failure is not None or error is not None:
        node = failure if failure is not None else error
        evidence = " ".join(
            [node.get("message", ""), node.get("type", ""), node.text or ""]
        ).upper()
        return "timeout" if "TIMEOUT" in evidence else "failure"
    if testcase.find("skipped") is not None:
        return "skipped"
    return "success"


def cmd_ci_import_junit(args: argparse.Namespace) -> int:
    """Persist Meson's suite-level JUnit timings and recovered flake events."""
    if args.run_attempt < 1:
        print("test_db: --run-attempt must be >= 1", file=sys.stderr)
        return 2
    builddir = Path(args.builddir)
    junit = Path(args.junit) if args.junit else builddir / "meson-logs" / "testlog.junit.xml"

    # Build directories persist between self-hosted jobs. Resolve the parent
    # first and refuse an older job's Meson log rather than attaching stale
    # results to a setup/compile failure that never reached the Test step.
    key = (args.workflow, args.run_id, args.run_attempt, args.job_name)
    with connect(create_dirs=True) as conn:
        _ensure_schema_initialized(conn)
        parent = conn.execute(
            """
            SELECT started_at FROM ci_runs
             WHERE workflow_id=? AND run_id=? AND run_attempt=? AND job_name=?
            """,
            key,
        ).fetchone()
    if parent is None:
        print(
            "test_db: refusing suite import without its parent ci_runs row",
            file=sys.stderr,
        )
        return 1
    job_started_at = int(parent[0])
    if not junit.exists():
        print(f"test_db: no Meson junit at {junit} (job ended before tests)")
        return 0
    if junit.stat().st_mtime < job_started_at:
        print(f"test_db: ignoring stale Meson junit at {junit} (predates this job)")
        return 0

    try:
        metadata = _meson_test_metadata(builddir)
    except (OSError, ValueError) as exc:
        print(
            f"test_db: ignoring malformed Meson test metadata at {builddir}: {exc}",
            file=sys.stderr,
        )
        metadata = {}
    try:
        root = ET.parse(junit).getroot()
    except (OSError, ET.ParseError) as exc:
        print(f"test_db: cannot import malformed Meson junit at {junit}: {exc}",
              file=sys.stderr)
        return 1
    rows: list[tuple[str, str, float, Optional[float]]] = []
    for testcase in root.iter("testcase"):
        junit_name = testcase.get("name", "")
        if not junit_name:
            continue
        suite_name = _match_meson_test_name(junit_name, metadata)
        try:
            duration = float(testcase.get("time", "0"))
        except ValueError:
            duration = 0.0
        timeout = metadata.get(suite_name, {}).get("timeout")
        try:
            timeout_value = float(timeout) if timeout is not None else None
        except (TypeError, ValueError):
            timeout_value = None
        rows.append((suite_name, _junit_status(testcase), duration, timeout_value))

    now = int(time.time())
    flake_report = (
        Path(args.flake_report)
        if args.flake_report
        else builddir / "meson-logs" / "flake-retry.json"
    )
    recovered: list[tuple[str, int, bool]] = []
    try:
        report_is_current = (
            flake_report.exists()
            and flake_report.stat().st_mtime >= job_started_at
        )
        if report_is_current:
            report = json.loads(flake_report.read_text(encoding="utf-8"))
            raw = report.get("recovered", []) if isinstance(report, dict) else []
            if not isinstance(raw, list):
                print(
                    "test_db: skipped malformed recovered flake entries: "
                    "recovered must be an array",
                    file=sys.stderr,
                )
                raw = []
            for index, entry in enumerate(raw):
                reason = None
                if not isinstance(entry, dict):
                    reason = "entry must be an object"
                else:
                    case_name = entry.get("case")
                    attempts = entry.get("attempts")
                    cross_platform = entry.get("cross_platform")
                    if not isinstance(case_name, str) or not case_name.strip():
                        reason = "case must be a non-empty string"
                    elif (
                        not isinstance(attempts, int)
                        or isinstance(attempts, bool)
                        or attempts < 1
                    ):
                        reason = "attempts must be a positive integer"
                    elif not isinstance(cross_platform, bool):
                        reason = "cross_platform must be a boolean"
                if reason is not None:
                    print(
                        "test_db: skipped malformed recovered flake entry "
                        f"{index}: {reason}",
                        file=sys.stderr,
                    )
                    continue
                recovered.append((case_name, attempts, cross_platform))
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"test_db: ignored malformed flake retry report at {flake_report}: {exc}",
            file=sys.stderr,
        )

    with connect(create_dirs=True) as conn:
        _ensure_schema_initialized(conn)
        for suite_name, status, duration, timeout in rows:
            conn.execute(
                """
                INSERT INTO ci_test_suites
                    (workflow_id, run_id, run_attempt, job_name, suite_name,
                     status, duration_seconds, timeout_seconds, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workflow_id, run_id, run_attempt, job_name, suite_name)
                DO UPDATE SET status=excluded.status,
                              duration_seconds=excluded.duration_seconds,
                              timeout_seconds=excluded.timeout_seconds,
                              recorded_at=excluded.recorded_at
                """,
                (*key, suite_name, status, duration, timeout, now),
            )
        for case_name, attempts, cross_platform in recovered:
            conn.execute(
                """
                INSERT INTO ci_flake_events
                    (workflow_id, run_id, run_attempt, job_name, case_name,
                     retry_attempts, cross_platform, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workflow_id, run_id, run_attempt, job_name, case_name)
                DO UPDATE SET retry_attempts=excluded.retry_attempts,
                              cross_platform=excluded.cross_platform,
                              recorded_at=excluded.recorded_at
                """,
                (
                    *key,
                    case_name,
                    attempts,
                    int(cross_platform),
                    now,
                ),
            )
    print(
        f"test_db: imported {len(rows)} suite timing(s) and "
        f"{len(recovered)} recovered flake(s) from {builddir}"
    )
    return 0


def cmd_ci_ingest(args: argparse.Namespace) -> int:
    """Pull recent CI runs from `gh run list --json` and insert.

    No GitHub API access from the CI workflow itself — that's a separate
    concern. This command runs locally (operator's dev box) and ingests
    history for the trend queries. Re-runnable; existing rows are upserted.
    """
    cmd = [
        "gh", "run", "list",
        "--workflow", args.workflow,
        "--limit", str(args.limit),
        "--json", "databaseId,headSha,headBranch,createdAt,updatedAt,conclusion,status,name",
    ]
    if args.branch:
        cmd.extend(["--branch", args.branch])
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        print(f"test_db: gh run list failed: {proc.stderr.strip()}", file=sys.stderr)
        return 1
    runs = json.loads(proc.stdout)

    inserted = 0
    skipped = 0
    with connect(create_dirs=True) as conn:
        _ensure_schema_initialized(conn)
        for run in runs:
            conclusion = run.get("conclusion") or "in_progress"
            # gh times are RFC3339 ("2026-04-28T09:45:07Z"). Parse to unix.
            from datetime import datetime, timezone
            def to_unix(s: str | None) -> int | None:
                if not s:
                    return None
                return int(datetime.fromisoformat(s.replace("Z", "+00:00"))
                           .astimezone(timezone.utc).timestamp())
            started = to_unix(run["createdAt"]) or 0
            finished = to_unix(run.get("updatedAt"))
            duration = (finished - started) if finished else None
            if conclusion not in VALID_CI_CONCLUSIONS:
                skipped += 1
                continue
            conn.execute(
                """
                INSERT INTO ci_runs
                    (workflow_id, run_id, run_attempt, job_name, triplet,
                     platform, runner, event_name, commit_sha, branch,
                     started_at, finished_at, duration_seconds, conclusion,
                     vcpkg_cache_hit, ccache_hit_ratio, notes)
                VALUES (?, ?, 1, ?, NULL, NULL, NULL, NULL, ?, ?, ?, ?, ?, ?, NULL, NULL, '')
                ON CONFLICT(workflow_id, run_id, run_attempt, job_name) DO UPDATE SET
                    commit_sha=excluded.commit_sha,
                    branch=excluded.branch,
                    started_at=excluded.started_at,
                    finished_at=excluded.finished_at,
                    duration_seconds=excluded.duration_seconds,
                    conclusion=excluded.conclusion
                """,
                (
                    args.workflow, run["databaseId"], run.get("name") or "(workflow)",
                    run["headSha"], run.get("headBranch") or "",
                    started, finished, duration, conclusion,
                ),
            )
            inserted += 1
    print(f"test_db: ingested {inserted} ci_runs from {args.workflow} ({skipped} skipped)")
    return 0


def cmd_ci_stats(args: argparse.Namespace) -> int:
    """Aggregate stats: median wall time, hit rate, failure rate per triplet.

    Window is `--since N{d|h}` (default 7d). Output is plain-text table.
    """
    seconds = _parse_window(args.since)
    cutoff = int(time.time()) - seconds
    with connect() as conn:
        conn.row_factory = sqlite3.Row
        # By triplet (or workflow if triplet NULL).
        rows = list(conn.execute(
            """
            SELECT
                COALESCE(platform, triplet, workflow_id) AS scope,
                COUNT(*)                       AS n,
                SUM(CASE WHEN conclusion='success' THEN 1 ELSE 0 END)   AS successes,
                SUM(CASE WHEN conclusion='failure' THEN 1 ELSE 0 END)   AS failures,
                SUM(CASE WHEN conclusion='cancelled' THEN 1 ELSE 0 END) AS cancellations,
                SUM(CASE WHEN conclusion='in_progress' THEN 1 ELSE 0 END) AS in_progress,
                AVG(vcpkg_cache_hit)                                    AS hit_rate,
                AVG(duration_seconds)                                   AS avg_duration
            FROM ci_runs
            WHERE started_at >= ?
            GROUP BY scope
            ORDER BY n DESC
            """,
            (cutoff,),
        ))
    if not rows:
        print(f"(no ci_runs since {args.since})")
        return 0
    print(f"{'scope':<24} {'n':>4} {'pass':>5} {'fail':>5} {'cncl':>5} "
          f"{'live':>5} {'fail%':>6} {'hit%':>5} {'avg_dur':>9}")
    print("-" * 81)
    for r in rows:
        n = r["n"] or 0
        fails = r["failures"] or 0
        completed = (r["successes"] or 0) + fails
        # Infrastructure cancels and hard-kill evidence must stay visible, but
        # they are not test verdicts and must not dilute the actual failure rate.
        fail_pct = (fails / completed * 100) if completed else 0
        hit = r["hit_rate"]
        hit_pct = f"{hit*100:>4.0f}%" if hit is not None else "  -- "
        avg = r["avg_duration"]
        avg_s = f"{int(avg)}s" if avg is not None else "    --"
        print(
            f"{(r['scope'] or '?')[:24]:<24} "
            f"{n:>4} {(r['successes'] or 0):>5} {fails:>5} "
            f"{(r['cancellations'] or 0):>5} {(r['in_progress'] or 0):>5} "
            f"{fail_pct:>5.1f}% "
            f"{hit_pct:>5} {avg_s:>9}"
        )
    return 0


def cmd_ci_suite_stats(args: argparse.Namespace) -> int:
    """Report suite reliability and duration distribution by platform."""
    cutoff = int(time.time()) - _parse_window(args.since)
    params: list[object] = [cutoff]
    where = "s.recorded_at >= ?"
    if args.platform:
        where += " AND r.platform=?"
        params.append(args.platform)
    if args.runner:
        where += " AND r.runner=?"
        params.append(args.runner)
    with connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = list(conn.execute(
            f"""
            SELECT COALESCE(r.platform, '?') AS platform,
                   s.suite_name, s.status, s.duration_seconds,
                   s.timeout_seconds
              FROM ci_test_suites s
              JOIN ci_runs r
                ON r.workflow_id=s.workflow_id
               AND r.run_id=s.run_id
               AND r.run_attempt=s.run_attempt
               AND r.job_name=s.job_name
             WHERE {where}
             ORDER BY r.platform, s.suite_name, s.duration_seconds
            """,
            params,
        ))
    grouped: dict[tuple[str, str], list[sqlite3.Row]] = {}
    for row in rows:
        grouped.setdefault((row["platform"], row["suite_name"]), []).append(row)
    if not grouped:
        print(f"(no CI suite timings since {args.since})")
        return 0
    print(
        f"{'platform':<9} {'suite':<32} {'n':>4} {'fail':>5} {'tout':>5} "
        f"{'median':>9} {'p95':>9} {'max':>9}"
    )
    print("-" * 92)
    for (platform_name, suite_name), samples in sorted(grouped.items()):
        durations = sorted(float(r["duration_seconds"]) for r in samples)
        median = (
            durations[len(durations) // 2]
            if len(durations) % 2
            else (durations[len(durations) // 2 - 1] + durations[len(durations) // 2]) / 2
        )
        p95 = durations[max(0, (95 * len(durations) + 99) // 100 - 1)]
        failures = sum(r["status"] == "failure" for r in samples)
        timeouts = sum(r["status"] == "timeout" for r in samples)
        print(
            f"{platform_name[:9]:<9} {suite_name[:32]:<32} {len(samples):>4} "
            f"{failures:>5} {timeouts:>5} {median:>8.1f}s {p95:>8.1f}s "
            f"{durations[-1]:>8.1f}s"
        )
    return 0


def cmd_ci_flakes(args: argparse.Namespace) -> int:
    """List known flakes that recovered during the selected CI window."""
    cutoff = int(time.time()) - _parse_window(args.since)
    with connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = list(conn.execute(
            """
            SELECT COALESCE(r.platform, '?') AS platform,
                   f.case_name,
                   COUNT(*) AS recoveries,
                   AVG(f.retry_attempts) AS avg_attempts,
                   MAX(f.recorded_at) AS last_seen,
                   MAX(f.cross_platform) AS cross_platform
              FROM ci_flake_events f
              JOIN ci_runs r
                ON r.workflow_id=f.workflow_id
               AND r.run_id=f.run_id
               AND r.run_attempt=f.run_attempt
               AND r.job_name=f.job_name
             WHERE f.recorded_at >= ?
             GROUP BY r.platform, f.case_name
             ORDER BY recoveries DESC, last_seen DESC
            """,
            (cutoff,),
        ))
    if not rows:
        print(f"(no recovered known flakes since {args.since})")
        return 0
    print(f"{'platform':<9} {'recoveries':>10} {'avg retry':>10} {'last seen':<20} case")
    print("-" * 100)
    for row in rows:
        last = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["last_seen"]))
        marker = " [all]" if row["cross_platform"] else ""
        print(
            f"{row['platform'][:9]:<9} {row['recoveries']:>10} "
            f"{row['avg_attempts']:>10.2f} {last:<20} {row['case_name']}{marker}"
        )
    return 0


def _parse_window(s: str) -> int:
    """Convert "7d" / "12h" / "30m" → seconds. Defaults to days if no unit."""
    s = s.strip().lower()
    if s.endswith("d"):
        return int(s[:-1]) * 86400
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("m"):
        return int(s[:-1]) * 60
    return int(s) * 86400


def _print_runs(rows: Iterable[sqlite3.Row]) -> None:
    print(
        f"{'run_id':<22} {'started':<20} {'mode':<8} {'branch':<24} "
        f"{'status':<8} {'dur':>6}  {'P/F/W/S':<11} commit"
    )
    print("-" * 110)
    for r in rows:
        started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["started_at"]))
        dur = f"{r['total_duration_seconds'] or 0}s"
        pfws = (
            f"{r['pass_count']}/{r['fail_count']}/{r['warn_count']}/{r['skip_count']}"
        )
        print(
            f"{r['run_id']:<22} {started:<20} {r['mode']:<8} "
            f"{r['branch'][:24]:<24} {r['overall_status']:<8} {dur:>6}  "
            f"{pfws:<11} {r['commit_sha'][:8]}"
        )


def cmd_query(args: argparse.Namespace) -> int:
    with connect() as conn:
        conn.row_factory = sqlite3.Row

        # Auto-vivified manual rows (mode='manual') are excluded from
        # --latest/--last/--flaky/--prune by default so operator captures
        # via `coverage-gate.sh --capture-baselines` etc. don't displace
        # real /test runs in the kept window or pollute trend/flaky stats.
        # Pass --include-manual to opt back in.
        manual_filter = "" if args.include_manual else " AND mode != 'manual'"

        if args.latest or args.last is not None:
            limit = 1 if args.latest else args.last
            rows = list(
                conn.execute(
                    f"SELECT * FROM test_runs WHERE 1=1{manual_filter} "
                    f"ORDER BY started_at DESC LIMIT ?",
                    (limit,),
                )
            )
            if not rows:
                print("(no runs recorded)")
                return 0
            _print_runs(rows)
            if args.latest and rows:
                # Also print gate detail for the single row.
                print()
                print(f"--- gates for {rows[0]['run_id']} ---")
                for g in conn.execute(
                    "SELECT phase, gate_name, status, duration_seconds, notes "
                    "FROM test_gates WHERE run_id=? "
                    "ORDER BY phase, gate_name",
                    (rows[0]["run_id"],),
                ):
                    print(
                        f"  P{g['phase']} {g['gate_name']:<32} "
                        f"{g['status']:<6} {g['duration_seconds']}s  "
                        f"{g['notes'] or ''}"
                    )
                # Sub-step timings if any.
                timings = list(
                    conn.execute(
                        "SELECT gate_name, step_name, duration_ms FROM test_timings "
                        "WHERE run_id=? ORDER BY gate_name, step_name",
                        (rows[0]["run_id"],),
                    )
                )
                if timings:
                    print()
                    print(f"--- timings for {rows[0]['run_id']} ---")
                    for t in timings:
                        print(
                            f"  {t['gate_name']}.{t['step_name']:<30} "
                            f"{t['duration_ms']:>8} ms"
                        )
                metrics = list(
                    conn.execute(
                        "SELECT metric_name, metric_value, metric_unit FROM test_metrics "
                        "WHERE run_id=? ORDER BY metric_name",
                        (rows[0]["run_id"],),
                    )
                )
                if metrics:
                    print()
                    print(f"--- metrics for {rows[0]['run_id']} ---")
                    for m in metrics:
                        print(
                            f"  {m['metric_name']:<40} "
                            f"{m['metric_value']:>12.3f} {m['metric_unit'] or ''}"
                        )
            return 0

        if args.diff:
            run_a, run_b = args.diff
            print(f"=== diff {run_a} vs {run_b} ===")
            gates_a = {
                r["gate_name"]: r
                for r in conn.execute(
                    "SELECT * FROM test_gates WHERE run_id=?", (run_a,)
                )
            }
            gates_b = {
                r["gate_name"]: r
                for r in conn.execute(
                    "SELECT * FROM test_gates WHERE run_id=?", (run_b,)
                )
            }
            all_gates = sorted(set(gates_a) | set(gates_b))
            print(f"{'gate':<34} {'A status':<10} {'B status':<10} {'A dur':>8} {'B dur':>8}")
            print("-" * 80)
            for g in all_gates:
                a = gates_a.get(g)
                b = gates_b.get(g)
                a_status = a["status"] if a else "(absent)"
                b_status = b["status"] if b else "(absent)"
                a_dur = f"{a['duration_seconds']}s" if a else "—"
                b_dur = f"{b['duration_seconds']}s" if b else "—"
                marker = "" if a_status == b_status else "  *"
                print(
                    f"{g:<34} {a_status:<10} {b_status:<10} {a_dur:>8} {b_dur:>8}{marker}"
                )
            return 0

        if args.trend:
            kind, name = args.trend.split("=", 1)
            if kind == "metric":
                where = "tm.metric_name=?"
                table = "test_metrics tm"
                value_col = "tm.metric_value"
                unit_col = "tm.metric_unit"
            elif kind == "timing":
                gate_step = name.split(".", 1)
                if len(gate_step) != 2:
                    print(
                        "trend timing= must be 'gate.step', e.g. 'phase2.image-swap'",
                        file=sys.stderr,
                    )
                    return 2
                gate, step = gate_step
                where = "tm.gate_name=? AND tm.step_name=?"
                table = "test_timings tm"
                value_col = "tm.duration_ms"
                unit_col = "'ms'"
            else:
                print(f"trend kind must be 'metric' or 'timing', got '{kind}'", file=sys.stderr)
                return 2

            params: list = []
            if kind == "metric":
                params.append(name)
            else:
                params.extend([gate, step])
            sql = (
                f"SELECT r.run_id, r.started_at, r.branch, r.commit_sha, "
                f"{value_col} AS v, {unit_col} AS u "
                f"FROM {table} JOIN test_runs r ON r.run_id=tm.run_id "
                f"WHERE {where}"
            )
            if args.branch:
                sql += " AND r.branch=?"
                params.append(args.branch)
            sql += " ORDER BY r.started_at ASC"
            rows = list(conn.execute(sql, params))
            if not rows:
                print(f"(no data for {args.trend})")
                return 0
            print(f"=== trend {args.trend} ===")
            # Unit column widened to 10 chars so "ops/sec" (7) and
            # "ms/agent" (8) don't push run_id right (ca-S3).
            print(f"{'started':<20} {'branch':<20} {'commit':<10} {'value':>14} {'unit':<10} run_id")
            for r in rows:
                started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["started_at"]))
                print(
                    f"{started:<20} {r['branch'][:20]:<20} {r['commit_sha'][:8]:<10} "
                    f"{r['v']:>14.3f} {(r['u'] or ''):<10} {r['run_id']}"
                )
            return 0

        if args.flaky:
            days = args.days or 14
            since = int(time.time()) - days * 86400
            flaky_manual_filter = "" if args.include_manual else " AND r.mode != 'manual'"
            sql = f"""
                SELECT g.gate_name,
                       SUM(CASE WHEN g.status='PASS' THEN 1 ELSE 0 END) AS pass_n,
                       SUM(CASE WHEN g.status='FAIL' THEN 1 ELSE 0 END) AS fail_n,
                       COUNT(*) AS total
                FROM test_gates g
                JOIN test_runs r ON r.run_id=g.run_id
                WHERE r.started_at >= ?{flaky_manual_filter}
                GROUP BY g.gate_name
                HAVING pass_n > 0 AND fail_n > 0
                ORDER BY (CAST(fail_n AS REAL) / total) DESC
            """
            rows = list(conn.execute(sql, (since,)))
            if not rows:
                print(f"(no flaky gates in last {days} days)")
                return 0
            print(f"=== flaky gates (last {days} days) ===")
            print(f"{'gate':<40} {'pass':>6} {'fail':>6} {'total':>6}  fail %")
            for r in rows:
                pct = 100.0 * r["fail_n"] / r["total"]
                print(
                    f"{r['gate_name']:<40} {r['pass_n']:>6} {r['fail_n']:>6} "
                    f"{r['total']:>6}  {pct:5.1f}%"
                )
            return 0

        if args.export:
            row = conn.execute(
                "SELECT * FROM test_runs WHERE run_id=?", (args.export,)
            ).fetchone()
            if not row:
                print(f"(no run {args.export})", file=sys.stderr)
                return 1
            data = {
                "run": dict(row),
                "gates": [
                    dict(g)
                    for g in conn.execute(
                        "SELECT * FROM test_gates WHERE run_id=? ORDER BY phase, gate_name",
                        (args.export,),
                    )
                ],
                "timings": [
                    dict(t)
                    for t in conn.execute(
                        "SELECT * FROM test_timings WHERE run_id=? ORDER BY gate_name, step_name",
                        (args.export,),
                    )
                ],
                "metrics": [
                    dict(m)
                    for m in conn.execute(
                        "SELECT * FROM test_metrics WHERE run_id=? ORDER BY metric_name",
                        (args.export,),
                    )
                ],
            }
            print(json.dumps(data, indent=2))
            return 0

        if args.prune is not None:
            keep = args.prune
            if keep < 1:
                print(
                    f"refusing to prune with --keep={keep} (minimum 1). "
                    f"Use sqlite3 directly if you really want to drop everything.",
                    file=sys.stderr,
                )
                return 2
            run_ids = [
                row[0]
                for row in conn.execute(
                    f"SELECT run_id FROM test_runs WHERE 1=1{manual_filter} "
                    f"ORDER BY started_at DESC"
                )
            ]
            to_delete = run_ids[keep:]
            if not to_delete:
                print(f"(nothing to prune, {len(run_ids)} runs <= keep={keep})")
                return 0
            if args.dry_run:
                print(f"--dry-run: would delete {len(to_delete)} runs:")
                for rid in to_delete:
                    print(f"  {display_run_id(rid)}")
                return 0
            with conn:
                placeholders = ",".join(["?"] * len(to_delete))
                # Foreign keys cascade to gates / timings / metrics.
                conn.execute(
                    f"DELETE FROM test_runs WHERE run_id IN ({placeholders})",
                    to_delete,
                )
            # Also reap the per-run log directories.
            removed_dirs = 0
            for rid in to_delete:
                d = safe_run_log_dir(rid)
                if d is None:
                    print(
                        f"test_db: skipped unsafe log dir for run_id={display_run_id(rid)}",
                        file=sys.stderr,
                    )
                    continue
                if d.exists():
                    for p in sorted(d.rglob("*"), reverse=True):
                        try:
                            p.unlink() if p.is_file() else p.rmdir()
                        except OSError:
                            pass
                    try:
                        d.rmdir()
                        removed_dirs += 1
                    except OSError:
                        pass
            print(f"pruned {len(to_delete)} runs, removed {removed_dirs} log dirs")
            return 0

        # No subquery → list last 10 runs.
        rows = list(
            conn.execute(
                f"SELECT * FROM test_runs WHERE 1=1{manual_filter} "
                f"ORDER BY started_at DESC LIMIT 10"
            )
        )
        if not rows:
            print("(no runs recorded)")
            return 0
        _print_runs(rows)
        return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="test_db.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="initialize the DB if missing")
    p_init.add_argument("--check", action="store_true", help="verify schema, no write")
    p_init.set_defaults(func=cmd_init)

    p_run_start = sub.add_parser("run-start", help="open a new run row")
    p_run_start.add_argument("--run-id", required=True)
    p_run_start.add_argument("--commit", required=True)
    p_run_start.add_argument("--branch", required=True)
    p_run_start.add_argument("--mode", required=True,
                              choices=["quick", "default", "full", "instructions"])
    p_run_start.add_argument("--notes", default=None)
    p_run_start.set_defaults(func=cmd_run_start)

    p_run_finish = sub.add_parser("run-finish", help="finalize a run row")
    p_run_finish.add_argument("--run-id", required=True)
    # Choices are the terminal states an operator might want to override to.
    # `RUNNING` is the auto-default before run-finish; never a valid override.
    # `default=None` covers the "not provided, auto-compute" case.
    p_run_finish.add_argument(
        "--status", default=None,
        choices=["PASS", "FAIL", "WARN", "ABORTED", "SKIP"],
        help="override computed overall_status",
    )
    p_run_finish.set_defaults(func=cmd_run_finish)

    p_gate = sub.add_parser("gate", help="record a gate result")
    p_gate.add_argument("--run-id", required=True)
    p_gate.add_argument("--phase", type=int, required=True)
    p_gate.add_argument("--gate", required=True)
    p_gate.add_argument("--status", required=True)
    p_gate.add_argument("--duration", type=int, required=True, help="seconds")
    p_gate.add_argument("--log", default=None)
    p_gate.add_argument("--notes", default=None)
    p_gate.set_defaults(func=cmd_gate)

    p_timing = sub.add_parser("timing", help="record a sub-step timing")
    p_timing.add_argument("--run-id", required=True)
    p_timing.add_argument("--gate", required=True)
    p_timing.add_argument("--step", required=True)
    p_timing.add_argument("--ms", type=int, required=True)
    p_timing.set_defaults(func=cmd_timing)

    p_metric = sub.add_parser("metric", help="record a quantitative metric")
    p_metric.add_argument("--run-id", required=True)
    p_metric.add_argument("--name", required=True)
    p_metric.add_argument("--value", type=float, required=True)
    p_metric.add_argument("--unit", default=None)
    p_metric.set_defaults(func=cmd_metric)

    # ── ci_runs subcommands (PR-9 of CI overhaul plan) ──────────────────
    p_ci_record = sub.add_parser(
        "ci-record",
        help="record one ci_runs row (idempotent on workflow+run+job)",
    )
    p_ci_record.add_argument("--workflow", required=True, help="e.g. ci.yml")
    p_ci_record.add_argument("--run-id", type=int, required=True, dest="run_id")
    p_ci_record.add_argument("--run-attempt", type=int, default=1, dest="run_attempt")
    p_ci_record.add_argument("--job-name", required=True, dest="job_name")
    p_ci_record.add_argument("--triplet", default=None)
    p_ci_record.add_argument("--platform", default=None)
    p_ci_record.add_argument("--runner", default=None)
    p_ci_record.add_argument("--event-name", default=None, dest="event_name")
    p_ci_record.add_argument("--commit", required=True)
    p_ci_record.add_argument("--branch", required=True)
    p_ci_record.add_argument("--started-at", type=int, required=True, dest="started_at")
    p_ci_record.add_argument("--finished-at", type=int, default=None, dest="finished_at")
    p_ci_record.add_argument(
        "--conclusion", required=True,
        help=f"one of {sorted(VALID_CI_CONCLUSIONS)}",
    )
    p_ci_record.add_argument(
        "--vcpkg-cache-hit", type=int, default=None, dest="vcpkg_cache_hit",
        choices=[0, 1], help="1 for hit, 0 for from-source",
    )
    p_ci_record.add_argument(
        "--ccache-hit-ratio", type=float, default=None, dest="ccache_hit_ratio",
        help="0.0-1.0",
    )
    p_ci_record.add_argument("--notes", default=None)
    p_ci_record.set_defaults(func=cmd_ci_record)

    p_ci_junit = sub.add_parser(
        "ci-import-junit",
        help="persist Meson suite timings and recovered-flake events",
    )
    p_ci_junit.add_argument("--workflow", required=True)
    p_ci_junit.add_argument("--run-id", type=int, required=True, dest="run_id")
    p_ci_junit.add_argument("--run-attempt", type=int, default=1, dest="run_attempt")
    p_ci_junit.add_argument("--job-name", required=True, dest="job_name")
    p_ci_junit.add_argument("--builddir", required=True)
    p_ci_junit.add_argument("--junit", default=None)
    p_ci_junit.add_argument("--flake-report", default=None, dest="flake_report")
    p_ci_junit.set_defaults(func=cmd_ci_import_junit)

    p_ci_ingest = sub.add_parser(
        "ci-ingest",
        help="pull recent CI runs from `gh run list --json` into ci_runs",
    )
    p_ci_ingest.add_argument(
        "--workflow", default="ci.yml",
        help="workflow file name (default: ci.yml)",
    )
    p_ci_ingest.add_argument("--limit", type=int, default=50)
    p_ci_ingest.add_argument("--branch", default=None)
    p_ci_ingest.set_defaults(func=cmd_ci_ingest)

    p_ci_stats = sub.add_parser(
        "ci-stats",
        help="aggregate CI stats per triplet/workflow over a window",
    )
    p_ci_stats.add_argument(
        "--since", default="7d",
        help="window: 7d / 12h / 30m (default 7d)",
    )
    p_ci_stats.set_defaults(func=cmd_ci_stats)

    p_ci_suite_stats = sub.add_parser(
        "ci-suite-stats",
        help="suite failure/timeout rates and duration distributions",
    )
    p_ci_suite_stats.add_argument(
        "--since", default="7d", help="window: 7d / 12h / 30m (default 7d)"
    )
    p_ci_suite_stats.add_argument("--platform", default=None)
    p_ci_suite_stats.add_argument("--runner", default=None)
    p_ci_suite_stats.set_defaults(func=cmd_ci_suite_stats)

    p_ci_flakes = sub.add_parser(
        "ci-flakes",
        help="recovered known-flake frequency by platform and case",
    )
    p_ci_flakes.add_argument(
        "--since", default="30d", help="window: 7d / 12h / 30m (default 30d)"
    )
    p_ci_flakes.set_defaults(func=cmd_ci_flakes)

    p_query = sub.add_parser("query", help="query historical runs")
    g = p_query.add_mutually_exclusive_group()
    g.add_argument("--latest", action="store_true", help="show the most recent run with detail")
    g.add_argument("--last", type=int, metavar="N", help="show last N runs")
    g.add_argument(
        "--diff", nargs=2, metavar=("RUN_A", "RUN_B"),
        help="side-by-side gate diff",
    )
    g.add_argument(
        "--trend", metavar="KIND=NAME",
        help="time series for one metric (metric=name) or step (timing=gate.step)",
    )
    g.add_argument("--flaky", action="store_true", help="gates that have alternated PASS↔FAIL")
    g.add_argument("--export", metavar="RUN_ID", help="dump full run as JSON")
    g.add_argument("--prune", type=int, metavar="KEEP_N", help="delete all but the most recent N")
    p_query.add_argument("--branch", default=None)
    p_query.add_argument("--days", type=int, default=None, help="window for --flaky (default 14)")
    p_query.add_argument(
        "--dry-run", action="store_true",
        help="for --prune: print what would be deleted without committing",
    )
    p_query.add_argument(
        "--include-manual", action="store_true",
        help="include mode='manual' rows (auto-vivified by --capture-baselines etc.) "
             "in --latest/--last/--flaky/--prune. Off by default so operator captures "
             "don't displace real /test runs in the kept window.",
    )
    p_query.set_defaults(func=cmd_query)

    args = parser.parse_args(argv)
    if getattr(args, "cmd", None) in {"run-start", "run-finish", "gate", "timing", "metric"}:
        if not validate_run_id(args.run_id):
            print(
                "test_db: invalid --run-id "
                "(allowed: A-Z a-z 0-9 . _ -)",
                file=sys.stderr,
            )
            return 2
    try:
        return args.func(args)
    except sqlite3.OperationalError as e:
        # One central net for every subcommand's connect()/execute() (#1146):
        # under concurrent writers (nightly + PR run sharing YUZU_TEST_DB on
        # one runner box) a busy_timeout-exhausted 'database is locked' used
        # to escape as a raw traceback. Exit 1 = operational failure; exit 2
        # stays reserved for validation errors. Only diagnose contention when
        # the error actually is lock-shaped — 'unable to open database file'
        # etc. must not be blamed on a concurrent writer.
        msg = str(e)
        # Primary result code (low byte of the extended code) when the driver
        # exposes it (Python 3.11+): SQLITE_BUSY=5, SQLITE_LOCKED=6,
        # SQLITE_PROTOCOL=15. The message-substring check is ONLY the fallback
        # for older Pythons — when the authoritative code is present it alone
        # decides, so a non-lock error naming a 'busy_*' table can't pick up
        # the contention hint (gov sec-1).
        code = getattr(e, "sqlite_errorcode", None)
        lock_shaped = (
            (code & 0xFF) in (5, 6, 15)
            if code is not None
            else ("locked" in msg.lower() or "busy" in msg.lower())
        )
        hint = (
            " — concurrent writer (overlapping runs sharing YUZU_TEST_DB?); "
            "busy_timeout exhausted"
            if lock_shaped
            else ""
        )
        print(f"test_db: SQLite operational error on {db_path()}: {msg}{hint}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
