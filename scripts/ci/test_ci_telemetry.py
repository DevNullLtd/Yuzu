#!/usr/bin/env python3
"""Hermetic regression test for runner-local CI telemetry."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from pathlib import Path

HERE = Path(__file__).resolve().parent
TELEMETRY_PATH = HERE / "ci-telemetry.py"
TEST_DB_PATH = HERE.parent / "test" / "test_db.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def check(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def fake_env(root: Path, attempt: int = 1) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "RUNNER_TOOL_CACHE": str(root / "tool-cache"),
        "RUNNER_NAME": "yuzu-bigtam-linux-2",
        "RUNNER_OS": "Linux",
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": str(attempt),
        "GITHUB_SHA": "a" * 40,
        "GITHUB_REF_NAME": "dev",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_JOB": "linux",
        "GITHUB_WORKFLOW": "CI",
        "GITHUB_WORKFLOW_REF": "DevNullLtd/Yuzu/.github/workflows/ci.yml@refs/heads/dev",
        "GITHUB_ENV": str(root / f"github-env-{attempt}"),
    }


def main() -> int:
    telemetry = load(TELEMETRY_PATH, "ci_telemetry")
    test_db = load(TEST_DB_PATH, "test_db_for_ci_telemetry")
    failures: list[str] = []

    with tempfile.TemporaryDirectory(prefix="yuzu-ci-telemetry-") as temp:
        root = Path(temp)
        env = fake_env(root)
        args = argparse.Namespace(job_name="Linux gcc-15 debug", triplet="x64-linux")
        check(telemetry.start(args, env) == 0, "start failed", failures)
        db = telemetry.telemetry_db_path(env)
        check(db.name == "test-runs.db", "database filename drifted", failures)
        check(env["RUNNER_NAME"] in db.parts, "database is not per-runner", failures)
        check(db.exists(), "start did not create the database", failures)

        builddir = root / "build-linux"
        (builddir / "meson-info").mkdir(parents=True)
        (builddir / "meson-logs").mkdir(parents=True)
        (builddir / "meson-info" / "intro-tests.json").write_text(
            json.dumps([
                {"name": "tar unit tests", "timeout": 90},
                {"name": "server unit tests", "timeout": 600},
            ]),
            encoding="utf-8",
        )
        (builddir / "meson-logs" / "testlog.junit.xml").write_text(
            "<testsuites><testsuite>"
            '<testcase name="tar - yuzu:tar unit tests" time="14.5"/>'
            '<testcase name="server - yuzu:server unit tests" time="602.1">'
            '<failure message="TIMEOUT">process killed at timeout</failure>'
            "</testcase></testsuite></testsuites>",
            encoding="utf-8",
        )
        (builddir / "meson-logs" / "flake-retry.json").write_text(
            json.dumps({
                "platform": "linux",
                "recovered": [
                    {
                        "case": "Known Flake", "cross_platform": False,
                        "attempts": 1,
                    },
                    {"case": "Bad Attempts", "cross_platform": False, "attempts": "1"},
                    {"case": "Bad Cross Flag", "cross_platform": "false", "attempts": 1},
                    {"cross_platform": False, "attempts": 1},
                    "not an object",
                ],
                "blocked": [],
            }),
            encoding="utf-8",
        )
        finish_args = argparse.Namespace(
            job_name="Linux gcc-15 debug", triplet="x64-linux",
            builddir=str(builddir), conclusion="failure",
        )
        check(telemetry.finish(finish_args, env) == 0, "finish failed", failures)

        with closing(sqlite3.connect(db)) as conn:
            version = conn.execute(
                "SELECT version FROM schema_meta WHERE store='test_runs_db'"
            ).fetchone()[0]
            job = conn.execute(
                "SELECT run_attempt, platform, runner, conclusion FROM ci_runs"
            ).fetchone()
            suites = conn.execute(
                "SELECT suite_name, status, duration_seconds, timeout_seconds "
                "FROM ci_test_suites ORDER BY suite_name"
            ).fetchall()
            flakes = conn.execute(
                "SELECT case_name, retry_attempts FROM ci_flake_events"
            ).fetchall()
        check(version == 3, f"schema is v{version}, expected v3", failures)
        check(job == (1, "linux", "yuzu-bigtam-linux-2", "failure"),
              f"wrong job row: {job}", failures)
        check(suites == [
            ("server unit tests", "timeout", 602.1, 600.0),
            ("tar unit tests", "success", 14.5, 90.0),
        ], f"wrong suite rows: {suites}", failures)
        check(flakes == [("Known Flake", 1)], f"wrong flake rows: {flakes}", failures)

        # A malformed recovered-flake entry is reporting corruption, not a
        # test result. Import the usable entry, warn for the rest, and report
        # the number actually accepted rather than the raw JSON array length.
        flake_import = subprocess.run(
            [
                sys.executable, str(TEST_DB_PATH), "ci-import-junit",
                "--workflow", "ci.yml", "--run-id", "12345",
                "--run-attempt", "1", "--job-name", "Linux gcc-15 debug",
                "--builddir", str(builddir),
            ],
            env=dict(os.environ, YUZU_TEST_DB=str(db)),
            capture_output=True, text=True, check=False,
        )
        check(
            flake_import.returncode == 0
            and "1 recovered flake(s)" in flake_import.stdout
            and "skipped malformed recovered flake entry" in flake_import.stderr,
            "malformed recovered-flake entries were not reported honestly: "
            f"{flake_import.stderr or flake_import.stdout}",
            failures,
        )

        query_env = dict(os.environ, YUZU_TEST_DB=str(db))
        suite_query = subprocess.run(
            [sys.executable, str(TEST_DB_PATH), "ci-suite-stats", "--since", "1d"],
            env=query_env, capture_output=True, text=True, check=False,
        )
        check(
            suite_query.returncode == 0
            and "server unit tests" in suite_query.stdout
            and "tar unit tests" in suite_query.stdout,
            f"suite stats query failed: {suite_query.stderr or suite_query.stdout}",
            failures,
        )
        flake_query = subprocess.run(
            [sys.executable, str(TEST_DB_PATH), "ci-flakes", "--since", "1d"],
            env=query_env, capture_output=True, text=True, check=False,
        )
        check(
            flake_query.returncode == 0 and "Known Flake" in flake_query.stdout,
            f"flake query failed: {flake_query.stderr or flake_query.stdout}",
            failures,
        )

        # A GitHub rerun must add attempt 2, not overwrite attempt 1.
        env2 = fake_env(root, attempt=2)
        check(telemetry.start(args, env2) == 0, "rerun start failed", failures)
        finish_args.builddir = None
        finish_args.conclusion = "success"
        check(telemetry.finish(finish_args, env2) == 0, "rerun finish failed", failures)
        with closing(sqlite3.connect(db)) as conn:
            attempts = conn.execute(
                "SELECT run_attempt, conclusion FROM ci_runs ORDER BY run_attempt"
            ).fetchall()
        check(attempts == [(1, "failure"), (2, "success")],
              f"rerun evidence was overwritten: {attempts}", failures)

        # The always() finalizer can run without the start step's exported
        # timestamp (for example after a runner interruption). Its fallback
        # timestamp must not overwrite the durable start row or collapse the
        # measured duration to zero.
        env4 = fake_env(root, attempt=4)
        check(telemetry.start(args, env4) == 0,
              "timestamp regression start failed", failures)
        aged_start = int(env4["YUZU_CI_JOB_STARTED_AT"]) - 30
        with closing(sqlite3.connect(db)) as conn:
            conn.execute(
                "UPDATE ci_runs SET started_at=? WHERE run_attempt=4",
                (aged_start,),
            )
            conn.commit()
        del env4["YUZU_CI_JOB_STARTED_AT"]
        missing_start_finish = argparse.Namespace(
            job_name="Linux gcc-15 debug", triplet="x64-linux",
            builddir=None, conclusion="success",
        )
        check(telemetry.finish(missing_start_finish, env4) == 0,
              "finalizer without exported start failed", failures)
        with closing(sqlite3.connect(db)) as conn:
            preserved_start = conn.execute(
                "SELECT started_at, duration_seconds FROM ci_runs "
                "WHERE run_attempt=4"
            ).fetchone()
        check(
            preserved_start is not None
            and preserved_start[0] == aged_start
            and preserved_start[1] >= 30,
            f"finalizer overwrote durable start/duration: {preserved_start}",
            failures,
        )

        # Corrupt JUnit is a telemetry-input failure. The job conclusion must
        # remain durable and the reporting wrapper must still exit green.
        env5 = fake_env(root, attempt=5)
        check(telemetry.start(args, env5) == 0,
              "malformed-JUnit start failed", failures)
        bad_builddir = root / "build-malformed-junit"
        (bad_builddir / "meson-logs").mkdir(parents=True)
        (bad_builddir / "meson-logs" / "testlog.junit.xml").write_text(
            "<testsuites><broken>", encoding="utf-8"
        )
        bad_finish = argparse.Namespace(
            job_name="Linux gcc-15 debug", triplet="x64-linux",
            builddir=str(bad_builddir), conclusion="success",
        )
        check(telemetry.finish(bad_finish, env5) == 0,
              "malformed JUnit changed the telemetry step result", failures)
        with closing(sqlite3.connect(db)) as conn:
            bad_junit_parent = conn.execute(
                "SELECT conclusion FROM ci_runs WHERE run_attempt=5"
            ).fetchone()
        check(bad_junit_parent == ("success",),
              f"malformed JUnit lost the parent result: {bad_junit_parent}", failures)

        # Even inability to create/open the runner-local database is
        # best-effort reporting. The workflow has an outer continue-on-error
        # guard too, but the recorder's own CLI contract must remain green.
        blocked_parent = root / "database-parent-is-a-file"
        blocked_parent.write_text("not a directory", encoding="utf-8")
        broken_env = fake_env(root, attempt=6)
        broken_env["YUZU_TEST_DB"] = str(blocked_parent / "test-runs.db")
        broken_recorder = subprocess.run(
            [
                sys.executable, str(TELEMETRY_PATH), "start",
                "--job-name", "Linux gcc-15 debug", "--triplet", "x64-linux",
            ],
            env=broken_env, capture_output=True, text=True, check=False,
        )
        check(
            broken_recorder.returncode == 0 and "::warning" in broken_recorder.stderr,
            "recorder storage failure escaped its best-effort boundary: "
            f"{broken_recorder.stderr or broken_recorder.stdout}",
            failures,
        )

        # The workflow must override Nathan's profile TEMP/TMP on Wee Tam with
        # this runner's Defender-excluded RUNNER_TEMP. TMPDIR uses forward
        # slashes so the MSYS2 runtime converts it to /d/... for bash tools.
        win_env = fake_env(root, attempt=3)
        win_env.update({
            "RUNNER_NAME": "yuzu-weetam-windows-3",
            "RUNNER_OS": "Windows",
            "RUNNER_TEMP": str(root / "windows-runner-temp"),
        })
        win_args = argparse.Namespace(
            job_name="Windows MSVC debug", triplet="x64-windows"
        )
        check(telemetry.start(win_args, win_env) == 0,
              "Windows start failed", failures)
        exported = Path(win_env["GITHUB_ENV"]).read_text(encoding="utf-8")
        for variable in ("TEMP", "TMP", "TMPDIR"):
            check(f"{variable}=" in exported,
                  f"Windows {variable} was not exported", failures)
        check(win_env["TEMP"] == win_env["RUNNER_TEMP"],
              "Windows TEMP does not use RUNNER_TEMP", failures)
        check(win_env["TMP"] == win_env["RUNNER_TEMP"],
              "Windows TMP does not use RUNNER_TEMP", failures)
        check(win_env["TMPDIR"] == win_env["RUNNER_TEMP"].replace("\\", "/"),
              "Windows TMPDIR is not MSYS2-compatible", failures)

        # A persistent builddir can retain attempt 1's Meson logs. Attempt 2
        # must not inherit them when it never reached its Test step.
        old_time = int(env2["YUZU_CI_JOB_STARTED_AT"]) - 10
        os.utime(builddir / "meson-logs" / "testlog.junit.xml", (old_time, old_time))
        stale_import = subprocess.run(
            [
                sys.executable, str(TEST_DB_PATH), "ci-import-junit",
                "--workflow", "ci.yml", "--run-id", "12345",
                "--run-attempt", "2", "--job-name", "Linux gcc-15 debug",
                "--builddir", str(builddir),
            ],
            env=query_env, capture_output=True, text=True, check=False,
        )
        with closing(sqlite3.connect(db)) as conn:
            inherited = conn.execute(
                "SELECT COUNT(*) FROM ci_test_suites WHERE run_attempt=2"
            ).fetchone()[0]
        check(
            stale_import.returncode == 0 and inherited == 0,
            f"stale suite evidence leaked into rerun: {stale_import.stderr}",
            failures,
        )

        # A runner that already has the old v2 DB migrates without losing rows.
        legacy = root / "legacy" / "test-runs.db"
        legacy.parent.mkdir()
        with closing(sqlite3.connect(legacy)) as conn:
            conn.executescript(test_db.SCHEMA_V1)
            conn.executescript(test_db.SCHEMA_V2)
            test_db.stamp_version(conn, 2)
            conn.execute(
                "INSERT INTO ci_runs "
                "(workflow_id,run_id,job_name,commit_sha,branch,started_at,conclusion) "
                "VALUES ('ci.yml',7,'Windows MSVC debug','deadbeef','dev',1,'failure')"
            )
            conn.commit()
        migrate_env = dict(os.environ, YUZU_TEST_DB=str(legacy))
        migrated = subprocess.run(
            [sys.executable, str(TEST_DB_PATH), "init"], env=migrate_env,
            capture_output=True, text=True, check=False,
        )
        check(migrated.returncode == 0,
              f"v2 migration failed: {migrated.stderr}", failures)
        with closing(sqlite3.connect(legacy)) as conn:
            old = conn.execute(
                "SELECT run_attempt, job_name, conclusion FROM ci_runs"
            ).fetchone()
        check(old == (1, "Windows MSVC debug", "failure"),
              f"v2 row lost in migration: {old}", failures)

        # Two connections can both observe v2 before either upgrades it. The
        # second upgrader must re-read the version after acquiring its write
        # lock; replaying the table replacement against v3 resets attempt and
        # platform fields and cascades away suite/flake children.
        race = root / "migration-race" / "test-runs.db"
        race.parent.mkdir()
        with closing(sqlite3.connect(race, isolation_level=None)) as conn:
            conn.executescript(test_db.SCHEMA_V1)
            conn.executescript(test_db.SCHEMA_V2)
            test_db.stamp_version(conn, 2)
        with (
            closing(sqlite3.connect(race, isolation_level=None)) as first,
            closing(sqlite3.connect(race, isolation_level=None)) as stale_reader,
        ):
            first.execute("PRAGMA foreign_keys=ON")
            stale_reader.execute("PRAGMA foreign_keys=ON")
            stale_version = test_db.schema_version(stale_reader)
            test_db._upgrade_schema(first, test_db.schema_version(first))
            first.execute(
                """
                INSERT INTO ci_runs
                    (workflow_id, run_id, run_attempt, job_name, triplet,
                     platform, runner, event_name, commit_sha, branch,
                     started_at, finished_at, duration_seconds, conclusion,
                     vcpkg_cache_hit, ccache_hit_ratio, notes)
                VALUES
                    ('ci.yml', 99, 2, 'Windows MSVC debug', 'x64-windows',
                     'windows', 'yuzu-weetam-windows-0', 'pull_request',
                     'deadbeef', 'dev', 100, 120, 20, 'success', 1, NULL, '')
                """
            )
            first.execute(
                """
                INSERT INTO ci_test_suites
                    (workflow_id, run_id, run_attempt, job_name, suite_name,
                     status, duration_seconds, timeout_seconds, recorded_at)
                VALUES
                    ('ci.yml', 99, 2, 'Windows MSVC debug',
                     'server unit tests', 'success', 10, 600, 120)
                """
            )
            first.execute(
                """
                INSERT INTO ci_flake_events
                    (workflow_id, run_id, run_attempt, job_name, case_name,
                     retry_attempts, cross_platform, recorded_at)
                VALUES
                    ('ci.yml', 99, 2, 'Windows MSVC debug',
                     'Recovered Flake', 1, 0, 120)
                """
            )
            test_db._upgrade_schema(stale_reader, stale_version)
            raced_parent = stale_reader.execute(
                "SELECT run_attempt, platform, event_name FROM ci_runs "
                "WHERE run_id=99"
            ).fetchone()
            raced_children = stale_reader.execute(
                "SELECT (SELECT COUNT(*) FROM ci_test_suites), "
                "       (SELECT COUNT(*) FROM ci_flake_events)"
            ).fetchone()
        check(
            raced_parent == (2, "windows", "pull_request")
            and raced_children == (1, 1),
            "stale v2 upgrader replayed migration and destroyed v3 evidence: "
            f"parent={raced_parent}, children={raced_children}",
            failures,
        )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print("ci-telemetry selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
