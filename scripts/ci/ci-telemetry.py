#!/usr/bin/env python3
"""Persist one GitHub Actions job into that runner's test-runs.db.

Each self-hosted runner gets a distinct database below RUNNER_TOOL_CACHE. The
path is outside the checkout, so actions/checkout cleanup and branch switches do
not erase the history. ``start`` writes an in-progress row and exports the path
and start timestamp through GITHUB_ENV; the workflow's always() ``finish`` step
finalizes the row and imports Meson's suite timings plus recovered flake events.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEST_DB = HERE.parent / "test" / "test_db.py"
SAFE_RUNNER = re.compile(r"^[A-Za-z0-9._-]+$")


def warning(message: str) -> None:
    """Emit a log-safe Actions warning for best-effort telemetry failures."""
    escaped = (
        message.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )
    print(f"::warning title=CI telemetry::{escaped}", file=sys.stderr)


def telemetry_db_path(env: dict[str, str]) -> Path:
    configured = env.get("YUZU_TEST_DB")
    if configured:
        return Path(configured).expanduser()
    runner = env.get("RUNNER_NAME", "")
    if not SAFE_RUNNER.fullmatch(runner) or runner in {".", ".."}:
        raise ValueError("RUNNER_NAME is missing or unsafe")
    tool_cache = env.get("RUNNER_TOOL_CACHE")
    if not tool_cache:
        raise ValueError("RUNNER_TOOL_CACHE is unset; refusing a non-persistent CI database")
    return Path(tool_cache) / "yuzu-test-runs" / runner / "test-runs.db"


def workflow_id(env: dict[str, str]) -> str:
    ref = env.get("GITHUB_WORKFLOW_REF", "")
    match = re.search(r"/\.github/workflows/([^/@]+)@", ref)
    if match:
        return match.group(1)
    return env.get("GITHUB_WORKFLOW", "unknown")


def platform_name(env: dict[str, str]) -> str:
    return {"Linux": "linux", "Windows": "windows", "macOS": "macos"}.get(
        env.get("RUNNER_OS", ""), env.get("RUNNER_OS", "").lower()
    )


def metadata(env: dict[str, str], job_name: str, triplet: str | None) -> dict[str, str]:
    required = ["GITHUB_RUN_ID", "GITHUB_SHA", "RUNNER_NAME", "RUNNER_OS"]
    missing = [name for name in required if not env.get(name)]
    if missing:
        raise ValueError("missing GitHub runner metadata: " + ", ".join(missing))
    return {
        "workflow": workflow_id(env),
        "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": env.get("GITHUB_RUN_ATTEMPT", "1"),
        "job_name": job_name,
        "triplet": triplet or "",
        "platform": platform_name(env),
        "runner": env["RUNNER_NAME"],
        "event_name": env.get("GITHUB_EVENT_NAME", "unknown"),
        "commit": env["GITHUB_SHA"],
        "branch": env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME", "unknown"),
    }


def append_github_env(env: dict[str, str], name: str, value: str) -> None:
    path = env.get("GITHUB_ENV")
    if not path:
        return
    if "\n" in name or "\n" in value or "\r" in value:
        raise ValueError(f"refusing newline in GitHub environment value {name}")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{name}={value}\n")


def export_windows_temp(env: dict[str, str]) -> None:
    """Route Windows job temporaries into that runner's excluded work temp."""
    if env.get("RUNNER_OS") != "Windows":
        return
    runner_temp = env.get("RUNNER_TEMP")
    if not runner_temp:
        raise ValueError("RUNNER_TEMP is unset on a Windows runner")
    Path(runner_temp).mkdir(parents=True, exist_ok=True)
    values = {
        "TEMP": runner_temp,
        "TMP": runner_temp,
        # MSYS2 converts this drive path to /d/... when it starts bash.
        "TMPDIR": runner_temp.replace("\\", "/"),
    }
    for name, value in values.items():
        env[name] = value
        append_github_env(env, name, value)


def run_db(env: dict[str, str], *args: str) -> int:
    proc = subprocess.run([sys.executable, str(TEST_DB), *args], env=env, check=False)
    return proc.returncode


def record_args(
    meta: dict[str, str], started: int, conclusion: str, env: dict[str, str]
) -> list[str]:
    args = [
        "ci-record",
        "--workflow", meta["workflow"],
        "--run-id", meta["run_id"],
        "--run-attempt", meta["run_attempt"],
        "--job-name", meta["job_name"],
        "--platform", meta["platform"],
        "--runner", meta["runner"],
        "--event-name", meta["event_name"],
        "--commit", meta["commit"],
        "--branch", meta["branch"],
        "--started-at", str(started),
        "--conclusion", conclusion,
        "--notes", f"github_job={env.get('GITHUB_JOB', 'unknown')}",
    ]
    if meta["triplet"]:
        args.extend(["--triplet", meta["triplet"]])
    return args


def ccache_hit_ratio() -> float | None:
    try:
        proc = subprocess.run(
            ["ccache", "--print-stats"], capture_output=True, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    stats: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        key, sep, value = line.partition("\t")
        if sep:
            try:
                stats[key] = int(value)
            except ValueError:
                pass
    hits = stats.get("direct_cache_hit", 0) + stats.get("preprocessed_cache_hit", 0)
    total = hits + stats.get("cache_miss", 0)
    return hits / total if total else None


def start(args: argparse.Namespace, env: dict[str, str]) -> int:
    db = telemetry_db_path(env).resolve()
    db.parent.mkdir(parents=True, exist_ok=True)
    env["YUZU_TEST_DB"] = str(db)
    started = int(time.time())
    env["YUZU_CI_JOB_STARTED_AT"] = str(started)
    append_github_env(env, "YUZU_TEST_DB", str(db))
    append_github_env(env, "YUZU_CI_JOB_STARTED_AT", str(started))
    export_windows_temp(env)
    if run_db(env, "init") != 0:
        warning("database initialization failed; telemetry was skipped")
        return 0
    meta = metadata(env, args.job_name, args.triplet)
    rc = run_db(env, *record_args(meta, started, "in_progress", env))
    if rc == 0:
        print(f"ci-telemetry: {meta['runner']} -> {db}")
    else:
        warning("job-start record failed; telemetry was skipped")
    return 0


def finish(args: argparse.Namespace, env: dict[str, str]) -> int:
    db = telemetry_db_path(env).resolve()
    env["YUZU_TEST_DB"] = str(db)
    meta = metadata(env, args.job_name, args.triplet)
    try:
        started = int(env["YUZU_CI_JOB_STARTED_AT"])
    except (KeyError, ValueError):
        started = int(time.time())
        warning(
            "YUZU_CI_JOB_STARTED_AT is unavailable; the durable database "
            "start time will be preserved when present"
        )
    finished = int(time.time())
    record = record_args(meta, started, args.conclusion, env)
    record.extend(["--finished-at", str(finished)])
    ratio = ccache_hit_ratio()
    if ratio is not None:
        record.extend(["--ccache-hit-ratio", f"{ratio:.6f}"])
    if run_db(env, *record) != 0:
        warning("job-finalization record failed; telemetry was skipped")
        return 0
    if args.builddir:
        rc = run_db(
            env,
            "ci-import-junit",
            "--workflow", meta["workflow"],
            "--run-id", meta["run_id"],
            "--run-attempt", meta["run_attempt"],
            "--job-name", meta["job_name"],
            "--builddir", args.builddir,
        )
        if rc != 0:
            warning("suite/flake import failed; the CI job result is unaffected")
    print(f"ci-telemetry: finalized {meta['job_name']} as {args.conclusion}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="runner-local persistent CI telemetry")
    sub = parser.add_subparsers(dest="command", required=True)
    p_start = sub.add_parser("start")
    p_start.add_argument("--job-name", required=True)
    p_start.add_argument("--triplet", default=None)
    p_finish = sub.add_parser("finish")
    p_finish.add_argument("--job-name", required=True)
    p_finish.add_argument("--triplet", default=None)
    p_finish.add_argument("--builddir", default=None)
    p_finish.add_argument(
        "--conclusion", required=True,
        choices=["success", "failure", "cancelled", "skipped", "timed_out", "neutral"],
    )
    args = parser.parse_args(argv)
    try:
        return start(args, os.environ.copy()) if args.command == "start" else finish(args, os.environ.copy())
    except Exception as exc:  # noqa: BLE001 - telemetry must never fail the CI job
        warning(f"recorder failed and was skipped: {exc}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
