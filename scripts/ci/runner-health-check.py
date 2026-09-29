#!/usr/bin/env python3
"""runner-health-check.py — query GitHub /actions/runners and report health.

Two consumers (do not duplicate the logic):

1. .github/workflows/runner-inventory-sentinel.yml
   Uses --mode sentinel (default). Compares actual to .github/runner-inventory.json,
   prints drift, writes typed failure outputs to $GITHUB_OUTPUT, and exits
   non-zero on any drift or control-plane failure. This is the loud issue path.

2. CI preflight jobs.
   Use --mode preflight. The same query reports per-runner and per-pool
   health to $GITHUB_OUTPUT. A preflight names each pool it requires with
   --require-pool; an unavailable required pool or an untrustworthy control-
   plane response fails the preflight instead of turning required checks into
   green skips.
   Also emits `linux_pool_healthy` — true iff >=1 runner eligible for the
   [self-hosted, Linux, X64] job pool is online (see LINUX_POOL_LABELS). The
   proto-compat + linux jobs gate on the pool rather than a single named runner,
   so any free pool member (yuzu-bigtam-* or the Shulgi fallback) keeps them
   running, while a wholly-offline pool still skips them fast. Likewise emits
   `weetam_pool_healthy` for the exact [self-hosted, Windows, X64,
   yuzu-weetam-windows] pool used by the Windows jobs.

The fall-closed contract is intentional: a degraded sentinel must NOT
silently accept "I don't know" as healthy. Always check `== 'true'`,
never `!= 'false'`.

PAT requirement: /repos/.../actions/runners requires admin scope, which
the default GITHUB_TOKEN cannot grant. Set RUNNER_INVENTORY_TOKEN as a
fine-grained PAT with Administration:read and pass it as GH_TOKEN.
Without it, both modes emit a typed control-plane failure and exit 1.

Automatic fork pull requests are deliberately not trusted. Preflight rejects
them before querying self-hosted runner state; a maintainer-approved workflow
dispatch path must invoke the full CI gate against an immutable PR head SHA.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum
import json
import os
import re
import subprocess
import sys
import time
import uuid
from typing import Any


INVENTORY_PATH = ".github/runner-inventory.json"
QUERY_TIMEOUT_SECONDS = 30
MAX_QUERY_ATTEMPTS = 3
RETRY_DELAYS_SECONDS = (1, 2)

# The self-hosted Linux job pool. ci.yml's proto-compat + linux jobs use
# runs-on: [self-hosted, Linux, X64], so any declared runner whose labels are a
# superset of this set is eligible to run them. In preflight mode the script
# emits `linux_pool_healthy=true` iff >=1 such runner is online+labelled
# (fail-closed: zero online -> the Linux jobs skip fast, exactly as the old
# single-named gate did when that one runner was down). This includes Shulgi
# (yuzu-wsl2-linux) as a fallback during the BigTam cutover; Shulgi drops out of
# the pool automatically when it is later removed from the inventory, leaving the
# yuzu-bigtam-* runners as the pool. Per-runner `<slug>_healthy` outputs are still
# emitted unchanged (the sentinel and any pinned-runner gates rely on them).
LINUX_POOL_LABELS = frozenset({"self-hosted", "Linux", "X64"})

# The Big Tam Linux pool. The ci.yml `linux` compile job pins
# runs-on: [self-hosted, Linux, X64, yuzu-bigtam-linux] because its toolchain
# (GCC 15 / Clang 21) exists only on Big Tam's Ubuntu 26.04 — Shulgi (24.04)
# cannot build it. preflight emits `bigtam_pool_healthy=true` iff >=1 such
# runner is online, so the pinned job skips fast (fail-closed) instead of
# queueing forever against an offline Big Tam. The compiler-agnostic
# proto-compat job stays on the broader linux_pool gate.
BIGTAM_POOL_LABELS = frozenset({"self-hosted", "Linux", "X64", "yuzu-bigtam-linux"})

# The Wee Tam Windows pool. Both ci.yml and nightly.yml pin this exact label;
# Shulgi remains useful as an operator testbed but cannot satisfy those jobs.
WEETAM_POOL_LABELS = frozenset(
    {"self-hosted", "Windows", "X64", "yuzu-weetam-windows"}
)

# The BigMags macOS pool. ci.yml's `macos` job pins
# runs-on: [self-hosted, macOS, ARM64, yuzu-bigmags-macos] because its
# Apple-Silicon toolchain exists only on the BigMags Mac Minis; no
# GitHub-hosted or Shulgi fallback can satisfy it. preflight emits
# `bigmags_pool_healthy=true` iff >=1 such runner is online, so the pinned
# job skips fast (fail-closed) instead of queueing forever against an
# offline pool.
BIGMAGS_POOL_LABELS = frozenset(
    {"self-hosted", "macOS", "ARM64", "yuzu-bigmags-macos"}
)


class QueryState(str, Enum):
    """Trust state of the runner-control interface."""

    OK = "ok"
    AUTH_ERROR = "auth_error"
    RATE_LIMIT = "rate_limit"
    API_ERROR = "api_error"
    MALFORMED_RESPONSE = "malformed_response"
    CONFIG_ERROR = "config_error"


@dataclass(frozen=True)
class QueryResult:
    state: QueryState
    payload: dict[str, Any] | None = None
    report: str = ""


def linux_pool_members(expected: dict[str, Any]) -> list[str]:
    """Declared runners eligible for the [self-hosted, Linux, X64] job pool."""
    return [
        name for name, exp in expected.items()
        if LINUX_POOL_LABELS.issubset(set(exp["labels"]))
    ]


def bigtam_pool_members(expected: dict[str, Any]) -> list[str]:
    """Declared runners eligible for the Big Tam (yuzu-bigtam-linux) job pool."""
    return [
        name for name, exp in expected.items()
        if BIGTAM_POOL_LABELS.issubset(set(exp["labels"]))
    ]


def weetam_pool_members(expected: dict[str, Any]) -> list[str]:
    """Declared runners eligible for the Wee Tam Windows job pool."""
    return [
        name for name, exp in expected.items()
        if WEETAM_POOL_LABELS.issubset(set(exp["labels"]))
    ]


def bigmags_pool_members(expected: dict[str, Any]) -> list[str]:
    """Declared runners eligible for the BigMags macOS job pool."""
    return [
        name for name, exp in expected.items()
        if BIGMAGS_POOL_LABELS.issubset(set(exp["labels"]))
    ]


def slug(name: str) -> str:
    """Convert a runner name to a GitHub-Actions-output-safe slug.

    e.g. "yuzu-wsl2-linux" -> "yuzu_wsl2_linux"
    The leading char must be a letter (GHA constraint).
    """
    s = re.sub(r"[^a-zA-Z0-9]+", "_", name).strip("_")
    if not s:
        return "runner"
    if not s[0].isalpha():
        s = "r_" + s
    return s


def write_output(key: str, value: str) -> None:
    """Append key=value to $GITHUB_OUTPUT (no-op outside Actions)."""
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a", encoding="utf-8") as f:
        # Use a fresh delimiter so API-provided text cannot terminate a
        # multi-line output and inject a sibling output.
        if "\n" in value:
            delimiter = f"YUZU_{uuid.uuid4().hex}"
            f.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")
        else:
            f.write(f"{key}={value}\n")


def _classify_query_error(stderr: str) -> QueryState:
    """Classify gh failures without treating every HTTP 403 as authentication."""
    text = stderr.lower()
    if any(marker in text for marker in (
        "rate limit", "secondary rate", "abuse detection",
    )):
        return QueryState.RATE_LIMIT
    if any(marker in text for marker in (
        "http 401", "status 401", "bad credentials",
        "resource not accessible", "must have admin",
        "requires authentication", "http 403: forbidden",
    )):
        return QueryState.AUTH_ERROR
    return QueryState.API_ERROR


def _print_auth_instructions(stderr: str) -> None:
    print("::error::Runner health check needs a PAT.")
    print()
    print("The default GITHUB_TOKEN cannot list /actions/runners — that endpoint")
    print("requires admin access to the repository, which is not grantable via")
    print("workflow permissions (no `administration` key at workflow scope).")
    print()
    print("To enable, create a PAT and store it as a repo secret:")
    print("  1. github.com → Settings → Developer settings → Personal access tokens")
    print("     → Fine-grained tokens → Generate new token")
    print("  2. Repository access = DevNullLtd/Yuzu only")
    print("  3. Permissions: 'Administration' = Read-only")
    print("  4. gh secret set RUNNER_INVENTORY_TOKEN --body <token>")
    print()
    print("Raw error from gh api:")
    print(stderr)


def _validate_payload(payload: object) -> QueryResult:
    if not isinstance(payload, dict) or not isinstance(payload.get("runners"), list):
        return QueryResult(
            QueryState.MALFORMED_RESPONSE,
            report="Runner-control response did not contain a runners list",
        )
    names: set[str] = set()
    for index, runner in enumerate(payload["runners"]):
        if not isinstance(runner, dict):
            return QueryResult(
                QueryState.MALFORMED_RESPONSE,
                report=f"Runner-control response entry {index} was not an object",
            )
        name = runner.get("name")
        status = runner.get("status")
        busy = runner.get("busy")
        labels = runner.get("labels")
        if (not isinstance(name, str) or not name
                or not isinstance(status, str) or not status
                or not isinstance(busy, bool)
                or not isinstance(labels, list)
                or any(not isinstance(label, dict)
                       or not isinstance(label.get("name"), str)
                       or not label["name"] for label in labels)):
            return QueryResult(
                QueryState.MALFORMED_RESPONSE,
                report=f"Runner-control response entry {index} lacked correctly typed fields",
            )
        if name in names:
            return QueryResult(
                QueryState.MALFORMED_RESPONSE,
                report=f"Runner-control response contained duplicate runner name {name!r}",
            )
        names.add(name)
    return QueryResult(QueryState.OK, payload=payload)


def query_runners() -> QueryResult:
    """Return a typed runner-control result with bounded transient retries."""
    state = QueryState.API_ERROR
    report = "Runner-control query failed"
    for attempt in range(MAX_QUERY_ATTEMPTS):
        try:
            result = subprocess.run(
                ["gh", "api", "/repos/DevNullLtd/Yuzu/actions/runners"],
                capture_output=True,
                text=True,
                check=False,
                timeout=QUERY_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            state = QueryState.API_ERROR
            report = f"Runner-control query timed out after {QUERY_TIMEOUT_SECONDS}s"
        except OSError as exc:
            state = QueryState.API_ERROR
            report = f"Runner-control query could not start: {exc}"
        else:
            if result.returncode != 0:
                stderr = result.stderr.strip()
                state = _classify_query_error(stderr)
                if state is QueryState.AUTH_ERROR:
                    _print_auth_instructions(stderr)
                    return QueryResult(
                        state,
                        report="Runner-control authentication failed: "
                        + (stderr or "no error text"),
                    )
                if state is QueryState.RATE_LIMIT:
                    return QueryResult(
                        state,
                        report="Runner-control API rate limit reached: "
                        + (stderr or "no error text"),
                    )
                report = "Runner-control query failed: " + (stderr or "no error text")
            else:
                try:
                    payload = json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    return QueryResult(
                        QueryState.MALFORMED_RESPONSE,
                        report=f"Runner-control response was not valid JSON: {exc}",
                    )
                return _validate_payload(payload)

        if attempt + 1 < MAX_QUERY_ATTEMPTS:
            time.sleep(RETRY_DELAYS_SECONDS[attempt])

    return QueryResult(state, report=report)


def is_healthy(actual: dict[str, Any] | None, expected_labels: list[str]) -> bool:
    """A runner is healthy iff registered, online, and all expected labels present."""
    if not actual:
        return False
    if actual["status"] != "online":
        return False
    return set(expected_labels).issubset(set(actual["labels"]))


def is_fork_pr() -> bool:
    """Return whether this is an automatic pull request from another repo."""
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        return False
    base = os.environ.get("GITHUB_REPOSITORY", "")
    head = os.environ.get("GITHUB_HEAD_REPOSITORY", "")
    return bool(base and head and base != head)


def write_control_failure(expected: dict[str, Any], result: QueryResult) -> None:
    """Emit a complete, typed unhealthy result for every consumer."""
    for name in expected:
        write_output(f"{slug(name)}_healthy", "false")
    for pool in ("linux", "bigtam", "weetam", "bigmags"):
        write_output(f"{pool}_pool_healthy", "false")
    write_output("all_healthy", "false")
    write_output("control_state", result.state.value)
    write_output("failure_kind", "runner_control_error")
    write_output("failure_count", "1")
    write_output("failure_report", result.report)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--mode",
        choices=("sentinel", "preflight"),
        default="sentinel",
        help="sentinel: loud failure on drift (issue-opening). "
             "preflight: per-runner health booleans and required-pool verdict.",
    )
    parser.add_argument(
        "--require-pool",
        action="append",
        choices=("linux", "bigtam", "weetam", "bigmags"),
        default=[],
        help="In preflight mode, fail when this pool has no healthy member. Repeatable.",
    )
    args = parser.parse_args(argv)

    try:
        with open(INVENTORY_PATH, encoding="utf-8") as f:
            inventory = json.load(f)
        runners = inventory["expected_runners"]
        if not isinstance(runners, list):
            raise TypeError("expected_runners is not a list")
        expected = {r["name"]: r for r in runners}
        if len(expected) != len(runners):
            raise ValueError("expected_runners contains duplicate names")
        for name, runner in expected.items():
            if (not isinstance(name, str) or not name
                    or not isinstance(runner.get("labels"), list)
                    or any(not isinstance(label, str) or not label
                           for label in runner["labels"])):
                raise TypeError("expected_runners contains an invalid name or labels list")
        strict = inventory.get("strict_unknown_runners", True)
        if not isinstance(strict, bool):
            raise TypeError("strict_unknown_runners is not a boolean")
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        result = QueryResult(
            QueryState.CONFIG_ERROR,
            report=f"Runner inventory cannot be trusted: {exc}",
        )
        write_control_failure({}, result)
        print(f"::error::{result.report}")
        return 1

    if args.mode == "preflight" and is_fork_pr():
        result = QueryResult(
            QueryState.AUTH_ERROR,
            report=("Automatic fork PR preflight is not trusted; use the "
                    "maintainer-dispatched trusted fork workflow."),
        )
        write_control_failure(expected, result)
        print(f"::error::{result.report}")
        return 1

    result = query_runners()
    if result.state is not QueryState.OK:
        write_control_failure(expected, result)
        print(f"::error::{result.report}")
        return 1
    assert result.payload is not None
    payload = result.payload

    actual = {
        r["name"]: {
            "name": r["name"],
            "labels": sorted(label_obj["name"] for label_obj in r["labels"]),
            "status": r["status"],
            "busy": r["busy"],
        }
        for r in payload["runners"]
    }

    print("=== Expected (.github/runner-inventory.json) ===")
    print(json.dumps(list(expected.values()), indent=2))
    print()
    print("=== Actual (GitHub /actions/runners) ===")
    print(json.dumps(list(actual.values()), indent=2))
    print()

    drift: list[str] = []
    healthy_map: dict[str, bool] = {}

    for name, exp in expected.items():
        act = actual.get(name)
        ok = is_healthy(act, exp["labels"])
        healthy_map[name] = ok
        if act is None:
            drift.append(f"MISSING: expected runner '{name}' not registered with GitHub")
            continue
        if act["status"] != "online":
            drift.append(f"OFFLINE: runner '{name}' reports status '{act['status']}'")
        missing_labels = set(exp["labels"]) - set(act["labels"])
        if missing_labels:
            drift.append(
                f"MISSING_LABEL: runner '{name}' missing expected labels {sorted(missing_labels)} "
                f"(actual: {sorted(act['labels'])})"
            )

    if strict:
        for name in actual:
            if name not in expected:
                drift.append(
                    f"UNKNOWN: unexpected runner '{name}' is registered "
                    f"but not declared in {INVENTORY_PATH} — either deregister it "
                    f"or add it to the inventory in a PR"
                )

    if args.mode == "preflight":
        # Emit one boolean per declared runner. Downstream jobs use
        # `if: needs.preflight.outputs.<slug>_healthy == 'true'`.
        all_healthy = True
        for name in expected:
            v = "true" if healthy_map.get(name, False) else "false"
            write_output(f"{slug(name)}_healthy", v)
            if v != "true":
                all_healthy = False
        # Pool gate: the [self-hosted, Linux, X64] job pool is healthy iff >=1
        # eligible runner is online (fail-closed). proto-compat + linux gate on
        # this instead of a single named runner.
        pool_members = {
            "linux": linux_pool_members(expected),
            "bigtam": bigtam_pool_members(expected),
            "weetam": weetam_pool_members(expected),
            "bigmags": bigmags_pool_members(expected),
        }
        pool_health = {
            pool_name: any(healthy_map.get(name, False) for name in members)
            for pool_name, members in pool_members.items()
        }
        write_output("linux_pool_healthy", "true" if pool_health["linux"] else "false")
        # Big Tam sub-pool gate for the gcc-15/clang-21 compile job (26.04-only).
        write_output("bigtam_pool_healthy", "true" if pool_health["bigtam"] else "false")
        write_output("weetam_pool_healthy", "true" if pool_health["weetam"] else "false")
        # BigMags macOS pool gate for the Apple-Silicon macos job.
        write_output("bigmags_pool_healthy", "true" if pool_health["bigmags"] else "false")
        write_output("all_healthy", "true" if all_healthy else "false")
        write_output("control_state", QueryState.OK.value)
        if drift:
            print("=== HEALTH ISSUES (preflight mode — non-fatal) ===")
            for d in drift:
                print(f"  - {d}")
        else:
            print("=== ALL RUNNERS HEALTHY ===")
        unavailable = [pool for pool in args.require_pool if not pool_health[pool]]
        if unavailable:
            report = "Required runner pool unavailable: " + ", ".join(unavailable)
            write_output("failure_kind", "required_pool_unavailable")
            write_output("failure_count", str(len(unavailable)))
            write_output("failure_report", report)
            print(f"::error::{report}")
            return 1
        return 0

    # sentinel mode: loud failure on drift, write report to $GITHUB_OUTPUT
    if drift:
        print("=== DRIFT DETECTED ===")
        for d in drift:
            print(f"  - {d}")
        report = "\n".join(f"- {d}" for d in drift)
        write_output("control_state", QueryState.OK.value)
        write_output("failure_kind", "inventory_drift")
        write_output("failure_count", str(len(drift)))
        write_output("failure_report", report)
        return 1

    print("=== RUNNER INVENTORY OK ===")
    write_output("control_state", QueryState.OK.value)
    return 0


if __name__ == "__main__":
    sys.exit(main())
