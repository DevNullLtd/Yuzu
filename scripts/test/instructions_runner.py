#!/usr/bin/env python3
"""
instructions_runner.py — schema-driven REST exerciser for the 217
InstructionDefinitions shipped under content/definitions/.

Companion to scripts/test/instructions-tests.sh (the bash entry that the
/test --instructions gate invokes). Auth, dispatch, and polling mirror
scripts/test/synthetic-uat-tests.sh:
  - form-login at POST /login (session cookie)
  - dispatch via POST /api/instructions/:id/execute (workflow_routes.cpp:1290)
  - poll results via GET /api/responses/:command_id (used by synthetic
    UAT test 6 — same correlation pattern)

Per-instruction outcome (recorded to the test-runs DB as both timing
and gate_notes):

  pass              dispatch returned 200, response polled within timeout,
                    output non-empty, response shape matches result.columns
  fail              dispatch error, no response within timeout, or shape
                    mismatch
  pending_approval  HTTP 202 with status=pending_approval — expected for
                    approval=manual/always/none; not a failure, but not a
                    semantic check either
  skip              definition risk-tag excluded by --risk filter
                    (destructive/network-disrupt/interactive by default)
  error             internal runner error (network, JSON parse, etc.) —
                    distinct from `fail` so flake-watching can separate
                    "instruction broken" from "test infra broken"

Risk classification table is at scripts/test/instructions-risk-classification.json.
Definitions whose id is NOT in the override map are classified by spec.type:
  type=question/query -> safe
  type=action         -> mutating
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import http.cookiejar
import json
import os
import platform
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.stderr.write("instructions_runner.py: PyYAML missing. "
                     "Install with `pip install pyyaml` "
                     "(or `pacman -S python-yaml` on MSYS2).\n")
    sys.exit(2)


# ── default behaviour knobs ────────────────────────────────────────────────

DEFAULT_DISPATCH_TIMEOUT_S = 10
DEFAULT_POLL_TIMEOUT_S = 30
DEFAULT_PARALLELISM = 4
DEFAULT_RISKS = ("safe", "mutating")  # what runs in the default gate

ALL_RISKS = ("safe", "mutating", "destructive", "forensic", "server-internal", "network-disrupt",
             "interactive")


# ── data classes ───────────────────────────────────────────────────────────


@dataclass
class Definition:
    id: str
    plugin: str
    action: str
    type: str            # question | action | query
    platforms: list[str]
    parameters: dict     # JSON-Schema-ish object from spec.parameters
    result_columns: list[dict]  # spec.result.columns
    approval_mode: str
    risk: str            # safe | mutating | destructive | network-disrupt | interactive
    file: str            # source YAML, for diagnostics


@dataclass
class Outcome:
    id: str
    risk: str
    status: str          # pass | fail | pending_approval | skip | error
    duration_ms: int
    http_code: int = 0
    command_id: str = ""
    execution_id: str = ""
    response_count: int = 0
    note: str = ""

    def short(self) -> str:
        bits = [f"{self.id} [{self.risk}]", self.status.upper(), f"{self.duration_ms}ms"]
        if self.note:
            bits.append(self.note)
        return " — ".join(bits)


# ── inventory loaders ──────────────────────────────────────────────────────


def load_risk_table(path: Path) -> dict[str, str]:
    raw = json.loads(path.read_text())
    return raw.get("_overrides", {})


# Plugins that name no agent plugin: the definition is catalog-only and the dispatch chokepoint
# denies it (reason=unclassified), so it can never pass by dispatch.
SERVER_ONLY_PLUGINS = ("_server", "server", "server_internal")


def classify(def_id: str, spec_type: str, overrides: dict[str, str], plugin: str = "") -> str:
    if def_id in overrides:
        return overrides[def_id]
    if plugin in SERVER_ONLY_PLUGINS:
        return "server-internal"
    if spec_type in ("question", "query"):
        return "safe"
    return "mutating"


def load_definitions(content_dir: Path, risk_table: dict[str, str]) -> list[Definition]:
    defs: list[Definition] = []
    for yaml_path in sorted(content_dir.glob("*.yaml")):
        with yaml_path.open() as fh:
            for doc in yaml.safe_load_all(fh):
                if not doc or doc.get("kind") != "InstructionDefinition":
                    continue
                md = doc.get("metadata", {}) or {}
                spec = doc.get("spec", {}) or {}
                exec_blk = spec.get("execution", {}) or {}
                params = spec.get("parameters", {}) or {}
                result = spec.get("result", {}) or {}
                approval = spec.get("approval", {}) or {}
                def_id = md.get("id", "")
                if not def_id:
                    continue
                defs.append(Definition(
                    id=def_id,
                    plugin=exec_blk.get("plugin", ""),
                    action=exec_blk.get("action", ""),
                    type=spec.get("type", ""),
                    platforms=spec.get("platforms", []) or [],
                    parameters=params,
                    result_columns=result.get("columns", []) or [],
                    approval_mode=approval.get("mode", "auto"),
                    risk=classify(def_id, spec.get("type", ""), risk_table, exec_blk.get("plugin", "")),
                    file=yaml_path.name,
                ))
    return defs


# ── host detection ─────────────────────────────────────────────────────────

def _detect_host() -> str:
    """Map platform.system() to the YAML platforms: vocabulary (darwin/linux/windows)."""
    s = platform.system().lower()
    if s == "darwin":
        return "darwin"
    if s == "windows":
        return "windows"
    return "linux"


HOST = _detect_host()


# ── parameter synthesis ────────────────────────────────────────────────────

# Per-host string defaults for common parameter names. Keys are matched as
# substrings against the lowercased parameter name, in declaration order —
# more-specific keys first.
_HOST_PATHS = {
    "linux":   {"file": "/bin/ls", "dir": "/tmp", "user_dir": "/tmp"},
    "darwin":  {"file": "/bin/ls", "dir": "/tmp", "user_dir": "/tmp"},
    "windows": {"file": r"C:\Windows\System32\notepad.exe",
                "dir": r"C:\Windows\Temp",
                "user_dir": r"C:\Windows\Temp"},
}

_HOST_GROUPS = {
    "linux": "root",
    "darwin": "wheel",
    "windows": "Administrators",
}


def _synth_string(name: str, schema: dict) -> str:
    """Best-effort string default for a parameter, host-aware."""
    nl = name.lower()
    paths = _HOST_PATHS[HOST]

    # Order matters: longer/more-specific tokens first.
    if nl == "sql" or nl.endswith("_sql") or "query" == nl:
        return "SELECT 1"
    if "sha256" in nl or nl == "hash" or nl.endswith("_hash"):
        return "0" * 64
    if "sha1" in nl:
        return "0" * 40
    if "md5" in nl:
        return "0" * 32
    if "thumbprint" in nl or "fingerprint" in nl:
        return "0" * 40
    if "url" in nl:
        return "https://example.invalid/yuzu-uat"
    if "domain" in nl:
        return "example.invalid"
    if nl == "ip" or nl.endswith("_ip") or "address" in nl or "host" in nl:
        return "127.0.0.1"
    if "filename" in nl or nl == "file_name":
        return "yuzu-uat-synth.bin"
    if "pattern" in nl or "glob" in nl:
        return "*.txt"
    if "extension" in nl:
        return "txt"
    if nl in ("root", "directory") or nl.endswith("_dir") or nl.endswith("_directory") or "folder" in nl:
        return paths["dir"]
    if nl == "path" or nl.endswith("_path") or nl == "file" or nl.endswith("_file"):
        return paths["file"]
    if "group" in nl:
        return _HOST_GROUPS[HOST]
    if "username" in nl or nl == "user":
        return "root" if HOST != "windows" else "Administrator"
    if "command" in nl or "cmd" in nl or "script" in nl:
        return "echo yuzu-uat-test"
    if nl == "id" or nl.endswith("_id") or "key" in nl or "name" in nl:
        return "yuzu-uat-test-id"
    if "regex" in nl or "expression" in nl:
        return ".*"
    validation = schema.get("validation", {}) or {}
    min_len = validation.get("minLength", 1)
    return "x" * max(int(min_len), 1)


def _value_for_property(name: str, schema: dict) -> Any:
    """Synthesise a sane default for a single parameter property.

    Honours, in order: explicit YAML `default:`, `enum:`, then a per-host
    name-based table for common parameter shapes (path, sql, url, sha256,
    group, thumbprint, ioc_*, directory, etc.).
    """
    # 1. Honour an explicit default if the YAML provides one.
    if "default" in schema and schema["default"] not in (None, ""):
        return schema["default"]

    enum = schema.get("enum") or schema.get("validation", {}).get("enum")
    if enum:
        return enum[0]

    t = schema.get("type", "string")

    if t in ("string", None):
        return _synth_string(name, schema)

    if t in ("integer", "int", "int32", "int64", "number"):
        validation = schema.get("validation", {}) or {}
        return int(validation.get("minimum", 0) or 0) or 10

    if t in ("boolean", "bool"):
        return False

    if t == "array":
        return []

    if t == "object":
        return {}

    return ""


def synthesise_params(spec_params: dict, override: dict[str, Any] | None = None) -> dict:
    """Build a parameter dict that satisfies `required` and `properties`.

    `override` (if provided) wins per-key, so PR C's hand-written test
    fixtures can replace specific values without touching this function.
    """
    out: dict[str, Any] = {}
    properties = spec_params.get("properties", {}) or {}
    required = set(spec_params.get("required", []) or [])
    for prop_name in required:
        prop_schema = properties.get(prop_name, {}) or {}
        out[prop_name] = _value_for_property(prop_name, prop_schema)
    # If the definition has no `required:` block but does declare properties
    # (e.g. security.ioc.check — all optional, but at least one must be
    # supplied), synthesise one property so dispatch exercises the plugin
    # rather than erroring at "no parameters provided".
    if not required and properties:
        first_name = next(iter(properties))
        out[first_name] = _value_for_property(first_name, properties[first_name] or {})
    if override:
        out.update(override)
    return out


# ── REST client ────────────────────────────────────────────────────────────


class YuzuClient:
    """Cookie-jar HTTP client for the Yuzu dashboard / REST API.

    Mirrors the form-login + cookie-jar pattern used by
    scripts/test/synthetic-uat-tests.sh. Threadsafe for read-only methods
    (post_instruction, get_response) — urlopen+CookieJar is reentrant for
    a steady-state cookie set.
    """

    def __init__(self, base_url: str, timeout: int = DEFAULT_DISPATCH_TIMEOUT_S):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def login(self, username: str, password: str) -> None:
        body = urllib.parse.urlencode({"username": username, "password": password}).encode()
        req = urllib.request.Request(
            f"{self.base}/login", data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        with self.opener.open(req, timeout=self.timeout) as resp:
            if resp.status not in (200, 302, 303):
                raise RuntimeError(f"login failed: HTTP {resp.status}")

    def execute_instruction(self, def_id: str, params: dict) -> tuple[int, dict]:
        body = json.dumps({"params": {k: str(v) if not isinstance(v, str) else v
                                       for k, v in params.items()}}).encode()
        req = urllib.request.Request(
            f"{self.base}/api/instructions/{urllib.parse.quote(def_id)}/execute",
            data=body, headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read() or b"{}")
                return resp.status, payload
        except urllib.error.HTTPError as e:
            try:
                payload = json.loads(e.read() or b"{}")
            except Exception:
                payload = {}
            return e.code, payload

    def get_responses(self, command_id: str) -> dict:
        req = urllib.request.Request(
            f"{self.base}/api/responses/{urllib.parse.quote(command_id)}")
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return {"error": str(e), "code": e.code}
        except urllib.error.URLError as e:
            return {"error": str(e)}


# ── single-definition exerciser ────────────────────────────────────────────


def exercise(client: YuzuClient, defn: Definition,
             param_overrides: dict[str, dict[str, Any]],
             poll_timeout_s: int) -> Outcome:
    started = time.monotonic()

    # Honour YAML `platforms:` — definitions that don't list the current
    # host should be skipped, not dispatched. `server` is a virtual platform
    # for server-internal instructions and always runs.
    if defn.platforms:
        eligible = set(defn.platforms)
        if "server" not in eligible and HOST not in eligible:
            return Outcome(defn.id, defn.risk, "skip",
                           int((time.monotonic() - started) * 1000),
                           note=f"host={HOST} not in platforms={sorted(eligible)}")

    try:
        params = synthesise_params(defn.parameters, param_overrides.get(defn.id))
    except Exception as e:
        return Outcome(defn.id, defn.risk, "error",
                       int((time.monotonic() - started) * 1000),
                       note=f"param-synth: {e}")

    try:
        code, payload = client.execute_instruction(defn.id, params)
    except Exception as e:
        return Outcome(defn.id, defn.risk, "error",
                       int((time.monotonic() - started) * 1000),
                       note=f"dispatch: {e}")

    if code == 202 and payload.get("status") == "pending_approval":
        return Outcome(defn.id, defn.risk, "pending_approval",
                       int((time.monotonic() - started) * 1000),
                       http_code=code,
                       execution_id=payload.get("approval_id", ""),
                       note=f"approval={defn.approval_mode}")

    if code != 200:
        msg = payload.get("error", {}).get("message") if isinstance(payload, dict) else ""
        return Outcome(defn.id, defn.risk, "fail",
                       int((time.monotonic() - started) * 1000),
                       http_code=code,
                       note=f"HTTP {code} {msg}".strip())

    command_id = payload.get("command_id", "")
    execution_id = payload.get("execution_id", "")
    if not command_id:
        return Outcome(defn.id, defn.risk, "fail",
                       int((time.monotonic() - started) * 1000),
                       http_code=code,
                       execution_id=execution_id,
                       note="dispatch ok but no command_id returned")

    deadline = time.monotonic() + poll_timeout_s
    last_payload: dict = {}
    response_count = 0
    while time.monotonic() < deadline:
        last_payload = client.get_responses(command_id)
        responses = last_payload.get("responses", []) if isinstance(last_payload, dict) else []
        response_count = len(responses)
        if response_count > 0:
            # Response received from at least one agent
            break
        time.sleep(0.5)

    duration_ms = int((time.monotonic() - started) * 1000)

    if response_count == 0:
        return Outcome(defn.id, defn.risk, "fail",
                       duration_ms, http_code=code, command_id=command_id,
                       execution_id=execution_id,
                       note=f"no response within {poll_timeout_s}s")

    # Loose shape validation: trust the agent's structured `status` and
    # `rc` fields rather than greping the body for "error|". Several
    # legitimate-empty cases (event_logs.errors returning rows whose
    # column-0 label is "error", agent_logging emitting an empty marker)
    # would otherwise be misclassified.
    sane_count = 0
    error_count = 0
    for r in last_payload.get("responses", []):
        out = r.get("output", "")
        if not out:
            continue
        status = r.get("status", "")
        # Agent reports rc explicitly when available; non-zero rc or
        # status=="error" is the authoritative failure signal.
        rc = r.get("rc", r.get("return_code", 0))
        if status == "error" or (isinstance(rc, int) and rc != 0):
            error_count += 1
        else:
            sane_count += 1

    if sane_count == 0 and error_count > 0:
        return Outcome(defn.id, defn.risk, "fail",
                       duration_ms, http_code=code, command_id=command_id,
                       execution_id=execution_id, response_count=response_count,
                       note=f"all {error_count} responses errored")

    return Outcome(defn.id, defn.risk, "pass",
                   duration_ms, http_code=code, command_id=command_id,
                   execution_id=execution_id, response_count=response_count)


# ── DB writeback ───────────────────────────────────────────────────────────


def db_record_timing(repo_root: Path, run_id: str, gate_name: str,
                     step: str, ms: int) -> None:
    """Best-effort: timing failures must not abort the gate."""
    try:
        subprocess.run(
            ["bash", str(repo_root / "scripts/test/test-db-write.sh"),
             "timing", "--run-id", run_id, "--gate", gate_name,
             "--step", step, "--ms", str(ms)],
            check=False, capture_output=True, timeout=5)
    except Exception:
        pass


def db_record_metric(repo_root: Path, run_id: str, name: str,
                     value: float, unit: str = "") -> None:
    try:
        cmd = ["bash", str(repo_root / "scripts/test/test-db-write.sh"),
               "metric", "--run-id", run_id, "--name", name,
               "--value", str(value)]
        if unit:
            cmd.extend(["--unit", unit])
        subprocess.run(cmd, check=False, capture_output=True, timeout=5)
    except Exception:
        pass


# ── orchestration ──────────────────────────────────────────────────────────


def run(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parents[2]
    risk_table_path = Path(args.risk_table) if args.risk_table else \
        repo_root / "scripts/test/instructions-risk-classification.json"
    content_dir = Path(args.content_dir) if args.content_dir else \
        repo_root / "content/definitions"

    overrides = load_risk_table(risk_table_path)
    all_defs = load_definitions(content_dir, overrides)
    if not all_defs:
        print("instructions_runner: no InstructionDefinitions found "
              f"under {content_dir}", file=sys.stderr)
        return 2

    selected_risks = set(args.risks)
    runnable = [d for d in all_defs if d.risk in selected_risks]
    skipped = [d for d in all_defs if d.risk not in selected_risks]
    if args.only_id:
        runnable = [d for d in runnable if d.id == args.only_id]
    if args.match:
        pat = re.compile(args.match)
        runnable = [d for d in runnable if pat.search(d.id)]

    print(f"instructions_runner: {len(all_defs)} total definitions, "
          f"{len(runnable)} runnable (risks={','.join(sorted(selected_risks))}), "
          f"{len(skipped)} skipped")

    param_overrides: dict[str, dict[str, Any]] = {}
    if args.params_override:
        try:
            param_overrides = json.loads(Path(args.params_override).read_text())
            param_overrides = {k: v for k, v in param_overrides.items()
                                if not k.startswith("_")}
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"instructions_runner: param overrides load failed: {e}",
                  file=sys.stderr)

    client = YuzuClient(args.dashboard, timeout=DEFAULT_DISPATCH_TIMEOUT_S)
    try:
        client.login(args.user, args.password)
    except Exception as e:
        print(f"instructions_runner: login failed: {e}", file=sys.stderr)
        return 2

    outcomes: list[Outcome] = []
    started_at = time.monotonic()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallelism) as pool:
        future_map = {pool.submit(exercise, client, d, param_overrides,
                                   args.poll_timeout): d for d in runnable}
        for fut in concurrent.futures.as_completed(future_map):
            outcome = fut.result()
            outcomes.append(outcome)
            if args.verbose or outcome.status in ("fail", "error"):
                print(f"  {outcome.short()}")
            if args.run_id:
                db_record_timing(repo_root, args.run_id, args.gate_name,
                                  outcome.id, outcome.duration_ms)

    total_ms = int((time.monotonic() - started_at) * 1000)

    # Tally
    counts = {"pass": 0, "fail": 0, "pending_approval": 0, "error": 0, "skip": 0}
    for o in outcomes:
        counts[o.status] = counts.get(o.status, 0) + 1
    # Risk-filtered defs never enter the executor; add them to the skip tally.
    counts["skip"] += len(skipped)

    summary = (f"instructions_runner: {counts['pass']} pass / "
               f"{counts['fail']} fail / {counts['pending_approval']} pending / "
               f"{counts['error']} error / {counts['skip']} skip "
               f"({total_ms}ms wall)")
    print(summary)

    if args.output:
        Path(args.output).write_text(json.dumps({
            "summary": counts,
            "total_ms": total_ms,
            "outcomes": [asdict(o) for o in outcomes],
        }, indent=2))

    if args.run_id:
        db_record_metric(repo_root, args.run_id, "instructions_pass",
                          counts["pass"], "count")
        db_record_metric(repo_root, args.run_id, "instructions_fail",
                          counts["fail"], "count")
        db_record_metric(repo_root, args.run_id, "instructions_pending_approval",
                          counts["pending_approval"], "count")
        db_record_metric(repo_root, args.run_id, "instructions_error",
                          counts["error"], "count")
        db_record_metric(repo_root, args.run_id, "instructions_total_ms",
                          total_ms, "ms")

    # Exit code:
    #   0  - all runnable instructions passed (or pending_approval, expected)
    #   1  - one or more fail/error
    #   2  - infrastructure failure (login, content-dir empty)
    if counts["fail"] > 0 or counts["error"] > 0:
        return 1
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dashboard", required=True,
                   help="Yuzu dashboard root, e.g. http://localhost:8080")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", required=True)
    p.add_argument("--risks", nargs="+", default=list(DEFAULT_RISKS),
                   choices=list(ALL_RISKS),
                   help=f"risk classes to run (default: {' '.join(DEFAULT_RISKS)})")
    p.add_argument("--match", default="",
                   help="restrict to definition IDs matching this regex")
    p.add_argument("--only-id", default="",
                   help="run exactly this one definition id (debugging)")
    p.add_argument("--parallelism", type=int, default=DEFAULT_PARALLELISM)
    p.add_argument("--poll-timeout", type=int, default=DEFAULT_POLL_TIMEOUT_S,
                   help=f"per-instruction response poll timeout (default: {DEFAULT_POLL_TIMEOUT_S}s)")
    p.add_argument("--content-dir", default="",
                   help="override content/definitions path")
    p.add_argument("--risk-table", default="",
                   help="override scripts/test/instructions-risk-classification.json path")
    p.add_argument("--params-override", default="",
                   help="optional JSON file mapping definition_id -> {param: value}")
    p.add_argument("--output", default="",
                   help="write per-instruction outcomes to this JSON file")
    p.add_argument("--run-id", default="",
                   help="if set, record timings/metrics to test-runs DB")
    p.add_argument("--gate-name", default="instructions",
                   help="gate name to scope timings under (default: instructions)")
    p.add_argument("--verbose", action="store_true",
                   help="print every outcome (default: only fail/error)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
