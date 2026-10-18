#!/usr/bin/env python3
"""
instructions_runner.py — schema-driven REST exerciser for the
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

  pass              dispatch returned 200 and an agent answered within the timeout
                    (dispatched and answered; no check of the result shape). A
                    destructive/forensic row passes only when every response row
                    is terminal SUCCESS with an empty error_detail.
  fail              dispatch error, no response within timeout, or every
                    answer errored (a destructive/forensic row also fails on
                    any errored answer, any error_detail, or a row still running
                    at the poll deadline)
  pending_approval  HTTP 202 with status=pending_approval — expected for
                    approval=always/auto/role-gated; not a failure, but nothing
                    ran and not a semantic check either
  skip              definition risk-tag excluded by the --risks filter
                    (everything but safe and mutating by default), or a
                    destructive/forensic definition the targeted run may not
                    dispatch (no override entry, required parameter missing,
                    server.* row, not eligible on the target's OS)
  error             internal runner error (network, JSON parse, etc.) —
                    distinct from `fail` so flake-watching can separate
                    "instruction broken" from "test infra broken"

Risk classification table is at scripts/test/instructions-risk-classification.json.
Definitions whose id is NOT in the override map are classified by plugin, then spec.type:
  plugin=_server/server/server_internal -> server-internal (catalog-only; the
                                           dispatch chokepoint denies them)
  type=question/query                   -> safe
  type=action                           -> mutating

The runner broadcasts: it sends no agent_ids and no scope. The exception is the opt-in classes
destructive and forensic (a Destructive or Forensics capability row). The server refuses a
broadcast for those and wants an explicit, in-scope agent id (exactly one for Forensics), so a
run that selects either class with --risks is a targeted run and needs all of:

  --target-agent-id ID     the one connected agent; sent as `agent_ids: [ID]` with those classes
                           only (every other dispatch has the same request body as before)
  --confirm-target HOST    that agent's hostname; checked against GET /api/agents before anything
                           is sent, together with the agent being listed (connected)
  --run-id ID              names the manifest and the User-Agent
  --params-override FILE   the params to send: a destructive/forensic definition is dispatched
                           only with its own entry here, used exactly as written and covering
                           every required parameter; every other one is skipped, never guessed
  loopback --dashboard     127.0.0.1, ::1 or localhost, else --allow-remote

Anything missing is a configuration error: exit 2, nothing dispatched. These instructions change
or read a real device, so a targeted run is serial, appends each dispatch to a manifest before
sending it, and polls each targeted row until every response row is terminal or the poll deadline
passes (--poll-timeout, at least 120 s for these classes unless given explicitly). It passes a row
only if every response row is SUCCESS with no error_detail; a row still running at the deadline
fails the run and stops further dispatch, so a following action never overlaps it. Ctrl-C and
SIGTERM stop dispatching (exit 130); a dispatch already sent is reported as in_flight_unknown, and
a transport failure after a POST was sent as dispatch_unknown (the run stops). Three consecutive
401/403 answers to execute, or to a targeted poll (503 too), stop the run.

Exit codes: 0 all passed; 1 a failure or error, an early stop, or a targeted run in which nothing
was executed (every row skipped or pending approval); 2 configuration/login/pre-flight error with
nothing dispatched; 130 interrupted. The manifest is an attempt log, not outcome evidence: its
first line is run-start, then one line per dispatch holding the exact params sent (treat it as
sensitive; it is created 0600 and only at creation).

--confirm-target is a wrong-target typo guard against what the connected server reports. It cannot
detect an ssh -L tunnel or a port forward to a different stack, and it is not an authorisation or
approval control; use a dedicated admin account on a disposable stack. A server-internal
definition is never sent a target: it names no agent plugin, so if selected it is broadcast and the
dispatch chokepoint denies it. A server.* row that the risk table classes destructive is skipped in
a targeted run for the same reason, as is testing.chargen.start (it streams until stopped).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import datetime
import errno
import http.client
import http.cookiejar
import json
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
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
# A destructive/forensic row is polled for longer unless --poll-timeout is given explicitly:
# a row still running at the deadline stops the run, so the default has to cover a slow action.
TARGETED_POLL_TIMEOUT_S = 120
DEFAULT_PARALLELISM = 4
DEFAULT_RISKS = ("safe", "mutating")  # what runs in the default gate

# Risk classes whose rows the server refuses to broadcast: dispatched to --target-agent-id.
TARGETED_RISKS = ("destructive", "forensic")
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")  # used with fullmatch

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
    risk: str            # one of ALL_RISKS
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
    dispatched: bool = False   # the server accepted the execute POST (HTTP 200), or it was sent
                               # and the run ended before the result came back
    dispatch_unknown: bool = False  # a targeted POST failed after it may have been sent

    def __post_init__(self) -> None:
        self.note = esc(self.note)  # a name or message from the server or an agent (CWE-117)

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
# denies it (reason=unclassified or forbidden), so it can never pass by dispatch.
SERVER_ONLY_PLUGINS = ("_server", "server", "server_internal")


def classify(def_id: str, spec_type: str, overrides: dict[str, str], plugin: str) -> str:
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


# Values tried, in order, when the name-based string default fails the parameter's
# `validation.pattern`. The server rejects a value that does not match (HTTP 400), so
# without this the runner reports a false FAIL for every pattern-constrained string
# whose name the table above does not recognise.
_PATTERN_FALLBACKS = (
    "10",                                    # digits
    "info",                                  # log level
    "192.0.2.0/30",                          # CIDR; RFC 5737 TEST-NET-1, never routed
    "true",                                  # boolean string
    "00000000-0000-0000-0000-000000000000",  # UUID
    "00:00:00:00:00:00",                     # MAC
)


def _fit_pattern(value: str, schema: dict) -> str:
    """`value` if it satisfies the schema's `validation.pattern`, else the first fallback
    that does; `value` unchanged when there is no pattern or nothing matches (the server
    then reports the mismatch, which is the honest outcome). The server matches with RE2
    PartialMatch (an unanchored search, as `re.search` is); Python's `re` is not RE2, so a
    pattern it cannot compile is left to the server rather than raised here."""
    pattern = (schema.get("validation") or {}).get("pattern")
    if not pattern:
        return value
    try:
        rx = re.compile(pattern)
    except re.error:
        return value
    return next((c for c in (value, *_PATTERN_FALLBACKS) if rx.search(c)), value)


def _value_for_property(name: str, schema: dict) -> Any:
    """Synthesise a sane default for a single parameter property.

    Honours, in order: explicit YAML `default:`, `enum:`, then a per-host
    name-based table for common parameter shapes (path, sql, url, sha256,
    group, thumbprint, ioc_*, directory, etc.), then fits a string to its
    `validation.pattern` (`_fit_pattern`). A default or enum value is used as
    written and is never pattern-fitted.
    """
    # 1. Honour an explicit default if the YAML provides one.
    if "default" in schema and schema["default"] not in (None, ""):
        return schema["default"]

    enum = schema.get("enum") or schema.get("validation", {}).get("enum")
    if enum:
        return enum[0]

    t = schema.get("type", "string")

    if t in ("string", None):
        return _fit_pattern(_synth_string(name, schema), schema)

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

    `override` (if provided) wins per-key, so a hand-written --params-override entry
    can replace specific values without touching this function.
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


def esc(text: Any) -> str:
    """Make a string console- and log-safe: ASCII control characters and DEL as \\xNN, every other
    non-ASCII character (C1 controls, U+2028/9, bidi controls, U+FEFF, any letter) as \\uXXXX
    (\\UXXXXXXXX above the BMP), so a name or message the server or an agent reported can neither
    forge a log line nor drive a terminal (CWE-117), and printing never raises UnicodeEncodeError
    on a cp1252 pipe."""
    out = []
    for c in str(text):
        o = ord(c)
        if o < 0x20 or o == 0x7f:
            out.append(f"\\x{o:02x}")
        elif o < 0x7f:
            out.append(c)
        elif o <= 0xffff:
            out.append(f"\\u{o:04x}")
        else:
            out.append(f"\\U{o:08x}")
    return "".join(out)


def clip(text: Any, limit: int = 200) -> str:
    s = str(text)
    return s if len(s) <= limit else s[:limit] + "..."


def wire_params(params: dict) -> dict[str, str]:
    """The params as they go on the wire (every value a string); the manifest records the same."""
    return {k: str(v) if not isinstance(v, str) else v for k, v in params.items()}


class YuzuClient:
    """Cookie-jar HTTP client for the Yuzu dashboard / REST API.

    Mirrors the form-login + cookie-jar pattern used by
    scripts/test/synthetic-uat-tests.sh. Threadsafe for read-only methods
    (post_instruction, get_response) — urlopen+CookieJar is reentrant for
    a steady-state cookie set.
    """

    def __init__(self, base_url: str, timeout: int = DEFAULT_DISPATCH_TIMEOUT_S, run_id: str = ""):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        # ProxyHandler({}) first: urllib would otherwise honour http_proxy/ALL_PROXY and the
        # OS proxy settings, sending a "loopback" run (and its password) through a proxy.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.jar))
        self.opener.addheaders = [("User-Agent", f"yuzu-instructions-runner/{run_id}")]

    def login(self, username: str, password: str) -> None:
        body = urllib.parse.urlencode({"username": username, "password": password}).encode()
        req = urllib.request.Request(
            f"{self.base}/login", data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        with self.opener.open(req, timeout=self.timeout) as resp:
            if resp.status not in (200, 302, 303):
                raise RuntimeError(f"login failed: HTTP {resp.status}")

    def list_agents(self) -> list:
        """GET /api/agents: the connected agents, each {agent_id, hostname, os, arch, agent_version}."""
        with self.opener.open(urllib.request.Request(f"{self.base}/api/agents"),
                              timeout=self.timeout) as resp:
            payload = json.loads(resp.read() or b"[]")
        if not isinstance(payload, list):
            raise ValueError("unexpected /api/agents body")
        return payload

    def execute_instruction(self, def_id: str, params: dict,
                            agent_ids: list[str] | None = None) -> tuple[int, dict]:
        body_obj: dict[str, Any] = {"params": wire_params(params)}
        if agent_ids:
            body_obj["agent_ids"] = agent_ids
        body = json.dumps(body_obj).encode()
        req = urllib.request.Request(
            f"{self.base}/api/instructions/{urllib.parse.quote(def_id)}/execute",
            data=body, headers={"Content-Type": "application/json",
                                # A cookie-session write must carry a same-site
                                # Origin, as the dashboard's own fetch does.
                                "Origin": self.base})
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
        except Exception as e:  # URLError, TimeoutError, JSONDecodeError, OSError ...
            return {"error": f"{type(e).__name__}: {e}"}


class Manifest:
    """Append-only JSONL record of every destructive/forensic dispatch, written BEFORE the POST."""

    def __init__(self, path: Path, run_id: str):
        self.path = path
        self.run_id = run_id
        # Owner-only, never through a symlink where the platform can say so; "\n" on every OS.
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        self._fh = os.fdopen(os.open(path, flags, 0o600), "a", encoding="utf-8", newline="\n")
        self._lock = threading.Lock()

    @staticmethod
    def _now() -> str:
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _write(self, obj: dict) -> None:
        line = json.dumps(obj, sort_keys=True)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())

    def start(self, **fields: Any) -> None:
        """The first line: what this run was pointed at (no credentials)."""
        self._write({"event": "run-start", "ts": self._now(), "run_id": self.run_id, **fields})

    def record(self, defn: Definition, target: str, params: dict) -> None:
        self._write({"event": "dispatch", "ts": self._now(), "run_id": self.run_id,
                     "id": defn.id, "risk": defn.risk, "target_agent_id": target,
                     "params": wire_params(params)})

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass  # never mask the summary or exit 130


# ── single-definition exerciser ────────────────────────────────────────────

POLL_INTERVAL_S = 0.5
# Consecutive 401/403 answers to a targeted execute that end the run: the session is gone or
# the account lost its grant, and every remaining row would fail the same way.
AUTH_ABORT_AFTER = 3
# CommandResponse::Status as the server serialises it in GET /api/responses/{id} rows.
STATUS_NAMES = {0: "RUNNING", 1: "SUCCESS", 2: "FAILURE", 3: "TIMEOUT", 4: "REJECTED"}
# Legacy string spellings of a frame still in flight; the wire sends integer 0.
INTERIM_STATUSES = ("running", "pending", "queued", "in_progress", "started", "dispatched")


class RunControl:
    """State shared by the workers and run(): the stop flag, which dispatches were begun."""

    def __init__(self) -> None:
        self.stop = threading.Event()
        self.sent: set[str] = set()   # definition ids whose execute POST was begun
        self.abort_reason = ""
        self.skip_note = "aborted before dispatch"   # why the rows that never started were skipped
        self._auth_failures = 0
        self._poll_refusals = 0
        self._lock = threading.Lock()

    def request_stop(self, reason: str = "", skip_note: str = "") -> None:
        if reason and not self.abort_reason:
            self.abort_reason = reason
            if skip_note:
                self.skip_note = skip_note
        self.stop.set()

    def mark_sent(self, def_id: str) -> None:
        with self._lock:
            self.sent.add(def_id)

    def note_status(self, code: int) -> None:
        with self._lock:
            self._auth_failures = self._auth_failures + 1 if code in (401, 403) else 0
            tripped = self._auth_failures >= AUTH_ABORT_AFTER
        if tripped:
            self.request_stop(f"{AUTH_ABORT_AFTER} consecutive HTTP 401/403 answers to execute: "
                              "the session or the account's grant is gone; stopping",
                              "stopped: execute is being refused")

    def note_poll(self, refused: bool | None) -> bool:
        """Count a targeted poll: True refused (401/403/503), False answered, None neither
        (a transport failure leaves the count alone). Returns True when this one tripped the stop."""
        if refused is None:
            return False
        with self._lock:
            self._poll_refusals = self._poll_refusals + 1 if refused else 0
            tripped = self._poll_refusals >= AUTH_ABORT_AFTER
        if tripped:
            self.request_stop(f"{AUTH_ABORT_AFTER} consecutive targeted polls refused with HTTP "
                              "401/403/503: the responses cannot be read; stopping",
                              "stopped: responses cannot be read")
        return tripped


def error_message(payload: Any) -> str:
    """The A4 error body's message, prefixed by its reason/code token when it has one.

    Tolerates a string `error`, a missing one and a non-dict body. Control characters are escaped.
    """
    if not isinstance(payload, dict):
        return ""
    err = payload.get("error")
    tag = payload.get("reason")
    if isinstance(err, dict):
        # error.code is the numeric HTTP status in an A4 body; only a string one is a token.
        tag = next((t for t in (err.get("reason"), err.get("code"), tag) if isinstance(t, str)), None)
        err = err.get("message")
    msg = err if isinstance(err, str) else ""
    if not isinstance(tag, str) or not tag:
        return esc(msg)
    return esc(f"{tag}: {msg}" if msg else tag)


# Definitions a targeted run cannot supervise: it needs a terminal state to move on.
TARGETED_UNSUPPORTED = {
    "testing.chargen.start": "streams until stopped; run it by hand with testing.chargen.stop",
}


def targeted_skip_reason(defn: Definition, param_overrides: dict[str, dict[str, Any]],
                         target_os: str = "") -> str:
    """Why a destructive/forensic definition must not be dispatched, or "" if it may be.

    It runs only with an operator-written override (--params-override) that is present for its id
    (membership: `{}` is a real entry) and supplies every required parameter; the override is
    then the whole params object, with no synthesised sibling values.
    """
    if defn.plugin in SERVER_ONLY_PLUGINS:
        return "server-internal: never dispatched with a target"
    if defn.id in TARGETED_UNSUPPORTED:
        return f"unsupported in targeted runs: {TARGETED_UNSUPPORTED[defn.id]}"
    if target_os and defn.platforms:
        eligible = set(defn.platforms)
        if "server" not in eligible and target_os not in eligible:
            return f"target os={target_os} not in platforms={sorted(eligible)}"
    if defn.id not in param_overrides:
        return "no --params-override entry for this definition"
    missing = [p for p in (defn.parameters.get("required") or []) if p not in param_overrides[defn.id]]
    if missing:
        return f"--params-override entry lacks required parameters {sorted(missing)}"
    return ""


def _int_status(r: Any) -> int | None:
    s = r.get("status") if isinstance(r, dict) else None
    return s if isinstance(s, int) and not isinstance(s, bool) else None


def row_in_flight(r: Any) -> bool:
    """A response row that is still RUNNING (integer 0 on the wire; legacy strings too)."""
    if not isinstance(r, dict):
        return False
    s = r.get("status")
    if isinstance(s, str):
        return s.lower() in INTERIM_STATUSES
    return _int_status(r) == 0


def grade_targeted(responses: list) -> tuple[str, bool]:
    """(why it is a fail, "" if every row finished SUCCESS with no error_detail; any row running).

    The wire row is {id, instruction_id, agent_id, timestamp, status, output, error_detail} with
    an integer status; a legacy string status or `rc` can only add a failure, never a pass.
    """
    problems: list[str] = []
    running = False
    for r in responses:
        if not isinstance(r, dict):
            problems.append("a response row is not an object")
            continue
        if row_in_flight(r):
            running = True
            continue
        reasons: list[str] = []
        s = _int_status(r)
        if s is None:
            raw = r.get("status")
            reasons.append("error" if raw == "error" else f"unrecognised status {clip(raw, 40)!r}")
        elif s != 1:
            reasons.append(STATUS_NAMES.get(s, f"status={s}"))
        rc = r.get("rc", r.get("return_code", 0))
        if isinstance(rc, int) and not isinstance(rc, bool) and rc != 0:
            reasons.append(f"rc={rc}")
        detail = r.get("error_detail")
        if isinstance(detail, str) and detail.strip():
            reasons.append(f"error_detail={clip(detail)!r}")
        if reasons:
            problems.append(f"{clip(r.get('agent_id', '?'), 64)}: {', '.join(reasons)}")
    notes = problems[:3] + ([f"(+{len(problems) - 3} more)"] if len(problems) > 3 else [])
    return "; ".join(notes), running


def _may_have_been_sent(e: BaseException) -> bool:
    """Whether a failed targeted POST may have reached the server.

    Only a failure that provably happened before any byte left is "not sent": the connection was
    refused, the name did not resolve, or the network/host was unreachable. Everything else that
    comes from the transport (a timeout, a reset, a dropped connection, an unreadable or
    non-JSON body after the server answered) may have been executed, so it is reported as
    dispatch_unknown. A non-transport exception (a bug here) stays a plain error.
    """
    cause = getattr(e, "reason", e)
    if isinstance(cause, (ConnectionRefusedError, socket.gaierror)):
        return False
    if isinstance(cause, OSError) and cause.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH,
                                                      errno.EADDRNOTAVAIL):
        return False
    return isinstance(e, (OSError, http.client.HTTPException, ValueError))


def _dispatch_unknown(defn: Definition, control: RunControl, duration_ms: int, detail: str) -> Outcome:
    control.request_stop("a targeted dispatch may have reached the server but its outcome is "
                         "unknown (dispatch_unknown); stopping",
                         "stopped: previous dispatch outcome unknown")
    return Outcome(defn.id, defn.risk, "error", duration_ms, dispatch_unknown=True,
                   note="dispatch_unknown: the request may have reached the server and the action "
                        "may have run (see the manifest); do not re-run blindly [" + detail + "]")


def exercise(client: YuzuClient, defn: Definition,
             param_overrides: dict[str, dict[str, Any]],
             poll_timeout_s: int, target_agent_id: str = "", target_os: str = "",
             manifest: Manifest | None = None, control: RunControl | None = None,
             targeted_poll_timeout_s: int | None = None) -> Outcome:
    accepted = [False]
    out = _exercise(client, defn, param_overrides, poll_timeout_s, target_agent_id, target_os,
                    manifest, accepted, control or RunControl(), targeted_poll_timeout_s)
    out.dispatched = accepted[0]
    return out


def _exercise(client: YuzuClient, defn: Definition,
              param_overrides: dict[str, dict[str, Any]],
              poll_timeout_s: int, target_agent_id: str, target_os: str,
              manifest: Manifest | None, accepted: list[bool], control: RunControl,
              targeted_poll_timeout_s: int | None = None) -> Outcome:
    started = time.monotonic()
    targeted = defn.risk in TARGETED_RISKS
    if targeted and targeted_poll_timeout_s:
        poll_timeout_s = targeted_poll_timeout_s

    def ms() -> int:
        return int((time.monotonic() - started) * 1000)

    # Honour YAML `platforms:` — definitions that don't list the current
    # host should be skipped, not dispatched. `server` is a virtual platform
    # for server-internal instructions and always runs. A targeted definition runs on
    # the target agent, so it is judged against the target's OS (the runner's OS as a fallback).
    if targeted:
        why = ("no --target-agent-id" if not target_agent_id
               else targeted_skip_reason(defn, param_overrides, target_os or HOST))
        if why:
            return Outcome(defn.id, defn.risk, "skip", ms(), note=why)
    elif defn.platforms:
        eligible = set(defn.platforms)
        if "server" not in eligible and HOST not in eligible:
            return Outcome(defn.id, defn.risk, "skip", ms(),
                           note=f"host={HOST} not in platforms={sorted(eligible)}")

    try:
        params = (dict(param_overrides[defn.id]) if targeted
                  else synthesise_params(defn.parameters, param_overrides.get(defn.id)))
    except Exception as e:
        return Outcome(defn.id, defn.risk, "error", ms(), note=f"param-synth: {e}")

    if targeted and manifest is None:
        return Outcome(defn.id, defn.risk, "error", ms(),
                       note="no manifest: refusing to dispatch unrecorded")

    # Checked immediately before the manifest line and the POST: nothing new starts after an abort.
    if control.stop.is_set():
        return Outcome(defn.id, defn.risk, "skip", ms(), note=control.skip_note)

    if targeted:
        try:
            manifest.record(defn, target_agent_id, params)
        except Exception as e:
            return Outcome(defn.id, defn.risk, "error", ms(), note=f"manifest: {e}")

    try:
        control.mark_sent(defn.id)
        if targeted:
            code, payload = client.execute_instruction(defn.id, params, [target_agent_id])
        else:
            code, payload = client.execute_instruction(defn.id, params)
    except Exception as e:
        if targeted and _may_have_been_sent(e):
            return _dispatch_unknown(defn, control, ms(), f"{type(e).__name__}: {e}")
        return Outcome(defn.id, defn.risk, "error", ms(), note=f"dispatch: {type(e).__name__}: {e}")
    if targeted:
        control.note_status(code)

    if code in (200, 202) and not isinstance(payload, dict):
        if targeted and code == 200:  # the server said OK: the action may have started
            return _dispatch_unknown(defn, control, ms(), "HTTP 200 body is not a JSON object")
        return Outcome(defn.id, defn.risk, "error", ms(), http_code=code,
                       note=f"dispatch: HTTP {code} body is not a JSON object")

    if code == 202 and payload.get("status") == "pending_approval":
        return Outcome(defn.id, defn.risk, "pending_approval", ms(),
                       http_code=code,
                       execution_id=payload.get("approval_id", ""),
                       note=f"approval={defn.approval_mode}")

    if code != 200:
        msg = error_message(payload)
        return Outcome(defn.id, defn.risk, "fail", ms(),
                       http_code=code,
                       note=f"HTTP {code} {msg}".strip())

    accepted[0] = True  # the server accepted the dispatch: the action has been started
    command_id = payload.get("command_id", "")
    execution_id = payload.get("execution_id", "")
    if not command_id:
        return Outcome(defn.id, defn.risk, "fail", ms(),
                       http_code=code,
                       execution_id=execution_id,
                       note="dispatch ok but no command_id returned")

    deadline = time.monotonic() + poll_timeout_s
    last_payload: dict = {}
    responses: list = []
    response_count = 0
    last_rows: list = []   # the rows of the last poll that returned any (targeted grading)
    poll_error = ""        # the last poll's error, "" when it answered
    while time.monotonic() < deadline:
        if control.stop.is_set():
            return Outcome(defn.id, defn.risk, "error", ms(), http_code=code,
                           command_id=command_id, execution_id=execution_id,
                           note="in_flight_unknown: dispatch was sent, result not collected")
        last_payload = client.get_responses(command_id)
        responses = last_payload.get("responses", []) if isinstance(last_payload, dict) else []
        response_count = len(responses)
        if targeted:
            failed = isinstance(last_payload, dict) and "error" in last_payload and not responses
            poll_error = str(last_payload["error"]) if failed else ""
            if responses:
                last_rows = responses
            http_code = last_payload.get("code") if failed else None
            # refused (401/403/503) counts toward the stop; a transport failure is neutral
            refused = (http_code in (401, 403, 503)) if http_code else (None if failed else False)
            if control.note_poll(refused):
                break
        # A destructive/forensic row waits for every row to leave RUNNING (the agent sends
        # periodic RUNNING frames and finalises the row in place); the rest take the first answer.
        if response_count > 0 and not (targeted and any(row_in_flight(r) for r in responses)):
            break
        time.sleep(POLL_INTERVAL_S)

    duration_ms = ms()

    if targeted:
        problems, running = grade_targeted(last_rows)
        notes = [problems] if problems else []
        if poll_error:
            notes.append(f"poll failed: {clip(poll_error)}; could not read the response, the "
                         "action may or may not have run")
        if running:
            notes.append(f"still running after {poll_timeout_s}s (--poll-timeout); the action may "
                         "still be executing on the target")
            # Never start a next action on top of one that has not finished.
            control.request_stop("a targeted row was still running at the poll deadline; "
                                 "dispatch stopped",
                                 "stopped: previous row still running")
        if not last_rows and not poll_error:
            notes.append(f"no response rows within {poll_timeout_s}s (--poll-timeout); the action "
                         "may or may not have run")
        return Outcome(defn.id, defn.risk, "fail" if notes else "pass",
                       duration_ms, http_code=code, command_id=command_id,
                       execution_id=execution_id, response_count=len(last_rows),
                       note="; ".join(notes))

    if response_count == 0:
        last_err = last_payload.get("error") if isinstance(last_payload, dict) else None
        return Outcome(defn.id, defn.risk, "fail",
                       duration_ms, http_code=code, command_id=command_id,
                       execution_id=execution_id,
                       note=f"no response within {poll_timeout_s}s"
                            + (f" (last poll: {last_err})" if last_err else ""))

    # Loose shape validation: trust the agent's structured `status` and
    # `rc` fields rather than greping the body for "error|". Several
    # legitimate-empty cases (event_logs.errors returning rows whose
    # column-0 label is "error", agent_logging emitting an empty marker)
    # would otherwise be misclassified.
    # NOTE: this safe/mutating grading still compares a string `status` and an `rc`, neither
    # of which the server's integer-status rows carry; tracked as a follow-up, unchanged here.
    sane_count = 0
    error_count = 0
    for r in responses:
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


def selected_targeted(args: argparse.Namespace) -> list[str]:
    return sorted(set(args.risks) & set(TARGETED_RISKS))


def targeting_error(args: argparse.Namespace) -> str:
    """Why the selected risk classes cannot be dispatched as configured, or "" if they can."""
    classes = selected_targeted(args)
    if not classes:
        return ""
    if not args.target_agent_id or not args.confirm_target:
        return (f"--risks {'/'.join(classes)} needs --target-agent-id ID (the id of one connected "
                "agent) and --confirm-target HOSTNAME")
    if not args.run_id:
        return (f"--risks {'/'.join(classes)} needs --run-id (it names the manifest and "
                "the User-Agent that attribute every request)")
    try:
        host = urllib.parse.urlsplit(args.dashboard).hostname or ""
    except ValueError:
        host = ""
    if host not in LOOPBACK_HOSTS and not args.allow_remote:
        return (f"--risks {'/'.join(classes)} against a non-loopback dashboard ({esc(host) or '?'}) "
                "needs --allow-remote")
    return ""


def _no_duplicate_keys(pairs: list) -> dict:
    seen: set = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


def load_param_overrides(path: str) -> dict[str, dict[str, Any]]:
    """Read --params-override ({definition_id: {param: value}}); raises ValueError on any defect.

    A value must be a string or an integer (a boolean is written as the string "true"/"false");
    a duplicate key at any level is an error, because the last one would silently win.
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (OSError, ValueError) as e:  # missing, unreadable, malformed JSON, bad encoding, duplicate key
        raise ValueError(f"--params-override {path}: {type(e).__name__}: {e}") from e
    if not isinstance(raw, dict):
        raise ValueError(f"--params-override {path}: top level must be an object")
    out = {k: v for k, v in raw.items() if not k.startswith("_")}
    for def_id, entry in out.items():
        if not isinstance(entry, dict):
            raise ValueError(f"--params-override {path}: the entry for {def_id!r} must be an object")
        for key, value in entry.items():
            if not (isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))):
                raise ValueError(
                    f"--params-override {path}: {def_id!r} parameter {key!r} must be a string or an "
                    f"integer, not {type(value).__name__} (write a boolean as \"true\" or \"false\")")
    return out


def redact_url(url: str) -> str:
    """The dashboard URL without any userinfo, for the banner and the manifest."""
    try:
        parts = urllib.parse.urlsplit(url)
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc.rpartition("@")[2], parts.path, "", ""))
    except ValueError:
        return "?"


def preflight(client: YuzuClient, args: argparse.Namespace) -> tuple[dict | None, str]:
    """Look the target up in the server's agent list (GET /api/agents, the dashboard's own
    agent list; an agent is listed while it is connected) and check --confirm-target."""
    try:
        agents = client.list_agents()
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except Exception:
            body = {}
        err = body.get("error") if isinstance(body, dict) else None
        perm = (err.get("permission") if isinstance(err, dict) else None) or \
               (body.get("permission") if isinstance(body, dict) else None)
        msg = error_message(body)
        return None, (f"GET /api/agents answered HTTP {e.code}" + (f": {msg}" if msg else "")
                      + (f" (needs {esc(perm)})" if isinstance(perm, str) else "")
                      + "; the route needs Infrastructure:Read")
    except Exception as e:
        return None, f"cannot read the agent list (GET /api/agents): {type(e).__name__}: {esc(e)}"
    agent = next((a for a in agents
                  if isinstance(a, dict) and a.get("agent_id") == args.target_agent_id), None)
    if agent is None:
        return None, f"agent {esc(args.target_agent_id)!r} is not in the server's connected-agent list"
    hostname = str(agent.get("hostname") or "")
    if not hostname or hostname.casefold() != args.confirm_target.casefold():
        return None, (f"--confirm-target {esc(args.confirm_target)!r} does not match the hostname of "
                      f"agent {esc(args.target_agent_id)!r} ({esc(hostname) or 'unknown'!r})")
    if not str(agent.get("os") or ""):
        return None, f"agent {esc(args.target_agent_id)!r} reports no os"
    return agent, ""


def write_output(path: str, payload: dict) -> None:
    try:
        Path(path).write_text(json.dumps(payload, indent=2))
    except OSError as e:  # never lose the exit code over the summary file
        print(f"instructions_runner: warning: could not write --output {esc(path)}: {esc(e)}",
              file=sys.stderr)


def check_output_writable(path: str) -> str:
    """"" if --output can be written, else why not; a file this created is removed again."""
    p = Path(path)
    existed = p.exists()
    try:
        with p.open("a", encoding="utf-8"):
            pass
    except OSError as e:
        return f"--output {esc(path)} is not writable: {type(e).__name__}: {esc(e)}"
    if not existed:
        try:
            p.unlink()
        except OSError:
            pass
    return ""


def run(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parents[2]
    risk_table_path = Path(args.risk_table) if args.risk_table else \
        repo_root / "scripts/test/instructions-risk-classification.json"
    content_dir = Path(args.content_dir) if args.content_dir else \
        repo_root / "content/definitions"

    if args.run_id and not RUN_ID_RE.fullmatch(args.run_id):
        print("instructions_runner: --run-id must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} "
              "(it names the manifest file and the User-Agent)", file=sys.stderr)
        return 2
    bad = targeting_error(args)
    if bad:
        print(f"instructions_runner: {bad}", file=sys.stderr)
        return 2

    param_overrides: dict[str, dict[str, Any]] = {}
    if args.params_override:
        try:
            param_overrides = load_param_overrides(args.params_override)
        except ValueError as e:
            print(f"instructions_runner: {e}", file=sys.stderr)
            return 2

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

    known = {d.id for d in all_defs}
    for stray in sorted(set(param_overrides) - known):
        print(f"instructions_runner: --params-override names no definition: {esc(stray)}",
              file=sys.stderr)

    classes = selected_targeted(args)
    targeted_defs = [d for d in runnable if d.risk in TARGETED_RISKS]
    if classes and not [d for d in targeted_defs if not targeted_skip_reason(d, param_overrides)]:
        print(f"instructions_runner: no {'/'.join(classes)} definition has a --params-override entry "
              "that covers its required parameters (a typo'd id, or an entry missing a required "
              "parameter)" + ("" if args.params_override else "; pass --params-override FILE")
              + "; nothing dispatched", file=sys.stderr)
        return 2

    if args.output:
        bad_output = check_output_writable(args.output)
        if bad_output:
            print(f"instructions_runner: {bad_output}", file=sys.stderr)
            return 2

    run_id = args.run_id or uuid.uuid4().hex[:8]
    client = YuzuClient(args.dashboard, timeout=DEFAULT_DISPATCH_TIMEOUT_S, run_id=run_id)
    try:
        client.login(args.user, args.password)
    except Exception as e:
        print(f"instructions_runner: login failed: {esc(e)}", file=sys.stderr)
        return 2

    target_os = ""
    manifest: Manifest | None = None
    parallelism = args.parallelism
    manifest_path = ""
    if classes:
        agent, why = preflight(client, args)
        if agent is None:
            print(f"instructions_runner: {why}; nothing dispatched", file=sys.stderr)
            return 2
        target_os = str(agent["os"]).lower()
        usable = [d for d in targeted_defs if not targeted_skip_reason(d, param_overrides, target_os)]
        for d in targeted_defs:
            reason = targeted_skip_reason(d, param_overrides, target_os)
            if reason and d.id in param_overrides:
                print(f"instructions_runner: warning: override for {d.id} skipped: {reason}",
                      file=sys.stderr)
        if not usable:
            print(f"instructions_runner: no {'/'.join(classes)} definition is eligible on the "
                  f"target (os={esc(target_os)}) with its override; nothing dispatched",
                  file=sys.stderr)
            return 2
        manifest_path = args.manifest or str(Path.cwd() / f"instructions-runner-{run_id}.manifest.jsonl")
        try:
            manifest = Manifest(Path(manifest_path), run_id)
            manifest.start(dashboard=redact_url(args.dashboard), target_agent_id=args.target_agent_id,
                           hostname=str(agent.get("hostname")), os=target_os,
                           agent_version=str(agent.get("agent_version", "?")), classes=classes)
        except OSError as e:
            print(f"instructions_runner: cannot open the manifest {manifest_path}: {esc(e)}",
                  file=sys.stderr)
            return 2
        # Same-path writers (filesystem.*, registry.*) race at parallelism > 1.
        if parallelism != 1:
            print("instructions_runner: destructive/forensic classes run one at a time "
                  f"(--parallelism {parallelism} ignored)")
            parallelism = 1
        print(f"instructions_runner: TARGETED RUN target={esc(args.target_agent_id)} "
              f"host={esc(agent.get('hostname'))} os={esc(target_os)} "
              f"version={esc(agent.get('agent_version', '?'))} "
              f"dashboard={redact_url(args.dashboard)} classes={','.join(classes)} "
              f"covered={len(usable)} skipped={len(targeted_defs) - len(usable)} "
              f"manifest={manifest_path}")
        if selected_risks & set(DEFAULT_RISKS):
            print("instructions_runner: mixed run: safe/mutating definitions are still sent to "
                  "EVERY agent")

    targeted_poll = args.poll_timeout if getattr(args, "poll_timeout_explicit", True) \
        else max(args.poll_timeout, TARGETED_POLL_TIMEOUT_S)
    outcomes: list[Outcome] = []
    started_at = time.monotonic()
    aborted = ""
    control = RunControl()
    future_map: dict[concurrent.futures.Future, Definition] = {}

    def collect(fut: concurrent.futures.Future) -> None:
        if fut.cancelled():
            return
        d = future_map[fut]
        try:
            outcome = fut.result()
        except Exception as e:
            outcome = Outcome(d.id, d.risk, "error", 0, note=f"{type(e).__name__}: {e}")
        outcomes.append(outcome)
        if args.verbose or outcome.status in ("fail", "error"):
            print(f"  {outcome.short()}")
        if args.run_id:
            db_record_timing(repo_root, args.run_id, args.gate_name, outcome.id, outcome.duration_ms)

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=parallelism)
    pending: set = set()
    try:
        for d in runnable:
            future_map[pool.submit(exercise, client, d, param_overrides, args.poll_timeout,
                                   args.target_agent_id, target_os, manifest, control,
                                   targeted_poll)] = d
        pending = set(future_map)
        # A timed wait, not as_completed: a bare lock wait is not interruptible on Windows.
        while pending:
            done, pending = concurrent.futures.wait(
                pending, timeout=0.5, return_when=concurrent.futures.FIRST_COMPLETED)
            for fut in done:
                collect(fut)
    except BaseException as e:  # KeyboardInterrupt included: stop further dispatch, keep the record
        aborted = type(e).__name__
        control.request_stop()
        pool.shutdown(wait=False, cancel_futures=True)
        print(f"instructions_runner: aborted ({aborted}); dispatch stopped", file=sys.stderr)
        try:  # let a worker that was mid-poll hand back what it has
            done, pending = concurrent.futures.wait(pending, timeout=1.0)
            for fut in done:
                collect(fut)
        except BaseException:
            pass
        have = {o.id for o in outcomes}
        for d in runnable:
            if d.id in control.sent and d.id not in have:
                outcomes.append(Outcome(d.id, d.risk, "error", 0, dispatched=True,
                                        note="in_flight_unknown: dispatch was sent, result not collected"))
                print(f"  {outcomes[-1].short()}")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        if manifest is not None:
            manifest.close()

    total_ms = int((time.monotonic() - started_at) * 1000)

    # Tally
    counts = {"pass": 0, "fail": 0, "pending_approval": 0, "error": 0, "skip": 0}
    for o in outcomes:
        counts[o.status] = counts.get(o.status, 0) + 1
    # Risk-filtered defs never enter the executor; add them to the skip tally.
    counts["skip"] += len(skipped)
    # dispatched = the server accepted the POST (HTTP 200: the action was started), or it was
    # sent and the run ended before its result came back; a 202 pending_approval is not.
    dispatched = sum(1 for o in outcomes if o.dispatched)
    # dispatch_unknown: a targeted POST failed after it may have been sent. It is counted on its
    # own and, conservatively, in the targeted-dispatched metric.
    unknown = sum(1 for o in outcomes if o.dispatch_unknown)
    targeted_dispatched = unknown + sum(1 for o in outcomes
                                        if o.dispatched and o.risk in TARGETED_RISKS)
    run_skips = sum(1 for o in outcomes if o.status == "skip")

    summary = (f"instructions_runner: {counts['pass']} pass / "
               f"{counts['fail']} fail / {counts['pending_approval']} pending / "
               f"{counts['error']} error / {counts['skip']} skip "
               f"({total_ms}ms wall)")
    print(summary)
    if classes:
        by_class = " ".join(f"{c}={sum(1 for o in outcomes if o.status == 'skip' and o.risk == c)}"
                            for c in classes)
        print(f"instructions_runner: skipped by class: {by_class}")
        print(f"instructions_runner: {dispatched} dispatched, {unknown} dispatch_unknown, "
              f"{counts['pending_approval']} pending_approval (not executed), {run_skips} skipped, "
              f"{counts['fail'] + counts['error']} failed (of {len(runnable)} selected)")
        nothing_executed = not dispatched and not unknown
        if nothing_executed:
            print(f"instructions_runner: nothing was executed ({counts['pending_approval']} "
                  f"pending_approval, {run_skips} skipped)", file=sys.stderr)
    else:
        nothing_executed = False
    if control.abort_reason:
        print(f"instructions_runner: {control.abort_reason}", file=sys.stderr)

    if args.output:
        write_output(args.output, {
            "summary": counts,
            "total_ms": total_ms,
            "run_id": run_id,
            "risks": sorted(selected_risks),
            "target_agent_id": args.target_agent_id,
            "dashboard": redact_url(args.dashboard),
            "user": args.user,
            "skipped": counts["skip"],
            "dispatched": dispatched,
            "manifest": manifest_path,
            "aborted": aborted or control.abort_reason,
            "outcomes": [asdict(o) for o in outcomes],
        })

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
        if classes:
            db_record_metric(repo_root, args.run_id, "instructions_targeted_dispatched",
                              targeted_dispatched, "count")

    # Exit code:
    #   0   - all runnable instructions passed (or pending_approval, expected)
    #   1   - one or more fail/error, the run stopped early, or a targeted run executed nothing
    #   2   - infrastructure or configuration failure (login, content-dir empty, opt-in targeting,
    #         --params-override, --run-id, target pre-flight); nothing was dispatched
    #   130 - interrupted (Ctrl-C or SIGTERM)
    if aborted == "KeyboardInterrupt":
        return 130
    if (aborted or control.abort_reason or counts["fail"] > 0 or counts["error"] > 0
            or nothing_executed):
        return 1
    return 0


EPILOG = """\
Exit codes: 0 every dispatched instruction passed (or is pending approval); 1 one or more failed or
errored, the run stopped early, or a targeted run executed nothing (every row skipped or pending
approval); 2 a configuration, login or pre-flight error, with nothing dispatched; 130 interrupted
(Ctrl-C or SIGTERM).

Destructive and forensic runs (--risks destructive forensic)
  Example, against a dedicated disposable stack on loopback:
    python3 scripts/test/instructions_runner.py --dashboard http://127.0.0.1:8080 \\
        --user uat-admin --password 'PASSWORD' --risks destructive forensic \\
        --target-agent-id AGENT_ID --confirm-target HOSTNAME --run-id my-run-1 \\
        --params-override overrides.json --output outcomes.json
  AGENT_ID and HOSTNAME: the Devices page of the dashboard, or GET /api/agents (agent_id, hostname).
  Needed: --target-agent-id, --confirm-target, --run-id and --params-override; the dashboard must be
  loopback (127.0.0.1, ::1, localhost) or --allow-remote is given. Before any dispatch the runner
  looks the id up in GET /api/agents, prints its hostname, OS and version, and requires HOSTNAME to
  match (case-insensitive). Definitions run one at a time, each with exactly its --params-override
  entry (no synthesised values) and only if that entry supplies every required parameter; every
  other definition is skipped, not dispatched. Each dispatch is appended to a manifest
  (--manifest PATH, default instructions-runner-<run-id>.manifest.jsonl) before it is sent. The
  runner polls each targeted row until every response row is terminal or the poll deadline passes
  (--poll-timeout, 120 s for these classes unless given); a row passes only when every response row
  is SUCCESS with no error_detail, and a row still running at the deadline fails the run and stops
  further dispatch. Ctrl-C and SIGTERM stop further dispatch; a dispatch already sent is reported
  in_flight_unknown, and a transport failure after a POST was sent is dispatch_unknown (the run
  stops; do not re-run blindly). Three consecutive 401/403 answers to execute, or to a targeted
  poll (503 too), stop the run.

  The manifest is an attempt log, not outcome evidence: the first line is run-start, then one line
  per dispatch with the exact params sent (treat it as sensitive; it is created 0600, at creation
  only; .gitignore covers only the default name). Forensic rows read behavioural data from the
  target, and the responses are stored in the server's response store.

  --confirm-target is a wrong-target typo guard against what the connected server reports. It cannot
  detect an ssh -L tunnel or a port forward to a different stack, and it is not an authorisation or
  approval control. Use a dedicated admin account on a disposable stack. The password on the command
  line is visible in ps: prefer that dedicated account; http:// with --allow-remote sends it in
  cleartext. With safe/mutating in the same --risks, those definitions are still sent to EVERY agent.

  Eligible ids: the entries classed destructive or forensic in the "_overrides" of
  scripts/test/instructions-risk-classification.json; each one's required parameters are under
  spec.parameters.required in content/definitions/*.yaml.

--params-override file ({definition id: {parameter: value}}). Values are strings or integers (write
a boolean as the string "true" or "false"); a duplicate key is an error; top-level keys starting
with "_" are ignored; an empty {} is valid only for a definition with no required parameters:
  {
    "_comment": "ignored",
    "device.tags.clear": {},
    "device.filesystem.append": {"path": "/tmp/yuzu_uat_scratch.txt", "content": "x"}
  }
  (device.filesystem.append: the path must already exist on the target.)

Side effects (NOT exhaustive: every destructive/forensic row in the risk table applies; the runner
undoes none of them):
  device.tags.clear              removes the target's tags
  agent.storage.clear            removes every key in the target's agent storage
  crossplatform.tar.rollup       permanently deletes TAR rows past retention; not recoverable; no
                                 approval gate
  security.certificates.delete   deletes a certificate from the target's store
  agent.content_dist.stage / execute_staged / cleanup / upload_file
                                 execute_staged RUNS the staged artefact on the target
  crossplatform.printing.clear_queue   cancels a print job; irreversible
  crossplatform.service.set_start_mode changes a service's start mode
  device.script_exec.*           runs arbitrary script text on the target
  agent.http_client.download     writes a downloaded file to the target
  device.wol.wake                sends a Wake-on-LAN packet
  workflow.config_search_and_replace   rewrites a config file on the target
  device.filesystem.*            change files at the paths in your override
  windows.registry.*             change or delete registry values/keys named in your override
  crossplatform.power.set_power_plan   changes the active power plan
  testing.chargen.start          streams until stopped, so a targeted run skips it (even with an
                                 override): the runner cannot target the mutating
                                 testing.chargen.stop; start and stop it by hand from the
                                 dashboard or REST with agent_ids
  server.* rows (for example server.policy.invalidate_all) are skipped, never sent.
"""


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, epilog=EPILOG,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dashboard", required=True,
                   help="Yuzu dashboard root, e.g. http://localhost:8080")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", required=True,
                   help="visible in ps on the command line; use a dedicated disposable-stack account")
    p.add_argument("--risks", nargs="+", default=list(DEFAULT_RISKS),
                   choices=list(ALL_RISKS),
                   help=f"risk classes to run, space-separated (default: {' '.join(DEFAULT_RISKS)})")
    p.add_argument("--target-agent-id", default="",
                   help="id of the one connected agent that destructive/forensic definitions "
                        "are dispatched to (required to select those classes)")
    p.add_argument("--confirm-target", default="",
                   help="the target agent's hostname, which must match the server's agent list "
                        "(required whenever destructive or forensic is selected, with "
                        "--target-agent-id and --run-id)")
    p.add_argument("--allow-remote", action="store_true",
                   help="allow destructive/forensic classes against a non-loopback --dashboard "
                        "(loopback: 127.0.0.1, ::1, localhost)")
    p.add_argument("--manifest", default="",
                   help="destructive/forensic dispatch record (JSON lines, written before each "
                        "dispatch; default: instructions-runner-<run-id>.manifest.jsonl)")
    p.add_argument("--match", default="",
                   help="restrict to definition IDs matching this regex")
    p.add_argument("--only-id", default="",
                   help="run exactly this one definition id (debugging)")
    p.add_argument("--parallelism", type=int, default=DEFAULT_PARALLELISM)
    p.add_argument("--poll-timeout", type=int, default=None,
                   help=f"per-instruction response poll timeout (default: {DEFAULT_POLL_TIMEOUT_S}s; "
                        f"{TARGETED_POLL_TIMEOUT_S}s for destructive/forensic rows). A targeted row "
                        "still running at the deadline fails and stops the run")
    p.add_argument("--content-dir", default="",
                   help="override content/definitions path")
    p.add_argument("--risk-table", default="",
                   help="override scripts/test/instructions-risk-classification.json path")
    p.add_argument("--params-override", default="",
                   help="JSON file mapping definition_id -> {param: value}; required for "
                        "destructive/forensic (see below); a missing or malformed file is an error")
    p.add_argument("--output", default="",
                   help="write per-instruction outcomes to this JSON file")
    p.add_argument("--run-id", default="",
                   help="[A-Za-z0-9][A-Za-z0-9._-]{0,63}; if set, record timings/metrics to the "
                        "test-runs DB; also names the User-Agent and the manifest (required for "
                        "destructive/forensic)")
    p.add_argument("--gate-name", default="instructions",
                   help="gate name to scope timings under (default: instructions)")
    p.add_argument("--verbose", action="store_true",
                   help="print every outcome (default: only fail/error)")
    ns = p.parse_args(argv)
    ns.poll_timeout_explicit = ns.poll_timeout is not None
    if ns.poll_timeout is None:
        ns.poll_timeout = DEFAULT_POLL_TIMEOUT_S
    ns.target_agent_id = ns.target_agent_id.strip()
    ns.confirm_target = ns.confirm_target.strip()
    return ns


def _raise_interrupt(signum: int, frame: Any) -> None:
    raise KeyboardInterrupt


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    previous = None
    try:  # SIGTERM takes the same abort path as Ctrl-C (summary, --output, exit 130)
        previous = signal.signal(signal.SIGTERM, _raise_interrupt)
    except (ValueError, OSError, AttributeError):  # not the main thread, or no such signal
        pass
    try:
        return run(args)
    except KeyboardInterrupt:
        print("instructions_runner: interrupted", file=sys.stderr)
        return 130
    finally:
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    sys.exit(main())
