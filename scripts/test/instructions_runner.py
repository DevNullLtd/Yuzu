#!/usr/bin/env python3
"""
instructions_runner.py - schema-driven REST exerciser for the
InstructionDefinitions shipped under content/definitions/.

Companion to scripts/test/instructions-tests.sh (the bash entry that the
/test --instructions gate invokes). Auth, dispatch, and polling mirror
scripts/test/synthetic-uat-tests.sh:
  - form-login at POST /login (session cookie)
  - dispatch via POST /api/instructions/:id/execute (workflow_routes.cpp:1290)
  - poll results via GET /api/responses/:command_id (used by synthetic
    UAT test 6 - same correlation pattern)

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
  pending_approval  HTTP 202 with status=pending_approval - the approval mode
                    is always, role-gated for a non-admin caller, or an
                    unrecognised approval mode; never auto. Not a failure, but
                    nothing ran and not a semantic check either
  skip              definition risk-tag excluded by the --risks filter
                    (everything but safe and mutating by default), or a
                    destructive/forensic definition the targeted run may not
                    dispatch (no override entry, required parameter missing,
                    server.* row, not eligible on the target's OS)
  error             internal runner error (network, JSON parse, etc.) -
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

Anything missing is a configuration error: exit 2, nothing dispatched. These instructions change or
read a real device, so a targeted run is serial, appends each dispatch to a manifest before sending
it, and polls each targeted row until every response row is terminal or the poll deadline passes
(--poll-timeout; 120 s for these classes unless it is given). The deadline is checked per poll, so
it can overrun by up to two polls (one in flight at the deadline plus the one final poll, about 20
s). A RUNNING row exists only for flushed output, so a quiet long-running action shows no rows at
all until it finishes. A row passes only if every response row is SUCCESS with no error_detail. A
row that ends without a verdict from terminal rows (no rows, rows still running, polls failing for
any reason, or a row the runner does not recognise) fails and stops further dispatch, so a following
action never overlaps it; a terminal FAILURE/TIMEOUT/REJECTED row is a known outcome and does not
stop the run. Ctrl-C, Ctrl-Break (Windows) and SIGTERM stop dispatching (exit 130); a dispatch
already claimed is reported as in_flight_unknown. Claimed is not sent: the stop is checked at the
claim and not again once the connection is open, so a connect or TLS handshake that stalls past
the stop can still transmit that one request to the target.

After a targeted POST was sent only these mean "not executed": any 4xx, a 503 carrying a recognised
pre-dispatch refusal reason, a 202 pending_approval (approval mode always, role-gated for a
non-admin caller, or an unrecognised mode; never auto), and a refused connection or unresolvable
name. HTTP 200 means the server started it. Everything else is dispatch_unknown and stops the run
(do not re-run blindly): a transport failure after send, any other 5xx, any 3xx, any 2xx other than
200 and a pending_approval 202, a 202 without pending_approval, the generic 503 "no agents reached"
(it also covers a failed send on the agent stream and names no command id; #6102), and any exception
after an accepted POST. Three consecutive 401/403 answers to execute, or 401/403/503 to a targeted
poll, also stop the run. Permissions: Execution:Execute to dispatch, Response:Read to poll,
Infrastructure:Read for the agent lookup.

Exit codes: 0 every dispatched instruction passed (or is pending approval); 1 one or more failed or
errored, the run stopped early, or a targeted run executed nothing (every destructive/forensic row
skipped or pending approval); 2 a configuration, login or pre-flight error with nothing dispatched,
including --poll-timeout below 1 (targeted runs only), --output equal to --manifest, an --output
that is a symlink (POSIX only) or not a regular file, a --dashboard URL with userinfo
(user:password@) or a backslash, or (targeted runs) an --output or a manifest that already exists;
130 interrupted (Ctrl-C, Ctrl-Break or SIGTERM). A failed write of --output at the end only
warns.

An untargeted run (no destructive or forensic class) is the one /test makes, and it is stricter than
it was: every request carries a yuzu-instructions-runner/<run-id> User-Agent, proxy environment
variables are ignored, a redirect on the execute POST is not followed, a missing or malformed
--params-override (including a duplicate key or a value that is not a string or an integer), a
--run-id outside [A-Za-z0-9][A-Za-z0-9._-]{0,63} and a --dashboard with userinfo or a backslash exit
2, --output refuses a symlink or a multi-link file, control characters in notes are escaped, and
SIGTERM now stops the run like Ctrl-C (exit 130). /test passes none of the inputs that exit 2.

The manifest is an attempt log, not outcome evidence: the first line is run-start, then a dispatch
line per attempt (the exact params sent: treat it as sensitive; it is created 0600 on POSIX, at
creation only; .gitignore covers only the default name), an accepted line when the server answers
it, and a not-sent line when a stop won the race after the dispatch line and the manifest was still
open (that POST was never made). The manifest is created exclusively: a path that already exists (an
earlier run, a symlink, a FIFO) is refused with exit 2, so rename it or pass a new --run-id.
--output is written through an owner-only descriptor (0600 at creation only; an existing file keeps
its mode) that refuses a symlink (POSIX only); a targeted run creates it exclusively and refuses an
existing one (rename it first: it holds the command_id record of an earlier run); an untargeted run
truncates and rewrites an existing --output in place, but only if it is a regular single-link file.
A SIGKILL, a double signal in the same instant, or SIGHUP (an ssh drop) can leave only the manifest.
--output holds command_id for accepted rows; rows rebuilt at an abort, and answers that land after
the manifest was closed, carry no command_id in --output or the manifest: check the target by
definition id and timestamp. A closed stdout may still end the process with exit 120 at interpreter
flush: --output and the metrics are written first and it fails closed, never a false 0. The stderr
list of not-started ids is capped at 30; the rest are in --output and the manifest. Forensic rows
read behavioural data from the target, and the responses are stored in the server's response store.

--confirm-target is a wrong-target typo guard against what the connected server reports. It cannot
detect an ssh -L tunnel or a port forward to a different stack, and it is not an authorisation or
approval control; use a dedicated admin account on a disposable stack. If safe or mutating classes
are in the same --risks they are still sent to every agent (the run says so on stderr); target flags
given with no destructive or forensic class selected are ignored, with a warning. A server-internal
definition is never sent a target: it names no agent plugin, so if selected it is broadcast and the
dispatch chokepoint denies it. A server.* row that the risk table classes destructive is skipped in
a targeted run for the same reason, as is testing.chargen.start (it streams until stopped; start and
stop it by hand through the dashboard or REST with agent_ids).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import datetime
import http.client
import http.cookiejar
import json
import os
import platform
import re
import signal
import socket
import stat
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
        bits = [f"{esc(self.id)} [{self.risk}]", self.status.upper(), f"{self.duration_ms}ms"]
        if self.note:
            bits.append(self.note)
        return " - ".join(bits)


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


def say(*args: Any, **kw: Any) -> None:
    """print() that never raises: a closed or broken stdout/stderr must not cost the exit code,
    the --output file or the metrics. (A closed stdout may still end the process with exit 120 at
    interpreter flush; --output and the metrics are written first, and it never reads as success.)"""
    try:
        print(*args, **kw)
    except (OSError, ValueError):
        pass


def clip(text: Any, limit: int = 200) -> str:
    s = str(text)
    return s if len(s) <= limit else s[:limit] + "..."


def wire_params(params: dict) -> dict[str, str]:
    """The params as they go on the wire (every value a string); the manifest records the same."""
    return {k: str(v) if not isinstance(v, str) else v for k, v in params.items()}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx answer to the execute POST is an answer, not an instruction: following it would
    re-issue the request (as a GET) at a place the operator never named."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


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
        self.post_opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.jar),
            _NoRedirect())
        self.post_opener.addheaders = self.opener.addheaders

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
            with self.post_opener.open(req, timeout=self.timeout) as resp:
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
            try:
                try:
                    body = json.loads(e.read() or b"{}")
                except Exception:
                    body = {}
            finally:
                e.close()
            msg = error_message(body)
            out: dict[str, Any] = {"error": f"HTTP {e.code}" + (f" {msg}" if msg else ""),
                                   "code": e.code}
            perm = a4_permission(body)
            if perm:
                out["permission"] = perm
            return out
        except Exception as e:  # URLError, TimeoutError, JSONDecodeError, OSError ...
            return {"error": f"{type(e).__name__}: {e}"}


class Manifest:
    """Append-only JSONL record of every destructive/forensic dispatch, written BEFORE the POST."""

    def __init__(self, path: Path, run_id: str):
        self.path = path
        self.run_id = run_id
        # Owner-only; "\n" on every OS. O_EXCL: the manifest is always a file this run created, so a
        # symlink, a FIFO (an open that would block before anything is sent), a hard link to someone
        # else's file and the manifest of an earlier run (a second run appended to it would blur the
        # "no dispatch line = never sent" rule) are all refused.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
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

    def not_sent(self, defn: Definition, why: str) -> None:
        """Close a dispatch line whose POST was never made (a stop won the race after it).
        Best effort: a write error (e.g. the manifest already closed at abort) is swallowed and the
        dispatch line then stays ambiguous."""
        try:
            self._write({"event": "not-sent", "ts": self._now(), "run_id": self.run_id,
                         "id": defn.id, "why": why})
        except Exception:
            pass  # the dispatch line alone still reads as "may or may not have run": conservative

    def accepted(self, defn: Definition, code: int, payload: Any) -> None:
        """The server answered a dispatch: its status and, when it gave them, the ids to look up."""
        rec: dict[str, Any] = {"event": "accepted", "ts": self._now(), "run_id": self.run_id,
                               "id": defn.id, "http": code}
        if isinstance(payload, dict):
            for key in ("command_id", "execution_id", "approval_id"):
                if payload.get(key) not in (None, ""):
                    rec[key] = str(payload[key])
        self._write(rec)

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass  # never mask the summary or exit 130

    def discard(self) -> None:
        """Close, and remove the file this run created, only if the path still names that file.

        For a manifest whose run-start could not be written: an empty stub would refuse the retry.
        The path is compared with the descriptor's device and inode first, so a file swapped in
        meanwhile is left alone (the check and the unlink are still two steps, not one).
        """
        try:
            mine = os.fstat(self._fh.fileno())
        except (OSError, ValueError):
            mine = None
        self.close()
        if mine is None:
            return
        try:
            now = os.stat(self.path, follow_symlinks=False)
            if (now.st_dev, now.st_ino) == (mine.st_dev, mine.st_ino):
                os.unlink(self.path)
        except OSError:
            pass


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

    def __init__(self, poll_explicit: bool = False) -> None:
        self.poll_explicit = poll_explicit   # --poll-timeout was given (changes how notes name it)
        self.stop = threading.Event()
        self.sent: set[str] = set()   # definition ids whose execute POST was begun
        self.abort_reason = ""
        self.skip_note = "aborted before dispatch"   # why the rows that never started were skipped
        self.targeted_total = 0                      # for the "dispatching n/N" line
        self._dispatch_n = 0
        self._auth_failures = 0
        self._poll_refusals = 0
        self._lock = threading.Lock()

    def request_stop(self, reason: str = "", skip_note: str = "") -> None:
        with self._lock:   # the same lock begin_dispatch takes: a stop and a claim cannot interleave
            if reason and not self.abort_reason:
                self.abort_reason = reason
                if skip_note:
                    self.skip_note = skip_note
            self.stop.set()

    def next_dispatch(self) -> int:
        with self._lock:
            self._dispatch_n += 1
            return self._dispatch_n

    def begin_dispatch(self, def_id: str) -> bool:
        """Claim the right to POST: False once a stop was requested, else the id joins `sent`.

        The stop check before the manifest write is only an early exit; this is the check that
        counts, made after that (slow, fsynced) write and atomic with request_stop: no new POST is
        claimed once a stop was requested. A POST already claimed stays in `sent`, so the abort
        reports it as in_flight_unknown.
        """
        with self._lock:
            if self.stop.is_set():
                return False
            self.sent.add(def_id)
            return True

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
    "testing.chargen.start": "streams until stopped; start and stop it by hand through the "
                             "dashboard or REST with agent_ids",
}


def a4_permission(body: Any) -> str:
    """The "<securable>:<operation>" an A4 denial names, "" when it names none."""
    err = body.get("error") if isinstance(body, dict) else None
    perm = (err.get("permission") if isinstance(err, dict) else None) or \
           (body.get("permission") if isinstance(body, dict) else None)
    return perm if isinstance(perm, str) else ""


# What a targeted execute POST can tell us. ONLY the "no" rows mean the action was not executed;
# every other outcome is "unknown" and stops the run (an allow-list: a new status, a proxy page or
# an odd exception can never read as "nothing happened").
#
#   answer / exception                                          executed?   action
#   ----------------------------------------------------------  ---------   ---------------------
#   200 with a JSON object                                      started     poll for a verdict
#   202 with status == "pending_approval"                       no          pending_approval, go on
#   any 4xx                                                     no          fail, go on
#   503 with error.reason in PRE_DISPATCH_503_REASONS           no          fail, go on
#   URLError whose .reason is ConnectionRefusedError or         no          error, go on
#       socket.gaierror (the connect phase: nothing was sent)
#   every other 5xx, every 3xx and 1xx, any other 2xx, a 202    UNKNOWN     dispatch_unknown, stop
#       without pending_approval, a 200 without an object,
#       any other exception (a timeout, a reset, a bare OSError
#       from getresponse, a decode error, a bug)
#
# Other pre-dispatch refusals (a 500 for an invalid stored schema, a 500 for a failed approval
# submit, a reasonless 503 for an unavailable store, approval queue or registry) cannot be told
# apart from a post-dispatch failure by status alone, so they are conservatively UNKNOWN too. That
# includes the generic 503 "no agents reached" (workflow_routes.cpp): it also covers a send that
# was attempted and failed on the agent stream, and carries no command id, so it cannot prove the
# action did not run. A distinct server reason for it is tracked in #6102; add that reason to
# PRE_DISPATCH_503_REASONS when it ships.
PRE_DISPATCH_503_REASONS = ("containment_unreadable", "route_unreadable", "os_gate_unreadable",
                            "quarantined", "plugin_not_found", "kill_switched_os")


def _is_pre_dispatch_503(payload: Any) -> bool:
    err = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(err, dict) and err.get("reason") in PRE_DISPATCH_503_REASONS:
        return True
    return False   # the generic "no agents reached" body is NOT proof (see the table above)


def _post_verdict(code: int, payload: Any) -> str:
    """"started", "not_executed" or "unknown" for a targeted execute answer (table above)."""
    if code == 200 and isinstance(payload, dict):
        return "started"
    if code == 202 and isinstance(payload, dict) and payload.get("status") == "pending_approval":
        return "not_executed"
    if 400 <= code < 500:
        return "not_executed"
    if code == 503 and _is_pre_dispatch_503(payload):
        return "not_executed"
    return "unknown"


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


def grade_targeted(responses: list, target: str = "") -> tuple[str, bool, bool]:
    """(why it is a fail, any row running, any row unrecognised).

    The wire row is {id, instruction_id, agent_id, timestamp, status, output, error_detail} with
    an integer status 0-4. A row that is not an object, has any other status, or names an agent
    other than the target is UNRECOGNISED: something is not as the runner assumes, so the caller
    stops the run. A row with no agent_id is tolerated. A legacy `rc` can only add a failure.
    """
    problems: list[str] = []
    running = False
    odd = False
    for r in responses:
        if not isinstance(r, dict):
            problems.append("a response row is not an object")
            odd = True
            continue
        agent = r.get("agent_id")
        if target and agent not in (None, "") and agent != target:
            problems.append(f"{clip(agent, 64)}: a row for an agent other than the target")
            odd = True
            continue
        if row_in_flight(r):
            running = True
            continue
        reasons: list[str] = []
        s = _int_status(r)
        if s is None or not 0 <= s <= 4:
            reasons.append(f"unrecognised status {clip(r.get('status'), 40)!r}")
            odd = True
        elif s != 1:
            reasons.append(STATUS_NAMES[s])
        rc = r.get("rc", r.get("return_code", 0))
        if isinstance(rc, int) and not isinstance(rc, bool) and rc != 0:
            reasons.append(f"rc={rc}")
        detail = r.get("error_detail")
        if not isinstance(detail, str):   # the real row always carries a string (response_routes.cpp)
            reasons.append(f"unrecognised error_detail {clip(detail, 40)!r}")
            odd = True
        elif detail != "":   # not stripped: a whitespace-only detail is still an error detail
            reasons.append(f"error_detail={clip(detail)!r}")
        if reasons:
            problems.append(f"{clip(r.get('agent_id', '?'), 64)}: {', '.join(reasons)}")
    notes = problems[:3] + ([f"(+{len(problems) - 3} more)"] if len(problems) > 3 else [])
    return "; ".join(notes), running, odd


def _may_have_been_sent(e: BaseException) -> bool:
    """Whether a failed targeted POST may have reached the server (table above).

    Only a connect-phase failure is provably unsent: urllib raises URLError(ConnectionRefusedError)
    or URLError(socket.gaierror) before a byte is written. Anything else, including a bare OSError
    from getresponse() (a reset, an unreachable host on a reused connection), a timeout, a decode
    error or a bug, is unknown.
    """
    if isinstance(e, urllib.error.URLError) and not isinstance(e, urllib.error.HTTPError):
        return not isinstance(e.reason, (ConnectionRefusedError, socket.gaierror))
    return True


def _ids(payload: Any) -> tuple[str, str]:
    """(command_id, execution_id) of an answer, "" when absent."""
    if not isinstance(payload, dict):
        return "", ""
    return (str(payload["command_id"]) if payload.get("command_id") is not None else "",
            str(payload["execution_id"]) if payload.get("execution_id") is not None else "")


def _dispatch_unknown(defn: Definition, control: RunControl, duration_ms: int, detail: str,
                      manifest: Manifest | None = None, payload: Any = None) -> Outcome:
    control.request_stop("a targeted dispatch may have reached the server but its outcome is "
                         "unknown (dispatch_unknown); stopping",
                         "stopped: previous dispatch outcome unknown")
    where = f" {esc(manifest.path)}" if getattr(manifest, "path", None) else ""
    command_id, execution_id = _ids(payload)
    return Outcome(defn.id, defn.risk, "error", duration_ms, dispatch_unknown=True,
                   command_id=command_id, execution_id=execution_id,
                   note=f"dispatch_unknown: the request may have reached the server and the action "
                        f"may have run (see the manifest{where}); do not re-run blindly [{detail}]")


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


def _poll_targeted(client: YuzuClient, defn: Definition, control: RunControl, poll_timeout_s: int,
                   code: int, payload: dict, ms: Any, target: str = "") -> Outcome:
    """Poll an accepted destructive/forensic dispatch to a verdict, or stop the run.

    A RUNNING row exists only for flushed output (the server never stores bare keepalive frames),
    so a quiet long-running action shows NO rows at all until its terminal frame arrives. A row
    that ends the poll without a verdict from terminal rows - no rows, rows still RUNNING, polls
    failing, or a row the runner does not recognise - leaves the action possibly still executing,
    so it stops further dispatch. A terminal FAILURE/TIMEOUT/REJECTED row is a known outcome and
    does not stop the run. The deadline is checked per poll, so it can overrun by up to one poll
    (about the 10 s request timeout); after it passes there is ONE final poll so a result that
    landed in the last interval is not lost.
    """
    command_id = payload.get("command_id")
    execution_id = str(payload.get("execution_id", ""))
    if not isinstance(command_id, str) or not command_id:
        raise ValueError("the 200 body has no usable command_id")
    hint = " (--poll-timeout)" if control.poll_explicit else " (default; raise --poll-timeout)"
    deadline = time.monotonic() + poll_timeout_s
    last_rows: list = []   # the rows of the last poll that returned any
    poll_error = ""        # the last poll's error, "" when it answered
    poll_perm = ""
    final = False
    while True:
        if control.stop.is_set():
            return Outcome(defn.id, defn.risk, "error", ms(), http_code=code,
                           command_id=command_id, execution_id=execution_id,
                           note="in_flight_unknown: dispatch was sent, result not collected")
        polled = client.get_responses(command_id)
        rows: list = []
        if isinstance(polled, dict) and "responses" in polled:
            rows = polled["responses"]
            if not isinstance(rows, list):
                raise TypeError(f"responses is {type(rows).__name__}, not a list")
        failed = isinstance(polled, dict) and "error" in polled and not rows
        poll_error = str(polled["error"]) if failed else ""
        poll_perm = str(polled.get("permission", "")) if failed else ""
        if rows:
            last_rows = rows
        http_code = polled.get("code") if failed else None
        # An HTTP-coded answer is refused (401/403/503: counts toward the stop) or not (any other
        # code, which resets the count); only a failure with no code (transport, garbage) is
        # neutral and leaves the count alone.
        refused = (http_code in (401, 403, 503)) if http_code else (None if failed else False)
        if control.note_poll(refused):
            break
        if rows and not any(row_in_flight(r) for r in rows):
            break
        if final:
            break
        if time.monotonic() < deadline:
            time.sleep(POLL_INTERVAL_S)
        final = time.monotonic() >= deadline

    problems, running, odd = grade_targeted(last_rows, target)
    notes = [problems] if problems else []
    reasons: dict[str, str] = {}   # stop reason -> skip note, in priority order
    if odd:
        notes.append("unrecognised response row: the runner cannot tell what happened")
        reasons["unrecognised response row"] = "stopped: unrecognised response row"
    if running:
        notes.append(f"still running after {poll_timeout_s}s{hint}; the action may still be "
                     "executing on the target")
        reasons["previous row still running"] = "stopped: previous row still running"
    if poll_error:
        notes.append(f"poll failed: {clip(poll_error)}"
                     + (f" (needs {esc(poll_perm)})" if poll_perm else "")
                     + "; could not read the response, the action may or may not have run")
        reasons["previous row's responses could not be read"] = \
            "stopped: previous row's responses could not be read"
    if not last_rows and not poll_error:
        notes.append(f"no response rows within {poll_timeout_s}s{hint}; the action may or may not "
                     "have run (a quiet long-running action shows no rows until it finishes)")
        reasons["previous row returned no response rows"] = \
            "stopped: previous row returned no response rows"
    if reasons:  # never start a next action on top of one that may not have finished
        why, skip_note = next(iter(reasons.items()))
        more = "" if odd else "; raise --poll-timeout if it needs longer"
        control.request_stop(f"a targeted row ended without a verdict ({why}){more}", skip_note)
    return Outcome(defn.id, defn.risk, "fail" if notes else "pass", ms(), http_code=code,
                   command_id=command_id, execution_id=execution_id,
                   response_count=len(last_rows), note="; ".join(notes))


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

    # Checked immediately before the manifest line and the claim: no new dispatch is claimed after
    # an abort.
    if control.stop.is_set():
        return Outcome(defn.id, defn.risk, "skip", ms(), note=control.skip_note)

    if targeted:
        try:
            manifest.record(defn, target_agent_id, params)
        except Exception as e:
            return Outcome(defn.id, defn.risk, "error", ms(), note=f"manifest: {e}")

    # The progress line is written BEFORE the claim: say() can block on a stalled stdout, and nothing
    # that can block may sit between the claim and the POST, or a stop requested during the stall
    # would still be followed by the POST. A row that then loses the claim says so on the next line.
    n = control.next_dispatch() if targeted else 0
    if targeted:
        say(f"instructions_runner: dispatching {esc(defn.id)} ({n}/{control.targeted_total or '?'})")

    if not control.begin_dispatch(defn.id):   # a stop landed before the claim
        if targeted:
            manifest.not_sent(defn, control.abort_reason or control.skip_note)
            say(f"instructions_runner: {esc(defn.id)} ({n}) not dispatched: a stop was requested")
        return Outcome(defn.id, defn.risk, "skip", ms(), note=control.skip_note)

    try:
        if targeted:
            code, payload = client.execute_instruction(defn.id, params, [target_agent_id])
        else:
            code, payload = client.execute_instruction(defn.id, params)
    except Exception as e:
        if targeted and _may_have_been_sent(e):
            return _dispatch_unknown(defn, control, ms(), f"{type(e).__name__}: {e}", manifest)
        return Outcome(defn.id, defn.risk, "error", ms(), note=f"dispatch: {type(e).__name__}: {e}")
    if targeted:
        control.note_status(code)
        try:  # the server answered: record that, with the ids needed to look the action up
            manifest.accepted(defn, code, payload)
        except Exception as e:
            say(f"instructions_runner: warning: could not record the answer for {esc(defn.id)} "
                f"in the manifest: {esc(e)}", file=sys.stderr)

    if targeted and _post_verdict(code, payload) == "unknown":
        detail = f"HTTP {code} {error_message(payload)}".strip()
        if not isinstance(payload, dict):
            detail += " (body is not a JSON object)"
        return _dispatch_unknown(defn, control, ms(), detail, manifest, payload)

    if code in (200, 202) and not isinstance(payload, dict):
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
    if targeted:
        # Anything that goes wrong from here on leaves an accepted action whose outcome is unknown.
        try:
            return _poll_targeted(client, defn, control, poll_timeout_s, code, payload, ms,
                                  target_agent_id)
        except Exception as e:
            return _dispatch_unknown(defn, control, ms(),
                                     f"after the accepted POST: {type(e).__name__}: {e}", manifest,
                                     payload)
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
    while time.monotonic() < deadline:
        if control.stop.is_set():
            return Outcome(defn.id, defn.risk, "error", ms(), http_code=code,
                           command_id=command_id, execution_id=execution_id,
                           note="in_flight_unknown: dispatch was sent, result not collected")
        last_payload = client.get_responses(command_id)
        responses = last_payload.get("responses", []) if isinstance(last_payload, dict) else []
        response_count = len(responses)
        if response_count > 0:  # the first answer (a targeted row waits for a verdict instead)
            break
        time.sleep(POLL_INTERVAL_S)

    duration_ms = ms()

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
    if args.poll_timeout < 1:
        return (f"--risks {'/'.join(classes)} needs --poll-timeout of at least 1 second (a row "
                "with no time to be polled would never get a verdict)")
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


def dashboard_error(url: str) -> str:
    """Why --dashboard cannot be used, or "". The message is fixed and never echoes the URL.

    Userinfo (user:password@) and a backslash are refused: the loopback check (urlsplit) and the
    HTTP client (urllib.request) parse them differently, so `http://evil.com@127.0.0.1:8080` would
    classify as loopback, and the credentials could reach stderr through an exception text.
    """
    if "\\" in url:
        return "--dashboard must not contain a backslash"
    try:
        netloc = urllib.parse.urlsplit(url).netloc
    except ValueError:
        return "--dashboard is not a valid URL"
    if "@" in netloc:
        return "--dashboard must not carry userinfo (user:password@); pass --user and --password"
    return ""


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
        perm = a4_permission(body)
        msg = error_message(body)
        return None, (f"GET /api/agents answered HTTP {e.code}" + (f": {msg}" if msg else "")
                      + (f" (needs {esc(perm)})" if perm else "")
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


def write_output(path: str, payload: dict, exclusive: bool = False) -> None:
    """Write the summary through a descriptor opened owner-only; a failure only warns.

    The open never follows a symlink where the platform can say so (O_NOFOLLOW) and never blocks on
    a FIFO planted since the pre-flight (O_NONBLOCK: ENXIO at once). A targeted run creates the
    file exclusively (O_EXCL), so a file planted since the pre-flight is never written. An
    untargeted run opens WITHOUT O_TRUNC, checks the descriptor (a regular file with a single
    link, so a hard link to someone else's file is refused) and only then truncates it in place.
    """
    fd = -1
    try:
        flags = (os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0) | (os.O_EXCL if exclusive else 0))
        fd = os.open(path, flags, 0o600)
        if not exclusive:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise OSError("refusing to write: not a regular file with a single link")
            os.ftruncate(fd, 0)
        if getattr(os, "O_NONBLOCK", 0) and hasattr(os, "set_blocking"):
            try:
                os.set_blocking(fd, True)
            except OSError:
                pass   # Windows limits set_blocking to pipes; a regular file never needed it
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1   # the file object owns it now
            fh.write(json.dumps(payload, indent=2))
    except OSError as e:  # never lose the exit code over the summary file
        say(f"instructions_runner: warning: could not write --output {esc(path)}: {esc(e)}",
            file=sys.stderr)
    finally:
        if fd >= 0:
            os.close(fd)


def check_output_writable(path: str, refuse_existing: bool = False) -> str:
    """"" if --output can be written, else why not; a file this created is removed again.

    A targeted run refuses an existing file: it holds the command_id record of an earlier run.
    """
    p = Path(path)
    if os.path.islink(path):
        return f"--output {esc(path)}: refusing to write through a symlink"
    existed = p.exists()
    if existed and not p.is_file():   # a FIFO, device or directory: never opened, never written
        return f"--output {esc(path)} exists and is not a regular file"
    if existed and refuse_existing:
        return (f"--output {esc(path)} already exists: rename it first, it holds the command_id "
                "record of an earlier run")
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


class _SignalGuard:
    """Ignore SIGINT while held (the handler itself drops SIGTERM and SIGBREAK), so a second
    signal cannot cost the --output record.

    Re-entrant: the abort handler takes it first thing, and the --output write takes it again;
    the handlers are put back only when the last holder lets go.
    """

    def __init__(self) -> None:
        self._depth = 0
        self._previous: Any = None
        self._lock = threading.Lock()

    def enter(self) -> None:
        with self._lock:
            if self._depth == 0:
                _INTERRUPT["ignore"] = "1"
                try:
                    self._previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
                except (ValueError, OSError):  # not the main thread
                    self._previous = None
            self._depth += 1

    def exit(self) -> None:
        with self._lock:
            if self._depth == 0:
                return
            self._depth -= 1
            if self._depth == 0:
                _INTERRUPT.pop("ignore", None)
                if self._previous is not None:
                    try:
                        signal.signal(signal.SIGINT, self._previous)
                    except (ValueError, OSError):
                        pass
                    self._previous = None

    def __enter__(self) -> "_SignalGuard":
        self.enter()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.exit()


_GUARD = _SignalGuard()


def run(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parents[2]
    risk_table_path = Path(args.risk_table) if args.risk_table else \
        repo_root / "scripts/test/instructions-risk-classification.json"
    content_dir = Path(args.content_dir) if args.content_dir else \
        repo_root / "content/definitions"

    bad = dashboard_error(args.dashboard)
    if bad:
        say(f"instructions_runner: {bad}", file=sys.stderr)
        return 2
    if args.run_id and not RUN_ID_RE.fullmatch(args.run_id):
        say("instructions_runner: --run-id must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} "
              "(it names the manifest file and the User-Agent)", file=sys.stderr)
        return 2
    bad = targeting_error(args)
    if bad:
        say(f"instructions_runner: {bad}", file=sys.stderr)
        return 2
    if not selected_targeted(args) and (args.target_agent_id or args.confirm_target
                                        or args.allow_remote):
        say("instructions_runner: warning: --target-agent-id, --confirm-target and --allow-remote "
            "apply only to the destructive and forensic classes, and none is selected in --risks: "
            "they are ignored, and every definition run is sent to EVERY agent", file=sys.stderr)

    param_overrides: dict[str, dict[str, Any]] = {}
    if args.params_override:
        try:
            param_overrides = load_param_overrides(args.params_override)
        except ValueError as e:
            say(f"instructions_runner: {e}", file=sys.stderr)
            return 2

    overrides = load_risk_table(risk_table_path)
    all_defs = load_definitions(content_dir, overrides)
    if not all_defs:
        say("instructions_runner: no InstructionDefinitions found "
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

    say(f"instructions_runner: {len(all_defs)} total definitions, "
          f"{len(runnable)} runnable (risks={','.join(sorted(selected_risks))}), "
          f"{len(skipped)} skipped")

    known = {d.id for d in all_defs}
    for stray in sorted(set(param_overrides) - known):
        say(f"instructions_runner: --params-override names no definition: {esc(stray)}",
              file=sys.stderr)

    classes = selected_targeted(args)
    targeted_defs = [d for d in runnable if d.risk in TARGETED_RISKS]
    if classes and not [d for d in targeted_defs if not targeted_skip_reason(d, param_overrides)]:
        say(f"instructions_runner: no {'/'.join(classes)} definition has a --params-override entry "
              "that covers its required parameters (a typo'd id, or an entry missing a required "
              "parameter)" + ("" if args.params_override else "; pass --params-override FILE")
              + "; nothing dispatched", file=sys.stderr)
        return 2

    if args.output:
        bad_output = check_output_writable(args.output, refuse_existing=bool(classes))
        planned_manifest = args.manifest or (
            str(Path.cwd() / f"instructions-runner-{args.run_id}.manifest.jsonl") if classes else "")
        if not bad_output and planned_manifest and \
                os.path.realpath(args.output) == os.path.realpath(planned_manifest):
            bad_output = "--output and --manifest are the same file"
        if bad_output:
            say(f"instructions_runner: {bad_output}", file=sys.stderr)
            return 2

    run_id = args.run_id or uuid.uuid4().hex[:8]
    client = YuzuClient(args.dashboard, timeout=DEFAULT_DISPATCH_TIMEOUT_S, run_id=run_id)
    try:
        client.login(args.user, args.password)
    except Exception as e:
        say(f"instructions_runner: login failed: {esc(e)}", file=sys.stderr)
        return 2

    target_os = ""
    manifest: Manifest | None = None
    parallelism = args.parallelism
    manifest_path = ""
    usable: list[Definition] = []
    if classes:
        agent, why = preflight(client, args)
        if agent is None:
            say(f"instructions_runner: {why}; nothing dispatched", file=sys.stderr)
            return 2
        target_os = str(agent["os"]).lower()
        usable = [d for d in targeted_defs if not targeted_skip_reason(d, param_overrides, target_os)]
        for d in targeted_defs:
            reason = targeted_skip_reason(d, param_overrides, target_os)
            if reason and d.id in param_overrides:
                say(f"instructions_runner: warning: override for {esc(d.id)} skipped: {esc(reason)}",
                      file=sys.stderr)
        if not usable:
            say(f"instructions_runner: no {'/'.join(classes)} definition is eligible on the "
                  f"target (os={esc(target_os)}) with its override; nothing dispatched",
                  file=sys.stderr)
            return 2
        manifest_path = args.manifest or str(Path.cwd() / f"instructions-runner-{run_id}.manifest.jsonl")
        try:
            manifest = Manifest(Path(manifest_path), run_id)
            manifest.start(dashboard=redact_url(args.dashboard), target_agent_id=args.target_agent_id,
                           hostname=str(agent.get("hostname")), os=target_os,
                           agent_version=str(agent.get("agent_version", "?")), classes=classes)
        except FileExistsError:
            say(f"instructions_runner: the manifest {esc(manifest_path)} already exists: "
                "rename it, or pass a different --manifest or --run-id (a manifest left by an "
                "earlier run holds that run's dispatch record: keep it until the target is "
                "checked)",
                file=sys.stderr)
            return 2
        except OSError as e:
            if manifest is not None:   # created by this run (O_EXCL) but run-start was not written
                manifest.discard()     # no stub left to block the retry
                manifest = None
            say(f"instructions_runner: cannot open the manifest {esc(manifest_path)}: {esc(e)}",
                  file=sys.stderr)
            return 2
        except BaseException:   # a Ctrl-C or a bug while run-start is written: same stub rule
            if manifest is not None:
                manifest.discard()
            raise
        # Same-path writers (filesystem.*, registry.*) race at parallelism > 1.
        if parallelism != 1:
            say("instructions_runner: destructive/forensic classes run one at a time "
                  f"(--parallelism {parallelism} ignored)")
            parallelism = 1
        say(f"instructions_runner: TARGETED RUN target={esc(args.target_agent_id)} "
              f"host={esc(agent.get('hostname'))} os={esc(target_os)} "
              f"version={esc(agent.get('agent_version', '?'))} "
              f"dashboard={esc(redact_url(args.dashboard))} classes={','.join(classes)} "
              f"covered={len(usable)} skipped={len(targeted_defs) - len(usable)} "
              f"manifest={esc(manifest_path)}")
        if selected_risks & set(DEFAULT_RISKS):
            say("instructions_runner: warning: mixed run: the safe and mutating definitions in "
                "this run are still sent to EVERY agent; only destructive and forensic go to the "
                "one target", file=sys.stderr)

    targeted_poll = args.poll_timeout if getattr(args, "poll_timeout_explicit", True) \
        else TARGETED_POLL_TIMEOUT_S
    outcomes: list[Outcome] = []
    timed: list[Outcome] = []   # collected rows; their timings are written once dispatch is over
    started_at = time.monotonic()
    aborted = ""
    interrupted = False
    control = RunControl(poll_explicit=getattr(args, "poll_timeout_explicit", True))
    control.targeted_total = len(usable)
    order = {d.id: i for i, d in enumerate(runnable)}   # submission order, for the record
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
        timed.append(outcome)
        if args.verbose or outcome.status in ("fail", "error"):
            say(f"  {outcome.short()}")

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=parallelism)
    pending: set = set()
    abort_hold = False
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
        # Not in collect(): the timing write is a subprocess of up to 5 s, and the worker would
        # dispatch the next row meanwhile while a Ctrl-C could not yet stop it (on Windows the
        # handler only raises in this thread). Every dispatch is over by now, so a Ctrl-C while
        # they are written cuts the timings short and ends the run with 130, rows all reported. An
        # aborted run (the except below) records no timings: its exit should not wait on a
        # subprocess per row.
        if args.run_id:
            try:
                for outcome in timed:
                    db_record_timing(repo_root, args.run_id, args.gate_name, outcome.id,
                                     outcome.duration_ms)
            except KeyboardInterrupt:
                # Every row had finished: they are all reported. The signal still ends the run
                # (exit 130, as everywhere else) and the remaining timings are not recorded.
                interrupted = True
                aborted = _INTERRUPT.get("signal") or "SIGINT"
                say("instructions_runner: interrupted while recording timings: every row had "
                    "finished, the remaining timings were not recorded", file=sys.stderr)
        # Every row is collected: from here a signal must not escape run() before --output is
        # written. _finish releases the hold once the record is on disk.
        _GUARD.enter()
        abort_hold = True
    except BaseException as e:  # KeyboardInterrupt included: stop further dispatch, keep the record
        control.request_stop()   # first: the worker stops even if a second signal lands next
        _GUARD.enter()           # then: a second signal must not interrupt the abort handler
        abort_hold = True
        interrupted = isinstance(e, KeyboardInterrupt)
        aborted = (_INTERRUPT.get("signal") or "SIGINT") if interrupted else type(e).__name__
        control.request_stop()
        pool.shutdown(wait=False, cancel_futures=True)
        say(f"instructions_runner: aborted ({aborted}); dispatch stopped", file=sys.stderr)
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
                say(f"  {outcomes[-1].short()}")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        if manifest is not None:
            manifest.close()

    # Rows cancelled or never started after an abort are reported, so the tally reconciles.
    have = {o.id for o in outcomes}
    for d in runnable:
        if d.id not in have:
            outcomes.append(Outcome(d.id, d.risk, "skip", 0,
                                    note=f"not started: {aborted or control.abort_reason or 'run ended'}"))

    outcomes.sort(key=lambda o: order.get(o.id, len(order)))
    return _finish(args, outcomes, skipped, runnable, classes, control, aborted, interrupted,
                   started_at, run_id, selected_risks, manifest_path, repo_root, abort_hold)


def _finish(args: argparse.Namespace, outcomes: list[Outcome], skipped: list[Definition],
            runnable: list[Definition], classes: list[str], control: RunControl, aborted: str,
            interrupted: bool, started_at: float, run_id: str, selected_risks: set[str],
            manifest_path: str, repo_root: Path, abort_hold: bool = False) -> int:
    """Tally, write --output FIRST, record metrics, then print.

    Signals are ignored only around the --output write itself (the handlers are back before the
    metrics subprocess calls and the printing). say() swallows a dead stdout/stderr, so --output
    and the metrics are written first; a closed stdout may still end the process with exit 120
    when the interpreter flushes it, which fails closed and is never a false 0.
    """
    total_ms = int((time.monotonic() - started_at) * 1000)

    # Tally
    counts = {"pass": 0, "fail": 0, "pending_approval": 0, "error": 0, "skip": 0}
    for o in outcomes:
        counts[o.status] = counts.get(o.status, 0) + 1
    # Risk-filtered defs never enter the executor; add them to the skip tally.
    counts["skip"] += len(skipped)
    # dispatched = the server accepted the POST (HTTP 200: the action was started), or it was
    # sent and the run ended before its result came back; a 202 pending_approval is not.
    dispatched = sum(1 for o in outcomes if o.dispatched and not o.dispatch_unknown)
    # dispatch_unknown: a targeted POST failed after it may have been sent (or an accepted one
    # could not be followed). It is counted on its own and, conservatively, in the targeted metric.
    unknown = sum(1 for o in outcomes if o.dispatch_unknown)
    tgt = [o for o in outcomes if o.risk in TARGETED_RISKS]
    tgt_dispatched = sum(1 for o in tgt if o.dispatched and not o.dispatch_unknown)
    tgt_unknown = sum(1 for o in tgt if o.dispatch_unknown)
    targeted_dispatched = tgt_dispatched + tgt_unknown
    run_skips = sum(1 for o in outcomes if o.status == "skip")
    stopped = bool(control.abort_reason or aborted)
    # Only the destructive/forensic outcomes count: a safe row that ran does not make a
    # targeted run that executed nothing a success.
    nothing_executed = bool(classes) and not targeted_dispatched

    record = {
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
        "aborted": aborted,
        "stop_reason": control.abort_reason,
        "dispatch_unknown": unknown,
        "outcomes": [asdict(o) for o in outcomes],
    }
    try:
        if args.output:
            with _GUARD:   # signals are ignored for this write only
                write_output(args.output, record, exclusive=bool(classes))
    finally:
        if abort_hold:
            _GUARD.exit()

    if args.run_id:
        db_record_metric(repo_root, args.run_id, "instructions_pass",
                          counts["pass"], "count")
        db_record_metric(repo_root, args.run_id, "instructions_fail",
                          counts["fail"], "count")
        db_record_metric(repo_root, args.run_id, "instructions_pending_approval",
                          counts["pending_approval"], "count")
        db_record_metric(repo_root, args.run_id, "instructions_error",
                          counts["error"], "count")
        db_record_metric(repo_root, args.run_id, "instructions_skipped",
                          counts["skip"], "count")
        db_record_metric(repo_root, args.run_id, "instructions_total_ms",
                          total_ms, "ms")
        if classes:
            db_record_metric(repo_root, args.run_id, "instructions_targeted_dispatched",
                              targeted_dispatched, "count")
            db_record_metric(repo_root, args.run_id, "instructions_dispatch_unknown",
                              unknown, "count")
            db_record_metric(repo_root, args.run_id, "instructions_stopped",
                              1 if stopped else 0, "count")

    say(f"instructions_runner: {counts['pass']} pass / "
        f"{counts['fail']} fail / {counts['pending_approval']} pending / "
        f"{counts['error']} error / {counts['skip']} skip "
        f"({total_ms}ms wall)")
    if classes:
        by_class = " ".join(f"{c}={sum(1 for o in outcomes if o.status == 'skip' and o.risk == c)}"
                            for c in classes)
        say(f"instructions_runner: skipped by class: {by_class}")
        say(f"instructions_runner: {dispatched} dispatched, {unknown} dispatch_unknown, "
            f"{counts['pending_approval']} pending_approval (not executed), {run_skips} skipped, "
            f"{counts['fail'] + counts['error']} failed (of {len(runnable)} selected)")
        if nothing_executed:
            say(f"instructions_runner: no destructive/forensic row was executed "
                f"({sum(1 for o in tgt if o.status == 'pending_approval')} pending_approval, "
                f"{sum(1 for o in tgt if o.status == 'skip')} skipped)", file=sys.stderr)
    if stopped:
        remaining = [esc(o.id) for o in outcomes if o.status == "skip"
                     and o.note.startswith(("stopped:", "not started"))]
        say(f"instructions_runner: stopped: {control.abort_reason or aborted}"
            + (f"; manifest: {esc(manifest_path)}" if manifest_path else "")
            + "; the manifest records attempts, not outcomes: check the target before retrying; "
              + ("to resume, rename the manifest and --output (or pass a new --run-id), then pass "
                 if manifest_path else "to resume pass ")
              + "--only-id (one id) or an anchored --match regex for the remaining ids only after "
              "verifying"
            + (f"; not started: {', '.join(remaining[:30])}"
               + (f" (+{len(remaining) - 30} more)" if len(remaining) > 30 else "")
               if remaining else ""),
            file=sys.stderr)

    # Exit code:
    #   0   - all runnable instructions passed (or pending_approval, expected)
    #   1   - one or more fail/error, the run stopped early, or a targeted run executed nothing
    #   2   - infrastructure or configuration failure (login, content-dir empty, opt-in targeting,
    #         --params-override, --run-id, --output, target pre-flight); nothing was dispatched
    #   130 - interrupted (Ctrl-C, Ctrl-Break or SIGTERM)
    if interrupted:
        return 130
    if stopped or counts["fail"] > 0 or counts["error"] > 0 or nothing_executed:
        return 1
    return 0


EPILOG = """\
Exit codes: 0 every dispatched instruction passed (or is pending approval); 1 one or more failed or
errored, the run stopped early, or a targeted run executed nothing (every destructive/forensic row
skipped or pending approval); 2 a configuration, login or pre-flight error with nothing dispatched,
including --poll-timeout below 1 (targeted runs only), --output equal to --manifest, an --output
that is a symlink (POSIX only) or not a regular file, a --dashboard URL with userinfo
(user:password@) or a backslash, or (targeted runs) an --output or a manifest that already exists;
130 interrupted (Ctrl-C, Ctrl-Break or SIGTERM). A failed write of --output at the end only warns.

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
  (--manifest PATH, default instructions-runner-<run-id>.manifest.jsonl) before it is sent.
  The runner polls each targeted row until every response row is terminal or the poll deadline
  passes (--poll-timeout; 120 s for these classes unless it is given). The deadline is checked per
  poll, so it can overrun by up to two polls (one in flight at the deadline plus the one final poll,
  about 20 s). A RUNNING row exists only for flushed output, so a quiet long-running action shows no
  rows at all until it finishes. A row passes only if every response row is SUCCESS with no
  error_detail. A row that ends without a verdict from terminal rows (no rows, rows still running,
  polls failing for any reason, or a row the runner does not recognise) fails and stops further
  dispatch, so a following action never overlaps it; a terminal FAILURE/TIMEOUT/REJECTED row is a
  known outcome and does not stop the run. Ctrl-C, Ctrl-Break (Windows) and SIGTERM stop
  dispatching (exit 130); a dispatch already claimed is reported as in_flight_unknown. Claimed is
  not sent: the stop is checked at the claim and not again once the connection is open, so a
  connect or TLS handshake that stalls past the stop can still transmit that one request to the
  target.

  After a targeted POST was sent only these mean "not executed": any 4xx, a 503 carrying a
  recognised pre-dispatch refusal reason, a 202 pending_approval (approval mode always, role-gated
  for a non-admin caller, or an unrecognised mode; never auto), and a refused connection or
  unresolvable name. HTTP 200 means the server started it. Everything else is dispatch_unknown and
  stops the run (do not re-run blindly): a transport failure after send, any other 5xx, any 3xx, any
  2xx other than 200 and a pending_approval 202, a 202 without pending_approval, the generic 503 "no
  agents reached" (it also covers a failed send on the agent stream and names no command id; #6102),
  and any exception after an accepted POST. Three consecutive 401/403 answers to execute, or
  401/403/503 to a targeted poll, also stop the run. Permissions: Execution:Execute to dispatch,
  Response:Read to poll, Infrastructure:Read for the agent lookup.

  The manifest is an attempt log, not outcome evidence: the first line is run-start, then a dispatch
  line per attempt (the exact params sent: treat it as sensitive; it is created 0600 on POSIX, at
  creation only; .gitignore covers only the default name), an accepted line when the server answers
  it, and a not-sent line when a stop won the race after the dispatch line and the manifest was
  still open (that POST was never made). The manifest is created exclusively: a path that already
  exists (an earlier run, a symlink, a FIFO) is refused with exit 2, so rename it or pass a new
  --run-id. --output is written through an owner-only descriptor (0600 at creation only; an existing
  file keeps its mode) that refuses a symlink (POSIX only); a targeted run creates it exclusively
  and refuses an existing one (rename it first: it holds the command_id record of an earlier run);
  an untargeted run truncates and rewrites an existing --output in place, but only if it is a
  regular single-link file. A SIGKILL, a double signal in the same instant, or SIGHUP (an ssh drop)
  can leave only the manifest. --output holds command_id for accepted rows; rows rebuilt at an
  abort, and answers that land after the manifest was closed, carry no command_id in --output or the
  manifest: check the target by definition id and timestamp. A closed stdout may still end the
  process with exit 120 at interpreter flush: --output and the metrics are written first and it
  fails closed, never a false 0. The stderr list of not-started ids is capped at 30; the rest are in
  --output and the manifest. Forensic rows read behavioural data from the target, and the responses
  are stored in the server's response store.

  Recovery after a stop. In the manifest a dispatch line is an attempt and an accepted line means
  only that the server answered it (http status and, when given, command_id, execution_id or
  approval_id): 200 means the server started it; an accepted line with a 5xx status may have run;
  202 and 4xx were not executed (an open approval ticket may remain). A dispatch line with no
  accepted line may or may not have run, unless a not-sent line follows it (a SIGKILL, a double
  signal in the same instant, or SIGHUP
  can leave only the manifest and no --output). --output holds command_id for every accepted row,
  plus the in_flight_unknown and dispatch_unknown rows (a dispatch_unknown row may have no
  command_id: a POST that failed in flight has none). A definition with no dispatch line was never
  sent. Check the target by hand (and the dashboard's executions) before retrying. To resume, rename
  the old manifest and --output first (a targeted run refuses an existing one of either; a new
  --run-id names a new default manifest), then pass --match with an
  anchored regex for the remaining ids only after verifying, e.g. --match
  '^(device\\.tags\\.clear|device\\.filesystem\\.append)$' (--only-id takes exactly one id).

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
  (device.filesystem.append: the path must already exist on the target. The path above is for a
  Unix target; on a Windows target use a path such as C:\\Windows\\Temp\\yuzu_uat_scratch.txt.)

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
                                 override); start and stop it by hand through the dashboard or
                                 REST with agent_ids
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
                        "dispatch; default: instructions-runner-<run-id>.manifest.jsonl). "
                        "Created exclusively: the path must not already exist")
    p.add_argument("--match", default="",
                   help="restrict to definition IDs matching this regex")
    p.add_argument("--only-id", default="",
                   help="run exactly this one definition id (debugging)")
    p.add_argument("--parallelism", type=int, default=DEFAULT_PARALLELISM)
    p.add_argument("--poll-timeout", type=int, default=None,
                   help=f"per-instruction response poll timeout (default: {DEFAULT_POLL_TIMEOUT_S}s; "
                        f"{TARGETED_POLL_TIMEOUT_S}s for destructive/forensic rows; the deadline can "
                        "overrun by up to two polls, about 20 s). A targeted row that ends without a verdict "
                        "(no rows, still running, polls failing) fails and stops the run; raise it "
                        "for a slow or quiet action")
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
                        "test-runs DB (no per-row timings for an aborted run); also names the "
                        "User-Agent and the manifest (required for destructive/forensic)")
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


_INTERRUPT: dict[str, str] = {}   # which signal raised the KeyboardInterrupt, for the record


def _raise_interrupt(signum: int, frame: Any) -> None:
    """The one handler for SIGINT, SIGTERM and (Windows) SIGBREAK: the first signal raises
    KeyboardInterrupt in the main thread; every later one is ignored, so a second KeyboardInterrupt
    can never land inside the abort handler or a lock wait and cost the --output record."""
    if _INTERRUPT.get("ignore") or _INTERRUPT.get("fired"):
        return
    _INTERRUPT["fired"] = "1"
    for name in ("SIGTERM", "SIGBREAK"):   # SIGBREAK exists on Windows only (Ctrl-Break, CTRL_BREAK_EVENT)
        if signum == getattr(signal, name, None):
            _INTERRUPT["signal"] = name
            break
    else:
        _INTERRUPT["signal"] = "SIGINT"
    raise KeyboardInterrupt


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    _INTERRUPT.clear()
    try:  # operator-visible on a pipe: the banner and each failed row must not sit in a buffer
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError, OSError):
        pass
    previous: dict[int, Any] = {}
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):   # all take the same abort path (summary, --output, 130)
        sig = getattr(signal, name, None)
        try:
            if sig is not None:
                previous[sig] = signal.signal(sig, _raise_interrupt)
        except (ValueError, OSError):  # not the main thread
            pass
    try:
        return run(args)
    except KeyboardInterrupt:
        say("instructions_runner: interrupted", file=sys.stderr)
        return 130
    finally:
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError, TypeError):
                pass


if __name__ == "__main__":
    sys.exit(main())
