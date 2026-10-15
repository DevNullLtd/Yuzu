#!/usr/bin/env python3
"""
instructions_quarantine_survivor.py — detached worker that drives the
quarantine ceremony for /test --instructions-quarantine.

Runs detached from any TTY (started via setsid+nohup by the bash entry,
scripts/test/instructions-quarantine.sh). The point of detaching is so
the survivor outlives:

  (a) Claude Code's TTY (which loses the Anthropic API during the network
      blackout and may either hang or be exited by the operator)
  (b) any shell invoked by Claude's Bash tool
  (c) the survivor's own external network (everything it needs is
      localhost — Yuzu dashboard at http://localhost:8080 stays
      reachable through the quarantine because the plugin auto-
      whitelists 127.0.0.1).

Contract:

  1.  Probe preconditions:
        - quarantine plugin loaded (dispatch security.quarantine.status,
          must succeed and not error)
        - external connectivity present (otherwise the test isn't
          measuring anything meaningful)
        - Yuzu localhost reachable
  2.  Dispatch security.quarantine.isolate with server_ip=127.0.0.1 and
      whitelist_ips=127.0.0.1 (loopback is auto-whitelisted by the
      plugin but we name it explicitly so the post-blackout result-
      shape comparison has a known-input contract).
  3.  Poll for response with rules_applied > 0. If response indicates
      failure or the agent didn't apply rules, abort with a clear note
      and DO NOT trust the firewall state.
  4.  Wait 5s grace, then probe external — MUST fail. If external still
      reachable, the firewall didn't actually close (likely permission
      issue — agent isn't root). Treat as test failure but still call
      release to be safe.
  5.  Probe Yuzu localhost — MUST succeed (the whitelist test).
  6.  Wait 10s, re-probe to confirm sustained blackout.
  7.  Dispatch security.quarantine.release. Poll for success.
  8.  Probe external — MUST succeed again.
  9.  Write results.json to state-dir.
  10. If --launch-resume is set, attempt to spawn a new Terminal with
      `claude --resume <session-id>` via osascript (macOS) or tmux
      (other platforms). Best-effort — failure here doesn't fail the
      ceremony; results.json includes the resume command for manual use.

Failure modes that DO NOT corrupt the box:
  - precondition probe fails -> exit 2, no firewall change
  - dispatch fails -> exit 2, no firewall change
  - response indicates plugin failure -> exit 2, no firewall change
  - blackout didn't actually happen -> exit 1, but call release anyway
  - sustained-blackout probe fails -> exit 1, call release
  - release dispatch fails -> exit 3 (operator action required:
    `pfctl -F all` on macOS as root, or `iptables -F` on Linux as root,
    or `netsh advfirewall reset` on Windows as admin)

This worker NEVER attempts to flush the OS firewall directly — it only
goes through the Yuzu plugin. Direct flush requires passwordless sudo,
which we deliberately don't depend on. If the Yuzu plugin succeeds at
isolate but fails at release, the operator has to intervene; this is
why exit 3 is a distinct status with operator-actionable text in
results.json.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http import cookiejar
from pathlib import Path


EXIT_OK = 0
EXIT_BLACKOUT_INCOMPLETE = 1
EXIT_PRECONDITION_FAIL = 2
EXIT_RELEASE_FAILED = 3
EXIT_INTERNAL = 4

# External destinations to probe during the blackout. Mix of:
#   - 1.1.1.1 / 8.8.8.8: TCP/443 to bare IPs (no DNS required)
#   - github.com / api.anthropic.com: TCP/443 to hostnames (DNS + TCP)
EXTERNAL_PROBES = [
    ("1.1.1.1", 443),
    ("8.8.8.8", 443),
    ("github.com", 443),
    ("api.anthropic.com", 443),
]

LOCALHOST_PROBES = [
    ("127.0.0.1", 8080),   # Yuzu dashboard
    ("127.0.0.1", 50051),  # Gateway agent-facing gRPC (or server agent-facing)
    ("127.0.0.1", 8081),   # Gateway health
]

PROBE_TIMEOUT_S = 3.0
DISPATCH_TIMEOUT_S = 10
POLL_TIMEOUT_S = 30
GRACE_AFTER_ISOLATE_S = 5
SUSTAINED_BLACKOUT_S = 10
GRACE_AFTER_RELEASE_S = 5


# ── data classes ───────────────────────────────────────────────────────────


@dataclass
class ProbeResult:
    target: str
    port: int
    reachable: bool
    duration_ms: int
    err: str = ""


@dataclass
class PhaseResult:
    name: str
    started_at: str = ""
    finished_at: str = ""
    ok: bool = False
    note: str = ""
    probes: list[ProbeResult] = field(default_factory=list)
    response: dict = field(default_factory=dict)


@dataclass
class CeremonyResult:
    started_at: str
    finished_at: str = ""
    overall_status: str = "RUNNING"
    exit_code: int = -1
    phases: list[PhaseResult] = field(default_factory=list)
    note: str = ""
    resume_command: str = ""
    relaunch_attempted: bool = False
    relaunch_succeeded: bool = False
    relaunch_method: str = ""


# ── helpers ────────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def probe_tcp(host: str, port: int, timeout_s: float = PROBE_TIMEOUT_S) -> ProbeResult:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return ProbeResult(host, port, True,
                                int((time.monotonic() - started) * 1000))
    except (socket.timeout, socket.gaierror, OSError) as e:
        return ProbeResult(host, port, False,
                            int((time.monotonic() - started) * 1000),
                            err=type(e).__name__ + ":" + str(e)[:80])


def probe_set(targets: list[tuple[str, int]]) -> list[ProbeResult]:
    return [probe_tcp(h, p) for h, p in targets]


def write_progress(state_dir: Path, payload: dict) -> None:
    (state_dir / "progress.json").write_text(
        json.dumps(payload, indent=2, default=str))


# ── REST client (minimal subset of YuzuClient from instructions_runner) ────


class YuzuClient:
    def __init__(self, base_url: str, timeout: int = DISPATCH_TIMEOUT_S):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.jar = cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def login(self, user: str, password: str) -> None:
        body = urllib.parse.urlencode({"username": user, "password": password}).encode()
        req = urllib.request.Request(
            f"{self.base}/login", data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        with self.opener.open(req, timeout=self.timeout) as resp:
            if resp.status not in (200, 302, 303):
                raise RuntimeError(f"login failed: HTTP {resp.status}")

    def execute(self, def_id: str, params: dict) -> tuple[int, dict]:
        body = json.dumps({"params": {k: str(v) for k, v in params.items()}}).encode()
        req = urllib.request.Request(
            f"{self.base}/api/instructions/{urllib.parse.quote(def_id)}/execute",
            data=body, headers={"Content-Type": "application/json",
                                # Same-site Origin, as the dashboard sends (cookie write).
                                "Origin": self.base})
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except Exception:
                return e.code, {}

    def poll_response(self, command_id: str, timeout_s: int = POLL_TIMEOUT_S) -> dict:
        deadline = time.monotonic() + timeout_s
        last: dict = {}
        while time.monotonic() < deadline:
            req = urllib.request.Request(
                f"{self.base}/api/responses/{urllib.parse.quote(command_id)}")
            try:
                with self.opener.open(req, timeout=self.timeout) as resp:
                    last = json.loads(resp.read() or b"{}")
                if last.get("responses"):
                    return last
            except (urllib.error.HTTPError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        return last


# ── main flow ──────────────────────────────────────────────────────────────


def run(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "survivor.pid").write_text(str(os.getpid()))

    result = CeremonyResult(started_at=_now_iso())
    if args.session_id and args.cwd:
        # populated up-front so it's present even on _abort paths; the
        # operator should always have a copy-pasteable resume in results.json.
        result.resume_command = (f"cd {args.cwd!r} && "
                                  f"claude --resume {args.session_id}")
    write_progress(state_dir, {"phase": "start", "pid": os.getpid()})

    client = YuzuClient(args.dashboard)

    # ── Phase 1: preconditions ────────────────────────────────────────────
    phase = PhaseResult(name="preconditions", started_at=_now_iso())
    try:
        client.login(args.user, args.password)
    except Exception as e:
        phase.note = f"login failed: {e}"
        phase.finished_at = _now_iso()
        result.phases.append(phase)
        return _abort(result, state_dir, EXIT_PRECONDITION_FAIL,
                       "login failed before any firewall change")

    pre_ext = probe_set(EXTERNAL_PROBES)
    pre_loc = probe_set(LOCALHOST_PROBES)
    phase.probes = pre_ext + pre_loc
    if not any(p.reachable for p in pre_ext):
        phase.note = "no external connectivity at start — ceremony is not measuring blackout"
        phase.finished_at = _now_iso()
        result.phases.append(phase)
        return _abort(result, state_dir, EXIT_PRECONDITION_FAIL, phase.note)
    if not all(p.reachable for p in pre_loc):
        unreached = [f"{p.target}:{p.port}" for p in pre_loc if not p.reachable]
        phase.note = f"localhost endpoints unreachable: {unreached}"
        phase.finished_at = _now_iso()
        result.phases.append(phase)
        return _abort(result, state_dir, EXIT_PRECONDITION_FAIL, phase.note)

    # plugin presence: dispatch security.quarantine.status (read-only) and
    # require a non-error response. If the agent doesn't have the
    # quarantine plugin loaded, this catches it without firewalling anything.
    code, payload = client.execute("security.quarantine.status", {})
    if code != 200:
        phase.note = f"quarantine.status dispatch HTTP {code}"
        phase.response = payload
        phase.finished_at = _now_iso()
        result.phases.append(phase)
        return _abort(result, state_dir, EXIT_PRECONDITION_FAIL, phase.note)
    cmd_id = payload.get("command_id", "")
    if not cmd_id:
        phase.note = "quarantine.status returned no command_id"
        phase.response = payload
        phase.finished_at = _now_iso()
        result.phases.append(phase)
        return _abort(result, state_dir, EXIT_PRECONDITION_FAIL, phase.note)

    poll = client.poll_response(cmd_id, timeout_s=15)
    phase.response = poll
    if not poll.get("responses"):
        phase.note = "quarantine.status returned no agent response — plugin not loaded?"
        phase.finished_at = _now_iso()
        result.phases.append(phase)
        return _abort(result, state_dir, EXIT_PRECONDITION_FAIL, phase.note)

    # any response counts as plugin loaded — even if state=disabled; we just
    # need the plugin to answer.
    phase.ok = True
    phase.finished_at = _now_iso()
    result.phases.append(phase)
    write_progress(state_dir, {"phase": "preconditions-ok"})

    # ── Phase 2: isolate ──────────────────────────────────────────────────
    iso_phase = PhaseResult(name="isolate", started_at=_now_iso())
    code, payload = client.execute(
        "security.quarantine.isolate",
        {"server_ip": "127.0.0.1", "whitelist_ips": "127.0.0.1"})
    if code != 200 or not payload.get("command_id"):
        iso_phase.note = f"isolate dispatch HTTP {code}"
        iso_phase.response = payload
        iso_phase.finished_at = _now_iso()
        result.phases.append(iso_phase)
        return _abort(result, state_dir, EXIT_PRECONDITION_FAIL,
                       "isolate dispatch failed before firewall change")

    iso_cmd_id = payload["command_id"]
    iso_poll = client.poll_response(iso_cmd_id, timeout_s=POLL_TIMEOUT_S)
    iso_phase.response = iso_poll

    # Inspect the response output. Yuzu agent responses are formatted as
    # "key1|value1\nkey2|value2..." — we look for `status|ok` and
    # `rules_applied|<n>`.
    isolate_indicates_success = False
    if iso_poll.get("responses"):
        out = iso_poll["responses"][0].get("output", "") or ""
        if "status|ok" in out or "rules_applied|" in out:
            isolate_indicates_success = True

    if not isolate_indicates_success:
        iso_phase.note = ("isolate response did not indicate success — "
                          "firewall likely unchanged")
        iso_phase.finished_at = _now_iso()
        result.phases.append(iso_phase)
        # belt-and-braces: dispatch release just in case partial state was
        # left behind.
        _try_release(client, result, state_dir)
        return _abort(result, state_dir, EXIT_PRECONDITION_FAIL, iso_phase.note)

    iso_phase.ok = True
    iso_phase.finished_at = _now_iso()
    result.phases.append(iso_phase)
    write_progress(state_dir, {"phase": "isolated"})

    # ── Phase 3: confirm blackout ─────────────────────────────────────────
    time.sleep(GRACE_AFTER_ISOLATE_S)

    blackout_phase = PhaseResult(name="confirm-blackout", started_at=_now_iso())
    blackout_ext = probe_set(EXTERNAL_PROBES)
    blackout_loc = probe_set(LOCALHOST_PROBES)
    blackout_phase.probes = blackout_ext + blackout_loc

    any_external_reached = any(p.reachable for p in blackout_ext)
    all_local_reached = all(p.reachable for p in blackout_loc)

    if any_external_reached:
        blackout_phase.note = ("EXTERNAL still reachable after isolate — "
                                "firewall did not actually close. Likely "
                                "agent is not running as root. Releasing "
                                "and aborting.")
        blackout_phase.finished_at = _now_iso()
        result.phases.append(blackout_phase)
        _try_release(client, result, state_dir)
        return _abort(result, state_dir, EXIT_BLACKOUT_INCOMPLETE,
                       blackout_phase.note)

    if not all_local_reached:
        unreached = [f"{p.target}:{p.port}" for p in blackout_loc
                     if not p.reachable]
        blackout_phase.note = (f"localhost endpoints lost after isolate: "
                                f"{unreached} — whitelist failure. Releasing.")
        blackout_phase.finished_at = _now_iso()
        result.phases.append(blackout_phase)
        _try_release(client, result, state_dir)
        return _abort(result, state_dir, EXIT_BLACKOUT_INCOMPLETE,
                       blackout_phase.note)

    blackout_phase.ok = True
    blackout_phase.finished_at = _now_iso()
    result.phases.append(blackout_phase)
    write_progress(state_dir, {"phase": "blackout-confirmed"})

    # ── Phase 4: sustained blackout ───────────────────────────────────────
    time.sleep(SUSTAINED_BLACKOUT_S)

    sustain_phase = PhaseResult(name="sustained-blackout", started_at=_now_iso())
    sustain_ext = probe_set(EXTERNAL_PROBES)
    sustain_phase.probes = sustain_ext
    sustain_phase.ok = not any(p.reachable for p in sustain_ext)
    if not sustain_phase.ok:
        sustain_phase.note = "external became reachable mid-blackout"
    sustain_phase.finished_at = _now_iso()
    result.phases.append(sustain_phase)
    write_progress(state_dir, {"phase": "sustained-checked",
                                "ok": sustain_phase.ok})

    # ── Phase 5: release ──────────────────────────────────────────────────
    rel_phase = PhaseResult(name="release", started_at=_now_iso())
    code, payload = client.execute("security.quarantine.release", {})
    if code != 200 or not payload.get("command_id"):
        rel_phase.note = (f"release dispatch HTTP {code} — operator must "
                          f"clear firewall manually (pfctl/iptables/netsh)")
        rel_phase.response = payload
        rel_phase.finished_at = _now_iso()
        result.phases.append(rel_phase)
        return _abort(result, state_dir, EXIT_RELEASE_FAILED, rel_phase.note)

    rel_cmd_id = payload["command_id"]
    rel_poll = client.poll_response(rel_cmd_id, timeout_s=POLL_TIMEOUT_S)
    rel_phase.response = rel_poll
    rel_indicates_success = False
    if rel_poll.get("responses"):
        out = rel_poll["responses"][0].get("output", "") or ""
        # The release plugin emits `status|released` (or `status|ok`
        # legacy form, or `status|released|note|...` when /etc/pf.conf
        # restoration falls back to `pfctl -d`). Match any of these.
        if ("status|ok" in out
                or "status|released" in out
                or "status|disabled" in out):
            rel_indicates_success = True

    if not rel_indicates_success:
        rel_phase.note = ("release dispatched but response did not indicate "
                          "success — firewall may be in a partial state. "
                          "Operator must verify with `pfctl -s rules` / "
                          "`iptables -L` / `netsh advfirewall show rule "
                          "name=YuzuQuarantine_*`")
        rel_phase.finished_at = _now_iso()
        result.phases.append(rel_phase)
        return _abort(result, state_dir, EXIT_RELEASE_FAILED, rel_phase.note)

    rel_phase.ok = True
    rel_phase.finished_at = _now_iso()
    result.phases.append(rel_phase)
    write_progress(state_dir, {"phase": "released"})

    # ── Phase 6: recovery probe ───────────────────────────────────────────
    time.sleep(GRACE_AFTER_RELEASE_S)
    rec_phase = PhaseResult(name="recovery", started_at=_now_iso())
    rec_ext = probe_set(EXTERNAL_PROBES)
    rec_phase.probes = rec_ext
    rec_phase.ok = any(p.reachable for p in rec_ext)
    if not rec_phase.ok:
        rec_phase.note = ("external still unreachable post-release — "
                          "firewall not fully cleared. Operator must verify.")
    rec_phase.finished_at = _now_iso()
    result.phases.append(rec_phase)

    # ── Final ────────────────────────────────────────────────────────────
    overall_ok = all(p.ok for p in result.phases)
    result.overall_status = "PASS" if overall_ok else "FAIL"
    result.exit_code = EXIT_OK if overall_ok else EXIT_BLACKOUT_INCOMPLETE
    result.finished_at = _now_iso()

    if args.launch_resume and args.session_id and args.cwd:
        _attempt_relaunch(result, args)

    _write_results(result, state_dir)
    return result.exit_code


def _try_release(client: YuzuClient, result: CeremonyResult, state_dir: Path) -> None:
    """Best-effort quarantine release after a failed isolate or sustained-
    blackout failure. Records an additional 'recovery-release' phase so the
    final results.json shows what happened during emergency cleanup.
    """
    rel = PhaseResult(name="emergency-release", started_at=_now_iso())
    try:
        code, payload = client.execute("security.quarantine.release", {})
        rel.response = payload
        if code == 200 and payload.get("command_id"):
            poll = client.poll_response(payload["command_id"], timeout_s=15)
            rel.response = poll
            out = (poll.get("responses") or [{}])[0].get("output", "") or ""
            rel.ok = ("status|ok" in out
                      or "status|released" in out
                      or "status|disabled" in out)
        else:
            rel.note = f"emergency release dispatch HTTP {code}"
    except Exception as e:
        rel.note = f"emergency release exception: {e}"
    rel.finished_at = _now_iso()
    result.phases.append(rel)


def _abort(result: CeremonyResult, state_dir: Path,
            exit_code: int, note: str) -> int:
    result.overall_status = "FAIL"
    result.exit_code = exit_code
    result.note = note
    result.finished_at = _now_iso()
    _write_results(result, state_dir)
    return exit_code


def _write_results(result: CeremonyResult, state_dir: Path) -> None:
    payload = asdict(result)
    (state_dir / "results.json").write_text(json.dumps(payload, indent=2,
                                                         default=str))


def _attempt_relaunch(result: CeremonyResult, args: argparse.Namespace) -> None:
    """Best-effort: open a new Terminal window and run `claude --resume <id>`.

    Failure is non-fatal — the resume command is in results.json and the
    operator can run it manually. We try osascript on macOS, then tmux,
    then give up.
    """
    result.relaunch_attempted = True

    # macOS: osascript spawns a new Terminal window
    if sys.platform == "darwin":
        try:
            cmd = (f'cd {args.cwd} && claude --resume {args.session_id}')
            script = (f'tell application "Terminal"\n'
                      f'  do script "{cmd}"\n'
                      f'  activate\n'
                      f'end tell')
            subprocess.run(["osascript", "-e", script], check=True,
                            timeout=10, capture_output=True)
            result.relaunch_method = "osascript-Terminal"
            result.relaunch_succeeded = True
            return
        except Exception as e:
            result.note = (result.note + " | " if result.note else "") + \
                          f"osascript launch failed: {e}"

    # Cross-platform: tmux detached session
    try:
        cmd = f"cd {args.cwd!r} && claude --resume {args.session_id}"
        subprocess.run(["tmux", "new-session", "-d",
                         "-s", "yuzu-claude-resume",
                         "bash", "-lc", cmd],
                        check=True, timeout=10, capture_output=True)
        result.relaunch_method = "tmux-detached"
        result.relaunch_succeeded = True
        return
    except FileNotFoundError:
        pass
    except Exception as e:
        result.note = (result.note + " | " if result.note else "") + \
                      f"tmux launch failed: {e}"

    result.relaunch_method = "none-available"


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--state-dir", required=True)
    p.add_argument("--dashboard", required=True)
    p.add_argument("--user", default="admin")
    p.add_argument("--password", required=True)
    p.add_argument("--session-id", default="",
                   help="Claude Code session UUID for --resume")
    p.add_argument("--cwd", default="",
                   help="working directory to cd into before claude --resume")
    p.add_argument("--launch-resume", action="store_true",
                   help="attempt to spawn a new terminal with `claude --resume` "
                        "after the ceremony completes")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        return run(args)
    except KeyboardInterrupt:
        print("survivor: interrupted — attempting emergency release",
              file=sys.stderr)
        try:
            client = YuzuClient(args.dashboard)
            client.login(args.user, args.password)
            client.execute("security.quarantine.release", {})
        except Exception:
            pass
        return EXIT_INTERNAL
    except Exception as e:
        print(f"survivor: internal error: {e}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
