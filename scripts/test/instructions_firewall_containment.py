#!/usr/bin/env python3
"""Regression for the firewall plugin's privilege grants on a UAT stack (privilege model step 6).

`firewall.quarantine` / `release` run `sudo -n nft ...` / `sudo -n pfctl ...` under the grants that
scripts/install-agent-user.sh writes (docs/agent-privilege-model.md, "How to add a new privileged
plugin", step 6). This script is that regression:

  1. PRECONDITION: `scripts/install-agent-user.sh --check` must exit 0 (the account and every
     grant are in place). Otherwise exit 2 and nothing is dispatched.
  2. PROBE (always): log in, find the agent, dispatch the read-only `firewall.quarantine_status`
     and require an agent answer, so a missing plugin or grant shows up without changing a rule.
  3. CONTAINMENT (only with --apply-containment): refuse (exit 2) when the host already reads
     anything but `inactive` (the release would lift a containment this run did not apply); dispatch
     `firewall.quarantine`, require the status to read `active`, then ALWAYS dispatch
     `firewall.release` (also on any failure; SIGINT/SIGTERM/SIGHUP are noted and the release still
     runs) and require the status to read `inactive` again.

DO NOT RUN THE CONTAINMENT STEP ON A REMOTE / SSH-ONLY HOST. It briefly blocks all traffic except
the allow set (loopback plus the agent's control channel). It refuses to run when an SSH session
is detected (SSH_CONNECTION / SSH_CLIENT / SSH_TTY) unless --i-have-console-access is given, and
never runs without --apply-containment. Run it on a local box with a keyboard and a screen.

Exit codes: 0 passed; 1 a check failed; 2 precondition or usage error (nothing changed);
3 release could not be confirmed: clear the firewall by hand (see agents/plugins/firewall/README.md).

The status is read from the exact `status|<token>` row of the agent's reply. The flow is covered
against a recording fake (tests/test_firewall_containment_ceremony.py); the live apply/release round
trip needs a UAT stack on a local host and has not been run on every OS.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http import cookiejar
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
INSTALL = REPO / "scripts" / "install-agent-user.sh"
EXIT_OK, EXIT_FAIL, EXIT_PRECONDITION, EXIT_RELEASE_FAILED = 0, 1, 2, 3
SSH_VARS = ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")
POLL_S = 20


class Client:
    """Minimal dashboard client (login by form, cookie jar, JSON POST/GET, response poll). Kept here, not
    imported from the legacy quarantine ceremony, so removing that plugin's scripts cannot break this one."""

    def __init__(self, base: str, timeout: int = 30):
        self.base, self.timeout = base.rstrip("/"), timeout
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookiejar.CookieJar()))

    def login(self, user: str, password: str) -> None:
        body = urllib.parse.urlencode({"username": user, "password": password}).encode()
        req = urllib.request.Request(f"{self.base}/login", data=body,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        with self.opener.open(req, timeout=self.timeout) as r:
            if r.status not in (200, 302, 303):
                raise RuntimeError(f"login failed: HTTP {r.status}")

    def get_json(self, path: str):
        with self.opener.open(urllib.request.Request(self.base + path), timeout=self.timeout) as r:
            return json.loads(r.read() or b"{}")

    def post_json(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(self.base + path, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json", "Origin": self.base})
        with self.opener.open(req, timeout=self.timeout) as r:
            return json.loads(r.read() or b"{}")

    def poll_response(self, command_id: str, timeout_s: int = POLL_S) -> dict:
        deadline, last = time.monotonic() + timeout_s, {}
        while time.monotonic() < deadline:
            try:
                last = self.get_json(f"/api/responses/{urllib.parse.quote(command_id)}")
                if last.get("responses"):
                    return last
            except (urllib.error.HTTPError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        return last


def refusal(args: argparse.Namespace, env=os.environ) -> str | None:
    """Why this run must not start, or None. Pure so the tests bind it without a network."""
    if platform.system() not in ("Linux", "Darwin"):
        return "POSIX hosts only (use scripts/install-agent-user.ps1 -Check on Windows)"
    if args.apply_containment and not args.i_have_console_access:
        ssh = [v for v in SSH_VARS if env.get(v)]
        if ssh:
            return f"an SSH session is detected ({', '.join(ssh)}): containment could lock you out"
    return None


def install_check() -> tuple[int, str]:
    r = subprocess.run(["bash", str(INSTALL), "--check"], capture_output=True, text=True, timeout=120)
    lines = (r.stdout + r.stderr).strip().splitlines()
    return r.returncode, lines[-1] if lines else ""


def dispatch(client: Client, agent_id: str, action: str, params: dict) -> dict:
    sent = client.post_json("/api/command", {"plugin": "firewall", "action": action, "agent_ids": [agent_id],
                                             "params": {k: str(v) for k, v in params.items()}})
    cid = sent.get("command_id", "")
    return client.poll_response(cid) if cid else {}


_STATUS_ROW = re.compile(r"\bstatus\|([a-z_]+)")


def status_token(client: Client, agent_id: str) -> str:
    """The `status|<token>` row of one `quarantine_status` answer, exactly: `active`, `inactive`,
    `active_unproven`, `partial`, `degraded`. Empty when no agent answered (an empty response envelope, an
    error) -- never a guess from a substring ("inactive" contains "active")."""
    m = _STATUS_ROW.search(json.dumps(dispatch(client, agent_id, "quarantine_status", {})).lower())
    return m.group(1) if m else ""


@contextlib.contextmanager
def _signals(handler, sigs):
    """Install `handler` for `sigs` for the span, then put the previous handlers back (the tests call
    main() in-process, so nothing may stay ignored after it returns)."""
    old = {sig: signal.signal(sig, handler) for sig in sigs}
    try:
        yield
    finally:
        for sig, prev in old.items():
            signal.signal(sig, prev)


def release_and_confirm(client: Client, agent_id: str) -> bool:
    """Dispatch `firewall.release` and require an explicit `inactive` answer. Any error, or no answer, is
    NOT a confirmation (exit 3)."""
    try:
        dispatch(client, agent_id, "release", {})
        time.sleep(2)
        return status_token(client, agent_id) == "inactive"
    except Exception as e:  # noqa: BLE001 - an unconfirmed release is exit 3, whatever stopped it
        print(f"release call failed: {e}", file=sys.stderr)
        return False


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--dashboard", required=True)
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="")
    p.add_argument("--agent-id", default="")
    p.add_argument("--exceptions", default="127.0.0.1", help="allow-set entries for the containment step")
    p.add_argument("--apply-containment", action="store_true", help="really contain and release (guarded)")
    p.add_argument("--i-have-console-access", action="store_true", help="allow --apply-containment from an SSH session")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    why = refusal(args)
    if why:
        print(f"refused: {why}", file=sys.stderr)
        return EXIT_PRECONDITION
    rc, last = install_check()
    if rc != 0:
        print(f"precondition failed: install-agent-user.sh --check exited {rc}: {last}", file=sys.stderr)
        return EXIT_PRECONDITION
    base = args.dashboard.rstrip("/")
    client = Client(base)
    try:
        client.login(args.user, args.password)
        agent_id = args.agent_id
        if not agent_id:
            agents = client.get_json("/api/agents")
            agents = agents.get("agents", agents) if isinstance(agents, dict) else agents
            if not agents:
                print("precondition failed: no agent registered", file=sys.stderr)
                return EXIT_PRECONDITION
            agent_id = agents[0].get("agent_id") or agents[0].get("id", "")
        before = status_token(client, agent_id)
        if not before:
            print("precondition failed: firewall.quarantine_status got no agent answer (plugin or grant missing?)", file=sys.stderr)
            return EXIT_PRECONDITION
        print("probe ok: firewall.quarantine_status answered")
        if not args.apply_containment:
            print("probe-only: nothing was changed (--apply-containment runs the live ceremony)")
            return EXIT_OK
        if before != "inactive":
            print(f"precondition failed: the host already reads status={before}; the ceremony would "
                  "release a containment it did not apply. Release it by hand first.", file=sys.stderr)
            return EXIT_PRECONDITION
        # From here a containment may be on the host. SIGINT/SIGTERM/SIGHUP only NOTE the signal, for the
        # whole span through the release: nothing can kill the process or skip the release in a gap, and
        # the exit code reports the interruption once the release is confirmed. (The calls in the span are
        # bounded by their own timeouts, so a signal waits at most one poll.)
        got = []
        ok = False
        err = None
        with _signals(lambda signum, _frame: got.append(signum), (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)):
            try:
                dispatch(client, agent_id, "quarantine", {"exceptions": args.exceptions})
                time.sleep(2)
                ok = status_token(client, agent_id) == "active"
                print(f"contained: {ok}")
            except BaseException as e:  # noqa: BLE001 - the release below must run for ANY failure
                err = e
            # ALWAYS release, then re-raise whatever stopped the containment step.
            released = release_and_confirm(client, agent_id)
        print(f"released: {released}")
        if not released:
            print("RELEASE NOT CONFIRMED: clear the firewall by hand", file=sys.stderr)
            return EXIT_RELEASE_FAILED
        if got:
            print(f"interrupted by signal {got[0]}; containment released", file=sys.stderr)
            return EXIT_FAIL
        if err is not None:
            raise err
        return EXIT_OK if ok else EXIT_FAIL
    except KeyboardInterrupt:
        return EXIT_FAIL
    except Exception as e:  # noqa: BLE001 - a script exit code, not a library
        print(f"failed: {e}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
