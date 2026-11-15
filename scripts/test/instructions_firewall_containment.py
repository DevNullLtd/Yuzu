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
     `firewall.quarantine` (with a `ttl_seconds` dead-man limit), require the status to read
     `active` (`active_unproven` is accepted, with a note, when no --probe-target was given: the plugin
     only calls a containment proven when it could probe a non-loopback target before and after), then ALWAYS dispatch
     `firewall.release` (also on any failure; SIGINT/SIGTERM/SIGHUP are noted and the release still
     runs) and require the status to read `inactive` again.

DO NOT RUN THE CONTAINMENT STEP ON A REMOTE / SSH-ONLY HOST. It briefly blocks all traffic except
the allow set (loopback plus the agent's control channel). It refuses to run when an SSH session
is detected (SSH_CONNECTION / SSH_CLIENT / SSH_TTY) unless --i-have-console-access is given, and
never runs without --apply-containment. The SSH check reads environment variables that `sudo` and a
long-lived tmux/screen session can drop, so --i-have-console-access is the real control. The dashboard
must be loopback (this host), or the release could not reach it while contained. --ttl-seconds is 0 (none) or at least 300, so the limit outlasts the release
confirmation. Run it on a local box with a keyboard and a screen.

Exit codes: 0 passed; 1 a check failed; 2 precondition or usage error (nothing changed);
3 release could not be confirmed: clear the firewall by hand (see agents/plugins/firewall/README.md).

--agent-id is required with --apply-containment (it never contains "the first agent listed"); a probe-only
run picks the agent itself only when exactly one is registered. A login that does not yield an authenticated
session exits 2.

The ceremony dispatches `quarantine`, `release` and `quarantine_status` only. `quarantine_allow` (the
fourth containment action) is not exercised here: it has no ceremony coverage, only its unit tests.

The status is read from the exact `status|<token>` row of the agent's reply, taken only from a SUCCESS
(status 1) row once no row is still RUNNING (status 0); FAILURE, TIMEOUT and REJECTED rows are no answer. The flow is covered
against a recording fake (tests/test_firewall_containment_ceremony.py); the live apply/release round
trip needs a UAT stack on a local host and has not been run live on any OS yet.
"""
from __future__ import annotations

import argparse
import contextlib
import ipaddress
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
POLL_APPLY_S = 90
RELEASE_READS = 4
# The limit must outlast the ceremony's own polling budget while contained: the status read after the apply
# (2 s + 20 s), the release dispatch (90 s), then RELEASE_READS re-reads (4 x (2 s + 20 s)) = 200 s, plus
# the apply's own wait (up to 90 s, which can run past the point the plugin starts the clock) = 290 s.
# Each poll deadline is checked between reads, so a degraded dashboard can add up to one 30 s read per
# poll: the dead-man limit is the backstop for that tail, not a promise it cannot occur.
MIN_TTL_S = 300
# CommandResponse.status (proto/yuzu/agent/v1/agent.proto): only SUCCESS is an answer; RUNNING is an
# interim row to poll past; FAILURE, TIMEOUT and REJECTED carry no usable status.
STATUS_RUNNING, STATUS_SUCCESS = 0, 1


class LoginError(RuntimeError):
    """The dashboard did not give this client an authenticated session."""


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
        try:
            self.opener.open(req, timeout=self.timeout).close()
            # A rejected login can still answer 200/302 (the login page), so the session is proven by an
            # authenticated read, never by the status of the form POST.
            self.get_json("/api/agents")
        except (OSError, ValueError) as e:  # URLError/HTTPError are OSError; a login page is not JSON
            raise LoginError(f"login failed: {e}") from e

    def get_json(self, path: str):
        with self.opener.open(urllib.request.Request(self.base + path), timeout=self.timeout) as r:
            return json.loads(r.read() or b"{}")

    def post_json(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(self.base + path, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json", "Origin": self.base})
        with self.opener.open(req, timeout=self.timeout) as r:
            return json.loads(r.read() or b"{}")

    def poll_response(self, command_id: str, timeout_s: int = POLL_S) -> dict:
        """The responses once every row has left RUNNING (a RUNNING row is interim, not the answer), or
        whatever was last read when the deadline passes."""
        deadline, last = time.monotonic() + timeout_s, {}
        while time.monotonic() < deadline:
            try:
                last = self.get_json(f"/api/responses/{urllib.parse.quote(command_id)}")
                rows = [r for r in last.get("responses") or [] if isinstance(r, dict)]
                if rows and not any(r.get("status") == STATUS_RUNNING for r in rows):
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
    # an apply or release can take the plugin up to a minute plus its verify: wait for the answer
    wait = POLL_APPLY_S if action in ("quarantine", "release") else POLL_S
    return client.poll_response(cid, timeout_s=wait) if cid else {}


_STATUS_ROW = re.compile(r"status\|([a-z_]+)(?:\|.*)?")


def status_token(client: Client, agent_id: str) -> str:
    """The `status|<token>` row of this agent's `quarantine_status` output, exactly: `active`, `inactive`,
    `active_unproven`, `partial`, `degraded`. Only a whole output LINE of a SUCCESS (status 1) response row
    that names this agent counts: a RUNNING, FAILURE, TIMEOUT or REJECTED row, a row with no integer status,
    a substring of an error string and another agent's row never do, and the rows must agree. Empty when
    no agent answered -- never a guess ("inactive" contains "active")."""
    answer = dispatch(client, agent_id, "quarantine_status", {})
    tokens = set()
    for r in answer.get("responses") or []:
        status = r.get("status") if isinstance(r, dict) else None
        if (not isinstance(r, dict) or r.get("agent_id") != agent_id or type(status) is not int
                or status != STATUS_SUCCESS or not isinstance(r.get("output"), str)):
            continue
        for line in r["output"].splitlines():
            m = _STATUS_ROW.fullmatch(line.strip().lower())
            if m:
                tokens.add(m.group(1))
    return tokens.pop() if len(tokens) == 1 else ""


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
    """Dispatch `firewall.release` and require an explicit `inactive` answer, re-reading the status a few
    times (a slow apply can still be finishing). Any error, or no answer, is NOT a confirmation (exit 3)."""
    try:
        dispatch(client, agent_id, "release", {})
        for _ in range(RELEASE_READS):
            time.sleep(2)
            if status_token(client, agent_id) == "inactive":
                return True
        return False
    except Exception as e:  # noqa: BLE001 - an unconfirmed release is exit 3, whatever stopped it
        print(f"release call failed: {e}", file=sys.stderr)
        return False


def dashboard_is_local(dashboard: str) -> bool:
    """The release is dispatched through the dashboard from this host while it is contained, and the
    allow set always carries loopback: so the dashboard must be loopback (the ceremony runs on a local
    box next to its UAT stack)."""
    try:
        host = (urllib.parse.urlparse(dashboard).hostname or "").lower()
        return host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--dashboard", required=True)
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default=os.environ.get("YUZU_PASSWORD", ""),
                   help="dashboard password (default: $YUZU_PASSWORD; an argv value is visible in the process list)")
    p.add_argument("--agent-id", default="")
    p.add_argument("--exceptions", default="127.0.0.1", help="allow-set entries for the containment step")
    p.add_argument("--probe-target", default="", help="ip:port the plugin probes before/after the apply; without it the status reads active_unproven")
    p.add_argument("--ttl-seconds", type=int, default=300, help="dead-man time limit on the containment (0 = none; the plugin's minimum is 60)")
    p.add_argument("--apply-containment", action="store_true", help="really contain and release (guarded)")
    p.add_argument("--i-have-console-access", action="store_true", help="allow --apply-containment from an SSH session")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    why = refusal(args)
    if why:
        print(f"refused: {why}", file=sys.stderr)
        return EXIT_PRECONDITION
    if args.apply_containment and 0 < args.ttl_seconds < MIN_TTL_S:
        print(f"refused: --ttl-seconds below {MIN_TTL_S} could end the containment before the release "
              "confirmation finishes (use 0 for none)", file=sys.stderr)
        return EXIT_PRECONDITION
    if args.apply_containment and not args.agent_id:
        print("refused: --agent-id is required with --apply-containment (the ceremony contains exactly the "
              "host you name, never the first agent the dashboard lists)", file=sys.stderr)
        return EXIT_PRECONDITION
    if args.apply_containment and not dashboard_is_local(args.dashboard):
        print("refused: the dashboard must be loopback (http://127.0.0.1:<port>) so the release can reach it "
              "while this host is contained", file=sys.stderr)
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
            if len(agents or []) != 1:
                print(f"precondition failed: {len(agents or [])} agents registered; pass --agent-id "
                      "(the probe picks one only when exactly one is registered)", file=sys.stderr)
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
                params = {"exceptions": args.exceptions}
                if args.ttl_seconds > 0:
                    params["ttl_seconds"] = args.ttl_seconds
                if args.probe_target:
                    params["probe_target"] = args.probe_target
                dispatch(client, agent_id, "quarantine", params)
                time.sleep(2)
                token = status_token(client, agent_id)
                ok = token == "active" or (token == "active_unproven" and not args.probe_target)
                if token == "active_unproven" and ok:
                    print("note: contained but unproven (no --probe-target); pass one to require a verified containment")
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
    except LoginError as e:
        print(f"precondition failed: {e}", file=sys.stderr)
        return EXIT_PRECONDITION
    except KeyboardInterrupt:
        return EXIT_FAIL
    except Exception as e:  # noqa: BLE001 - a script exit code, not a library
        print(f"failed: {e}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
