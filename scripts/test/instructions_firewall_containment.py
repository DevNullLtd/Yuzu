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
     `firewall.quarantine` (with a `ttl_seconds` dead-man limit), leave a host alone whose apply answer
     says it was already contained (`already_active`, `repaired`, `incomplete_apply_converged`: not this
     run's containment, so it is never released), require the status to read
     `active` (`active_unproven` is accepted, with a note, when no --probe-target was given: the plugin
     only calls a containment proven when it could probe a non-loopback target before and after), then ALWAYS dispatch
     `firewall.release` (also on any failure; SIGINT/SIGTERM/SIGHUP are noted and the release still
     runs; a release is dispatched again, up to 3 times in all, while the host reads inactive but no release
     of this run is proven, e.g. after a refused one) and require the status to read `inactive` again.

DO NOT RUN THE CONTAINMENT STEP ON A REMOTE / SSH-ONLY HOST. It briefly blocks all traffic except
the allow set (loopback plus the agent's control channel). It refuses to run when an SSH session
is detected (SSH_CONNECTION / SSH_CLIENT / SSH_TTY) unless --i-have-console-access is given, and
never runs without --apply-containment. The SSH check reads environment variables that `sudo` and a
long-lived tmux/screen session can drop, so --i-have-console-access is the real control. The dashboard
URL must be loopback (this host), or the run must be --remote (below); that checks the URL, not the
network path, so it is also a precondition that the server and its stores are reachable over loopback
while this host is contained (a server whose Postgres is published from a Docker network is not: the
containment would cut it off and the release could not be dispatched, exit 3). --ttl-seconds must be
at least 300 (default 900; 0 and negative values are refused in apply mode), so the limit outlasts the
release confirmation and still ends a containment after a SIGKILL or a power loss. Run it on a local box
with a keyboard and a screen. The login user needs read access to /api/agents (Infrastructure:Read),
which is how a login is proven.

ONE HOST CANNOT RUN THE CONTAINMENT. A containment whose control endpoint is the host itself is refused
by the agent (`refused|self_host`, exit 2 here, nothing changed, nothing released), by design: the server
it must keep reaching would be the host that is cut off. So an --apply-containment run with the agent and
the server on one host (a loopback dashboard against this host's own agent) ends that way whenever the
agent's control endpoint is one of the host's own addresses, loopback included; a containment round trip
needs the server on ANOTHER host and --remote. The agent compares ADDRESSES only: a server in a container
or VM on this host, reached at a bridge address, is not one of them (see the standing ruling below).
Any other refusal the agent answers to the apply (`own_addresses_unreadable` among them) is not a
precondition of this script: it ends exit 1 with the `NOT released` message, nothing released.

--remote: this script runs on the server's host (or any other host), and the agent it contains is on a
DIFFERENT machine that this script does not run on, so nothing here is cut off and the dashboard may be
any address. With --apply-containment it needs all of: --agent-id, --agent-hostname (the agent's own
hostname, typed by the operator: it must equal the hostname the agent reported to the server, be the one
registered agent under that name, and not be one of THIS machine's names or localhost) and
--i-have-console-access-to-the-agent (the operator is at the agent's console, so a release the network
cannot deliver can still be done by hand). The SSH check does not apply (this machine is not contained),
and the local install check is not run: `install-agent-user.sh --check` on the AGENT host is the
operator's precondition. --agent-hostname and --i-have-console-access-to-the-agent without --remote are a
usage error (exit 2). The release is dispatched through the server and depends on the agent's control
endpoint staying reachable while it is contained; the time limit (--ttl-seconds) is the backstop.

Exit codes: 0 passed; 1 a check failed; 2 precondition or usage error (nothing changed);
3 release could not be confirmed: clear the firewall by hand (see docs/user-manual/security-hardening.md,
"A device that is its own server is never contained").

--agent-id is required with --apply-containment (it never contains "the first agent listed") and must be
registered exactly once under one of this machine's hostnames (full name, case-insensitive; a first-label
match, `localhost` and an empty name never bind); a probe-only run picks the agent itself only when
exactly one is registered. A passing apply also needs a release command of its own to succeed and undo
something: an `inactive` read after a refused release, or after the time limit or another actor had
already released the host (`no_state_record`, `state_unreadable`), exits 1 ("release unproven"), not 0.
A login that does not yield an authenticated session exits 2. The host binding trusts the hostname each agent
reported about itself: it stops a mistyped or remote agent id, it is not an authentication (a remote clone with
the same default name, while this host's own agent is not registered, would bind). The release is never skipped
by a failing terminal: every message after the apply goes through a print that cannot raise.

An --apply-containment run holds an exclusive lock on yuzu_firewall_containment_ceremony.lock in the temp
directory from before its first dispatch until its release is confirmed: a second run started while it is
held exits 2 with nothing dispatched, so two runs cannot release each other's containment. The lock file is
in the temp directory, which on macOS is per user (runs by different users, or under sudo, do not exclude
each other), and on Linux a lock file another user created there makes this run refuse to start (`could not
open the run lock`, exit 2: a different message from a held lock).

The ceremony dispatches `quarantine`, `release` and `quarantine_status` only. `quarantine_allow` (the
fourth containment action) is not exercised here: it has no ceremony coverage, only its unit tests.

--record PATH writes one JSON object when the run ends, on every exit path of a run (UTC time, mode local or
remote, agent id, hostname, the statuses read in order, contained and released, the exit code, the
agent's refusal token if it refused): the retained pass or fail record of the run. The file is created
for this run alone, mode 0600: a PATH that already exists (a file or a symlink) is refused (exit 2,
nothing dispatched) and left as it was, so a second run never replaces the record of the first.

A command that cannot be dispatched (the server refuses the POST, for example a user who is not an
administrator) ends `dispatch refused: <reason>` (exit 1): nothing was applied, so there is nothing to
release and RELEASE NOT CONFIRMED (exit 3) is not printed. That holds for the refused apply, not for a
release the server refuses AFTER an apply went out: the host may be contained, so that release is
retried and can still end exit 3. A status read whose row stays RUNNING with no
change for NO_PROGRESS_POLLS polls in a row ends that read early (`no progress`) instead of consuming
its whole budget; an apply or release is never cut short that way, because its row legitimately stays
RUNNING while the plugin works.

Standing ruling (the URL-versus-path precondition of #7860, item d): the agent refuses
(`refused|self_host`) when its control endpoint is one of its host's own addresses, loopback included,
and a --remote run is not on the contained host, so in both cases this script's own calls cannot be cut
by its own apply. One case remains: a server in a container or VM on this host, reached at a bridge
address, is not an own address, so a local run does contain the host and its loopback dashboard calls
can then be cut (the hazard described above). There the precondition above is the operator's to meet,
and the time limit (--ttl-seconds) is the backstop. No authenticated-read probe is added.

The status is read from the exact `status|<token>` row of the agent's reply, taken only from a SUCCESS
(status 1) row once no row is still RUNNING (status 0); FAILURE, TIMEOUT and REJECTED rows are no answer. The flow is covered
against a recording fake (tests/test_firewall_containment_ceremony.py); the live apply/release round
trip needs a UAT stack whose server is on another host than the agent it contains (--remote).
"""
from __future__ import annotations

import argparse
import contextlib
import datetime
import http.client
import ipaddress
import json
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: refusal() stops the run before any lock is needed
    fcntl = None

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import instructions_runner  # noqa: E402  (the shared dashboard client)

REPO = HERE.parent.parent
INSTALL = REPO / "scripts" / "install-agent-user.sh"
EXIT_OK, EXIT_FAIL, EXIT_PRECONDITION, EXIT_RELEASE_FAILED = 0, 1, 2, 3
SSH_VARS = ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")
POLL_S = 20
LOCK_PATH = os.path.join(tempfile.gettempdir(), "yuzu_firewall_containment_ceremony.lock")
POLL_APPLY_S = 90
RELEASE_READS = 4
RELEASE_ATTEMPTS = 3  # a `busy` or otherwise refused release is dispatched again while the host is not inactive
# The limit must outlast the ceremony's own polling budget while contained: the status read after the apply
# (2 s + 20 s), the release dispatch (90 s), then RELEASE_READS re-reads (4 x (2 s + 20 s)) = 200 s, plus
# the apply's own wait (up to 90 s, which can run past the point the plugin starts the clock) = 290 s.
# Each poll deadline is checked between reads, so a degraded dashboard can add up to one 30 s read per
# poll, and a release that has to be retried runs past the floor: the dead-man limit is the backstop for
# that tail, not a promise it cannot occur. The default leaves headroom over the floor for the tail.
MIN_TTL_S = 300
DEFAULT_TTL_S = 900  # the floor plus the retried-release tail (about 646 s worst case) with headroom
# CommandResponse.status (proto/yuzu/agent/v1/agent.proto): only SUCCESS is an answer; RUNNING is an
# interim row to poll past; FAILURE, TIMEOUT and REJECTED carry no usable status.
STATUS_RUNNING, STATUS_SUCCESS = 0, 1
# A status read whose rows stay RUNNING with an unchanged body for this many successful polls in a row (0.5 s
# apart, so 10 s) is stuck, not slow: a status read takes a second or two. The poll ends there, as `no
# progress`, instead of spending the rest of its budget. An apply or release is never held to it.
NO_PROGRESS_POLLS = 20


def say(*args, **kw) -> None:
    """print() that cannot raise. After the apply a containment may be on the host, and the release must run
    whatever happens to the terminal: a hung-up pty raises OSError(EIO) and a closed pipe BrokenPipeError
    (both OSError), a closed stream ValueError. A message that cannot be written is dropped."""
    try:
        print(*args, **kw)
    except (OSError, ValueError):
        pass


# What to run on the host when the ceremony cannot confirm a release (the names are the plugin's own).
HAND_RELEASE = ("dispatch firewall.release from the dashboard (the plugin's own undo; a containment removed by hand "
                "while its record is still active is re-applied within 60 s). Only when the agent cannot be "
                "reached: stop the agent service first, then Linux: sudo nft delete table inet yuzu_quarantine "
                "(without nft: delete the yuzu-fwq-* chains and the jumps to them, in iptables and ip6tables), "
                "macOS: sudo pfctl -a com.apple/000.yuzu_quarantine -F rules -F nat")


def signal_note(got: list) -> str:
    return f"; interrupted by signal {got[0]}" if got else ""


class LoginError(RuntimeError):
    """The dashboard did not give this client an authenticated session."""


class DispatchRefused(RuntimeError):
    """The server refused to dispatch a command (it answered the POST with a client error, or with no
    command id), so the command never reached the agent: nothing was applied."""


class Client(instructions_runner.YuzuClient):
    """The runner's dashboard client (no proxy, cookie jar, no-redirect POST opener), plus the two calls this
    ceremony needs: a JSON POST and a response poll that waits past RUNNING rows."""

    def __init__(self, base: str, timeout: int = 30):
        super().__init__(base, timeout=timeout, run_id="firewall-containment")

    def login(self, user: str, password: str):
        """Log in and return the `/api/agents` list that proved the session."""
        try:
            super().login(user, password)
            # A rejected login can still answer 200/302 (the login page), so the session is proven by an
            # authenticated read, never by the status of the form POST.
            return self.list_agents()
        except (OSError, ValueError, RuntimeError, http.client.HTTPException) as e:  # URLError/HTTPError are
            # OSError; a login page is not JSON; a truncated body is an IncompleteRead
            why = (" (the session is valid but this user cannot read /api/agents: it needs Infrastructure:Read)"
                   if getattr(e, "code", None) == 403 else "")
            raise LoginError(f"login failed: {e}{why}") from e

    def post_json(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(self.base + path, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json", "Origin": self.base})
        with self.post_opener.open(req, timeout=self.timeout) as r:
            return json.loads(r.read() or b"{}")

    def poll_response(self, command_id: str, timeout_s: int = POLL_S, no_progress_polls: int = 0) -> dict:
        """The responses once every row has left RUNNING (a RUNNING row is interim, not the answer), or
        whatever was last read when the deadline passes. A failed read (`get_responses` answers with an
        `error`: a reset, a timeout, a non-JSON body, an expired session's 401/403) is one lost poll, and the
        last such error is reported when the poll ends without an answer. With `no_progress_polls` set, a
        command whose rows stay RUNNING with the response body unchanged for that many consecutive successful
        polls ends the poll early (`no progress`, reported); the deadline stays the outer limit, and a lost
        poll neither counts toward the bound nor resets it."""
        deadline, last, lost = time.monotonic() + timeout_s, {}, ""
        previous, unchanged = None, 0
        while time.monotonic() < deadline:
            got = self.get_responses(command_id)
            if got.get("error"):
                lost = str(got["error"])
            else:
                last = got
                rows = [r for r in got.get("responses") or [] if isinstance(r, dict)]
                if rows and not any(r.get("status") == STATUS_RUNNING for r in rows):
                    return last
                body = json.dumps(got, sort_keys=True, default=str)
                unchanged = unchanged + 1 if body == previous else 0
                previous = body
                if no_progress_polls and unchanged >= no_progress_polls:
                    say(f"poll for {command_id}: no progress: the rows stayed RUNNING and unchanged for "
                        f"{no_progress_polls} polls in a row", file=sys.stderr)
                    return last
            time.sleep(0.5)
        if lost:
            say(f"poll for {command_id}: last error: {lost}", file=sys.stderr)
        return last


def take_run_lock() -> tuple[int | None, str | None, str]:
    """An exclusive, non-blocking lock on LOCK_PATH, held (by the returned descriptor) until the run ends, so a
    second containment run cannot release the first one's containment. Returns (fd, reason, error): `fd` is the
    held descriptor, or None with a `reason` of "held" (another run holds the lock), "open_failed" (the lock
    file could not be opened) or "lock_failed" (the lock call itself failed, for example ENOLCK on a file
    system without locks); `error` says why for the last two. They are different faults and are reported as
    such: only a lock another run holds is "held".
    LOCK_PATH is in the temp directory, which on macOS is per user (runs by different users, or under sudo,
    do not exclude each other); on Linux a lock file another user created there makes this run refuse to start."""
    try:
        fd = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as e:
        return None, "open_failed", str(e)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None, "held", ""
    except OSError as e:
        os.close(fd)
        return None, "lock_failed", str(e)
    return fd, None, ""


def refusal(args: argparse.Namespace, env=os.environ) -> str | None:
    """Why this run must not start, or None. Pure so the tests bind it without a network."""
    if platform.system() not in ("Linux", "Darwin"):
        return "POSIX hosts only (use scripts/install-agent-user.ps1 -Check on Windows)"
    remote = getattr(args, "remote", False)
    if not remote and (getattr(args, "agent_hostname", "") or getattr(args, "i_have_console_access_to_agent", False)):
        return "--agent-hostname and --i-have-console-access-to-the-agent are only for --remote runs (usage error)"
    # In remote mode this machine is not contained, so an SSH session here is no risk.
    if args.apply_containment and not remote and not args.i_have_console_access:
        ssh = [v for v in SSH_VARS if env.get(v)]
        if ssh:
            return f"an SSH session is detected ({', '.join(ssh)}): containment could lock you out"
    record = getattr(args, "record", "")
    if record and os.path.lexists(record):
        return (f"--record {record!r} already exists: a record is never overwritten and never written through a "
                "symlink (a second run keeps the first run's record: choose a new path)")
    return None


def remote_refusal(args: argparse.Namespace, nodes) -> str | None:
    """Why a --remote --apply-containment run must not start, or None (pure). The agent is on another
    machine, so the operator names it and says they can reach its console: a release the network cannot
    deliver (the agent's control endpoint is blocked while it is contained) can still be done by hand."""
    if not args.agent_id:
        return ("--agent-id is required with --apply-containment (the ceremony contains exactly the "
                "host you name, never the first agent the dashboard lists)")
    name = (getattr(args, "agent_hostname", "") or "").strip().lower().rstrip(".")
    if not name or name in ("localhost", "localhost.localdomain"):
        return ("--remote --apply-containment needs --agent-hostname, the agent's own hostname (not empty and "
                "not localhost): the ceremony only contains the machine you name")
    if not getattr(args, "i_have_console_access_to_agent", False):
        return ("--remote --apply-containment needs --i-have-console-access-to-the-agent: the release goes "
                "through the network the containment blocks, and the time limit is only the backstop")
    if _host_names(name) & {n for node in nodes for n in _host_names(node)}:
        return (f"--agent-hostname {name!r} is one of this machine's own names: that is the one-host case, "
                "which the agent refuses (refused|self_host). Run without --remote, or name the other machine")
    return None


def install_check() -> tuple[int, str]:
    r = subprocess.run(["bash", str(INSTALL), "--check"], capture_output=True, text=True, timeout=120)
    lines = (r.stdout + r.stderr).strip().splitlines()
    return r.returncode, lines[-1] if lines else ""


def dispatch(client: Client, agent_id: str, action: str, params: dict) -> dict:
    """Send one command and poll for the answer. Raises DispatchRefused when the server refuses it (a 4xx on
    the POST, such as a user who is not an administrator) or answers without a command id: the command never
    reached the agent. Any other failure of the POST (a reset, a timeout, a 5xx) is NOT a refusal: the server
    may already have sent it, so it propagates as the error it is."""
    try:
        sent = client.post_json("/api/command", {"plugin": "firewall", "action": action, "agent_ids": [agent_id],
                                                 "params": {k: str(v) for k, v in params.items()}})
    except urllib.error.HTTPError as e:
        if 400 <= e.code < 500:
            raise DispatchRefused(f"HTTP {e.code} {e.reason}") from e
        raise
    cid = sent.get("command_id", "") if isinstance(sent, dict) else ""
    if not cid:
        raise DispatchRefused(f"the server answered without a command id ({str(sent)[:120]})")
    # an apply or release can take the plugin up to a minute plus its verify: wait for the answer, with no
    # no-progress bound (its row stays RUNNING while the plugin works). A status read is quick: a row that
    # sits RUNNING and unchanged is stuck.
    long_wait = action in ("quarantine", "release")
    return client.poll_response(cid, timeout_s=POLL_APPLY_S if long_wait else POLL_S,
                                no_progress_polls=0 if long_wait else NO_PROGRESS_POLLS)


_STATUS_ROW = re.compile(r"status\|([a-z_]+)(?:\|.*)?")
# Notes the plugin writes when the host was ALREADY contained (or a containment was converged) and this
# apply therefore did not create the containment: the ceremony must not release what it did not apply.
_NOT_OURS_NOTES = frozenset({"note|already_active=1", "note|repaired=1", "note|incomplete_apply_converged=1"})
# Notes on a release answer that mean it found nothing of this run's to undo.
_NOTHING_RELEASED_NOTES = frozenset({"note|no_state_record=1", "note|state_unreadable=1"})


def answer_lines(answer, agent_id: str) -> list[str]:
    """The output lines (stripped, lower-cased) of this agent's SUCCESS (status 1) response rows. A RUNNING,
    FAILURE, TIMEOUT or REJECTED row, a row with no integer status, another agent's row and an error string
    contribute nothing."""
    lines: list[str] = []
    for r in (answer.get("responses") if isinstance(answer, dict) else None) or []:
        status = r.get("status") if isinstance(r, dict) else None
        if (not isinstance(r, dict) or r.get("agent_id") != agent_id or type(status) is not int
                or status != STATUS_SUCCESS or not isinstance(r.get("output"), str)):
            continue
        lines.extend(line.strip().lower() for line in r["output"].splitlines())
    return lines


def status_token(client: Client, agent_id: str, seen: list | None = None) -> str:
    """The `status|<token>` row of this agent's `quarantine_status` output, exactly: `active`, `inactive`,
    `active_unproven`, `partial`, `degraded`. Only a whole output LINE of a SUCCESS (status 1) response row
    that names this agent counts: a RUNNING, FAILURE, TIMEOUT or REJECTED row, a row with no integer status,
    a substring of an error string and another agent's row never do, and the rows must agree. Empty when
    no agent answered -- never a guess ("inactive" contains "active"). `seen`, when given, collects every
    token read (the run record's `statuses`)."""
    tokens = set()
    for line in answer_lines(dispatch(client, agent_id, "quarantine_status", {}), agent_id):
        m = _STATUS_ROW.fullmatch(line)
        if m:
            tokens.add(m.group(1))
    token = tokens.pop() if len(tokens) == 1 else ""
    if seen is not None:
        seen.append(token)
    return token


# The only terminal states a FIRST clean apply of this run can answer: it took hold (`active`,
# `active_unproven`, `partial`) or it undid itself (`rolled_back`).
_OWN_APPLY_STATUSES = frozenset({"active", "active_unproven", "partial", "rolled_back"})


def agent_rows(answer, agent_id: str) -> list[str]:
    """Every output line (stripped, lower-cased) of this agent's response rows, whatever their status: a
    non-zero rc keeps its rows in `output` or in `error_detail`."""
    lines: list[str] = []
    for r in (answer.get("responses") if isinstance(answer, dict) else None) or []:
        if isinstance(r, dict) and r.get("agent_id") == agent_id:
            for field in ("output", "error_detail"):
                if isinstance(r.get(field), str):
                    lines.extend(line.strip().lower() for line in r[field].splitlines())
    return lines


def refusal_token(answer, agent_id: str):
    """The text after `status|refused|` of the first such row this agent answered (`self_host`,
    `own_addresses_unreadable`, `privilege_unavailable`, ...), else None: what --record keeps as the refusal."""
    prefix = "status|refused|"
    for line in agent_rows(answer, agent_id):
        if line.startswith(prefix):
            return line[len(prefix):] or None
    return None


def apply_was_not_ours(answer, agent_id: str) -> bool:
    """True iff the `quarantine` answer shows the containment is not this run's, so it is left alone: the
    plugin said the host was already contained or converged (`already_active`, `repaired`,
    `incomplete_apply_converged`), or it answered anything a first clean apply cannot (`degraded`, `busy`,
    `refused`, `update_failed`: another actor's apply or record got there first). A lost or unreadable answer
    (no status line at all) and an apply that threw (`degraded|exception`) are NOT a verdict: the apply may
    still be landing or may have landed before the throw, so the release runs."""
    lines = agent_rows(answer, agent_id)
    if any(line in _NOT_OURS_NOTES for line in lines):
        return True
    if "status|degraded|exception" in lines:
        # The plugin threw; the throw can follow the `applying` record and part of the mutation, so this
        # run may have made a containment it cannot see: ownership is unknown, like a lost answer.
        return False
    statuses = {m.group(1) for line in lines if (m := _STATUS_ROW.fullmatch(line))}
    return bool(statuses) and not statuses <= _OWN_APPLY_STATUSES


def release_proven(answer, agent_id: str) -> bool:
    """True iff this agent's `release` command ended in a SUCCESS row that reads `status|inactive` and did not
    say it found nothing to undo (`no_state_record`, `state_unreadable`): a refused or failed release, and a
    no-op release after the time limit or another actor had already ended the containment, are not proof."""
    lines = answer_lines(answer, agent_id)
    return "status|inactive" in lines and not any(line in _NOTHING_RELEASED_NOTES for line in lines)


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


def release_and_confirm(client: Client, agent_id: str, seen: list | None = None) -> tuple[bool, bool]:
    """Dispatch `firewall.release` (again, up to RELEASE_ATTEMPTS times, while the host is not inactive) and
    require an explicit `inactive` answer, re-reading the status a few times (a slow apply can still be
    finishing). Returns (confirmed, proven): `confirmed` is the host reading `inactive`; `proven` is that a
    release command of this run succeeded and undid something (see `release_proven`). A lost poll or a
    transport error is one lost read, never the end of the release. An `inactive` read ends the attempts only
    once a release of this run is proven (or the attempts are used up); before that the release is dispatched
    again, because an apply whose answer was lost can still land. No `inactive` read is exit 3."""
    proven = False
    for attempt in range(RELEASE_ATTEMPTS):
        try:
            proven = release_proven(dispatch(client, agent_id, "release", {}), agent_id) or proven
        except Exception as e:  # noqa: BLE001 - the next attempt and the status reads still run
            say(f"release call {attempt + 1} failed: {e}", file=sys.stderr)
        for _ in range(RELEASE_READS):
            time.sleep(2)
            try:
                if status_token(client, agent_id, seen) == "inactive":
                    if proven or attempt == RELEASE_ATTEMPTS - 1:
                        return True, proven
                    # `inactive` with no release of this run proven: the release was refused (`busy` while an
                    # apply was still in flight) or its answer was lost, and that apply can still land. Release
                    # again rather than trust a read taken before it did.
                    break
            except Exception as e:  # noqa: BLE001
                say(f"status read failed: {e}", file=sys.stderr)
    return False, proven


def _host_names(name: str) -> set[str]:
    """A hostname as a comparable set: lower-cased, trailing dot dropped, and with a trailing `.local`
    (mDNS) also offered without it. Never a first-label shortcut: `box` is not `box.corp.example`."""
    n = (name or "").strip().lower().rstrip(".")
    return {n, n[: -len(".local")]} - {""} if n.endswith(".local") else ({n} - {""})


def agent_is_this_host(agents, agent_id: str, nodes, os_name: str = "") -> bool:
    """True iff exactly one registry entry carries `agent_id`, its hostname equals one of this machine's
    names (`nodes`), its `os` is this machine's (`os_name`, when given), and NO other registered agent has
    a name of this machine's (two agents under one name, a clone or a default such as `ubuntu`, cannot be
    told apart). An empty or `localhost` hostname never binds. The ceremony cuts the named agent off the
    network, so it must be the box in front of the operator."""
    entries = [a for a in agents or [] if isinstance(a, dict)]
    hits = [a for a in entries if (a.get("agent_id") or a.get("id")) == agent_id]
    if len(hits) != 1:
        return False
    mine = {n for node in nodes for n in _host_names(node)}
    host = str(hits[0].get("hostname") or "").strip().lower().rstrip(".")
    if host in ("", "localhost", "localhost.localdomain", "localhost.") or not _host_names(host) & mine:
        return False
    if os_name and str(hits[0].get("os") or "").strip().lower() != os_name.lower():
        return False
    return not any(a is not hits[0] and _host_names(str(a.get("hostname") or "")) & mine for a in entries)


def agent_is_named_remote(agents, agent_id: str, agent_hostname: str, nodes) -> bool:
    """True iff exactly one registry entry carries `agent_id`, the hostname it reported equals
    `agent_hostname` (the operator's typed name) under `_host_names`, that name is NOT one of this machine's
    (`nodes`: the ceremony runs elsewhere), and no other registered agent carries it (two agents under one
    name cannot be told apart). An empty or `localhost` name never binds. The agent's OS is not checked: the
    agent is on another machine and may be any OS."""
    entries = [a for a in agents or [] if isinstance(a, dict)]
    hits = [a for a in entries if (a.get("agent_id") or a.get("id")) == agent_id]
    if len(hits) != 1:
        return False
    want = _host_names(agent_hostname)
    host = str(hits[0].get("hostname") or "").strip().lower().rstrip(".")
    if not want or host in ("", "localhost", "localhost.localdomain") or not _host_names(host) & want:
        return False
    mine = {n for node in nodes for n in _host_names(node)}
    if want & mine or _host_names(host) & mine:
        return False
    return not any(a is not hits[0] and _host_names(str(a.get("hostname") or "")) & want for a in entries)


def this_host_names() -> list[str]:
    return [platform.node(), socket.gethostname()]


def this_host_os() -> str:
    """The `os` a registry entry of this machine carries (agents register `linux` / `darwin`)."""
    return platform.system().lower()


def dashboard_is_local(dashboard: str) -> bool:
    """The release is dispatched through the dashboard from this host while it is contained, and the
    allow set always carries loopback: so the dashboard must be loopback (the ceremony runs on a local
    box next to its UAT stack)."""
    try:
        host = (urllib.parse.urlparse(dashboard).hostname or "").lower()
        return host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def cleartext_login(dashboard: str) -> bool:
    """Is the dashboard plain http at an address that is not loopback? The login then sends the admin
    password and the session cookie across the network unencrypted (pure)."""
    return urllib.parse.urlparse(dashboard).scheme.lower() == "http" and not dashboard_is_local(dashboard)


CLEARTEXT_WARNING = ("warning: the dashboard at {host} is plain http at a non-loopback address: the admin "
                     "password and the session cookie cross the network unencrypted. Run this on the server's host "
                     "(a loopback dashboard) or use an https dashboard")

LOOPBACK_REFUSAL = ("refused: the dashboard must be loopback (http://127.0.0.1:<port>) so the release can reach it "
                    "while this host is contained, or pass --remote (the server on another host, with "
                    "--agent-hostname and --i-have-console-access-to-the-agent). A run where the agent and the "
                    "server are on one host ends refused|self_host (exit 2) by design: the agent will not contain "
                    "the host its own control endpoint is on, so a containment round trip needs --remote. The "
                    "check compares the host's own addresses only: a server in a container or VM on this host, "
                    "reached at a bridge address, is not one of them, so the agent does contain that host")

SELF_HOST_TEXT = ("the agent's control endpoint is the agent host itself, so it refused to contain it "
                  "(status|refused|self_host): nothing was changed and no release was dispatched. The check compares "
                  "the host's own addresses only. The ceremony needs the server on another host: run it with "
                  "--remote (and --agent-hostname, --i-have-console-access-to-the-agent) against that server")

REMOTE_NOTE = ("remote mode: the agent host is not this machine. The release goes through the server and depends "
               "on the agent's control endpoint staying reachable while it is contained; the time limit "
               "(--ttl-seconds) is the backstop. The install check on the agent host "
               "(scripts/install-agent-user.sh --check) is your precondition, and it was not run here")


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                epilog="One host cannot run the containment: an --apply-containment run whose agent "
                                       "control endpoint is one of the host's own addresses (the agent and the "
                                       "server on the same host) ends refused|self_host (exit 2) by design, and a "
                                       "containment round trip needs --remote. A server in a container or VM on "
                                       "this host, reached at a bridge address, is not refused. The run lock file is "
                                       "in the temp directory, which on macOS is per user (runs by different users, "
                                       "or under sudo, do not exclude each other), and on Linux a lock file another "
                                       "user created there makes the run refuse to start. See the module docstring.")
    p.add_argument("--dashboard", required=True)
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default=os.environ.get("YUZU_PASSWORD", ""),
                   help="dashboard password (default: $YUZU_PASSWORD; an argv value is visible in the process list)")
    p.add_argument("--agent-id", default="",
                   help="the agent to probe or contain; required with --apply-containment, where it must be "
                        "registered exactly once under this machine's hostname (or, with --remote, under "
                        "--agent-hostname)")
    p.add_argument("--exceptions", default="127.0.0.1", help="allow-set entries for the containment step")
    p.add_argument("--probe-target", default="", help="ip:port the plugin probes before/after the apply; without it the status reads active_unproven")
    p.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_S,
                   help=f"dead-man time limit on the containment, at least {MIN_TTL_S} (apply mode refuses 0 and anything shorter)")
    p.add_argument("--apply-containment", action="store_true", help="really contain and release (guarded)")
    p.add_argument("--i-have-console-access", action="store_true", help="allow --apply-containment from an SSH session")
    p.add_argument("--remote", action="store_true",
                   help="this script runs on the server's host (or another one), NOT on the agent: the dashboard may "
                        "be any address and the SSH check does not apply. With --apply-containment it needs "
                        "--agent-id, --agent-hostname and --i-have-console-access-to-the-agent. A plain http "
                        "dashboard at a non-loopback address sends the admin password and the session cookie "
                        "across the network unencrypted (the script warns): run on the server's host or use "
                        "an https dashboard")
    p.add_argument("--agent-hostname", default="",
                   help="--remote only: the agent's own hostname, typed by you; it must equal the hostname the "
                        "agent reported to the server and not be one of this machine's names")
    p.add_argument("--i-have-console-access-to-the-agent", dest="i_have_console_access_to_agent",
                   action="store_true",
                   help="--remote only: you are at the agent's console, so a release the network cannot "
                        "deliver can be done by hand")
    p.add_argument("--record", default="",
                   help="write one JSON record of the run to PATH when it ends, on every exit path of a run (mode 0600; "
                        "a PATH that already exists, a symlink included, is refused: a record is never overwritten)")
    return p.parse_args(argv)


def new_record(args: argparse.Namespace) -> dict:
    """The run record `--record` retains: filled in as the run goes, written when it ends."""
    return {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "mode": "remote" if getattr(args, "remote", False) else "local",
            "agent_id": getattr(args, "agent_id", ""), "hostname": getattr(args, "agent_hostname", ""),
            "statuses": [], "contained": False, "released": False, "exit_code": EXIT_FAIL, "refusal": None}


def write_record(path: str, rec: dict) -> None:
    """Write the run record to a file this call creates (O_EXCL: an existing path, a symlink included, is
    never opened, truncated or written through), mode 0600 (a new file has at most the creation mode). A
    failure to write it is reported and never changes the run's exit code; a write that fails after this
    call created the file removes it, and an open that fails never removes anything."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as e:   # EEXIST: the file is another run's record, never ours to remove
        say(f"could not write the run record {path}: {e}", file=sys.stderr)
        return
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(rec, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError as e:   # a partial file this call created would block the corrected retry
        # Best-effort cleanup that unlinks by name, so someone who controls the record's directory could
        # rename a file onto the path and have it removed. That actor can already replace the record, and
        # this only runs after this call's own failed write.
        with contextlib.suppress(OSError):
            os.unlink(path)
        say(f"could not write the run record {path}: {e}", file=sys.stderr)


def main(argv=None) -> int:
    args = parse_args(argv)
    rec = new_record(args)
    rc = EXIT_FAIL
    try:
        rc = checked_run(args, rec)
        return rc
    finally:
        rec["exit_code"] = rc
        if getattr(args, "record", ""):
            write_record(args.record, rec)


def checked_run(args: argparse.Namespace, rec: dict) -> int:
    why = refusal(args)
    if why:
        say(f"refused: {why}", file=sys.stderr)
        return EXIT_PRECONDITION
    remote = getattr(args, "remote", False)
    if args.apply_containment and args.ttl_seconds < MIN_TTL_S:
        say(f"refused: --ttl-seconds must be at least {MIN_TTL_S}: a shorter limit could end the containment "
              "before the first release confirmation finishes (a release that has to be retried can still outlast "
              "it: the limit is the backstop for that tail), and none (0 or negative) would leave a SIGKILL or a "
              "power loss with nothing to end it", file=sys.stderr)
        return EXIT_PRECONDITION
    if args.apply_containment and not args.agent_id:
        say("refused: --agent-id is required with --apply-containment (the ceremony contains exactly the "
              "host you name, never the first agent the dashboard lists)", file=sys.stderr)
        return EXIT_PRECONDITION
    if args.apply_containment and remote:
        why = remote_refusal(args, this_host_names())
        if why:
            say(f"refused: {why}", file=sys.stderr)
            return EXIT_PRECONDITION
    elif args.apply_containment and not dashboard_is_local(args.dashboard):
        say(LOOPBACK_REFUSAL, file=sys.stderr)
        return EXIT_PRECONDITION
    lock = None
    if args.apply_containment:
        lock, reason, error = take_run_lock()
        if lock is None and reason in ("open_failed", "lock_failed"):
            what = "open" if reason == "open_failed" else "take"
            say(f"refused: could not {what} the run lock {LOCK_PATH}: {error}; nothing was dispatched",
                file=sys.stderr)
            return EXIT_PRECONDITION
        if lock is None:
            say(f"refused: another containment run holds {LOCK_PATH}; nothing was dispatched", file=sys.stderr)
            return EXIT_PRECONDITION
    try:
        return run(args, rec)
    finally:
        if lock is not None:
            os.close(lock)


def run(args: argparse.Namespace, rec: dict | None = None) -> int:
    rec = rec if rec is not None else new_record(args)
    remote = getattr(args, "remote", False)
    if remote:
        # The agent is on another machine: its install check is the operator's precondition there, not ours.
        say(REMOTE_NOTE if args.apply_containment else
            "remote mode: the install check on the agent host (scripts/install-agent-user.sh --check) is your "
            "precondition, and it was not run here")
    else:
        rc, last = install_check()
        if rc != 0:
            say(f"precondition failed: install-agent-user.sh --check exited {rc}: {last}", file=sys.stderr)
            return EXIT_PRECONDITION
    base = args.dashboard.rstrip("/")
    if cleartext_login(base):  # every mode logs in the same way, a probe-only run included
        say(CLEARTEXT_WARNING.format(host=urllib.parse.urlparse(base).hostname), file=sys.stderr)
    client = Client(base)
    try:
        agents = client.login(args.user, args.password)
        agent_id = args.agent_id
        agents = agents.get("agents", agents) if isinstance(agents, dict) else agents
        if args.apply_containment and remote:
            if not agent_is_named_remote(agents, agent_id, args.agent_hostname, this_host_names()):
                reg = [a.get("hostname") for a in agents or [] if isinstance(a, dict) and a.get("agent_id") == agent_id]
                say(f"refused: agent {agent_id!r} is not the only agent registered under the name you typed "
                      f"({args.agent_hostname!r}; registry says {reg or 'no such agent'}), or that name is one of this "
                      f"machine's ({this_host_names()}); the ceremony only contains the machine you named",
                      file=sys.stderr)
                return EXIT_PRECONDITION
        elif args.apply_containment and not agent_is_this_host(agents, agent_id, this_host_names(), this_host_os()):
            reg = [a.get("hostname") for a in agents or [] if isinstance(a, dict) and a.get("agent_id") == agent_id]
            say(f"refused: agent {agent_id!r} is not the only agent registered under this host's name and "
                  f"OS (registry says {reg or 'no such agent'}, this host is {this_host_names()} / "
                  f"{this_host_os()}); the ceremony only contains the box you are sitting at", file=sys.stderr)
            return EXIT_PRECONDITION
        if not agent_id:
            if len(agents or []) != 1:
                say(f"precondition failed: {len(agents or [])} agents registered; pass --agent-id "
                      "(the probe picks one only when exactly one is registered)", file=sys.stderr)
                return EXIT_PRECONDITION
            agent_id = agents[0].get("agent_id") or agents[0].get("id", "")
        rec["agent_id"] = agent_id
        reported = [a.get("hostname") for a in agents or [] if isinstance(a, dict)
                    and (a.get("agent_id") or a.get("id")) == agent_id]
        rec["hostname"] = (reported[0] if reported and reported[0] else rec["hostname"]) or ""
        before = status_token(client, agent_id, rec["statuses"])
        if not before:
            say("precondition failed: firewall.quarantine_status got no agent answer (plugin or grant missing?)", file=sys.stderr)
            return EXIT_PRECONDITION
        say("probe ok: firewall.quarantine_status answered")
        if not args.apply_containment:
            say("probe-only: nothing was changed (--apply-containment runs the live ceremony)")
            return EXIT_OK
        if before != "inactive":
            say(f"precondition failed: the host already reads status={before}; the ceremony would "
                  "release a containment it did not apply. Release it by hand first.", file=sys.stderr)
            return EXIT_PRECONDITION
        # From here a containment may be on the host. SIGINT/SIGTERM/SIGHUP only NOTE the signal, for the
        # whole span through the release: nothing can kill the process or skip the release in a gap, and
        # the exit code reports the interruption once the release is confirmed. (The calls in the span are
        # bounded by their own timeouts, so a signal waits at most one poll.)
        got = []
        ok = False
        err = None
        not_ours = False
        refused = None
        with _signals(lambda signum, _frame: got.append(signum), (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)):
            try:
                params = {"exceptions": args.exceptions, "ttl_seconds": args.ttl_seconds}
                if args.probe_target:
                    params["probe_target"] = args.probe_target
                try:
                    answer = dispatch(client, agent_id, "quarantine", params)
                except DispatchRefused as e:
                    refused = e  # the server never sent it: nothing was applied
                if refused is None:
                    rec["refusal"] = refusal_token(answer, agent_id)
                    if rec["refusal"] == "self_host":
                        say(SELF_HOST_TEXT + signal_note(got), file=sys.stderr)
                        return EXIT_PRECONDITION
                    not_ours = apply_was_not_ours(answer, agent_id)
                    if not not_ours:
                        time.sleep(2)
                        token = status_token(client, agent_id, rec["statuses"])
                        ok = token == "active" or (token == "active_unproven" and not args.probe_target)
                        if token == "active_unproven" and ok:
                            say("note: contained but unproven (no --probe-target); pass one to require a verified containment")
                        say(f"contained: {ok}")
                        rec["contained"] = ok
            except BaseException as e:  # noqa: BLE001 - the release below must run for ANY failure
                err = e
            if refused is not None:
                say(f"dispatch refused: {refused}: the apply was never sent, so nothing was applied and there is "
                      f"nothing to release{signal_note(got)}", file=sys.stderr)
                return EXIT_FAIL
            if err is not None:
                say(f"containment step failed: {err!r}", file=sys.stderr)
            if not_ours:
                # Somebody else's containment (or one this run did not create): releasing it would lift
                # a containment the ceremony never applied.
                say("NOT released: either the containment is not this run's, or this run's own apply did not take "
                      "hold (the apply answered already_active / repaired / incomplete_apply_converged, or "
                      "something a clean first apply cannot: degraded, busy, refused, update_failed). Read "
                      "quarantine_status; a containment that is there ends at its own time limit or by "
                      f"({HAND_RELEASE}){signal_note(got)}.", file=sys.stderr)
                return EXIT_FAIL
            # ALWAYS release, then re-raise whatever stopped the containment step.
            released, proven = release_and_confirm(client, agent_id, rec["statuses"])
        say(f"released: {released}")
        rec["released"] = released
        if not released:
            say("RELEASE NOT CONFIRMED: the host did not read inactive after "
                  f"{RELEASE_ATTEMPTS} release attempts; clear the firewall by hand ({HAND_RELEASE})"
                  + signal_note(got), file=sys.stderr)
            return EXIT_RELEASE_FAILED
        if not proven:
            say("release unproven: the host reads inactive, but no release command of this run succeeded and "
                  "undid anything (it was refused or failed, found nothing to undo because the dead-man limit "
                  "or another actor had already ended the containment, or this run's own apply had already "
                  f"rolled itself back; or the apply's answer was lost and the apply is still landing: check "
                  f"quarantine_status, the dead-man limit ends it){signal_note(got)}", file=sys.stderr)
            return EXIT_FAIL
        if got:
            say(f"interrupted by signal {got[0]}; containment released", file=sys.stderr)
            return EXIT_FAIL
        if err is not None:
            raise err
        return EXIT_OK if ok else EXIT_FAIL
    except LoginError as e:
        say(f"precondition failed: {e}", file=sys.stderr)
        return EXIT_PRECONDITION
    except DispatchRefused as e:
        # A read before the apply (or a probe-only run): the server refused it, nothing was changed.
        say(f"dispatch refused: {e}: nothing was applied", file=sys.stderr)
        return EXIT_FAIL
    except KeyboardInterrupt:
        return EXIT_FAIL
    except Exception as e:  # noqa: BLE001 - a script exit code, not a library
        say(f"failed: {e}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
