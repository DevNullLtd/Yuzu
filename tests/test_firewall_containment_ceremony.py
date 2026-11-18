#!/usr/bin/env python3
"""Guards and flow of scripts/test/instructions_firewall_containment.py (privilege model step 6).

The live apply/release needs a UAT stack on a local host and is not run here. What IS run, with no
network and no firewall change: the refusal rules (SSH session, missing console flag, non-POSIX host),
the install-agent-user.sh --check precondition, and the whole apply/release flow against a recording
fake of the dispatch seam: the status token is read exactly (inactive is not active), a missing answer
is never a confirmation, and the release runs, and is confirmed or exits 3, on every failure path.
Also pinned: the SUCCESS-only status rule and the poll past RUNNING, the explicit --agent-id bound to this
host by full hostname, the 300 s limit floor (0 and negative refused in apply mode), a refused login
exiting 2, a host the apply found already contained is never released, and a pass needs a release of
this run's own that succeeded and undid something (otherwise exit 1, "release unproven"). A held run lock
exits 2 with nothing dispatched, and a poll's error answer is reported, never swallowed.
"""
import contextlib
import io
import os
import platform
import signal
import subprocess
import sys
import unittest
from unittest import mock
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "test" / "instructions_firewall_containment.py"
sys.path.insert(0, str(SCRIPT.parent))
import instructions_firewall_containment as fc  # noqa: E402


def args(**kw):
    base = dict(dashboard="http://127.0.0.1:9", user="a", password="", agent_id="", exceptions="127.0.0.1",
                apply_containment=False, i_have_console_access=False)
    base.update(kw)
    return type("A", (), base)()


def on(system):
    return mock.patch.object(fc.platform, "system", return_value=system)


class Guards(unittest.TestCase):
    def test_ssh_session_refuses_containment(self):
        with on("Linux"):
            for var in fc.SSH_VARS:
                self.assertIn("SSH", fc.refusal(args(apply_containment=True), {var: "x"}) or "")

    def test_console_flag_allows_ssh_containment(self):
        with on("Darwin"):
            self.assertIsNone(fc.refusal(args(apply_containment=True, i_have_console_access=True),
                                         {"SSH_TTY": "x"}))

    def test_probe_only_is_allowed_over_ssh(self):
        with on("Linux"):
            self.assertIsNone(fc.refusal(args(), {"SSH_CONNECTION": "x"}))

    def test_a_non_posix_host_is_refused(self):
        with on("Windows"):
            self.assertIn("POSIX", fc.refusal(args(), {}) or "")

    def test_script_refuses_under_ssh_before_any_network(self):
        env = dict(os.environ, SSH_CONNECTION="1 2 3 4")
        r = subprocess.run([sys.executable, str(SCRIPT), "--dashboard", "http://127.0.0.1:9",
                            "--apply-containment"], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, fc.EXIT_PRECONDITION)
        self.assertIn("refused", r.stderr)
        if platform.system() in ("Linux", "Darwin"):  # elsewhere the POSIX-only refusal comes first
            self.assertIn("SSH", r.stderr)

    def test_failed_install_check_exits_2_before_any_dispatch(self):
        # install_check is the only thing mocked: had the script gone on past it, it would have tried to
        # reach the dashboard and exited 1, never 2.
        with mock.patch.object(fc, "install_check", return_value=(1, "account missing")), \
                mock.patch.object(fc, "refusal", return_value=None):
            self.assertEqual(fc.main(["--dashboard", "http://127.0.0.1:9"]), fc.EXIT_PRECONDITION)

    def test_unverified_install_check_refuses_and_tells_the_user_to_run_as_root(self):
        # --check exits 6 when the sudoers file is present but unreadable to this user (R4-CHECKGREEN).
        # The ceremony must treat that as a failed precondition (never as a pass) and say why.
        # install_check itself is NOT mocked-away in spirit: the real `--check` exit statuses (0 healthy,
        # 1 drift, 6 unverified) are asserted against a synthetic layout by tests/test_agent_installer_exec.py,
        # which can build that layout; this file only owns what the ceremony does with the number.
        import io
        err = io.StringIO()
        with mock.patch.object(fc, "install_check", return_value=(6, "unverified")), \
                mock.patch.object(fc, "refusal", return_value=None), mock.patch("sys.stderr", err):
            self.assertEqual(fc.main(["--dashboard", "http://127.0.0.1:9"]), fc.EXIT_PRECONDITION)
        self.assertIn("as root", err.getvalue())


def row(token):
    """The terminal answer: CommandResponse.status SUCCESS (1) carries the plugin output."""
    return {"responses": [{"agent_id": "a", "status": 1, "output": f"status|{token}"}], "count": 1}


def running():
    """The interim row an agent writes first: status RUNNING (0), no output yet."""
    return {"responses": [{"agent_id": "a", "status": 0, "output": ""}], "count": 1}


EMPTY = {"responses": [], "count": 0}
REL = {"responses": [{"agent_id": "a", "status": 1, "output": "status|inactive"}], "count": 1}  # a release that worked
BUSY = {"responses": [{"agent_id": "a", "status": 2, "output": "", "error_detail": "busy"}], "count": 1}


class Status(unittest.TestCase):
    def tok(self, reply, agent="a"):
        with mock.patch.object(fc, "dispatch", return_value=reply):
            return fc.status_token(None, agent)

    def test_inactive_is_not_active(self):
        self.assertEqual(self.tok(row("inactive")), "inactive")
        self.assertEqual(self.tok(row("active")), "active")
        self.assertEqual(self.tok(row("active_unproven")), "active_unproven")

    def test_no_answer_is_empty_never_a_token(self):
        self.assertEqual(self.tok(EMPTY), "")
        self.assertEqual(self.tok({}), "")

    def test_only_this_agents_whole_status_line_counts(self):
        # an error string, another agent's row, a non-status line and a mid-line mention are not an answer
        spoof = {"error": "x status|inactive", "responses": [
            {"agent_id": "other", "status": 1, "output": "status|inactive"},
            {"agent_id": "a", "status": 1, "output": "refused|x status|inactive"},
            {"agent_id": "a", "status": 1, "output": "note|status|inactive"}]}
        self.assertEqual(self.tok(spoof), "")
        real = {"responses": [{"agent_id": "a", "status": 1, "output": "verify|control=ok\nstatus|active|probe\nnote|x"}]}
        self.assertEqual(self.tok(real), "active")

    def test_only_a_success_row_is_an_answer(self):
        # RUNNING (0) is interim; FAILURE (2), TIMEOUT (3) and REJECTED (4) carry no usable status; a row
        # with no status, or one that is not an integer, never counts (True == 1 must not slip through).
        for status in (0, 2, 3, 4, None, True, "1", 1.0):
            with self.subTest(status=status):
                r = {"agent_id": "a", "output": "status|inactive", "error_detail": "plugin crashed"}
                if status is not None:
                    r["status"] = status
                self.assertEqual(self.tok({"responses": [r]}), "")

    def test_a_running_row_beside_the_terminal_one_does_not_hide_the_answer(self):
        both = {"responses": [{"agent_id": "a", "status": 0, "output": ""},
                              {"agent_id": "a", "status": 1, "output": "status|active"}]}
        self.assertEqual(self.tok(both), "active")

    def test_disagreeing_rows_are_not_an_answer(self):
        two = {"responses": [{"agent_id": "a", "status": 1, "output": "status|inactive\nstatus|active"}]}
        self.assertEqual(self.tok(two), "")


class Poll(unittest.TestCase):
    """Client.poll_response against a scripted get_responses: it must poll PAST a RUNNING row to the terminal one."""

    def poll(self, replies, timeout_s=20):
        client = fc.Client("http://127.0.0.1:9")
        seq = list(replies)
        with mock.patch.object(client, "get_responses", side_effect=lambda _p: seq.pop(0) if len(seq) > 1 else seq[0]), \
                mock.patch.object(fc.time, "sleep"):
            return client.poll_response("cid", timeout_s=timeout_s), seq

    def test_it_polls_past_running_to_the_terminal_row(self):
        client = fc.Client("http://127.0.0.1:9")
        reads = []
        replies = [EMPTY, running(), running(), row("inactive")]
        with mock.patch.object(client, "get_responses", side_effect=lambda _p: reads.append(1) or replies[len(reads) - 1]), \
                mock.patch.object(fc.time, "sleep"):
            got = client.poll_response("cid", timeout_s=20)
        self.assertEqual(got, row("inactive"))
        self.assertEqual(len(reads), 4)  # an early return on the first row (empty or RUNNING) reads fewer

    def test_a_row_that_never_leaves_running_is_returned_at_the_deadline_and_is_no_answer(self):
        ticks = iter(range(0, 1000, 3))  # the clock advances 3 s per read, so a deadline of 10 s ends the poll
        with mock.patch.object(fc.time, "monotonic", side_effect=lambda: next(ticks)):
            client = fc.Client("http://127.0.0.1:9")
            with mock.patch.object(client, "get_responses", return_value=running()), mock.patch.object(fc.time, "sleep"):
                got = client.poll_response("cid", timeout_s=10)
        self.assertEqual(got, running())
        with mock.patch.object(fc, "dispatch", return_value=got):
            self.assertEqual(fc.status_token(None, "a"), "")

    def test_a_terminal_failure_row_ends_the_poll(self):
        failed = {"responses": [{"agent_id": "a", "status": 2, "output": "", "error_detail": "boom"}]}
        got, _ = self.poll([running(), failed])
        self.assertEqual(got, failed)


class Transient(unittest.TestCase):
    def test_a_lost_poll_is_retried_not_fatal(self):
        # get_responses turns a reset, a timeout, a non-JSON body or an HTTP error into an `error` answer
        client = fc.Client("http://127.0.0.1:9")
        replies = [{"error": "ConnectionResetError: x"}, {"error": "TimeoutError: t"},
                   {"error": "JSONDecodeError: not json"}, {"error": "HTTP 502", "code": 502}, row("inactive")]
        with mock.patch.object(client, "get_responses", side_effect=lambda _p: replies.pop(0)), \
                mock.patch.object(fc.time, "sleep"):
            self.assertEqual(client.poll_response("cid", timeout_s=60), row("inactive"))
        self.assertEqual(replies, [])

    def test_an_error_answer_never_replaces_the_last_good_read(self):
        client = fc.Client("http://127.0.0.1:9")
        ticks = iter(range(0, 1000, 3))
        replies = [running(), {"error": "HTTP 401 expired", "code": 401}]
        with mock.patch.object(fc.time, "monotonic", side_effect=lambda: next(ticks)), \
                mock.patch.object(client, "get_responses", side_effect=lambda _p: replies.pop(0) if len(replies) > 1 else replies[0]), \
                mock.patch.object(fc.time, "sleep"), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(client.poll_response("cid", timeout_s=10), running())


class PollSaysWhy(unittest.TestCase):
    def test_a_poll_error_is_reported(self):
        client = fc.Client("http://127.0.0.1:9")
        ticks = iter(range(0, 1000, 3))
        err = io.StringIO()
        with mock.patch.object(fc.time, "monotonic", side_effect=lambda: next(ticks)), \
                mock.patch.object(client, "get_responses",
                                  return_value={"error": "HTTP 401 session expired", "code": 401}), \
                mock.patch.object(fc.time, "sleep"), contextlib.redirect_stderr(err):
            self.assertEqual(client.poll_response("cid", timeout_s=10), {})
        self.assertIn("HTTP 401 session expired", err.getvalue())

    def test_the_client_is_the_runners(self):
        self.assertTrue(issubclass(fc.Client, fc.instructions_runner.YuzuClient))


class Proof(unittest.TestCase):
    def test_a_release_row_must_be_a_real_success(self):
        good = {"responses": [{"agent_id": "a", "status": 1, "output": "status|inactive"}]}
        self.assertTrue(fc.release_proven(good, "a"))
        for bad in ({"responses": [{"agent_id": "a", "status": True, "output": "status|inactive"}]},
                    {"responses": [{"agent_id": "a", "status": 0, "output": "status|inactive"}]},
                    {"responses": [{"agent_id": "b", "status": 1, "output": "status|inactive"}]},
                    {"responses": [{"agent_id": "a", "status": 1, "output": "status|partial"}]},
                    BUSY, EMPTY, {}, None):
            self.assertFalse(fc.release_proven(bad, "a"), bad)

    def test_the_apply_notes_are_whole_lines_of_this_agents_success_rows(self):
        def ans(output, status=1, agent="a", **kw):
            return {"responses": [dict(agent_id=agent, status=status, output=output, **kw)]}
        noted = "status|active\nnote|already_active=1"
        self.assertTrue(fc.apply_was_not_ours(ans(noted), "a"))
        self.assertFalse(fc.apply_was_not_ours(ans(noted), "b"))     # another agent's row says nothing
        self.assertFalse(fc.apply_was_not_ours(ans("status|active\nx note|already_active=1"), "a"))  # not a line
        # every answer a first clean apply of this run can give is ours; so is a lost or status-less one
        for ours in ("status|active", "status|active_unproven|x", "status|partial|residue",
                     "status|rolled_back|apply_failed\nrolled_back|apply_failed"):
            self.assertFalse(fc.apply_was_not_ours(ans(ours, status=1 if "rolled" not in ours else 2), "a"), ours)
        self.assertFalse(fc.apply_was_not_ours({}, "a"))
        self.assertFalse(fc.apply_was_not_ours(ans("", status=3), "a"))        # a server TIMEOUT proves nothing
        # whatever else is somebody else's: degraded, busy, refused, update_failed, in any status field
        for foreign in ("status|degraded|os_unreadable", "status|busy", "status|refused|release_in_progress",
                        "status|update_failed|x", "status|degraded"):
            for st in (1, 2):
                self.assertTrue(fc.apply_was_not_ours(ans(foreign, status=st), "a"), (foreign, st))
        self.assertTrue(fc.apply_was_not_ours(ans("", status=2, error_detail="status|busy"), "a"))


class Login(unittest.TestCase):
    def test_a_403_names_the_missing_read_access(self):
        def denied():
            raise fc.urllib.error.HTTPError("u", 403, "no", None, None)
        with self.assertRaises(fc.LoginError) as cm:
            self.login(denied)
        self.assertIn("Infrastructure:Read", str(cm.exception))

    """A 200/302 from the login POST proves nothing: the session is proven by an authenticated read."""

    def login(self, list_agents):
        client = fc.Client("http://127.0.0.1:9")
        with mock.patch.object(fc.instructions_runner.YuzuClient, "login"), \
                mock.patch.object(client, "list_agents", side_effect=list_agents):
            return client.login("a", "b")

    def test_an_authenticated_read_is_a_login(self):
        self.assertEqual(self.login(lambda: []), [])

    def test_a_login_page_instead_of_json_is_a_failed_login(self):
        def page():
            raise ValueError("Expecting value")  # json.JSONDecodeError is a ValueError
        with self.assertRaises(fc.LoginError):
            self.login(page)

    def test_a_401_on_the_authenticated_read_is_a_failed_login(self):
        def denied():
            raise fc.urllib.error.HTTPError("u", 401, "no", None, None)
        with self.assertRaises(fc.LoginError):
            self.login(denied)


class Local(unittest.TestCase):
    def test_only_a_loopback_dashboard_is_allowed(self):
        for ok in ("http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"):
            self.assertTrue(fc.dashboard_is_local(ok), ok)
        for bad in ("http://192.0.2.7:8080", "http://dash.example:8080", "https://[::1", "", "127.0.0.1"):
            self.assertFalse(fc.dashboard_is_local(bad), bad)


@unittest.skipUnless(hasattr(signal, "SIGHUP"), "the ceremony is POSIX-only")
class Flow(unittest.TestCase):
    """main() against a recording fake of the dispatch seam. `script` maps an action to the list of replies
    (or exceptions) it answers with, in order."""

    def run_main(self, script, apply=True, extra=(), dashboard="http://127.0.0.1:9", agent=True, client=None,
                 lock=None):
        # a per-process lock file: concurrent jobs on one CI box must not share the run lock
        if lock is None:
            lock = os.path.join(fc.tempfile.gettempdir(), f"yuzu_test_fwc_run_{os.getpid()}.lock")
            self.addCleanup(lambda: Path(lock).unlink(missing_ok=True))
        calls = []
        self.params = {}
        if client is None:
            client = mock.MagicMock()
            client.login.return_value = {"agents": [{"agent_id": "a", "hostname": "Box.local", "os": "linux"}]}

        def fake(_client, _agent, action, params):
            calls.append(action)
            self.params[action] = params
            r = script[action].pop(0)
            if isinstance(r, BaseException):
                raise r
            return r(calls) if callable(r) else r

        argv = ["--dashboard", dashboard] + (["--agent-id", "a"] if agent else []) + \
               (["--apply-containment"] if apply else []) + list(extra)
        with mock.patch.object(fc, "refusal", return_value=None), \
                mock.patch.object(fc, "install_check", return_value=(0, "")), \
                mock.patch.object(fc, "Client", return_value=client), \
                mock.patch.object(fc, "this_host_names", return_value=["box"]), \
                mock.patch.object(fc, "this_host_os", return_value="linux"), \
                mock.patch.object(fc.time, "sleep"), \
                mock.patch.object(fc, "LOCK_PATH", lock), \
                mock.patch.object(fc, "dispatch", side_effect=fake):
            return fc.main(argv), calls

    def test_probe_requires_an_agent_answer(self):
        rc, calls = self.run_main({"quarantine_status": [EMPTY]}, apply=False)
        self.assertEqual(rc, fc.EXIT_PRECONDITION)
        self.assertEqual(calls, ["quarantine_status"])

    def test_probe_only_changes_nothing(self):
        rc, calls = self.run_main({"quarantine_status": [row("inactive")]}, apply=False)
        self.assertEqual(rc, fc.EXIT_OK)
        self.assertEqual(calls, ["quarantine_status"])

    def test_success_contains_then_releases_and_confirms(self):
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                                   "quarantine": [{}], "release": [REL]})
        self.assertEqual(rc, fc.EXIT_OK)
        self.assertEqual(calls, ["quarantine_status", "quarantine", "quarantine_status", "release",
                                 "quarantine_status"])

    def test_inactive_after_the_apply_is_not_contained_but_still_releases(self):
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("inactive"), row("inactive")],
                                   "quarantine": [{}], "release": [REL]})
        self.assertEqual(rc, fc.EXIT_FAIL)
        self.assertIn("release", calls)

    def test_a_missing_release_answer_exits_3(self):
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active")] + [EMPTY] * fc.RELEASE_READS,
                               "quarantine": [{}], "release": [REL]})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)

    def test_a_release_that_raises_exits_3(self):
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active")],
                               "quarantine": [{}], "release": [OSError("offline")]})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)

    def test_a_still_active_status_after_the_release_exits_3(self):
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active")] + [row("active")] * fc.RELEASE_READS,
                               "quarantine": [{}], "release": [REL]})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)

    def test_a_slow_release_is_confirmed_by_a_later_read(self):
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("partial"),
                                                         row("inactive")],
                                   "quarantine": [{}], "release": [REL]})
        self.assertEqual(rc, fc.EXIT_OK)
        self.assertEqual(calls, ["quarantine_status", "quarantine", "quarantine_status", "release",
                                 "quarantine_status", "quarantine_status"])

    def test_a_spoofed_inactive_in_an_error_string_is_not_a_confirmed_release(self):
        spoof = {"error": "x status|inactive", "responses": []}
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active")] + [spoof] * fc.RELEASE_READS,
                               "quarantine": [{}], "release": [REL]})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)

    def test_a_failure_while_containing_still_releases(self):
        for boom in (RuntimeError("x"), KeyboardInterrupt()):
            with self.subTest(boom=type(boom).__name__):
                rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("inactive")],
                                           "quarantine": [boom], "release": [REL]})
                self.assertEqual(rc, fc.EXIT_FAIL)
                self.assertIn("release", calls)

    def test_the_apply_carries_the_dead_man_limit_and_the_probe_target(self):
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                               "quarantine": [{}], "release": [REL]}, extra=["--probe-target", "198.18.0.9:443"])
        self.assertEqual(rc, fc.EXIT_OK)
        self.assertEqual(self.params["quarantine"], {"exceptions": "127.0.0.1", "ttl_seconds": fc.DEFAULT_TTL_S,
                                                     "probe_target": "198.18.0.9:443"})
        self.assertGreaterEqual(fc.DEFAULT_TTL_S, fc.MIN_TTL_S)

    def test_an_unproven_containment_passes_only_without_a_probe_target(self):
        script = lambda: {"quarantine_status": [row("inactive"), row("active_unproven"), row("inactive")],
                          "quarantine": [{}], "release": [REL]}
        rc, calls = self.run_main(script())
        self.assertEqual(rc, fc.EXIT_OK)
        rc, calls = self.run_main(script(), extra=["--probe-target", "198.18.0.9:443"])
        self.assertEqual(rc, fc.EXIT_FAIL)       # a requested probe that did not verify is a failure ...
        self.assertIn("release", calls)          # ... and the release still runs

    def test_a_limit_too_short_for_the_release_confirmation_is_refused(self):
        rc, calls = self.run_main({}, extra=["--ttl-seconds", "60"])
        self.assertEqual(rc, fc.EXIT_PRECONDITION)
        self.assertEqual(calls, [])
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                               "quarantine": [{}], "release": [REL]}, extra=["--ttl-seconds", str(fc.MIN_TTL_S)])
        self.assertEqual(rc, fc.EXIT_OK)

    def test_the_limit_floor_covers_the_polling_budget(self):
        # status read after the apply + one release + its re-reads + the apply's own wait must fit the floor
        budget = (2 + fc.POLL_S) + fc.POLL_APPLY_S + fc.RELEASE_READS * (2 + fc.POLL_S) + fc.POLL_APPLY_S
        self.assertGreaterEqual(fc.MIN_TTL_S, budget)
        self.assertEqual(fc.MIN_TTL_S, 300)  # the documented floor; a change here is a documented change
        rc, calls = self.run_main({}, extra=["--ttl-seconds", str(fc.MIN_TTL_S - 1)])
        self.assertEqual(rc, fc.EXIT_PRECONDITION)
        self.assertEqual(calls, [])

    def test_only_the_apply_and_release_get_the_long_poll(self):
        client = mock.MagicMock()
        client.post_json.return_value = {"command_id": "c"}
        for action, want in (("quarantine", fc.POLL_APPLY_S), ("release", fc.POLL_APPLY_S),
                             ("quarantine_status", fc.POLL_S), ("quarantine_allow", fc.POLL_S)):
            with self.subTest(action=action):
                fc.dispatch(client, "a", action, {})
                self.assertEqual(client.poll_response.call_args.kwargs["timeout_s"], want)

    def test_a_non_loopback_dashboard_is_refused_for_the_apply_only(self):
        rc, calls = self.run_main({}, dashboard="http://192.0.2.7:8080")
        self.assertEqual(rc, fc.EXIT_PRECONDITION)
        self.assertEqual(calls, [])
        rc, _ = self.run_main({"quarantine_status": [row("inactive")]}, apply=False,
                              dashboard="http://192.0.2.7:8080")
        self.assertEqual(rc, fc.EXIT_OK)         # a probe-only run changes nothing, so any dashboard is fine

    def test_zero_or_several_registered_agents_exit_before_any_dispatch(self):
        for agents in ([], [{"agent_id": "a"}, {"agent_id": "b"}]):
            with self.subTest(n=len(agents)):
                client = mock.MagicMock()
                client.login.return_value = {"agents": agents}
                rc, calls = self.run_main({}, apply=False, agent=False, client=client)
                self.assertEqual(rc, fc.EXIT_PRECONDITION)
                self.assertEqual(calls, [])

    def test_a_lone_registered_agent_is_picked_by_the_probe_only(self):
        client = mock.MagicMock()
        client.login.return_value = {"agents": [{"agent_id": "a"}]}
        rc, calls = self.run_main({"quarantine_status": [row("inactive")]}, apply=False, agent=False, client=client)
        self.assertEqual(rc, fc.EXIT_OK)
        self.assertEqual(calls, ["quarantine_status"])

    def test_no_limit_is_refused_in_apply_mode(self):
        for ttl in ("-1", "0", "1", str(fc.MIN_TTL_S - 1)):
            with self.subTest(ttl=ttl):
                rc, calls = self.run_main({}, extra=["--ttl-seconds", ttl])
                self.assertEqual(rc, fc.EXIT_PRECONDITION)
                self.assertEqual(calls, [])

    def test_the_apply_is_bound_to_this_host(self):
        for agents in ([{"agent_id": "a", "hostname": "other-box"}], [{"agent_id": "z", "hostname": "box"}],
                       [{"agent_id": "a", "hostname": ""}], []):
            with self.subTest(agents=agents):
                client = mock.MagicMock()
                client.login.return_value = {"agents": agents}
                rc, calls = self.run_main({}, client=client)
                self.assertEqual(rc, fc.EXIT_PRECONDITION)
                self.assertEqual(calls, [])
        ok = [{"agent_id": "a", "hostname": "Box.local"}]
        self.assertTrue(fc.agent_is_this_host(ok, "a", ["BOX."]))
        self.assertTrue(fc.agent_is_this_host(ok, "a", ["box.local"]))
        self.assertTrue(fc.agent_is_this_host([{"agent_id": "a", "hostname": "box.corp.example"}], "a",
                                              ["Box.Corp.Example."]))
        # a first-label match is NOT this host, nor is a localhost / empty name, nor a repeated agent id
        for hostname, node in (("box.evil.example", "box"), ("box", "box.evil.example"), ("localhost", "localhost"),
                               ("localhost.localdomain", "localhost.localdomain"), ("", "")):
            with self.subTest(hostname=hostname, node=node):
                self.assertFalse(fc.agent_is_this_host([{"agent_id": "a", "hostname": hostname}], "a", [node]))
        twice = [{"agent_id": "a", "hostname": "box"}, {"agent_id": "a", "hostname": "box"}]
        self.assertFalse(fc.agent_is_this_host(twice, "a", ["box"]))
        # a clone registered under the same name cannot be told apart from this box: refused
        clones = [{"agent_id": "a", "hostname": "ubuntu"}, {"agent_id": "remote", "hostname": "Ubuntu."}]
        self.assertFalse(fc.agent_is_this_host(clones, "remote", ["ubuntu"]))
        self.assertFalse(fc.agent_is_this_host(clones, "a", ["ubuntu"]))
        # the registry os must be this machine's os; either of this machine's names binds
        mine = [{"agent_id": "a", "hostname": "box", "os": "Linux"}]
        self.assertTrue(fc.agent_is_this_host(mine, "a", ["other", "box"], "linux"))
        self.assertFalse(fc.agent_is_this_host(mine, "a", ["box"], "darwin"))
        self.assertFalse(fc.agent_is_this_host([{"agent_id": "a", "hostname": "box"}], "a", ["box"], "linux"))
        self.assertFalse(fc.agent_is_this_host([{"agent_id": "a", "hostname": "localhost."}], "a", ["localhost."]))
        # the same id under two hostnames is no single host; a bare name beside this host's `.local` name is a clone
        self.assertFalse(fc.agent_is_this_host([{"agent_id": "a", "hostname": "box"},
                                                {"agent_id": "a", "hostname": "other"}], "a", ["box"]))
        self.assertFalse(fc.agent_is_this_host([{"agent_id": "a", "hostname": "box.local"},
                                                {"agent_id": "b", "hostname": "box"}], "a", ["box.local"]))
        with mock.patch.object(fc.platform, "node", return_value="n1"), \
                mock.patch.object(fc.socket, "gethostname", return_value="n2"):
            self.assertEqual(fc.this_host_names(), ["n1", "n2"])  # both names are offered to the binding

    def test_a_refused_release_followed_by_inactive_is_not_a_pass(self):
        # the apply is still in flight, the release is refused `busy`, yet a later status read says inactive
        # An unproven `inactive` is not trusted: the release is dispatched again (the apply can still land),
        # and the run ends 'release unproven' only once the attempts are used up.
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("active")] + [row("inactive")] * fc.RELEASE_ATTEMPTS,
                                   "quarantine": [{}], "release": [BUSY] * fc.RELEASE_ATTEMPTS})
        self.assertEqual(rc, fc.EXIT_FAIL)
        self.assertEqual(calls.count("release"), fc.RELEASE_ATTEMPTS)
        self.assertEqual(calls[-1], "quarantine_status")
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active")] + [row("active")] * (fc.RELEASE_READS * fc.RELEASE_ATTEMPTS),
                               "quarantine": [{}], "release": [BUSY] * fc.RELEASE_ATTEMPTS})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)  # an unconfirmed release is still exit 3

    def test_a_containment_this_run_did_not_apply_is_never_released(self):
        for note in ("already_active=1", "repaired=1", "incomplete_apply_converged=1"):
            with self.subTest(note=note):
                applied = {"responses": [{"agent_id": "a", "status": 1, "output": f"status|active\nnote|{note}"}]}
                rc, calls = self.run_main({"quarantine_status": [row("inactive")], "quarantine": [applied],
                                           "release": [REL]})
                self.assertEqual(rc, fc.EXIT_FAIL)
                self.assertNotIn("release", calls)
        # a plain apply answer (no such note) is ours and is released; so is no answer at all
        for answer in ({"responses": [{"agent_id": "a", "status": 1, "output": "status|active"}]}, {}):
            with self.subTest(answer=answer):
                rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                                           "quarantine": [answer], "release": [REL]})
                self.assertIn("release", calls)

    def test_an_apply_a_first_clean_run_cannot_give_is_never_released(self):
        # another actor got in between the inactive read and our apply: nothing here may lift its containment
        for foreign, st in (("status|degraded|os_unreadable", 1), ("status|degraded", 1), ("status|busy", 2),
                            ("status|update_failed|converge", 2), ("status|refused|release_in_progress", 2),
                            ("status|refused|state_unreadable", 2)):
            with self.subTest(answer=foreign):
                applied = {"responses": [{"agent_id": "a", "status": st, "output": foreign}]}
                rc, calls = self.run_main({"quarantine_status": [row("inactive")], "quarantine": [applied],
                                           "release": [REL]})
                self.assertNotEqual(rc, fc.EXIT_OK)
                self.assertNotIn("release", calls)
        # ... while our own answers, a rolled-back apply, an apply that threw (it can follow part of the
        # mutation: the plugin's real `status|degraded|exception` rows) and a lost one all reach the release
        for own in ({"responses": [{"agent_id": "a", "status": 2, "output": "status|rolled_back|x"}]}, EMPTY,
                    {"responses": [{"agent_id": "a", "status": 1, "output": "status|degraded|exception"}]},
                    {"responses": [{"agent_id": "a", "status": 2, "output": "status|degraded|exception\nnote|x=1"}]},
                    {"responses": [{"agent_id": "a", "status": 3, "output": ""}]}):
            with self.subTest(own=own):
                rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("inactive")],
                                           "quarantine": [own], "release": [REL]})
                self.assertIn("release", calls)

    def test_a_terminal_that_cannot_be_written_never_skips_the_release(self):
        class Dead:
            def write(self, *_a):
                raise BrokenPipeError(32, "gone")

            def flush(self):
                raise BrokenPipeError(32, "gone")
        for boom in (RuntimeError("x"), OSError(5, "EIO")):
            with self.subTest(boom=type(boom).__name__), mock.patch.object(sys, "stdout", Dead()), \
                    mock.patch.object(sys, "stderr", Dead()):
                rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("inactive"), row("inactive")],
                                           "quarantine": [boom], "release": [REL]})
                self.assertEqual(rc, fc.EXIT_FAIL)
                self.assertIn("release", calls)
                self.assertEqual(calls[-1], "quarantine_status")  # and the release was confirmed

    def test_a_signal_is_named_on_the_not_ours_and_unproven_exits(self):
        for answer, release in (({"responses": [{"agent_id": "a", "status": 2, "output": "status|busy"}]}, REL),
                                ({}, {"responses": [{"agent_id": "a", "status": 1,
                                                     "output": "status|inactive\nnote|no_state_record=1"}]})):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc, _ = self.run_main({"quarantine_status": [row("inactive")] * (2 + fc.RELEASE_ATTEMPTS),
                                       "quarantine": [lambda _c, a=answer: signal.raise_signal(signal.SIGTERM) or a],
                                       "release": [release] * fc.RELEASE_ATTEMPTS})
            self.assertEqual(rc, fc.EXIT_FAIL)
            self.assertIn(f"interrupted by signal {int(signal.SIGTERM)}", err.getvalue())

    def test_a_release_that_found_nothing_to_undo_is_not_proof(self):
        for note in ("no_state_record=1", "state_unreadable=1"):
            with self.subTest(note=note):
                noop = {"responses": [{"agent_id": "a", "status": 1, "output": f"status|inactive\nnote|{note}"}]}
                rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active")] + [row("inactive")] * fc.RELEASE_ATTEMPTS,
                                       "quarantine": [{}], "release": [noop] * fc.RELEASE_ATTEMPTS})
                self.assertEqual(rc, fc.EXIT_FAIL)  # the time limit (or someone else) released it, not this run

    def test_an_apply_that_lands_after_a_refused_release_is_released_by_the_retry(self):
        # apply answer lost; release #1 refused `busy` and the host still reads inactive; the apply then
        # lands, so release #2 undoes it: the run passes only because the retry ran
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("inactive"), row("inactive"),
                                                         row("inactive")],
                                   "quarantine": [{}], "release": [BUSY, REL]})
        self.assertEqual(rc, fc.EXIT_FAIL)  # ok is False (never read active), but the second release ran
        self.assertEqual(calls.count("release"), 2)

    def test_login_reads_the_agents_once_and_the_attempts_are_three(self):
        c = fc.Client("http://127.0.0.1:9")
        reads = []
        with mock.patch.object(fc.instructions_runner.YuzuClient, "login"), \
                mock.patch.object(c, "list_agents", side_effect=lambda: reads.append(1) or []):
            self.assertEqual(c.login("a", "b"), [])
        self.assertEqual(reads, [1])
        self.assertEqual(fc.RELEASE_ATTEMPTS, 3)  # the docstring and the TTL budget both say three
        self.assertGreaterEqual(fc.DEFAULT_TTL_S, 646)  # the worst case with every attempt used

    def test_a_truncated_agents_payload_at_login_is_exit_2(self):
        client = mock.MagicMock()
        client.login.side_effect = fc.LoginError("login failed: IncompleteRead")
        rc, _ = self.run_main({}, client=client)
        self.assertEqual(rc, fc.EXIT_PRECONDITION)
        c = fc.Client("http://127.0.0.1:9")
        with mock.patch.object(fc.instructions_runner.YuzuClient, "login"), \
                mock.patch.object(c, "list_agents", side_effect=fc.http.client.IncompleteRead(b"x")):
            with self.assertRaises(fc.LoginError):
                c.login("a", "b")

    def test_the_short_limit_text_says_the_limit_is_the_backstop_for_the_retry_tail(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.run_main({}, extra=["--ttl-seconds", "60"])
        self.assertIn("backstop", err.getvalue())

    def test_a_proven_release_stays_proven_across_a_later_refused_attempt(self):
        # attempt 1 worked but the host still read active; attempt 2 was refused (nothing left to release);
        # the host then reads inactive: the run's own release is proven by the first attempt
        reads = [row("inactive"), row("active")] + [row("active")] * fc.RELEASE_READS + [row("inactive")]
        rc, calls = self.run_main({"quarantine_status": reads, "quarantine": [{}], "release": [REL, BUSY]})
        self.assertEqual(rc, fc.EXIT_OK)
        self.assertEqual(calls.count("release"), 2)

    def test_a_refused_release_is_retried_until_it_works(self):
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("active")] + [row("active")] * fc.RELEASE_READS
                                                         + [row("inactive")],
                                   "quarantine": [{}], "release": [BUSY, REL]})
        self.assertEqual(rc, fc.EXIT_OK)
        self.assertEqual(calls.count("release"), 2)

    def test_the_release_is_attempted_a_bounded_number_of_times(self):
        reads = [row("inactive"), row("active")] + [row("active")] * (fc.RELEASE_READS * fc.RELEASE_ATTEMPTS)
        rc, calls = self.run_main({"quarantine_status": reads, "quarantine": [{}], "release": [BUSY] * fc.RELEASE_ATTEMPTS})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)
        self.assertEqual(calls.count("release"), fc.RELEASE_ATTEMPTS)

    def test_a_transport_error_during_the_release_is_one_lost_read(self):
        # a reset on the first status re-read must not abandon the release: the next read confirms it
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("active"), ConnectionResetError("x"),
                                                         row("inactive")],
                                   "quarantine": [{}], "release": [REL]})
        self.assertEqual(rc, fc.EXIT_OK)
        self.assertEqual(calls.count("release"), 1)

    def test_the_binding_gets_this_machines_os_and_names(self):
        client = mock.MagicMock()
        client.login.return_value = {"agents": [{"agent_id": "a", "hostname": "box", "os": "linux"}]}
        with mock.patch.object(fc, "agent_is_this_host", wraps=fc.agent_is_this_host) as bound:
            self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                           "quarantine": [{}], "release": [REL]}, client=client)
        self.assertEqual(bound.call_args.args[2:], (["box"], "linux"))

    def test_the_hand_release_text_names_the_plugins_own_objects(self):
        for name in ("firewall.release", "yuzu_quarantine", "yuzu-fwq-", "com.apple/000.yuzu_quarantine",
                     "-F rules -F nat", "ip6tables", "stop the agent service"):
            self.assertIn(name, fc.HAND_RELEASE)
        self.assertNotIn("-F all", fc.HAND_RELEASE)  # it flushes global states and counters the plugin leaves alone
        self.assertLess(fc.HAND_RELEASE.index("firewall.release"), fc.HAND_RELEASE.index("nft"))

    def test_the_apply_names_its_agent(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc, calls = self.run_main({}, agent=False)
        self.assertEqual(rc, fc.EXIT_PRECONDITION)
        self.assertEqual(calls, [])
        self.assertIn("--agent-id is required", err.getvalue())  # not the host-binding refusal in disguise

    def test_a_held_run_lock_exits_2_before_any_dispatch(self):
        lock = os.path.join(fc.tempfile.gettempdir(), f"yuzu_test_fwc_{os.getpid()}.lock")
        holder = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fc.fcntl.flock(holder, fc.fcntl.LOCK_EX | fc.fcntl.LOCK_NB)  # another run holds it
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc, calls = self.run_main({"quarantine_status": [row("inactive")]}, lock=lock)
            self.assertEqual(rc, fc.EXIT_PRECONDITION)
            self.assertEqual(calls, [])
            self.assertIn("another containment run", err.getvalue())
            fc.fcntl.flock(holder, fc.fcntl.LOCK_UN)  # once it is free, a run takes it and releases it on exit
            rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                                   "quarantine": [{}], "release": [REL]}, lock=lock)
            self.assertEqual(rc, fc.EXIT_OK)
            fc.fcntl.flock(holder, fc.fcntl.LOCK_EX | fc.fcntl.LOCK_NB)  # raises if the run kept it
        finally:
            os.close(holder)
            os.unlink(lock)

    def test_a_failed_login_exits_2_before_any_dispatch(self):
        client = mock.MagicMock()
        client.login.side_effect = fc.LoginError("login failed: HTTP Error 401")
        rc, calls = self.run_main({}, client=client)
        self.assertEqual(rc, fc.EXIT_PRECONDITION)
        self.assertEqual(calls, [])

    def test_an_already_contained_host_is_refused_before_any_change(self):
        for token in ("active", "partial", "degraded"):
            with self.subTest(token=token):
                rc, calls = self.run_main({"quarantine_status": [row(token)]})
                self.assertEqual(rc, fc.EXIT_PRECONDITION)
                self.assertEqual(calls, ["quarantine_status"])

    def test_a_signal_while_containing_still_releases_and_the_handlers_are_restored(self):
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(sig=sig.name):
                before = tuple(signal.getsignal(x) for x in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT))
                rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                                           "quarantine": [lambda _c, sig=sig: signal.raise_signal(sig)],
                                           "release": [REL]})
                self.assertEqual(rc, fc.EXIT_FAIL)  # interrupted, but released and confirmed
                self.assertEqual(calls[-2:], ["release", "quarantine_status"])
                after = tuple(signal.getsignal(x) for x in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT))
                self.assertEqual(after, before)

    def test_a_signal_during_the_release_does_not_skip_the_confirmation(self):
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                                   "quarantine": [{}],
                                   "release": [lambda _c: signal.raise_signal(signal.SIGTERM) or REL]})
        self.assertEqual(rc, fc.EXIT_FAIL)
        self.assertEqual(calls[-2:], ["release", "quarantine_status"])


if __name__ == "__main__":
    unittest.main()
