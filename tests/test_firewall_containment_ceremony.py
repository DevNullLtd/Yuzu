#!/usr/bin/env python3
"""Guards and flow of scripts/test/instructions_firewall_containment.py (privilege model step 6).

The live apply/release needs a UAT stack on a local host and is not run here. What IS run, with no
network and no firewall change: the refusal rules (SSH session, missing console flag, non-POSIX host),
the install-agent-user.sh --check precondition, and the whole apply/release flow against a recording
fake of the dispatch seam: the status token is read exactly (inactive is not active), a missing answer
is never a confirmation, and the release runs, and is confirmed or exits 3, on every failure path.
"""
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
    """Client.poll_response against a scripted get_json: it must poll PAST a RUNNING row to the terminal one."""

    def poll(self, replies, timeout_s=20):
        client = fc.Client("http://127.0.0.1:9")
        seq = list(replies)
        with mock.patch.object(client, "get_json", side_effect=lambda _p: seq.pop(0) if len(seq) > 1 else seq[0]), \
                mock.patch.object(fc.time, "sleep"):
            return client.poll_response("cid", timeout_s=timeout_s), seq

    def test_it_polls_past_running_to_the_terminal_row(self):
        client = fc.Client("http://127.0.0.1:9")
        reads = []
        replies = [EMPTY, running(), running(), row("inactive")]
        with mock.patch.object(client, "get_json", side_effect=lambda _p: reads.append(1) or replies[len(reads) - 1]), \
                mock.patch.object(fc.time, "sleep"):
            got = client.poll_response("cid", timeout_s=20)
        self.assertEqual(got, row("inactive"))
        self.assertEqual(len(reads), 4)  # an early return on the first row (empty or RUNNING) reads fewer

    def test_a_row_that_never_leaves_running_is_returned_at_the_deadline_and_is_no_answer(self):
        with mock.patch.object(fc.time, "monotonic", side_effect=[0, 1, 2, 3, 100, 100]):
            client = fc.Client("http://127.0.0.1:9")
            with mock.patch.object(client, "get_json", return_value=running()), mock.patch.object(fc.time, "sleep"):
                got = client.poll_response("cid", timeout_s=10)
        self.assertEqual(got, running())
        with mock.patch.object(fc, "dispatch", return_value=got):
            self.assertEqual(fc.status_token(None, "a"), "")

    def test_a_terminal_failure_row_ends_the_poll(self):
        failed = {"responses": [{"agent_id": "a", "status": 2, "output": "", "error_detail": "boom"}]}
        got, _ = self.poll([running(), failed])
        self.assertEqual(got, failed)


class Login(unittest.TestCase):
    """A 200/302 from the login POST proves nothing: the session is proven by an authenticated read."""

    def login(self, get_json):
        client = fc.Client("http://127.0.0.1:9")
        with mock.patch.object(client.opener, "open", return_value=mock.MagicMock()), \
                mock.patch.object(client, "get_json", side_effect=get_json):
            client.login("a", "b")

    def test_an_authenticated_read_is_a_login(self):
        self.login(lambda _p: {"agents": []})

    def test_a_login_page_instead_of_json_is_a_failed_login(self):
        def page(_p):
            raise ValueError("Expecting value")  # json.JSONDecodeError is a ValueError
        with self.assertRaises(fc.LoginError):
            self.login(page)

    def test_a_401_on_the_authenticated_read_is_a_failed_login(self):
        def denied(_p):
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

    def run_main(self, script, apply=True, extra=(), dashboard="http://127.0.0.1:9", agent=True, client=None):
        calls = []
        self.params = {}
        if client is None:
            client = mock.MagicMock()
            client.get_json.return_value = {"agents": [{"agent_id": "a", "hostname": "Box.local"}]}

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
                mock.patch.object(fc.platform, "node", return_value="box"), \
                mock.patch.object(fc.time, "sleep"), \
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
        self.assertEqual(self.params["quarantine"],
                         {"exceptions": "127.0.0.1", "ttl_seconds": 300, "probe_target": "198.18.0.9:443"})
        self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                       "quarantine": [{}], "release": [REL]}, extra=["--ttl-seconds", "0"])
        self.assertEqual(self.params["quarantine"], {"exceptions": "127.0.0.1"})

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
        # 22 s status read + 90 s release + 4 x 22 s re-reads + 90 s apply = 290 s must fit inside the floor
        self.assertGreaterEqual(fc.MIN_TTL_S, 290)
        self.assertEqual(fc.MIN_TTL_S, 300)
        rc, calls = self.run_main({}, extra=["--ttl-seconds", str(fc.MIN_TTL_S - 1)])
        self.assertEqual(rc, fc.EXIT_PRECONDITION)
        self.assertEqual(calls, [])

    def test_only_the_apply_and_release_get_the_long_poll(self):
        client = mock.MagicMock()
        client.post_json.return_value = {"command_id": "c"}
        for action, want in (("quarantine", fc.POLL_APPLY_S), ("release", fc.POLL_APPLY_S),
                             ("quarantine_status", fc.POLL_S)):
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
                client.get_json.return_value = {"agents": agents}
                rc, calls = self.run_main({}, apply=False, agent=False, client=client)
                self.assertEqual(rc, fc.EXIT_PRECONDITION)
                self.assertEqual(calls, [])

    def test_a_lone_registered_agent_is_picked_by_the_probe_only(self):
        client = mock.MagicMock()
        client.get_json.return_value = {"agents": [{"agent_id": "a"}]}
        rc, calls = self.run_main({"quarantine_status": [row("inactive")]}, apply=False, agent=False, client=client)
        self.assertEqual(rc, fc.EXIT_OK)
        self.assertEqual(calls, ["quarantine_status"])

    def test_a_negative_limit_is_refused_not_silently_dropped(self):
        rc, calls = self.run_main({}, extra=["--ttl-seconds", "-1"])
        self.assertEqual(rc, fc.EXIT_PRECONDITION)
        self.assertEqual(calls, [])

    def test_the_apply_is_bound_to_this_host(self):
        for agents in ([{"agent_id": "a", "hostname": "other-box"}], [{"agent_id": "z", "hostname": "box"}],
                       [{"agent_id": "a", "hostname": ""}], []):
            with self.subTest(agents=agents):
                client = mock.MagicMock()
                client.get_json.return_value = {"agents": agents}
                rc, calls = self.run_main({}, client=client)
                self.assertEqual(rc, fc.EXIT_PRECONDITION)
                self.assertEqual(calls, [])
        self.assertTrue(fc.agent_is_this_host([{"agent_id": "a", "hostname": "BOX.corp.example"}], "a", "box.local"))

    def test_a_refused_release_followed_by_inactive_is_not_a_pass(self):
        # the apply is still in flight, the release is refused `busy`, yet a later status read says inactive
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                                   "quarantine": [{}], "release": [BUSY]})
        self.assertEqual(rc, fc.EXIT_FAIL)
        self.assertEqual(calls[-2:], ["release", "quarantine_status"])
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active")] + [row("active")] * fc.RELEASE_READS,
                               "quarantine": [{}], "release": [BUSY]})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)  # an unconfirmed release is still exit 3

    def test_the_apply_names_its_agent(self):
        rc, calls = self.run_main({}, agent=False)
        self.assertEqual(rc, fc.EXIT_PRECONDITION)
        self.assertEqual(calls, [])

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
