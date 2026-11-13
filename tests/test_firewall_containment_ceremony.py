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
    return {"responses": [{"agent_id": "a", "status": 0, "output": f"status|{token}"}], "count": 1}


EMPTY = {"responses": [], "count": 0}


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
            {"agent_id": "other", "status": 0, "output": "status|inactive"},
            {"agent_id": "a", "status": 1, "output": "refused|x status|inactive"},
            {"agent_id": "a", "status": 0, "output": "note|status|inactive"}]}
        self.assertEqual(self.tok(spoof), "")
        real = {"responses": [{"agent_id": "a", "status": 0, "output": "verify|control=ok\nstatus|active|probe\nnote|x"}]}
        self.assertEqual(self.tok(real), "active")

    def test_a_failed_row_is_not_an_answer(self):
        failed = {"responses": [{"agent_id": "a", "status": 1, "output": "status|inactive",
                                 "error_detail": "plugin crashed"}]}
        self.assertEqual(self.tok(failed), "")

    def test_disagreeing_rows_are_not_an_answer(self):
        two = {"responses": [{"agent_id": "a", "status": 0, "output": "status|inactive\nstatus|active"}]}
        self.assertEqual(self.tok(two), "")


class Reachable(unittest.TestCase):
    def ok(self, dashboard, exceptions="127.0.0.1"):
        return fc.dashboard_reachable_while_contained(dashboard, exceptions)

    def test_loopback_and_covered_ip_literals_only(self):
        self.assertTrue(self.ok("http://127.0.0.1:8080"))
        self.assertTrue(self.ok("http://localhost:8080"))
        self.assertTrue(self.ok("http://[::1]:8080"))
        self.assertTrue(self.ok("http://192.0.2.7:8080", "127.0.0.1,192.0.2.7:8080"))
        self.assertTrue(self.ok("http://192.0.2.7:8080", "192.0.2.7"))              # any port, outbound, both protocols
        self.assertTrue(self.ok("http://192.0.2.7:8080", "192.0.2.0/24/tcp/out"))
        self.assertTrue(self.ok("http://192.0.2.7:8080", "192.0.2.0/24:8080"))      # the prefix may carry the port
        self.assertTrue(self.ok("https://192.0.2.7", "192.0.2.7:443/tcp"))           # scheme default port
        self.assertTrue(self.ok("http://[2001:db8::7]:8080", "[2001:db8::7]:8080"))
        self.assertTrue(self.ok("http://[2001:db8::7]:8080", "2001:db8::/32"))

    def test_other_hosts_and_hostnames_are_refused(self):
        self.assertFalse(self.ok("http://192.0.2.8:8080", "192.0.2.7"))
        self.assertFalse(self.ok("http://dash.example:8080", "dash.example"))  # DNS is blocked while contained
        self.assertFalse(self.ok("http://192.0.2.7:8080", "garbage,,"))

    def test_an_entry_that_does_not_let_the_release_through_is_refused(self):
        dash = "https://10.0.0.5:8443"
        for entry in ("10.0.0.5:22", "10.0.0.5/udp", "10.0.0.5/in", "10.0.0.5/out/in", "10.0.0.0/8/in",
                      "10.0.0.5:8443/udp", "10.0.0.5:8444", "0.0.0.0/0", "10.0.0.5/8/16", "10.0.0.5/x"):
            with self.subTest(entry=entry):
                self.assertFalse(self.ok(dash, entry))
        for entry in ("10.0.0.5:8443", "10.0.0.5:8443/tcp/out", "10.0.0.0/8", "10.0.0.0/8:8443/tcp"):
            with self.subTest(entry=entry):
                self.assertTrue(self.ok(dash, entry))

    def test_an_unparseable_dashboard_is_refused_not_raised(self):
        self.assertFalse(self.ok("https://[::1", "127.0.0.1"))


@unittest.skipUnless(hasattr(signal, "SIGHUP"), "the ceremony is POSIX-only")
class Flow(unittest.TestCase):
    """main() against a recording fake of the dispatch seam. `script` maps an action to the list of replies
    (or exceptions) it answers with, in order."""

    def run_main(self, script, apply=True, extra=(), dashboard="http://127.0.0.1:9", agent=True, client=None):
        calls = []
        self.params = {}

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
                mock.patch.object(fc, "Client", return_value=client or mock.MagicMock()), \
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
                                   "quarantine": [{}], "release": [{}]})
        self.assertEqual(rc, fc.EXIT_OK)
        self.assertEqual(calls, ["quarantine_status", "quarantine", "quarantine_status", "release",
                                 "quarantine_status"])

    def test_inactive_after_the_apply_is_not_contained_but_still_releases(self):
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("inactive"), row("inactive")],
                                   "quarantine": [{}], "release": [{}]})
        self.assertEqual(rc, fc.EXIT_FAIL)
        self.assertIn("release", calls)

    def test_a_missing_release_answer_exits_3(self):
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active")] + [EMPTY] * fc.RELEASE_READS,
                               "quarantine": [{}], "release": [{}]})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)

    def test_a_release_that_raises_exits_3(self):
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active")],
                               "quarantine": [{}], "release": [OSError("offline")]})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)

    def test_a_still_active_status_after_the_release_exits_3(self):
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active")] + [row("active")] * fc.RELEASE_READS,
                               "quarantine": [{}], "release": [{}]})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)

    def test_a_slow_release_is_confirmed_by_a_later_read(self):
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("partial"),
                                                         row("inactive")],
                                   "quarantine": [{}], "release": [{}]})
        self.assertEqual(rc, fc.EXIT_OK)
        self.assertEqual(calls, ["quarantine_status", "quarantine", "quarantine_status", "release",
                                 "quarantine_status", "quarantine_status"])

    def test_a_spoofed_inactive_in_an_error_string_is_not_a_confirmed_release(self):
        spoof = {"error": "x status|inactive", "responses": []}
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active")] + [spoof] * fc.RELEASE_READS,
                               "quarantine": [{}], "release": [{}]})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)

    def test_a_failure_while_containing_still_releases(self):
        for boom in (RuntimeError("x"), KeyboardInterrupt()):
            with self.subTest(boom=type(boom).__name__):
                rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("inactive")],
                                           "quarantine": [boom], "release": [{}]})
                self.assertEqual(rc, fc.EXIT_FAIL)
                self.assertIn("release", calls)

    def test_the_apply_carries_the_dead_man_limit_and_the_probe_target(self):
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                               "quarantine": [{}], "release": [{}]}, extra=["--probe-target", "198.18.0.9:443"])
        self.assertEqual(rc, fc.EXIT_OK)
        self.assertEqual(self.params["quarantine"],
                         {"exceptions": "127.0.0.1", "ttl_seconds": 300, "probe_target": "198.18.0.9:443"})
        self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                       "quarantine": [{}], "release": [{}]}, extra=["--ttl-seconds", "0"])
        self.assertEqual(self.params["quarantine"], {"exceptions": "127.0.0.1"})

    def test_an_unproven_containment_passes_only_without_a_probe_target(self):
        script = lambda: {"quarantine_status": [row("inactive"), row("active_unproven"), row("inactive")],
                          "quarantine": [{}], "release": [{}]}
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
                               "quarantine": [{}], "release": [{}]}, extra=["--ttl-seconds", str(fc.MIN_TTL_S)])
        self.assertEqual(rc, fc.EXIT_OK)

    def test_a_dashboard_the_contained_host_could_not_reach_is_refused(self):
        rc, calls = self.run_main({}, dashboard="http://192.0.2.7:8080")
        self.assertEqual(rc, fc.EXIT_PRECONDITION)
        self.assertEqual(calls, [])
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                                   "quarantine": [{}], "release": [{}]}, dashboard="http://192.0.2.7:8080",
                                  extra=["--exceptions", "127.0.0.1,192.0.2.7:8080"])
        self.assertEqual(rc, fc.EXIT_OK)
        rc, _ = self.run_main({"quarantine_status": [row("inactive")]}, apply=False,
                              dashboard="http://192.0.2.7:8080")
        self.assertEqual(rc, fc.EXIT_OK)         # a probe-only run changes nothing, so any dashboard is fine

    def test_no_registered_agent_and_a_failed_login_exit_before_any_dispatch(self):
        client = mock.MagicMock()
        client.get_json.return_value = {"agents": []}
        rc, calls = self.run_main({}, agent=False, client=client)
        self.assertEqual(rc, fc.EXIT_PRECONDITION)
        self.assertEqual(calls, [])
        client = mock.MagicMock()
        client.login.side_effect = OSError("refused")
        rc, calls = self.run_main({}, client=client)
        self.assertEqual(rc, fc.EXIT_FAIL)
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
                                           "release": [{}]})
                self.assertEqual(rc, fc.EXIT_FAIL)  # interrupted, but released and confirmed
                self.assertEqual(calls[-2:], ["release", "quarantine_status"])
                after = tuple(signal.getsignal(x) for x in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT))
                self.assertEqual(after, before)

    def test_a_signal_during_the_release_does_not_skip_the_confirmation(self):
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("inactive")],
                                   "quarantine": [{}],
                                   "release": [lambda _c: signal.raise_signal(signal.SIGTERM)]})
        self.assertEqual(rc, fc.EXIT_FAIL)
        self.assertEqual(calls[-2:], ["release", "quarantine_status"])


if __name__ == "__main__":
    unittest.main()
