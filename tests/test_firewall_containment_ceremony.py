#!/usr/bin/env python3
"""Guards and flow of scripts/test/instructions_firewall_containment.py (privilege model step 6).

The live apply/release needs a UAT stack on a local host and is not run here. What IS run, with no
network and no firewall change: the refusal rules (SSH session, missing console flag, non-POSIX host),
the install-agent-user.sh --check precondition, and the whole apply/release flow against a recording
fake of the dispatch seam: the status token is read exactly (inactive is not active), a missing answer
is never a confirmation, and the release runs, and is confirmed or exits 3, on every failure path.
"""
import os
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

    def test_failed_install_check_exits_2_before_any_dispatch(self):
        # The dashboard is a closed port: had the script gone on to log in, the exit would be 1.
        with mock.patch.object(fc, "install_check", return_value=(1, "account missing")), \
                mock.patch.object(fc, "refusal", return_value=None):
            self.assertEqual(fc.main(["--dashboard", "http://127.0.0.1:9"]), fc.EXIT_PRECONDITION)


def row(token):
    return {"responses": [{"agent_id": "a", "status": 0, "output": f"status|{token}"}], "count": 1}


EMPTY = {"responses": [], "count": 0}


class Status(unittest.TestCase):
    def tok(self, reply):
        with mock.patch.object(fc, "dispatch", return_value=reply):
            return fc.status_token(None, "a")

    def test_inactive_is_not_active(self):
        self.assertEqual(self.tok(row("inactive")), "inactive")
        self.assertEqual(self.tok(row("active")), "active")
        self.assertEqual(self.tok(row("active_unproven")), "active_unproven")

    def test_no_answer_is_empty_never_a_token(self):
        self.assertEqual(self.tok(EMPTY), "")
        self.assertEqual(self.tok({}), "")


@unittest.skipUnless(hasattr(signal, "SIGHUP"), "the ceremony is POSIX-only")
class Flow(unittest.TestCase):
    """main() against a recording fake of the dispatch seam. `script` maps an action to the list of replies
    (or exceptions) it answers with, in order."""

    def run_main(self, script, apply=True):
        calls = []

        def fake(_client, _agent, action, _params):
            calls.append(action)
            r = script[action].pop(0)
            if isinstance(r, BaseException):
                raise r
            return r(calls) if callable(r) else r

        argv = ["--dashboard", "http://unused", "--agent-id", "a"] + (["--apply-containment"] if apply else [])
        with mock.patch.object(fc, "refusal", return_value=None), \
                mock.patch.object(fc, "install_check", return_value=(0, "")), \
                mock.patch.object(fc, "Client"), mock.patch.object(fc.time, "sleep"), \
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
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active"), EMPTY],
                               "quarantine": [{}], "release": [{}]})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)

    def test_a_release_that_raises_exits_3(self):
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active")],
                               "quarantine": [{}], "release": [OSError("offline")]})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)

    def test_a_still_active_status_after_the_release_exits_3(self):
        rc, _ = self.run_main({"quarantine_status": [row("inactive"), row("active"), row("active")],
                               "quarantine": [{}], "release": [{}]})
        self.assertEqual(rc, fc.EXIT_RELEASE_FAILED)

    def test_a_failure_while_containing_still_releases(self):
        for boom in (RuntimeError("x"), KeyboardInterrupt()):
            with self.subTest(boom=type(boom).__name__):
                rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("inactive")],
                                           "quarantine": [boom], "release": [{}]})
                self.assertEqual(rc, fc.EXIT_FAIL)
                self.assertIn("release", calls)

    def test_sigterm_while_containing_still_releases_and_the_handlers_are_restored(self):
        before = (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))
        rc, calls = self.run_main({"quarantine_status": [row("inactive"), row("inactive")],
                                   "quarantine": [lambda _c: signal.raise_signal(signal.SIGTERM)],
                                   "release": [{}]})
        self.assertEqual(rc, fc.EXIT_FAIL)
        self.assertIn("release", calls)
        self.assertEqual((signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)), before)


if __name__ == "__main__":
    unittest.main()
