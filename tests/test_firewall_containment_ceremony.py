#!/usr/bin/env python3
"""Guards of scripts/test/instructions_firewall_containment.py (privilege model step 6).

The live apply/release needs a UAT stack on a local host and is not run here. What IS run, with no
network and no firewall change: the refusal rules (SSH session, missing console flag) and the
install-agent-user.sh --check precondition (a failing --check must exit 2 before any login or
dispatch; a passing one goes on to the probe).
"""
import os
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


class Guards(unittest.TestCase):
    def test_ssh_session_refuses_containment(self):
        for var in fc.SSH_VARS:
            self.assertIn("SSH", fc.refusal(args(apply_containment=True), {var: "x"}) or "")

    def test_console_flag_allows_ssh_containment(self):
        self.assertIsNone(fc.refusal(args(apply_containment=True, i_have_console_access=True), {"SSH_TTY": "x"}))

    def test_probe_only_is_allowed_over_ssh(self):
        self.assertIsNone(fc.refusal(args(), {"SSH_CONNECTION": "x"}))

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

    def test_passing_install_check_goes_on_to_the_probe(self):
        with mock.patch.object(fc, "install_check", return_value=(0, "")), \
                mock.patch.object(fc, "refusal", return_value=None):
            # nothing listens on port 9: the login fails, which is exit 1, not a precondition exit
            self.assertEqual(fc.main(["--dashboard", "http://127.0.0.1:9"]), fc.EXIT_FAIL)


if __name__ == "__main__":
    unittest.main()
