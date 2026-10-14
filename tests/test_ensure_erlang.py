#!/usr/bin/env python3
"""scripts/ensure-erlang.sh, sourced the way its real callers source it.

release-preflight.sh, integration-test.sh and others source the helper under
`set -euo pipefail`. Its contract is: always return 0, never kill the caller,
activate the pinned OTP when one exists, and leave PATH unchanged (and say so)
when none does. Each case runs a fresh bash with HOME, PATH and the pin
pointed at fake installs in a temp dir; the pin is a made-up major (97) so a
real OTP on the host can never satisfy it. POSIX bash only.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
HELPER = os.path.join(REPO, "scripts", "ensure-erlang.sh")
BASH = shutil.which("bash")


def fake_erl(path, version=None, eval_fails=False):
    """An erl that answers -version, and prints `version` for the -eval probe."""
    with open(path, "w", encoding="ascii") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            case "$*" in
              *-version*) exit 0 ;;
              *-eval*) {"exit 1" if eval_fails else f"printf '%s' '{version}'"} ;;
            esac
            """))
    os.chmod(path, 0o755)


@unittest.skipIf(sys.platform == "win32" or not BASH, "POSIX bash only")
class EnsureErlangTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="yuzu_test_ensure_erlang_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = os.path.join(self.tmp, "home")
        # A kerl install of the pinned (made-up) release.
        self.kerl_root = os.path.join(self.home, ".kerl", "97.4.1")
        os.makedirs(os.path.join(self.kerl_root, "bin"))
        os.makedirs(os.path.join(self.kerl_root, "releases", "97"))
        with open(os.path.join(self.kerl_root, "releases", "97", "OTP_VERSION"), "w") as f:
            f.write("97.4.1\n")
        fake_erl(os.path.join(self.kerl_root, "bin", "erl"), "97.4.1")
        with open(os.path.join(self.kerl_root, "activate"), "w") as f:
            f.write(f'export PATH="{self.kerl_root}/bin:$PATH"\n')
        # A wrong-version erl first on PATH.
        self.path_dir = os.path.join(self.tmp, "wrong")
        os.makedirs(self.path_dir)
        fake_erl(os.path.join(self.path_dir, "erl"), "99.1.1")

    def source(self, pin="97.4", home=True, path_first=None, extra_env=None):
        """Source the helper under set -euo pipefail; return (rc, erl, stderr)."""
        script = textwrap.dedent(f"""\
            set -euo pipefail
            source "{HELPER}" {pin}
            echo "SURVIVED:$(command -v erl || true)"
            """)
        env = {"PATH": os.pathsep.join([path_first or self.path_dir,
                                         os.path.dirname(sys.executable),
                                         "/usr/bin", "/bin"])}
        if home:
            env["HOME"] = self.home
        env.update(extra_env or {})
        out = subprocess.run([BASH, "-c", script], capture_output=True, text=True,
                             env=env, timeout=120)
        erl = ""
        for line in out.stdout.splitlines():
            if line.startswith("SURVIVED:"):
                erl = line[len("SURVIVED:"):]
        return out.returncode, erl, out.stderr

    def test_activates_the_pinned_install_over_a_wrong_version_on_path(self):
        rc, erl, err = self.source()
        self.assertEqual(rc, 0, err)
        self.assertEqual(erl, os.path.join(self.kerl_root, "bin", "erl"), err)

    def test_an_erl_whose_version_probe_fails_does_not_kill_a_strict_caller(self):
        # A real erl exits 1 from -eval when its OTP_VERSION file is missing.
        broken = os.path.join(self.tmp, "broken")
        os.makedirs(broken)
        fake_erl(os.path.join(broken, "erl"), eval_fails=True)
        rc, erl, err = self.source(path_first=broken)
        self.assertEqual(rc, 0, err)
        self.assertEqual(erl, os.path.join(self.kerl_root, "bin", "erl"), err)

    def test_unset_home_does_not_kill_a_strict_caller(self):
        rc, erl, err = self.source(home=False)
        self.assertEqual(rc, 0, err)
        self.assertNotEqual(erl, "", err)  # survived and printed

    def test_an_unobtainable_pin_leaves_path_unchanged_and_says_so(self):
        rc, erl, err = self.source(pin="96.1")
        self.assertEqual(rc, 0, err)
        self.assertEqual(erl, os.path.join(self.path_dir, "erl"))
        self.assertIn("not found", err)

    def test_an_invalid_pin_falls_back_to_the_default_never_looser(self):
        rc, _, err = self.source(pin="'28; rm -rf x'")
        self.assertEqual(rc, 0, err)
        self.assertIn("using the pinned default", err)


if __name__ == "__main__":
    unittest.main()
