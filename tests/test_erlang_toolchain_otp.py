#!/usr/bin/env python3
"""OTP pin resolution in scripts/erlang_toolchain.py.

Meson resolves the gateway's Erlang/OTP at configure time with
`erlang_toolchain.py find-otp`, and the build/test wrappers put the result first
on PATH (base_env). These tests pin the selection rules with fake OTP installs
(a bin/erl file beside releases/<major>/OTP_VERSION) in a temp dir, with HOME,
PATH and the version-manager dirs pointed into it. Real installs under the
well-known prefixes (/opt/homebrew, /usr/local, C:\\Program Files) are still
scanned, so every expectation uses a version no real install has (28.4.99,
97.1, ...) and stays hermetic on any CI host.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
sys.path.insert(0, SCRIPTS)
import erlang_toolchain as et  # noqa: E402


def make_install(root, version):
    """A fake OTP install at root: bin/erl + releases/<major>/OTP_VERSION."""
    bin_dir = os.path.join(root, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    rel = os.path.join(root, "releases", version.split(".")[0])
    os.makedirs(rel, exist_ok=True)
    with open(os.path.join(rel, "OTP_VERSION"), "w", encoding="ascii") as f:
        f.write(version + "\n")
    erl = os.path.join(bin_dir, "erl.exe" if sys.platform == "win32" else "erl")
    with open(erl, "w", encoding="ascii") as f:
        f.write("")
    os.chmod(erl, 0o755)
    return bin_dir


class OtpPinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="yuzu_test_otp_")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        env = {
            "HOME": self.home,
            "USERPROFILE": self.home,
            "PATH": os.path.join(self.tmp, "nothing"),
            "ASDF_DATA_DIR": os.path.join(self.tmp, "asdf"),
            "MISE_DATA_DIR": os.path.join(self.tmp, "mise"),
            "SystemRoot": os.environ.get("SystemRoot", ""),
        }
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def kerl(self, name, version):
        return make_install(os.path.join(self.home, ".kerl", name), version)

    def test_version_matches_is_a_floor_within_the_major(self):
        # Every pinned toolchain today must pass: the Windows runner contract
        # (28.4.2), the macOS CI download (28.5.0.7), setup-beam's latest 28.x.
        self.assertTrue(et.version_matches("28.4", "28.4"))
        self.assertTrue(et.version_matches("28.4.2", "28.4"))
        self.assertTrue(et.version_matches("28.5.0.7", "28.4"))
        self.assertTrue(et.version_matches("28.40", "28.4"))  # numeric, not string
        self.assertTrue(et.version_matches("28.0.1", "28"))
        self.assertFalse(et.version_matches("28.3.9", "28.4"))
        self.assertFalse(et.version_matches("29.1.1", "28.4"))  # a new major is a migration
        self.assertFalse(et.version_matches("27.3", "28"))
        self.assertFalse(et.version_matches(None, "28.4"))
        self.assertFalse(et.version_matches("", "28.4"))

    def test_otp_version_reads_the_install_without_starting_a_vm(self):
        bin_dir = make_install(os.path.join(self.tmp, "otp"), "28.4.2")
        self.assertEqual(et.otp_version(bin_dir), "28.4.2")
        self.assertIsNone(et.otp_version(os.path.join(self.tmp, "missing", "bin")))

    def test_wrong_version_on_path_loses_to_a_matching_kerl_install(self):
        # The case that broke the Mac: Homebrew OTP 29 first on PATH, kerl 28.4
        # installed but never consulted.
        path_bin = make_install(os.path.join(self.tmp, "brew"), "97.1.1")
        os.environ["PATH"] = path_bin
        kerl_bin = self.kerl("28.4.99", "28.4.99")
        bin_dir, version, source, report = et.find_otp("28.4")
        self.assertEqual((bin_dir, version, source), (kerl_bin, "28.4.99", "kerl"))
        self.assertTrue(any("97.1.1" in line for line in report))

    def test_matching_path_install_wins_over_a_higher_kerl_match(self):
        # The erl already on PATH is the operator's active choice.
        path_bin = make_install(os.path.join(self.tmp, "active"), "96.2.1")
        os.environ["PATH"] = path_bin
        self.kerl("96.2.9", "96.2.9")
        bin_dir, version, source, _ = et.find_otp("96.2")
        self.assertEqual((bin_dir, version, source), (path_bin, "96.2.1", "PATH"))

    def test_highest_matching_release_wins_among_non_path_installs(self):
        self.kerl("a", "95.4.1")
        self.kerl("b", "95.3.9")  # below the floor
        best = self.kerl("c", "95.6.2")
        self.kerl("d", "96.0.0")  # next major: never
        bin_dir, version, _, _ = et.find_otp("95.4")
        self.assertEqual((bin_dir, version), (best, "95.6.2"))

    def test_kerl_installs_are_found_without_kerl_on_path(self):
        kerl_bin = self.kerl("whatever-name", "94.1.3")
        bin_dir, _, source, _ = et.find_otp("94.1")
        self.assertEqual((bin_dir, source), (kerl_bin, "kerl"))

    def test_explicit_yuzu_otp_bin_of_the_wrong_version_is_an_error(self):
        # A wrong explicit choice must never be silently replaced.
        os.environ["YUZU_OTP_BIN"] = make_install(os.path.join(self.tmp, "explicit"), "93.1")
        self.kerl("93.2", "93.2")
        bin_dir, _, _, report = et.find_otp("93.2")
        self.assertIsNone(bin_dir)
        self.assertTrue(report[0].startswith("YUZU_OTP_BIN:"))

    def test_yuzu_otp_version_overrides_the_default_pin(self):
        os.environ["YUZU_OTP_VERSION"] = "92.7"
        kerl_bin = self.kerl("92.7.1", "92.7.1")
        self.assertEqual(et.wanted_otp_version(), "92.7")
        self.assertEqual(et.find_otp()[0], kerl_bin)

    def test_base_env_puts_the_pinned_otp_first_on_path(self):
        pinned = make_install(os.path.join(self.tmp, "pinned"), "91.1")
        os.environ["YUZU_OTP_BIN"] = pinned
        env = et.base_env()
        self.assertEqual(env["PATH"].split(os.pathsep)[0], pinned)

    @unittest.skipIf(sys.platform == "win32", "uses a POSIX shell script as the fake shim")
    def test_a_launcher_shim_resolves_to_the_real_install(self):
        # Chocolatey's bin/ holds an erl shim with no releases/ beside it; the
        # resolver must hand back the install's own bin/, never the shim dir
        # (rebar3 must not run through the escript shim).
        real_bin = make_install(os.path.join(self.tmp, "Erlang OTP"), "87.4.2")
        real_root = os.path.dirname(real_bin)
        shim_dir = os.path.join(self.tmp, "chocolatey", "bin")
        os.makedirs(shim_dir)
        shim = os.path.join(shim_dir, "erl")
        with open(shim, "w", encoding="ascii") as f:
            f.write("#!/bin/sh\nprintf '%s\\n%s' '" + real_root + "' '87.4.2'\n")
        os.chmod(shim, 0o755)
        os.environ["PATH"] = shim_dir
        bin_dir, version, source, report = et.find_otp("87.4")
        self.assertEqual((bin_dir, version, source), (real_bin, "87.4.2", "PATH"))
        self.assertTrue(any("shim for" in line for line in report))

    def test_cli_success_prints_bin_version_source(self):
        kerl_bin = self.kerl("90.3", "90.3")
        out = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "erlang_toolchain.py"),
             "find-otp", "--version", "90.3"],
            capture_output=True, text=True, env=dict(os.environ), timeout=60,
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.splitlines(), [kerl_bin, "90.3", "kerl"])

    def test_cli_failure_exits_1_and_lists_what_it_found(self):
        self.kerl("89.1", "89.1")
        out = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "erlang_toolchain.py"),
             "find-otp", "--version", "88.8"],
            capture_output=True, text=True, env=dict(os.environ), timeout=60,
        )
        self.assertEqual(out.returncode, 1)
        self.assertEqual(out.stdout, "")
        self.assertIn("no Erlang/OTP 88.8 found", out.stderr)
        self.assertIn("-> 89.1", out.stderr)


if __name__ == "__main__":
    unittest.main()
