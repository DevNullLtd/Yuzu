#!/usr/bin/env python3
"""OTP pin resolution in scripts/erlang_toolchain.py.

Meson resolves the gateway's Erlang/OTP at configure time with
`erlang_toolchain.py find-otp`, and the build/test wrappers put the result first
on PATH (base_env). These tests pin the selection rules with fake OTP installs
(a bin/erl file beside releases/<rel>/OTP_VERSION) in a temp dir, with HOME,
PATH and the version-manager dirs pointed into it.

Hermeticity: real installs under the well-known prefixes (/opt/homebrew,
/usr/local, /usr/lib*/erlang, C:\\Program Files) are still scanned by the
resolver, so every case that reaches that scan uses a made-up MAJOR (80-99)
that no real install has; a real OTP 28.x on the CI host can never win or
lose a comparison here. Cases that return before the scan (YUZU_OTP_BIN,
a matching PATH erl) may use any version.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SCRIPTS = os.path.join(REPO, "scripts")
sys.path.insert(0, SCRIPTS)
import erlang_toolchain as et  # noqa: E402

ERL = "erl.exe" if sys.platform == "win32" else "erl"


def make_install(root, version, releases=None, start_erl=None):
    """A fake OTP install at root: bin/erl + releases/<rel>/OTP_VERSION.

    releases: {rel: version} to create several release dirs (default: one,
    named after version's major). start_erl: the <otp_rel> to name in
    releases/start_erl.data, if any.
    """
    bin_dir = os.path.join(root, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    for rel, v in (releases or {version.split(".")[0]: version}).items():
        d = os.path.join(root, "releases", rel)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "OTP_VERSION"), "w", encoding="ascii") as f:
            f.write(v + "\n")
    if start_erl is not None:
        with open(os.path.join(root, "releases", "start_erl.data"), "w", encoding="ascii") as f:
            f.write(f"16.3 {start_erl}\n")
    erl = os.path.join(bin_dir, ERL)
    with open(erl, "w", encoding="ascii") as f:
        f.write("")
    os.chmod(erl, 0o755)
    return bin_dir


class OtpPinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="yuzu_test_otp_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
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

    def kerl(self, name, version, **kw):
        return make_install(os.path.join(self.home, ".kerl", name), version, **kw)

    def cli(self, *args):
        return subprocess.run(
            [sys.executable, os.path.join(SCRIPTS, "erlang_toolchain.py"), *args],
            capture_output=True, text=True, env=dict(os.environ), timeout=60,
        )

    # ── version arithmetic ──────────────────────────────────────────────────
    def test_version_matches_is_a_floor_within_the_major(self):
        # Every pinned toolchain today must pass: the Windows runner contract
        # (28.4.2), the macOS CI download (28.5.0.7), setup-beam's latest 28.x.
        for found in ("28.4", "28.4.0", "28.4.2", "28.5.0.7", "28.40", "28.5**", "28.4.2**"):
            self.assertTrue(et.version_matches(found, "28.4"), found)
        self.assertTrue(et.version_matches("28.0.1", "28"))
        self.assertTrue(et.version_matches("28.4", "28.4.0"))  # zero-padded, not (28,4) < (28,4,0)
        for found in ("28.3.9", "28.3**", "29.1.1", "27.3", None, ""):
            self.assertFalse(et.version_matches(found, "28.4"), found)

    def test_patch_apply_versions_compare_by_their_leading_digits(self):
        # otp_patch_apply writes e.g. "28.5**"; it is 28.5, not 28.0.
        self.assertEqual(et._version_key("28.5**"), (28, 5))
        self.assertEqual(et._version_key("28.4.2**"), (28, 4, 2))

    # ── reading an install ──────────────────────────────────────────────────
    def test_otp_version_reads_the_install_without_starting_a_vm(self):
        bin_dir = make_install(os.path.join(self.tmp, "otp"), "28.4.2")
        self.assertEqual(et.otp_version(bin_dir), "28.4.2")
        self.assertIsNone(et.otp_version(os.path.join(self.tmp, "missing", "bin")))

    def test_several_releases_use_the_live_one_named_by_start_erl_data(self):
        # A newer major installed over an older one leaves releases/28 behind.
        # The live release is 29; reporting the stale 28.4.2 would build on 29
        # while claiming 28.4 - the failure this resolver exists to prevent.
        root = os.path.join(self.tmp, "mixed")
        bin_dir = make_install(root, "86.1.1",
                               releases={"85": "85.4.2", "86": "86.1.1"}, start_erl="86")
        self.assertEqual(et.otp_version(bin_dir), "86.1.1")
        os.environ["PATH"] = bin_dir
        self.assertIsNone(et.find_otp("85.4")[0])

    def test_several_releases_without_start_erl_data_are_not_guessed(self):
        root = os.path.join(self.tmp, "ambiguous")
        bin_dir = make_install(root, "84.1", releases={"83": "83.4", "84": "84.1"})
        # No start_erl.data and the fake erl cannot run: unknown, not "83.4".
        failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        with mock.patch.object(et.subprocess, "run", return_value=failed):
            self.assertIsNone(et.otp_version(bin_dir))

    @unittest.skipIf(sys.platform == "win32", "POSIX symlink layout")
    def test_a_symlinked_erl_resolves_to_the_real_bin_not_the_shared_dir(self):
        # /usr/bin/erl -> /usr/lib64/erlang/bin/erl: never put /usr/bin first.
        real_bin = make_install(os.path.join(self.tmp, "lib64", "erlang"), "82.4.1")
        shared = os.path.join(self.tmp, "usr-bin")
        os.makedirs(shared)
        os.symlink(os.path.join(real_bin, "erl"), os.path.join(shared, "erl"))
        os.environ["PATH"] = shared
        bin_dir, version, source, _ = et.find_otp("82.4")
        self.assertEqual((os.path.realpath(bin_dir), version, source),
                         (os.path.realpath(real_bin), "82.4.1", "PATH"))
        self.assertNotEqual(os.path.realpath(bin_dir), os.path.realpath(shared))

    def test_a_launcher_shim_resolves_to_the_real_install(self):
        # Chocolatey's bin/ holds an erl shim with no releases/ beside it; the
        # resolver asks it for code:root_dir() and returns the install's own
        # bin/, never the shim dir (rebar3 must not run through the escript
        # shim). The VM probe is mocked so this runs on every platform.
        real_bin = make_install(os.path.join(self.tmp, "Erlang OTP"), "87.4.2")
        shim_dir = os.path.join(self.tmp, "chocolatey", "bin")
        os.makedirs(shim_dir)
        with open(os.path.join(shim_dir, ERL), "w", encoding="ascii") as f:
            f.write("")
        os.chmod(os.path.join(shim_dir, ERL), 0o755)
        probe = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=os.path.dirname(real_bin) + "\n87.4.2", stderr="")
        with mock.patch.object(et.subprocess, "run", return_value=probe):
            bin_dir, version = et.probe_install(shim_dir)
        self.assertEqual((os.path.normpath(bin_dir), version),
                         (os.path.normpath(real_bin), "87.4.2"))

    # ── selection rules ─────────────────────────────────────────────────────
    def test_wrong_version_on_path_loses_to_a_matching_kerl_install(self):
        # The case that broke the Mac: Homebrew OTP 29 first on PATH, kerl 28.4
        # installed but never consulted. (Made-up majors: hermetic.)
        path_bin = make_install(os.path.join(self.tmp, "brew"), "99.1.1")
        os.environ["PATH"] = path_bin
        kerl_bin = self.kerl("98.4.9", "98.4.9")
        bin_dir, version, source, report = et.find_otp("98.4")
        self.assertEqual((bin_dir, version, source), (kerl_bin, "98.4.9", "kerl"))
        self.assertIn(f"PATH: {path_bin} -> 99.1.1", report)

    def test_matching_path_install_wins_over_a_higher_kerl_match(self):
        # The erl already on PATH is the operator's active choice.
        path_bin = make_install(os.path.join(self.tmp, "active"), "96.2.1")
        os.environ["PATH"] = path_bin
        self.kerl("96.2.9", "96.2.9")
        self.assertEqual(et.find_otp("96.2")[:3], (path_bin, "96.2.1", "PATH"))

    def test_highest_matching_release_wins_among_non_path_installs(self):
        self.kerl("a", "95.4.1")
        self.kerl("b", "95.3.9")  # below the floor
        best = self.kerl("c", "95.6.2")
        self.kerl("d", "96.0.0")  # next major: never
        self.assertEqual(et.find_otp("95.4")[:2], (best, "95.6.2"))

    def test_kerl_installs_are_found_without_kerl_on_path(self):
        kerl_bin = self.kerl("whatever-name", "94.1.3")
        bin_dir, _, source, _ = et.find_otp("94.1")
        self.assertEqual((bin_dir, source), (kerl_bin, "kerl"))

    def test_explicit_yuzu_otp_bin_of_the_wrong_version_is_an_error(self):
        # A wrong explicit choice must never be silently replaced.
        explicit = make_install(os.path.join(self.tmp, "explicit"), "93.1")
        os.environ["YUZU_OTP_BIN"] = explicit
        self.kerl("93.2", "93.2")
        bin_dir, _, _, report = et.find_otp("93.2")
        self.assertIsNone(bin_dir)
        self.assertEqual(report, [f"YUZU_OTP_BIN: {explicit} -> 93.1"])

    def test_explicit_yuzu_otp_bin_with_no_erl_is_an_error_not_ignored(self):
        missing = os.path.join(self.tmp, "typo")
        os.environ["YUZU_OTP_BIN"] = missing
        self.kerl("92.2", "92.2")  # would match: must still not be chosen
        bin_dir, _, _, report = et.find_otp("92.2")
        self.assertIsNone(bin_dir)
        self.assertEqual(len(report), 1)
        self.assertTrue(report[0].startswith(f"YUZU_OTP_BIN: {missing} -> no working erl here"))

    def test_yuzu_otp_version_overrides_the_default_pin(self):
        os.environ["YUZU_OTP_VERSION"] = "92.7"
        kerl_bin = self.kerl("92.7.1", "92.7.1")
        self.assertEqual(et.wanted_otp_version(), "92.7")
        self.assertEqual(et.find_otp()[0], kerl_bin)

    # A fake Windows filesystem: an attacker-planted C:\Erlang (any user can
    # create it) beside a real C:\Program Files\Erlang OTP. glob answers
    # every pattern against it, so a C:\Erlang re-added in literal OR glob
    # form would be found - the test cannot pass vacuously.
    WIN_FILES = {
        "c:\\erlang\\bin\\erl.exe",
        "c:\\erlang\\erts-16.3\\bin\\escript.exe",
        "c:\\program files\\erlang otp\\bin\\erl.exe",
        "c:\\program files\\erlang otp\\erts-16.3\\bin\\escript.exe",
        "c:\\tools\\rebar3\\rebar3",
    }

    def _win_fs(self):
        import fnmatch
        dirs = {"c:\\erlang", "c:\\program files\\erlang otp"}

        def norm(p):
            return p.replace("/", "\\").lower()

        def isfile(p):
            return norm(p) in self.WIN_FILES

        def glob_(pattern):
            pat = norm(pattern)
            return sorted(x for x in (self.WIN_FILES | dirs) if fnmatch.fnmatch(x, pat))

        return (mock.patch.object(et.sys, "platform", "win32"),
                mock.patch.object(et.shutil, "which", return_value=None),
                mock.patch.object(et.os.path, "isfile", side_effect=isfile),
                mock.patch.object(et.glob, "glob", side_effect=glob_))

    def test_c_erlang_is_never_a_windows_candidate(self):
        # Any authenticated Windows user can create C:\Erlang; the runners build
        # as LOCAL SYSTEM. It must not be scanned (only an explicit choice).
        p1, p2, p3, p4 = self._win_fs()
        with p1, p2, p3, p4:
            dirs = [d.replace("/", "\\").lower() for _, d in et.otp_candidates()]
        # (On a POSIX test host abspath prefixes the fake C:\ paths with the
        # cwd, so match on the tail.)
        self.assertTrue(any(d.endswith("c:\\program files\\erlang otp\\bin") for d in dirs),
                        dirs)  # the scan works...
        self.assertFalse(any("c:\\erlang\\" in d + "\\" and "program files" not in d
                             for d in dirs), dirs)  # ...and skips C:\Erlang

    def test_rebar3_prefix_never_runs_an_escript_under_c_erlang(self):
        os.environ.pop("YUZU_ESCRIPT", None)
        p1, p2, p3, p4 = self._win_fs()
        with p1, p2, p3, p4, mock.patch.object(et, "find_otp", return_value=(None, None, None, [])):
            prefix = et.rebar3_prefix()
        self.assertEqual(prefix[0].replace("/", "\\").lower(),
                         "c:\\program files\\erlang otp\\erts-16.3\\bin\\escript.exe")

    def test_rebar3_prefix_with_only_c_erlang_finds_no_escript(self):
        # Order-independent: with no Program Files install at all, a C:\Erlang
        # root listed anywhere in the scan would be picked. It must not be.
        self.WIN_FILES = {f for f in OtpPinTests.WIN_FILES if "program files" not in f}
        os.environ.pop("YUZU_ESCRIPT", None)
        p1, p2, p3, p4 = self._win_fs()
        with p1, p2, p3, p4, \
                mock.patch.object(et, "find_otp", return_value=(None, None, None, [])), \
                mock.patch.object(et.sys, "stderr"), \
                self.assertRaises(SystemExit):
            et.rebar3_prefix()

    def test_a_candidate_path_with_a_line_break_is_refused(self):
        # Injected, not created: Windows cannot name a directory with a line
        # break. The probe reports a match, so only the refusal stops it.
        evil = os.path.join(self.home, ".kerl", "a\nb", "bin")
        with mock.patch.object(et, "otp_candidates", return_value=[("kerl", evil)]), \
                mock.patch.object(et, "probe_install", return_value=(evil, "77.4.1")):
            bin_dir, _, _, report = et.find_otp("77.4")
        self.assertIsNone(bin_dir)
        self.assertTrue(any("refused (line break in path)" in r for r in report), report)

    def test_start_erl_data_naming_a_path_is_not_followed(self):
        root = os.path.join(self.tmp, "crafted")
        bin_dir = make_install(root, "79.1", releases={"78": "78.4", "79": "79.1"},
                               start_erl="../../outside")
        # A real OTP_VERSION at the traversal target, so following the path
        # WOULD yield a version: the test fails if the digits rule is removed.
        outside = os.path.join(root, "releases", "..", "..", "outside")
        os.makedirs(outside, exist_ok=True)
        with open(os.path.join(outside, "OTP_VERSION"), "w", encoding="ascii") as f:
            f.write("78.9\n")
        failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        with mock.patch.object(et.subprocess, "run", return_value=failed):
            self.assertIsNone(et.otp_version(bin_dir))

    # ── base_env ────────────────────────────────────────────────────────────
    def test_base_env_puts_the_pinned_otp_first_on_path(self):
        os.environ["YUZU_OTP_VERSION"] = "91.1"
        pinned = make_install(os.path.join(self.tmp, "pinned"), "91.1")
        os.environ["YUZU_OTP_BIN"] = pinned
        self.assertEqual(et.base_env()["PATH"].split(os.pathsep)[0], pinned)

    def test_base_env_refuses_a_configured_otp_that_no_longer_matches(self):
        # Configured 91.1, later replaced by 90.x: fail loudly ("reconfigure"),
        # never fall through to whatever erl is next on PATH.
        os.environ["YUZU_OTP_VERSION"] = "91.1"
        os.environ["YUZU_OTP_BIN"] = make_install(os.path.join(self.tmp, "replaced"), "90.9")
        with mock.patch.object(et.sys, "stderr") as err, self.assertRaises(SystemExit) as cm:
            et.base_env()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("Reconfigure", "".join(c.args[0] for c in err.write.call_args_list))

    # ── CLI contract (Meson relies on the exit codes) ───────────────────────
    def test_cli_success_prints_bin_version_source(self):
        kerl_bin = self.kerl("90.3", "90.3")
        out = self.cli("find-otp", "--version", "90.3")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.splitlines(), [kerl_bin, "90.3", "kerl", "90.3"])

    def test_cli_no_match_exits_1_and_lists_what_it_found(self):
        self.kerl("89.1", "89.1")
        out = self.cli("find-otp", "--version", "88.8")
        self.assertEqual((out.returncode, out.stdout), (1, ""))
        self.assertIn("no Erlang/OTP 88.8 or later 88.x found", out.stderr)
        self.assertIn(f"kerl: {os.path.join(self.home, '.kerl', '89.1', 'bin')} -> 89.1",
                      out.stderr)

    def test_cli_invalid_pin_is_a_usage_error_not_a_skip(self):
        out = self.cli("find-otp", "--version", "28.4; rm -rf x")
        self.assertEqual(out.returncode, 2)

    def test_an_internal_failure_exits_3_never_1(self):
        # Meson skips the gateway only on 1; a resolver crash must not look
        # like "no matching OTP".
        with mock.patch.object(et, "find_otp", side_effect=RuntimeError("boom")), \
                mock.patch.object(et.sys, "stderr"):
            self.assertEqual(et.main(["find-otp", "--version", "80.1"]), et.EXIT_INTERNAL)


class PinCopiesAgree(unittest.TestCase):
    """The pin's copies that nothing else ties together must pass the pin."""

    def test_windows_runner_contract_and_macos_ci_versions_pass_the_pin(self):
        with open(os.path.join(REPO, "deploy", "windows", "toolchain-contract.json"),
                  encoding="utf-8") as f:
            contract = json.load(f)
        found = []

        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == "erlang" and isinstance(v, (str, list)):
                        found.extend(v if isinstance(v, list) else [v])
                    else:
                        walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(contract)
        self.assertTrue(found, "no erlang pin found in toolchain-contract.json")
        with open(os.path.join(REPO, ".github", "workflows", "ci.yml"), encoding="utf-8") as f:
            ci = re.findall(r"""^\s*OTP_VERSION:\s*['"]?([0-9][0-9.]*)['"]?\s*$""", f.read(), re.M)
        self.assertTrue(ci, "no OTP_VERSION pin found in ci.yml (macOS download)")
        found += ci
        for v in found:
            self.assertTrue(et.version_matches(v, et.DEFAULT_OTP_VERSION),
                            f"{v} does not pass DEFAULT_OTP_VERSION {et.DEFAULT_OTP_VERSION}")


if __name__ == "__main__":
    unittest.main()
