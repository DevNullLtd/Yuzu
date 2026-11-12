#!/usr/bin/env python3
"""Regression net for the `server` feature option (ADR-0035 ladder step 3).

The server is supported on Linux only. Step 3 replaced the boolean
`build_server` with a feature option that turns the server off on any
non-Linux TARGET by itself, so the Windows and macOS CI legs need no flag
(a stored non-default value would break the reconfigure of an older branch on
Wee Tam's persistent build dirs). These checks pin that contract.

Lexical (always runs, stdlib only):

- meson.options declares `server` as a feature defaulting to `auto`, and
  keeps `build_server` as a DEPRECATED boolean defaulting to `true`. Deleting
  `build_server` makes Meson refuse to reconfigure any build dir that stored
  it ("Unknown options"), even with --wipe, so its removal is a planned
  wipe-or-rename event (ADR-0035 step 4), never a quiet cleanup.
- meson.build derives `build_server` from the feature with
  `disable_auto_if(_server_host != 'linux')`, errors on
  `-Dserver=enabled` for a non-Linux target and on `enabled` contradicting a
  passed or stored `build_server=false`, still ANDs in the deprecated boolean, and does
  all of that before the first dependency lookup (so a non-Linux
  misconfiguration fails with the ADR message, not a missing-package error).
  No other meson.build reads either option.

Behavioural (runs when meson and a C/C++ compiler are on PATH): configures
the real tree with a cross file for a Windows target and for a Linux target,
in a temporary build dir, and checks each outcome that is decided before the
dependency lookups. The configure is expected to stop later on missing
vcpkg packages; only the early outcome is asserted.

Each lexical check is also run against a mutated copy of the sources and must
fail there, so a check that stops matching anything cannot pass silently.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OPTIONS = ROOT / "meson.options"
BUILD = ROOT / "meson.build"
SETUP = ROOT / "scripts" / "setup.sh"
GATING = ROOT / "tests" / "shell" / "test_build_examples_gating.sh"

HOST_LOWER = "_server_host = host_machine.system().to_lower()"
DERIVE = "_server_opt = get_option('server').disable_auto_if(_server_host != 'linux')"
ASSIGN = "build_server   = _server_opt.allowed() and get_option('build_server')"
NON_LINUX_ERROR = re.compile(
    r"^if _server_opt\.enabled\(\) and _server_host != 'linux'\n"
    r"  error\('-Dserver=enabled: the Yuzu server is Linux-only[^\n]*\)\n"
    r"endif$", re.M)
CONTRADICTION_ERROR = re.compile(
    r"^if _server_opt\.enabled\(\) and not get_option\('build_server'\)\n"
    r"  error\('-Dserver=enabled contradicts the deprecated -Dbuild_server=false[^\n]*\)\n"
    r"endif$", re.M)


def option_line(options: str, name: str) -> str:
    found = re.findall(rf"^option\('{re.escape(name)}',[^\n]*$", options, re.M)
    return found[0] if len(found) == 1 else ""


def problems(options: str, build: str, other_builds: dict) -> list:
    found = []

    server = option_line(options, "server")
    if not server:
        found.append("meson.options: expected exactly one `server` option")
    else:
        if not re.search(r"type: 'feature'", server):
            found.append("meson.options: `server` must be a feature option")
        if not re.search(r"value: 'auto'", server):
            found.append("meson.options: `server` must default to auto (auto is what turns it off off-Linux)")

    legacy = option_line(options, "build_server")
    if not legacy:
        found.append("meson.options: `build_server` is gone; deleting it breaks every build dir "
                     "that stored it (ADR-0035 step 4 plans that, with the dirs deleted or renamed)")
    else:
        if not re.search(r"type: 'boolean'", legacy) or not re.search(r"value: true\b", legacy):
            found.append("meson.options: `build_server` must stay a boolean defaulting to true")
        if not re.search(r"deprecated: true\b", legacy):
            found.append("meson.options: `build_server` must stay deprecated: true")

    code = "\n".join(l for l in build.splitlines() if not l.lstrip().startswith("#"))
    # Meson keeps a cross file's `system = 'Linux'` verbatim: the comparison must be on a lowercased copy.
    if code.count(HOST_LOWER) != 1:
        found.append("meson.build: _server_host must be host_machine.system().to_lower(), assigned once")
    # No raw (case-preserving) host_machine.system() use between that line and the feature summary's end.
    i, j = code.find(HOST_LOWER), code.find("build_examples = get_option('build_examples')")
    if i != -1 and j > i and "host_machine.system()" in code[i + len(HOST_LOWER):j]:
        found.append("meson.build: the server guard must use _server_host, not a raw host_machine.system()")
    if code.count(DERIVE) != 1:
        found.append("meson.build: the server feature must be derived exactly once with "
                     "disable_auto_if(_server_host != 'linux')")
    if code.count(ASSIGN) != 1:
        found.append("meson.build: build_server must be `_server_opt.allowed() and get_option('build_server')`")
    if len(NON_LINUX_ERROR.findall(code)) != 1:
        found.append("meson.build: -Dserver=enabled on a non-Linux target must be a configure error")
    if len(CONTRADICTION_ERROR.findall(code)) != 1:
        found.append("meson.build: -Dserver=enabled with a passed or stored build_server=false must be a configure error")
    # Any indentation: an assignment inside an `if` after the guard re-decides the value.
    if len(re.findall(r"^\s*build_server\s*=(?!=)", code, re.M)) != 1:
        found.append("meson.build: build_server must be assigned exactly once")
    if code.count("get_option('server')") != 1 or code.count("get_option('build_server')") != 2:
        found.append("meson.build: the option is read somewhere other than the guard")

    # The guard sits before the first dependency lookup.
    first_dep = re.search(r"\bdependency\(|find_library\(|vcpkg_installed", code)
    guard_end = code.find(ASSIGN)
    if first_dep and guard_end != -1 and first_dep.start() < guard_end:
        found.append("meson.build: the server guard must come before the first dependency lookup")

    for path, text in other_builds.items():
        # subdir() shares meson.build's variable scope, so a reassignment there reaches the guard's value.
        if re.search(r"^\s*build_server\s*=(?!=)", text, re.M):
            found.append(f"{path}: assigns build_server; meson.build's guard is the only assignment")
        if re.search(r"get_option\('(?:build_)?server'\)", text):
            found.append(f"{path}: reads the server option; meson.build's `build_server` variable is the only reader")
    return found


def other_meson_builds() -> dict:
    out = subprocess.run(["git", "ls-files", "*meson.build"], cwd=ROOT,
                         capture_output=True, text=True)
    paths = out.stdout.split() if out.returncode == 0 else []
    return {p: (ROOT / p).read_text(encoding="utf-8") for p in paths
            if p != "meson.build" and (ROOT / p).is_file()}


class ServerFeatureOptionLexical(unittest.TestCase):
    def setUp(self):
        self.options = OPTIONS.read_text(encoding="utf-8")
        self.build = BUILD.read_text(encoding="utf-8")
        self.others = other_meson_builds()

    def test_source_is_clean(self):
        self.assertEqual(problems(self.options, self.build, self.others), [])

    def test_mutations_are_caught(self):
        mutations = {
            "server option deleted": ("options", "option('server',", "option('server_x',"),
            "server default enabled": ("options", "type: 'feature', value: 'auto'", "type: 'feature', value: 'enabled'"),
            "server made boolean": ("options", "type: 'feature', value: 'auto'", "type: 'boolean', value: true"),
            "build_server deleted": ("options", "option('build_server',", "option('build_server_x',"),
            "build_server not deprecated": ("options", "value: true,  deprecated: true,", "value: true,"),
            "build_server default false": ("options", "type: 'boolean', value: true,  deprecated: true", "type: 'boolean', value: false, deprecated: true"),
            "cross-file case kept verbatim": ("build", HOST_LOWER, "_server_host = host_machine.system()"),
            "guard reads the raw system": ("build", "if not build_server and _server_host != 'linux'", "if not build_server and host_machine.system() != 'linux'"),
            "auto not disabled off-Linux": ("build", ".disable_auto_if(_server_host != 'linux')", ""),
            "auto disabled on Linux": ("build", "disable_auto_if(_server_host != 'linux')", "disable_auto_if(_server_host == 'linux')"),
            "non-Linux enabled error dropped": ("build", "if _server_opt.enabled() and _server_host != 'linux'\n  error(", "if _server_opt.enabled() and _server_host != 'linux'\n  warning("),
            "contradiction error dropped": ("build", "if _server_opt.enabled() and not get_option('build_server')\n  error(", "if _server_opt.enabled() and not get_option('build_server')\n  message("),
            "deprecated boolean ignored": ("build", ASSIGN, "build_server   = _server_opt.allowed()"),
            "boolean alone decides": ("build", ASSIGN, "build_server   = get_option('build_server')"),
            "second assignment": ("build", "build_examples = get_option('build_examples')", "build_server = true\nbuild_examples = get_option('build_examples')"),
            "indented reassignment": ("build", "build_examples = get_option('build_examples')", "if true\n  build_server = true\nendif\nbuild_examples = get_option('build_examples')"),
            "guard after a dependency": ("build", "# ── Feature summary", "_early = dependency('zlib')\n# ── Feature summary"),
        }
        for name, (which, old, new) in mutations.items():
            with self.subTest(mutation=name):
                srcs = {"options": self.options, "build": self.build}
                self.assertIn(old, srcs[which], f"mutation anchor for {name!r} not found")
                srcs[which] = srcs[which].replace(old, new, 1)
                self.assertNotEqual(problems(srcs["options"], srcs["build"], self.others), [],
                                    f"{name!r} was not caught")
        with self.subTest(mutation="subdir reassigns build_server"):
            others = dict(self.others)
            others["tests/meson.build"] = "  build_server = true\n"
            self.assertNotEqual(problems(self.options, self.build, others), [])
        with self.subTest(mutation="subdir reads the option"):
            others = dict(self.others)
            others["server/meson.build"] = "if get_option('build_server')\nendif\n"
            self.assertNotEqual(problems(self.options, self.build, others), [])


SETUP_GUARD = 'if [[ "$HOST_OS" != "linux" && -z "$CROSS_FILE" ]]; then\n'
SETUP_ARGS = "  VCPKG_INSTALL_ARGS+=(--x-no-default-features --x-feature=tests)\n"


def setup_problems(setup: str, gating: str) -> list:
    """setup.sh installs the agent-only profile off Linux, with Catch2
    unconditionally; the gating test asserts there is no server target off
    Linux. Both are named in the ADR-0035 step-3 Status block."""
    found = []
    i = setup.find(SETUP_GUARD)
    if i < 0:
        return ["setup.sh: the non-Linux, no-cross-file agent-only vcpkg block is gone"]
    block = setup[i:setup.find("\nfi\n", i)]
    if SETUP_ARGS not in block + "\n":
        found.append("setup.sh: off Linux the install must pass `--x-no-default-features --x-feature=tests` "
                     "unconditionally (a plain run after `--tests` must not drop Catch2)")
    # The block is exactly the one install-args line and an echo: nothing else may alter the array here.
    body = [l.strip() for l in block.splitlines()[1:] if l.strip() and not l.strip().startswith("#")]
    if [l for l in body if not l.startswith("echo ") and l != SETUP_ARGS.strip()]:
        found.append("setup.sh: the agent-only block must hold only the install-args line and an echo")
    # Everywhere else in the file the array is only ever appended to once the declaration has run:
    # a later reset (`=(`, `=`, `unset`) would silently drop --x-feature=tests (the A-R1 defect).
    uses = [l.strip() for l in setup.splitlines()
            if "VCPKG_INSTALL_ARGS" in l and not l.strip().startswith("#")]
    resets = [l for l in uses if re.search(r"VCPKG_INSTALL_ARGS=|unset\s+VCPKG_INSTALL_ARGS|VCPKG_INSTALL_ARGS\[", l)
              and "[@]" not in l]
    if len(resets) != 1 or not resets[0].startswith("VCPKG_INSTALL_ARGS=("):
        found.append("setup.sh: VCPKG_INSTALL_ARGS must be declared once and only appended to (+=) afterwards")
    if len(uses) != 4:
        found.append(f"setup.sh: VCPKG_INSTALL_ARGS has {len(uses)} uses, expected 4 (declare, --triplet, agent-only, invoke); "
                     "a deliberate new use is a reviewed edit of this count and of setup_problems()'s other pins, not a bypass")
    if re.search(r"\bif\b[^\n]*\$TESTS", block):
        found.append("setup.sh: --x-feature=tests must not be conditional on --tests off Linux")
    if '"yuzu-server" in names' not in gating or 'uname_s != "Linux"' not in gating:
        found.append("test_build_examples_gating.sh: must assert no yuzu-server target off Linux")
    return found


class SetupAndGatingLexical(unittest.TestCase):
    def setUp(self):
        self.setup = SETUP.read_text(encoding="utf-8")
        self.gating = GATING.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        self.assertEqual(setup_problems(self.setup, self.gating), [])

    def test_mutations_are_caught(self):
        mutations = {
            "tests feature conditional again": ("setup", SETUP_ARGS,
                "  VCPKG_INSTALL_ARGS+=(--x-no-default-features)\n  if $TESTS; then\n    VCPKG_INSTALL_ARGS+=(--x-feature=tests)\n  fi\n"),
            "tests feature dropped": ("setup", SETUP_ARGS, "  VCPKG_INSTALL_ARGS+=(--x-no-default-features)\n"),
            "opt-out dropped": ("setup", SETUP_ARGS, "  VCPKG_INSTALL_ARGS+=(--x-feature=tests)\n"),
            "later reset drops tests": ("setup", '"$VCPKG_EXE" "${VCPKG_INSTALL_ARGS[@]}"', 'VCPKG_INSTALL_ARGS=(install --x-manifest-root="$PROJECT_ROOT" --x-no-default-features)\n"$VCPKG_EXE" "${VCPKG_INSTALL_ARGS[@]}"'),
            "later conditional reset": ("setup", '"$VCPKG_EXE" "${VCPKG_INSTALL_ARGS[@]}"', '[[ "$BUILDTYPE" == release ]] && VCPKG_INSTALL_ARGS=(--x-no-default-features)\n"$VCPKG_EXE" "${VCPKG_INSTALL_ARGS[@]}"'),
            "later unset": ("setup", '"$VCPKG_EXE" "${VCPKG_INSTALL_ARGS[@]}"', 'unset VCPKG_INSTALL_ARGS\n"$VCPKG_EXE" "${VCPKG_INSTALL_ARGS[@]}"'),
            "reset inside the block": ("setup", SETUP_ARGS, SETUP_ARGS + "  VCPKG_INSTALL_ARGS=(--x-no-default-features)\n"),
            "block removed": ("setup", SETUP_GUARD, 'if [[ "$HOST_OS" == "none" ]]; then\n'),
            "gating server-target assertion dropped": ("gating", '"yuzu-server" in names', "False"),
            "gating off-Linux condition dropped": ("gating", 'uname_s != "Linux"', "False"),
        }
        for name, (which, old, new) in mutations.items():
            with self.subTest(mutation=name):
                srcs = {"setup": self.setup, "gating": self.gating}
                self.assertIn(old, srcs[which], f"mutation anchor for {name!r} not found")
                srcs[which] = srcs[which].replace(old, new, 1)
                self.assertNotEqual(setup_problems(srcs["setup"], srcs["gating"]), [], f"{name!r} was not caught")


def _tool(name):
    return shutil.which(name)


HAVE_TOOLS = bool(_tool("meson") and _tool("cc") and _tool("c++"))


@unittest.skipUnless(HAVE_TOOLS, "meson, cc and c++ are needed for the behavioural configure")
class ServerFeatureOptionBehaviour(unittest.TestCase):
    """Configure the real tree for a Windows and a Linux target and check the
    outcome decided before the dependency lookups."""

    def configure(self, system: str, *opts: str) -> str:
        tmp = tempfile.mkdtemp(prefix="yuzu_test_server_opt_")
        try:
            cross = Path(tmp) / "cross.ini"
            cross.write_text(
                "[binaries]\nc = 'cc'\ncpp = 'c++'\n"
                f"[host_machine]\nsystem = '{system}'\ncpu_family = 'x86_64'\n"
                "cpu = 'x86_64'\nendian = 'little'\n",
                encoding="utf-8")
            env = dict(os.environ, VCPKG_ROOT=str(Path(tmp) / "no-vcpkg"))
            r = subprocess.run(
                ["meson", "setup", "--cross-file", str(cross), *opts,
                 str(Path(tmp) / "b"), str(ROOT)],
                capture_output=True, text=True, timeout=300, env=env)
            return r.stdout + r.stderr
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_windows_enabled_is_an_error(self):
        out = self.configure("windows", "-Dserver=enabled")
        self.assertIn("-Dserver=enabled: the Yuzu server is Linux-only and cannot be built for a windows target", out)

    def test_windows_auto_is_agent_only(self):
        out = self.configure("windows")
        self.assertIn("Server: off (the Yuzu server is Linux-only, ADR-0035; this windows build is agent-only)", out)
        self.assertNotIn("Linux-only and cannot be built", out)

    def test_darwin_auto_with_stored_true_is_agent_only(self):
        # A build dir from before step 3 may carry build_server=true; it cannot
        # turn the server on off Linux.
        out = self.configure("darwin", "-Dbuild_server=true")
        self.assertIn("this darwin build is agent-only", out)

    def test_linux_enabled_contradicting_deprecated_false_is_an_error(self):
        out = self.configure("linux", "-Dserver=enabled", "-Dbuild_server=false")
        self.assertIn("-Dserver=enabled contradicts the deprecated -Dbuild_server=false", out)

    def test_linux_deprecated_false_says_why_the_server_is_off(self):
        out = self.configure("linux", "-Dbuild_server=false")
        self.assertIn("Server: off because the deprecated -Dbuild_server=false is set", out)
        # An explicit -Dserver=disabled is the supported spelling: no deprecation nag.
        out = self.configure("linux", "-Dserver=disabled", "-Dbuild_server=false")
        self.assertNotIn("deprecated -Dbuild_server=false is set", out)

    def test_cross_file_system_case_is_ignored(self):
        # Meson keeps a cross file's `system = 'Linux'` verbatim (no warning):
        # the server must still be ON, and a capitalised non-Linux still off.
        out = self.configure("Linux")
        self.assertRegex(out, r"dependency|Dependency", out[-2000:])
        self.assertNotIn("Server: off", out)
        self.assertNotIn("Linux-only and cannot be built", out)
        out = self.configure("Windows", "-Dserver=enabled")
        self.assertIn("cannot be built for a windows target", out)

    def test_linux_auto_does_not_turn_the_server_off(self):
        out = self.configure("linux")
        # Prove the configure got past the guard (to the dependency lookups),
        # so the absence below is not just an earlier abort.
        self.assertRegex(out, r"dependency|Dependency", out[-2000:])
        self.assertNotIn("Server: off", out)
        self.assertNotIn("Linux-only and cannot be built", out)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
