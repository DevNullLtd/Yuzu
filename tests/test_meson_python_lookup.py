#!/usr/bin/env python3
"""Every Meson target that runs a repo script uses `yuzu_python`.

The root meson.build defines one interpreter for all script targets (on
Windows the interpreter running Meson; a bare find_program('python3') there
resolves MSYS2's /usr/bin/python3, which cannot open C:/ paths). A second,
ad-hoc lookup silently reintroduces that failure: one arrived through an
ordinary dev merge within hours of the rule landing. This test fails on any
find_program() of a python interpreter outside the single definition.
"""
import os
import re
import subprocess
import sys
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
LOOKUP = re.compile(r"find_program\(\s*'python")
FIND_INSTALLATION = re.compile(r"find_installation\(")


class MesonPythonLookup(unittest.TestCase):
    def test_no_ad_hoc_python_lookup_in_any_meson_build(self):
        # Tracked files only: walking the tree would also scan build dirs and
        # vcpkg_installed (third-party meson.build files, minutes of I/O).
        try:
            files = subprocess.run(
                ["git", "-C", REPO, "ls-files", "*meson.build"],
                capture_output=True, text=True, check=True, timeout=60,
            ).stdout.split()
        except (OSError, subprocess.SubprocessError):
            self.skipTest("git unavailable: cannot list tracked meson.build files")
        offenders, installations = [], []
        for rel in files:
            with open(os.path.join(REPO, rel), encoding="utf-8") as f:
                text = f.read()
            code = "\n".join(l.split("#", 1)[0] for l in text.splitlines())
            # Whitespace-insensitive, so a call split across lines is caught.
            for m in LOOKUP.finditer(code):
                line = code.count("\n", 0, m.start()) + 1
                offenders.append(f"{rel}:{line}: {text.splitlines()[line - 1].strip()}")
            installations += [rel for _ in FIND_INSTALLATION.finditer(code)]
        self.assertEqual(installations, ["meson.build"],
                         "exactly one find_installation() (the yuzu_python definition)")
        # The single definition (root meson.build, non-Windows branch).
        allowed = [o for o in offenders
                   if o.startswith("meson.build:") and "yuzu_python = find_program" in o]
        self.assertEqual(len(allowed), 1, offenders)
        self.assertEqual([o for o in offenders if o not in allowed], [],
                         "use yuzu_python instead of a fresh python lookup")


if __name__ == "__main__":
    sys.exit(unittest.main())
