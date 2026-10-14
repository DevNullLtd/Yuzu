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


class MesonPythonLookup(unittest.TestCase):
    def test_no_ad_hoc_python_lookup_in_any_meson_build(self):
        try:
            files = subprocess.run(
                ["git", "-C", REPO, "ls-files", "*meson.build"],
                capture_output=True, text=True, check=True, timeout=60,
            ).stdout.split()
        except (OSError, subprocess.SubprocessError):
            files = []
            for root, _, names in os.walk(REPO):
                if "meson.build" in names and "/." not in root.replace("\\", "/"):
                    files.append(os.path.relpath(os.path.join(root, "meson.build"), REPO))
        offenders = []
        for rel in files:
            with open(os.path.join(REPO, rel), encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    if LOOKUP.search(line) and not line.lstrip().startswith("#"):
                        offenders.append(f"{rel}:{n}: {line.strip()}")
        # The single definition (root meson.build, non-Windows branch).
        allowed = [o for o in offenders
                   if o.startswith("meson.build:") and "yuzu_python = find_program" in o]
        self.assertEqual(len(allowed), 1, offenders)
        self.assertEqual([o for o in offenders if o not in allowed], [],
                         "use yuzu_python instead of a fresh python lookup")


if __name__ == "__main__":
    sys.exit(unittest.main())
