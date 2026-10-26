#!/usr/bin/env python3
"""A docs/ file a Meson target reads must be re-included in the Docker context.

/.dockerignore excludes docs/ wholesale, and the server images `COPY . .` the
repo root before `meson setup`. A build input under docs/ (for example the TSV
server/core/meson.build embeds) is therefore absent in the image build unless
/.dockerignore carries an explicit `!<repo-relative path>` line. CI does not
build the images, so the failure otherwise surfaces only at release time.
Lexical check: no Docker pattern matching is emulated.
"""
import os
import posixpath
import re
import subprocess
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
FILES_ARG = re.compile(r"files\(\s*'([^']+)'")


class DockerContextEmbeds(unittest.TestCase):
    def test_docs_inputs_of_meson_targets_are_reincluded(self):
        # Tracked files only: walking the tree would also scan build dirs and
        # vcpkg_installed (third-party meson.build files, minutes of I/O).
        try:
            files = subprocess.run(
                ["git", "-C", REPO, "ls-files", "*meson.build"],
                capture_output=True, text=True, check=True, timeout=60,
            ).stdout.split()
        except (OSError, subprocess.SubprocessError):
            self.skipTest("git unavailable: cannot list tracked meson.build files")
        needed = set()
        for rel in files:
            with open(os.path.join(REPO, rel), encoding="utf-8") as f:
                code = "\n".join(l.split("#", 1)[0] for l in f.read().splitlines())
            for m in FILES_ARG.finditer(code):
                target = posixpath.normpath(posixpath.join(posixpath.dirname(rel), m.group(1)))
                if target.startswith("docs/"):
                    needed.add(target)
        self.assertTrue(needed, "expected at least one docs/ build input (the retention TSV)")
        with open(os.path.join(REPO, ".dockerignore"), encoding="utf-8") as f:
            lines = [l.strip() for l in f]
        # Docker applies rules in order, last match wins: the `!` line must follow `docs/`.
        excl = lines.index("docs/") if "docs/" in lines else -1
        missing = sorted(p for p in needed if "!" + p not in lines or lines.index("!" + p) < excl)
        self.assertEqual(missing, [],
                         "add `!<path>` AFTER the docs/ exclusion in /.dockerignore")


if __name__ == "__main__":
    unittest.main()
