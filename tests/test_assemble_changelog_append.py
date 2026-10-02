#!/usr/bin/env python3
"""Tests for `scripts/assemble-changelog.py promote X.Y.Z --append` (#5221).

A fix that lands after a version was promoted (a release-candidate hotfix)
leaves its fragment in changelog.d/, and a plain `promote X.Y.Z` refuses an
existing section. --append folds those fragments into the existing section.
These tests run the real script against a temporary CHANGELOG.md and
changelog.d/. Stdlib only.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "assemble-changelog.py"

CHANGELOG = """# Changelog

## [Unreleased]

Unreleased changes live in changelog.d/.

## [1.2.0] - 2026-09-01

### Added

- **Existing added bullet.**

### Fixed

- **Existing fixed bullet.**

## [1.1.0] - 2026-08-01

### Fixed

- **Older release bullet.**
"""


class PromoteAppend(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_cl_")
        self.dir = Path(self.tmp.name)
        self.changelog = self.dir / "CHANGELOG.md"
        self.changelog.write_text(CHANGELOG, encoding="utf-8")
        self.frags = self.dir / "changelog.d"
        self.frags.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def frag(self, name: str, body: str) -> Path:
        p = self.frags / name
        p.write_text(body + "\n", encoding="utf-8")
        return p

    def run_append(self, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--changelog", str(self.changelog),
             "--fragments-dir", str(self.frags), "promote", "1.2.0", "--append", *extra],
            capture_output=True, text=True)

    def section(self) -> str:
        t = self.changelog.read_text(encoding="utf-8")
        a = t.index("## [1.2.0]")
        return t[a:t.index("\n## [1.1.0]")]

    def test_appends_into_existing_and_new_subsections(self):
        f1 = self.frag("10-a.fixed.md", "- **New fixed bullet.**")
        f2 = self.frag("11-b.security.md", "- **New security bullet.**")
        f3 = self.frag("12-c.changed.md", "- **New changed bullet.**")
        r = self.run_append()
        self.assertEqual(r.returncode, 0, r.stderr)
        sec = self.section()
        heads = [l for l in sec.split("\n") if l.startswith("### ")]
        self.assertEqual(heads, ["### Added", "### Changed", "### Fixed", "### Security"])
        self.assertLess(sec.index("Existing fixed bullet"), sec.index("New fixed bullet"))
        for text in ("Existing added bullet", "New changed bullet", "New security bullet"):
            self.assertIn(text, sec)
        self.assertTrue(sec.startswith("## [1.2.0] - 2026-09-01"))
        self.assertIn("Older release bullet", self.changelog.read_text(encoding="utf-8"))
        self.assertNotIn("New fixed bullet", self.changelog.read_text(encoding="utf-8").split("## [1.1.0]")[1])
        for f in (f1, f2, f3):
            self.assertFalse(f.exists())

    def test_date_override(self):
        self.frag("10-a.fixed.md", "- **New fixed bullet.**")
        r = self.run_append("--date", "2026-10-10")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.section().startswith("## [1.2.0] - 2026-10-10"))

    def test_refuses_missing_section(self):
        self.frag("10-a.fixed.md", "- **x.**")
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "--changelog", str(self.changelog),
             "--fragments-dir", str(self.frags), "promote", "9.9.9", "--append"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("no ## [9.9.9] section", r.stderr)
        self.assertEqual(self.changelog.read_text(encoding="utf-8"), CHANGELOG)

    def test_refuses_without_fragments(self):
        r = self.run_append()
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.changelog.read_text(encoding="utf-8"), CHANGELOG)

    def test_refuses_legacy_unreleased_content(self):
        self.changelog.write_text(CHANGELOG.replace(
            "Unreleased changes live in changelog.d/.\n",
            "Unreleased changes live in changelog.d/.\n\n### Fixed\n\n- **Legacy bullet.**\n"), encoding="utf-8")
        f = self.frag("10-a.fixed.md", "- **x.**")
        r = self.run_append()
        self.assertEqual(r.returncode, 1)
        self.assertIn("legacy subsections", r.stderr)
        self.assertTrue(f.exists())

    def test_bad_fragment_aborts_without_changes(self):
        self.frag("10-a.fixed.md", "not a bullet")
        r = self.run_append()
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.changelog.read_text(encoding="utf-8"), CHANGELOG)

    def test_append_requires_promote(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "--check", "--append"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
