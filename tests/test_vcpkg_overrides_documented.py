#!/usr/bin/env python3
"""Every vcpkg.json `overrides` entry is documented, and every documented pin exists.

An override pins a port to an exact version above the `builtin-baseline`,
normally for a security fix, and it holds the port back once the baseline
passes it. The monthly baseline-bump PR rewrites only the baseline SHA, so the
obligation to delete an override lives in docs: the "Security dependency pins"
table in docs/build-guide.md (what the pin fixes, when to delete it) and the
checklist in docs/dependency-updates.md "vcpkg baseline". This test keeps the
table coupled to the manifest:

  1. each `overrides` entry has a row whose first two cells are the port (in
     backticks) and the same version;
  2. each row names a port that has an `overrides` entry, so a deleted
     override cannot leave a stale row claiming a pin that no longer exists.

It cannot tell whether the baseline has passed a pin; that check is the
checklist's, made by the reviewer of the baseline bump.

Stdlib only; never edits the checkout.
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "vcpkg.json"
GUIDE = ROOT / "docs" / "build-guide.md"
HEADING = "### Security dependency pins"
ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*([^|\s]+)\s*\|")


def overrides(manifest_text: str) -> dict:
    data = json.loads(manifest_text)
    out = {}
    for entry in data.get("overrides", []):
        version = entry.get("version") or entry.get("version-string") or entry.get(
            "version-semver") or entry.get("version-date")
        if "port-version" in entry:
            version = f"{version}#{entry['port-version']}"
        out[entry["name"]] = version
    return out


def documented(guide_text: str):
    """Rows of the first table in the HEADING section: {port: version}, or None if absent."""
    lines = guide_text.splitlines()
    try:
        start = lines.index(HEADING)
    except ValueError:
        return None
    rows, in_table = {}, False
    for line in lines[start + 1:]:
        if line.startswith("#"):
            break
        if line.startswith("|"):
            in_table = True
            if m := ROW.match(line):
                rows[m.group(1)] = m.group(2)
        elif in_table:
            break
    return rows


def problems(manifest_text: str, guide_text: str):
    pins = overrides(manifest_text)
    rows = documented(guide_text)
    if rows is None:
        return [f"docs/build-guide.md has no '{HEADING}' section"] if pins else []
    errs = []
    for port, version in sorted(pins.items()):
        if port not in rows:
            errs.append(f"vcpkg.json overrides {port} {version}, but docs/build-guide.md "
                        f"'{HEADING}' has no row for it (what it fixes, when to delete it)")
        elif rows[port] != version:
            errs.append(f"vcpkg.json overrides {port} to {version}; the build-guide row says "
                        f"{rows[port]}")
    for port in sorted(set(rows) - set(pins)):
        errs.append(f"docs/build-guide.md '{HEADING}' documents a {port} pin that vcpkg.json "
                    "no longer overrides: delete the row")
    return errs


class Checkout(unittest.TestCase):
    def test_overrides_and_pins_table_agree(self):
        errs = problems(MANIFEST.read_text(encoding="utf-8"), GUIDE.read_text(encoding="utf-8"))
        self.assertEqual(errs, [], "\n".join(errs))


class SelfTest(unittest.TestCase):
    GUIDE = (f"## vcpkg\n\n{HEADING}\n\nIntro.\n\n| Port | Pinned | Fixes | Delete when |\n"
             "|---|---|---|---|\n| `brotli` | 1.2.1 | CVE | later |\n\nMore text.\n")

    @staticmethod
    def manifest(*entries):
        return json.dumps({"name": "x", "overrides": [dict(e) for e in entries]})

    def test_matching_passes(self):
        self.assertEqual(problems(self.manifest({"name": "brotli", "version": "1.2.1"}),
                                  self.GUIDE), [])

    def test_undocumented_override_fails(self):
        errs = problems(self.manifest({"name": "brotli", "version": "1.2.1"},
                                      {"name": "zlib", "version": "1.3.2"}), self.GUIDE)
        self.assertTrue(any("zlib" in e and "no row" in e for e in errs), errs)

    def test_version_mismatch_fails(self):
        errs = problems(self.manifest({"name": "brotli", "version": "1.2.2"}), self.GUIDE)
        self.assertTrue(any("1.2.2" in e for e in errs), errs)

    def test_port_version_is_part_of_the_pin(self):
        errs = problems(self.manifest({"name": "brotli", "version": "1.2.1", "port-version": 1}),
                        self.GUIDE)
        self.assertTrue(any("1.2.1#1" in e for e in errs), errs)

    def test_stale_row_fails(self):
        errs = problems(self.manifest(), self.GUIDE)
        self.assertTrue(any("no longer overrides" in e for e in errs), errs)

    def test_missing_section_fails_only_with_overrides(self):
        self.assertTrue(problems(self.manifest({"name": "brotli", "version": "1.2.1"}), "# x\n"))
        self.assertEqual(problems(self.manifest(), "# x\n"), [])


if __name__ == "__main__":
    unittest.main()
