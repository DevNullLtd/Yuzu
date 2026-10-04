#!/usr/bin/env python3
"""test_software_vocabulary_consistency.py — #5328's installed-software vocabulary drift gate.

The typed installed-software store carries a `kind` and an `ecosystem` per row. The
agents emit the values; MCP `query_installed_software`, the OpenAPI description of
`GET /api/v1/inventory/software` and the inventory manual publish them; and the CPE
Lane-3 predicate (`is_os_native`, cpe_normalize.hpp) routes them. This script checks,
against the real tree, that:

  1. every published surface equals the agreed vocabulary (EXPECTED_*);
  2. every value an agent emits is in that vocabulary (emitted ⊆ published);
  3. every non-Lane-1 ecosystem and Lane-3 kind is named in `is_os_native`, and `pkg`
     is NOT a kind-level trigger (it is routed by its ecosystem).

Discovery is anti-vacuous: each emitter pattern must match a file and the emitted sets
must be non-empty, otherwise the test fails rather than passing on nothing.
Hermetic: parses sources only.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_KINDS = {"package", "app", "pkg", "feat"}
EXPECTED_ECOSYSTEMS = {
    "rpm", "deb", "apk", "pacman", "windows", "macos",
    "macos_pkgutil", "brew", "optional_feature",
}
LANE1 = {"rpm", "deb", "apk", "pacman"}
LANE3_KINDS = {"app", "feat"}

# Plain patterns only: Path.glob has no brace expansion.
EMITTER_GLOBS = [
    "agents/plugins/installed_apps/src/*.cpp",
    "agents/plugins/installed_apps/src/*.hpp",
    "agents/core/src/sync_source_installed_software.*",
]
MCP_SRC = "server/core/src/mcp_server.cpp"
OPENAPI_SRC = "server/core/src/rest_api_v1.cpp"
MANUAL = "docs/user-manual/inventory.md"
CPE_HDR = "server/core/src/cpe_normalize.hpp"

LITERAL_RE = re.compile(r'\b(kind|ecosystem)\s*=\s*"([a-z_]+)"')


def discover_sources(root, patterns):
    files = []
    for pat in patterns:
        found = sorted(root.glob(pat))
        if not found:
            raise AssertionError(f"emitter pattern matches no file: {pat}")
        files.extend(found)
    return files


def extract_literals(text):
    """Return ({kinds}, {ecosystems}) assigned from string literals."""
    kinds, ecos = set(), set()
    for field, value in LITERAL_RE.findall(text):
        (kinds if field == "kind" else ecos).add(value)
    return kinds, ecos


def extract_enumeration(text, field):
    """The `<field> (a|b|c)` enumeration; exactly one match or a hard failure."""
    found = re.findall(rf"\b{field} \(([a-z_|]+)\)", text)
    if len(found) != 1:
        raise AssertionError(f"expected exactly one `{field} (...)` enumeration, found {len(found)}")
    return set(found[0].split("|"))


def extract_table_row(text, field):
    """Backticked cell values of the manual's `| `<field>` |` row."""
    rows = [l for l in text.splitlines() if re.match(rf"\s*\| `{field}` \|", l)]
    if len(rows) != 1:
        raise AssertionError(f"expected exactly one `{field}` table row, found {len(rows)}")
    return set(re.findall(r"`([a-z_]+)`", rows[0].split("|", 2)[2]))


def read(rel):
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


class VocabularyConsistency(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        files = discover_sources(REPO_ROOT, EMITTER_GLOBS)
        cls.emitted_kinds, cls.emitted_ecos = set(), set()
        for f in files:
            k, e = extract_literals(f.read_text(encoding="utf-8"))
            cls.emitted_kinds |= k
            cls.emitted_ecos |= e

    def test_discovery_is_not_vacuous(self):
        self.assertTrue(self.emitted_kinds)
        self.assertTrue(self.emitted_ecos)
        self.assertIn("macos_pkgutil", self.emitted_ecos)
        self.assertIn("app", self.emitted_kinds)

    def test_mcp_enumeration(self):
        text = read(MCP_SRC)
        self.assertEqual(extract_enumeration(text, "kind"), EXPECTED_KINDS)
        self.assertEqual(extract_enumeration(text, "ecosystem"), EXPECTED_ECOSYSTEMS)

    def test_openapi_enumeration(self):
        text = read(OPENAPI_SRC)
        self.assertEqual(extract_enumeration(text, "kind"), EXPECTED_KINDS)
        self.assertEqual(extract_enumeration(text, "ecosystem"), EXPECTED_ECOSYSTEMS)

    def test_manual_table(self):
        text = read(MANUAL)
        self.assertEqual(extract_table_row(text, "kind"), EXPECTED_KINDS)
        self.assertEqual(extract_table_row(text, "ecosystem"), EXPECTED_ECOSYSTEMS)

    def test_emitted_subset_of_published(self):
        self.assertLessEqual(self.emitted_kinds, EXPECTED_KINDS)
        self.assertLessEqual(self.emitted_ecos, EXPECTED_ECOSYSTEMS)

    def test_lane3_predicate_covers_vocabulary(self):
        hdr = read(CPE_HDR)
        for eco in EXPECTED_ECOSYSTEMS - LANE1:
            self.assertIn(f'eco == "{eco}"', hdr)
        for kind in LANE3_KINDS:
            self.assertIn(f'kind == "{kind}"', hdr)
        self.assertNotIn('kind == "pkg"', hdr)


if __name__ == "__main__":
    unittest.main()
