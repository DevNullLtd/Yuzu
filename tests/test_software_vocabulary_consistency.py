#!/usr/bin/env python3
"""test_software_vocabulary_consistency.py — #5328's installed-software vocabulary drift gate.

The typed installed-software store carries a `kind` and an `ecosystem` per row. The
agents emit the values; MCP `query_installed_software`, the OpenAPI description of
`GET /api/v1/inventory/software` and the inventory manual publish them; and the CPE
Lane-3 predicate (`is_os_native`, cpe_normalize.hpp) routes them. This script checks,
against the real tree, that:

  1. every published surface equals the agreed vocabulary (EXPECTED_*) — the one prose
     `kind (a|b)` enumeration per source file AND every JSON `enum` array the catalogue
     twins publish for `kind`/`ecosystem` (MCP input schemas, OpenAPI parameters); the
     OpenAPI ecosystem arrays are generated from kEcosystemFamilies and pinned in C++;
  2. the values the agents emit are exactly that vocabulary (emitted == published);
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
CATALOG_RULES = "server/core/src/software_catalog_rules.hpp"
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


def extract_json_enums(text, field):
    """Every JSON-schema `enum` array published for `<field>`, as a list of sets.

    Two shapes: the MCP tool schemas' `"<field>": {... "enum": [...]}` property, and the OpenAPI
    parameter `{"name": "<field>", ... "schema": {... "enum": [...]}}`. The span between the key
    and its `enum` never crosses a closing brace, so a later field's enum is never attributed to
    this one."""
    patterns = (
        rf'"{field}":\s*\{{[^{{}}]*?"enum":\s*\[([^\]]*)\]',
        rf'"name":\s*"{field}"[^{{}}]*"schema":\s*\{{[^{{}}]*?"enum":\s*\[([^\]]*)\]',
    )
    return [set(re.findall(r'"([a-z_]+)"', m.group(1))) for pat in patterns
            for m in re.finditer(pat, text)]


def extract_table_row(text, field):
    """Backticked cell values of the manual's `| `<field>` |` row."""
    rows = [l for l in text.splitlines() if re.match(rf"\s*\| `{field}` \|", l)]
    if len(rows) != 1:
        raise AssertionError(f"expected exactly one `{field}` table row, found {len(rows)}")
    return set(re.findall(r"`([a-z_]+)`", rows[0].split("|", 2)[2]))


def read(rel):
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def table_ecosystems():
    """The ecosystem vocabulary: kEcosystemFamilies, the catalogue's single source of truth.
    Anti-vacuous: the parsed entry count must equal the declared std::array size."""
    m = re.search(r"std::array<EcosystemFamily, (\d+)> kEcosystemFamilies\{\{(.*?)\}\};",
                  read(CATALOG_RULES), re.S)
    if not m:
        raise AssertionError("kEcosystemFamilies not found in " + CATALOG_RULES)
    body = re.sub(r"//[^\n]*", "", m.group(2))  # a commented-out row is not a table row
    entries = re.findall(r'\{"([a-z_]+)", "[a-z]+"\}', body)
    if not entries or len(entries) != int(m.group(1)):
        raise AssertionError(f"parsed {len(entries)} ecosystems, declared {m.group(1)}")
    if len(set(entries)) != len(entries):
        raise AssertionError(f"duplicate ecosystem rows in {CATALOG_RULES}: {entries}")
    return set(entries)


EXPECTED_ECOSYSTEMS = table_ecosystems()


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

    def test_json_enum_arrays_equal_vocabulary(self):
        # Anti-vacuous: each file must carry at least one `kind` enum array, and the MCP source
        # also an `ecosystem` one (OpenAPI's are generated); every one must equal the vocabulary.
        for rel in (MCP_SRC, OPENAPI_SRC):
            text = read(rel)
            # Other tools reuse the field name `kind` for unrelated enums (e.g. the orientation
            # tool's fleet|agent|...): an array is a software-vocabulary array iff it shares a
            # value with the vocabulary, so a drifted copy (a dropped value) is still caught.
            kinds = [k for k in extract_json_enums(text, "kind") if k & EXPECTED_KINDS]
            ecos = [e for e in extract_json_enums(text, "ecosystem") if e & EXPECTED_ECOSYSTEMS]
            self.assertGreaterEqual(len(kinds), 1, f"{rel}: no JSON `kind` enum found")
            if rel == MCP_SRC:  # OpenAPI's ecosystem arrays are generated; pinned in C++
                self.assertGreaterEqual(len(ecos), 1, f"{rel}: no JSON `ecosystem` enum found")
            for k in kinds:
                self.assertEqual(k, EXPECTED_KINDS, rel)
            for e in ecos:
                self.assertEqual(e, EXPECTED_ECOSYSTEMS, rel)

    def test_manual_table(self):
        text = read(MANUAL)
        self.assertEqual(extract_table_row(text, "kind"), EXPECTED_KINDS)
        self.assertEqual(extract_table_row(text, "ecosystem"), EXPECTED_ECOSYSTEMS)

    def test_emitted_equals_published(self):
        self.assertEqual(self.emitted_kinds, EXPECTED_KINDS)
        self.assertEqual(self.emitted_ecos, EXPECTED_ECOSYSTEMS)

    def test_lane3_predicate_covers_vocabulary(self):
        hdr = read(CPE_HDR)
        for eco in EXPECTED_ECOSYSTEMS - LANE1:
            self.assertIn(f'eco == "{eco}"', hdr)
        for kind in LANE3_KINDS:
            self.assertIn(f'kind == "{kind}"', hdr)
        self.assertNotIn('kind == "pkg"', hdr)


if __name__ == "__main__":
    unittest.main()
