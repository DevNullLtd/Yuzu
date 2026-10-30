#!/usr/bin/env python3
"""test_shares_definition.py -- pins the definition YAML's result columns (the row_kind-first,
field_1..field_7 name sequence and the row_kind enum) to the row layout shares_legs.hpp and
shares_parsers.hpp emit, so a reordered or renamed result column fails here rather than only
in a dashboard, and that the description keeps its configured-not-live and sensitivity
wording. The column checks compare the YAML with the literals below and do not read the C++.

It also pins the macOS best-effort disclosure (the /etc/exports reading is an emulation of
Apple's mountd, not mountd) in the four places a reader meets it: the definition description,
the changelog fragment, the plugin README and the descriptor notes string in shares_plugin.cpp.
That last one is the only C++ this file reads, as plain text for one short phrase and with no
C++ parsing. Each phrase is asserted on its own, so dropping one disclosure fails by name.

Runnable standalone: `python3 tests/test_shares_definition.py` (how meson runs it; a bare
pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "shares.yaml"
README = REPO_ROOT / "agents" / "plugins" / "shares" / "README.md"
CHANGELOG = REPO_ROOT / "changelog.d" / "2026-10-29-shares-macos-leg.added.md"
PLUGIN_SOURCE = REPO_ROOT / "agents" / "plugins" / "shares" / "src" / "shares_plugin.cpp"

# One stream, rows discriminated by field 0 (row_kind); the YAML names the shared tail fields
# generically (field_1..field_7) and documents each row kind's meaning in the column
# descriptions, so this pins the literal column-name sequence and the row_kind enum.
EXPECTED_COLUMNS = ["row_kind"] + [f"field_{i}" for i in range(1, 8)]
ROW_KINDS = ["status", "source", "share"]


def _definition() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    assert len(docs) == 1, "shares.yaml defines exactly one action (list)"
    return docs[0]


def _flat(text: str) -> str:
    """Lower-cased with every whitespace run collapsed, so re-wrapping a folded or hard-wrapped
    sentence can neither hide a phrase nor fake one."""
    return " ".join(text.split()).lower()


def _description() -> str:
    return _flat(_definition()["metadata"]["description"])


def _text(path: Path) -> str:
    return _flat(path.read_text(encoding="utf-8"))


def _caveat_lead(number: int) -> str:
    """The bold lead of numbered item `number` under '## Caveats and known gaps' in the README."""
    readme = README.read_text(encoding="utf-8")
    start = readme.index("## Caveats and known gaps")
    end = readme.find("\n## ", start + 1)
    section = readme[start : end if end != -1 else len(readme)]
    match = re.search(rf"^{number}\. \*\*(.+?)\*\*", section, re.MULTILINE)
    assert match, f"README has no numbered caveat {number} with a bold lead"
    return match.group(1).lower()


class SharesDefinitionColumns(unittest.TestCase):
    def test_row_kind_leads_and_the_columns_match_the_wire_row(self):
        names = [c["name"] for c in _definition()["spec"]["result"]["columns"]]
        self.assertEqual(names, EXPECTED_COLUMNS)

    def test_row_kind_values_are_the_shapes_the_plugin_emits_today(self):
        row_kind = _definition()["spec"]["result"]["columns"][0]
        self.assertEqual(row_kind["values"], ROW_KINDS)

    def test_description_states_configured_not_live_and_the_sensitivity(self):
        text = _definition()["metadata"]["description"].lower()
        self.assertIn("configured", text)
        self.assertIn("not live", text)
        self.assertIn("acl", text)
        self.assertIn("account", text)


class SharesDefinitionContract(unittest.TestCase):
    def test_identity_platforms_gather_approval_and_compatibility_are_pinned(self):
        doc = _definition()
        spec = doc["spec"]
        self.assertEqual(doc["metadata"]["id"], "crossplatform.network.shares")
        self.assertEqual(spec["execution"]["plugin"], "shares")
        self.assertEqual(spec["execution"]["action"], "list")
        self.assertEqual(spec["platforms"], ["windows", "linux", "darwin"])
        self.assertEqual(spec["execution"]["concurrency"], "per-device")
        self.assertEqual(spec["gather"]["ttlSeconds"], 3600)
        self.assertEqual(spec["approval"]["mode"], "auto")
        self.assertEqual(spec["permissions"]["executeRoles"], ["endpoint-admin", "endpoint-operator"])
        self.assertEqual(spec["compatibility"]["requiredPlugins"], ["shares"])
        self.assertEqual(spec["parameters"]["properties"], {})
        self.assertEqual(spec["type"], "question")  # read-only: the catalogue gate relies on it
        self.assertEqual(doc["status"]["phase"], "active")


class SharesMacosBestEffortDisclosure(unittest.TestCase):
    """The macOS /etc/exports reading is Apple's mountd grammar emulated best-effort. Host-dependent
    checks are not modelled, so an export may be shown that mountd would drop or omitted that it
    would keep, and a uid-0 account not named root is not flagged no_root_squash. Generated output
    follows the prose, so a consistent regeneration of weaker prose passes the generator checks;
    these phrases are what fail instead."""

    def _require(self, label, text, phrases):
        for phrase in phrases:
            with self.subTest(source=label, phrase=phrase):
                self.assertIn(phrase, text)

    def test_definition_description_carries_the_disclosure(self):
        self._require(
            "shares.yaml description",
            _description(),
            ["best-effort", "would drop", "would keep", "uid-0", "no_root_squash",
             "not whether every mountd rejection was modelled"],
        )

    def test_changelog_carries_the_disclosure(self):
        self._require(
            "changelog fragment",
            _text(CHANGELOG),
            ["best-effort", "would drop", "would keep", "uid-0"],
        )

    def test_readme_calls_the_parser_an_emulation(self):
        self._require("README", _text(README), ["best-effort emulation"])

    def test_readme_caveat_5_is_the_mountd_caveat(self):
        # The README and the descriptor notes both point at "caveat 5" by number.
        lead = _caveat_lead(5)
        self._require("README caveat 5", lead, ["/etc/exports", "mountd"])

    def test_descriptor_notes_carry_the_disclosure(self):
        self._require("shares_plugin.cpp", _text(PLUGIN_SOURCE), ["emulated best-effort"])


if __name__ == "__main__":
    unittest.main()
