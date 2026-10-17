#!/usr/bin/env python3
"""test_shares_definition.py -- pins the definition YAML's result columns (the row_kind-first,
field_1..field_7 name sequence and the row_kind enum) to the row layout shares_legs.hpp and
shares_parsers.hpp emit, so a reordered or renamed result column fails here rather than only
in a dashboard, and that the description keeps its configured-not-live and sensitivity
wording. It compares the YAML with the literals below; it does not read the C++.

Runnable standalone: `python3 tests/test_shares_definition.py` (how meson runs it; a bare
pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "shares.yaml"

# One stream, rows discriminated by field 0 (row_kind); the YAML names the shared tail fields
# generically (field_1..field_7) and documents each row kind's meaning in the column
# descriptions, so this pins the literal column-name sequence and the row_kind enum.
EXPECTED_COLUMNS = ["row_kind"] + [f"field_{i}" for i in range(1, 8)]
ROW_KINDS = ["status", "source", "share"]


def _definition() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    assert len(docs) == 1, "shares.yaml defines exactly one action (list)"
    return docs[0]


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


if __name__ == "__main__":
    unittest.main()
