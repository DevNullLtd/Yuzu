#!/usr/bin/env python3
"""test_mgmt_posture_definition.py -- pins the definition YAML's result columns (the
row_kind-first, field_1..field_3 name sequence and the row_kind enum) to the row layout
mgmt_posture_parsers.hpp emits, so a reordered or renamed result column fails here rather
than only in a dashboard. It compares the YAML with the literals below; it does not read the C++.

Runnable standalone: `python3 tests/test_mgmt_posture_definition.py` (how meson runs
it; a bare pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "mgmt_posture.yaml"

# One stream, rows discriminated by field 0 (row_kind); the YAML names the shared tail
# fields generically (field_1..field_3) and documents each row kind's meaning in the column
# descriptions, so this pins the literal column-name sequence and the row_kind enum.
EXPECTED_COLUMNS = ["row_kind", "field_1", "field_2", "field_3"]
ROW_KINDS = ["status", "plane", "mdm_enrolled", "mdm_provider", "tenant_id", "krb5_keytab"]


def _definition() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    assert len(docs) == 1, "mgmt_posture.yaml defines exactly one action (posture)"
    return docs[0]


class MgmtPostureDefinitionColumns(unittest.TestCase):
    def test_one_definition_for_the_mgmt_posture_plugin(self):
        d = _definition()
        self.assertEqual(d["spec"]["execution"]["plugin"], "mgmt_posture")
        self.assertEqual(d["spec"]["execution"]["action"], "posture")
        self.assertEqual(d["metadata"]["id"], "crossplatform.security.mgmt_posture")

    def test_row_kind_leads_and_the_columns_match_the_wire_row(self):
        names = [c["name"] for c in _definition()["spec"]["result"]["columns"]]
        self.assertEqual(names, EXPECTED_COLUMNS)

    def test_row_kind_values_are_the_shapes_the_plugin_emits_today(self):
        row_kind = _definition()["spec"]["result"]["columns"][0]
        self.assertEqual(row_kind["values"], ROW_KINDS)


if __name__ == "__main__":
    unittest.main()
