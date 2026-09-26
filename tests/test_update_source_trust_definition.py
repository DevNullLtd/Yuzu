#!/usr/bin/env python3
"""test_update_source_trust_definition.py -- ties the C++ row-format contract
(`format_status_row`/`format_apt_source_row`/`format_apt_keyring_row` in
tests/unit/test_update_source_trust_parsers.cpp) to the definition YAML that actually
ships it, so a reordered or renamed result column fails here rather than only in a
dashboard.

Runnable standalone: `python3 tests/test_update_source_trust_definition.py` (how meson runs
it; a bare pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "update_source_trust.yaml"

# update_source_trust_parsers.hpp's format_status_row/format_apt_source_row/
# format_apt_keyring_row emit three row shapes on one stream, discriminated by
# field 0 (row_kind); narrower shapes leave the tail fields off the row. The YAML
# names the shared fields generically (field_1..field_10, widest shape first) and
# documents each row kind's actual meaning in the column description text, so this
# test pins the literal column-name sequence and the row_kind enum -- it cannot pin
# a per-row-kind field name, because the YAML itself doesn't have one.
EXPECTED_COLUMNS = ["row_kind"] + [f"field_{i}" for i in range(1, 11)]
ROW_KINDS = ["status", "apt_source", "apt_keyring"]


def _definition() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    assert len(docs) == 1, "update_source_trust.yaml defines exactly one action (sources)"
    return docs[0]


class UpdateSourceTrustDefinitionColumns(unittest.TestCase):
    def test_one_definition_for_the_update_source_trust_plugin(self):
        d = _definition()
        self.assertEqual(d["spec"]["execution"]["plugin"], "update_source_trust")
        self.assertEqual(d["spec"]["execution"]["action"], "sources")
        self.assertEqual(d["metadata"]["id"], "crossplatform.security.update_source_trust")

    def test_row_kind_leads_and_the_columns_match_the_wire_row(self):
        names = [c["name"] for c in _definition()["spec"]["result"]["columns"]]
        self.assertEqual(names, EXPECTED_COLUMNS)

    def test_row_kind_values_are_the_three_shapes_the_plugin_emits_today(self):
        row_kind = _definition()["spec"]["result"]["columns"][0]
        self.assertEqual(row_kind["values"], ROW_KINDS)


if __name__ == "__main__":
    unittest.main()
