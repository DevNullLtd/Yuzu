#!/usr/bin/env python3
"""test_virtualization_definition.py -- ties the C++ row-format contract (the status row plus
`host|<is_virtual>|<kind>|<vendor>|<product>|<source>|<confidence>` and
`container|<yes|no|unknown>|<evidence>`, formatted by virtualization_parsers.hpp and
virtualization_legs.hpp) to the definition YAML that actually ships it, so a reordered or renamed
result column fails here rather than only in a dashboard.

Runnable standalone: `python3 tests/test_virtualization_definition.py` (how meson runs it; a bare
pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "virtualization.yaml"

# Field 0 is the row discriminator the server decoder keeps as row_kind, so it must lead; the
# host row is the widest (six fields after the discriminator).
EXPECTED_COLUMNS = ["row_kind", "field_1", "field_2", "field_3", "field_4", "field_5", "field_6"]
ROW_KINDS = ["status", "host", "container"]


def _definitions() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    return {d["spec"]["execution"]["action"]: d for d in docs}


class VirtualizationDefinitionColumns(unittest.TestCase):
    def test_one_definition_for_the_host_action(self):
        defs = _definitions()
        self.assertEqual(sorted(defs), ["host"])
        d = defs["host"]
        self.assertEqual(d["spec"]["execution"]["plugin"], "virtualization")
        self.assertEqual(d["metadata"]["id"], "crossplatform.virtualization.host")
        self.assertEqual(d["spec"]["platforms"], ["windows", "linux", "darwin"])

    def test_row_kind_leads_and_the_columns_match_the_wire_rows(self):
        names = [c["name"] for c in _definitions()["host"]["spec"]["result"]["columns"]]
        self.assertEqual(names, EXPECTED_COLUMNS)

    def test_row_kind_values_are_the_status_host_and_container_rows(self):
        row_kind = _definitions()["host"]["spec"]["result"]["columns"][0]
        self.assertEqual(row_kind["values"], ROW_KINDS)


if __name__ == "__main__":
    unittest.main()
