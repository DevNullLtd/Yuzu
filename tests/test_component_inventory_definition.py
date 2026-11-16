#!/usr/bin/env python3
"""test_component_inventory_definition.py -- ties the C++ row grammar of the component_inventory
plugin (component_scan.hpp format_component_row:
`comp|java|<name>|<version>|<version_source>|<path>|<size>|<mtime>|<anchor_app>`) to the definition
YAML that ships it, so a reordered or renamed result column fails here rather than only in a
dashboard.

Runnable standalone: `python3 tests/test_component_inventory_definition.py` (how meson runs it).
"""
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "component_inventory.yaml"

# The status row (`status|scan|<level>|<tokens>`) reuses the first four columns. The server decoder
# keeps field 0 as the row's discriminator (row_kind), so it must lead.
EXPECTED_COLUMNS = [
    "row_kind", "kind", "name", "version", "version_source", "path", "size", "mtime", "anchor_app",
]


def _definitions() -> list:
    return [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]


class ComponentInventoryDefinitionColumns(unittest.TestCase):
    def test_one_definition_on_the_scan_action(self):
        defs = _definitions()
        self.assertEqual(len(defs), 1)
        d = defs[0]
        self.assertEqual(d["metadata"]["id"], "crossplatform.components.scan")
        self.assertEqual(d["spec"]["execution"]["plugin"], "component_inventory")
        self.assertEqual(d["spec"]["execution"]["action"], "scan")
        self.assertEqual(d["spec"]["parameters"]["properties"], {})

    def test_row_kind_leads_and_the_columns_match_the_wire_row(self):
        names = [c["name"] for c in _definitions()[0]["spec"]["result"]["columns"]]
        self.assertEqual(names, EXPECTED_COLUMNS)

    def test_row_kind_values_are_the_status_row_and_comp(self):
        self.assertEqual(_definitions()[0]["spec"]["result"]["columns"][0]["values"], ["status", "comp"])


if __name__ == "__main__":
    unittest.main()
