#!/usr/bin/env python3
"""test_component_inventory_definition.py -- ties the C++ row grammar of the component_inventory
plugin (component_scan.hpp format_component_row:
`comp|<java|native>|<name>|<version>|<version_source>|<path>|<size>|<mtime>|<anchor_app>`) to the
definitions YAML that ships it (one per action, scan and native), so a reordered or renamed result column fails here rather than only in a
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


def _definition(action: str) -> dict:
    (d,) = [d for d in _definitions() if d["spec"]["execution"]["action"] == action]
    return d


class ComponentInventoryDefinitionColumns(unittest.TestCase):
    def test_one_definition_per_action(self):
        defs = _definitions()
        self.assertEqual(len(defs), 2)
        for action in ("scan", "native"):
            d = _definition(action)
            self.assertEqual(d["metadata"]["id"], f"crossplatform.components.{action}")
            self.assertEqual(d["spec"]["execution"]["plugin"], "component_inventory")
            self.assertEqual(d["spec"]["parameters"]["properties"], {})
            self.assertEqual(d["spec"]["platforms"], ["darwin", "linux"])

    def test_row_kind_leads_and_the_columns_match_the_wire_row(self):
        for action in ("scan", "native"):
            names = [c["name"] for c in _definition(action)["spec"]["result"]["columns"]]
            self.assertEqual(names, EXPECTED_COLUMNS, action)

    def test_row_kind_values_are_the_status_row_and_comp(self):
        for action in ("scan", "native"):
            self.assertEqual(_definition(action)["spec"]["result"]["columns"][0]["values"], ["status", "comp"])

    def test_native_row_grammar_and_closed_version_sources(self):
        cols = {c["name"]: c for c in _definition("native")["spec"]["result"]["columns"]}
        self.assertEqual(cols["kind"]["example"], "native")
        # The server's closed version_source set (installed_software_v3.hpp) already holds all four.
        self.assertEqual(cols["version_source"]["values"], ["filename", "elf", "macho", "unreadable"])
        self.assertEqual(cols["version_source"]["example"], "filename")
        self.assertEqual(_definition("scan")["spec"]["result"]["columns"][4]["values"],
                         ["filename", "pom", "manifest", "unreadable"])

    def test_native_definition_states_the_default_off_contract_and_the_bounds(self):
        d = _definition("native")
        text = " ".join(d["metadata"]["description"].split())
        for needle in ("switched off", "/api/v1/plugin-config/component_inventory/kill-switch", "action=native",
                       "5,000 rows", "package_tree_skipped", "/usr/local/lib"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
