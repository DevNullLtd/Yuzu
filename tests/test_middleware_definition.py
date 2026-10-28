#!/usr/bin/env python3
"""test_middleware_definition.py -- ties the C++ row-format contract
(`<id>|<title>|<name>|<version>|<install_path>|<edition>`, six fields, formatted by the
middleware parsers in agents/shared/middleware_parsers.hpp) to the definition YAML that
actually ships it, so a reordered or renamed result column fails here rather than only in a
dashboard.

Runnable standalone: `python3 tests/test_middleware_definition.py` (how meson runs it; a bare
pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "middleware.yaml"

# The status row (`status|<action>|<level>|<reason>`) reuses the first columns. The server
# decoder keeps field 0 as the row's discriminator (row_kind), so it must lead.
EXPECTED_COLUMNS = ["row_kind", "title", "name", "version", "install_path", "edition"]
ACTIONS = ["ibm_mq"]


def _definitions() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    return {d["spec"]["execution"]["action"]: d for d in docs}


class MiddlewareDefinitionColumns(unittest.TestCase):
    def test_one_definition_per_action_on_the_middleware_plugin(self):
        defs = _definitions()
        self.assertEqual(sorted(defs), ACTIONS)
        for action, d in defs.items():
            self.assertEqual(d["spec"]["execution"]["plugin"], "middleware")
            self.assertEqual(d["metadata"]["id"], f"crossplatform.middleware.{action}")
            self.assertEqual(d["spec"]["platforms"], ["linux"])

    def test_row_kind_leads_and_the_columns_match_the_wire_row(self):
        for action, d in _definitions().items():
            names = [c["name"] for c in d["spec"]["result"]["columns"]]
            self.assertEqual(names, EXPECTED_COLUMNS, action)

    def test_row_kind_values_are_the_status_row_and_the_action(self):
        for action, d in _definitions().items():
            row_kind = d["spec"]["result"]["columns"][0]
            self.assertEqual(row_kind["values"], ["status", action])


if __name__ == "__main__":
    unittest.main()
