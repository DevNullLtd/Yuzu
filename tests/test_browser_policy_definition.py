#!/usr/bin/env python3
"""test_browser_policy_definition.py -- ties the C++ row-format contract
(`format_policy_row`/`format_status_row` in tests/unit/test_browser_policy_parsers.cpp) to
the definition YAML that actually ships it, so a reordered or renamed result column fails
here rather than only in a dashboard.

Runnable standalone: `python3 tests/test_browser_policy_definition.py` (how meson runs it; a
bare pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "browser_policy.yaml"

# browser_policy_parsers.hpp's format_policy_row / format_status_row; both row kinds are
# nine fields wide, discriminated by field 0 (row_kind). A status row repeats the typed
# result status in-band (name = the action, value = the state, detail = reason tokens).
EXPECTED_COLUMNS = [
    "row_kind", "browser", "level", "scope", "name", "value_type", "value", "source", "detail",
]
ROW_KINDS = ["policy", "status"]


def _definition() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    assert len(docs) == 1, "browser_policy.yaml defines exactly one action (policies)"
    return docs[0]


class BrowserPolicyDefinitionColumns(unittest.TestCase):
    def test_one_definition_for_the_browser_policy_plugin(self):
        d = _definition()
        self.assertEqual(d["spec"]["execution"]["plugin"], "browser_policy")
        self.assertEqual(d["spec"]["execution"]["action"], "policies")
        self.assertEqual(d["metadata"]["id"], "crossplatform.browser_policy.policies")

    def test_row_kind_leads_and_the_columns_match_the_wire_row(self):
        names = [c["name"] for c in _definition()["spec"]["result"]["columns"]]
        self.assertEqual(names, EXPECTED_COLUMNS)

    def test_row_kind_values_are_the_policy_row_and_the_status_row(self):
        row_kind = _definition()["spec"]["result"]["columns"][0]
        self.assertEqual(row_kind["values"], ROW_KINDS)


if __name__ == "__main__":
    unittest.main()
