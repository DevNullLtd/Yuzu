#!/usr/bin/env python3
"""test_filesystem_definition.py -- pins the shipped `device.filesystem.find_by_hash` definition
(content/definitions/filesystem.yaml) to the row contract the plugin writes
(`match|<path>|<size>`, an optional `truncated|<reason>|visited=N|...` row,
`matches_found|<count>`), so a reordered, renamed or reverted result column fails here rather than
only in a dashboard.

tests/unit/server/test_result_set_matcher.cpp keeps its own copy of the schema (the server test
binary has no YAML loader); this file ties that copy to the definition that actually ships.

Runnable standalone: `python3 tests/test_filesystem_definition.py` (how meson runs it; a bare
pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "filesystem.yaml"
DEFINITION_ID = "device.filesystem.find_by_hash"


def _find_by_hash() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    matches = [d for d in docs if d["metadata"]["id"] == DEFINITION_ID]
    assert len(matches) == 1, f"expected exactly one {DEFINITION_ID}, found {len(matches)}"
    return matches[0]


class FindByHashDefinition(unittest.TestCase):
    def test_runs_the_filesystem_plugins_find_by_hash_action(self):
        execution = _find_by_hash()["spec"]["execution"]
        self.assertEqual(execution["plugin"], "filesystem")
        self.assertEqual(execution["action"], "find_by_hash")

    def test_version_is_0_4_0(self):
        # 0.3.0 -> 0.4.0 changed the declared columns (matches_found is a row kind, not a column).
        self.assertEqual(_find_by_hash()["metadata"]["version"], "0.4.0")

    def test_three_string_columns_in_wire_order(self):
        columns = _find_by_hash()["spec"]["result"]["columns"]
        self.assertEqual([c["name"] for c in columns], ["row_kind", "path", "size"])
        self.assertEqual([c["type"] for c in columns], ["string", "string", "string"])

    def test_row_kind_values_are_the_three_wire_row_kinds(self):
        row_kind = _find_by_hash()["spec"]["result"]["columns"][0]
        self.assertEqual(row_kind["values"], ["match", "truncated", "matches_found"])


if __name__ == "__main__":
    unittest.main()
