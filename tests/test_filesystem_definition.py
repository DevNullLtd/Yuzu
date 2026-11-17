#!/usr/bin/env python3
"""test_filesystem_definition.py -- pins the shipped `device.filesystem.find_by_hash` definition
(content/definitions/filesystem.yaml) to the row contract the plugin writes
(`match|<path>|<size>`, an optional `network_mount_guard|unavailable` row, an optional
`truncated|<reason>|visited=N|...` row, `matches_found|<count>`), and the shipped
`device.filesystem.search_dir` definition (content/definitions/t2_capabilities.yaml) to its rows
(`result|<path>|<directory|file>`, the same optional guard and trailer rows,
`total_matches|<count>`), so a reordered, renamed or reverted result column fails here rather than
only in a dashboard.

tests/unit/server/test_result_set_matcher.cpp keeps its own copy of the schema (the server test
binary has no YAML loader); the same column names, types, row_kind values and `discriminator` are
pinned in both places.

Runnable standalone: `python3 tests/test_filesystem_definition.py` (how meson runs it; a bare
pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "filesystem.yaml"
DEFINITION_ID = "device.filesystem.find_by_hash"
SEARCH_DIR_DEFINITION = REPO_ROOT / "content" / "definitions" / "t2_capabilities.yaml"
SEARCH_DIR_ID = "device.filesystem.search_dir"


def _find_by_hash() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    matches = [d for d in docs if d["metadata"]["id"] == DEFINITION_ID]
    assert len(matches) == 1, f"expected exactly one {DEFINITION_ID}, found {len(matches)}"
    return matches[0]


def _search_dir() -> dict:
    docs = [d for d in yaml.safe_load_all(SEARCH_DIR_DEFINITION.read_text(encoding="utf-8")) if d]
    matches = [d for d in docs if d["metadata"]["id"] == SEARCH_DIR_ID]
    assert len(matches) == 1, f"expected exactly one {SEARCH_DIR_ID}, found {len(matches)}"
    return matches[0]


class FindByHashDefinition(unittest.TestCase):
    def test_runs_the_filesystem_plugins_find_by_hash_action(self):
        execution = _find_by_hash()["spec"]["execution"]
        self.assertEqual(execution["plugin"], "filesystem")
        self.assertEqual(execution["action"], "find_by_hash")

    def test_version_is_0_4_0(self):
        # 0.3.0 -> 0.4.0 changed the declared columns (matches_found is a row kind, not a column).
        self.assertEqual(_find_by_hash()["metadata"]["version"], "0.4.0")

    def test_three_columns_in_wire_order(self):
        # A column matcher takes a row as a data row only when its field count equals this width,
        # so the match row (`match|path|size`) is the one three-field row kind; size is the byte
        # count, as in file_hash.
        columns = _find_by_hash()["spec"]["result"]["columns"]
        self.assertEqual([c["name"] for c in columns], ["row_kind", "path", "size"])
        self.assertEqual([c["type"] for c in columns], ["string", "string", "int64"])

    def test_row_kind_opts_in_to_the_every_pipe_split(self):
        # `discriminator: true` on the first column is what makes the server's result-set matcher
        # split these rows on every pipe (bind_declared_columns stores `row_discriminator`).
        # Without it a key/value plugin's rows are key + remainder and never match a wider
        # declaration, so dropping the key silently turns every column matcher on this
        # instruction into a never-match; it is on the first column only.
        columns = _find_by_hash()["spec"]["result"]["columns"]
        self.assertIs(columns[0]["discriminator"], True)
        self.assertEqual([c["name"] for c in columns if "discriminator" in c], ["row_kind"])

    def test_row_kind_values_are_the_wire_row_kinds(self):
        row_kind = _find_by_hash()["spec"]["result"]["columns"][0]
        self.assertEqual(row_kind["values"],
                         ["match", "truncated", "matches_found", "network_mount_guard"])


class SearchDirDefinition(unittest.TestCase):
    """search_dir adopts the find_by_hash column shape (#6478): `result|<path>|<entry_type>` is the
    one three-field row kind; the trailer, total_matches and the guard row never match."""

    def test_runs_the_filesystem_plugins_search_dir_action(self):
        execution = _search_dir()["spec"]["execution"]
        self.assertEqual(execution["plugin"], "filesystem")
        self.assertEqual(execution["action"], "search_dir")

    def test_version_is_0_5_0(self):
        # 0.4.0 -> 0.5.0 changed the declared columns (row_kind added, total_matches is a row kind).
        self.assertEqual(_search_dir()["metadata"]["version"], "0.5.0")

    def test_three_columns_in_wire_order(self):
        columns = _search_dir()["spec"]["result"]["columns"]
        self.assertEqual([c["name"] for c in columns], ["row_kind", "path", "entry_type"])
        self.assertEqual([c["type"] for c in columns], ["string", "string", "string"])

    def test_row_kind_is_the_discriminator_on_the_first_column_only(self):
        columns = _search_dir()["spec"]["result"]["columns"]
        self.assertIs(columns[0]["discriminator"], True)
        self.assertEqual([c["name"] for c in columns if "discriminator" in c], ["row_kind"])

    def test_row_kind_values_are_the_wire_row_kinds(self):
        row_kind = _search_dir()["spec"]["result"]["columns"][0]
        self.assertEqual(row_kind["values"],
                         ["result", "truncated", "total_matches", "network_mount_guard"])

    def test_entry_type_values(self):
        entry_type = _search_dir()["spec"]["result"]["columns"][2]
        self.assertEqual(entry_type["values"], ["file", "directory"])


if __name__ == "__main__":
    unittest.main()
