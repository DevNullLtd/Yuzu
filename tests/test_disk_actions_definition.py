#!/usr/bin/env python3
"""test_disk_actions_definition.py -- pins the definition YAML contract of the two planned
disk_actions actions (partitions, topology) against the literals below, so a gather block added
to an on-demand definition, a renamed or reordered result column, or a changed platform set
fails here rather than only in a dashboard or in the regenerate-to-pass plugin_doc_gen gate. It
compares the YAML with the literals below; it does not read the C++.

Runnable standalone: `python3 tests/test_disk_actions_definition.py` (how meson runs it; a bare
pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "disk_actions.yaml"

ALL_OSES = ["windows", "linux", "darwin"]

# action -> (definition id, result columns). row_kind first (status, then the action's own row
# kind), then the final column schema the leg PRs fill. Each is on-demand: no gather block.
PLANNED = {
    "partitions": (
        "crossplatform.storage.partitions",
        ["row_kind", "disk", "partition", "size_bytes", "type", "mount_points", "detail"],
        "partition",
    ),
    "topology": (
        "crossplatform.storage.topology",
        ["row_kind", "kind", "name", "uuid", "members", "detail"],
        "topology",
    ),
}


def _definitions() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    return {d["metadata"]["id"]: d for d in docs}


def _definition(action: str) -> dict:
    return _definitions()[PLANNED[action][0]]


class DiskActionsPlannedDefinitions(unittest.TestCase):
    def test_identity_platforms_and_on_demand_contract(self):
        for action, (definition_id, _, _) in PLANNED.items():
            with self.subTest(action=action):
                doc = _definition(action)
                spec = doc["spec"]
                self.assertEqual(doc["metadata"]["id"], definition_id)
                self.assertEqual(spec["execution"]["plugin"], "disk_actions")
                self.assertEqual(spec["execution"]["action"], action)
                self.assertEqual(spec["platforms"], ALL_OSES)
                self.assertEqual(spec["type"], "question")  # read-only: the catalogue gate relies on it
                self.assertNotIn("gather", spec)  # on-demand until a sync is wired; planned rows are not worth gathering

    def test_row_kind_leads_and_the_columns_match_the_wire_row(self):
        for action, (_, expected, _) in PLANNED.items():
            with self.subTest(action=action):
                names = [c["name"] for c in _definition(action)["spec"]["result"]["columns"]]
                self.assertEqual(names, expected)

    def test_row_kind_values_are_status_then_the_row_kind_the_action_emits(self):
        for action, (_, _, kind) in PLANNED.items():
            with self.subTest(action=action):
                row_kind = _definition(action)["spec"]["result"]["columns"][0]
                self.assertEqual(row_kind["values"], ["status", kind])

    def test_every_column_is_declared_on_all_three_oses(self):
        for action in PLANNED:
            for column in _definition(action)["spec"]["result"]["columns"]:
                with self.subTest(action=action, column=column["name"]):
                    self.assertEqual(column["platforms"], ALL_OSES)


if __name__ == "__main__":
    unittest.main()
