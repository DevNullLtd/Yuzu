#!/usr/bin/env python3
"""test_hardware_definition.py -- pins the definition YAML contract of the four planned hardware
actions (chassis, baseboard, swap, machine_id) and of the columns appended to processors and
memory, against the literals below, so a gather block added to an on-demand definition, a
renamed or reordered result column, or a changed platform set fails here rather than only in a
dashboard or in the regenerate-to-pass plugin_doc_gen gate. It compares the YAML with the
literals below; it does not read the C++.

Runnable standalone: `python3 tests/test_hardware_definition.py` (how meson runs it; a bare
pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "hardware.yaml"

ALL_OSES = ["windows", "linux", "darwin"]

# The four planned actions: row_kind first (status, then the action's own kind), then the final
# column schema the leg PRs fill. Each is on-demand: no gather block until a sync is wired.
PLANNED = {
    "chassis": ["row_kind", "type", "serial", "asset_tag", "source"],
    "baseboard": ["row_kind", "vendor", "product", "serial", "source"],
    "swap": ["row_kind", "device", "total_mb", "used_mb", "source"],
    "machine_id": ["row_kind", "hash_hex", "algorithm", "source"],
}

# processors/memory keep their existing columns and append the always-"-" tail; the platform
# sets are the ones committed (memory's DIMM-only columns are Windows and Linux).
PROCESSORS_COLUMNS = ["index", "model", "cores", "threads", "clock_mhz", "socket_designation", "stepping"]
PROCESSORS_APPENDED = {"socket_designation": ALL_OSES, "stepping": ALL_OSES}
MEMORY_COLUMNS = ["slot", "size_mb", "type", "speed_mhz", "manufacturer", "part_number", "serial"]
MEMORY_APPENDED = {
    "manufacturer": ["windows", "linux"],
    "part_number": ["windows", "linux"],
    "serial": ["windows", "linux"],
}


def _definitions() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    return {d["metadata"]["id"]: d for d in docs}


def _definition(action: str) -> dict:
    return _definitions()[f"device.hardware.{action}"]


def _columns(action: str) -> list:
    return _definition(action)["spec"]["result"]["columns"]


class HardwarePlannedDefinitions(unittest.TestCase):
    def test_identity_platforms_and_on_demand_contract(self):
        for action in PLANNED:
            with self.subTest(action=action):
                doc = _definition(action)
                spec = doc["spec"]
                self.assertEqual(doc["metadata"]["id"], f"device.hardware.{action}")
                self.assertEqual(spec["execution"]["plugin"], "hardware")
                self.assertEqual(spec["execution"]["action"], action)
                self.assertEqual(spec["platforms"], ALL_OSES)
                self.assertEqual(spec["type"], "question")  # read-only: the catalogue gate relies on it
                self.assertNotIn("gather", spec)  # on-demand until a sync is wired; planned rows are not worth gathering

    def test_row_kind_leads_and_the_columns_match_the_wire_row(self):
        for action, expected in PLANNED.items():
            with self.subTest(action=action):
                self.assertEqual([c["name"] for c in _columns(action)], expected)

    def test_row_kind_values_are_status_then_the_action_kind(self):
        for action in PLANNED:
            with self.subTest(action=action):
                self.assertEqual(_columns(action)[0]["values"], ["status", action])

    def test_every_planned_column_is_declared_on_all_three_oses(self):
        for action in PLANNED:
            for column in _columns(action):
                with self.subTest(action=action, column=column["name"]):
                    self.assertEqual(column["platforms"], ALL_OSES)


class HardwareAppendedColumns(unittest.TestCase):
    def test_processors_columns_end_socket_designation_then_stepping(self):
        self.assertEqual([c["name"] for c in _columns("processors")], PROCESSORS_COLUMNS)

    def test_processors_appended_columns_platform_sets(self):
        by_name = {c["name"]: c for c in _columns("processors")}
        for name, platforms in PROCESSORS_APPENDED.items():
            with self.subTest(column=name):
                self.assertEqual(by_name[name]["platforms"], platforms)

    def test_memory_columns_end_manufacturer_part_number_serial(self):
        self.assertEqual([c["name"] for c in _columns("memory")], MEMORY_COLUMNS)

    def test_memory_appended_columns_platform_sets(self):
        by_name = {c["name"]: c for c in _columns("memory")}
        for name, platforms in MEMORY_APPENDED.items():
            with self.subTest(column=name):
                self.assertEqual(by_name[name]["platforms"], platforms)


if __name__ == "__main__":
    unittest.main()
