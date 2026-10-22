#!/usr/bin/env python3
"""test_registry_definition.py -- pins content/definitions/registry.yaml's contract for the
registry plugin's typed verified writes: the nine definition ids, the six-type enum on set_value,
delete_key's five result columns in order (compatible-by-append: `status` stays first) and its
non-recursive wording, and the role gates on every mutating definition.
It compares the YAML with the literals below; it does not read the C++ (the wire rows are pinned
by tests/unit/test_registry_parsers.cpp / test_registry_core.cpp).

Runnable standalone: `python3 tests/test_registry_definition.py` (how meson runs it; a bare
pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import json
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "registry.yaml"

ACTIONS = ["get_value", "get_user_value", "list_profiles", "set_value", "enumerate_keys", "delete_value",
           "delete_key", "key_exists", "enumerate_values"]
IDS = {f"windows.registry.{a}": a for a in ACTIONS}
MUTATING = ["set_value", "delete_value", "delete_key"]
SIX_TYPES = ["REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REG_MULTI_SZ", "REG_QWORD"]
DELETE_KEY_COLUMNS = ["status", "counted_keys", "counted_values", "dry_run", "capped"]


def _definitions() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    return {d["metadata"]["id"]: d for d in docs}


def _spec(action: str) -> dict:
    by_action = {d["spec"]["execution"]["action"]: d for d in _definitions().values()}
    return by_action[action]["spec"]


class RegistryDefinitionIds(unittest.TestCase):
    def test_nine_definitions_each_bound_to_its_action(self):
        defs = _definitions()
        self.assertEqual({i: d["spec"]["execution"]["action"] for i, d in defs.items()}, IDS)

    def test_every_definition_is_the_registry_plugin_on_windows_only(self):
        for i, d in _definitions().items():
            with self.subTest(definition=i):
                self.assertEqual(d["spec"]["execution"]["plugin"], "registry")
                self.assertEqual(d["spec"]["platforms"], ["windows"])
                self.assertEqual(d["spec"]["execution"]["concurrency"], "per-device")
                self.assertIn("registry", d["spec"]["compatibility"]["requiredPlugins"])


class RegistryMutatingDefinitionsAreGated(unittest.TestCase):
    def test_every_mutating_definition_is_role_gated_to_endpoint_admin(self):
        for action in MUTATING:
            with self.subTest(action=action):
                spec = _spec(action)
                self.assertEqual(spec["type"], "action")
                self.assertEqual(spec["approval"]["mode"], "role-gated")
                self.assertEqual(spec["permissions"]["executeRoles"], ["endpoint-admin"])


class RegistrySetValue(unittest.TestCase):
    def test_type_is_exactly_the_six_writable_names(self):
        props = _spec("set_value")["parameters"]["properties"]
        self.assertEqual(props["type"]["validation"]["enum"], SIX_TYPES)

    def test_data_hex_is_optional_and_value_text_stays_required_for_compatibility(self):
        params = _spec("set_value")["parameters"]
        self.assertIn("data_hex", params["properties"])
        self.assertNotIn("data_hex", params["required"])
        self.assertEqual(params["required"], ["hive", "key", "name", "value"])

    def test_status_is_the_single_result_column(self):
        cols = _spec("set_value")["result"]["columns"]
        self.assertEqual([c["name"] for c in cols], ["status"])


class RegistryDeleteKey(unittest.TestCase):
    def test_five_result_columns_status_first_in_order(self):
        cols = _spec("delete_key")["result"]["columns"]
        self.assertEqual([c["name"] for c in cols], DELETE_KEY_COLUMNS)

    def test_takes_only_the_hive_and_the_key(self):
        spec = _spec("delete_key")["parameters"]
        self.assertEqual(sorted(spec["properties"]), ["hive", "key"])
        self.assertEqual(spec["required"], ["hive", "key"])

    def test_version_is_the_minor_bump(self):
        self.assertEqual(_definitions()["windows.registry.delete_key"]["metadata"]["version"], "1.1.0")

    def test_description_is_non_recursive_and_names_the_value_cap(self):
        text = _definitions()["windows.registry.delete_key"]["metadata"]["description"].lower()
        self.assertIn("key_has_subkeys", text)
        self.assertIn("10,000 nodes (the key plus up to 9,999 values)", text)
        self.assertIn("lower bound", text)
        self.assertNotIn("recursive=true", text)
        self.assertNotIn("every value and subkey", text)

    def test_capped_column_is_the_value_count_cap(self):
        cols = {c["name"]: c for c in _spec("delete_key")["result"]["columns"]}
        self.assertIn("10,000 nodes (the key plus up to 9,999 values)", cols["capped"]["description"])
        self.assertIn("Always 0", cols["dry_run"]["description"])


class RegistryDefinitionPins(unittest.TestCase):
    """Values a quiet edit could weaken while every test above stayed green."""

    def test_hive_enum_is_the_four_hives(self):
        for action in MUTATING:
            with self.subTest(action=action):
                enum = _spec(action)["parameters"]["properties"]["hive"]["validation"]["enum"]
                self.assertEqual(enum, ["HKLM", "HKCU", "HKCR", "HKU"])

    def test_data_hex_carries_one_mebibyte(self):
        limit = _spec("set_value")["parameters"]["properties"]["data_hex"]["validation"]["maxLength"]
        self.assertEqual(limit, 2 * 1024 * 1024)  # hex characters: 1 MiB of data

    def test_definition_versions_and_the_plugin_doc_version(self):
        want = {"set_value": "1.1.0", "delete_value": "1.1.0", "delete_key": "1.1.0"}
        got = {d["spec"]["execution"]["action"]: d["metadata"]["version"] for d in _definitions().values()}
        for action, version in want.items():
            with self.subTest(action=action):
                self.assertEqual(got[action], version)
        docs = json.loads((REPO_ROOT / "content" / "plugin-docs" / "registry.json").read_text(encoding="utf-8"))
        self.assertEqual(docs["version"], "2.0.0")

    def test_the_writers_are_classified_destructive_for_the_risk_gate(self):
        overrides = json.loads((REPO_ROOT / "scripts" / "test" / "instructions-risk-classification.json")
                               .read_text(encoding="utf-8"))["_overrides"]
        for action in MUTATING:
            with self.subTest(action=action):
                self.assertEqual(overrides[f"windows.registry.{action}"], "destructive")


if __name__ == "__main__":
    unittest.main()
