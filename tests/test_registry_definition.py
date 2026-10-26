#!/usr/bin/env python3
"""test_registry_definition.py -- pins content/definitions/registry.yaml's contract for the
registry plugin's typed verified writes: the twelve definition ids, the six-type enum on set_value and
set_user_value, delete_key's five result columns in order (compatible-by-append: `status` stays first), its
recursion and dry-run parameters and the mixed-fleet hazard its description states, the apply plan's bounds
and row columns, and the role gates on every mutating definition.
It compares the YAML with the literals below; it reads the C++ only for one lexical pin on the
Windows fixtures' scratch-key names (the wire rows are pinned by tests/unit/test_registry_parsers.cpp /
test_registry_core.cpp).

Runnable standalone: `python3 tests/test_registry_definition.py` (how meson runs it; a bare
pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import json
import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "registry.yaml"

ACTIONS = ["get_value", "get_user_value", "list_profiles", "set_value", "enumerate_keys", "delete_value",
           "delete_key", "key_exists", "enumerate_values", "set_user_value", "delete_user_value", "apply"]
IDS = {f"windows.registry.{a}": a for a in ACTIONS}
MUTATING = ["set_value", "delete_value", "delete_key", "set_user_value", "delete_user_value", "apply"]
HIVE_PARAMETER = ["set_value", "delete_value", "delete_key"]  # the other mutators name a profile or carry a plan
APPLY_COLUMNS = ["row_kind"] + [f"field_{i}" for i in range(1, 14)]
SIX_TYPES = ["REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REG_MULTI_SZ", "REG_QWORD"]
DELETE_KEY_COLUMNS = ["status", "counted_keys", "counted_values", "dry_run", "capped"]


def _definitions() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    return {d["metadata"]["id"]: d for d in docs}


def _spec(action: str) -> dict:
    by_action = {d["spec"]["execution"]["action"]: d for d in _definitions().values()}
    return by_action[action]["spec"]


def _words(text: str) -> str:
    return " ".join(text.split())


def _version(text: str) -> tuple:
    return tuple(int(part) for part in text.split("."))


class RegistryDefinitionIds(unittest.TestCase):
    def test_twelve_definitions_each_bound_to_its_action(self):
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

    def test_neither_value_nor_data_hex_is_required_because_one_of_them_is_sent(self):
        params = _spec("set_value")["parameters"]
        self.assertIn("data_hex", params["properties"])
        self.assertNotIn("data_hex", params["required"])
        self.assertNotIn("value", params["required"])
        self.assertEqual(params["required"], ["hive", "key", "name"])
        text = params["properties"]["value"]["description"]
        self.assertIn("exactly one of `value` and `data_hex`", " ".join(text.split()))
        self.assertIn("empty value", text)

    def test_status_is_the_single_result_column(self):
        cols = _spec("set_value")["result"]["columns"]
        self.assertEqual([c["name"] for c in cols], ["status"])


class RegistryDeleteKey(unittest.TestCase):
    def test_five_result_columns_status_first_in_order(self):
        cols = _spec("delete_key")["result"]["columns"]
        self.assertEqual([c["name"] for c in cols], DELETE_KEY_COLUMNS)

    def test_takes_the_hive_the_key_and_the_two_optional_flags(self):
        spec = _spec("delete_key")["parameters"]
        self.assertEqual(sorted(spec["properties"]), ["dry_run", "hive", "key", "recursive"])
        self.assertEqual(spec["required"], ["hive", "key"])  # additive: the flags are optional

    def test_the_flags_are_true_false_strings_defaulting_to_false(self):
        props = _spec("delete_key")["parameters"]["properties"]
        for flag in ("recursive", "dry_run"):
            with self.subTest(flag=flag):
                self.assertEqual(props[flag]["type"], "string")
                self.assertEqual(props[flag]["default"], "false")
                self.assertEqual(props[flag]["validation"]["enum"], ["true", "false"])

    def test_version_is_the_additive_minor_bump(self):
        self.assertEqual(_definitions()["windows.registry.delete_key"]["metadata"]["version"], "1.2.0")

    def test_description_states_the_recursion_contract(self):
        text = _words(_definitions()["windows.registry.delete_key"]["metadata"]["description"])
        for needle in ("key_has_subkeys", "tree_too_large", "10,000 keys and values", "600 levels", "lower bound",
                       "key_is_link", "concurrent_change", "RegDeleteTreeW", "size bound and a link sweep, not a list",
                       "what the delete removed"):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)

    def test_the_2_0_x_dry_run_hazard_is_stated_where_the_operator_reads_it(self):
        # A registry 2.0.x agent never reads dry_run: delete_key(dry_run=true) DELETES a leaf key there, and nothing on the
        # server compares a plugin version at dispatch (#6484), so the definition itself has to say so.
        defn = _definitions()["windows.registry.delete_key"]
        for where, text in (("description", defn["metadata"]["description"]),
                            ("dry_run parameter", _spec("delete_key")["parameters"]["properties"]["dry_run"]["description"])):
            with self.subTest(where=where):
                words = _words(text)
                self.assertIn("2.0.x", words)
                self.assertIn("DELETES a key that has no subkeys", words)
        self.assertIn("#6484", _words(defn["metadata"]["description"]))

    def test_min_agent_version_is_declared_as_the_input_to_the_dispatch_gate(self):
        # Declared and exported, not compared at dispatch today (#6484); pinned so the gate is correct the day it lands.
        self.assertGreaterEqual(_version(_spec("delete_key")["compatibility"]["minAgentVersion"]), (0, 15, 0))

    def test_capped_dry_run_and_counts_columns_describe_the_new_semantics(self):
        cols = {c["name"]: c for c in _spec("delete_key")["result"]["columns"]}
        self.assertIn("10,000 keys and values, 600 levels", cols["capped"]["description"])
        self.assertIn("tree_too_large", cols["capped"]["description"])
        self.assertIn("1 (counted, nothing deleted) or 0", cols["dry_run"]["description"])
        self.assertNotIn("Always 0", cols["dry_run"]["description"])
        self.assertIn("REMOVED", cols["counted_keys"]["description"])


class RegistryPerUserWrites(unittest.TestCase):
    def test_set_user_value_has_the_six_type_enum_and_the_value_or_data_hex_rule(self):
        props = _spec("set_user_value")["parameters"]["properties"]
        self.assertEqual(props["type"]["validation"]["enum"], SIX_TYPES)
        self.assertEqual(sorted(props), ["data_hex", "key", "name", "sid", "type", "username", "value"])
        self.assertEqual(_spec("set_user_value")["parameters"]["required"], ["key", "name"])
        self.assertIn("exactly one of", _words(props["value"]["description"]))
        self.assertEqual(props["data_hex"]["validation"]["maxLength"], 2 * 1024 * 1024)

    def test_delete_user_value_takes_the_profile_the_key_and_the_name(self):
        props = _spec("delete_user_value")["parameters"]["properties"]
        self.assertEqual(sorted(props), ["key", "name", "sid", "username"])
        self.assertEqual(_spec("delete_user_value")["parameters"]["required"], ["key", "name"])

    def test_both_state_the_flush_the_guard_and_the_mixed_fleet_answer(self):
        for action in ("set_user_value", "delete_user_value"):
            with self.subTest(action=action):
                text = _words(_definitions()[f"windows.registry.{action}"]["metadata"]["description"])
                self.assertIn("2.0.x", text)
                self.assertIn("unknown action", text)
        text = _words(_definitions()["windows.registry.set_user_value"]["metadata"]["description"])
        self.assertIn("flushed", text)
        self.assertIn("hive-file guard", text)

    def test_the_status_column_names_the_hive_warnings_and_the_audit_row(self):
        for action in ("set_user_value", "delete_user_value"):
            with self.subTest(action=action):
                cols = _spec(action)["result"]["columns"]
                self.assertEqual([c["name"] for c in cols], ["status"])
                self.assertIn(f"audit|op={action}|", cols[0]["description"])
                self.assertIn("hive=HKU", cols[0]["description"])


class RegistryApply(unittest.TestCase):
    def test_plan_is_the_only_required_parameter_and_is_bounded_to_64_kib(self):
        params = _spec("apply")["parameters"]
        self.assertEqual(params["required"], ["plan"])
        self.assertEqual(sorted(params["properties"]), ["continue_on_error", "dry_run", "plan"])
        self.assertEqual(params["properties"]["plan"]["validation"]["maxLength"], 65536)
        self.assertIn("256", params["properties"]["plan"]["description"])

    def test_dry_run_defaults_to_true_and_continue_on_error_to_false(self):
        props = _spec("apply")["parameters"]["properties"]
        self.assertEqual(props["dry_run"]["default"], "true")
        self.assertEqual(props["continue_on_error"]["default"], "false")
        for flag in ("dry_run", "continue_on_error"):
            with self.subTest(flag=flag):
                self.assertEqual(props[flag]["type"], "string")
                self.assertEqual(props[flag]["validation"]["enum"], ["true", "false"])

    def test_result_columns_are_the_row_kind_and_thirteen_fields(self):
        cols = _spec("apply")["result"]["columns"]
        self.assertEqual([c["name"] for c in cols], APPLY_COLUMNS)
        self.assertEqual(cols[0]["values"], ["item", "undo", "audit", "summary"])

    def test_description_states_the_contract_an_operator_acts_on(self):
        text = _words(_definitions()["windows.registry.apply"]["metadata"]["description"])
        for needle in ("Dry run is the default", "ONE verdict function", "dependent_items", "NOT transactional",
                       "unrepresentable_name", "THE EXACT-NAME RULE", "512 KiB", "undo_complete=0",
                       "cannot see the ACL a key that does not exist yet will inherit", "2.0.x", "unknown action",
                       "600 rows per agent per minute"):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)

    def test_the_audit_columns_follow_the_audit_line_order(self):
        # field_1..field_13 of an `audit` row are the first 13 tokens of the audit line: op, hive, result, reason, verify,
        # key, name, type, len, dry_run, counted_keys, counted_values, capped (registry_parsers.hpp render_audit_line).
        cols = {c["name"]: c["description"] for c in _spec("apply")["result"]["columns"]}
        for field, token in zip(range(1, 14), ("op=apply.<op>", "hive=", "result=", "reason=", "verify=", "key=", "name=",
                                               "type=", "len=", "dry_run=", "counted_keys=", "counted_values=", "capped=")):
            with self.subTest(field=field):
                self.assertIn(f"audit: {token}", cols[f"field_{field}"])


class RegistryDefinitionPins(unittest.TestCase):
    """Values a quiet edit could weaken while every test above stayed green."""

    def test_hive_enum_is_the_four_hives(self):
        for action in HIVE_PARAMETER:
            with self.subTest(action=action):
                enum = _spec(action)["parameters"]["properties"]["hive"]["validation"]["enum"]
                self.assertEqual(enum, ["HKLM", "HKCU", "HKCR", "HKU"])

    def test_data_hex_carries_one_mebibyte(self):
        limit = _spec("set_value")["parameters"]["properties"]["data_hex"]["validation"]["maxLength"]
        self.assertEqual(limit, 2 * 1024 * 1024)  # hex characters: 1 MiB of data

    def test_data_hex_states_the_limit_of_the_routes_that_cap_a_parameter_at_64_kib(self):
        text = " ".join(_spec("set_value")["parameters"]["properties"]["data_hex"]["description"].split())
        self.assertIn("64 KiB", text)
        self.assertIn("32 KiB of data", text)
        self.assertNotIn("restore a value captured", text)

    def test_the_writers_declare_the_release_that_first_carries_them(self):
        # Declared and exported, not compared at dispatch (docs/user-manual/upgrading.md): 1.0.0 named no agent.
        for action in MUTATING:
            with self.subTest(action=action):
                self.assertGreaterEqual(_version(_spec(action)["compatibility"]["minAgentVersion"]), (0, 15, 0))

    def test_definition_versions_and_the_plugin_doc_version(self):
        want = {"get_value": "1.1.0", "set_value": "1.1.0", "delete_value": "1.1.0", "delete_key": "1.2.0",
                "set_user_value": "1.0.0", "delete_user_value": "1.0.0", "apply": "1.0.0"}
        got = {d["spec"]["execution"]["action"]: d["metadata"]["version"] for d in _definitions().values()}
        for action, version in want.items():
            with self.subTest(action=action):
                self.assertEqual(got[action], version)
        docs = json.loads((REPO_ROOT / "content" / "plugin-docs" / "registry.json").read_text(encoding="utf-8"))
        self.assertEqual(docs["version"], "2.1.0")

    def test_no_registry_fixture_spells_the_scratch_key_stem_itself(self):
        # tests/unit/test_helpers.hpp registry_scratch_prefix() is the one place the `YuzuTest-` stem is written: it
        # adds the CI job scope that scripts/ci/check-registry-test-leftovers.ps1 keys on (#6488). A fixture that
        # spells its own "YuzuTest-..." key bypasses the scope, so a key it leaks is invisible to the per-job check.
        # Lexical: the quoted and backslash-prefixed spellings in code lines (comments are skipped), the stem run on into
        # a longer name included (an HKU mount name such as L"YuzuTestHold..." bypasses the scope the same way).
        fixtures = sorted((REPO_ROOT / "tests" / "unit").glob("test_registry_*.cpp"))
        self.assertTrue(fixtures)
        for path in fixtures:
            with self.subTest(file=path.name):
                lines = [n for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
                         if not line.strip().startswith(("//", "*")) and re.search(r'["\\]YuzuTest[-\w]', line)]
                self.assertEqual(lines, [], "build the key name from yuzu::test::registry_scratch_prefix()")

    def test_the_scope_variable_is_spelt_the_same_by_its_producer_and_consumers(self):
        # Lexical pin: CI sets YUZU_TEST_REGISTRY_SCOPE and the fixtures read it; a rename in one place would leave the
        # leftover check (handed the scope as -Scope) judging a scope no fixture uses.
        for rel, spelling in (("tests/unit/test_helpers.hpp", 'getenv("YUZU_TEST_REGISTRY_SCOPE")'),
                              (".github/workflows/ci.yml", "YUZU_TEST_REGISTRY_SCOPE: ")):
            with self.subTest(file=rel):
                self.assertIn(spelling, (REPO_ROOT / rel).read_text(encoding="utf-8"))

    def test_the_writers_are_classified_destructive_for_the_risk_gate(self):
        overrides = json.loads((REPO_ROOT / "scripts" / "test" / "instructions-risk-classification.json")
                               .read_text(encoding="utf-8"))["_overrides"]
        for action in MUTATING:
            with self.subTest(action=action):
                self.assertEqual(overrides[f"windows.registry.{action}"], "destructive")


if __name__ == "__main__":
    unittest.main()
