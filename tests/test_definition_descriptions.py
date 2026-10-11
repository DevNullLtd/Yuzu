#!/usr/bin/env python3
"""test_definition_descriptions.py - self-test AND repo gate for
scripts/ci/check-definition-descriptions.py.

(1) Pins the lint's thresholds and rule set against literals, so loosening a minimum or dropping
    a rule is a reviewed change to this file, not a silent edit to the script.
(2) Feeds the linter synthetic definitions with one seeded defect each and asserts that exactly
    that rule fires, and that a conforming definition fires nothing.
(3) Exercises the ratchet in both directions: a failure missing from the baseline is NEW, a
    baselined entry that no longer fails is STALE, and a malformed baseline is refused.
(4) Runs the real script over the real tree (the repo gate).

Runnable standalone: `python3 tests/test_definition_descriptions.py` (how meson runs it). Needs
PyYAML, like the other definition tests. Hermetic apart from reading content/definitions.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ci" / "check-definition-descriptions.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_definition_descriptions", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load()

SUBPROCESS_TIMEOUT_S = 120


def run_script(argv, **kwargs):
    """Run the lint script as a child process; a hang fails the test instead of the job."""
    try:
        return subprocess.run(argv, capture_output=True, text=True, check=False,
                              timeout=SUBPROCESS_TIMEOUT_S, **kwargs)
    except subprocess.TimeoutExpired:
        raise AssertionError(
            f"{SCRIPT.name} did not finish within {SUBPROCESS_TIMEOUT_S}s") from None

GOOD_DESCRIPTION = "Lists every running process on the endpoint with its owner and start time."


def definition(**overrides):
    """A conforming definition document; keyword overrides replace whole top-level sections."""
    doc = {
        "kind": "InstructionDefinition",
        "metadata": {
            "id": "test.demo.list",
            "displayName": "List Demo",
            "description": GOOD_DESCRIPTION,
            "tags": ["demo"],
        },
        "spec": {
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Maximum rows to return."},
                },
            },
            "result": {
                "columns": [
                    {"name": "pid", "type": "int64", "description": "Process id."},
                ],
            },
        },
    }
    doc.update(overrides)
    return doc


def fired(doc):
    _, failures = M.lint_definition(doc, "fallback")
    return {rule: sorted(keys) for rule, keys in failures.items() if keys}


class Constants(unittest.TestCase):
    def test_thresholds_and_rules_are_pinned(self):
        self.assertEqual(M.MIN_DEFINITION_DESCRIPTION, 40)
        self.assertEqual(M.MIN_PARAMETER_DESCRIPTION, 10)
        self.assertEqual(
            M.RULES,
            ("definition-description", "parameter-description",
             "result-column-description", "tags"),
        )


class SeededDefects(unittest.TestCase):
    def test_conforming_definition_fires_nothing(self):
        self.assertEqual(fired(definition()), {})

    def test_missing_description(self):
        doc = definition()
        del doc["metadata"]["description"]
        self.assertEqual(fired(doc), {"definition-description": ["test.demo.list"]})

    def test_short_description_after_whitespace_collapse(self):
        doc = definition()
        doc["metadata"]["description"] = "Lists   processes.\n\n   Short."
        self.assertEqual(fired(doc), {"definition-description": ["test.demo.list"]})

    def test_description_of_exactly_the_minimum_passes(self):
        doc = definition()
        doc["metadata"]["description"] = "x" * 40
        self.assertEqual(fired(doc), {})
        doc["metadata"]["description"] = "x" * 39
        self.assertEqual(fired(doc), {"definition-description": ["test.demo.list"]})

    def test_description_equal_to_the_name(self):
        doc = definition()
        long_name = "A display name that is itself forty characters long or more"
        doc["metadata"]["displayName"] = long_name
        doc["metadata"]["description"] = "  " + long_name.upper().replace(" ", "  ") + " "
        self.assertEqual(fired(doc), {"definition-description": ["test.demo.list"]})

    def test_empty_or_blank_tags(self):
        for tags in (None, [], [""], "demo"):
            doc = definition()
            doc["metadata"]["tags"] = tags
            self.assertEqual(fired(doc), {"tags": ["test.demo.list"]}, repr(tags))
        doc = definition()
        del doc["metadata"]["tags"]
        self.assertEqual(fired(doc), {"tags": ["test.demo.list"]})

    def test_parameter_without_or_with_short_description(self):
        doc = definition()
        props = doc["spec"]["parameters"]["properties"]
        props["nodesc"] = {"type": "string"}
        props["short"] = {"type": "string", "description": "too short"}  # 9 characters
        props["edge"] = {"type": "string", "description": "ten chars."}  # exactly 10
        self.assertEqual(
            fired(doc),
            {"parameter-description": ["test.demo.list:nodesc", "test.demo.list:short"]},
        )

    def test_result_column_without_description(self):
        doc = definition()
        doc["spec"]["result"]["columns"].append({"name": "owner", "type": "string"})
        doc["spec"]["result"]["columns"].append(
            {"name": "blank", "type": "string", "description": "  \n "})
        self.assertEqual(
            fired(doc),
            {"result-column-description": ["test.demo.list:blank", "test.demo.list:owner"]},
        )

    def test_definition_without_parameters_or_result_is_not_a_failure_for_those_rules(self):
        doc = definition()
        del doc["spec"]["parameters"]
        del doc["spec"]["result"]
        self.assertEqual(fired(doc), {})

    def test_missing_id_falls_back_to_a_file_position_key(self):
        doc = definition()
        del doc["metadata"]["id"]
        doc["metadata"]["tags"] = []
        self.assertEqual(fired(doc), {"tags": ["fallback"]})


class Ratchet(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_defdesc_")
        self.addCleanup(self.tmp.cleanup)
        self.content = Path(self.tmp.name) / "content"
        self.dir = self.content / "definitions"
        self.dir.mkdir(parents=True)
        self.baseline = Path(self.tmp.name) / "baseline.json"

    def write_yaml(self, name, text):
        (self.dir / name).write_text(text, encoding="utf-8")

    def run_main(self, *extra):
        out = run_script(
            [sys.executable, str(SCRIPT), "--content-root", str(self.content),
             "--baseline", str(self.baseline), *extra])
        return out.returncode, out.stdout + out.stderr

    DEFECTIVE = (
        "---\n"
        "kind: InstructionDefinition\n"
        "metadata:\n"
        "  id: t.bad.one\n"
        "  description: short\n"
        "  tags: [x]\n"
        "spec:\n"
        "  result:\n"
        "    columns:\n"
        "      - name: c\n"
    )

    def test_update_then_clean_then_new_then_stale(self):
        self.write_yaml("a.yaml", self.DEFECTIVE)
        rc, out = self.run_main("--update-baseline")
        self.assertEqual(rc, 0, out)
        baseline = json.loads(self.baseline.read_text(encoding="utf-8"))["baseline"]
        self.assertEqual(baseline["definition-description"], ["t.bad.one"])
        self.assertEqual(baseline["result-column-description"], ["t.bad.one:c"])

        rc, out = self.run_main()
        self.assertEqual(rc, 0, out)

        # A second defective definition is not baselined: NEW.
        self.write_yaml("b.yaml", self.DEFECTIVE.replace("t.bad.one", "t.bad.two"))
        rc, out = self.run_main()
        self.assertEqual(rc, 1, out)
        self.assertIn("NEW      definition-description: t.bad.two", out)
        self.assertNotIn("STALE", out)

        # Fixing a baselined failure without shrinking the baseline: STALE.
        (self.dir / "b.yaml").unlink()
        self.write_yaml("a.yaml", self.DEFECTIVE.replace("description: short",
                        "description: " + GOOD_DESCRIPTION))
        rc, out = self.run_main()
        self.assertEqual(rc, 1, out)
        self.assertIn("STALE    definition-description: t.bad.one", out)
        self.assertNotIn("NEW", out)

    def _defective(self, def_id, parameter_description=GOOD_DESCRIPTION[:9], tags="[x]"):
        """One definition whose only defects are a short parameter description and/or tags."""
        return (
            "---\n"
            "kind: InstructionDefinition\n"
            "metadata:\n"
            f"  id: {def_id}\n"
            f"  description: {GOOD_DESCRIPTION}\n"
            f"  tags: {tags}\n"
            "spec:\n"
            "  parameters:\n"
            "    type: object\n"
            "    properties:\n"
            "      p:\n"
            "        type: string\n"
            f"        description: {parameter_description}\n"
        )

    def test_new_and_stale_for_the_parameter_description_rule(self):
        self.write_yaml("a.yaml", self._defective("t.par.one"))
        self.assertEqual(self.run_main("--update-baseline")[0], 0)
        baseline = json.loads(self.baseline.read_text(encoding="utf-8"))["baseline"]
        self.assertEqual(baseline["parameter-description"], ["t.par.one:p"])
        self.assertEqual(self.run_main()[0], 0)

        self.write_yaml("b.yaml", self._defective("t.par.two"))
        rc, out = self.run_main()
        self.assertEqual(rc, 1, out)
        self.assertIn("NEW      parameter-description: t.par.two:p", out)
        self.assertIn("at least 10 characters", out)  # the message states the threshold
        self.assertNotIn("STALE", out)

        (self.dir / "b.yaml").unlink()
        self.write_yaml("a.yaml", self._defective("t.par.one", parameter_description="Long enough."))
        rc, out = self.run_main()
        self.assertEqual(rc, 1, out)
        self.assertIn("STALE    parameter-description: t.par.one:p", out)
        self.assertNotIn("NEW", out)

    def test_new_and_stale_for_the_tags_rule(self):
        self.write_yaml("a.yaml", self._defective("t.tag.one", parameter_description="Long enough.",
                                                  tags="[]"))
        self.assertEqual(self.run_main("--update-baseline")[0], 0)
        baseline = json.loads(self.baseline.read_text(encoding="utf-8"))["baseline"]
        self.assertEqual(baseline["tags"], ["t.tag.one"])
        self.assertEqual(self.run_main()[0], 0)

        self.write_yaml("b.yaml", self._defective("t.tag.two", parameter_description="Long enough.",
                                                  tags="[]"))
        rc, out = self.run_main()
        self.assertEqual(rc, 1, out)
        self.assertIn("NEW      tags: t.tag.two", out)
        self.assertNotIn("STALE", out)

        (self.dir / "b.yaml").unlink()
        self.write_yaml("a.yaml", self._defective("t.tag.one", parameter_description="Long enough.",
                                                  tags="[x]"))
        rc, out = self.run_main()
        self.assertEqual(rc, 1, out)
        self.assertIn("STALE    tags: t.tag.one", out)
        self.assertNotIn("NEW", out)

    def test_new_definition_description_violation_states_the_threshold(self):
        self.write_yaml("a.yaml", self.DEFECTIVE)
        self.assertEqual(self.run_main("--update-baseline")[0], 0)
        self.write_yaml("b.yaml", self.DEFECTIVE.replace("t.bad.one", "t.bad.two"))
        rc, out = self.run_main()
        self.assertEqual(rc, 1, out)
        self.assertIn("at least 40 characters", out)

    def test_deleting_a_baselined_definition_is_stale(self):
        self.write_yaml("a.yaml", self.DEFECTIVE)
        self.assertEqual(self.run_main("--update-baseline")[0], 0)
        (self.dir / "a.yaml").unlink()
        self.write_yaml("keep.yaml", self.DEFECTIVE.replace("t.bad.one", "t.keep"))
        rc, out = self.run_main()
        self.assertEqual(rc, 1, out)
        self.assertIn("STALE    definition-description: t.bad.one", out)

    def test_malformed_baseline_and_unparseable_yaml_are_usage_errors(self):
        self.write_yaml("a.yaml", self.DEFECTIVE)
        self.baseline.write_text(json.dumps({"baseline": {"tags": []}}), encoding="utf-8")
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(self.run_main("--update-baseline")[0], 0)
        self.write_yaml("broken.yaml", "key: [unclosed\n")
        self.assertEqual(self.run_main()[0], 2)

    def test_non_definition_documents_are_ignored(self):
        self.write_yaml("a.yaml", self.DEFECTIVE + "---\nkind: InstructionSet\nmetadata:\n  id: s\n")
        self.assertEqual(self.run_main("--update-baseline")[0], 0)
        self.assertEqual(self.run_main()[0], 0)

    def test_baseline_that_is_not_an_object_is_a_usage_error(self):
        self.write_yaml("a.yaml", self.DEFECTIVE)
        for text in ("[]", '"x"', "null", "[" * 100000):
            self.baseline.write_text(text, encoding="utf-8")
            rc, out = self.run_main()
            self.assertEqual(rc, 2, out)
            self.assertNotIn("Traceback", out)

    def test_yaml_nested_too_deeply_is_a_usage_error_not_a_traceback(self):
        self.write_yaml("deep.yaml", "k: " + "[" * 5000 + "]" * 5000 + "\n")
        rc, out = self.run_main()
        self.assertEqual(rc, 2, out)
        self.assertIn("deep.yaml", out)
        self.assertNotIn("Traceback", out)

    # The walk is the one server/core/scripts/embed_content.py ships: both roots, recursively.
    def write_at(self, relative, text):
        path = self.content / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_definition_in_a_nested_directory_is_linted(self):
        self.baseline.write_text(json.dumps({"baseline": {r: [] for r in M.RULES}}), encoding="utf-8")
        self.write_at("definitions/vendor/deep/x.yaml", self.DEFECTIVE)
        rc, out = self.run_main()
        self.assertEqual(rc, 1, out)
        self.assertIn("NEW      definition-description: t.bad.one", out)

    def test_definition_in_a_pack_is_linted_and_a_product_pack_document_is_not(self):
        self.write_yaml("a.yaml", self.DEFECTIVE.replace("t.bad.one", "t.def.one"))
        self.write_at("packs/sub/p.yaml",
                      self.DEFECTIVE.replace("t.bad.one", "t.pack.one") +
                      "---\nkind: ProductPack\nmetadata:\n  id: pk\n  description: short\n")
        rc, out = self.run_main("--update-baseline")
        self.assertEqual(rc, 0, out)
        baseline = json.loads(self.baseline.read_text(encoding="utf-8"))["baseline"]
        self.assertEqual(baseline["definition-description"], ["t.def.one", "t.pack.one"])
        self.assertEqual(baseline["tags"], [])  # the ProductPack document is not a definition
        self.assertEqual(self.run_main()[0], 0)

    def test_no_definition_under_either_root_is_a_usage_error(self):
        self.write_at("other/x.yaml", self.DEFECTIVE)  # outside definitions/ and packs/
        self.assertEqual(self.run_main("--update-baseline")[0], 2)

    def test_same_file_name_in_two_directories_gets_distinct_fallback_keys(self):
        no_id = self.DEFECTIVE.replace("  id: t.bad.one\n", "")
        self.write_at("definitions/a/x.yaml", no_id)
        self.write_at("definitions/b/x.yaml", no_id)
        self.assertEqual(self.run_main("--update-baseline")[0], 0)
        baseline = json.loads(self.baseline.read_text(encoding="utf-8"))["baseline"]
        self.assertEqual(baseline["definition-description"],
                         ["definitions/a/x.yaml#0", "definitions/b/x.yaml#0"])


class RepoGate(unittest.TestCase):
    def test_shipped_definitions_match_the_baseline(self):
        out = run_script([sys.executable, str(SCRIPT)], cwd=str(ROOT))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)


if __name__ == "__main__":
    unittest.main()
