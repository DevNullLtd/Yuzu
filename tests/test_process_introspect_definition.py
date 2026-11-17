#!/usr/bin/env python3
"""test_process_introspect_definition.py -- pins the definition YAML's result columns (the
row_kind-first, field_1..field_4 name sequence and the row_kind enum) to the row layout
process_introspect_parsers.hpp emits, the parameter contract (required pid and facet, the
closed facet enum, the pid and start_time patterns) and the never-disclosed wording, so a
reordered or renamed column or a widened parameter fails here rather than only in a dashboard.
It compares the YAML with the literals below, except the facet enum, which it compares with the
`kFacetNames` initializer in process_introspect_parsers.hpp (the one list the plugin parses
against), so a facet added to the C++ alone fails here; it reads nothing else from the C++.

Runnable standalone: `python3 tests/test_process_introspect_definition.py` (how meson runs it;
a bare pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "process_introspect.yaml"
PARSERS = (REPO_ROOT / "agents" / "plugins" / "process_introspect" / "src"
           / "process_introspect_parsers.hpp")

EXPECTED_COLUMNS = ["row_kind"] + [f"field_{i}" for i in range(1, 5)]
ROW_KINDS = ["status", "target", "limit", "sigmask", "cap", "seccomp", "oom", "sched"]


def _facets_from_header() -> list:
    """The names in `kFacetNames{...}`; an empty capture is a failure, never a vacuous pass."""
    m = re.search(r"kFacetNames\s*\{([^}]*)\}", PARSERS.read_text(encoding="utf-8"))
    assert m, "kFacetNames initializer not found in process_introspect_parsers.hpp"
    names = re.findall(r'"([a-z_]+)"', m.group(1))
    assert names, "kFacetNames initializer holds no facet names"
    return names


def _definition() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    assert len(docs) == 1, "process_introspect.yaml defines exactly one action (inspect)"
    return docs[0]


class ProcessIntrospectDefinitionColumns(unittest.TestCase):
    def test_row_kind_leads_and_the_columns_match_the_wire_row(self):
        names = [c["name"] for c in _definition()["spec"]["result"]["columns"]]
        self.assertEqual(names, EXPECTED_COLUMNS)

    def test_row_kind_values_are_the_shapes_the_plugin_emits_today(self):
        row_kind = _definition()["spec"]["result"]["columns"][0]
        self.assertEqual(row_kind["values"], ROW_KINDS)


class ProcessIntrospectDefinitionParameters(unittest.TestCase):
    def _params(self) -> dict:
        return _definition()["spec"]["parameters"]

    def test_pid_and_facet_are_required_and_start_time_is_optional(self):
        self.assertEqual(self._params()["required"], ["pid", "facet"])
        self.assertEqual(sorted(self._params()["properties"]), ["facet", "pid", "start_time"])

    def test_facet_enum_is_kfacetnames(self):
        self.assertEqual(self._params()["properties"]["facet"]["validation"]["enum"],
                         _facets_from_header())

    def test_pid_and_start_time_patterns(self):
        props = self._params()["properties"]
        pid = re.compile(props["pid"]["validation"]["pattern"])
        for ok in ("1", "9", "10", "4242", "99999999", "123456789", "999999999", "1000000000",
                   "1999999999", "2147483647"):
            self.assertTrue(pid.fullmatch(ok), ok)
        for bad in ("", "0", "01", "-1", "1 ", "abc", "12345678901",
                    "2147483648", "2999999999", "3999999999", "9999999999"):
            self.assertFalse(pid.fullmatch(bad), bad)
            # the server matches unanchored (RE2 PartialMatch): a dropped outer group would
            # let `^a|b$` match a longer string on one arm only, so search must refuse too
            self.assertFalse(pid.search(bad), bad)
        # Exactness at every arm edge: for each prefix of INT32_MAX padded to ten digits with
        # 0s and with 9s, the values one either side must be accepted iff 1..INT32_MAX.
        max_pid, digits = 2147483647, str(2147483647)
        for pad in "09":
            for cut in range(len(digits) + 1):
                edge = int((digits[:cut] + pad * len(digits))[:len(digits)])
                for n in (edge - 1, edge, edge + 1):
                    if n < 0:
                        continue
                    with self.subTest(n=n):
                        self.assertEqual(bool(pid.fullmatch(str(n))), 1 <= n <= max_pid, n)
                        self.assertEqual(bool(pid.search(str(n))), 1 <= n <= max_pid, n)
        st = re.compile(props["start_time"]["validation"]["pattern"])
        for ok in ("", "0123abcd.1", "0123abcd.18446744073709551615"):
            self.assertTrue(st.fullmatch(ok), ok)
        for bad in ("0123ABCD.1", "0123abcd", "0123abc.1", "0123abcd.", "0123abcd.1|x",
                    "0123abcd.123456789012345678901", "zz"):
            self.assertFalse(st.fullmatch(bad), bad)

    def test_start_time_description_names_the_target_row_as_the_source(self):
        text = " ".join(self._params()["properties"]["start_time"]["description"].split())
        self.assertIn("field 2 of the `target` row", text)
        self.assertIn("no other plugin or action emits it", text)


class ProcessIntrospectDefinitionContract(unittest.TestCase):
    def test_identity_platforms_gather_approval_and_compatibility_are_pinned(self):
        doc = _definition()
        spec = doc["spec"]
        self.assertEqual(doc["metadata"]["id"], "crossplatform.process_introspect.inspect")
        self.assertEqual(spec["execution"]["plugin"], "process_introspect")
        self.assertEqual(spec["execution"]["action"], "inspect")
        self.assertEqual(spec["platforms"], ["windows", "linux", "darwin"])
        self.assertEqual(spec["execution"]["concurrency"], "per-device")
        self.assertEqual(spec["gather"]["ttlSeconds"], 300)
        # role-gated <-> ExecuteGate::AdminOrApproval (test_capability_gate_consistency.py maps it)
        self.assertEqual(spec["approval"]["mode"], "role-gated")
        self.assertEqual(spec["permissions"]["executeRoles"], ["admin"])
        self.assertEqual(spec["compatibility"]["requiredPlugins"], ["process_introspect"])
        self.assertEqual(spec["type"], "question")  # read-only: the catalogue gate relies on it
        self.assertEqual(doc["status"]["phase"], "active")

    def test_description_states_one_process_off_until_enabled_and_never_disclosed(self):
        text = " ".join(_definition()["metadata"]["description"].lower().split())
        for phrase in (
            "one process on one device", "off until enabled", "file or memory contents",
            "environment values", "socket payloads", "command-line arguments",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
