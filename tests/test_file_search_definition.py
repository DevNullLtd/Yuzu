#!/usr/bin/env python3
"""test_file_search_definition.py -- pins the definition YAML to the plugin: the row_kind-first
field_1..field_6 columns and the row_kind enum (each of the nine kinds a slice emits must also be a
`"<kind>|"` row prefix in the headers that format it; the planned-leg `status` row is gone with the
last planned leg), the root (the POSIX and the Windows forms), pattern, kinds and cursor grammar with
its bounds read from the headers that enforce them, the approval mode against the catalogue fragment's
gate, and the never-disclosed wording.

Runnable standalone: `python3 tests/test_file_search_definition.py` (how meson runs it; a bare
pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "file_search.yaml"
FRAGMENT = (REPO_ROOT / "server" / "core" / "src" / "capability_decls"
            / "plugin_action_catalogue_file_search.hpp")
PLUGIN_SRC = REPO_ROOT / "agents" / "plugins" / "file_search" / "src"
SHARED = REPO_ROOT / "agents" / "shared"
ROW_HEADERS = [PLUGIN_SRC / "file_search_rows.hpp", PLUGIN_SRC / "file_search_extents.hpp",
               SHARED / "file_search_coverage.hpp", SHARED / "file_search_names.hpp"]

EXPECTED_COLUMNS = ["row_kind"] + [f"field_{i}" for i in range(1, 7)]
# The nine row kinds of a slice, in the order the plugin documents them. Every leg ships (Linux, macOS and
# Windows), so there is no planned-leg `status` row any more.
SLICE_ROW_KINDS = ["match", "extents", "volume", "gap", "gaps_dropped", "volumes_dropped",
                   "coverage", "cursor", "search"]
ROW_KINDS = SLICE_ROW_KINDS
KINDS_ENUM = ["files", "directories", "both"]


def _int_constant(path: Path, name: str) -> int:
    """The value of `name = <digits>` or `name = <a> * <b>` (digit separators allowed) in `path`;
    a missing constant is a failure, never a vacuous pass."""
    m = re.search(rf"\b{name}\s*=\s*([0-9']+)(?:\s*\*\s*([0-9']+))?\s*;", path.read_text(encoding="utf-8"))
    assert m, f"{name} not found in {path.name}"
    value = int(m.group(1).replace("'", ""))
    if m.group(2):
        value *= int(m.group(2).replace("'", ""))
    return value


def _definition() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    assert len(docs) == 1, "file_search.yaml defines exactly one action (search)"
    return docs[0]


class FileSearchDefinitionColumns(unittest.TestCase):
    def test_row_kind_leads_and_the_columns_match_the_wire_row(self):
        names = [c["name"] for c in _definition()["spec"]["result"]["columns"]]
        self.assertEqual(names, EXPECTED_COLUMNS)

    def test_row_kind_values_are_the_shapes_the_plugin_emits_today(self):
        row_kind = _definition()["spec"]["result"]["columns"][0]
        self.assertEqual(row_kind["values"], ROW_KINDS)
        self.assertNotIn("status", row_kind["values"])  # the planned-leg row is gone
        self.assertNotIn("status:", row_kind["description"])

    def test_every_slice_row_kind_is_a_row_prefix_in_the_headers(self):
        text = "\n".join(p.read_text(encoding="utf-8") for p in ROW_HEADERS)
        for kind in SLICE_ROW_KINDS:
            with self.subTest(kind=kind):
                self.assertRegex(text, rf'"{kind}\|"', f"no `\"{kind}|\"` row prefix in the row headers")

    def test_every_column_describes_the_kinds_it_serves(self):
        # A column whose description names no row kind of the slice is a dead column.
        columns = _definition()["spec"]["result"]["columns"]
        for col in columns[1:]:
            with self.subTest(column=col["name"]):
                self.assertTrue(any(f"{k}:" in col["description"] for k in SLICE_ROW_KINDS),
                                col["name"])


class FileSearchDefinitionParameters(unittest.TestCase):
    def _params(self) -> dict:
        return _definition()["spec"]["parameters"]

    def test_root_and_pattern_are_required_and_kinds_and_cursor_are_optional(self):
        self.assertEqual(self._params()["required"], ["root", "pattern"])
        self.assertEqual(sorted(self._params()["properties"]), ["cursor", "kinds", "pattern", "root"])

    def test_kinds_enum_and_default(self):
        kinds = self._params()["properties"]["kinds"]
        self.assertEqual(kinds["validation"]["enum"], KINDS_ENUM)
        self.assertEqual(kinds["default"], "files")

    def test_bounds_equal_the_ones_the_agent_enforces(self):
        props = self._params()["properties"]
        self.assertEqual(props["root"]["validation"]["maxLength"],
                         _int_constant(PLUGIN_SRC / "file_search_rows.hpp", "kMaxRootBytes"))
        self.assertEqual(props["pattern"]["validation"]["maxLength"],
                         _int_constant(SHARED / "file_search_query.hpp", "kMaxPatternBytes"))
        # The longest cursor accepted is the fs1 token plus the volume prefix around it.
        request = (PLUGIN_SRC / "file_search_request.hpp").read_text(encoding="utf-8")
        m = re.search(r"kMaxRequestCursorBytes\s*=\s*fsr::kMaxCursorTokenBytes\s*\+\s*(\d+)\s*;", request)
        self.assertTrue(m, "kMaxRequestCursorBytes initializer not found in file_search_request.hpp")
        self.assertEqual(props["cursor"]["validation"]["maxLength"],
                         _int_constant(SHARED / "file_search_cursor.hpp", "kMaxCursorTokenBytes")
                         + int(m.group(1)))

    def test_root_pattern_is_an_absolute_path_prefix_in_either_form(self):
        root = re.compile(self._params()["properties"]["root"]["validation"]["pattern"])
        for ok in ("/", "/home", "/srv/data/", "/Users/x", "/x", "C:\\x", "c:\\", "C:/x",
                   "\\\\?\\Volume{0f1e2d3c-1111-2222-3333-44445555aabb}\\",
                   "\\\\?\\volume{0f1e2d3c-1111-2222-3333-44445555aabb}\\dir"):
            self.assertTrue(root.search(ok), ok)
        for bad in ("", "home", "./x", "../x", " /x", "C:", "C:x", "\\foo", "relative\\dir"):
            self.assertFalse(root.search(bad), bad)

    def test_root_description_names_the_root_tokens(self):
        text = " ".join(self._params()["properties"]["root"]["description"].split())
        for token in ("root_is_link", "root_not_found", "root_not_a_directory", "root_unc", "root_device_path"):
            with self.subTest(token=token):
                self.assertIn(token, text)


class FileSearchDefinitionContract(unittest.TestCase):
    def test_identity_platforms_gather_approval_and_compatibility_are_pinned(self):
        doc = _definition()
        spec = doc["spec"]
        self.assertEqual(doc["metadata"]["id"], "crossplatform.file_search.search")
        self.assertEqual(spec["execution"]["plugin"], "file_search")
        self.assertEqual(spec["execution"]["action"], "search")
        self.assertEqual(spec["platforms"], ["windows", "linux", "darwin"])
        for column in spec["result"]["columns"]:
            self.assertEqual(column["platforms"], ["windows", "linux", "darwin"], column["name"])
        self.assertEqual(spec["execution"]["concurrency"], "per-device")
        self.assertEqual(spec["gather"]["ttlSeconds"], 300)
        self.assertEqual(spec["permissions"]["executeRoles"], ["admin"])
        self.assertEqual(spec["compatibility"]["requiredPlugins"], ["file_search"])
        self.assertEqual(spec["type"], "question")  # read-only: the catalogue gate relies on it
        self.assertEqual(doc["status"]["phase"], "active")

    def test_approval_mode_matches_the_catalogue_gate(self):
        fragment = FRAGMENT.read_text(encoding="utf-8")
        gate = re.search(r"\.execute_gate\s*=\s*ExecuteGate::(\w+)\s*,", fragment)
        self.assertTrue(gate, "no .execute_gate in the file_search fragment")
        # role-gated <-> ExecuteGate::AdminOrApproval (test_capability_gate_consistency.py maps it)
        self.assertEqual(gate.group(1), "AdminOrApproval")
        self.assertEqual(_definition()["spec"]["approval"]["mode"], "role-gated")

    def test_description_states_the_never_disclosed_wording(self):
        text = " ".join(_definition()["metadata"]["description"].lower().split())
        for phrase in (
            "names, types, sizes, times and extents", "opened and never read", "no file content is read or hashed",
            "on by default", "forensics:read", "not a snapshot",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
