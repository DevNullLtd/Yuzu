#!/usr/bin/env python3
"""test_certificates_definition.py -- pins the result columns of the certificates `list` and
`details` definitions to the row header the plugin writes (`kCertRowHeader` in
certificates_plugin.cpp), so a column added, renamed or reordered on one side only fails here
rather than in a dashboard or a downstream parser. Unlike the shares/runtimes definition tests,
the expected sequence is read from the C++ source, not copied into this file.

Runnable standalone: `python3 tests/test_certificates_definition.py` (how meson runs it; a bare
pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "certificates.yaml"
PLUGIN_SOURCE = REPO_ROOT / "agents" / "plugins" / "certificates" / "src" / "certificates_plugin.cpp"

# `constexpr std::string_view kCertRowHeader = "..." "...";` -- one or more adjacent literals.
_HEADER_DECL = re.compile(r"constexpr\s+std::string_view\s+kCertRowHeader\s*=\s*((?:\s*\"[^\"]*\")+)\s*;")
_LITERAL = re.compile(r"\"([^\"]*)\"")


def row_header_columns(source: str) -> list[str]:
    """The `|`-separated column names of kCertRowHeader, or [] if the declaration is not found."""
    match = _HEADER_DECL.search(source)
    if not match:
        return []
    return "".join(_LITERAL.findall(match.group(1))).split("|")


def _definitions() -> dict[str, dict]:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    return {d["spec"]["execution"]["action"]: d for d in docs}


def _column_names(doc: dict) -> list[str]:
    return [c["name"] for c in doc["spec"]["result"]["columns"]]


class CertificatesDefinitionColumns(unittest.TestCase):
    def setUp(self):
        self.header = row_header_columns(PLUGIN_SOURCE.read_text(encoding="utf-8"))
        self.assertTrue(self.header, "kCertRowHeader declaration not found in certificates_plugin.cpp")

    def test_list_and_details_columns_match_the_plugin_row_header(self):
        defs = _definitions()
        for action in ("list", "details"):
            with self.subTest(action=action):
                self.assertEqual(_column_names(defs[action]), self.header)

    def test_crypto_profile_columns_follow_key_usage_on_every_platform(self):
        self.assertEqual(self.header[7:], ["key_usage", "key_algorithm", "key_bits", "signature_algorithm"])
        defs = _definitions()
        for action in ("list", "details"):
            columns = {c["name"]: c for c in defs[action]["spec"]["result"]["columns"]}
            for name in ("key_algorithm", "key_bits", "signature_algorithm"):
                with self.subTest(action=action, column=name):
                    self.assertEqual(columns[name]["platforms"], ["windows", "linux", "darwin"])
                    self.assertIn("(unknown)", columns[name]["description"])


class RowHeaderParser(unittest.TestCase):
    """The parser above must still match the shape it is meant to read, or the test is vacuous."""

    def test_reads_adjacent_literals(self):
        src = 'constexpr std::string_view kCertRowHeader =\n    "a|b|"\n    "c";\n'
        self.assertEqual(row_header_columns(src), ["a", "b", "c"])

    def test_missing_declaration_reads_as_empty(self):
        self.assertEqual(row_header_columns('constexpr std::string_view kOther = "a|b";'), [])


if __name__ == "__main__":
    unittest.main()
