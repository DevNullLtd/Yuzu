"""Lexical tripwire: filesystem.exists must refuse a network/device path up front and must never
fall back to the RAW caller path (WP10 review finding). The refusal is Windows-only code, so this
pins the shape on every host; the pure predicate is covered by test_local_path_policy.cpp."""
import pathlib
import re
import unittest

SRC = pathlib.Path(__file__).resolve().parents[1] / "agents/plugins/filesystem/src/filesystem_plugin.cpp"


class ExistsNoRawFallback(unittest.TestCase):
    def body(self):
        s = SRC.read_text()
        i = s.index("int do_exists(")
        return s[i:s.index("int do_list_dir(", i)]

    def test_refusal_precedes_validation(self):
        b = self.body()
        self.assertIn("path_refusal(path)", b)
        self.assertLess(b.index("path_refusal(path)"), b.index("validate_path_or_parent("))

    def test_the_refusal_branch_is_live_and_returns(self):
        # The up-front refusal must be a real condition that returns an error row: neutralising it
        # (`if (false && ...)`, a removed `return 1`) must fail here.
        b = self.body()
        i = b.index("path_refusal(path)")
        branch = b[i - 40:b.index("validate_path_or_parent(")]
        # The EXACT condition: any extra clause (`; false && ...`) or a different test fails here.
        self.assertIn(
            "if (const auto refusal = path_refusal(path); yuzu::shared::local_path::refused(refusal)) {",
            branch)
        self.assertNotRegex(branch, r"if\s*\(\s*(false|0)\b")
        self.assertIn("return 1;", branch)
        self.assertIn('"error|{}"', branch)

    def test_exists_row_follows_the_canonical_recheck(self):
        # ONE consistent answer: the canonical re-check runs before any `exists|` row, so a refusal
        # is an error row alone and never `exists|true` followed by an error.
        b = self.body()
        self.assertLess(b.index("validate_path(path, base_dir)"), b.index('"exists|{}"'))

    def test_no_raw_path_fallback(self):
        b = self.body()
        self.assertIsNone(re.search(r"std::string\{path\}", b), "raw caller path used after validation")
        self.assertIsNone(re.search(r"canon\.empty\(\)\s*\?\s*path_str", b))


if __name__ == "__main__":
    unittest.main()
