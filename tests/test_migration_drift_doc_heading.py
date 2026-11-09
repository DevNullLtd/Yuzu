#!/usr/bin/env python3
"""The migration-drift log line's doc pointer names a real upgrading.md heading (#7158).

`kDriftDocHeading` (server/core/src/pg/pg_migration_runner.cpp) is quoted by the runner's
drift and malformed-hash log lines as `docs/user-manual/upgrading.md, "<heading>"`. The doc
heading carries a `Behaviour change: ` prefix that the constant does not. If either side is
renamed alone, an operator reading the log line is sent to a heading that does not exist
(the #7164 defect). This test reads the constant out of the .cpp, joining the adjacent string
literals, and asserts the doc has exactly one `## Behaviour change: <constant>` heading.

The negative cases run the same check on in-memory mutated copies (a renamed heading, a
renamed constant, a duplicated heading), so the check itself is proven able to fail without
touching a tracked file.
"""
import os
import re
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CPP = os.path.join(REPO, "server", "core", "src", "pg", "pg_migration_runner.cpp")
DOC = os.path.join(REPO, "docs", "user-manual", "upgrading.md")
PREFIX = "Behaviour change: "

DECL = re.compile(r"kDriftDocHeading\s*=\s*((?:\s*\"(?:[^\"\\]|\\.)*\")+)\s*;")
LITERAL = re.compile(r"\"((?:[^\"\\]|\\.)*)\"")


def read_constant(cpp_text):
    """The constant's value, adjacent string literals joined; None if not found."""
    m = DECL.search(cpp_text)
    if not m:
        return None
    return "".join(LITERAL.findall(m.group(1)))


def heading_count(doc_text, constant):
    wanted = "## " + PREFIX + constant
    return sum(1 for line in doc_text.splitlines() if line.rstrip() == wanted)


def problems(cpp_text, doc_text):
    constant = read_constant(cpp_text)
    if not constant:
        return ["kDriftDocHeading not found (or not a plain string literal) in the runner"]
    n = heading_count(doc_text, constant)
    if n != 1:
        return ["expected exactly one '## %s%s' heading in upgrading.md, found %d"
                % (PREFIX, constant, n)]
    return []


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class DriftDocHeading(unittest.TestCase):
    def test_constant_matches_exactly_one_heading(self):
        self.assertEqual(problems(_read(CPP), _read(DOC)), [])

    def test_a_renamed_heading_fails(self):
        cpp, doc = _read(CPP), _read(DOC)
        constant = read_constant(cpp)
        self.assertTrue(constant)
        renamed = doc.replace("## " + PREFIX + constant, "## " + PREFIX + constant + " (renamed)")
        self.assertNotEqual(renamed, doc)
        self.assertTrue(problems(cpp, renamed))

    def test_a_renamed_constant_fails(self):
        cpp, doc = _read(CPP), _read(DOC)
        self.assertTrue(problems(cpp.replace("the server stops", "the server halts"), doc))

    def test_a_duplicated_heading_fails(self):
        cpp, doc = _read(CPP), _read(DOC)
        constant = read_constant(cpp)
        dup = doc + "\n## " + PREFIX + constant + "\n"
        self.assertTrue(problems(cpp, dup))

    def test_literal_concatenation_is_joined(self):
        text = 'constexpr const char* kDriftDocHeading =\n    "a b "\n    "c";\n'
        self.assertEqual(read_constant(text), "a b c")


if __name__ == "__main__":
    unittest.main()
