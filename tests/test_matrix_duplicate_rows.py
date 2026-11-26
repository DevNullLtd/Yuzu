#!/usr/bin/env python3
"""test_matrix_duplicate_rows.py — catch a "keep both sides" merge resolution.

Two checks:
  1. docs/os-capability-matrix.md: no table repeats a row key. Hand-written
     tables are keyed on the first cell; the generated per-action tables on
     (plugin, action, os). Keys, not whole lines: the two sides of a bad
     resolution usually differ in text.
  2. No leftover merge-conflict marker in the docs, plugin or content trees.
     `=======` alone is not matched: it is also a Markdown heading underline.

Hermetic: reads sources only.
Run: python3 tests/test_matrix_duplicate_rows.py
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MATRIX = REPO_ROOT / "docs" / "os-capability-matrix.md"
MARKER_ROOTS = ("docs", "agents/plugins", "content")
MARKER_SUFFIXES = {".md", ".json", ".yaml", ".yml"}
MARKER_RE = re.compile(r"^(<{7}|\|{7}|>{7})( |$)")
GENERATED_HEADING = "## Generated:"


def duplicate_rows(text: str) -> list[str]:
    found: list[str] = []
    seen: dict[tuple[str, ...], int] = {}
    generated = False
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("## "):
            generated = line.startswith(GENERATED_HEADING)
        if not line.startswith("|"):
            seen = {}  # the table ended
            continue
        cells = [c.strip() for c in line.split("|")[1:]]
        key = tuple(cells[: 3 if generated else 1])
        if all(set(c) <= set("-: ") for c in key):
            continue  # separator row, or a blank first cell
        if key in seen:
            found.append(f"line {number} repeats line {seen[key]}: {' | '.join(key)}")
        else:
            seen[key] = number
    return found


def conflict_markers(text: str) -> list[int]:
    return [n for n, line in enumerate(text.splitlines(), 1) if MARKER_RE.match(line)]


class MatrixDuplicateRows(unittest.TestCase):
    def test_matrix_has_no_repeated_row_key(self):
        self.assertEqual(
            duplicate_rows(MATRIX.read_text(encoding="utf-8")), [],
            "docs/os-capability-matrix.md has two rows for one key. This is usually a "
            "conflict resolved by keeping both sides: combine them into one row.",
        )

    def test_no_leftover_conflict_markers(self):
        bad = [
            f"{path.relative_to(REPO_ROOT)}:{n}"
            for root in MARKER_ROOTS
            for path in sorted((REPO_ROOT / root).rglob("*"))
            if path.suffix in MARKER_SUFFIXES and path.is_file()
            for n in conflict_markers(path.read_text(encoding="utf-8", errors="replace"))
        ]
        self.assertEqual(bad, [], "leftover merge-conflict markers")


class LintFires(unittest.TestCase):
    """The checks above pass on a clean tree, so prove they can fail."""

    def test_hand_table_keyed_on_first_cell(self):
        text = "| a | b |\n|---|---|\n| echo | old |\n| echo | new |\n"
        self.assertEqual(len(duplicate_rows(text)), 1)

    def test_same_key_in_two_tables_is_allowed(self):
        text = "| echo | x |\n\n| echo | y |\n"
        self.assertEqual(duplicate_rows(text), [])

    def test_generated_table_keyed_on_three_cells(self):
        head = f"{GENERATED_HEADING} x\n\n"
        ok = head + "| p | a | linux |\n| p | a | macos |\n"
        bad = head + "| p | a | linux | one |\n| p | a | linux | two |\n"
        self.assertEqual(duplicate_rows(ok), [])
        self.assertEqual(len(duplicate_rows(bad)), 1)

    def test_conflict_markers(self):
        text = "<<<<<<< HEAD\nTitle\n=======\n>>>>>>> dev\n"
        self.assertEqual(conflict_markers(text), [1, 4])


if __name__ == "__main__":
    unittest.main()
