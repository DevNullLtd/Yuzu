#!/usr/bin/env python3
"""test_enablement_os_applicability.py — ADR-3006 drift gate.

`kUnitOs` in server/core/src/enablement_units.hpp (one row per plugin.action:
which agent OSes the switchable unit is applicable on) must equal what the
generated block of docs/os-capability-matrix.md says: applicable on an OS iff
its Support is not `unsupported` (macos -> darwin). Checked in both
directions. The two reserved control-channel rows that are catalogue rows but
never units (`__guard__.push_rules`, `__sync__.now`) must be in neither.

Hermetic: reads sources only. The generated block is never edited here.
Run: python3 tests/test_enablement_os_applicability.py
"""

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools" / "plugin-doc-gen"))

import plugin_doc_gen as g  # noqa: E402

HEADER = REPO_ROOT / "server" / "core" / "src" / "enablement_units.hpp"
MATRIX = REPO_ROOT / "docs" / "os-capability-matrix.md"

BITS = {"windows": 1, "linux": 2, "macos": 4}
BIT_NAMES = {"kWin": 1, "kLin": 2, "kMac": 4}
ROW_RE = re.compile(r'^\s*\{"([^"]+)",\s*"([^"]+)",\s*([A-Za-z0-9_| ]+)\},\s*$', re.M)
NOT_UNITS = {("__guard__", "push_rules"), ("__sync__", "now")}


def header_rows() -> dict[tuple[str, str], int]:
    text = HEADER.read_text(encoding="utf-8")
    start = text.index("kUnitOs{{")
    body = text[start:text.index("}};", start)]
    out: dict[tuple[str, str], int] = {}
    for plugin, action, expr in ROW_RE.findall(body):
        mask = 0
        for tok in (t.strip() for t in expr.split("|")):
            mask |= BIT_NAMES[tok] if tok in BIT_NAMES else int(tok)
        if (plugin, action) in out:
            raise AssertionError(f"duplicate kUnitOs row {plugin}.{action}")
        out[(plugin, action)] = mask
    return out


def matrix_rows() -> dict[tuple[str, str], int]:
    parsed = g.parse_matrix_block(MATRIX.read_text(encoding="utf-8"))
    out: dict[tuple[str, str], int] = {}
    for plugin, actions in parsed.items():
        for action, legs in actions.items():
            out[(plugin, action)] = sum(
                BITS[os_name] for os_name, leg in legs.items() if leg.support != "unsupported"
            )
    return out


class EnablementOsApplicability(unittest.TestCase):
    def test_header_rows_parse(self):
        self.assertGreater(len(header_rows()), 200)

    def test_every_matrix_pair_has_a_row_and_vice_versa(self):
        h, m = set(header_rows()), set(matrix_rows())
        self.assertEqual(
            sorted(m - h), [],
            "matrix pair with no kUnitOs row - add it to kUnitOs in "
            "server/core/src/enablement_units.hpp (mask from the matrix generated block)",
        )
        self.assertEqual(
            sorted(h - m), [],
            "kUnitOs row with no matrix pair - remove or fix it in kUnitOs in "
            "server/core/src/enablement_units.hpp",
        )

    def test_masks_match_the_matrix(self):
        h, m = header_rows(), matrix_rows()
        bad = {
            f"{p}.{a}": (h[(p, a)], m[(p, a)])
            for (p, a) in h
            if (p, a) in m and h[(p, a)] != m[(p, a)]
        }
        self.assertEqual(
            bad, {},
            "kUnitOs mask != matrix applicable set (header, matrix) - fix the row in kUnitOs in "
            "server/core/src/enablement_units.hpp from the matrix generated block",
        )

    def test_control_channel_rows_are_in_neither(self):
        self.assertEqual(NOT_UNITS & set(header_rows()), set())
        self.assertEqual(NOT_UNITS & set(matrix_rows()), set())


if __name__ == "__main__":
    unittest.main()
