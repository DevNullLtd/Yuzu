#!/usr/bin/env python3
"""test_instructions_risk_table.py - the /test --instructions risk table must not drift.

The Instructions gate (scripts/test/instructions_runner.py) POSTs every default-risk
definition as a broadcast. The server refuses a broadcast for any capability row that
requires explicit targets: DispatchClass::Destructive, or the Forensics securable
(requires_explicit_targets in server/core/src/dispatch_destructive_gate.hpp). A definition
that targets such a row but is classified safe or mutating therefore fails the gate with
HTTP 400 on every run. The risk table was hand-maintained and lagged the capability
declarations for months (14 definitions), so this test derives the set from the
capability_decls fragments and requires every matching definition to be classified into a
class the default run skips.

Runnable standalone: `python3 tests/test_instructions_risk_table.py`. Hermetic: reads
source files only (needs PyYAML, as the runner does). No subprocess, network or clock.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "test"))
import instructions_runner as ir  # noqa: E402

FRAGMENTS = sorted((ROOT / "server/core/src/capability_decls").glob("*.hpp"))
# One catalogue row: ".plugin = "p", .action = "a", ... }," (rows are brace-delimited, one per entry).
ROW = re.compile(r'\.plugin\s*=\s*"([^"]+)",\s*\.action\s*=\s*"([^"]+)",(.*?)\n\s*\},', re.S)
DESTRUCTIVE = re.compile(r"\.dispatch_class\s*=\s*DispatchClass::Destructive")
FORENSICS = re.compile(r'\.securable\s*=\s*"Forensics"')


def explicit_target_rows(texts):
    """{(plugin, action)} for every row the server refuses to broadcast, plus the row count."""
    rows, total = set(), 0
    for text in texts:
        for plugin, action, body in ROW.findall(text):
            total += 1
            if DESTRUCTIVE.search(body) or FORENSICS.search(body):
                rows.add((plugin, action))
    return rows, total


def misclassified(rows, defs):
    """Definitions targeting a row in `rows` whose risk the default run would still dispatch."""
    return sorted(d.id for d in defs
                  if (d.plugin, d.action) in rows and d.risk in ir.DEFAULT_RISKS)


class RiskTable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.total = explicit_target_rows(p.read_text(encoding="utf-8") for p in FRAGMENTS)
        table = ir.load_risk_table(ROOT / "scripts/test/instructions-risk-classification.json")
        cls.defs = ir.load_definitions(ROOT / "content/definitions", table)

    def test_parse_is_not_vacuous(self):
        # A regex that silently stopped matching would make the main check pass on nothing.
        self.assertGreater(self.total, 100, "catalogue row regex found too few rows")
        self.assertGreater(len(self.rows), 10, "no Destructive/Forensics rows found")

    def test_explicit_target_definitions_are_not_in_the_default_run(self):
        bad = misclassified(self.rows, self.defs)
        self.assertEqual(bad, [], "definitions the server refuses to broadcast are classified "
                                  "safe/mutating in scripts/test/instructions-risk-classification.json; "
                                  "classify them destructive or forensic")

    def test_failure_mode_on_synthetic_data(self):
        d = ir.Definition(id="x.y", plugin="p", action="a", type="action", platforms=[],
                          parameters={}, result_columns=[], approval_mode="auto", risk="mutating", file="x.yaml")
        self.assertEqual(misclassified({("p", "a")}, [d]), ["x.y"])
        d.risk = "forensic"
        self.assertEqual(misclassified({("p", "a")}, [d]), [])
        self.assertEqual(ir.classify("a.b", "action", {}, "server_internal"), "server-internal")


if __name__ == "__main__":
    unittest.main(verbosity=2)
