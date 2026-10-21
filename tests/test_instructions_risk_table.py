#!/usr/bin/env python3
"""test_instructions_risk_table.py - the /test --instructions risk table must not drift.

The Instructions gate (scripts/test/instructions_runner.py) POSTs every default-risk
definition as a broadcast. The server refuses a broadcast for any capability row that
requires explicit targets: DispatchClass::Destructive, or the Forensics securable
(requires_explicit_targets in server/core/src/dispatch_destructive_gate.hpp). A definition
that targets such a row but is classified safe or mutating therefore fails the gate with
HTTP 400 on every run. The risk table was hand-maintained and lagged the capability
declarations for months (14 definitions), so this test derives the set from the
capability_decls fragments and requires every matching definition to carry the opt-in class
its row implies: `forensic` for a Forensics row, and `destructive` (or the more specific
`network-disrupt`/`interactive`) for a Destructive row. It also pins the two runner rules the
table leans on: the server-only plugin spellings and the removed HTTP-200 auto-pass.

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


# The opt-in classes a definition may carry, by the kind of row it targets.
ALLOWED = {"forensic": ("forensic",), "destructive": ("destructive", "network-disrupt", "interactive")}


def explicit_target_rows(texts):
    """({(plugin, action): "forensic"|"destructive"} for every row the server refuses to
    broadcast, row count)."""
    rows, total = {}, 0
    for text in texts:
        for plugin, action, body in ROW.findall(text):
            total += 1
            if FORENSICS.search(body):
                rows[(plugin, action)] = "forensic"
            elif DESTRUCTIVE.search(body):
                rows[(plugin, action)] = "destructive"
    return rows, total


def misclassified(rows, defs):
    """Definitions targeting a row in `rows` whose risk is not an opt-in class for that row."""
    return sorted(d.id for d in defs
                  if (d.plugin, d.action) in rows and d.risk not in ALLOWED[rows[(d.plugin, d.action)]])


def make_def(plugin="p", risk="mutating", def_id="x.y"):
    return ir.Definition(id=def_id, plugin=plugin, action="a", type="action", platforms=[],
                         parameters={}, result_columns=[], approval_mode="auto", risk=risk, file="x.yaml")


class FakeClient:
    """Stands in for YuzuClient: dispatch always succeeds, polling returns `responses`."""

    def __init__(self, responses):
        self.responses = responses

    def execute_instruction(self, def_id, params):
        return 200, {"command_id": "c1"}

    def get_responses(self, command_id):
        return {"responses": self.responses}


class RiskTable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        texts = [p.read_text(encoding="utf-8") for p in FRAGMENTS]
        cls.rows, cls.total = explicit_target_rows(texts)
        # Independent counts straight off the text (comment lines stripped), so a regex that
        # drops rows cannot hide.
        code = [re.sub(r"(?m)^\s*//.*$", "", t) for t in texts]
        cls.raw_rows = sum(len(re.findall(r"\.plugin\s*=", t)) for t in code)
        cls.raw_forensics = sum(len(FORENSICS.findall(t)) for t in code)
        cls.raw_destructive = sum(len(DESTRUCTIVE.findall(t)) for t in code)
        cls.parsed_destructive = sum(1 for t in texts for _, _, body in ROW.findall(t)
                                     if DESTRUCTIVE.search(body))
        cls.table = ir.load_risk_table(ROOT / "scripts/test/instructions-risk-classification.json")
        cls.defs = ir.load_definitions(ROOT / "content/definitions", cls.table)

    def test_parse_is_not_vacuous(self):
        # A regex that silently dropped rows would make the main check pass on nothing.
        self.assertTrue(FRAGMENTS, "no capability_decls fragments found")
        self.assertGreater(self.total, 0)
        why = " (or a non-comment line outside a catalogue row matched the raw pattern)"
        self.assertEqual(self.total, self.raw_rows, "ROW regex dropped or invented catalogue rows" + why)
        self.assertEqual(list(self.rows.values()).count("forensic"), self.raw_forensics,
                         "a Forensics row was not parsed as one" + why)
        self.assertEqual(self.parsed_destructive, self.raw_destructive,
                         "a Destructive dispatch_class was not parsed inside a row" + why)
        self.assertEqual(set(self.rows.values()), {"forensic", "destructive"})

    def test_definitions_side_is_not_vacuous(self):
        # The main check compares definitions to rows; empty definitions (moved content dir) or a
        # renamed `plugin` key would leave it green with nothing compared.
        matched = [d for d in self.defs if (d.plugin, d.action) in self.rows]
        self.assertGreaterEqual(len(matched), 20, "too few definitions matched an explicit-target row")
        self.assertEqual({self.rows[(d.plugin, d.action)] for d in matched}, {"forensic", "destructive"})

    def test_default_run_excludes_every_opt_in_class(self):
        opt_in = {"destructive", "forensic", "server-internal", "network-disrupt", "interactive"}
        self.assertEqual(set(ir.DEFAULT_RISKS) & opt_in, set())

    def test_risk_table_matches_definitions(self):
        ids = {d.id for d in self.defs}
        self.assertEqual(sorted(set(self.table) - ids), [], "risk-table entries naming no definition")
        self.assertEqual(sorted(set(self.table.values()) - set(ir.ALL_RISKS)), [], "unknown risk class")

    def test_explicit_target_definitions_carry_their_opt_in_class(self):
        bad = misclassified(self.rows, self.defs)
        self.assertEqual(bad, [], "definitions the server refuses to broadcast carry the wrong class in "
                                  "scripts/test/instructions-risk-classification.json; a Forensics row "
                                  "needs forensic, a Destructive row destructive")

    def test_failure_mode_on_synthetic_data(self):
        rows = {("p", "a"): "destructive", ("p", "b"): "forensic"}
        d = make_def(risk="mutating")
        self.assertEqual(misclassified(rows, [d]), ["x.y"])
        for bad in ("safe", "server-internal"):
            d.risk = bad
            self.assertEqual(misclassified(rows, [d]), ["x.y"], bad)
        for ok in ("destructive", "network-disrupt", "interactive"):
            d.risk = ok
            self.assertEqual(misclassified(rows, [d]), [], ok)
        d.risk = "forensic"  # reserved for Forensics rows: a label swap must be caught
        self.assertEqual(misclassified(rows, [d]), ["x.y"])
        f = make_def(risk="destructive")
        f.action = "b"
        self.assertEqual(misclassified(rows, [f]), ["x.y"])
        f.risk = "forensic"
        self.assertEqual(misclassified(rows, [f]), [])

    def test_runner_risk_rules(self):
        for plugin in ("_server", "server", "server_internal"):
            self.assertEqual(ir.classify("a.b", "action", {}, plugin), "server-internal", plugin)
        self.assertEqual(ir.classify("a.b", "query", {}, "os_info"), "safe")
        self.assertEqual(ir.classify("a.b", "action", {}, "os_info"), "mutating")
        self.assertEqual(ir.classify("a.b", "action", {"a.b": "safe"}, "server"), "safe")  # override wins
        self.assertIn("forensic", ir.ALL_RISKS)
        self.assertIn("server-internal", ir.ALL_RISKS)
        args = ir.parse_args(["--dashboard", "http://x", "--password", "x",
                              "--risks", "forensic", "server-internal"])
        self.assertEqual(args.risks, ["forensic", "server-internal"])

    def test_server_side_definition_needs_an_agent_response(self):
        # HTTP 200 + command_id used to auto-pass server-side plugins without any response, which
        # hid the dispatch chokepoint denying them. poll_timeout_s=0 skips the poll loop (no sleep).
        for plugin in ("_server", "server", "server_internal"):
            outcome = ir.exercise(FakeClient([]), make_def(plugin=plugin), {}, poll_timeout_s=0)
            self.assertEqual(outcome.status, "fail", plugin)
            self.assertIn("no response within", outcome.note)
        # The pass case breaks on its first poll; 30s is never reached, so a stalled VM cannot flip it.
        answered = FakeClient([{"output": "x", "status": "ok", "rc": 0}])
        self.assertEqual(ir.exercise(answered, make_def(plugin="server"), {}, poll_timeout_s=30).status, "pass")


if __name__ == "__main__":
    unittest.main(verbosity=2)
