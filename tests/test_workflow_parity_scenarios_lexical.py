#!/usr/bin/env python3
"""#2146 lexical gate: the two workflow replay-parity matrices run the scenarios one table names.

Two matrices prove "a replay says what the first answer said": the stand-in matrix in
tests/unit/server/test_workflow_execute_twins.cpp (no Postgres) and the real-engine matrix in
tests/unit/server/test_workflow_engine.cpp ([pg], skipped without a database). They drifted once:
the real-engine matrix lacked four states only the stand-in had (interrupted before anything was
sent, late_denied as the first step, a deadline already passed, a not-completed run whose every
attempted step reached). Both now take each scenario's expected class and reason from
tests/unit/server/workflow_parity_scenarios.hpp and name it with `parity_scenario("<key>")`.

This gate compares, from source text:
  * the keys each file passes to `parity_scenario("...")` with the table's rows for that matrix
    (a row marked kBoth must appear in both files, kStandIn / kReal in that one only);
  * that a row run by only one matrix says why (`why_one_sided`), and a kBoth row does not;
  * that keys are unique, and that no row's expected class is outside the closed outcome set.

It cannot see whether a scenario's body is honest (a case that names a key and asserts nothing
passes); the C++ cases check the class, the reason and the replay against the table's row.
Usage: python3 -I tests/test_workflow_parity_scenarios_lexical.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UNIT = ROOT / "tests" / "unit" / "server"
TABLE = UNIT / "workflow_parity_scenarios.hpp"
STAND_IN = UNIT / "test_workflow_execute_twins.cpp"
REAL = UNIT / "test_workflow_engine.cpp"

CLASSES = {"succeeded", "partial", "failed", "aborted", "interrupted"}
ROW = re.compile(
    r'\{\s*"(?P<key>[a-z0-9_]+)"\s*,\s*"(?P<cls>[a-z_]+)"\s*,\s*"(?P<reason>[a-z_]+)"\s*,\s*'
    r'Matrix::(?P<in>kStandIn|kReal|kBoth)\s*,\s*(?P<why>"(?:[^"\\]|\\.)*")\s*\}')
USE = re.compile(r'\bparity_scenario\s*\(\s*"([a-z0-9_]+)"\s*\)')


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def table_rows(text: str):
    return [m.groupdict() for m in ROW.finditer(strip_comments(text))]


def used_keys(text: str):
    return USE.findall(strip_comments(text))


def problems(table_text: str, stand_in_text: str, real_text: str):
    out = []
    rows = table_rows(table_text)
    if not rows:
        return ["no scenario rows parsed from workflow_parity_scenarios.hpp"]
    keys = [r["key"] for r in rows]
    for k in sorted({k for k in keys if keys.count(k) > 1}):
        out.append(f"duplicate scenario key {k}")
    for r in rows:
        if r["cls"] not in CLASSES:
            out.append(f"{r['key']}: expected class {r['cls']} is not one of {sorted(CLASSES)}")
        one_sided = r["in"] != "kBoth"
        has_why = r["why"] != '""'
        if one_sided and not has_why:
            out.append(f"{r['key']}: run by one matrix only ({r['in']}) but gives no why_one_sided")
        if not one_sided and has_why:
            out.append(f"{r['key']}: kBoth rows carry no why_one_sided text")
    stand_in_used = used_keys(stand_in_text)
    real_used = used_keys(real_text)
    for name, used in (("stand-in", stand_in_used), ("real-engine", real_used)):
        for k in sorted({k for k in used if used.count(k) > 1}):
            out.append(f"{name} matrix names scenario {k} more than once")
        for k in sorted(set(used) - set(keys)):
            out.append(f"{name} matrix names scenario {k}, which the table does not have")
    want_stand_in = {r["key"] for r in rows if r["in"] in ("kStandIn", "kBoth")}
    want_real = {r["key"] for r in rows if r["in"] in ("kReal", "kBoth")}
    for k in sorted(want_stand_in - set(stand_in_used)):
        out.append(f"stand-in matrix does not run scenario {k}")
    for k in sorted(want_real - set(real_used)):
        out.append(f"real-engine matrix does not run scenario {k}")
    for k in sorted(set(stand_in_used) - want_stand_in):
        out.append(f"stand-in matrix runs scenario {k}, which the table assigns to the real engine only")
    for k in sorted(set(real_used) - want_real):
        out.append(f"real-engine matrix runs scenario {k}, which the table assigns to the stand-in only")
    return out


class ParityScenarioGate(unittest.TestCase):
    def test_matrices_run_the_table(self):
        found = problems(TABLE.read_text(), STAND_IN.read_text(), REAL.read_text())
        self.assertEqual(found, [], "\n".join(found))

    def test_the_gate_sees_each_kind_of_drift(self):
        table = (
            'inline constexpr Scenario kScenarios[] = {\n'
            '  {"a", "succeeded", "none", Matrix::kBoth, ""},\n'
            '  {"b", "partial", "none", Matrix::kReal, "stand-in has no policy"},\n'
            '};\n'
        )
        stand_in = 'x(parity_scenario("a"));'
        real = 'x(parity_scenario("a")); y(parity_scenario("b"));'
        self.assertEqual(problems(table, stand_in, real), [])
        self.assertTrue(any("does not run scenario a" in p for p in problems(table, "", real)))
        self.assertTrue(any("does not run scenario a" in p for p in problems(table, stand_in, 'y(parity_scenario("b"));')))
        self.assertTrue(any("scenario b, which the table assigns to the real engine only" in p
                            for p in problems(table, stand_in + 'z(parity_scenario("b"));', real)))
        self.assertTrue(any("does not have" in p for p in problems(table, stand_in + 'z(parity_scenario("q"));', real)))
        self.assertTrue(any("gives no why_one_sided" in p
                            for p in problems(table.replace('"stand-in has no policy"', '""'), stand_in, real)))
        self.assertTrue(any("more than once" in p for p in problems(table, stand_in + stand_in, real)))
        # a commented-out use is not a use
        self.assertTrue(any("does not run scenario a" in p
                            for p in problems(table, '// parity_scenario("a")', real)))


if __name__ == "__main__":
    unittest.main()
