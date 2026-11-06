#!/usr/bin/env python3
"""#2146 lexical gate: the workflow-run metric families are seeded, counted and alerted on by names
the server really exports.

`promtool test rules` feeds a rule hand-written input series, so a rule that names a metric or a
label value the server never emits parses, passes every case and can never fire (#2553, the
observability conventions' shipped-alert-rules row). This gate closes that for the four rules
added with the workflow-run outcome counter and the run-table growth rule, by checking them against
the C++ source:

  * server.cpp calls `seed_workflow_run_metrics(metrics_)` exactly once, outside a comment (the
    unit test proves the function seeds the closed sets; only this proves the server calls it);
  * the REST and MCP twins each bind `count_run_outcome` to `make_workflow_run_outcome_counter`
    (one copy of the counter, and a transport that forgets it counts nothing);
  * every `yuzu_*` metric name and every `label="value"` matcher in the four alert expressions is
    a quoted string literal somewhere under server/core/src (a gauge, a counter name, a closed-set
    label value), so a rename on either side fails here;
  * the run-table size gauges are described and the failure counter pre-seeded in server.cpp, and
    the maintenance tick calls `refresh_table_size_metrics` exactly once, outside a comment;
  * the five alerts, the outcome counter and the three run-table series are named in the metrics
    manual, and every alert carries a runbook_url.

Not checked: that a (metric, label, value) triple is seeded TOGETHER. A value is only matched
against the flat literal corpus (the closed sets are spread over several files, some built from
another header's constant), so a value seeded under a different metric still passes.

Lexical only: a call moved into dead code is review-enforced. Usage:
  python3 -I tests/test_workflow_run_metrics_wiring_lexical.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "server" / "core" / "src"
ALERTS = ROOT / "docs" / "prometheus" / "yuzu-alerts.yml"
METRICS_MD = ROOT / "docs" / "user-manual" / "metrics.md"
RULES = (
    "YuzuHeldOpenUtilisationHigh",
    "YuzuWorkflowFinalizeFailed",
    "YuzuWorkflowRunGlobalCapRefused",
    "YuzuWorkflowIndeterminateReplays",
    "YuzuWorkflowExecutionsTableLarge",
)
SIZE_SERIES = (
    "yuzu_server_workflow_executions_rows",
    "yuzu_server_workflow_executions_bytes",
    "yuzu_server_workflow_executions_stats_unavailable_total",
)
SIZE_CONSTANTS = (
    "kWorkflowExecutionsRowsMetric",
    "kWorkflowExecutionsBytesMetric",
    "kWorkflowExecutionsStatsUnavailableMetric",
)
DESCRIBE = r"metrics_\s*\.\s*describe\s*\(\s*yuzu::server::%s\b"
SEED_FAILURES = re.compile(
    r"metrics_\s*\.\s*counter\s*\(\s*yuzu::server::kWorkflowExecutionsStatsUnavailableMetric\b")
REFRESH_CALL = re.compile(r"\bworkflow_engine_\s*->\s*refresh_table_size_metrics\s*\(\s*\)\s*;")
SEED_CALL = re.compile(r"\bseed_workflow_run_metrics\s*\(\s*metrics_\s*\)\s*;")
BIND = re.compile(r"count_run_outcome\s*=\s*make_workflow_run_outcome_counter\s*\(")
METRIC = re.compile(r"\byuzu_[a-z_]+[a-z]\b")
MATCHER = re.compile(r'\b([a-z_]+)\s*(?:=|=~)\s*"([^"]+)"')


def code_lines(src):
    """Lines that are not comment lines (// or inside a /* ... */ block), `//` tails cut."""
    in_block = False
    for line in src.splitlines():
        text = line.strip()
        if in_block:
            in_block = "*/" not in text
            continue
        if text.startswith("//"):
            continue
        if text.startswith("/*"):
            in_block = "*/" not in text
            continue
        yield text.split("//")[0]


def count_matches(src, pattern):
    return sum(len(pattern.findall(line)) for line in code_lines(src))


def rule_exprs(alerts_text, names):
    """name -> the expr text of that alert (up to its `for:`/`labels:`)."""
    out = {}
    for name in names:
        m = re.search(r"- alert: %s\n\s+expr: \|\n(?P<expr>.*?)\n\s+(?:for|labels):" % re.escape(name),
                      alerts_text, re.S)
        if m:
            out[name] = m.group("expr")
    return out


def literal_corpus():
    """Every double-quoted string literal in server/core/src, as one blob."""
    parts = []
    for p in sorted(SRC.glob("*.[ch]pp")):
        parts.extend(re.findall(r'"([^"\n]*)"', p.read_text(encoding="utf-8", errors="replace")))
    return set(parts)


def unexported(expr, corpus):
    """Names and matcher values in `expr` that no source literal carries."""
    bad = []
    for name in sorted(set(METRIC.findall(expr))):
        if name not in corpus:
            bad.append(name)
    for label, value in MATCHER.findall(expr):
        if label not in corpus:
            bad.append("label %s" % label)
        if value not in corpus:
            bad.append("%s=%s" % (label, value))
    return bad


class WorkflowRunMetricsWiring(unittest.TestCase):
    def test_server_seeds_once(self):
        src = (SRC / "server.cpp").read_text(encoding="utf-8")
        self.assertEqual(count_matches(src, SEED_CALL), 1)

    def test_both_twins_bind_the_counter(self):
        for name in ("workflow_execute_routes.cpp", "mcp_server.cpp"):
            src = (SRC / name).read_text(encoding="utf-8")
            self.assertEqual(count_matches(src, BIND), 1, name)

    def test_alert_expressions_name_only_exported_series(self):
        text = ALERTS.read_text(encoding="utf-8")
        exprs = rule_exprs(text, RULES)
        self.assertEqual(sorted(exprs), sorted(RULES), "an alert or its expr block is missing")
        corpus = literal_corpus()
        for name, expr in exprs.items():
            self.assertEqual(unexported(expr, corpus), [], name)

    def test_alerts_and_counter_are_documented(self):
        md = METRICS_MD.read_text(encoding="utf-8")
        for needle in RULES + SIZE_SERIES + ("yuzu_server_workflow_run_outcome_total",):
            self.assertTrue(needle in md, "%s is not named in docs/user-manual/metrics.md" % needle)

    def test_every_workflow_alert_has_a_runbook(self):
        text = ALERTS.read_text(encoding="utf-8")
        for name in RULES:
            m = re.search(r"- alert: %s\n(?P<body>.*?)(?=\n      - alert: |\n  - name: |\Z)" % name, text, re.S)
            self.assertIsNotNone(m, name)
            self.assertIn("runbook_url:", m.group("body"), "%s has no runbook_url" % name)

    def test_size_series_are_exported_by_the_names_the_rule_reads(self):
        # The rule reads the series by its literal name; the exported name is the header constant.
        header = (SRC / "workflow_engine.hpp").read_text(encoding="utf-8")
        for const, series in zip(SIZE_CONSTANTS, SIZE_SERIES):
            self.assertRegex(header, r'\b%s\[\]\s*=\s*(?:\n\s*)?"%s"' % (const, series))
        server = (SRC / "server.cpp").read_text(encoding="utf-8")
        for const in SIZE_CONSTANTS[:2]:
            self.assertEqual(count_matches(server, re.compile(DESCRIBE % const)), 1, const)
        self.assertEqual(count_matches(server, re.compile(DESCRIBE % SIZE_CONSTANTS[2])), 1)
        self.assertEqual(count_matches(server, SEED_FAILURES), 1)

    def test_maintenance_tick_samples_the_table_once(self):
        server = (SRC / "server.cpp").read_text(encoding="utf-8")
        self.assertEqual(count_matches(server, REFRESH_CALL), 1)

    def test_gate_sees_a_removed_call_a_renamed_metric_and_a_unknown_label_value(self):
        self.assertEqual(count_matches("void f() {\n// seed_workflow_run_metrics(metrics_);\n}", SEED_CALL), 0)
        self.assertEqual(count_matches("/*\n seed_workflow_run_metrics(metrics_);\n*/", SEED_CALL), 0)
        self.assertEqual(count_matches("void f() { seed_workflow_run_metrics(metrics_); }", SEED_CALL), 1)
        self.assertEqual(count_matches("p.count_run_outcome = make_workflow_run_outcome_counter(m);", BIND), 1)
        self.assertEqual(count_matches("p.count_run_outcome = {};", BIND), 0)
        corpus = {"yuzu_a_total", "good", "reason"}
        self.assertEqual(unexported('increase(yuzu_a_total{reason="good"}[5m]) > 0', corpus), [])
        self.assertEqual(unexported('increase(yuzu_b_total{reason="good"}[5m]) > 0', corpus), ["yuzu_b_total"])
        self.assertEqual(unexported('increase(yuzu_a_total{reason="bad"}[5m]) > 0', corpus), ["reason=bad"])
        self.assertEqual(unexported('yuzu_a_total{nope="good"} > 0', corpus), ["label nope"])
        self.assertEqual(count_matches("void f() {\n// workflow_engine_->refresh_table_size_metrics();\n}", REFRESH_CALL), 0)
        self.assertEqual(count_matches("if (workflow_engine_) workflow_engine_->refresh_table_size_metrics();", REFRESH_CALL), 1)


if __name__ == "__main__":
    unittest.main()
