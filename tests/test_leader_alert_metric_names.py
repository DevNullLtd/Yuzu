#!/usr/bin/env python3
"""The leader-election alerts and docs may name only series the server really exports.

`promtool test rules` cannot know the exporter: it feeds a rule hand-written input series, so
a rule (and its test) that names `yuzu_server_leader_is_leaderr` parses, passes every case, and
can never fire in production. That is the "parses but cannot fire" class (#2553, the
observability conventions' shipped-alert-rules row). This test closes it for the HA WS-11
(#4014) family by comparing against the ONE place the names are defined:

  * exported   = the `"yuzu_server_leader_*"` string literals in server/core/src/leader_metrics.hpp
  * alert rules (docs/prometheus/yuzu-alerts.yml), their promtool cases
    (tests/prometheus/yuzu-alerts.test.yml) and the user manual metrics reference
    (docs/user-manual/metrics.md) may reference ONLY exported names;
  * the metrics reference must document EVERY exported name, and every `cause` label value the
    elector counts (the closed arrays in server/core/src/leader_elector.hpp).

Comments count: a name in a comment that is not exported is still a documentation lie.
A token ending in `_` (a wildcard such as `yuzu_server_leader_*`) is a prefix, not a name.

Usage:
  python3 -I tests/test_leader_alert_metric_names.py
  python3 -I tests/test_leader_alert_metric_names.py --repo-root DIR
"""
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TAG = "test_leader_alert_metric_names"

METRICS_HPP = "server/core/src/leader_metrics.hpp"
ELECTOR_HPP = "server/core/src/leader_elector.hpp"
CONSUMERS = (
    "docs/prometheus/yuzu-alerts.yml",
    "tests/prometheus/yuzu-alerts.test.yml",
    "docs/user-manual/metrics.md",
)
DOC = "docs/user-manual/metrics.md"

_TOKEN = re.compile(r"yuzu_server_leader_[a-z_]*[a-z]")
_LITERAL = re.compile(r'"(yuzu_server_leader_[a-z_]*[a-z])"')
_LABEL_ARRAY = re.compile(
    r"k(?:AcquireFailure|LeadershipLoss)Labels\s*=\s*\{(?P<body>[^}]*)\}", re.S)


def tokens(text):
    """Every complete metric-name token in `text` (wildcard prefixes are not names)."""
    out = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in _TOKEN.finditer(line):
            end = m.end()
            if end < len(line) and line[end] == "_":
                continue  # defensive; the regex is greedy so this does not normally happen
            out.setdefault(m.group(0), lineno)
    return out


def exported_names(hpp_text):
    return {m.group(1) for m in _LITERAL.finditer(hpp_text)}


def cause_labels(elector_text):
    labels = []
    for m in _LABEL_ARRAY.finditer(elector_text):
        labels += re.findall(r'"([a-z_]+)"', m.group("body"))
    return labels


def problems(read):
    """`read(rel)` returns a file's text. Returns a list of human-readable problems."""
    out = []
    exported = exported_names(read(METRICS_HPP))
    if len(exported) < 7:
        out.append(f"{METRICS_HPP}: expected the 7 exported yuzu_server_leader_* names, "
                   f"found {len(exported)} ({sorted(exported)}); did the literals move?")
    for rel in CONSUMERS:
        for name, lineno in sorted(tokens(read(rel)).items(), key=lambda kv: kv[1]):
            if name not in exported:
                out.append(f"{rel}:{lineno}: `{name}` is not exported by {METRICS_HPP} "
                           f"(a rule or doc naming it can never match a real series)")
    doc_tokens = tokens(read(DOC))
    for name in sorted(exported):
        if name not in doc_tokens:
            out.append(f"{DOC}: exported metric `{name}` is not documented")
    doc = read(DOC)
    labels = cause_labels(read(ELECTOR_HPP))
    if len(labels) != 6:
        out.append(f"{ELECTOR_HPP}: expected 6 cause labels (4 acquire-failure + 2 loss), "
                   f"found {labels}")
    for label in labels:
        if label not in doc:
            out.append(f"{DOC}: cause label `{label}` is not documented")
    # Every alert must reference at least one exported series (a rule with none is dead).
    alerts = read("docs/prometheus/yuzu-alerts.yml")
    group = alerts.split("- name: yuzu-ha-leader", 1)
    if len(group) != 2:
        out.append("docs/prometheus/yuzu-alerts.yml: group `yuzu-ha-leader` not found")
    else:
        body = group[1].split("\n  - name:", 1)[0]
        for alert in re.findall(r"- alert: (\w+)", body):
            seg = body.split(f"- alert: {alert}", 1)[1].split("- alert:", 1)[0]
            expr = seg.split("expr: |", 1)[1].split("for:", 1)[0] if "expr: |" in seg else ""
            if not tokens(expr):
                out.append(f"yuzu-alerts.yml: alert {alert} references no yuzu_server_leader_* series")
    return out


def _reader(root):
    root = Path(root)

    def read(rel):
        return (root / rel).read_text(encoding="utf-8")

    return read


class LeaderAlertMetricNames(unittest.TestCase):
    root = ROOT

    def test_every_referenced_name_is_exported_and_documented(self):
        out = problems(_reader(self.root))
        for m in out:
            print(f"\n::error::{TAG}: {m}", file=sys.stderr)
        self.assertEqual(out, [])


class CheckerSelfTest(unittest.TestCase):
    """The checker itself: a renamed or undocumented name must make it FAIL."""

    HPP = ('inline constexpr const char* A = "yuzu_server_leader_is_leader";\n'
           'inline constexpr const char* B = "yuzu_server_leader_epoch";\n'
           'inline constexpr const char* C = "yuzu_server_leader_acquired_total";\n'
           'inline constexpr const char* D = "yuzu_server_leader_acquire_failures_total";\n'
           'inline constexpr const char* E = "yuzu_server_leader_lost_total";\n'
           'inline constexpr const char* F = "yuzu_server_leader_last_ok_age_seconds";\n'
           'inline constexpr const char* G = "yuzu_server_leader_loop_errors_total";\n')
    ELECTOR = ('kAcquireFailureLabels = {"connect", "lock_query", "lock_guard", "epoch_record"};\n'
               'kLeadershipLossLabels = {"liveness_failed", "resigned"};\n')
    DOC = ("yuzu_server_leader_is_leader yuzu_server_leader_epoch yuzu_server_leader_acquired_total\n"
           "yuzu_server_leader_acquire_failures_total yuzu_server_leader_lost_total\n"
           "yuzu_server_leader_last_ok_age_seconds yuzu_server_leader_loop_errors_total\n"
           "connect lock_query lock_guard epoch_record liveness_failed resigned\n")
    ALERTS = ("groups:\n  - name: yuzu-ha-leader\n    rules:\n"
              "      - alert: A1\n        expr: |\n          yuzu_server_leader_is_leader > 1\n"
              "        for: 2m\n")
    TEST = "series: 'yuzu_server_leader_is_leader{job=\"x\"}'\n"

    def files(self, **over):
        f = {METRICS_HPP: self.HPP, ELECTOR_HPP: self.ELECTOR, DOC: self.DOC,
             "docs/prometheus/yuzu-alerts.yml": self.ALERTS,
             "tests/prometheus/yuzu-alerts.test.yml": self.TEST}
        f.update(over)
        return f

    def run_check(self, f):
        return problems(f.__getitem__)

    def test_clean_tree_passes(self):
        self.assertEqual(self.run_check(self.files()), [])

    def test_renamed_name_in_alert_fails(self):
        out = self.run_check(self.files(**{
            "docs/prometheus/yuzu-alerts.yml":
                self.ALERTS.replace("is_leader", "is_leaderr")}))
        self.assertTrue(any("is_leaderr" in m and "not exported" in m for m in out), out)

    def test_renamed_name_in_promtool_case_fails(self):
        out = self.run_check(self.files(**{
            "tests/prometheus/yuzu-alerts.test.yml": self.TEST.replace("leader_is", "leader_isx")}))
        self.assertTrue(any("not exported" in m for m in out), out)

    def test_undocumented_export_fails(self):
        out = self.run_check(self.files(**{DOC: self.DOC.replace(
            "yuzu_server_leader_loop_errors_total", "")}))
        self.assertTrue(any("loop_errors_total" in m and "not documented" in m for m in out), out)

    def test_undocumented_cause_label_fails(self):
        out = self.run_check(self.files(**{DOC: self.DOC.replace("epoch_record", "")}))
        self.assertTrue(any("epoch_record" in m for m in out), out)

    def test_wildcard_prefix_is_not_a_name(self):
        self.assertEqual(tokens("see yuzu_server_leader_* for all"), {})

    def test_alert_with_no_series_fails(self):
        out = self.run_check(self.files(**{
            "docs/prometheus/yuzu-alerts.yml":
                self.ALERTS.replace("yuzu_server_leader_is_leader > 1", "vector(1) > 1")}))
        self.assertTrue(any("references no" in m for m in out), out)

    def test_real_tree_reader_rejects_a_missing_group(self):
        with tempfile.TemporaryDirectory() as d:
            for rel, text in self.files(**{"docs/prometheus/yuzu-alerts.yml": "groups: []\n"}).items():
                p = Path(d) / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8")
            out = problems(_reader(d))
        self.assertTrue(any("group `yuzu-ha-leader` not found" in m for m in out), out)


def main(argv):
    args = list(argv[1:])
    rest = []
    while args:
        a = args.pop(0)
        if a == "--repo-root" and args:
            LeaderAlertMetricNames.root = Path(args.pop(0))
        else:
            rest.append(a)
    result = unittest.main(argv=[argv[0]] + rest, exit=False).result
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
