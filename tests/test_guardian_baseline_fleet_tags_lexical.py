#!/usr/bin/env python3
"""#5605 drift guard for the Guardian baseline-persistence fleet signal.

The agent writes three heartbeat tags (agents/core/src/guardian_baseline_heartbeat.hpp:
`yuzu.guardian_baseline_unpersisted`, `_rebaselined_at_boot`, `_persist_failures`). The server
derives `yuzu_fleet_guardian_baseline_*` gauges from them through ONE table
(server/core/src/guardian_baseline_fleet_tags.hpp, consumed by AgentHealthStore::recompute_metrics
and by the describe loop in server.cpp), and ONE alert (`YuzuGuardianBaselineUnpersisted`) reads
row 0's gauge. The unit test tests/unit/server/test_guardian_baseline_fleet_tags.cpp binds the
agent's REAL emitters to the table, but it cannot see the three things this file pins, none of
which any compiler or C++ test checks: the alert, metrics.md and the agent.cpp call site.

A coordinated rename of the agent tag and the table row keeps the C++ pin test green (both sides
moved together) while the documentation, the dashboards and the alert still name the old tag, so
this gate also binds the documented tag names. It enforces, by source text only (no build):

  1. The set of `yuzu.guardian_baseline_*` string literals in the agent's heartbeat header equals
     the set of tags in the server table (both directions), and the table parses completely (the
     tag-literal count inside `kGuardianBaselineMetrics` equals the rows recovered).
  2. Row 0 is `yuzu.guardian_baseline_unpersisted` and `kGuardianBaselineUnpersistedIndex` is 0
     (`_reporting` keys on it alone). Gauge names are `yuzu_fleet_guardian_baseline_`-prefixed and
     unique across the table and the two meta gauges, and the header is 7-bit ASCII (HELP text).
  3. server.cpp registers HELP by looping over the table (a hand-copied name list there would drift
     from what recompute_metrics publishes) and describes both meta gauges; agent_registry.cpp
     still clears, reads and PUBLISHES from the same table (the `.set(...)` publish expressions
     are required, not just the identifiers: a needle that survives in a comment or an unrelated
     line proves nothing).
  4. agent.cpp's heartbeat Group D2 still calls all three emitters (`//` and `/* */` comments and
     literal `#if 0` regions stripped first, so a call that is commented out or compiled out does
     not count). Deleting a call site is otherwise caught by no test: the emitters are pinned, the
     call is not. This pin is source text: it does not run in a packaged build with no tree.
  5. The alert `YuzuGuardianBaselineUnpersisted` exists in docs/prometheus/yuzu-alerts.yml, its
     `expr` names the SAME gauge as table row 0, it has a `runbook_url`, and NO alert expression
     reads the monitor-only gauges (a boot-scan count and a latching cumulative sum must never be
     alerted on).
  6. The promtool file still has at least MIN_PROMTOOL_CASES cases for the alert (an alert with no
     case is the #2553 "parses but cannot fire" trap; what each case catches is recorded in that
     file's comments, the gate only stops them being deleted).
  7. docs/user-manual/metrics.md has a TABLE ROW for every gauge and for every heartbeat tag (a
     bare mention in prose does not count).

Lexical only: it cannot see that recompute_metrics reads a row correctly (that is
tests/unit/server/test_agent_health_store.cpp, "REAL AgentHealthStore: guardian baseline ...").
Comments are stripped before matching so comment text cannot satisfy a check (`#if 0` is handled
only in its literal form; an `#elif` after it is treated as live, which errs towards keeping text).
The self-tests apply in-memory mutations and require problems() to report each one.

Usage: python3 tests/test_guardian_baseline_fleet_tags_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_HEARTBEAT_HPP = ROOT / "agents" / "core" / "src" / "guardian_baseline_heartbeat.hpp"
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
TAGS_HPP = ROOT / "server" / "core" / "src" / "guardian_baseline_fleet_tags.hpp"
AGENT_REGISTRY_CPP = ROOT / "server" / "core" / "src" / "agent_registry.cpp"
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"
METRICS_MD = ROOT / "docs" / "user-manual" / "metrics.md"
ALERTS_YML = ROOT / "docs" / "prometheus" / "yuzu-alerts.yml"
ALERTS_TEST = ROOT / "tests" / "prometheus" / "yuzu-alerts.test.yml"

ALERT = "YuzuGuardianBaselineUnpersisted"
# T20, T21, T22, T23, T24, T24b, T25, T26, T27a, T27b and the CH-1 characterisation pin. Lower it
# only by removing a case on purpose.
MIN_PROMTOOL_CASES = 11
PROMTOOL_CASE_PREFIX = "baseline unpersisted - "
EMITTERS = (
    "emit_guardian_baseline_unpersisted_heartbeat_tag",
    "emit_guardian_baseline_rebaselined_heartbeat_tag",
    "emit_guardian_baseline_persist_heartbeat_tags",
)
TAG_RE = r"yuzu\.guardian_baseline_[a-z0-9_]+"
GAUGE_RE = r"yuzu_fleet_guardian_baseline_[a-z0-9_]+"


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def strip_if0(src: str) -> str:
    """Blank every line of a literal `#if 0` region (nesting-aware; an `#else` of the outermost
    `#if 0` is live again). Line count is preserved."""
    out = []
    dead = 0
    for line in src.splitlines():
        directive = line.strip()
        if dead == 0:
            if re.match(r"#\s*if\s+0\b", directive):
                dead = 1
                out.append("")
            else:
                out.append(line)
            continue
        if re.match(r"#\s*if", directive):
            dead += 1
        elif re.match(r"#\s*endif", directive):
            dead -= 1
        elif dead == 1 and re.match(r"#\s*(else|elif)\b", directive):
            dead = 0
        out.append("")
    return "\n".join(out)


def strip_line_comments(src: str) -> str:
    """Remove `#if 0` regions, `/* */` blocks and `//` comments, leaving string, character and raw
    string literals intact (a `//` inside a string is code). Newlines are kept so a stripped block
    cannot join two statements. Despite its historic name this also strips block comments."""
    src = strip_if0(src)
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            while i < n and src[i] != "\n":
                i += 1
        elif two == "/*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(" " + "\n" * src.count("\n", i, j))
            i = j
        elif c == "R" and src[i + 1:i + 2] == '"' and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            m = re.match(r'R"([^()\\\s]{0,16})\(', src[i:])
            end = src.find(")" + m.group(1) + '"', i + m.end()) if m else -1
            j = n if end < 0 else end + len(m.group(1)) + 2
            out.append(src[i:j])
            i = j
        elif c == '"' or (c == "'" and not (i > 0 and src[i - 1].isalnum())):
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def strip_yaml_comments(src: str) -> str:
    return "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))


def agent_tags() -> set:
    return set(re.findall(r'"(' + TAG_RE + r')"', strip_line_comments(read(AGENT_HEARTBEAT_HPP))))


def table_block() -> str:
    m = re.search(r"kGuardianBaselineMetrics\[\]\s*=\s*\{(.*?)\n\};", strip_line_comments(read(TAGS_HPP)), re.S)
    return m.group(1) if m else ""


def table_rows() -> list:
    """(tag, gauge) for each kGuardianBaselineMetrics row, in table order."""
    return re.findall(r'\{\s*"(' + TAG_RE + r')"\s*,\s*"(' + GAUGE_RE + r')"\s*,', table_block())


def meta_gauges() -> list:
    return re.findall(
        r'kGuardianBaseline(?:ReportingGauge|TagRejectedGauge)\s*=\s*"(' + GAUGE_RE + r')"',
        strip_line_comments(read(TAGS_HPP)),
    )


def alert_blocks() -> dict:
    """alert name -> the alert's own text, comment lines dropped. A block runs from its
    `- alert:` line to the next non-comment line indented no deeper than that dash (a sibling
    rule, a group, or the end of the file), so trailing commented-out rules never leak in."""
    lines = read(ALERTS_YML).splitlines()
    out = {}
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)- alert:\s*(\w+)\s*$", lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(1))
        body = []
        j = i + 1
        while j < len(lines):
            ln = lines[j]
            if ln.strip() and not ln.lstrip().startswith("#") and len(ln) - len(ln.lstrip()) <= indent:
                break
            if not ln.lstrip().startswith("#"):
                body.append(ln)
            j += 1
        out[m.group(2)] = "\n" + "\n".join(body)
        i = j
    return out


def expr_of(block: str) -> str:
    """The alert's `expr` text (a block scalar or an inline scalar), comments stripped."""
    m = re.search(r"\n\s*expr:(.*?)(?=\n\s*(?:for|labels|annotations|keep_firing_for):)", block, re.S)
    return strip_yaml_comments(m.group(1)) if m else ""


def problems() -> list:
    out = []
    rows = table_rows()
    if not rows:
        return ["could not parse kGuardianBaselineMetrics from guardian_baseline_fleet_tags.hpp (stale pattern)"]

    # 1. the row regex recovered every row, and the agent/server tag sets are equal
    literals_in_table = re.findall(r'"' + TAG_RE + r'"', table_block())
    if len(literals_in_table) != len(rows):
        out.append(f"kGuardianBaselineMetrics holds {len(literals_in_table)} tag literals but only "
                   f"{len(rows)} rows parsed: a row was reformatted out of the gate's reach")
    table_tags = {r[0] for r in rows}
    emitted = agent_tags()
    if not emitted:
        out.append('no "yuzu.guardian_baseline_*" string literal found in guardian_baseline_heartbeat.hpp (stale pattern)')
    for t in sorted(emitted - table_tags):
        out.append(f"the agent header writes {t} but no server table row reads it (a write nobody reads)")
    for t in sorted(table_tags - emitted):
        out.append(f"the server table reads {t} but the agent header never writes it (dead gauge)")

    # 2. row 0, gauge names, encoding
    if rows[0][0] != "yuzu.guardian_baseline_unpersisted":
        out.append("row 0 of kGuardianBaselineMetrics must be yuzu.guardian_baseline_unpersisted "
                   "(_reporting and the alert key on it)")
    if not re.search(r"kGuardianBaselineUnpersistedIndex\s*=\s*0\s*;", strip_line_comments(read(TAGS_HPP))):
        out.append("kGuardianBaselineUnpersistedIndex must be 0")
    gauges = [r[1] for r in rows] + meta_gauges()
    if len(meta_gauges()) != 2:
        out.append(f"expected 2 meta gauges (reporting, tag_rejected), got {meta_gauges()}")
    dup = {g for g in gauges if gauges.count(g) > 1}
    if dup:
        out.append(f"duplicate gauge names: {sorted(dup)}")
    try:
        read(TAGS_HPP).encode("ascii")
    except UnicodeEncodeError as e:
        out.append(f"guardian_baseline_fleet_tags.hpp must be 7-bit ASCII (HELP text): {e}")

    # 3. HELP registration and the rollup go through the table
    srv = strip_line_comments(read(SERVER_CPP))
    if not re.search(r"for\s*\(\s*const\s+auto&\s+(\w+)\s*:\s*detail::kGuardianBaselineMetrics\s*\)\s*"
                     r"metrics_\.describe\(\s*\1\.gauge\s*,\s*\1\.help\s*,", srv):
        out.append("server.cpp must register HELP with `for (const auto& m : detail::kGuardianBaselineMetrics) "
                   "metrics_.describe(m.gauge, m.help, ...)` (a hand-listed name drifts from recompute_metrics)")
    for needle in ("kGuardianBaselineReportingGauge", "kGuardianBaselineReportingHelp",
                   "kGuardianBaselineTagRejectedGauge", "kGuardianBaselineTagRejectedHelp"):
        if needle not in srv:
            out.append(f"server.cpp no longer describes the meta gauges via {needle}")
    reg = strip_line_comments(read(AGENT_REGISTRY_CPP))
    reg_flat = re.sub(r"\s+", "", reg)
    for publish in ("metrics.gauge(kGuardianBaselineMetrics[i].gauge).set(gbp_sum[i])",
                    "metrics.gauge(kGuardianBaselineReportingGauge).set(",
                    "metrics.gauge(kGuardianBaselineTagRejectedGauge).set("):
        if publish.replace(" ", "") not in reg_flat:
            out.append(f"agent_registry.cpp must publish `{publish}...` (the identifier surviving "
                       f"somewhere else is not the gauge being published)")
    for needle in ("kGuardianBaselineMetrics", "kNGuardianBaselineMetrics", "kGuardianBaselineUnpersistedIndex",
                   "kGuardianBaselineReportingGauge", "kGuardianBaselineTagRejectedGauge",
                   "parse_guardian_baseline_count"):
        if needle not in reg:
            out.append(f"agent_registry.cpp no longer references {needle}")

    # 4. the agent.cpp call sites (Group D2)
    agent_src = strip_line_comments(read(AGENT_CPP))
    for e in EMITTERS:
        n = len(re.findall(re.escape(e) + r"\s*\(", agent_src))
        if n != 1:
            out.append(f"agent.cpp must call {e}(...) exactly once in the heartbeat block (found {n}): "
                       f"a deleted call site is caught by no other test")
    flat = re.sub(r"\s+", "", agent_src)
    if "emit_guardian_baseline_unpersisted_heartbeat_tag(tags,guardian_->baseline_unpersisted())" not in flat:
        out.append("agent.cpp must feed emit_guardian_baseline_unpersisted_heartbeat_tag from "
                   "guardian_->baseline_unpersisted() (never a defaulted value: nullopt means dormant)")
    if "emit_guardian_baseline_rebaselined_heartbeat_tag(tags,guardian_->baseline_rebaselined_at_boot())" not in flat:
        out.append("agent.cpp must feed emit_guardian_baseline_rebaselined_heartbeat_tag from "
                   "guardian_->baseline_rebaselined_at_boot()")

    # 5. the alert
    blocks = alert_blocks()
    block = blocks.get(ALERT)
    if block is None:
        out.append(f"alert {ALERT} not found in docs/prometheus/yuzu-alerts.yml")
    else:
        if rows[0][1] not in expr_of(block):
            out.append(f"{ALERT}'s expr must name {rows[0][1]} (table row 0's gauge); "
                       f"found expr {expr_of(block).strip()!r}")
        if "runbook_url" not in block:
            out.append(f"{ALERT} has no runbook_url")
    monitor_only = [r[1] for r in rows[1:]]
    for name, b in blocks.items():
        ex = expr_of(b)
        for g in monitor_only:
            if g in ex:
                out.append(f"alert {name} reads {g}: that gauge is monitor-only (a per-boot count or a "
                           f"latching cumulative sum) and must never back an alert")

    # 6. the behaviour cases
    cases = len(re.findall(r"(?m)^\s*name:\s*" + re.escape(PROMTOOL_CASE_PREFIX), read(ALERTS_TEST)))
    if cases < MIN_PROMTOOL_CASES:
        out.append(f"tests/prometheus/yuzu-alerts.test.yml has {cases} '{PROMTOOL_CASE_PREFIX}' cases, "
                   f"expected at least {MIN_PROMTOOL_CASES}: deleting cases leaves a rule that parses "
                   f"but is no longer behaviour-tested (#2553)")

    # 7. metrics.md table rows, for every gauge and every tag
    md = read(METRICS_MD)
    for name in gauges + sorted(table_tags | emitted):
        if not re.search(r"(?m)^\|\s*`" + re.escape(name) + r"[`{]", md):
            out.append(f"docs/user-manual/metrics.md has no table row for {name}")
    return out


class GuardianBaselineFleetTagsLexical(unittest.TestCase):
    def _problems_with(self, transforms):
        """problems() with each path in `transforms` read through its function."""
        global read
        real_read = read
        try:
            read = lambda p: transforms[p](real_read(p)) if p in transforms else real_read(p)  # noqa: E731
            return problems()
        finally:
            read = real_read

    def test_no_drift(self):
        found = problems()
        self.assertEqual(found, [], "\n" + "\n".join(f"  - {p}" for p in found))

    def test_self_check_detects_a_coordinated_agent_and_table_rename(self):
        # The C++ pin test stays green here (both sides moved together). Only the docs still name
        # the old tag, so this is the gap the lexical gate exists for.
        old, new = "yuzu.guardian_baseline_unpersisted", "yuzu.guardian_baseline_unwritten"
        self.assertIn(old, read(AGENT_HEARTBEAT_HPP), "stale pattern: tag not in the agent header")
        self.assertIn(old, read(TAGS_HPP), "stale pattern: tag not in the server table")
        found = self._problems_with({
            AGENT_HEARTBEAT_HPP: lambda s: s.replace(old, new),
            TAGS_HPP: lambda s: s.replace(old, new),
        })
        self.assertTrue(any("metrics.md has no table row for " + new in p for p in found), found)

    def test_self_check_detects_a_renamed_agent_tag_alone(self):
        found = self._problems_with({
            AGENT_HEARTBEAT_HPP: lambda s: s.replace('"yuzu.guardian_baseline_rebaselined_at_boot"',
                                                     '"yuzu.guardian_baseline_rebaselined_at_bootz"')})
        self.assertTrue(any("never writes it" in p for p in found), found)
        self.assertTrue(any("no server table row reads it" in p for p in found), found)

    def test_self_check_detects_a_new_agent_tag_with_no_row(self):
        found = self._problems_with({
            AGENT_HEARTBEAT_HPP: lambda s: s + '\ninline constexpr char kX[] = "yuzu.guardian_baseline_extra";\n'})
        self.assertTrue(any("yuzu.guardian_baseline_extra" in p for p in found), found)

    def test_self_check_detects_a_row_the_regex_cannot_parse(self):
        found = self._problems_with({
            TAGS_HPP: lambda s: s.replace('{"yuzu.guardian_baseline_persist_failures", "yuzu_fleet_guardian_baseline_persist_failures",',
                                          '{"yuzu.guardian_baseline_persist_failures", std::string("yuzu_fleet_guardian_baseline_persist_failures").c_str(),', 1)})
        self.assertTrue(any("reformatted out of the gate's reach" in p for p in found), found)

    def test_self_check_detects_a_reordered_row_zero(self):
        def swap(s):
            return (s.replace("kGuardianBaselineUnpersistedIndex = 0", "kGuardianBaselineUnpersistedIndex = 1"))
        found = self._problems_with({TAGS_HPP: swap})
        self.assertTrue(any("kGuardianBaselineUnpersistedIndex must be 0" in p for p in found), found)

    def test_self_check_detects_a_deleted_agent_emit_call(self):
        # Comment stripping must not let the call survive as text in a comment.
        found = self._problems_with({
            AGENT_CPP: lambda s: re.sub(r"emit_guardian_baseline_unpersisted_heartbeat_tag\(\s*tags,\s*guardian_->baseline_unpersisted\(\)\);",
                                        "// emit_guardian_baseline_unpersisted_heartbeat_tag(tags, guardian_->baseline_unpersisted());", s, count=1)})
        self.assertTrue(any("emit_guardian_baseline_unpersisted_heartbeat_tag(...) exactly once" in p for p in found), found)

    def test_self_check_detects_a_block_comment_wrapped_emit_call(self):
        # A /* */ wrapper must not let the call survive as text (only // was stripped before).
        found = self._problems_with({
            AGENT_CPP: lambda s: re.sub(r"(emit_guardian_baseline_unpersisted_heartbeat_tag\(\s*tags,\s*guardian_->baseline_unpersisted\(\)\);)",
                                        r"/* \1 */", s, count=1)})
        self.assertTrue(any("emit_guardian_baseline_unpersisted_heartbeat_tag(...) exactly once" in p for p in found), found)

    def test_self_check_detects_an_if_zero_compiled_out_emit_call(self):
        found = self._problems_with({
            AGENT_CPP: lambda s: re.sub(r"(emit_guardian_baseline_rebaselined_heartbeat_tag\(\s*tags,\s*guardian_->baseline_rebaselined_at_boot\(\)\);)",
                                        r"\n#if 0\n\1\n#endif\n", s, count=1)})
        self.assertTrue(any("emit_guardian_baseline_rebaselined_heartbeat_tag(...) exactly once" in p for p in found), found)

    def test_self_check_detects_a_deleted_publish_site(self):
        # The identifiers stay referenced (the read side), only the publish expression goes.
        found = self._problems_with({
            AGENT_REGISTRY_CPP: lambda s: s.replace(".set(gbp_sum[i])", ".set(0)", 1)})
        self.assertTrue(any("agent_registry.cpp must publish" in p for p in found), found)

    def test_self_check_detects_a_defaulted_unpersisted_feed(self):
        found = self._problems_with({
            AGENT_CPP: lambda s: s.replace("guardian_->baseline_unpersisted());",
                                           "guardian_->baseline_unpersisted().value_or(0));", 1)})
        self.assertTrue(any("never a defaulted value" in p for p in found), found)

    def test_self_check_detects_a_hand_listed_describe(self):
        found = self._problems_with({
            SERVER_CPP: lambda s: s.replace("for (const auto& m : detail::kGuardianBaselineMetrics)",
                                            "for (const auto& m : detail::kGuardianIoCeilingMetrics)", 1)})
        self.assertTrue(any("server.cpp must register HELP" in p for p in found), found)

    def test_self_check_detects_a_renamed_alert_gauge(self):
        found = self._problems_with({
            ALERTS_YML: lambda s: s.replace("max_over_time(yuzu_fleet_guardian_baseline_unpersisted[5m])",
                                            "max_over_time(yuzu_fleet_guardian_baseline_unwritten[5m])", 1)})
        self.assertTrue(any("must name yuzu_fleet_guardian_baseline_unpersisted" in p for p in found), found)

    def test_self_check_detects_a_missing_alert(self):
        found = self._problems_with({
            ALERTS_YML: lambda s: s.replace("- alert: " + ALERT, "- alert: " + ALERT + "Renamed", 1)})
        self.assertTrue(any("not found in docs/prometheus/yuzu-alerts.yml" in p for p in found), found)

    def test_self_check_detects_a_missing_runbook_url(self):
        def drop(s):
            i = s.index("- alert: " + ALERT)
            j = s.index("runbook_url:", i)
            return s[:j] + "runbook_link:" + s[j + len("runbook_url:"):]
        found = self._problems_with({ALERTS_YML: drop})
        self.assertTrue(any("has no runbook_url" in p for p in found), found)

    def test_self_check_detects_an_alert_on_a_monitor_only_gauge(self):
        found = self._problems_with({
            ALERTS_YML: lambda s: s.replace("max_over_time(yuzu_fleet_guardian_baseline_unpersisted[5m])",
                                            "max_over_time(yuzu_fleet_guardian_baseline_persist_failures[5m])", 1)})
        self.assertTrue(any("monitor-only" in p for p in found), found)

    def test_self_check_detects_deleted_promtool_cases(self):
        found = self._problems_with({
            ALERTS_TEST: lambda s: s.replace("name: " + PROMTOOL_CASE_PREFIX, "name: x - ")})
        self.assertTrue(any("behaviour-tested" in p for p in found), found)

    def test_self_check_detects_a_missing_metrics_row(self):
        found = self._problems_with({
            METRICS_MD: lambda s: s.replace("| `yuzu_fleet_guardian_baseline_reporting` |", "| `yuzu_fleet_guardian_baseline_reportingx` |", 1)})
        self.assertTrue(any("no table row for yuzu_fleet_guardian_baseline_reporting" in p for p in found), found)


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
