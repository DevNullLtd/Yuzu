#!/usr/bin/env python3
"""#3663 drift guard for the agent command-dedup store's fleet telemetry.

The agent carries the dedup store's safety-net signals on the heartbeat as `yuzu.dedup_*` tags
(agents/core/src/agent.cpp). The server derives `yuzu_fleet_agents_dedup_*` gauges from them
(server/core/src/dedup_fleet_tags.hpp, consumed by AgentHealthStore::recompute_metrics). The
two sides share no header ON PURPOSE (server production code must not gain an upward dependency
on an agent private header), so nothing in the compiler binds them: rename a tag on the agent and
the gauge goes silently dead, add a tag on the agent and nobody ever reads it. The agent's tags
are written inline in the heartbeat block rather than by a callable emitter (extracting one is
issue #5417's seam), so this pin is source-text, not a linked test. It enforces:

  1. EVERY `yuzu.dedup_*` string literal agent.cpp contains (comments stripped) is consumed by a
     row of the server table (or `kDedupRowsTag`) or is listed, with a reason AND an issue
     number, in DELIBERATELY_UNCONSUMED; and every tag the server table reads is emitted by the
     agent. Collecting every literal (not one assignment shape) means `tags.emplace(...)`, a
     respaced `tags[ "k" ]` or a digit in a key cannot hide a tag from the check. A new agent tag
     with no server row is a red test here, not a write nobody reads (the enterprise-architect
     ruling on #6912).
  2. The table parses completely: the number of `"yuzu.dedup_*"` literals inside
     `kDedupAgentCountMetrics` equals the number of rows the row regex recovered, so a row
     reformatted out of the regex's reach is a red test, not a silently dropped gauge.
  3. The presence row is `yuzu.dedup_degraded`, is FIRST, and is the only flag
     (`kDedupPresenceIndex` is 0; recompute_metrics treats row 0 as "this agent is measured").
  4. Every gauge name is `yuzu_fleet_`-prefixed and unique across the table, the rows-max gauge
     and the two meta-gauges; the header is 7-bit ASCII (the HELP strings live in it).
  5. The capacity HELP's "20000" is the agent's `kMaxDedupRows` (parsed from the agent header, not
     restated here), so a change to the ring bound without the HELP is a red test.
  6. The agent emits `yuzu.dedup_rows` exactly once, only from the store's `cached_row_count()`
     and never via `value_or(...)`: an unknown count must stay ABSENT, because the server reads a
     present "0" as an empty store.
  7. server.cpp registers HELP for the whole family through the table (a hand-copied name list
     there would drift from what recompute_metrics publishes).
  8. Every gauge has a TABLE ROW in docs/user-manual/metrics.md (a bare mention in prose does
     not count), and the YuzuDedupStoreDegraded alert exists, evaluates the degraded gauge, has a
     runbook_url, and still has all its behaviour cases in tests/prometheus/yuzu-alerts.test.yml
     (an alert with no case is the #2553 "parses but cannot fire" trap; what each case catches is
     recorded in that file's comments, the gate only stops them being deleted).

Lexical only: it cannot see that recompute_metrics reads a row correctly (that is
tests/unit/server/test_agent_health_store.cpp, "REAL AgentHealthStore: dedup ...", and
tests/unit/server/test_dedup_fleet_tags.cpp for the parse itself). `//` comments are stripped
before matching so comment text mentioning a tag cannot satisfy a check. The self-test applies
in-memory mutations and requires problems() to report each one.

Usage: python3 tests/test_dedup_fleet_tags_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
STORE_HPP = ROOT / "agents" / "core" / "include" / "yuzu" / "agent" / "command_dedup_store.hpp"
# #3678: the ring size is single-sourced here; the store's kMaxDedupRows is bound to it.
HORIZON_HPP = ROOT / "common" / "include" / "yuzu" / "command_replay_horizon.hpp"
TAGS_HPP = ROOT / "server" / "core" / "src" / "dedup_fleet_tags.hpp"
AGENT_REGISTRY_CPP = ROOT / "server" / "core" / "src" / "agent_registry.cpp"
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"
METRICS_MD = ROOT / "docs" / "user-manual" / "metrics.md"
ALERTS_YML = ROOT / "docs" / "prometheus" / "yuzu-alerts.yml"
ALERTS_TEST = ROOT / "tests" / "prometheus" / "yuzu-alerts.test.yml"

ALERT = "YuzuDedupStoreDegraded"
MIN_PROMTOOL_CASES = 11  # A, B, C, C-1, D, E, F, G, H, I, J; lower it only by removing a case on purpose
DEGRADED_GAUGE = "yuzu_fleet_agents_dedup_store_degraded"

# Tags the agent emits that NO server row consumes, on purpose. Each value MUST carry the issue
# that tracks consuming it (`#<digits>`): an exemption with no tracker is how a tag ships unread.
# An entry must still be emitted by the agent (a stale entry is a failure) and must NOT be
# consumed by the server table (once it is, delete the entry). This is the only way past check 1.
DELIBERATELY_UNCONSUMED = {
    # #3665 corrupt-store recovery. A per-process 0/1 that returns to 0 on the next agent restart
    # while the quarantined files stay on the endpoint, so a gauge derived from it alone loses the
    # signal. The consumer needs a restart-surviving marker designed WITH it (the enterprise-
    # architect ruling on #6912: a marker with no consumer is a write nobody reads, so the two ship
    # together). The owner chose to leave it out of the first change (#3663).
    "yuzu.dedup_quarantined": "per-process; needs a restart-surviving marker designed with its "
                              "consumer, tracked in #6933",
}


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def strip_line_comments(src: str) -> str:
    # A `//` inside a string literal on the same line is an accepted blind spot (no such line in
    # the pinned regions); stripping errs towards losing text, which makes a check go red, not green.
    return "\n".join(re.sub(r"//.*$", "", line) for line in src.splitlines())


def agent_emitted_tags() -> set:
    """Every "yuzu.dedup_*" string literal in agent.cpp, comments stripped."""
    return set(re.findall(r'"(yuzu\.dedup_[a-z0-9_]+)"', strip_line_comments(read(AGENT_CPP))))


def table_block() -> str:
    m = re.search(r"kDedupAgentCountMetrics\[\]\s*=\s*\{(.*?)\n\};", strip_line_comments(read(TAGS_HPP)), re.S)
    return m.group(1) if m else ""


def table_rows() -> list:
    """(tag, kind, gauge) for each kDedupAgentCountMetrics row, in table order."""
    return re.findall(
        r'\{\s*"(yuzu\.dedup_[a-z0-9_]+)"\s*,\s*DedupCountKind::(\w+)\s*,\s*"(yuzu_fleet_[a-z0-9_]+)"',
        table_block(),
    )


def rows_tag() -> str:
    m = re.search(r'kDedupRowsTag\s*=\s*"(yuzu\.dedup_[a-z0-9_]+)"', strip_line_comments(read(TAGS_HPP)))
    return m.group(1) if m else ""


def other_gauges() -> list:
    return re.findall(
        r'k(?:DedupRowsMaxGauge|DedupReportingGauge|DedupTagRejectedGauge)\s*=\s*"(yuzu_fleet_[a-z0-9_]+)"',
        strip_line_comments(read(TAGS_HPP)),
    )


def kmax_dedup_rows() -> int:
    """The agent's ring bound: kAgentDedupRingRows (command_replay_horizon.hpp), which
    command_dedup_store.hpp must bind kMaxDedupRows to (checked in problems(), check 5)."""
    m = re.search(r"kAgentDedupRingRows\s*=\s*(\d+)\s*;", strip_line_comments(read(HORIZON_HPP)))
    return int(m.group(1)) if m else -1


def store_binds_to_shared_ring_constant() -> bool:
    return bool(re.search(r"kMaxDedupRows\s*=\s*(?:::)?(?:yuzu::)?kAgentDedupRingRows\s*;",
                          strip_line_comments(read(STORE_HPP))))


def problems() -> list:
    out = []
    rows = table_rows()
    if not rows:
        return ["could not parse kDedupAgentCountMetrics from dedup_fleet_tags.hpp (stale pattern)"]

    # 2. the row regex recovered every row
    literals_in_table = re.findall(r'"yuzu\.dedup_[a-z0-9_]+"', table_block())
    if len(literals_in_table) != len(rows):
        out.append(f"kDedupAgentCountMetrics holds {len(literals_in_table)} tag literals but only "
                   f"{len(rows)} rows parsed: a row was reformatted out of the gate's reach")

    consumed = {r[0] for r in rows} | ({rows_tag()} if rows_tag() else set())
    emitted = agent_emitted_tags()

    # 1. parity, both directions, with a tracked exemption list
    if not emitted:
        out.append('no "yuzu.dedup_*" string literal found in agent.cpp (stale pattern)')
    for t in sorted(emitted - consumed - set(DELIBERATELY_UNCONSUMED)):
        out.append(f"agent.cpp emits {t} but no server row consumes it (add a row, or the tag is a "
                   f"write nobody reads)")
    for t in sorted(consumed - emitted):
        out.append(f"the server table reads {t} but agent.cpp never emits it (dead gauge)")
    for t, why in DELIBERATELY_UNCONSUMED.items():
        if t not in emitted:
            out.append(f"DELIBERATELY_UNCONSUMED lists {t} but agent.cpp no longer emits it (stale entry)")
        if t in consumed:
            out.append(f"{t} is now consumed by the server table: remove it from DELIBERATELY_UNCONSUMED")
        if not re.search(r"#[1-9]\d*", why):
            out.append(f"DELIBERATELY_UNCONSUMED[{t}] names no issue number (#<digits>, not #0): an "
                       f"exemption with no tracker is how a tag ships unread")

    # 3. presence row
    if rows[0][0] != "yuzu.dedup_degraded":
        out.append("row 0 of kDedupAgentCountMetrics must be yuzu.dedup_degraded (the presence row)")
    if not re.search(r"kDedupPresenceIndex\s*=\s*0\s*;", read(TAGS_HPP)):
        out.append("kDedupPresenceIndex must be 0")
    if rows[0][1] != "kFlag":
        out.append("the presence row must be kFlag (a real 0/1 reading)")
    for tag, kind, _ in rows[1:]:
        if kind != "kPositiveCounter":
            out.append(f"{tag}: only the presence row is a flag; others are kPositiveCounter")

    # 4. gauge names and encoding
    gauges = [r[2] for r in rows] + other_gauges()
    if len(other_gauges()) != 3:
        out.append(f"expected 3 non-table gauges (rows_max, reporting, tag_rejected), got {other_gauges()}")
    dup = {g for g in gauges if gauges.count(g) > 1}
    if dup:
        out.append(f"duplicate gauge names: {sorted(dup)}")
    try:
        read(TAGS_HPP).encode("ascii")
    except UnicodeEncodeError as e:
        out.append(f"dedup_fleet_tags.hpp must be 7-bit ASCII (HELP text): {e}")

    # 5. the capacity HELP's ring bound is the agent's constant
    kmax = kmax_dedup_rows()
    if kmax < 0:
        out.append("could not parse kAgentDedupRingRows from command_replay_horizon.hpp (stale pattern)")
    elif not store_binds_to_shared_ring_constant():
        out.append("command_dedup_store.hpp kMaxDedupRows is not bound to yuzu::kAgentDedupRingRows "
                   "(#3678): the ring size must be single-sourced in command_replay_horizon.hpp")
    else:
        m = re.search(r'kDedupRowsMaxHelp\s*=(.*?)";', strip_line_comments(read(TAGS_HPP)), re.S)
        help_text = "".join(re.findall(r'"([^"]*)"', m.group(1) + '"')) if m else ""
        if not re.search(r"(?<!\d)" + str(kmax) + r"(?!\d)", help_text):
            out.append(f"kDedupRowsMaxHelp does not state the agent's kMaxDedupRows ({kmax}): the ring "
                       f"bound changed without the HELP")
        near = re.search(r"near (\d+)", help_text)
        if not near or abs(int(near.group(1)) - kmax) > 1000:
            out.append("kDedupRowsMaxHelp 'near N' is not within 1000 of kMaxDedupRows")

    # 6. the rows tag is emitted only from cached_row_count(), never defaulted
    agent_src = strip_line_comments(read(AGENT_CPP))
    if not re.search(r'if\s*\(\s*const\s+auto\s+rows\s*=\s*command_dedup_->cached_row_count\(\)\s*\)\s*'
                     r'tags\["yuzu\.dedup_rows"\]\s*=', re.sub(r"\s+", " ", agent_src)):
        out.append('agent.cpp must emit yuzu.dedup_rows only inside `if (const auto rows = '
                   'command_dedup_->cached_row_count())` (an unknown count stays ABSENT)')
    if agent_src.count('"yuzu.dedup_rows"') != 1:
        out.append('agent.cpp must contain exactly one "yuzu.dedup_rows" emission (found '
                   f'{agent_src.count(chr(34) + "yuzu.dedup_rows" + chr(34))}): a second one is how a '
                   'defaulted 0 reaches the wire')
    if "value_or" in "".join(re.findall(r'[^;{}]*cached_row_count\(\)[^;{}]*', agent_src)):
        out.append("agent.cpp must not default cached_row_count() with value_or: the server reads a "
                   "present 0 as an empty store")

    # 7. HELP registration via the table
    reg = strip_line_comments(read(AGENT_REGISTRY_CPP))
    for needle in ("kDedupAgentCountMetrics", "kDedupRowsTag", "kDedupReportingGauge",
                   "kDedupTagRejectedGauge", "kDedupRowsMaxGauge", "classify_dedup_value"):
        if needle not in reg:
            out.append(f"agent_registry.cpp no longer references {needle}")
    srv = strip_line_comments(read(SERVER_CPP))
    for needle in ("kDedupAgentCountMetrics", "kDedupReportingGauge", "kDedupTagRejectedGauge",
                   "kDedupRowsMaxGauge"):
        if needle not in srv:
            out.append(f"server.cpp no longer registers HELP via {needle}")

    # 8. docs, alert, behaviour case
    md = read(METRICS_MD)
    for g in gauges:
        if not re.search(r"(?m)^\|\s*`" + re.escape(g) + r"[`{]", md):
            out.append(f"docs/user-manual/metrics.md has no table row for {g}")
    alerts = read(ALERTS_YML)
    m = re.search(r"- alert:\s*" + ALERT + r"\b(.*?)(?=\n\s*- alert:|\n\s*- name:|\Z)", alerts, re.S)
    if not m:
        out.append(f"alert {ALERT} not found in docs/prometheus/yuzu-alerts.yml")
    else:
        if DEGRADED_GAUGE not in m.group(1):
            out.append(f"{ALERT} must evaluate {DEGRADED_GAUGE}")
        if "runbook_url" not in m.group(1):
            out.append(f"{ALERT} has no runbook_url")
    cases = len(re.findall(r"(?m)^\s*name:\s*dedup store degraded - ", read(ALERTS_TEST)))
    if cases < MIN_PROMTOOL_CASES:
        out.append(f"tests/prometheus/yuzu-alerts.test.yml has {cases} 'dedup store degraded' cases, "
                   f"expected at least {MIN_PROMTOOL_CASES}: deleting cases leaves a rule that parses "
                   f"but is no longer behaviour-tested (#2553)")
    return out


class DedupFleetTagsLexical(unittest.TestCase):
    def _problems_with(self, path, transform):
        """problems() with `path` read through `transform`, restoring the real reader after."""
        global read
        real_read = read
        try:
            read = lambda p: transform(real_read(p)) if p == path else real_read(p)  # noqa: E731
            return problems()
        finally:
            read = real_read

    def test_no_drift(self):
        found = problems()
        self.assertEqual(found, [], "\n" + "\n".join(f"  - {p}" for p in found))

    def test_self_check_detects_a_renamed_agent_tag(self):
        orig = read(AGENT_CPP)
        self.assertIn('"yuzu.dedup_replays"', orig, "stale pattern: replays tag not in agent.cpp")
        found = self._problems_with(AGENT_CPP, lambda s: s.replace('"yuzu.dedup_replays"', '"yuzu.dedup_replayz"'))
        self.assertTrue(any("yuzu.dedup_replayz" in p for p in found), found)
        self.assertTrue(any("yuzu.dedup_replays but agent.cpp never emits" in p for p in found), found)

    def test_self_check_detects_an_unlisted_emplace_tag(self):
        # The old assignment-shaped regex would have missed this form entirely.
        found = self._problems_with(
            AGENT_CPP, lambda s: s.replace('tags["yuzu.dedup_degraded"]',
                                           'tags.emplace("yuzu.dedup_new2", "1"); tags["yuzu.dedup_degraded"]', 1))
        self.assertTrue(any("yuzu.dedup_new2" in p for p in found), found)

    def test_self_check_detects_a_row_the_regex_cannot_parse(self):
        # The row regex tolerates any whitespace, so respacing is not a blind spot; a kind spelled
        # as a cast instead of an enumerator is one, and must be reported by the literal count.
        found = self._problems_with(
            TAGS_HPP, lambda s: s.replace('{"yuzu.dedup_replays", DedupCountKind::kPositiveCounter,',
                                          '{"yuzu.dedup_replays", static_cast<DedupCountKind>(1),', 1))
        self.assertTrue(any("reformatted out of the gate's reach" in p for p in found), found)

    def test_self_check_detects_a_defaulted_rows_tag(self):
        found = self._problems_with(
            AGENT_CPP, lambda s: s.replace("cached_row_count())", "cached_row_count().value_or(0))", 1))
        self.assertTrue(found, "value_or on the rows count must be reported")

    def test_self_check_detects_a_second_rows_emission(self):
        found = self._problems_with(
            AGENT_CPP, lambda s: s.replace('tags["yuzu.dedup_rows"] =', 'tags["yuzu.dedup_rows"] = "0"; tags["yuzu.dedup_rows"] =', 1))
        self.assertTrue(any("exactly one" in p for p in found), found)

    def test_self_check_detects_deleted_promtool_cases(self):
        found = self._problems_with(ALERTS_TEST, lambda s: s.replace("name: dedup store degraded - ", "name: x - "))
        self.assertTrue(any("behaviour-tested" in p for p in found), found)

    def test_self_check_detects_a_zero_issue_number(self):
        global DELIBERATELY_UNCONSUMED
        real = dict(DELIBERATELY_UNCONSUMED)
        try:
            DELIBERATELY_UNCONSUMED = {k: "tracked in #0" for k in real}
            found = problems()
        finally:
            DELIBERATELY_UNCONSUMED = real
        self.assertTrue(any("names no issue number" in p for p in found), found)

    def test_self_check_detects_a_stale_ring_bound_in_the_help(self):
        found = self._problems_with(HORIZON_HPP, lambda s: re.sub(r"(kAgentDedupRingRows\s*=\s*)20000", r"\g<1>30000", s))
        self.assertTrue(any("kMaxDedupRows" in p for p in found), found)

    def test_self_check_detects_a_store_ring_bound_that_forks_the_shared_constant(self):
        found = self._problems_with(
            STORE_HPP, lambda s: re.sub(r"(kMaxDedupRows\s*=\s*)::yuzu::kAgentDedupRingRows", r"\g<1>20000", s))
        self.assertTrue(any("not bound to yuzu::kAgentDedupRingRows" in p for p in found), found)


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
