#!/usr/bin/env python3
"""#3663 drift guard for the agent command-dedup store's fleet telemetry.

The agent carries the dedup store's safety-net signals on the heartbeat as `yuzu.dedup_*` tags
(agents/core/src/agent.cpp). The server derives `yuzu_fleet_agents_dedup_*` gauges from them
(server/core/src/dedup_fleet_tags.hpp, consumed by AgentHealthStore::recompute_metrics). The
two sides share no header ON PURPOSE (server production code must not gain an upward dependency
on an agent private header), so nothing in the compiler binds them: rename a tag on the agent and
the gauge goes silently dead, add a tag on the agent and nobody ever reads it. The agent's tags
are written inline in the heartbeat block rather than by a callable emitter, so this pin is
source-text, not a linked test. It enforces:

  1. EVERY `yuzu.dedup_*` tag agent.cpp emits is consumed by a row of the server table (or
     `kDedupRowsTag`) or is listed, with a reason, in DELIBERATELY_UNCONSUMED, and every tag the
     server table reads is emitted by the agent. A new agent
     tag with no server row is a red test here, not a write nobody reads (the enterprise-architect
     ruling on #6912: a marker with no consumer is a write nobody reads).
  2. The presence row is `yuzu.dedup_degraded` and is FIRST in the table (`kDedupPresenceIndex`
     is 0 and recompute_metrics treats row 0 as the "this agent is measured" signal).
  3. Every gauge name is `yuzu_fleet_`-prefixed, unique across the table, the rows-max gauge and
     the two meta-gauges, and the header is 7-bit ASCII (HELP text is checked by
     scripts/ci/check-metrics-help-ascii.sh; the header is the source of those strings).
  4. server.cpp registers HELP for the whole family through the table (a hand-copied name list
     there would drift from what recompute_metrics publishes).
  5. Every gauge is documented in docs/user-manual/metrics.md, and the YuzuDedupStoreDegraded
     alert exists, fires on the degraded gauge, and has a behaviour case in
     tests/prometheus/yuzu-alerts.test.yml (an alert with no case is the #2553 "parses but cannot
     fire" trap).

Lexical only: it cannot see that recompute_metrics reads a row correctly (that is
tests/unit/server/test_agent_health_store.cpp, "REAL AgentHealthStore: dedup ..."). `//` comments
are stripped before matching so comment text mentioning a tag cannot satisfy a check.

Usage: python3 tests/test_dedup_fleet_tags_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
TAGS_HPP = ROOT / "server" / "core" / "src" / "dedup_fleet_tags.hpp"
AGENT_REGISTRY_CPP = ROOT / "server" / "core" / "src" / "agent_registry.cpp"
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"
METRICS_MD = ROOT / "docs" / "user-manual" / "metrics.md"
ALERTS_YML = ROOT / "docs" / "prometheus" / "yuzu-alerts.yml"
ALERTS_TEST = ROOT / "tests" / "prometheus" / "yuzu-alerts.test.yml"
TAG = "test_dedup_fleet_tags_lexical"

# Tags the agent emits that NO server row consumes, on purpose, each with the reason. An entry
# must still be emitted by the agent (a stale entry is a failure) and must NOT be consumed by the
# server table (once it is, delete the entry). This is the only way past check 1 below.
DELIBERATELY_UNCONSUMED = {
    # #3665 corrupt-store recovery. A per-process 0/1 that returns to 0 on the next agent restart
    # while the quarantined files stay on the endpoint, so a gauge derived from it alone loses the
    # signal. The consumer needs a restart-surviving marker designed WITH it (the enterprise-
    # architect ruling on #6912: a marker with no consumer is a write nobody reads, so the two
    # ship together). Tracked as the follow-up on #3663; the owner chose to leave it out of the
    # first change.
    "yuzu.dedup_quarantined": "per-process; needs a restart-surviving marker designed with its consumer",
}

ALERT = "YuzuDedupStoreDegraded"
DEGRADED_GAUGE = "yuzu_fleet_agents_dedup_store_degraded"


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def strip_line_comments(src: str) -> str:
    # A `//` inside a string literal on the same line is an accepted blind spot (no such line in
    # the pinned regions); stripping errs towards losing text, which makes a check go red, not green.
    return "\n".join(re.sub(r"//.*$", "", line) for line in src.splitlines())


def agent_emitted_tags() -> set:
    src = strip_line_comments(read(AGENT_CPP))
    return set(re.findall(r'tags\["(yuzu\.dedup_[a-z_]+)"\]\s*=', src))


def table_rows() -> list:
    """(tag, kind, gauge) for each kDedupAgentCountMetrics row, in table order."""
    src = strip_line_comments(read(TAGS_HPP))
    m = re.search(r"kDedupAgentCountMetrics\[\]\s*=\s*\{(.*?)\n\};", src, re.S)
    if not m:
        return []
    body = m.group(1)
    rows = re.findall(
        r'\{\s*"(yuzu\.dedup_[a-z_]+)"\s*,\s*DedupCountKind::(\w+)\s*,\s*"(yuzu_fleet_[a-z_]+)"',
        body,
    )
    return rows


def rows_tag() -> str:
    m = re.search(r'kDedupRowsTag\s*=\s*"(yuzu\.dedup_[a-z_]+)"', strip_line_comments(read(TAGS_HPP)))
    return m.group(1) if m else ""


def other_gauges() -> list:
    src = strip_line_comments(read(TAGS_HPP))
    return re.findall(
        r'k(?:DedupRowsMaxGauge|DedupReportingGauge|DedupTagRejectedGauge)\s*=\s*"(yuzu_fleet_[a-z_]+)"',
        src,
    )


def problems() -> list:
    out = []
    rows = table_rows()
    if not rows:
        return ["could not parse kDedupAgentCountMetrics from dedup_fleet_tags.hpp (stale pattern)"]
    consumed = {r[0] for r in rows} | ({rows_tag()} if rows_tag() else set())
    emitted = agent_emitted_tags()

    if not emitted:
        out.append("no `tags[\"yuzu.dedup_*\"] =` assignment found in agent.cpp (stale pattern)")
    for t in sorted(emitted - consumed - set(DELIBERATELY_UNCONSUMED)):
        out.append(f"agent.cpp emits {t} but no server row consumes it (add a row, or the tag is a "
                   f"write nobody reads)")
    for t in sorted(set(DELIBERATELY_UNCONSUMED) - emitted):
        out.append(f"DELIBERATELY_UNCONSUMED lists {t} but agent.cpp no longer emits it (stale entry)")
    for t in sorted(set(DELIBERATELY_UNCONSUMED) & consumed):
        out.append(f"{t} is now consumed by the server table: remove it from DELIBERATELY_UNCONSUMED")
    for t in sorted(consumed - emitted):
        out.append(f"the server table reads {t} but agent.cpp never emits it (dead gauge)")

    if rows[0][0] != "yuzu.dedup_degraded":
        out.append("row 0 of kDedupAgentCountMetrics must be yuzu.dedup_degraded (the presence row)")
    if not re.search(r"kDedupPresenceIndex\s*=\s*0\s*;", read(TAGS_HPP)):
        out.append("kDedupPresenceIndex must be 0")
    if rows[0][1] != "kFlag":
        out.append("the presence row must be kFlag (a real 0/1 reading)")
    for tag, kind, _ in rows[1:]:
        if kind != "kPositiveCounter":
            out.append(f"{tag}: only the presence row is a flag; others are kPositiveCounter")

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

    md = read(METRICS_MD)
    for g in gauges:
        if g not in md:
            out.append(f"docs/user-manual/metrics.md does not document {g}")

    alerts = read(ALERTS_YML)
    m = re.search(r"- alert:\s*" + ALERT + r"\b(.*?)(?=\n\s*- alert:|\n\s*- name:|\Z)", alerts, re.S)
    if not m:
        out.append(f"alert {ALERT} not found in docs/prometheus/yuzu-alerts.yml")
    else:
        if DEGRADED_GAUGE not in m.group(1):
            out.append(f"{ALERT} must evaluate {DEGRADED_GAUGE}")
        if "runbook_url" not in m.group(1):
            out.append(f"{ALERT} has no runbook_url")
    if ALERT not in read(ALERTS_TEST):
        out.append(f"no behaviour case for {ALERT} in tests/prometheus/yuzu-alerts.test.yml")
    return out


class DedupFleetTagsLexical(unittest.TestCase):
    def test_no_drift(self):
        found = problems()
        self.assertEqual(found, [], "\n" + "\n".join(f"  - {p}" for p in found))

    def test_self_check_detects_a_renamed_agent_tag(self):
        # Mutation self-test: a tag renamed on the agent only must be reported on BOTH sides,
        # otherwise this gate is vacuous. Applied in memory; the working tree is never touched.
        global read
        orig = read(AGENT_CPP)
        self.assertIn('tags["yuzu.dedup_replays"]', orig, "stale pattern: replays tag not in agent.cpp")
        mutated = orig.replace('tags["yuzu.dedup_replays"]', 'tags["yuzu.dedup_replayz"]')
        real_read = read
        try:
            read = lambda p: mutated if p == AGENT_CPP else real_read(p)  # noqa: E731
            found = problems()
        finally:
            read = real_read
        self.assertTrue(any("yuzu.dedup_replayz" in p for p in found), found)
        self.assertTrue(any("yuzu.dedup_replays but agent.cpp never emits" in p for p in found), found)


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
