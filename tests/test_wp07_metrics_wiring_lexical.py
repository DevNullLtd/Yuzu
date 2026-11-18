#!/usr/bin/env python3
"""WP07 lexical gate for two wiring statements no unit test can reach.

  1. agents/core/src/agent.cpp: when a command's output was dropped, the agent increments the
     agent-local counter `yuzu_agent_plugin_output_dropped_total{plugin}` and the process-wide
     `g_output_dropped_commands` that feeds the `yuzu.output_dropped` heartbeat tag.
  2. server/core/src/server.cpp: the boot probe calls pg::report_server_encoding(...), which sets
     the `yuzu_pg_server_encoding_not_utf8` gauge (the helper itself is unit-tested).

Comments are stripped before matching, and each pin is one anchored pattern. This is lexical: it
cannot model an `#if 0` block, a backslash-continued // comment, or a call inside a string literal.
Run: python3 tests/test_wp07_metrics_wiring_lexical.py
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

_TOKEN = re.compile(
    r'"(?:\\.|[^"\\\n])*"'
    r"|'(?:\\.|[^'\\\n])'"
    r"|//[^\n]*"
    r"|/\*.*?\*/",
    re.S,
)


def strip_comments(text: str) -> str:
    return _TOKEN.sub(lambda m: m.group(0) if m.group(0)[0] in "\"'" else " ", text)


PINS = [
    ("agent.cpp",
     "agents/core/src/agent.cpp",
     r'metrics_\.counter\("yuzu_agent_plugin_output_dropped_total", \{\{"plugin", cmd\.plugin\(\)\}\}\)'
     r"\s*\.increment\(\);\s*g_output_dropped_commands\.fetch_add\(1,"),
    ("server.cpp report_server_encoding",
     "server/core/src/server.cpp",
     r"const bool utf8 = pg::report_server_encoding\(probe\.get\(\), metrics_, &enc\);"),
]


def main() -> int:
    bad = []
    for name, rel, rx in PINS:
        text = strip_comments((ROOT / rel).read_text(encoding="utf-8"))
        n = len(re.findall(rx, text))
        if n != 1:
            bad.append(f"{name} (matched {n}x, want exactly 1)")
    for b in bad:
        print(f"FAIL: WP07 wiring statement lost or changed: {b}")
    if not bad:
        print(f"ok: {len(PINS)} WP07 wiring statements present")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
