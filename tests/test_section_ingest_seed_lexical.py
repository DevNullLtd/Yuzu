#!/usr/bin/env python3
"""Static lexical gate over server/core/src/server.cpp: the server's metrics setup must call
`seed_section_ingest_series(metrics_)` exactly once.

Why: yuzu_inventory_section_ingest_total is read through increase() by
YuzuInventorySectionIngestRefused. A series that first appears already at 1 contributes no
increase, so without the boot-time pre-seed the first refused section per facet would never
alert (docs/observability-conventions.md). The unit test proves the function seeds the closed
set; only this gate proves the server calls it.

Comment-only lines (`//` or inside a block comment) are skipped, so a commented-out call
does not count. Lexical only: it cannot see a call moved into dead code (review-enforced). Usage: python3 tests/test_section_ingest_seed_lexical.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"
CALL = re.compile(r"\bseed_section_ingest_series\s*\(\s*metrics_\s*\)\s*;")


def call_count(src):
    """Calls on lines that are not comment lines (// or inside a /* ... */ block)."""
    n, in_block = 0, False
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
        n += len(CALL.findall(text.split("//")[0]))
    return n


class SectionIngestSeedWiring(unittest.TestCase):
    def test_server_seeds_the_series_once(self):
        self.assertEqual(call_count(SERVER_CPP.read_text(encoding="utf-8")), 1)

    def test_gate_sees_a_removed_or_commented_call(self):
        self.assertEqual(call_count("/*\n seed_section_ingest_series(metrics_);\n*/"), 0)
        self.assertEqual(call_count("void f() {\n// seed_section_ingest_series(metrics_);\n}"), 0)
        self.assertEqual(call_count("void f() { seed_section_ingest_series(metrics_); }"), 1)


if __name__ == "__main__":
    unittest.main()
