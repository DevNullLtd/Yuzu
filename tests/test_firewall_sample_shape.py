#!/usr/bin/env python3
"""Shape gate for the firewall plugin's three committed captures (meson `docs` suite).

Pins #4398: every captured `state` and `rules` block in
agents/plugins/firewall/docs/samples/<os>.txt reports one `ruleset|` row, so a
read that failed cannot pass as a capture of an empty ruleset. Hermetic: parses
the checked-in files with the plugin-doc-gen parser, builds and runs nothing.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools" / "plugin-doc-gen"))

import plugin_doc_gen as g  # noqa: E402

SAMPLES = REPO_ROOT / "agents" / "plugins" / "firewall" / "docs" / "samples"
ACTIONS = ["state", "rules", "quarantine", "release", "quarantine_status", "quarantine_allow"]
# The macOS capture is taken without root, where pf is unreadable and the plugin
# answers `ruleset|unknown` beside its `error|` rows; Linux and Windows are root
# or elevated captures, so their ruleset is a count and carries no error row.
PRIVILEGED = ("linux", "windows")


def ruleset_problems(os_name: str, text: str) -> list[str]:
    """Shape problems of one sample file; empty when it conforms."""
    sample = g.parse_sample(text, os_name)
    by_name = {a["action"]: a for a in sample.actions}
    problems = [f"{os_name}: no `== action={a}` block" for a in ACTIONS if a not in by_name]
    for name in ("state", "rules"):
        block = by_name.get(name)
        if block is None or block["not_captured"] is not None:
            continue
        rows = block["rows"]
        counts = [r.split("|", 1)[1] for r in rows if r.startswith("ruleset|")]
        if len(counts) != 1:
            problems.append(f"{os_name}: action {name} holds {len(counts)} ruleset rows, expected 1")
        elif os_name in PRIVILEGED and not counts[0].isdigit():
            problems.append(f"{os_name}: action {name} ruleset is {counts[0]!r}, expected a count")
        if os_name in PRIVILEGED and any(r.startswith("error|") for r in rows):
            problems.append(f"{os_name}: action {name} carries an error row in a privileged capture")
    return problems


class FirewallSampleShape(unittest.TestCase):
    def test_committed_samples_conform(self):
        for os_name in ("linux", "macos", "windows"):
            text = (SAMPLES / f"{os_name}.txt").read_text(encoding="utf-8")
            self.assertEqual(ruleset_problems(os_name, text), [], os_name)

    def test_missing_ruleset_row_is_caught(self):
        text = (SAMPLES / "linux.txt").read_text(encoding="utf-8")
        broken = text.replace("ruleset|1\n", "", 1)
        self.assertNotEqual(broken, text)
        self.assertIn("linux: action state holds 0 ruleset rows, expected 1", ruleset_problems("linux", broken))

    def test_error_row_in_privileged_capture_is_caught(self):
        text = (SAMPLES / "linux.txt").read_text(encoding="utf-8")
        broken = text.replace("backend|nftables\n", "backend|nftables\nerror|nft:list:exit:1\n", 1)
        self.assertIn("linux: action state carries an error row in a privileged capture",
                      ruleset_problems("linux", broken))


if __name__ == "__main__":
    unittest.main()
