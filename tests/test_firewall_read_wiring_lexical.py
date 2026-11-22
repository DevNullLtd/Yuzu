#!/usr/bin/env python3
"""Static lexical gate over the firewall plugin's `state` and `rules` read wiring.

Each OS reads its firewall through a block that only that OS compiles, so no single build or unit
suite can see a dropped call, a swapped argument or a default where a failure belongs. The decisions
live in pure functions the unit suites test (firewall_parsers.hpp); what this gate pins is the thin
wiring around them, per OS class below:

  MacosReadWiring    do_state_macos and do_rules_macos run every pf read as
                     run_bounded_subprocess(yuzu::shared::sudo_wrap(fq::pfctl_*_argv()), ...) with
                     stderr unmerged: no `/sbin/pfctl` literal (a bare pfctl exits 1 for the
                     least-privilege account), no sudo_runner( and no merge_stderr (pfctl's
                     "No ALTQ support in kernel" banner would land in the rule rows and the count).

Matching runs on tests/cpp_lex_helper.live_text(): comments, backslash-continued comments and
`#if 0` blocks are removed first (string contents kept), so a pin cannot be satisfied by commented-out
or disabled text. Lexical only: it cannot see a relocation that keeps the tokens but changes control
flow (review-enforced). Each class carries an in-memory mutation self-test; a mutation whose pattern
no longer matches fails loudly (stale pattern) rather than passing vacuously.

Usage: python3 -I tests/test_firewall_read_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import cpp_lex_helper as lexh  # noqa: E402

PLUGIN_CPP = ROOT / "agents" / "plugins" / "firewall" / "src" / "firewall_plugin.cpp"
TAG = "test_firewall_read_wiring_lexical"
HINT = (
    " (this gate pins the OS-specific read wiring of the firewall plugin; if firewall_plugin.cpp was"
    " legitimately restructured, update tests/test_firewall_read_wiring_lexical.py)"
)


def squash(text):
    return re.sub(r"\s+", " ", text)


def function_body(live, signature):
    """The text between the braces of the function whose header matches `signature` (a regex that
    ends just before the opening brace), string-aware so a brace inside a literal cannot unbalance
    it. None when the function is not there."""
    m = re.search(signature, live)
    if not m:
        return None
    i = live.find("{", m.end() - 1)
    if i < 0:
        return None
    depth, j = 0, i
    while j < len(live):
        c = live[j]
        if c in "\"'":
            q = c
            j += 1
            while j < len(live) and live[j] != q:
                j += 2 if live[j] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return live[i + 1:j]
        j += 1
    return None


# ── macOS ───────────────────────────────────────────────────────────────────────────────────────

_PF_READ = (r"run_bounded_subprocess\( ?yuzu::shared::sudo_wrap\(fq::%s\(\)\), "
            r"SubprocessOptions\{\.deadline = kAcqDeadline\}\)")
# The pf reads each macOS action must make, in order. Anything else it spawns is socketfilterfw.
MACOS_READS = {
    "do_state_macos": ("pfctl_info_argv", "pfctl_anchors_argv", "pfctl_rules_argv"),
    "do_rules_macos": ("pfctl_rules_argv", "pfctl_anchors_argv"),
}


def macos_problems(plugin_src):
    out = []
    live = lexh.live_text(plugin_src)
    for fn, argvs in MACOS_READS.items():
        body = function_body(live, r"void " + fn + r"\(yuzu::CommandContext& ctx\) ?(?=\{)")
        if body is None:
            out.append(f"firewall_plugin.cpp no longer defines void {fn}(yuzu::CommandContext&)")
            continue
        text = squash(body)
        pos = -1
        for builder in argvs:
            m = re.search(_PF_READ % builder, text)
            if not m:
                out.append(f"{fn} no longer runs run_bounded_subprocess(sudo_wrap(fq::{builder}()), "
                           "SubprocessOptions{.deadline = kAcqDeadline}) (a pf read without the "
                           "granted sudo, or without its deadline, is refused for a non-root agent)")
            elif m.start() < pos:
                out.append(f"{fn} reads fq::{builder}() out of order (the row builders take the "
                           "results positionally)")
            else:
                pos = m.start()
        if "/sbin/pfctl" in text:
            out.append(f"{fn} names a /sbin/pfctl literal (a bare pfctl exits 1 for the agent account; "
                       "the read argv comes from fq::pfctl_*_argv() through sudo_wrap)")
        if "sudo_runner(" in text or "merge_stderr" in text:
            out.append(f"{fn} merges stderr (sudo_runner or merge_stderr): pfctl's `No ALTQ support in "
                       "kernel` banner would land in the rule rows and the count")
        spawned = len(re.findall(r"run_bounded_subprocess\(", text))
        if spawned != len(argvs) + 1:
            out.append(f"{fn} spawns {spawned} processes, expected {len(argvs) + 1} (socketfilterfw and "
                       f"{len(argvs)} pf reads)")
    return out


def _mut(pattern, repl):
    return lambda raw: re.subn(pattern, repl, raw, count=1, flags=re.S)


MACOS_MUTATIONS = [
    # (mutator over the raw source, substring expected in a problem message)
    (_mut(r"sudo_wrap\(fq::pfctl_info_argv\(\)\)", '{"/sbin/pfctl", "-s", "info"}'), "do_state_macos"),
    (_mut(r"yuzu::shared::sudo_wrap\(fq::pfctl_anchors_argv\(\)\)", "fq::pfctl_anchors_argv()"),
     "no longer runs run_bounded_subprocess(sudo_wrap(fq::pfctl_anchors_argv())"),
    (_mut(r"yuzu::shared::sudo_wrap\(fq::pfctl_rules_argv\(\)\)", "fq::pfctl_rules_argv()"),
     "no longer runs run_bounded_subprocess(sudo_wrap(fq::pfctl_rules_argv())"),
    (_mut(r"(void do_rules_macos.*?)yuzu::shared::sudo_wrap\(fq::pfctl_anchors_argv\(\)\)",
          r"\1yuzu::shared::sudo_wrap(fq::pfctl_siblings_argv())"), "do_rules_macos"),
    (_mut(r"(void do_state_macos.*?SubprocessOptions\{\.deadline = kAcqDeadline\}\);.*?)"
          r"(const auto pf_res = run_bounded_subprocess\(yuzu::shared::sudo_wrap\(fq::pfctl_info_argv\(\)\),"
          r"\s*SubprocessOptions\{\.deadline = kAcqDeadline\}\);)",
          r"\1/* \2 */ const auto pf_res = run_bounded_subprocess(yuzu::shared::sudo_wrap(fq::pfctl_rules_argv()), "
          r"SubprocessOptions{.deadline = kAcqDeadline}); // swapped"), "do_state_macos"),
    (_mut(r"(void do_state_macos.*?)SubprocessOptions\{\.deadline = kAcqDeadline\}\);(\s*const auto anchors_res)",
          r"\1SubprocessOptions{.deadline = kAcqDeadline, .merge_stderr = true});\2"), "merges stderr"),
    (_mut(r"(void do_rules_macos.*?)const auto anchors_res = run_bounded_subprocess\(",
          r"\1const auto anchors_res = sudo_runner("), "do_rules_macos"),
    # the deadline dropped from one pf read (an unbounded wait on a hung sudo or pfctl)
    (_mut(r"(void do_state_macos.*?fq::pfctl_rules_argv\(\)\),\s*)SubprocessOptions\{\.deadline = kAcqDeadline\}",
          r"\1SubprocessOptions{}"), "no longer runs run_bounded_subprocess(sudo_wrap(fq::pfctl_rules_argv())"),
]


class MacosReadWiring(unittest.TestCase):
    def setUp(self):
        self.cpp = PLUGIN_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = macos_problems(self.cpp)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (mutate, expected) in enumerate(MACOS_MUTATIONS, 1):
            with self.subTest(mutation=i, expected=expected):
                mutated, n = mutate(self.cpp)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = macos_problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertTrue(any(expected in m for m in p), f"expected {expected!r} in {p}")

    def test_a_pf_read_in_a_comment_or_dead_block_does_not_count(self):
        hidden = self.cpp.replace(
            "const auto anchors_res = run_bounded_subprocess(yuzu::shared::sudo_wrap(fq::pfctl_anchors_argv()),",
            "const auto anchors_res = run_bounded_subprocess({}, "
            "/* yuzu::shared::sudo_wrap(fq::pfctl_anchors_argv()), */", 1)
        self.assertNotEqual(hidden, self.cpp)
        self.assertTrue(macos_problems(hidden))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
