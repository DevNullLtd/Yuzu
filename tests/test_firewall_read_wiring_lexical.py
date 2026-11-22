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

  WindowsRuleReadWiring
                     do_rules_windows reads each of a rule's five properties into an HRESULT of
                     its own and hands every one to the pure builder (win_rule_row takes a
                     WinRuleRead): no FAILED() decides a row field (S_FALSE passes it and reads as
                     a false-safe default), a rule the enumerator returned but whose object cannot
                     be obtained is written as an all-unknown row and counted (neither skip site
                     reaches `continue` without a row), and the trailer carries the property tally.

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


# ── Windows ─────────────────────────────────────────────────────────────────────────────────────

# getter -> (the WinRuleRead field its HRESULT must reach)
WIN_PROPERTIES = {
    "get_Name": "name_hr",
    "get_Enabled": "enabled_hr",
    "get_Direction": "dir_hr",
    "get_Action": "action_hr",
    "get_Profiles": "profiles_hr",
}


def windows_problems(plugin_src, parsers_src):
    out = []
    live = lexh.live_text(plugin_src)
    body = function_body(live, r"void do_rules_windows\(yuzu::CommandContext& ctx\) ?(?=\{)")
    if body is None:
        return ["firewall_plugin.cpp no longer defines void do_rules_windows(yuzu::CommandContext&)"]
    text = squash(body)

    getters = re.findall(r"\brule->(get_\w+)\(", text)
    if sorted(getters) != sorted(WIN_PROPERTIES):
        out.append(f"do_rules_windows reads rule properties {sorted(getters)}, expected exactly "
                   f"{sorted(WIN_PROPERTIES)}")
    for getter, field in WIN_PROPERTIES.items():
        m = re.search(r"(?:const )?HRESULT (\w+) = rule->%s\(" % getter, text)
        if not m:
            out.append(f"rule->{getter}( is no longer assigned to an HRESULT (a refused or failed read "
                       "would leave a false-safe default in the row)")
            continue
        if not re.search(r"\.%s = static_cast<std::uint32_t>\(%s\)" % (field, m.group(1)), text):
            out.append(f"the HRESULT of rule->{getter}( no longer reaches WinRuleRead::{field} "
                       "(the builder would trust the value of a read it was never told failed)")

    first_read = text.find("rule->get_")
    emit = re.search(r"emit_rule\( ?yuzu::firewall::WinRuleRead\{", text)
    if emit is None:
        out.append("do_rules_windows no longer builds a WinRuleRead for emit_rule( (win_rule_row takes "
                   "the five HRESULTs)")
    elif first_read >= 0 and "FAILED(" in text[first_read:emit.start()]:
        out.append("a FAILED( test sits between the property reads and the row: S_FALSE passes it and "
                   "reads as a default (action BLOCK), so no field may be decided by it")
    if re.search(r"\b(dir_s|action_s)\b", text):
        out.append("do_rules_windows builds a direction or action string in the shell again "
                   "(dir_s/action_s): the pure builder decides every field")
    if len(re.findall(r"win_rule_row\(", text)) != 1 or not re.search(
            r"ctx\.write_output\(yuzu::firewall::win_rule_row\(read\)\)", text):
        out.append("the only row write is no longer ctx.write_output(yuzu::firewall::win_rule_row(read)) "
                   "inside emit_rule")
    if "win_rule_first_failure(read)" not in text or "++count;" not in text:
        out.append("emit_rule no longer tallies win_rule_first_failure(read) and counts the row")

    # neither skip site (a VARIANT that is not a dispatch pointer, a failed QueryInterface) may reach
    # `continue` without writing the rule's row: the enumerator returned an item, so it counts
    continues = len(re.findall(r"\bcontinue;", text))
    with_row = len(re.findall(r"emit_rule\([^;]*\); continue;", text))
    if continues != with_row or continues != 2:
        out.append(f"do_rules_windows has {continues} `continue;` and {with_row} of them follow an "
                   "emit_rule( row write; the two skip sites (not a dispatch pointer, QueryInterface "
                   "failed) must each write an all-unknown row before they continue")
    for what, pat in (
            ("a VARIANT that is not a dispatch pointer",
             r"if \( ?v\.vt != VT_DISPATCH \|\| !v\.pdispVal ?\) \{ VariantClear\(&v\); "
             r"emit_rule\( ?yuzu::firewall::win_rule_unobtained\("),
            ("a failed QueryInterface",
             r"if \( ?FAILED\(qhr\) \|\| !rule ?\) \{ emit_rule\( ?yuzu::firewall::win_rule_unobtained\(")):
        if not re.search(pat, text):
            out.append(f"the skip site for {what} no longer writes win_rule_unobtained(...) before it continues")

    if not re.search(r"win_rules_trailer_rows\( ?count, truncated, enum_failed, static_cast<uint32_t>\(hr\), "
                     r"property_failures, first_property_hr ?\)", text):
        out.append("the trailer no longer receives property_failures and first_property_hr "
                   "(`error|rule_property:` would never be written)")

    squashed = squash(live)
    if not re.search(r"static_assert\( ?NET_FW_RULE_DIR_IN == 1 && NET_FW_RULE_DIR_OUT == 2", squashed) or \
            not re.search(r"static_assert\( ?NET_FW_ACTION_BLOCK == 0 && NET_FW_ACTION_ALLOW == 1", squashed):
        out.append("the static_asserts pinning NET_FW_RULE_DIR_* and NET_FW_ACTION_* to the values "
                   "win_rule_row maps are gone")
    if not re.search(r"inline std::string win_rule_row\( ?const WinRuleRead& \w+ ?\)", squash(lexh.live_text(parsers_src))):
        out.append("firewall_parsers.hpp: win_rule_row no longer takes a WinRuleRead")
    return out


PARSERS_HPP = ROOT / "agents" / "plugins" / "firewall" / "src" / "firewall_parsers.hpp"

WINDOWS_MUTATIONS = [
    (_mut(r"const HRESULT enabled_hr = rule->get_Enabled\(", "rule->get_Enabled("),
     "rule->get_Enabled( is no longer assigned to an HRESULT"),
    (_mut(r"const HRESULT name_hr = rule->get_Name\(", "(void)rule->get_Name("),
     "rule->get_Name( is no longer assigned to an HRESULT"),
    (_mut(r"\.profiles_hr = static_cast<std::uint32_t>\(profiles_hr\)", ".profiles_hr = 0"),
     "no longer reaches WinRuleRead::profiles_hr"),
    (_mut(r"\.dir_hr = static_cast<std::uint32_t>\(dir_hr\)", ".dir_hr = static_cast<std::uint32_t>(action_hr)"),
     "no longer reaches WinRuleRead::dir_hr"),
    (_mut(r"(const HRESULT dir_hr = rule->get_Direction\(&dir\);)",
          r'\1 std::string dir_s = FAILED(dir_hr) ? "unknown" : "in";'),
     "FAILED( test sits between"),
    (_mut(r"(NET_FW_ACTION action\{\};)", r'\1 std::string action_s = "allow";'), "dir_s/action_s"),
    (_mut(r"(if \(v\.vt != VT_DISPATCH \|\| !v\.pdispVal\) \{\s*VariantClear\(&v\);)\s*emit_rule\([^;]*;", r"\1"),
     "skip site"),
    (_mut(r"(if \(FAILED\(qhr\) \|\| !rule\) \{)\s*emit_rule\(.*?\);(\s*continue;)", r"\1\2"),
     "skip site"),
    (_mut(r"property_failures,\s*first_property_hr\)\)", "0, 0))"), "property_failures and first_property_hr"),
    (_mut(r"static_assert\(NET_FW_ACTION_BLOCK == 0 && NET_FW_ACTION_ALLOW == 1,", "static_assert(true,"),
     "static_asserts"),
    (_mut(r"if \(const auto failed_hr = yuzu::firewall::win_rule_first_failure\(read\); failed_hr != 0\) \{",
          "if (false) { const auto failed_hr = 0u;"), "emit_rule no longer tallies"),
]


class WindowsRuleReadWiring(unittest.TestCase):
    def setUp(self):
        self.cpp = PLUGIN_CPP.read_text(encoding="utf-8")
        self.hpp = PARSERS_HPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = windows_problems(self.cpp, self.hpp)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (mutate, expected) in enumerate(WINDOWS_MUTATIONS, 1):
            with self.subTest(mutation=i, expected=expected):
                mutated, n = mutate(self.cpp)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = windows_problems(mutated, self.hpp)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertTrue(any(expected in m for m in p), f"expected {expected!r} in {p}")

    def test_the_builder_signature_is_pinned(self):
        mutated = self.hpp.replace("win_rule_row(const WinRuleRead& r)", "win_rule_row(std::string_view r)", 1)
        self.assertNotEqual(mutated, self.hpp)
        self.assertTrue(any("no longer takes a WinRuleRead" in m for m in windows_problems(self.cpp, mutated)))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
