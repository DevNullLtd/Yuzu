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

  LinuxSnapshotWiring
                     both Linux dispatchers try firewalld, nftables, the root snapshot broker, ufw
                     and iptables in that order, firewalld's answer standing at once only when its
                     read was complete: a partial one (getServices refused to the account) is held
                     behind the nftables and snapshot rungs, which replace it only with an active
                     ruleset (both write nothing else), and is written when none does, before ufw;
                     only the netlink table-dump row is deferred (to
                     the decline path), never the socket-open diagnostics; the broker reader opens
                     a close-on-exec non-blocking ScopedFd socket, checks SO_PEERCRED for root,
                     bounds its wait and its size, and never writes to the socket. The installer
                     helper's `snapshot` word is the second transport, tried only when the socket
                     is absent: only a complete run that exited 0 is parsed, and anything else is
                     a silent decline.

  BrokerUnits        the shipped socket, template service and snapshot script are exactly the
                     reviewed directive sets, agree with the plugin's socket path and with what the
                     deb and rpm packaging install, the script reads nothing, and the agent unit's
                     NoNewPrivileges and single capability are untouched. The service unit
                     deliberately has no NoNewPrivileges (SELinux denies the tools' domain
                     transition under it), and the gate says so by name.

Matching runs on tests/cpp_lex_helper.live_text(): comments, backslash-continued comments and
`#if 0` blocks are removed first (string contents kept), so a pin cannot be satisfied by commented-out
or disabled text. Lexical only: it cannot see a relocation that keeps the tokens but changes control
flow (review-enforced). Each class carries an in-memory mutation self-test; a mutation whose pattern
no longer matches fails loudly (stale pattern) rather than passing vacuously.

Usage: python3 -I tests/test_firewall_read_wiring_lexical.py
"""
import os
import re
import shutil
import subprocess
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


# ── Linux ───────────────────────────────────────────────────────────────────────────────────────

LINUX_ORDER = {
    "do_state_linux": ("firewalld_rung", "try_nftables_state", "try_snapshot", "try_ufw_state", "try_iptables_state"),
    "do_rules_linux": ("firewalld_rung", "try_nftables_rules", "try_snapshot", "try_ufw_rules", "try_iptables_rules"),
}
LINUX_ACTION = {"do_state_linux": "state", "do_rules_linux": "rules"}
# calls that would write to the broker socket (the agent sends nothing)
WRITE_CALLS = (r"::write\(", r"::send\(", r"::sendto\(", r"::sendmsg\(", r"::writev\(", r"::pwrite\(",
               r"\bwrite\(sock", r"\bsend\(sock")
WRITE_ROWS = r"for \( ?const auto& row : firewalld\.rows ?\) ctx\.write_output\(row\);"


def linux_problems(plugin_src):
    out = []
    live = lexh.live_text(plugin_src)
    for fn, rungs in LINUX_ORDER.items():
        body = function_body(live, r"void " + fn + r"\(yuzu::CommandContext& ctx\) ?(?=\{)")
        if body is None:
            out.append(f"firewall_plugin.cpp no longer defines void {fn}(yuzu::CommandContext&)")
            continue
        text = squash(body)
        action = LINUX_ACTION[fn]
        pos = [text.find(r + "(") for r in rungs]
        if -1 in pos:
            out.append(f"{fn} no longer calls {rungs[pos.index(-1)]}(")
        elif pos != sorted(pos):
            out.append(f"{fn} no longer tries {', '.join(rungs)} in that order (the snapshot sits after "
                       "nftables and before ufw)")
        # firewalld is read for this action by the one rung that writes nothing itself
        if not re.search(r"const auto firewalld = firewalld_rung\( ?yuzu::firewall::FwReadAction::%s ?\);" % action, text):
            out.append(f"{fn} no longer reads firewalld with firewalld_rung(FwReadAction::{action}) into `firewalld`")
        # a COMPLETE firewalld read answers at once, first of all
        complete = re.search(r"if \( ?firewalld\.read == yuzu::firewall::FirewalldRead::complete ?\) \{ %s return; \}"
                             % WRITE_ROWS, text)
        if not complete or complete.start() > text.find(rungs[1] + "("):
            out.append(f"{fn} no longer writes firewalld's rows and returns, before any other rung, when its read "
                       "is complete")
        # a PARTIAL one only marks the dispatch: the nft rung and the snapshot rung then answer only active
        flag = re.search(r"info\.firewalld_running = firewalld\.read == yuzu::firewall::FirewalldRead::partial;", text)
        info = text.find("NftFallthroughInfo info;")
        if not flag or info < 0 or flag.start() < info or flag.start() > text.find(rungs[1] + "("):
            out.append(f"{fn} no longer sets info.firewalld_running from a partial firewalld read before the "
                       f"{rungs[1]} rung")
        snap = rungs[2]
        if not re.search(r"if \( ?%s\(ctx, info, yuzu::firewall::FwReadAction::%s\) ?\) return;" % (snap, action), text):
            out.append(f"{fn} no longer returns when {snap}(ctx, info, FwReadAction::{action}) answers")
        # the deferred table-dump row is written after the snapshot declines and before the next rung
        written = re.search(r"for \( ?const auto& row : info\.pending_rows ?\) ctx\.write_output\(row\);", text)
        at = text.find(snap + "(")
        if not written or at < 0 or written.start() < at or written.start() > text.find(rungs[3] + "("):
            out.append(f"{fn} no longer writes info.pending_rows after {snap} declines and before "
                       f"{rungs[3]} (the deferred table-dump row would be lost)")
        # the held firewalld answer: after the deferred rows, before ufw, and nothing else answers after it
        held = re.search(r"if \( ?info\.firewalld_running ?\) \{ %s return; \}" % WRITE_ROWS, text)
        if not held or not written or held.start() < written.start() or held.start() > text.find(rungs[3] + "("):
            out.append(f"{fn} no longer writes the held firewalld rows and returns after info.pending_rows and "
                       f"before {rungs[3]} (ufw and iptables are not consulted behind a running firewalld)")

    # the firewalld rung reads and returns rows: it writes nothing itself
    rung = function_body(live, r"FirewalldRung firewalld_rung\(yuzu::firewall::FwReadAction action\) ?(?=\{)")
    if rung is None:
        out.append("firewall_plugin.cpp no longer defines FirewalldRung firewalld_rung(FwReadAction action)")
    else:
        text = squash(rung)
        if "write_output" in text:
            out.append("firewalld_rung writes a row itself: the dispatcher decides whether firewalld's rows stand")
        if not re.search(r"yuzu::firewall::firewalld_read\( ?q\.reachable, q\.services_complete ?\)", text) or \
                not re.search(r"yuzu::firewall::firewalld_rows\( ?q\.zones, q\.services_complete, action ?\)", text):
            out.append("firewalld_rung no longer decides through firewalld_read and firewalld_rows")
    if not re.search(r"FirewalldRung firewalld_rung\(yuzu::firewall::FwReadAction\) \{ return \{\}; \}", squash(live)):
        out.append("the build without libsystemd no longer has a firewalld_rung that reports no firewalld")

    # while firewalld was only partly read, the nft rung answers only a ruleset that shows content, and
    # writes no backend row before it knows
    for name, guard in (("try_nftables_state", r"verdict != yuzu::firewall::NftVerdict::active"),
                        ("try_nftables_rules", r"!yuzu::firewall::nft_has_content\(chains, rules\)")):
        body = function_body(live, r"bool " + name + r"\(yuzu::CommandContext& ctx, NftFallthroughInfo& info\) ?(?=\{)")
        if body is None:
            out.append(f"firewall_plugin.cpp no longer defines {name}(ctx, info)")
            continue
        text = squash(body)
        held = re.search(r"if \( ?info\.firewalld_running && %s ?\) return false;" % guard, text)
        if not held or held.start() > text.find('ctx.write_output("backend|nftables")'):
            out.append(f"{name} no longer declines, before it writes its backend row, when firewalld is held and the "
                       "ruleset shows no content")

    probe = function_body(live, r"\[\[nodiscard\]\] std::optional<NftProbeResult> run_nft_probe\(yuzu::CommandContext& ctx,\s*"
                                r"NftFallthroughInfo& info\) ?(?=\{)")
    if probe is None:
        out.append("firewall_plugin.cpp no longer defines run_nft_probe(ctx, info)")
    else:
        text = squash(probe)
        if len(re.findall(r"pending_rows\.push_back\(", text)) != 1 or not re.search(
                r'info\.pending_rows\.push_back\( ?yuzu::firewall::nft_diag_row\( ?"table",', text):
            out.append("run_nft_probe no longer defers exactly the table-dump row "
                       '(info.pending_rows.push_back(nft_diag_row("table", ...)))')
        if re.search(r'ctx\.write_output\( ?yuzu::firewall::nft_diag_row\( ?"table"', text):
            out.append("run_nft_probe writes the table-dump row at once again (an EPERM row beside a "
                       "successful snapshot read would mislead)")
        opens = len(re.findall(r"for \( ?const auto& row : yuzu::firewall::nft_open_diag_rows\(open_errnos\) ?\) "
                               r"ctx\.write_output\(row\);", text))
        if opens != 2:
            out.append(f"run_nft_probe writes the socket-open diagnostic rows (error|fd_exhausted, "
                       f"error|nftables:socket:eperm) at {opens} sites, expected 2: they are never deferred")

    reader = function_body(live, r"\[\[nodiscard\]\] std::expected<std::string, std::string>\s+"
                                 r"read_fw_snapshot\(std::chrono::steady_clock::time_point deadline\) ?(?=\{)")
    if reader is None:
        out.append("firewall_plugin.cpp no longer defines read_fw_snapshot(deadline)")
    else:
        text = squash(reader)
        for what, pat in (
                ("an AF_UNIX stream socket that is close-on-exec and non-blocking, owned by a ScopedFd",
                 r"yuzu::agent::ScopedFd sock\(::socket\(AF_UNIX, SOCK_STREAM \| SOCK_CLOEXEC \| SOCK_NONBLOCK, 0\)\)"),
                ("the peer-credential check (SO_PEERCRED)", r"SO_PEERCRED"),
                ("the refusal of a peer that is not root", r"cred\.uid != 0\) return std::unexpected\(std::string\{\"peer_not_root\"\}\)"),
                ("the socket path bound (static_assert on sun_path)", r"static_assert\( ?yuzu::firewall::kFwSnapshotSocketPath\.size\(\) < sizeof\(addr\.sun_path\)"),
                ("the deadline (remaining_ms and a timeout token)", r"remaining_ms\(deadline\)"),
                ("the poll before every read", r"::poll\("),
                ("the size cap", r"text\.size\(\) > yuzu::firewall::kFwSnapshotMaxBytes"),
                ("a retry of EINTR", r"errno == EINTR")):
            if not re.search(pat, text):
                out.append(f"read_fw_snapshot no longer has {what}")
        for pat in WRITE_CALLS:
            if re.search(pat, text):
                out.append("read_fw_snapshot writes to the socket (/%s/): the agent sends nothing, the "
                           "broker reads no input" % pat)
        if "::close(" in text:
            out.append("read_fw_snapshot closes a descriptor by hand: ScopedFd is the single release path")
    helper = function_body(live, r"\[\[nodiscard\]\] std::optional<std::string> read_fw_snapshot_via_helper\(\) ?(?=\{)")
    if helper is None:
        out.append("firewall_plugin.cpp no longer defines read_fw_snapshot_via_helper()")
    else:
        text = squash(helper)
        for what, pat in (
                ("the refusal to run for root or under NoNewPrivileges (sudo cannot elevate there)",
                 r"if \( ?::geteuid\( ?\) == 0 \|\| privilege_refusal\( ?\) ?\) return std::nullopt;"),
                ("the sudo-wrapped helper snapshot word as its only argv, with the deadline and a cap of twice the broker's cut",
                 r"run_bounded_subprocess\( ?yuzu::shared::sudo_wrap\(\{std::string\{fq::kFwHelperPath\}, \"snapshot\"\}\), "
                 r"SubprocessOptions\{\.deadline = kAcqDeadline, \.output_cap_bytes = 2 \* yuzu::firewall::kFwSnapshotMaxBytes\}\)"),
                ("the rule that only a complete run that exited 0 is returned (subprocess_complete, a silent decline otherwise)",
                 r"if \( ?!subprocess_complete\(res\) ?\) return std::nullopt; return res\.output;")):
            if not re.search(pat, text):
                out.append(f"read_fw_snapshot_via_helper no longer has {what}")
        if "merge_stderr" in text or "sudo_runner(" in text:
            out.append("read_fw_snapshot_via_helper merges stderr: sudo's message would be read as listing")
        if "exit_code" in text or "write_output" in text:
            out.append("read_fw_snapshot_via_helper decides on an exit code itself or writes a row: "
                       "subprocess_complete is the one rule and the decline is silent")
    snapshot = function_body(live, r"bool try_snapshot\(yuzu::CommandContext& ctx, const NftFallthroughInfo& info,\s*"
                                   r"yuzu::firewall::FwReadAction action\) ?(?=\{)")
    if snapshot is None:
        out.append("firewall_plugin.cpp no longer defines try_snapshot(ctx, info, action)")
    else:
        text = squash(snapshot)
        if not re.search(r"if \( ?!reply && reply\.error\(\)\.empty\(\) ?\) \{[^{}]*read_fw_snapshot_via_helper\(\)", text):
            out.append("try_snapshot no longer tries the helper transport only when the socket is absent "
                       "(an empty token): a reported socket failure must not fall to sudo")
        if not re.search(r"yuzu::firewall::linux_snapshot_answer\( ?\*snapshot, info\.tables_seen, action ?\)", text):
            out.append("try_snapshot no longer decides through linux_snapshot_answer(*snapshot, info.tables_seen, action)")
        # held firewalld: only an active answer is written and accepted, any other writes just its error| rows
        if not re.search(r"const bool answers = !info\.firewalld_running \|\| answer\.state == yuzu::firewall::NftVerdict::active;"
                         r" for \( ?const auto& row : answer\.rows ?\) if \( ?answers \|\| row\.starts_with\(\"error\|\"\) ?\) "
                         r"ctx\.write_output\(row\); return answers;", text):
            out.append("try_snapshot no longer answers only an active ruleset while firewalld is held (a held firewalld "
                       "is replaced only by a complete read that shows an active ruleset, never by inactive or unknown), "
                       "writing just the error| rows otherwise")
    if len(re.findall(r"else the root snapshot broker over AF_UNIX \(packaged systemd socket\)", squash(live))) != 2:
        out.append("the Linux state and rules descriptors no longer both name the root snapshot broker")
    return out


def _lmut(pattern, repl, count=1):
    return lambda raw: re.subn(pattern, repl, raw, count=count, flags=re.S)


_HELD_ROWS = r"\{\s*for \(const auto& row : firewalld\.rows\)\s*ctx\.write_output\(row\);\s*return;\s*\}"

LINUX_MUTATIONS = [
    # the snapshot rung dropped from the state ladder
    (_lmut(r"\s*if \(try_snapshot\(ctx, info, yuzu::firewall::FwReadAction::state\)\)\s*return;", ""), "do_state_linux"),
    # ... and from the rules ladder
    (_lmut(r"\s*if \(try_snapshot\(ctx, info, yuzu::firewall::FwReadAction::rules\)\)\s*return;", ""), "do_rules_linux"),
    # moved after ufw: the snapshot must come before it
    (_lmut(r"(\s*if \(try_snapshot\(ctx, info, yuzu::firewall::FwReadAction::rules\)\)\s*return;)(.*?if \(try_ufw_rules\(ctx\)\)\s*return;)",
           r"\2\1"), "in that order"),
    # the snapshot asked for the wrong action
    (_lmut(r"try_snapshot\(ctx, info, yuzu::firewall::FwReadAction::state\)", "try_snapshot(ctx, info, yuzu::firewall::FwReadAction::rules)"),
     "no longer returns when try_snapshot"),
    # the deferred rows never written (state)
    (_lmut(r"for \(const auto& row : info\.pending_rows\)\s*ctx\.write_output\(row\);", ""), "info.pending_rows"),
    # the table-dump row written at once again
    (_lmut(r'info\.pending_rows\.push_back\(yuzu::firewall::nft_diag_row\("table", table\.res\)\);',
           'ctx.write_output(yuzu::firewall::nft_diag_row("table", table.res));'), "defers exactly the table-dump row"),
    # a socket-open diagnostic deferred as well
    (_lmut(r"(for \(const auto& row : yuzu::firewall::nft_open_diag_rows\(open_errnos\)\)\s*)ctx\.write_output\(row\);",
           r"\1info.pending_rows.push_back(row);"), "never deferred"),
    # firewalld: a complete read no longer answers at once (state, then rules)
    (_lmut(r"firewalld\.read == yuzu::firewall::FirewalldRead::complete", "firewalld.read != yuzu::firewall::FirewalldRead::absent"),
     "when its read is complete"),
    (_lmut(r"(FwReadAction::rules\);\s*if \()firewalld\.read == yuzu::firewall::FirewalldRead::complete",
           r"\1firewalld.read != yuzu::firewall::FirewalldRead::absent"), "when its read is complete"),
    # firewalld: a partial read no longer marks the dispatch (state, then rules)
    (_lmut(r"info\.firewalld_running = firewalld\.read == yuzu::firewall::FirewalldRead::partial;", "info.firewalld_running = false;"),
     "no longer sets info.firewalld_running"),
    (_lmut(r"(FwReadAction::rules\);.*?)info\.firewalld_running = firewalld\.read == yuzu::firewall::FirewalldRead::partial;",
           r"\1info.firewalld_running = false;"), "no longer sets info.firewalld_running"),
    # firewalld: the held rows are never written when nothing shows an active ruleset (state, then rules)
    (_lmut(r"\s*if \(info\.firewalld_running\) " + _HELD_ROWS, ""), "no longer writes the held firewalld rows"),
    (_lmut(r"(FwReadAction::rules\)\)\s*return;.*?)\s*if \(info\.firewalld_running\) " + _HELD_ROWS, r"\1"),
     "no longer writes the held firewalld rows"),
    # firewalld: ufw and iptables consulted behind a running firewalld (the held write does not return)
    (_lmut(r"(if \(info\.firewalld_running\) \{\s*for \(const auto& row : firewalld\.rows\)\s*ctx\.write_output\(row\);)\s*return;",
           r"\1"), "no longer writes the held firewalld rows"),
    # firewalld: the positions. The complete-read block moved after the nftables rung (state ladder) ...
    (_lmut(r"(\s*if \(firewalld\.read == yuzu::firewall::FirewalldRead::complete\) " + _HELD_ROWS + r")"
           r"(\s*NftFallthroughInfo info;\s*info\.firewalld_running = [^;]*;\s*if \(try_nftables_state\(ctx, info\)\)\s*return;)",
           r"\2\1"), "no longer writes firewalld's rows and returns, before any other rung, when its read is complete"),
    # ... the held flag set only after the nftables rung has run (state ladder) ...
    (_lmut(r"(\s*info\.firewalld_running = firewalld\.read == yuzu::firewall::FirewalldRead::partial;)"
           r"(\s*if \(try_nftables_state\(ctx, info\)\)\s*return;)", r"\2\1"),
     "no longer sets info.firewalld_running from a partial firewalld read before the"),
    # ... the held write ahead of the deferred rows (state ladder) ...
    (_lmut(r"(\s*for \(const auto& row : info\.pending_rows\)\s*ctx\.write_output\(row\);)"
           r"((?:\s*//[^\n]*)*\s*if \(info\.firewalld_running\) " + _HELD_ROWS + r")", r"\2\1"),
     "no longer writes the held firewalld rows and returns after info.pending_rows"),
    # ... and the held write after ufw has been consulted (rules ladder)
    (_lmut(r"(\s*if \(info\.firewalld_running\) " + _HELD_ROWS + r")(\s*if \(try_ufw_rules\(ctx\)\)\s*return;)", r"\2\1"),
     "no longer writes the held firewalld rows and returns after info.pending_rows and before try_ufw_rules"),
    # the nft rung answers a non-active ruleset while firewalld is held, or writes its row first
    (_lmut(r"if \(info\.firewalld_running && verdict != yuzu::firewall::NftVerdict::active\)\s*return false;", ""),
     "try_nftables_state no longer declines"),
    (_lmut(r"verdict != yuzu::firewall::NftVerdict::active\)\s*return false;", "verdict == yuzu::firewall::NftVerdict::unknown) return false;"),
     "try_nftables_state no longer declines"),
    (_lmut(r"(if \(info\.firewalld_running && verdict != yuzu::firewall::NftVerdict::active\)\s*return false;)(\s*ctx\.write_output\(\"backend\|nftables\"\);[^\n]*)",
           r"\2\1"), "try_nftables_state no longer declines"),
    (_lmut(r"if \(info\.firewalld_running && !yuzu::firewall::nft_has_content\(chains, rules\)\)\s*return false;", ""),
     "try_nftables_rules no longer declines"),
    (_lmut(r"(if \(info\.firewalld_running && !yuzu::firewall::nft_has_content\(chains, rules\)\)\s*return false;)(\s*ctx\.write_output\(\"backend\|nftables\"\);[^\n]*)",
           r"\2\1"), "try_nftables_rules no longer declines"),
    # the snapshot rung answers a non-active ruleset while firewalld is held
    (_lmut(r"const bool answers = !info\.firewalld_running \|\| answer\.state == yuzu::firewall::NftVerdict::active;",
           "const bool answers = true;"), "only an active ruleset while firewalld is held"),
    (_lmut(r"if \(answers \|\| row\.starts_with\(\"error\|\"\)\)", "if (true)"), "only an active ruleset while firewalld is held"),
    (_lmut(r"return answers;", "return true;"), "only an active ruleset while firewalld is held"),
    # the firewalld rung writes a row itself, or decides without the pure functions
    (_lmut(r"(const auto q = query_firewalld\(\);)", r'\1 write_output("x");'), "firewalld_rung writes a row itself"),
    (_lmut(r"yuzu::firewall::firewalld_read\(q\.reachable, q\.services_complete\)",
           "(q.reachable ? yuzu::firewall::FirewalldRead::complete : yuzu::firewall::FirewalldRead::absent)"),
     "decides through firewalld_read"),
    # the reader: no root check
    (_lmut(r"if \(cred\.uid != 0\)\s*return std::unexpected\(std::string\{\"peer_not_root\"\}\);", ""),
     "refusal of a peer that is not root"),
    (_lmut(r"cred\.uid != 0", "cred.uid != 1"), "refusal of a peer that is not root"),
    # the reader: blocking, inheritable socket
    (_lmut(r"SOCK_STREAM \| SOCK_CLOEXEC \| SOCK_NONBLOCK", "SOCK_STREAM"), "close-on-exec and non-blocking"),
    # the reader: no deadline
    (_lmut(r"const auto left = remaining_ms\(deadline\);", "const auto left = std::chrono::milliseconds{1000};"),
     "the deadline"),
    # the reader: unbounded
    (_lmut(r"if \(text\.size\(\) > yuzu::firewall::kFwSnapshotMaxBytes\)\s*return std::unexpected\(std::string\{\"oversized\"\}\);", ""),
     "the size cap"),
    # the reader: writes to the socket
    (_lmut(r"(char buf\[16 \* 1024\];)", r"\1 (void)::write(sock.get(), &buf[0], 1);"), "writes to the socket"),
    # a hand-written close beside the ScopedFd
    (_lmut(r"(char buf\[16 \* 1024\];)", r"\1 ::close(sock.get());"), "closes a descriptor by hand"),
    # the helper transport: the exit rule, the guard, the cap, the stderr, the token condition
    (_lmut(r"if \(!subprocess_complete\(res\)\)\s*return std::nullopt;\s*return res\.output;", "return res.output;"),
     "complete run that exited 0"),
    (_lmut(r"if \(!subprocess_complete\(res\)\)", "if (!res.tool_ran)"), "complete run that exited 0"),
    (_lmut(r"if \(::geteuid\(\) == 0 \|\| privilege_refusal\(\)\)\s*return std::nullopt;\s*const auto res = run_bounded_subprocess",
           "const auto res = run_bounded_subprocess"),
     "refusal to run for root or under NoNewPrivileges"),
    (_lmut(r"if \(::geteuid\(\) == 0 \|\| privilege_refusal\(\)\)", "if (::geteuid() == 0)"),
     "refusal to run for root or under NoNewPrivileges"),
    (_lmut(r",\s*\.output_cap_bytes = 2 \* yuzu::firewall::kFwSnapshotMaxBytes", ""), "a cap of twice the broker's cut"),
    (_lmut(r"\.output_cap_bytes = 2 \* yuzu::firewall::kFwSnapshotMaxBytes\}",
           ".output_cap_bytes = 2 * yuzu::firewall::kFwSnapshotMaxBytes, .merge_stderr = true}"), "a cap of twice the broker's cut"),
    (_lmut(r"\.output_cap_bytes = 2 \* yuzu::firewall::kFwSnapshotMaxBytes", ".output_cap_bytes = 2 * 1024 * 1024"),
     "a cap of twice the broker's cut"),
    (_lmut(r"if \(!reply && reply\.error\(\)\.empty\(\)\)", "if (!reply)"), "only when the socket is absent"),
    (_lmut(r"\{std::string\{fq::kFwHelperPath\}, \"snapshot\"\}", '{std::string{fq::kFwHelperPath}, "snapshot", "x"}'),
     "helper snapshot word as its only argv"),
    # a descriptor without the broker
    (_lmut(r"else the root snapshot broker over AF_UNIX \(packaged systemd socket\), ", "", count=1),
     "descriptors no longer both name"),
]


class LinuxSnapshotWiring(unittest.TestCase):
    def setUp(self):
        self.cpp = PLUGIN_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = linux_problems(self.cpp)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (mutate, expected) in enumerate(LINUX_MUTATIONS, 1):
            with self.subTest(mutation=i, expected=expected):
                mutated, n = mutate(self.cpp)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = linux_problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertTrue(any(expected in m for m in p), f"expected {expected!r} in {p}")


# ── the broker units, the script and what the packages install ──────────────────────────────────

SYSTEMD = ROOT / "deploy" / "systemd"
PACKAGING = ROOT / "deploy" / "packaging"

SOCKET_UNIT = {
    "Unit": {"Description": "Yuzu agent read-only firewall snapshot socket",
             "Documentation": "https://github.com/DevNullLtd/Yuzu",
             "PartOf": "yuzu-agent.service"},
    "Socket": {"ListenStream": "/run/yuzu-fw-snapshot.sock", "SocketUser": "root", "SocketGroup": "yuzu-agent",
               "SocketMode": "0660", "Accept": "yes", "MaxConnections": "4", "RemoveOnStop": "yes"},
}
SERVICE_UNIT = {
    "Unit": {"Description": "Yuzu agent read-only firewall snapshot (one connection)",
             "Documentation": "https://github.com/DevNullLtd/Yuzu",
             "CollectMode": "inactive-or-failed"},
    "Service": {"User": "root",
                "ExecStart": "/bin/sh /usr/share/yuzu/scripts/yuzu-fw-snapshot.sh",
                "StandardInput": "null", "StandardOutput": "socket", "StandardError": "null",
                "RuntimeMaxSec": "30", "TasksMax": "16",
                "CapabilityBoundingSet": "CAP_NET_ADMIN CAP_NET_RAW",
                "RestrictAddressFamilies": "AF_UNIX AF_NETLINK AF_INET AF_INET6",
                "IPAddressDeny": "any", "SystemCallFilter": "@system-service", "SystemCallErrorNumber": "EPERM",
                "SystemCallArchitectures": "native", "LockPersonality": "true", "MemoryDenyWriteExecute": "true",
                "ProtectSystem": "strict", "ReadWritePaths": "-/run/xtables.lock", "ProtectHome": "true",
                "PrivateTmp": "true", "PrivateDevices": "true", "ProtectKernelModules": "true",
                "ProtectKernelTunables": "true", "ProtectControlGroups": "true", "RestrictNamespaces": "true"},
}


def parse_unit(text):
    """{section: {key: value}} of a unit file; a key given twice is a problem the caller sees as a
    list of values, comments and blank lines are skipped."""
    out, section = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            out.setdefault(section, {})
            continue
        key, _, value = line.partition("=")
        cur = out.setdefault(section, {})
        cur[key.strip()] = cur[key.strip()] + [value.strip()] if key.strip() in cur and isinstance(cur[key.strip()], list) \
            else ([cur[key.strip()], value.strip()] if key.strip() in cur else value.strip())
    return out


def code_lines(text):
    return [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]


def broker_problems(sources):
    """`sources` maps a short name to file text: socket, service, script, agent, deb, rpm, spec,
    parsers."""
    out = []
    for name, want in (("socket", SOCKET_UNIT), ("service", SERVICE_UNIT)):
        got = parse_unit(sources[name])
        if "Install" in got:
            out.append(f"the {name} unit has an [Install] section: nothing enables it, the agent unit's Wants= pulls it in")
        for section, directives in want.items():
            have = got.get(section, {})
            for key, value in directives.items():
                if have.get(key) != value:
                    out.append(f"the {name} unit's {section} {key} is {have.get(key)!r}, expected {value!r}")
            for key in have:
                if key not in directives:
                    out.append(f"the {name} unit has a directive the review did not cover: {section} {key}")
        for section in got:
            if section not in want:
                out.append(f"the {name} unit has a section the review did not cover: [{section}]")
    # NoNewPrivileges is deliberately absent from the service: under SELinux enforcing it makes every exec of
    # nft, iptables and ip6tables a denied nnp_transition (three audit denials per read) and leaves the tools
    # in the script's domain instead of their own; the agent unit keeps it (checked below)
    if "NoNewPrivileges" in parse_unit(sources["service"]).get("Service", {}):
        out.append("the service unit sets NoNewPrivileges: SELinux denies the domain transition of the tools it "
                   "runs, three denials per read (ADR-3007 clause 7)")
    # the socket path is the one the plugin connects to
    m = re.search(r'kFwSnapshotSocketPath = "([^"]+)"', sources["parsers"])
    if not m or m.group(1) != SOCKET_UNIT["Socket"]["ListenStream"]:
        out.append("kFwSnapshotSocketPath in firewall_parsers.hpp is not the socket's ListenStream")
    # the script path the service runs is the path the packages install it to, with the modes
    script = "/usr/share/yuzu/scripts/yuzu-fw-snapshot.sh"
    deb, rpm, spec = sources["deb"], sources["rpm"], sources["spec"]
    if "deploy/systemd/yuzu-fw-snapshot.sh" not in deb or '"$PKG/usr/share/yuzu/scripts/"' not in deb or \
            'chmod 0755 "$PKG/usr/share/yuzu/scripts/yuzu-fw-snapshot.sh"' not in deb:
        out.append(f"build-deb.sh does not install the script to {script} with mode 0755")
    for unit in ("yuzu-fw-snapshot.socket", "yuzu-fw-snapshot@.service"):
        if f"deploy/systemd/{unit}" not in deb or '"$PKG/usr/lib/systemd/system/"' not in deb:
            out.append(f"build-deb.sh does not copy {unit} to usr/lib/systemd/system")
    if "chmod 0644 \"$PKG/usr/lib/systemd/system/yuzu-fw-snapshot.socket\" \"$PKG/usr/lib/systemd/system/yuzu-fw-snapshot@.service\"" not in deb:
        out.append("build-deb.sh does not set mode 0644 on the two broker units")
    for f in ("yuzu-fw-snapshot.socket", "yuzu-fw-snapshot@.service", "yuzu-fw-snapshot.sh"):
        if f'deploy/systemd/{f}" "$TOPDIR/SOURCES/"' not in rpm:
            out.append(f"build-rpm.sh does not copy {f} into SOURCES")
    spec_lines = [l.strip() for l in spec.splitlines()]
    files_at = spec_lines.index("%files") if "%files" in spec_lines else len(spec_lines)
    for line in (
            "install -D -m 0644 %{_sourcedir}/yuzu-fw-snapshot.socket %{buildroot}%{_unitdir}/yuzu-fw-snapshot.socket",
            "install -D -m 0644 %{_sourcedir}/yuzu-fw-snapshot@.service %{buildroot}%{_unitdir}/yuzu-fw-snapshot@.service",
            "install -D -m 0755 %{_sourcedir}/yuzu-fw-snapshot.sh %{buildroot}%{_datadir}/yuzu/scripts/yuzu-fw-snapshot.sh"):
        if line not in spec_lines[:files_at]:
            out.append(f"yuzu-agent.spec no longer has in %install: {line}")
    for line in ("%{_unitdir}/yuzu-fw-snapshot.socket", "%{_unitdir}/yuzu-fw-snapshot@.service",
                 "%{_datadir}/yuzu/scripts/yuzu-fw-snapshot.sh"):
        if line not in spec_lines[files_at:]:
            out.append(f"yuzu-agent.spec no longer lists in %files: {line}")
    # the script reads nothing and runs nothing it was not given
    code = "\n".join(code_lines(sources["script"]))
    for what, pat in (("read", r"\bread\b"), ("eval", r"\beval\b"), ("sh -c", r"\bsh -c\b"),
                      ("a command substitution", r"\$\(|`"), ("cat", r"\bcat\b"), ("stdin", r"/dev/stdin|<&0|< /dev/")):
        if re.search(pat, code):
            out.append(f"yuzu-fw-snapshot.sh uses {what}: it reads no input")
    if "[ $# -eq 0 ] || exit 64" not in code:
        out.append("yuzu-fw-snapshot.sh no longer refuses an argument with exit 64")
    # the agent unit is untouched where it matters
    agent = sources["agent"]
    agent_code = "\n".join(code_lines(agent))
    caps = [l for l in agent_code.splitlines() if re.match(r"\s*(Ambient|Capability|Secure)\w*=", l)
            or re.match(r"\s*(AmbientCapabilities|CapabilityBoundingSet)=", l)]
    if sorted(caps) != ["AmbientCapabilities=CAP_DAC_READ_SEARCH", "CapabilityBoundingSet=CAP_DAC_READ_SEARCH"]:
        out.append(f"the agent unit's capability lines are {caps}: exactly AmbientCapabilities and "
                   "CapabilityBoundingSet=CAP_DAC_READ_SEARCH are allowed")
    if not re.search(r"^NoNewPrivileges=true$", agent_code, re.M):
        out.append("the agent unit no longer has NoNewPrivileges=true")
    unit = parse_unit(agent).get("Unit", {})
    wants = unit.get("Wants")
    after = unit.get("After")
    for key, val in (("Wants", wants), ("After", after)):
        vals = val if isinstance(val, list) else [val]
        if "yuzu-fw-snapshot.socket" not in vals:
            out.append(f"the agent unit's {key}= no longer names yuzu-fw-snapshot.socket")
    return out


BROKER_FILES = {
    "socket": SYSTEMD / "yuzu-fw-snapshot.socket",
    "service": SYSTEMD / "yuzu-fw-snapshot@.service",
    "script": SYSTEMD / "yuzu-fw-snapshot.sh",
    "agent": SYSTEMD / "yuzu-agent.service",
    "deb": PACKAGING / "debian" / "build-deb.sh",
    "rpm": PACKAGING / "rpm" / "build-rpm.sh",
    "spec": PACKAGING / "rpm" / "yuzu-agent.spec",
    "parsers": ROOT / "agents" / "plugins" / "firewall" / "src" / "firewall_parsers.hpp",
}


def _set(name, old, new):
    def mutate(sources):
        if old not in sources[name]:
            return sources, 0
        changed = dict(sources)
        changed[name] = sources[name].replace(old, new, 1)
        return changed, 1
    return mutate


BROKER_MUTATIONS = [
    (_set("socket", "RemoveOnStop=yes", "RemoveOnStop=no"), "RemoveOnStop"),
    (_set("socket", "SocketMode=0660", "SocketMode=0666"), "SocketMode"),
    (_set("socket", "MaxConnections=4", "MaxConnections=40"), "MaxConnections"),
    (_set("socket", "SocketGroup=yuzu-agent", "SocketGroup=users"), "SocketGroup"),
    (_set("socket", "[Socket]\n", "[Install]\nWantedBy=sockets.target\n\n[Socket]\n"), "[Install]"),
    (_set("socket", "Accept=yes", "Accept=yes\nBind=0.0.0.0"), "a directive the review did not cover"),
    (_set("service", "ProtectSystem=strict", "NoNewPrivileges=true\nProtectSystem=strict"), "sets NoNewPrivileges"),
    (_set("service", "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW", "CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN"),
     "CapabilityBoundingSet"),
    (_set("service", "StandardInput=null", "StandardInput=socket"), "StandardInput"),
    (_set("service", "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6", "RestrictAddressFamilies=AF_UNIX AF_NETLINK"),
     "RestrictAddressFamilies"),
    (_set("service", "ProtectSystem=strict", "ProtectSystem=full"), "ProtectSystem"),
    (_set("service", "SystemCallFilter=@system-service\n", ""), "SystemCallFilter"),
    (_set("service", "RuntimeMaxSec=30\n", ""), "RuntimeMaxSec"),
    (_set("service", "ExecStart=/bin/sh /usr/share/yuzu/scripts/yuzu-fw-snapshot.sh",
          "ExecStart=/bin/sh /usr/share/yuzu/scripts/other.sh"), "ExecStart"),
    (_set("script", "[ $# -eq 0 ] || exit 64", "true"), "exit 64"),
    (_set("script", "host_snapshot\n", "read line\nhost_snapshot\n"), "uses read"),
    (_set("script", "host_snapshot\n", "eval \"$line\"\nhost_snapshot\n"), "uses eval"),
    (_set("script", "host_snapshot\n", "x=$(cat)\nhost_snapshot\n"), "command substitution"),
    (_set("agent", "CapabilityBoundingSet=CAP_DAC_READ_SEARCH", "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN"),
     "capability lines"),
    (_set("agent", "AmbientCapabilities=CAP_DAC_READ_SEARCH", "AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_NET_ADMIN"),
     "capability lines"),
    (_set("agent", "NoNewPrivileges=true", "NoNewPrivileges=false"), "NoNewPrivileges"),
    (_set("agent", "Wants=yuzu-fw-snapshot.socket\n", ""), "Wants="),
    (_set("agent", "After=yuzu-fw-snapshot.socket\n", ""), "After="),
    (_set("parsers", 'kFwSnapshotSocketPath = "/run/yuzu-fw-snapshot.sock"', 'kFwSnapshotSocketPath = "/run/other.sock"'),
     "kFwSnapshotSocketPath"),
    (_set("deb", 'chmod 0755 "$PKG/usr/share/yuzu/scripts/yuzu-fw-snapshot.sh"\n', ""), "build-deb.sh"),
    (_set("rpm", 'cp "$SCRIPT_DIR/../../../deploy/systemd/yuzu-fw-snapshot.sh" "$TOPDIR/SOURCES/"\n', ""), "build-rpm.sh"),
    (_set("spec", "%{_datadir}/yuzu/scripts/yuzu-fw-snapshot.sh\n%dir", "%dir"), "yuzu-agent.spec"),
]


class BrokerUnits(unittest.TestCase):
    def setUp(self):
        self.sources = {k: v.read_text(encoding="utf-8") for k, v in BROKER_FILES.items()}

    def test_source_is_clean(self):
        p = broker_problems(self.sources)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (mutate, expected) in enumerate(BROKER_MUTATIONS, 1):
            with self.subTest(mutation=i, expected=expected):
                mutated, n = mutate(self.sources)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = broker_problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertTrue(any(expected in m for m in p), f"expected {expected!r} in {p}")

    @unittest.skipIf(os.name == "nt", "the execute bit is not represented on Windows; the packages set the modes "
                                      "themselves (chmod in build-deb.sh, install -m in the spec), both pinned in broker_problems")
    def test_the_script_and_units_have_the_modes_the_packages_install(self):
        def executable(path):
            return bool(os.stat(path).st_mode & 0o111)
        self.assertTrue(executable(BROKER_FILES["script"]), "the script is shipped 0755")
        for name in ("socket", "service"):
            self.assertFalse(executable(BROKER_FILES[name]), f"the {name} unit is not executable")

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze is not installed")
    def test_systemd_accepts_the_directives_of_the_units(self):
        # Only a directive systemd does not know or cannot parse fails this: the units refer to a
        # script, an agent unit and a group that do not exist on a build host, and verify says so.
        bad = re.compile(r"Unknown (?:key|section|lvalue)|Failed to parse|Invalid argument|Unknown assignment|"
                         r"Invalid|unsupported|not a valid")
        for name in ("socket", "service", "agent"):
            r = subprocess.run(["systemd-analyze", "verify", "--man=no", str(BROKER_FILES[name])],
                               capture_output=True, text=True, timeout=60)
            findings = [l for l in (r.stdout + r.stderr).splitlines() if bad.search(l)]
            self.assertEqual(findings, [], name)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
