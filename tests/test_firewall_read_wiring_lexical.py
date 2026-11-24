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
                     the decline path), and only while no table has been seen (a second pass whose
                     table dump fails after a table was seen writes its row at once), never the
                     socket-open diagnostics; info.tables_seen decides that and is what every clamp
                     reads. Its reads are pinned: try_snapshot hands it to linux_snapshot_rung, and
                     do_state_linux, straight after the held firewalld answer, calls try_ufw_state
                     and try_iptables_state with `true` inside `if (info.tables_seen)`, a block that
                     returns, and with `false` only after it, each handing its parameter to
                     gate_state_on_completeness (the rules ladder has no clamp at ufw or iptables:
                     there the flag picks between two endings that both read `unknown`). Its writes
                     are pinned by name: the file assigns tables_seen in one statement, which can
                     only turn it on; names the member nowhere but in that statement, an
                     `if (info.tables_seen)` and the linux_snapshot_rung argument; and assigns the
                     struct as a whole in no function that holds it as a writable `info`. A write
                     that neither names the member nor assigns `info` (through a reference, a
                     pointer or a structured binding to the struct, for example) is not seen
                     (review-enforced). The broker reader (in
                     firewall_snapshot_reader.hpp, which the plugin and its tests share) opens
                     a close-on-exec non-blocking ScopedFd socket, checks SO_PEERCRED for the
                     expected uid (the plugin passes none, so root), bounds its wait and its size,
                     and never writes to the socket. The installer helper's `snapshot` word is the
                     second transport, tried only when the socket is absent and the helper file is
                     there: the pure helper_snapshot_outcome decides what the run came to (its
                     listing, or a `helper:<token>` row), and the run gets what is left of the
                     rung's one deadline. try_snapshot computes that deadline once and hands the
                     transport to the pure linux_snapshot_rung, which takes a second whole
                     snapshot before it answers `inactive` and answers `unknown` when that second
                     snapshot cannot be taken; the plugin never decides a snapshot itself. A
                     declined first snapshot answer writes its error rows and lets the ladder go
                     on.

  BrokerUnits        the shipped socket, template service and snapshot script are exactly the
                     reviewed directive sets, agree with the plugin's socket path and with what the
                     deb and rpm packaging install, the script reads nothing, and the agent unit's
                     NoNewPrivileges and single capability are untouched. The service unit
                     deliberately has no NoNewPrivileges (with SELinux enforcing, the exec of nft
                     under it was a denied nnp_transition and nft ran in the script's domain), and
                     the gate says so by name.

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
READER_HPP = ROOT / "agents" / "plugins" / "firewall" / "src" / "firewall_snapshot_reader.hpp"
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


# the pure row builder each macOS read hands its results to, and the variable each pf argv must
# land in: the builders take the results positionally, so two swapped results (all one type) keep
# every compile and pure test green while the rows describe the wrong reads
MACOS_BUILDERS = {
    "do_state_macos": r"macos_state_rows\( ?alf_res, pf_res, anchors_res, rules_res ?\)",
    "do_rules_macos": r"macos_rules_rows\( ?listapps_res, rules_res, anchors_res ?\)",
}
MACOS_RESULT_VAR = {"pfctl_info_argv": "pf_res", "pfctl_anchors_argv": "anchors_res",
                    "pfctl_rules_argv": "rules_res"}


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
        if not re.search(MACOS_BUILDERS[fn], text):
            out.append(f"{fn} no longer calls {MACOS_BUILDERS[fn]} with its results in that order "
                       "(the builder takes them positionally)")
        for builder in argvs:
            m = re.search(r"const auto (\w+) = run_bounded_subprocess\( ?yuzu::shared::sudo_wrap\( ?fq::"
                          + builder + r"\(\) ?\)", text)
            if m and m.group(1) != MACOS_RESULT_VAR[builder]:
                out.append(f"{fn} stores the fq::{builder}() read in {m.group(1)}, expected "
                           f"{MACOS_RESULT_VAR[builder]} (the builder takes the results positionally)")
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
    # two results swapped in the builder call (positional, one type), in each function
    (_mut(r"macos_state_rows\(alf_res, pf_res, anchors_res, rules_res\)",
          "macos_state_rows(alf_res, pf_res, rules_res, anchors_res)"), "no longer calls macos_state_rows"),
    (_mut(r"macos_rules_rows\(listapps_res, rules_res, anchors_res\)",
          "macos_rules_rows(listapps_res, anchors_res, rules_res)"), "no longer calls macos_rules_rows"),
    # a read stored in the other read's variable
    (_mut(r"const auto pf_res = (run_bounded_subprocess\(yuzu::shared::sudo_wrap\(fq::pfctl_info_argv)",
          r"const auto anchors_res = \1"), "stores the fq::pfctl_info_argv() read in anchors_res"),
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


# WinRuleRead field -> the expression (a regex) its own read feeds
WIN_VALUES = {
    "name": r"name_utf8",
    "enabled": r"enabled != VARIANT_FALSE",
    "dir": r"static_cast<int>\(dir\)",
    "action": r"static_cast<int>\(action\)",
    "profiles": r"profiles_mask",
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

    # each value reaches the field of its own name (the HRESULT assignments above pin the statuses;
    # these pin the values, which are all ints or longs and swap without a compile error)
    for field, expr in WIN_VALUES.items():
        if not re.search(r"\.%s = %s[,}]" % (field, expr), text):
            out.append(f"WinRuleRead::{field} is no longer assigned from its own property read "
                       f"({expr.replace(chr(92), '')})")

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
    (_mut(r"\.dir = static_cast<int>\(dir\),\s*\.action = static_cast<int>\(action\)",
          ".dir = static_cast<int>(action), .action = static_cast<int>(dir)"),
     "WinRuleRead::dir is no longer assigned"),
    (_mut(r"\.enabled = enabled != VARIANT_FALSE", ".enabled = true"), "WinRuleRead::enabled is no longer"),
    (_mut(r"\.profiles = profiles_mask", ".profiles = 0"), "WinRuleRead::profiles is no longer"),
    (_mut(r"\.name = name_utf8", '.name = ""'), "WinRuleRead::name is no longer"),
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


DIRECT_IPTABLES_PINS = (
    ("the iptables-installed guard that ends the ladder at `none`",
     r'if \( ?::access\("/usr/sbin/iptables", X_OK\) != 0 ?\) return std::nullopt;'),
    ("one shared deadline, computed once, from kAcqDeadline",
     r"const auto deadline = std::chrono::steady_clock::now\(\) \+ kAcqDeadline;"),
    ("the IPv4 pass then the IPv6 pass (`for (const bool ip6 : {false, true})`)",
     r"for \( ?const bool ip6 : \{false, true\} ?\)"),
    ("both absolute tool paths, IPv4 first",
     r'const char\* tool = ip6 \? "/usr/sbin/ip6tables" : "/usr/sbin/iptables";'),
    ("each family's own names file",
     r'read_xt_names\( ?ip6 \? "/proc/net/ip6_tables_names" : "/proc/net/ip_tables_names" ?\)'),
    ("the tool's presence checked once per family",
     r"const bool installed = ::access\(tool, X_OK\) == 0;"),
    ("the flavour starting as unknown (a version run that is not made gates nothing)",
     r"auto flavour = yuzu::firewall::IptablesFlavour::unknown;"),
    ("the one literal `<tool> --version` run, on the remaining deadline, only for an installed tool",
     r'if \( ?installed ?\) \{ const auto left = yuzu::firewall::remaining_ms\(deadline\); '
     r'if \( ?left\.count\(\) > 0 ?\) \{ const auto ver = run_bounded_subprocess\( ?\{tool, "--version"\}, '
     r"SubprocessOptions\{\.deadline = left\} ?\);"),
    ("the flavour parsed from the version run's own ran, exit, completeness and output",
     r"flavour = yuzu::firewall::parse_iptables_flavour\( ?ver\.tool_ran, ver\.exit_code == 0, "
     r"subprocess_complete\(ver\), ver\.output ?\);"),
    ("the plan decided by plan_iptables_family from the flavour, the names read and the tool's presence",
     r"plan_iptables_family\( ?flavour, names\.outcome, names\.text, installed ?\)"),
    ("every table of kIptablesDirectTables, by index",
     r"i < yuzu::firewall::kIptablesDirectTables\.size\(\)"),
    ("a table that is not to run, or has no time left, pushed as a read (never skipped)",
     r"if \( ?plan\.action\[i\] != Action::run \|\| left\.count\(\) <= 0 ?\) \{ "
     r"(?://[^;{}]*?)?reads\.push_back\( ?yuzu::firewall::iptables_unrun_read\("),
    ("the literal argv `{tool, \"-t\", table, \"-S\"}` on the remaining deadline",
     r'run_bounded_subprocess\( ?\{tool, "-t", std::string\{table\}, "-S"\}, '
     r"SubprocessOptions\{\.deadline = left\} ?\)"),
    ("the run classified with its own tool_ran, exit and completeness",
     r"classify_iptables_table_read\( ?ip6, table, res\.tool_ran, res\.exit_code == 0, "
     r"subprocess_complete\(res\), res\.output ?\)"),
)


def direct_iptables_problems(live):
    body = function_body(live, r"std::optional<std::vector<yuzu::firewall::IptablesTableRead>> "
                               r"read_iptables_tables\(\) ?(?=\{)")
    if body is None:
        return ["firewall_plugin.cpp no longer defines read_iptables_tables() (the root direct iptables read)"]
    text = squash(body)
    out = [f"read_iptables_tables no longer has {what}" for what, pat in DIRECT_IPTABLES_PINS
           if not re.search(pat, text)]
    if len(re.findall(r"run_bounded_subprocess\(", text)) != 2:
        out.append("read_iptables_tables spawns other than its `--version` run and its `-t <table> -S` run")
    return out


def linux_problems(plugin_src, reader_src):
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
        # the flag clamps the ufw and iptables rungs of the state ladder (the rules ladder has no
        # clamp there): straight after the held firewalld answer they run with `true` inside
        # `if (info.tables_seen)`, a block that returns, and with `false` only after it
        if fn == "do_state_linux" and held and not re.compile(
                r" ?if \( ?info\.tables_seen ?\) \{ if \( ?try_ufw_state\(ctx, ?true\) ?\) return; "
                r"if \( ?try_iptables_state\(ctx, ?true\) ?\) return; [^{}]*\breturn; \} "
                r"if \( ?try_ufw_state\(ctx, ?false\) ?\) return; "
                r"if \( ?try_iptables_state\(ctx, ?false\) ?\) return;").match(text, held.end()):
            out.append("do_state_linux no longer calls try_ufw_state and try_iptables_state clamped (`true`) "
                       "inside `if (info.tables_seen) { ... return; }` straight after the held firewalld "
                       "answer, and unclamped (`false`) only after that block (unclamped, either rung can "
                       "answer inactive beside tables the netlink read saw)")

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
        if len(re.findall(r"pending_rows\.push_back\(", text)) != 1:
            out.append("run_nft_probe no longer defers exactly the table-dump row "
                       '(info.pending_rows.push_back(nft_diag_row("table", ...)))')
        at_once = r'ctx\.write_output\( ?yuzu::firewall::nft_diag_row\( ?"table", table\.res ?\) ?\);'
        if len(re.findall(at_once, text)) != 1 or not re.search(
                r"if \( ?!table\.open_errno ?\) \{ if \( ?info\.tables_seen ?\) " + at_once +
                r" else info\.pending_rows\.push_back\( ?"
                r'yuzu::firewall::nft_diag_row\( ?"table", table\.res ?\) ?\); \}', text):
            out.append("run_nft_probe no longer writes the table-dump row at once exactly when a "
                       "table was seen and defers it otherwise, for a dump that ran (deferred with "
                       "a table seen, the snapshot rung's clamped unknown has no reason row; "
                       "written at once with none seen, an EPERM row sits beside a successful "
                       "snapshot read; a socket that did not open has no dump to report)")
        # info.tables_seen decides that branch and feeds every clamp: the whole file assigns it
        # once, after the table-failure branch, and that assignment can only turn it on.
        seen = (r"return std::nullopt; \} info\.tables_seen = info\.tables_seen \|\| "
                r"!yuzu::firewall::parse_nft_tables\(table\.buf\)\.empty\(\);")
        assigned = re.findall(r"(?<!bool )\btables_seen ?[|&^]?=(?!=)", squash(live))
        if len(assigned) != 1 or not re.search(seen, text):
            out.append("firewall_plugin.cpp no longer sets info.tables_seen in exactly one "
                       "place, in run_nft_probe after the table-failure branch, as "
                       "info.tables_seen || <the dump listed a table> (never set or cleared, the "
                       "snapshot, ufw and iptables rungs can answer inactive beside tables the "
                       "netlink read saw; set early, every read is clamped and an EPERM row sits "
                       "beside a snapshot answer)")
        opens = len(re.findall(r"for \( ?const auto& row : yuzu::firewall::nft_open_diag_rows\(open_errnos\) ?\) "
                               r"ctx\.write_output\(row\);", text))
        if opens != 2:
            out.append(f"run_nft_probe writes the socket-open diagnostic rows (error|fd_exhausted, "
                       f"error|nftables:socket:eperm) at {opens} sites, expected 2: they are never deferred")

    # the root direct iptables read: both families, the four tables of the pure list, the table list
    # gating each run, one deadline, one literal argv per run
    out += direct_iptables_problems(live)

    # each of the two clamped rungs hands its parameter to the pure function that applies the clamp
    for name, hand_over in (
            ("try_ufw_state", r"yuzu::firewall::gate_state_on_completeness\( ?complete && shaped, tables_seen,"),
            ("try_iptables_state", r"yuzu::firewall::iptables_direct_answer\( ?\*reads, tables_seen\)")):
        body = function_body(live, r"bool " + name + r"\(yuzu::CommandContext& ctx, bool tables_seen\) ?(?=\{)")
        if body is None or not re.search(hand_over, squash(body)):
            out.append(f"{name} no longer takes tables_seen and hands it to "
                       f"{'gate_state_on_completeness(complete && shaped, tables_seen, ...)' if name == 'try_ufw_state' else 'iptables_direct_answer(*reads, tables_seen)'} "
                       "(its own inactive would stand beside tables the netlink read saw)")
    # the member is named nowhere but in its pinned reads and its one assignment: a reference or a
    # pointer to it, or std::exchange on it, would clear it with no assignment by name
    named = re.sub(r"if \( ?info\.tables_seen ?\)|info\.tables_seen = info\.tables_seen \|\||"
                   r"linux_snapshot_rung\( ?read, info\.tables_seen,", "", squash(live))
    if re.search(r"[.>:]tables_seen\b", named):
        out.append("firewall_plugin.cpp names the tables_seen member outside `if (info.tables_seen)`, the "
                   "linux_snapshot_rung argument and its one assignment (a reference or a pointer to it, or "
                   "std::exchange on it, can clear the flag every clamp reads)")
    # ... and no function that holds the struct as a writable `info` assigns it as a whole
    for name in ("run_nft_probe", "try_nftables_state", "try_nftables_rules", "do_state_linux", "do_rules_linux"):
        body = function_body(live, r"\b" + name + r"\(yuzu::CommandContext& ctx[^)]*\) ?(?=\{)")
        if body is not None and re.search(r"(?<!NftFallthroughInfo )\binfo ?=(?!=)", squash(body)):
            out.append(f"{name} assigns `info` as a whole: a reset clears info.tables_seen, the held firewalld "
                       "answer and the deferred rows without naming them")

    reader = function_body(lexh.live_text(reader_src),
                           r"\[\[nodiscard\]\] inline std::expected<std::string, std::string>\s+"
                           r"read_fw_snapshot\(std::string_view socket_path, "
                           r"std::chrono::steady_clock::time_point deadline,\s*::uid_t peer_uid = 0\) ?(?=\{)")
    if reader is None:
        out.append("firewall_snapshot_reader.hpp no longer defines read_fw_snapshot(socket_path, deadline, peer_uid = 0)")
    else:
        text = squash(reader)
        for what, pat in (
                ("an AF_UNIX stream socket that is close-on-exec and non-blocking, owned by a ScopedFd",
                 r"yuzu::agent::ScopedFd sock\(::socket\(AF_UNIX, SOCK_STREAM \| SOCK_CLOEXEC \| SOCK_NONBLOCK, 0\)\)"),
                ("the peer-credential check (SO_PEERCRED)", r"SO_PEERCRED"),
                ("the refusal of a peer that is not the expected uid (root, by default)",
                 r"cred\.uid != peer_uid\) return std::unexpected\(std::string\{\"peer_not_root\"\}\)"),
                ("the socket path bound (a path that does not fit sun_path is an io_error)",
                 r"socket_path\.size\(\) >= sizeof\(addr\.sun_path\)\) return std::unexpected\(std::string\{\"io_error\"\}\)"),
                ("the deadline (the time left from remaining_ms, a timeout token)",
                 r"const auto left = remaining_ms\(deadline\);"),
                ("the poll before every read", r"::poll\("),
                ("the poll timeout clamped to INT_MAX (a far deadline must not wrap to an unbounded poll)",
                 r"::poll\(&pfd, 1, static_cast<int>\(std::min<std::chrono::milliseconds::rep>\(left\.count\(\), INT_MAX\)\)\)"),
                ("the size cap", r"text\.size\(\) > kFwSnapshotMaxBytes"),
                ("a retry of EINTR after the poll", r"if \( ?ready < 0 ?\) \{ if \( ?errno == EINTR ?\) continue;"),
                ("a retry of EINTR after the read", r"errno == EINTR \|\| errno == EAGAIN")):
            if not re.search(pat, text):
                out.append(f"read_fw_snapshot no longer has {what}")
        if len(re.findall(r"return std::unexpected\(std::string\{\"timeout\"\}\);", text)) != 2:
            out.append("read_fw_snapshot no longer has the timeout token at both of its waits (a deadline already "
                       "past, and a poll that ran out)")
        for pat in WRITE_CALLS:
            if re.search(pat, text):
                out.append("read_fw_snapshot writes to the socket (/%s/): the agent sends nothing, the "
                           "broker reads no input" % pat)
        if "::close(" in text:
            out.append("read_fw_snapshot closes a descriptor by hand: ScopedFd is the single release path")
    if "read_fw_snapshot(std::string_view" in live:
        out.append("firewall_plugin.cpp defines its own read_fw_snapshot again: the plugin and its tests share the "
                   "one in firewall_snapshot_reader.hpp")
    if re.search(r"remaining_ms\(std::chrono::steady_clock::time_point", live):
        out.append("firewall_plugin.cpp defines its own remaining_ms again: the time left until a deadline is "
                   "yuzu::firewall::remaining_ms in firewall_snapshot_reader.hpp, which the reader and the netlink "
                   "legs share")
    if not re.search(r"\[\[nodiscard\]\] inline std::chrono::milliseconds\s+remaining_ms\(std::chrono::steady_clock::time_point "
                     r"deadline\) noexcept", lexh.live_text(reader_src)):
        out.append("firewall_snapshot_reader.hpp no longer defines remaining_ms(deadline)")
    if "linux_snapshot_answer(" in live:
        out.append("firewall_plugin.cpp calls linux_snapshot_answer itself: a snapshot is decided through "
                   "linux_snapshot_rung, which takes a second snapshot before it answers inactive")
    if not re.search(r"static_assert\( ?yuzu::firewall::kFwSnapshotSocketPath\.size\(\) < sizeof\(sockaddr_un::sun_path\)", live):
        out.append("firewall_plugin.cpp no longer static_asserts that the broker socket path fits sockaddr_un::sun_path")
    helper = function_body(live, r"\[\[nodiscard\]\] std::expected<std::string, std::string>\s+"
                                 r"read_fw_snapshot_via_helper\(std::chrono::steady_clock::time_point deadline\) ?(?=\{)")
    if helper is None:
        out.append("firewall_plugin.cpp no longer defines read_fw_snapshot_via_helper(deadline)")
    else:
        text = squash(helper)
        for what, pat in (
                ("the silent decline for root, under NoNewPrivileges (sudo cannot elevate there) and when the helper "
                 "file is not there (a host the installer did not provision makes no sudo call)",
                 r"if \( ?::geteuid\( ?\) == 0 \|\| privilege_refusal\( ?\) \|\| "
                 r"::access\(std::string\{fq::kFwHelperPath\}\.c_str\(\), X_OK\) != 0 ?\) "
                 r"return std::unexpected\(std::string\{\}\);"),
                ("the run's budget: what is left of the rung's one deadline, a token and no run once it is spent",
                 r"const auto left = yuzu::firewall::remaining_ms\(deadline\); if \( ?left\.count\(\) <= 0 ?\) "
                 r"return std::unexpected\(std::string\{\"helper:timeout\"\}\);"),
                ("the sudo-wrapped helper snapshot word as its only argv, with the time left and a cap of twice the "
                 "broker's cut, decided by helper_snapshot_outcome",
                 r"return yuzu::firewall::helper_snapshot_outcome\( ?run_bounded_subprocess\( ?"
                 r"yuzu::shared::sudo_wrap\(\{std::string\{fq::kFwHelperPath\}, \"snapshot\"\}\), "
                 r"SubprocessOptions\{\.deadline = left, "
                 r"\.output_cap_bytes = 2 \* yuzu::firewall::kFwSnapshotMaxBytes\}\)\);")):
            if not re.search(pat, text):
                out.append(f"read_fw_snapshot_via_helper no longer has {what}")
        if "kAcqDeadline" in text:
            out.append("read_fw_snapshot_via_helper starts a deadline of its own: both reads of the rung share one")
        if "merge_stderr" in text or "sudo_runner(" in text:
            out.append("read_fw_snapshot_via_helper merges stderr: sudo's message would be read as listing")
        if "exit_code" in text or "write_output" in text or "subprocess_complete" in text:
            out.append("read_fw_snapshot_via_helper decides on an exit code itself or writes a row: "
                       "helper_snapshot_outcome is the one rule")
    snapshot = function_body(live, r"bool try_snapshot\(yuzu::CommandContext& ctx, const NftFallthroughInfo& info,\s*"
                                   r"yuzu::firewall::FwReadAction action\) ?(?=\{)")
    if snapshot is None:
        out.append("firewall_plugin.cpp no longer defines try_snapshot(ctx, info, action)")
    else:
        text = squash(snapshot)
        if len(re.findall(r"std::chrono::steady_clock::now\(\) \+ kAcqDeadline", text)) != 1 or not re.search(
                r"const auto deadline = std::chrono::steady_clock::now\(\) \+ kAcqDeadline;", text):
            out.append("try_snapshot no longer computes ONE deadline, now + kAcqDeadline, for the whole rung (the "
                       "second read of an inactive answer shares it, so the worst case does not grow)")
        if not re.search(r"auto reply = yuzu::firewall::read_fw_snapshot\( ?yuzu::firewall::kFwSnapshotSocketPath, "
                         r"deadline ?\);", text):
            out.append("try_snapshot no longer reads the broker with read_fw_snapshot(kFwSnapshotSocketPath, "
                       "deadline) and no uid (the socket must have been made by root)")
        if not re.search(r"if \( ?!reply && reply\.error\(\)\.empty\(\) ?\) \{[^{}]*return read_fw_snapshot_via_helper\(deadline\);", text):
            out.append("try_snapshot no longer tries the helper transport only when the socket is absent "
                       "(an empty token): a reported socket failure must not fall to sudo")
        if not re.search(r"yuzu::firewall::linux_snapshot_rung\( ?read, info\.tables_seen, info\.firewalld_running, "
                         r"action ?\)", text):
            out.append("try_snapshot no longer decides through linux_snapshot_rung(read, info.tables_seen, "
                       "info.firewalld_running, action): the rung takes a second snapshot before it answers inactive "
                       "and holds firewalld's answer unless a complete read shows an active ruleset")
        if not re.search(r"for \( ?const auto& row : rung\.rows ?\) ctx\.write_output\(row\); return rung\.answered;", text):
            out.append("try_snapshot no longer writes the rung's rows and returns its answer")
    if len(re.findall(r"else the root snapshot broker over AF_UNIX \(packaged systemd socket\)", squash(live))) != 2:
        out.append("the Linux state and rules descriptors no longer both name the root snapshot broker")
    return out


def _lmut(pattern, repl, count=1):
    return lambda raw: re.subn(pattern, repl, raw, count=count, flags=re.S)


_HELD_ROWS = r"\{\s*for \(const auto& row : firewalld\.rows\)\s*ctx\.write_output\(row\);\s*return;\s*\}"

LINUX_MUTATIONS = [
    # the root direct iptables read: nat dropped by an off-by-one, the IPv6 pass dropped, a swapped tool
    # the flavour: the version run dropped, parsed from the wrong run result, gating handed the wrong flavour
    (_lmut(r"const auto ver = run_bounded_subprocess\(\{tool, \"--version\"\},\s*SubprocessOptions\{\.deadline = left\}\);",
           'const auto ver = run_bounded_subprocess({tool, "-V"}, SubprocessOptions{.deadline = left});'),
     "read_iptables_tables no longer has the one literal"),
    (_lmut(r"ver\.tool_ran, ver\.exit_code == 0", "true, ver.exit_code == 0"),
     "read_iptables_tables no longer has the flavour parsed"),
    (_lmut(r"plan_iptables_family\(flavour, names\.outcome", "plan_iptables_family(yuzu::firewall::IptablesFlavour::legacy, names.outcome"),
     "read_iptables_tables no longer has the plan decided"),
    (_lmut(r"auto flavour = yuzu::firewall::IptablesFlavour::unknown;", "auto flavour = yuzu::firewall::IptablesFlavour::legacy;"),
     "read_iptables_tables no longer has the flavour starting as unknown"),
    (_lmut(r"i < yuzu::firewall::kIptablesDirectTables\.size\(\)",
           "i + 1 < yuzu::firewall::kIptablesDirectTables.size()"), "read_iptables_tables no longer has every table"),
    (_lmut(r"for \(const bool ip6 : \{false, true\}\)", "for (const bool ip6 : {false})"),
     "read_iptables_tables no longer has the IPv4 pass then the IPv6 pass"),
    (_lmut(r'ip6 \? "/usr/sbin/ip6tables" : "/usr/sbin/iptables"', 'ip6 ? "/usr/sbin/iptables" : "/usr/sbin/ip6tables"'),
     "read_iptables_tables no longer has both absolute tool paths"),
    (_lmut(r'"/proc/net/ip6_tables_names" : "/proc/net/ip_tables_names"',
           '"/proc/net/ip_tables_names" : "/proc/net/ip6_tables_names"'),
     "read_iptables_tables no longer has each family's own names file"),
    (_lmut(r'\{tool, "-t", std::string\{table\}, "-S"\}', '{tool, "-S", std::string{table}, "-t"}'),
     "read_iptables_tables no longer has the literal argv"),
    (_lmut(r"SubprocessOptions\{\.deadline = left\}\);\s*reads", "SubprocessOptions{.deadline = kAcqDeadline});\n reads"),
     "read_iptables_tables no longer has the literal argv"),
    (_lmut(r"res\.tool_ran, res\.exit_code == 0", "true, res.exit_code == 0"),
     "read_iptables_tables no longer has the run classified"),
    (_lmut(r"plan\.action\[i\] != Action::run \|\| left\.count\(\) <= 0", "plan.action[i] != Action::run"),
     "read_iptables_tables no longer has a table that is not to run"),
    (_lmut(r"if \(::access\(\"/usr/sbin/iptables\", X_OK\) != 0\)\s*return std::nullopt;", ""),
     "read_iptables_tables no longer has the iptables-installed guard"),
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
    # the guard inverted: a row written at once with no table seen, deferred with one seen
    (_lmut(r'if \(info\.tables_seen\)(\s*ctx\.write_output\(yuzu::firewall::nft_diag_row\("table", table\.res\)\);)',
           r'if (!info.tables_seen)\1'), "writes the table-dump row at once exactly when a table was seen"),
    # the guard removed: the row always deferred, so a clamped unknown has no reason row
    (_lmut(r'if \(info\.tables_seen\)\s*ctx\.write_output\(yuzu::firewall::nft_diag_row\("table", table\.res\)\);\s*else\s*'
           r'(info\.pending_rows\.push_back\(yuzu::firewall::nft_diag_row\("table", table\.res\)\);)', r'\1'),
     "writes the table-dump row at once exactly when a table was seen"),
    # the socket guard dropped: a socket that did not open writes a row for a dump that never ran
    (_lmut(r"if \(!table\.open_errno\) \{(\s*if \(info\.tables_seen\))", r"if (true) {\1"),
     "writes the table-dump row at once exactly when a table was seen"),
    # info.tables_seen never set: nothing is clamped, a re-run's table-dump row is deferred again
    (_lmut(r"\n\s*info\.tables_seen = info\.tables_seen \|\| "
           r"!yuzu::firewall::parse_nft_tables\(table\.buf\)\.empty\(\);", ""),
     "no longer sets info.tables_seen in exactly one place"),
    # ... set before the table dump was looked at: every read is clamped, no row is deferred
    (_lmut(r"(const auto table = take\(nft::kNftMsgGettable, table_deadline\);)",
           r"\1 info.tables_seen = true;"),
     "no longer sets info.tables_seen in exactly one place"),
    # ... cleared before the snapshot rung: its clamp and the clamp of ufw and iptables are lost
    (_lmut(r"(if \(try_snapshot\(ctx, info, yuzu::firewall::FwReadAction::state\)\))",
           r"info.tables_seen = false; \1"),
     "no longer sets info.tables_seen in exactly one place"),
    # ... cleared with no assignment by name: std::exchange on the member, then a reference to it
    (_lmut(r"(if \(try_snapshot\(ctx, info, yuzu::firewall::FwReadAction::state\)\))",
           r"(void)std::exchange(info.tables_seen, false); \1"),
     "names the tables_seen member outside"),
    (_lmut(r"(if \(try_snapshot\(ctx, info, yuzu::firewall::FwReadAction::state\)\))",
           r"{ bool& ts = info.tables_seen; ts = false; } \1"),
     "names the tables_seen member outside"),
    # ... and the whole struct reset
    (_lmut(r"(if \(try_snapshot\(ctx, info, yuzu::firewall::FwReadAction::state\)\))",
           r"info = NftFallthroughInfo{}; \1"),
     "do_state_linux assigns `info` as a whole"),
    # the state dispatcher no longer reads the flag for ufw and iptables: both run unclamped
    (_lmut(r"if \(info\.tables_seen\) \{(?=(?:\s*//[^\n]*)*\s*if \(try_ufw_state)", "if (false) {"),
     "no longer calls try_ufw_state and try_iptables_state clamped"),
    # ... the clamp argument of the ufw rung, then of the iptables rung, turned off
    (_lmut(r"try_ufw_state\(ctx, /\*tables_seen=\*/true\)", "try_ufw_state(ctx, /*tables_seen=*/false)"),
     "no longer calls try_ufw_state and try_iptables_state clamped"),
    (_lmut(r"try_iptables_state\(ctx, /\*tables_seen=\*/true\)", "try_iptables_state(ctx, /*tables_seen=*/false)"),
     "no longer calls try_ufw_state and try_iptables_state clamped"),
    # ... the clamped block falls through to the unclamped rungs
    (_lmut(r'(ctx\.write_output\("ruleset\|unknown"\);[^\n]*\n\s*)return;'
           r"(\s*\}\s*(?://[^\n]*\s*)*if \(try_ufw_state\(ctx, /\*tables_seen=\*/false\)\))", r"\1\2"),
     "no longer calls try_ufw_state and try_iptables_state clamped"),
    # ... an unclamped rung ahead of the block
    (_lmut(r"(if \(info\.tables_seen\) \{(?:\s*//[^\n]*)*\s*if \(try_ufw_state)",
           r"if (try_ufw_state(ctx, false)) return; \1"),
     "no longer calls try_ufw_state and try_iptables_state clamped"),
    # a clamped rung no longer hands the flag to the pure function (ufw, then iptables)
    (_lmut(r"(complete && shaped, )tables_seen(, yuzu::firewall::parse_ufw_status)", r"\1false\2"),
     "try_ufw_state no longer takes tables_seen and hands it to gate_state_on_completeness"),
    (_lmut(r"(iptables_direct_answer\(\*reads, )tables_seen\)", r"\1false)"),
     "try_iptables_state no longer takes tables_seen and hands it to iptables_direct_answer"),
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
    # the snapshot is decided without the pure rung, or its held-firewalld input or its answer is bypassed
    (_lmut(r"linux_snapshot_rung\(read, info\.tables_seen, info\.firewalld_running, action\)",
           "linux_snapshot_rung(read, info.tables_seen, false, action)"), "decides through linux_snapshot_rung"),
    (_lmut(r"linux_snapshot_rung\(read, info\.tables_seen, info\.firewalld_running, action\)",
           "linux_snapshot_answer(*snapshot, info.tables_seen, action)"), "decides through linux_snapshot_rung"),
    (_lmut(r"return rung\.answered;", "return true;"), "writes the rung's rows and returns its answer"),
    (_lmut(r"for \(const auto& row : rung\.rows\)\s*ctx\.write_output\(row\);", ""),
     "writes the rung's rows and returns its answer"),
    # a second deadline for the second read, or a fresh one for the helper run
    (_lmut(r"(const auto deadline = std::chrono::steady_clock::now\(\) \+ kAcqDeadline;)",
           r"\1 (void)(std::chrono::steady_clock::now() + kAcqDeadline);"), "ONE deadline"),
    (_lmut(r"return read_fw_snapshot_via_helper\(deadline\);",
           "return read_fw_snapshot_via_helper(std::chrono::steady_clock::now() + kAcqDeadline);"),
     "helper transport only when the socket is absent"),
    (_lmut(r"SubprocessOptions\{\.deadline = left,", "SubprocessOptions{.deadline = kAcqDeadline,"),
     "the sudo-wrapped helper snapshot word as its only argv"),
    (_lmut(r"if \(left\.count\(\) <= 0\)\s*return std::unexpected\(std::string\{\"helper:timeout\"\}\);", ""),
     "the run's budget"),
    # the firewalld rung writes a row itself, or decides without the pure functions
    (_lmut(r"(const auto q = query_firewalld\(\);)", r'\1 write_output("x");'), "firewalld_rung writes a row itself"),
    (_lmut(r"yuzu::firewall::firewalld_read\(q\.reachable, q\.services_complete\)",
           "(q.reachable ? yuzu::firewall::FirewalldRead::complete : yuzu::firewall::FirewalldRead::absent)"),
     "decides through firewalld_read"),
    # the broker is read with a uid, or not through the shared reader at all
    (_lmut(r"yuzu::firewall::kFwSnapshotSocketPath, deadline\);", "yuzu::firewall::kFwSnapshotSocketPath, deadline, 1000);"),
     "with read_fw_snapshot(kFwSnapshotSocketPath"),
    (_lmut(r"yuzu::firewall::kFwSnapshotSocketPath, deadline\);", 'std::string_view{"/run/other.sock"}, deadline);'),
     "with read_fw_snapshot(kFwSnapshotSocketPath"),
    # the plugin defines a remaining_ms of its own again
    (_lmut(r"(// The socket client itself is)",
           r"[[nodiscard]] std::chrono::milliseconds remaining_ms(std::chrono::steady_clock::time_point d) noexcept { return {}; }\n\1"),
     "its own remaining_ms"),
    # the plugin defines a reader of its own again, or loses the path bound
    (_lmut(r"(// The socket client itself is)", r"[[nodiscard]] std::expected<std::string, std::string> x() { return read_fw_snapshot(std::string_view{\"\"}); }\n\1"),
     "its own read_fw_snapshot"),
    (_lmut(r"static_assert\(yuzu::firewall::kFwSnapshotSocketPath\.size\(\) < sizeof\(sockaddr_un::sun_path\),", "static_assert(true,"),
     "static_asserts that the broker socket path fits"),
    # the helper transport: the decision, the guards, the cap, the stderr
    (_lmut(r"return yuzu::firewall::helper_snapshot_outcome\(run_bounded_subprocess\(", "return std::unexpected(std::string{}); (run_bounded_subprocess("),
     "helper snapshot word as its only argv"),
    (_lmut(r"\|\| privilege_refusal\(\) \|\| ::access", "|| ::access"),
     "silent decline for root, under NoNewPrivileges"),
    (_lmut(r"if \(::geteuid\(\) == 0 \|\| privilege_refusal\(\)", "if (privilege_refusal()"),
     "silent decline for root, under NoNewPrivileges"),
    (_lmut(r"\s*\|\| ::access\(std::string\{fq::kFwHelperPath\}\.c_str\(\), X_OK\) != 0\)", ")"),
     "when the helper file is not there"),
    (_lmut(r"X_OK\) != 0\)\s*return std::unexpected\(std::string\{\}\);", "X_OK) != 0) return std::unexpected(std::string{\"x\"});"),
     "silent decline for root"),
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


# The shared socket client, in its own header (the plugin and its tests run the same code)
READER_MUTATIONS = [
    # no peer check
    (_lmut(r"if \(cred\.uid != peer_uid\)\s*return std::unexpected\(std::string\{\"peer_not_root\"\}\);", ""),
     "refusal of a peer that is not the expected uid"),
    (_lmut(r"cred\.uid != peer_uid", "cred.uid != 1"), "refusal of a peer that is not the expected uid"),
    (_lmut(r"cred\.uid != peer_uid", "cred.uid == peer_uid"), "refusal of a peer that is not the expected uid"),
    (_lmut(r"SOL_SOCKET, SO_PEERCRED", "SOL_SOCKET, SO_PASSCRED"), "peer-credential check"),
    # blocking, inheritable socket
    (_lmut(r"SOCK_STREAM \| SOCK_CLOEXEC \| SOCK_NONBLOCK", "SOCK_STREAM"), "close-on-exec and non-blocking"),
    # a path that does not fit
    (_lmut(r"if \(socket_path\.size\(\) >= sizeof\(addr\.sun_path\)\)\s*return std::unexpected\(std::string\{\"io_error\"\}\);", ""),
     "the socket path bound"),
    # no deadline, no timeout token, no poll
    (_lmut(r"const auto left = remaining_ms\(deadline\);", "const auto left = std::chrono::milliseconds{1000};"),
     "the deadline"),
    (_lmut(r"if \(left\.count\(\) <= 0\)\s*return std::unexpected\(std::string\{\"timeout\"\}\);",
           'if (left.count() <= 0) return std::unexpected(std::string{"io_error"});'), "the timeout token at both"),
    (_lmut(r"if \(ready == 0\)\s*return std::unexpected\(std::string\{\"timeout\"\}\);",
           'if (ready == 0) return std::unexpected(std::string{"io_error"});'), "the timeout token at both"),
    (_lmut(r"::poll\(&pfd, 1, static_cast<int>\(std::min<std::chrono::milliseconds::rep>\(left\.count\(\), INT_MAX\)\)\)",
           "1"), "the poll before every read"),
    # a far deadline wraps to a negative poll timeout, which poll() reads as unbounded
    (_lmut(r"static_cast<int>\(std::min<std::chrono::milliseconds::rep>\(left\.count\(\), INT_MAX\)\)",
           "static_cast<int>(left.count())"), "clamped to INT_MAX"),
    # unbounded
    (_lmut(r"if \(text\.size\(\) > kFwSnapshotMaxBytes\)\s*return std::unexpected\(std::string\{\"oversized\"\}\);", ""),
     "the size cap"),
    # writes to the socket
    (_lmut(r"(char buf\[16 \* 1024\];)", r"\1 (void)::write(sock.get(), &buf[0], 1);"), "writes to the socket"),
    (_lmut(r"(char buf\[16 \* 1024\];)", r"\1 (void)::send(sock.get(), &buf[0], 1, 0);"), "writes to the socket"),
    # a hand-written close beside the ScopedFd
    (_lmut(r"(char buf\[16 \* 1024\];)", r"\1 ::close(sock.get());"), "closes a descriptor by hand"),
    # no retry of EINTR
    (_lmut(r"if \(ready < 0\) \{\s*if \(errno == EINTR\)\s*continue;\s*return",
           'if (ready < 0) { return'), "a retry of EINTR"),
]


class LinuxSnapshotWiring(unittest.TestCase):
    def setUp(self):
        self.cpp = PLUGIN_CPP.read_text(encoding="utf-8")
        self.reader = READER_HPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = linux_problems(self.cpp, self.reader)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (mutate, expected) in enumerate(LINUX_MUTATIONS, 1):
            with self.subTest(mutation=i, expected=expected):
                mutated, n = mutate(self.cpp)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = linux_problems(mutated, self.reader)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertTrue(any(expected in m for m in p), f"expected {expected!r} in {p}")

    def test_the_flavour_gate_is_pinned(self):
        hpp = PARSERS_HPP.read_text(encoding="utf-8")
        gate = r"if \(tool_installed && flavour != IptablesFlavour::legacy\) \{\s*plan\.action\.fill\(IptablesTableAction::run\);"
        parse = (r"if \(!tool_ran \|\| !exit_ok \|\| !complete\)\s*return IptablesFlavour::unknown;.*?"
                 r"if \(nft == legacy\)\s*return IptablesFlavour::unknown;")
        for what, pat in (("the shim and unknown flavours running every table", gate),
                          ("a version run that failed, timed out or printed neither marker reading unknown", parse)):
            self.assertTrue(re.search(pat, hpp, re.S), f"firewall_parsers.hpp no longer has {what}")
        for what, pat, repl in (
                ("unknown flavour gated like legacy", r"flavour != IptablesFlavour::legacy", "flavour == IptablesFlavour::nf_tables"),
                ("a shim gated like legacy", r"flavour != IptablesFlavour::legacy", "false"),
                ("a failed version run read as a flavour", r"if \(!tool_ran \|\| !exit_ok \|\| !complete\)", "if (false)"),
                ("both markers read as a flavour", r"if \(nft == legacy\)", "if (false)")):
            mutated, n = re.subn(pat, repl, hpp, count=1)
            self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
            self.assertFalse(re.search(gate, mutated, re.S) and re.search(parse, mutated, re.S),
                             f"{what} was not detected")

    def test_the_direct_table_list_is_pinned(self):
        hpp = PARSERS_HPP.read_text(encoding="utf-8")
        pat = r'kIptablesDirectTables\{"filter", "raw", "mangle",\s*"nat"\};'
        self.assertTrue(re.search(pat, hpp), "kIptablesDirectTables is no longer filter, raw, mangle, nat")
        decl = re.search(pat, hpp).group(0)
        for dropped in ('"filter", ', '"raw", ', '"mangle",', '"nat"'):
            mutated = hpp.replace(decl, decl.replace(dropped, "", 1), 1)
            self.assertNotEqual(mutated, hpp, "mutation changed nothing (stale pattern)")
            self.assertFalse(re.search(pat, mutated), f"dropping {dropped} was not detected")

    def test_reader_mutations_are_caught(self):
        for i, (mutate, expected) in enumerate(READER_MUTATIONS, 1):
            with self.subTest(mutation=i, expected=expected):
                mutated, n = mutate(self.reader)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = linux_problems(self.cpp, mutated)
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
                "ProtectSystem": "strict", "ReadOnlyPaths": "/run", "ProtectHome": "true",
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
    # NoNewPrivileges is deliberately absent from the service: with SELinux enforcing, the exec
    # of nft under it was a denied nnp_transition and nft ran in the script's domain; the agent
    # unit keeps it (checked below)
    if "NoNewPrivileges" in parse_unit(sources["service"]).get("Service", {}):
        out.append("the service unit sets NoNewPrivileges: with SELinux enforcing, the exec of "
                   "nft under it was a denied nnp_transition and nft ran in the script's domain "
                   "(ADR-3007 clause 7)")
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
    # the three fixed reads, each by its literal path: nft for nf_tables, and each legacy family's save tool by
    # its own name (never the alternatives-selected iptables, which on the nft backend is the shim and lists
    # nothing the nft section does not, and never a tool that loads a module or takes a lock)
    for line in ("NFT=/usr/sbin/nft", "XT4=/usr/sbin/iptables-legacy-save", "XT6=/usr/sbin/ip6tables-legacy-save",
                 "snap_one 'nft -a list ruleset' \"$NFT\" -a list ruleset",
                 "snap_xt 'iptables-legacy-save' \"$XT4\" /proc/net/ip_tables_names",
                 "snap_xt 'ip6tables-legacy-save' \"$XT6\" /proc/net/ip6_tables_names"):
        if line not in [l.strip() for l in code.splitlines()]:
            out.append(f"yuzu-fw-snapshot.sh no longer has the line: {line}")
    if re.search(r"/usr/sbin/(?:iptables|ip6tables)(?![-\w])|\biptables -S\b|\bip6tables -S\b|(?<![-\w])-S(?![-\w])", code):
        out.append("yuzu-fw-snapshot.sh runs the alternatives-selected iptables or `-S` (the nft shim, the filter table "
                   "only): the legacy save tools are read by name")
    for what, pat in (("modprobe", r"\bmodprobe\b"), ("insmod", r"\binsmod\b"), ("a lock file", r"xtables\.lock|\bflock\b"),
                      ("a file test of the tool's identity", r" -ef "), ("the retired marker", r"\[unloaded\]"),
                      ("a file write", r"(?<![<>&0-9])>{1,2}\s*[^&\s/][^\s]*|>\s*/(?!dev/null)")):
        if re.search(pat, code):
            out.append(f"yuzu-fw-snapshot.sh has {what}: for the tables the kernel lists, the legacy save reads load no module, take no lock and write no file")
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
    (_set("script", "XT4=/usr/sbin/iptables-legacy-save", "XT4=/usr/sbin/iptables"), "XT4=/usr/sbin/iptables-legacy-save"),
    (_set("script", "XT6=/usr/sbin/ip6tables-legacy-save", "XT6=/usr/sbin/ip6tables-save"), "XT6=/usr/sbin/ip6tables-legacy-save"),
    (_set("script", "NFT=/usr/sbin/nft\n", "NFT=/usr/sbin/nft\nIPT=/usr/sbin/iptables\n"), "alternatives-selected iptables"),
    (_set("script", "snap_xt 'iptables-legacy-save' \"$XT4\" /proc/net/ip_tables_names",
          "snap_xt 'iptables-legacy-save' \"$XT4\" /proc/net/ip6_tables_names"), "snap_xt 'iptables-legacy-save'"),
    (_set("script", "snap_xt 'ip6tables-legacy-save' \"$XT6\" /proc/net/ip6_tables_names\n",
          "snap_xt 'ip6tables-legacy-save' \"$XT6\" /proc/net/ip6_tables_names\nmodprobe ip_tables\n"), "has modprobe"),
    (_set("script", "snap_one 'nft -a list ruleset' \"$NFT\" -a list ruleset", "snap_one 'nft -a list ruleset' \"$NFT\" -S"),
     "snap_one 'nft -a list ruleset'"),
    (_set("script", "host_snapshot\n", "echo x > /run/xtables.lock\nhost_snapshot\n"), "a lock file"),
    (_set("script", "host_snapshot\n", "echo x > /tmp/out\nhost_snapshot\n"), "a file write"),
    (_set("service", "ReadOnlyPaths=/run", "ReadWritePaths=-/run/xtables.lock"), "ReadOnlyPaths"),
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

    # What `systemd-analyze verify` prints about a directive systemd does not know or cannot parse. The bare
    # `Invalid` is safe to keep because findings() looks only at the lines that name the unit under test.
    VERIFY_BAD = re.compile(r"Unknown (?:key|section|lvalue)|Failed to parse|Invalid argument|Unknown assignment|"
                            r"Invalid|unsupported|not a valid")

    @classmethod
    def findings(cls, output, path):
        """The lines of a `verify` run that are about `path` (its file path or its unit name) and carry a bad
        word. verify also prints lines about other units on the host (a foreign unit's PIDFile warning shows
        up in every run), and one of those that happens to contain `Invalid` is not this unit's defect."""
        own = (str(path), Path(path).name)
        return [l for l in output.splitlines() if any(o in l for o in own) and cls.VERIFY_BAD.search(l)]

    def test_verify_findings_are_only_the_lines_about_the_unit_under_test(self):
        path = BROKER_FILES["service"]
        output = "\n".join([
            "/usr/lib/systemd/system/other.service:7: PIDFile= references a path below legacy directory /var/run/, "
            "updating /var/run/x.pid -> /run/x.pid; please update the unit file accordingly. Invalid",
            f"{path}:12: Unknown key name 'Bogus' in section 'Service', ignoring.",
            f"{path.name}: Failed to parse the thing",
            "other.socket: Invalid argument",
        ])
        self.assertEqual(self.findings(output, path),
                         [f"{path}:12: Unknown key name 'Bogus' in section 'Service', ignoring.",
                          f"{path.name}: Failed to parse the thing"])
        self.assertEqual(self.findings("other.service:1: Invalid\n", path), [])

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze is not installed")
    def test_systemd_accepts_the_directives_of_the_units(self):
        # Only a directive systemd does not know or cannot parse fails this: the units refer to a
        # script, an agent unit and a group that do not exist on a build host, and verify says so.
        for name in ("socket", "service", "agent"):
            r = subprocess.run(["systemd-analyze", "verify", "--man=no", str(BROKER_FILES[name])],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(self.findings(r.stdout + r.stderr, BROKER_FILES[name]), [], name)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
