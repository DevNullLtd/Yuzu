#!/usr/bin/env python3
"""ADR-3008 lexical gate: how plugin code may reach a blocking OS call.

Over agents/plugins/**/*.{cpp,hpp,mm}, with comments and string/char literals blanked:
  (a) no direct call of a Windows API that agent-core reads for plugins (BANNED, the two WTS reads
      in their unsuffixed, A, W and Ex spellings); GetAdaptersAddresses stays allowed in the
      firewall plugin only;
  (b) no include of the agent-core driver bounded_single_flight.hpp, and no use of a *_for_test
      seam declared in agents/core/include/yuzu/agent/win_*.hpp or proc_snapshot_read.hpp;
  (c) the per-file count of `bounded_call*(` sites equals GRANDFATHERED. A new file or a higher
      count fails; a lower count fails until the table is lowered, so the freeze only ratchets down;
  (d) each WIRED site keeps the text that handles a bounded answer, in shells no unit test reaches:
      shares' unanswered page; users' "did not complete" returns, its declaration of a failed or
      cut read, its return on a refused session listing, and the tool budget's deadline, settlement
      and end-of-run status on the per-account tools; the status device_identity and network_config
      forward; and the cause filesystem_posture puts on its VSS marks;
  (e) no `.detach(`: a thread detached by plugin code can outlive the plugin.

Stated limits: a wrapper whose name does not start with `bounded_call` is not seen, nor is a call
with explicit template arguments (`bounded_call_ex<F>(`); (a) matches the listed spellings only;
(b) sees a direct include, not a transitive one; (e) does not see `->detach(`. Lexical only; the
self-test plants each violation in memory and requires it flagged.
"""
import functools
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGINS = ROOT / "agents" / "plugins"

BANNED = (
    "NetShareEnum", "NetUserEnum", "NetLocalGroupGetMembers", "NetSessionEnum",
    "NetGetJoinInformation", "WTSEnumerateSessions(?:Ex)?[AW]?",
    "WTSQuerySessionInformation(?:Ex)?[AW]?", "CreateVssBackupComponents", "GetAdaptersAddresses",
)
ALLOWED = {("firewall/src/firewall_plugin.cpp", "GetAdaptersAddresses")}

# Frozen plugin-local sites, relative to agents/plugins: definitions of bounded_call* wrappers
# count too. Lower a number when a site moves to agent-core; never raise one (ADR-3008 D7 repeats
# this table).
GRANDFATHERED = {
    "disk_space/src/disk_space_plugin.cpp": 1,
    "discovery/src/discovery_plugin.cpp": 1,
    "echo/src/echo_mapdrive_collector.cpp": 1,
    "echo/src/echo_registry_source.cpp": 2,
    "file_search/src/file_search_shell.cpp": 1,
    "file_search/src/file_search_win.cpp": 1,
    "installed_apps/src/installed_apps_pkgdb_read.hpp": 1,
    "ioc/src/ioc_plugin.cpp": 1,
    "power_health/src/power_health_plugin.cpp": 10,
    "printing/src/printing_plugin.cpp": 3,
    "processes/src/processes_plugin.cpp": 2,
    "procfetch/src/procfetch_plugin.cpp": 1,
    "windows_updates/src/windows_updates_plugin.cpp": 1,
}

# What may lie between a users read and its handling: anything but the next users read.
BEFORE_NEXT_USERS_READ = (r"(?:(?!\bread_(?:wts_sessions|local_users|local_group_members)\s*\()"
                          r"[\s\S])*?")

# (d) (file, what starts a site, what must follow it, how many sites there are).
WIRED = (
    ("shares/src/shares_win.cpp", r"\bread_share_page\s*\(",
     r"[^{}]*\bpage\.unanswered\s*=\s*yuzu::agent::bounded_cause\s*\(\s*read\.status\s*\)\s*;", 1),
    ("users/src/users_plugin.cpp",
     r"\bread_(?:wts_sessions|local_users|local_group_members)\s*\(",
     r"[^;]*;\s*if\s*\(\s*yuzu::agent::forward_bounded_failure\s*\(\s*ctx\s*,\s*read\.status\b"
     r"[^;{]*(?:\{[^{}]*)?\breturn\s+1\s*;", 5),
    ("users/src/users_plugin.cpp", r"\brun_account_tool\s*\(\s*ctx\s*,",
     r"\s*\{[^{}]*\}\s*,\s*\*deadline\s*,\s*status_forwarded\s*,\s*tool_skipped\s*\)\s*;", 4),
    ("users/src/users_plugin.cpp", r"\bToolOutcome\s+run_account_tool\s*\(",
     r"[^{}]*\{\s*auto\s+out\s*=\s*run_tool\s*\(\s*std::move\(argv\)\s*,\s*0\s*,\s*deadline\s*\)", 1),
    # ... and every such `deadline` comes from the budget.
    ("users/src/users_plugin.cpp",
     r"\bdeadline\s*=\s*(?:tool_deadline\s*\(\s*\)|budget\.next_deadline\s*\()", "", 5),
    # Each per-account tool's outcome is settled against that deadline and the full one,
    ("users/src/users_plugin.cpp", r"\bToolOutcome\s+run_account_tool\s*\(",
     r"[^{}]*\{[^{}]*\byuzu::users::settle_account_tool\s*\(\s*ctx\s*,\s*out\.res\s*,"
     r"\s*deadline\s*,\s*kUsersCmdDeadline\s*,\s*out\.output\s*,"
     r"\s*status_forwarded\s*,\s*tool_skipped\s*\)\s*;", 1),
    # ... and both declare calls (Linux, macOS) keep the two flags in order.
    ("users/src/users_plugin.cpp", r"\byuzu::users::declare_budget_exhausted\s*\(",
     r"\s*ctx\s*,\s*,\s*tool_skipped\s*,\s*status_forwarded\s*\)\s*;", 2),
    # An answered read that is not the whole list is declared before the next read.
    ("users/src/users_plugin.cpp", r"\bread_wts_sessions\s*\(",
     BEFORE_NEXT_USERS_READ + r"\bdeclare_partial\s*\(\s*ctx\s*,\s*"
     r"yuzu::users_win::wts_degraded_provenance\s*\(\s*read\s*\)\s*\)\s*;", 2),
    ("users/src/users_plugin.cpp", r"\bread_(?:local_users|local_group_members)\s*\(",
     BEFORE_NEXT_USERS_READ + r"\bdeclare_partial\s*\(\s*ctx\s*,\s*"
     r"yuzu::users_win::incomplete_provenance\s*\(\s*,\s*read\.truncated\s*,"
     r"\s*read\.no_progress\s*\)\s*\)\s*;", 3),
    # A refused session listing then fails the command.
    ("users/src/users_plugin.cpp", r"\bread_wts_sessions\s*\(",
     BEFORE_NEXT_USERS_READ + r"\bdeclare_partial\s*\([^;]*;\s*"
     r"if\s*\(\s*!\s*read\.enumerated\s*\)\s*return\s+1\s*;", 2),
    # The status writes of the other Windows shells.
    ("device_identity/src/device_identity_plugin.cpp", r"\bread_join_info\s*\(",
     r"[^{}]*\byuzu::agent::forward_bounded_failure\s*\(\s*ctx\s*,\s*read\.status\s*,\s*\)\s*;",
     1),
    ("network_config/src/network_config_plugin.cpp", r"\bread_adapters\s*\(",
     r"[^;]*;\s*yuzu::agent::forward_bounded_failure\s*\(\s*ctx\s*,\s*list\.status\s*,\s*\)\s*;",
     1),
    ("filesystem_posture/src/filesystem_posture_win.cpp", r"\bread_vss_snapshots\s*\(",
     r"[\s\S]*?\bprovenance\.append\s*\(\s*\)\s*\.append\s*\(\s*mark\.cause\s*\)\s*;", 1),
)

SITE = re.compile(r"\bbounded_call\w*\s*\(")
BANNED_CALL = re.compile(r"\b(" + "|".join(BANNED) + r")\s*\(")
DETACH = re.compile(r"\.\s*detach\s*\(")
INCLUDE = re.compile(r"^[ \t]*#[ \t]*include\b", re.M)
DRIVER = re.compile(r'[ \t]*[<"][^<>"\n]*\bbounded_single_flight\.hpp[>"]')
TOKEN = re.compile(
    r"//(?:\\\n|[^\n])*"                                                 # line comment
    r"|/\*.*?(?:\*/|\Z)"                                                 # block comment
    r'|\b(?:u8|[uUL])?R"(?P<d>[^ ()\\\n]{0,16})\(.*?(?:\)(?P=d)"|\Z)'    # raw string
    r"|(?P<num>\b\d(?:'?\w)*)"                                           # 1'000 opens no char
    r'|"(?:\\.|[^"\\\n])*"?'                                             # string
    r"|'(?:\\.|[^'\\\n])*'?",                                            # char
    re.S)


@functools.lru_cache(maxsize=None)
def blank(text):
    """Blank comments and literals in one left-to-right pass; offsets and newlines are kept."""
    return TOKEN.sub(lambda m: m["num"] or re.sub(r"[^\n]", " ", m[0]), text)


def sources():
    return {p.relative_to(PLUGINS).as_posix(): p.read_text(encoding="utf-8", errors="replace")
            for ext in ("*.cpp", "*.hpp", "*.mm") for p in PLUGINS.rglob(ext)}


def seams():
    headers = ROOT / "agents" / "core" / "include" / "yuzu" / "agent"
    return {name
            for p in (*headers.glob("win_*.hpp"), headers / "proc_snapshot_read.hpp")
            for name in re.findall(r"\b(\w+_for_test)\s*\(", blank(p.read_text(encoding="utf-8")))}


@functools.lru_cache(maxsize=None)
def scan(name, raw, seam):
    """One file's (a), (b) and (e) findings and its (c) site count. Cached on the name and the full
    text, so a self-test edit rescans only the file it changes."""
    code, found = blank(raw), []
    for m in BANNED_CALL.finditer(code):
        if (name, m[1]) not in ALLOWED:
            found.append(f"{name}: calls {m[1]}: use the bounded agent-core read (ADR-3008)")
    if any(DRIVER.match(raw, m.end()) for m in INCLUDE.finditer(code)):
        found.append(f"{name}: includes bounded_single_flight.hpp, which is agent-core only")
    for m in seam.finditer(code):
        found.append(f"{name}: names {m[1]}, a seam for test binaries")
    if DETACH.search(code):
        found.append(f"{name}: detaches a thread, which can outlive the plugin (ADR-3008)")
    return tuple(found), len(SITE.findall(code))


def problems(srcs, table, seam_names):
    found, counts = [], {}
    seam = re.compile(r"\b(" + "|".join(sorted(seam_names)) + r")\b")
    for name, raw in sorted(srcs.items()):
        file_found, n = scan(name, raw, seam)
        found += file_found
        if n:
            counts[name] = n
    for name in sorted(counts.keys() | table.keys()):
        have, frozen = counts.get(name, 0), table.get(name, 0)
        if have > frozen:
            found.append(f"{name}: {have} bounded_call sites, {frozen} frozen: no new detached "
                         "call in a plugin; bound it in agent-core (ADR-3008)")
        elif have < frozen:
            found.append(f"{name}: {have} bounded_call sites, {frozen} frozen: lower "
                         "GRANDFATHERED (and the table in ADR-3008)")
    for name, site, then, expected in WIRED:
        code = blank(srcs.get(name, ""))
        sites, handled = (len(re.findall(p, code)) for p in (site, site + then))
        if (sites, handled) != (expected, expected):
            found.append(f"{name}: {handled} of {sites} `{site}` sites are handled, {expected} "
                         "expected: keep the bounded-answer wiring (ADR-3008)")
    return found


class BoundedOsCall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srcs, cls.seams = sources(), seams()  # one read of the tree; no test edits it

    def run_gate(self, edits=None, table=GRANDFATHERED):
        return problems({**self.srcs, **(edits or {})}, table, self.seams)

    def assert_flagged(self, name, needle, **kwargs):
        got = self.run_gate(**kwargs)
        self.assertEqual(len(got), 1, got)
        self.assertTrue(got[0].startswith(name + ":") and needle in got[0], got)

    def append(self, name, line):
        return {name: self.srcs.get(name, "") + "\n" + line + "\n"}

    def test_tree(self):
        self.assertIn("read_vss_snapshots_for_test", self.seams)  # else (b) is vacuous
        self.assertEqual(self.run_gate(), [])

    def test_selftest_planted_violations_are_caught(self):
        new = "shares/src/planted.cpp"
        processes = "processes/src/processes_plugin.cpp"
        power = "power_health/src/power_health_plugin.cpp"
        for name, line, needle in (
            (new, "void f() { ::NetShareEnum (nullptr); }", "calls NetShareEnum"),
            (new, "void f() { GetAdaptersAddresses(0); }", "calls GetAdaptersAddresses"),
            (new, "#include <yuzu/agent/bounded_single_flight.hpp>", "agent-core only"),
            (new, '  #  include "bounded_single_flight.hpp"', "agent-core only"),
            (new, "auto r = read_vss_snapshots_for_test(d, f);", "seam for test binaries"),
            (new, "auto r = read_proc_snapshot_bounded_for_test(p, d, f);", "seam for test binaries"),
            (new, "void f(std::thread t) { t.detach(); }", "detaches a thread"),
            (new, "void f() { WTSEnumerateSessions(0); }", "calls WTSEnumerateSessions"),
            (new, "void f() { ::WTSEnumerateSessionsExW(0); }", "calls WTSEnumerateSessionsExW"),
            (new, "void f() { WTSQuerySessionInformationA(0); }",
             "calls WTSQuerySessionInformationA"),
            (new, "auto r = yuzu::shared::bounded_call(d, f);", "1 bounded_call sites, 0 frozen"),
            (processes, "auto r = yuzu::shared::bounded_call_ex(d, f);", "3 bounded_call sites"),
            (power, "auto r = bounded_call_tracked(f);", "11 bounded_call sites"),
            (new, "int n = 1'000; bounded_call(d, f); char c = 'x';", "1 bounded_call sites"),
        ):
            with self.subTest(line=line):
                self.assert_flagged(name, needle, edits=self.append(name, line))

    def test_selftest_dropped_wiring_is_caught(self):
        shares, users = "shares/src/shares_win.cpp", "users/src/users_plugin.cpp"
        identity = "device_identity/src/device_identity_plugin.cpp"
        network = "network_config/src/network_config_plugin.cpp"
        posture = "filesystem_posture/src/filesystem_posture_win.cpp"
        guard = r"if \(yuzu::agent::forward_bounded_failure\("
        # (file, what to break, its replacement, how often it occurs): one occurrence at a time.
        for name, pattern, replacement, expected in (
            (shares, r"page\.unanswered = [^;]*;", "", 1),
            (users, r"(?s)" + guard + r".*?return 1;(?:\n    \})?", "", 5),
            (users, r"(?s)(" + guard + r".*?)return 1;", r"\1", 5),
            (users, r"\*deadline,", "kUsersCmdDeadline,", 4),
            (users, r"std::move\(argv\), 0, deadline", "std::move(argv)", 1),
            (users, r"deadline =\s+(?:tool_deadline|budget\.next_deadline)\(", "deadline = f(", 5),
            (users, r"yuzu::users::settle_account_tool\([^;]*;", "", 1),
            (users, r"status_forwarded, tool_skipped\);", "tool_skipped, status_forwarded);", 5),
            (users, r"yuzu::users::declare_budget_exhausted\([^;]*;", "", 2),
            (users, r"declare_partial\(ctx, yuzu::users_win::wts_degraded_provenance\(read\)\);",
             "", 2),
            (users, r"(?s)declare_partial\(ctx, yuzu::users_win::incomplete_provenance\(.*?\);",
             "", 3),
            (users, r"if \(!read\.enumerated\)\s+return 1;", "", 2),
            (identity, r"yuzu::agent::forward_bounded_failure\([^;]*;", "", 1),
            (network, r"yuzu::agent::forward_bounded_failure\([^;]*;", "", 1),
            (posture, r"provenance\.append\([^;]*mark\.cause\);", "", 1),
        ):
            src = self.srcs[name]
            matches = list(re.finditer(pattern, src))
            self.assertEqual(len(matches), expected, pattern)
            for m in matches:
                with self.subTest(pattern=pattern, at=m.start()):
                    edit = src[:m.start()] + m.expand(replacement) + src[m.end():]
                    got = self.run_gate(edits={name: edit})
                    self.assertTrue(got and all(g.startswith(name + ":") for g in got), got)

    def test_selftest_the_table_only_ratchets_down(self):
        name = "processes/src/processes_plugin.cpp"
        self.assert_flagged(name, "lower GRANDFATHERED", table={**GRANDFATHERED, name: 3})
        self.assert_flagged(name, "0 bounded_call sites", edits={name: ""})

    def test_selftest_comments_and_literals_are_not_sites(self):
        text = ('// bounded_call(a) NetUserEnum(b)\n/* bounded_call_ex(\n NetSessionEnum( */\n'
                'auto s = "bounded_call(\\" NetShareEnum(";\n'
                'auto r = R"x(bounded_call(")x";\n// #include <bounded_single_flight.hpp>\n'
                'auto t = "#include <bounded_single_flight.hpp>";\n'
                'void f() { dism_bounded_call(); }\n')
        self.assertEqual(self.run_gate(edits={"shares/src/planted.cpp": text}), [])


if __name__ == "__main__":
    sys.exit(unittest.main(argv=[sys.argv[0]]) or 0)
