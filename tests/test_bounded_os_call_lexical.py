#!/usr/bin/env python3
"""ADR-3008 lexical gate: how plugin code may reach a blocking OS call.

Over agents/plugins/**/*.{cpp,hpp,mm}, with comments and string/char literals blanked:
  (a) no direct call of a Windows API that agent-core reads for plugins (BANNED);
      GetAdaptersAddresses stays allowed in the firewall plugin only;
  (b) no include of the agent-core driver bounded_single_flight.hpp, and no use of a *_for_test
      seam declared in agents/core/include/yuzu/agent/win_*.hpp;
  (c) the per-file count of `bounded_call*(` sites equals GRANDFATHERED. A new file or a higher
      count fails; a lower count fails until the table is lowered, so the freeze only ratchets down;
  (d) each WIRED site keeps the text that handles a bounded answer, in shells no unit test reaches:
      shares' unanswered page, users' "did not complete" returns and its declaration of a failed or
      cut read, and the tool budget's deadline, settlement and end-of-run status on the
      per-account tools.

Stated limits: a wrapper whose name does not start with `bounded_call` is not seen, nor is a call
with explicit template arguments (`bounded_call_ex<F>(`); (a) matches the listed spellings only;
(b) sees a direct include, not a transitive one. Lexical only; the self-test plants each violation
in memory and requires it flagged.
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
    "NetGetJoinInformation", "WTSEnumerateSessionsW", "WTSQuerySessionInformationW",
    "CreateVssBackupComponents", "GetAdaptersAddresses",
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
     r"\s*\{[^{}]*\}\s*,\s*\*deadline\s*,", 4),
    ("users/src/users_plugin.cpp", r"\bToolOutcome\s+run_account_tool\s*\(",
     r"[^{}]*\{\s*auto\s+out\s*=\s*run_tool\s*\(\s*std::move\(argv\)\s*,\s*0\s*,\s*deadline\s*\)", 1),
    # ... and every such `deadline` comes from the budget.
    ("users/src/users_plugin.cpp",
     r"\bdeadline\s*=\s*(?:tool_deadline\s*\(\s*\)|budget\.next_deadline\s*\()", "", 5),
    # Each per-account tool's outcome is settled against that deadline and the full one,
    ("users/src/users_plugin.cpp", r"\bToolOutcome\s+run_account_tool\s*\(",
     r"[^{}]*\{[^{}]*\byuzu::users::settle_account_tool\s*\(\s*ctx\s*,\s*out\.res\s*,"
     r"\s*deadline\s*,\s*kUsersCmdDeadline\s*,\s*out\.output\s*,", 1),
    # ... and each run (Linux, macOS) ends by declaring a spent budget.
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
)

SITE = re.compile(r"\bbounded_call\w*\s*\(")
BANNED_CALL = re.compile(r"\b(" + "|".join(BANNED) + r")\s*\(")
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
    return {name
            for p in (ROOT / "agents" / "core" / "include" / "yuzu" / "agent").glob("win_*.hpp")
            for name in re.findall(r"\b(\w+_for_test)\s*\(", blank(p.read_text(encoding="utf-8")))}


def problems(srcs, table, seam_names):
    found, counts = [], {}
    seam = re.compile(r"\b(" + "|".join(sorted(seam_names)) + r")\b")
    for name, raw in sorted(srcs.items()):
        code = blank(raw)
        for m in BANNED_CALL.finditer(code):
            if (name, m[1]) not in ALLOWED:
                found.append(f"{name}: calls {m[1]}: use the bounded agent-core read (ADR-3008)")
        if any(DRIVER.match(raw, m.end()) for m in INCLUDE.finditer(code)):
            found.append(f"{name}: includes bounded_single_flight.hpp, which is agent-core only")
        for m in seam.finditer(code):
            found.append(f"{name}: names {m[1]}, a seam for test binaries")
        if n := len(SITE.findall(code)):
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
    def setUp(self):
        self.srcs, self.seams = sources(), seams()

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
            (new, "auto r = yuzu::shared::bounded_call(d, f);", "1 bounded_call sites, 0 frozen"),
            (processes, "auto r = yuzu::shared::bounded_call_ex(d, f);", "3 bounded_call sites"),
            (power, "auto r = bounded_call_tracked(f);", "11 bounded_call sites"),
            (new, "int n = 1'000; bounded_call(d, f); char c = 'x';", "1 bounded_call sites"),
        ):
            with self.subTest(line=line):
                self.assert_flagged(name, needle, edits=self.append(name, line))

    def test_selftest_dropped_wiring_is_caught(self):
        shares, users = "shares/src/shares_win.cpp", "users/src/users_plugin.cpp"
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
            (users, r"yuzu::users::declare_budget_exhausted\([^;]*;", "", 2),
            (users, r"declare_partial\(ctx, yuzu::users_win::wts_degraded_provenance\(read\)\);",
             "", 2),
            (users, r"(?s)declare_partial\(ctx, yuzu::users_win::incomplete_provenance\(.*?\);",
             "", 3),
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
