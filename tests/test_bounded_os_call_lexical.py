#!/usr/bin/env python3
"""ADR-3008 lexical gate: how plugin code may reach a blocking OS call.

Over agents/plugins/**/*.{cpp,hpp,mm}, with comments and string/char literals blanked:
  (a) no direct call of a Windows API that agent-core reads for plugins (BANNED);
      GetAdaptersAddresses stays allowed in the firewall plugin only;
  (b) no include of the agent-core driver bounded_single_flight.hpp, and no use of a *_for_test
      seam declared in agents/core/include/yuzu/agent/win_*.hpp;
  (c) the per-file count of `bounded_call*(` sites equals GRANDFATHERED. A new file or a higher
      count fails; a lower count fails until the table is lowered, so the freeze only ratchets down.

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
