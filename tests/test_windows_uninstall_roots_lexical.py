#!/usr/bin/env python3
"""Static lexical gate over agents/plugins/installed_apps/src/installed_apps_plugin.cpp: the three
Windows Uninstall roots.

`windows_roots()` is a function-local table inside a `#ifdef _WIN32` block, and the only unit test
that could reach it (tests/unit/test_installed_apps_registry_walk.cpp) is a Windows-only TU, so on
every other host nothing observes it. Its two flags carry the row 1.4 degraded-case rule: the
64-bit and WOW6432Node HKLM views are machine scope and must exist (`absent_ok = false`, a failure
degrades the walk), while the agent identity's OWN HKCU view is per-user data (`absent_ok = true`,
`degrades_walk = false`). Flipping any of them compiles and leaves every behavioural test green, so
this gate pins the three rows, in order.

Lexical only: it cannot see a table that is built another way (review-enforced).
Usage: python3 tests/test_windows_uninstall_roots_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN_CPP = ROOT / "agents" / "plugins" / "installed_apps" / "src" / "installed_apps_plugin.cpp"
TAG = "test_windows_uninstall_roots_lexical"
HINT = (
    " (this gate pins the three Windows Uninstall roots of windows_roots(); if the table was"
    " legitimately changed, update EXPECTED_ROWS AND the MUTATIONS patterns in"
    " tests/test_windows_uninstall_roots_lexical.py)"
)

# root, subkey, extra_sam, absent_ok, degrades_walk
EXPECTED_ROWS = [
    "{HKEY_LOCAL_MACHINE,kUninstallKey,KEY_WOW64_64KEY,false,true}",
    "{HKEY_LOCAL_MACHINE,kUninstallKey,KEY_WOW64_32KEY,false,true}",
    "{HKEY_CURRENT_USER,kUninstallKey,0,true,false}",
]
TABLE = re.compile(r"reg_walk::UninstallRoot roots\[\] = \{(.*?)\};")


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def problems(src):
    """One message per violated invariant, in row order; [] when clean."""
    tables = TABLE.findall(normalise(src))
    if len(tables) != 1:
        return [f"found {len(tables)} `reg_walk::UninstallRoot roots[] = {{...}};` tables, expected exactly one"]
    rows = [re.sub(r"\s+", "", r) for r in re.findall(r"\{[^{}]*\}", tables[0])]
    if len(rows) != len(EXPECTED_ROWS):
        return [f"windows_roots() has {len(rows)} rows, expected exactly three (HKLM-64, HKLM-32, HKCU)"]
    return [f"windows_roots() row {n} is {got}, expected {want}"
            for n, (got, want) in enumerate(zip(rows, EXPECTED_ROWS), 1) if got != want]


# Each row damages one invariant: (pattern, repl, expected substring of a problem). The patterns
# match the raw plugin source.
MUTATIONS = [
    # 1. HKLM-64 made optional
    (r"(KEY_WOW64_64KEY, )false, true", r"\g<1>true, true", "row 1"),
    # 2. HKLM-32 made optional (the 32-bit view is absent only on a 32-bit OS)
    (r"(KEY_WOW64_32KEY, )false, true", r"\g<1>true, true", "row 2"),
    # 3. the HKCU view made to degrade the machine-scope walk
    (r"(HKEY_CURRENT_USER, kUninstallKey, 0, true, )false", r"\g<1>true", "row 3"),
    # 4. HKCU made mandatory
    (r"(HKEY_CURRENT_USER, kUninstallKey, 0, )true, false", r"\g<1>false, false", "row 3"),
    # 5. a row deleted
    (r"\{HKEY_CURRENT_USER, kUninstallKey, 0, true, false\},", "", "expected exactly three"),
]


class InstalledAppsWindowsRootsLexical(unittest.TestCase):
    def setUp(self):
        self.raw = PLUGIN_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.raw)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (pat, repl, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(mutation=i, pattern=pat):
                mutated, n = re.subn(pat, repl, self.raw, count=1)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertTrue(any(expected in m for m in p),
                                f"expected a problem containing {expected!r}, got {p}")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
