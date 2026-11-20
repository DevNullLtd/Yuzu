#!/usr/bin/env python3
"""Lexical tripwire: the pkg_inventory plugin must never run Homebrew's brew, or any subprocess.

The macOS agent runs as root and a Homebrew prefix (machine or user-owned) is writable by a
non-root account, so running `<prefix>/bin/brew` would run a user-controlled file as root.
pkg_inventory reads directories and one receipt file per formula; nothing here may spawn. The
installed_apps guard (test_installed_apps_no_brew_lexical.py) scans installed_apps only.

Best-effort text pins over the C/C++ sources of the plugin, read through cpp_lex_helper.lex
(comments removed, string literals kept and joined): a name built at run time or reached by
indirection is not caught. Checks:
  1. no whole-word `brew` (so `homebrew`, `.homebrew`, `BrewReceipt` and `parse_brew_receipt`
     pass, while `/bin/brew`, "brew" and "brew list" fail);
  2. no `run_bounded_subprocess` and no `subprocess_runner` (the sanctioned-runner route that
     scripts/ci/check-plugin-spawn-lexical.sh allows);
  3. docs/agent-spawn-sink-manifest.md holds no `pkg_inventory/<function>#<n>` row.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cpp_lex_helper as lexh  # noqa: E402

PLUGIN = ROOT / "agents/plugins/pkg_inventory/src"
MANIFEST = ROOT / "docs/agent-spawn-sink-manifest.md"

BREW = re.compile(r"\bbrew\b", re.I)
SPAWN = re.compile(r"\b(run_bounded_subprocess|subprocess_runner)\b")
MANIFEST_ROW = re.compile(r"pkg_inventory/\w+#\d+")


def findings(name: str, src: str) -> list[str]:
    """One message per violation in one source file's text (comments removed)."""
    code = lexh.lex(src)
    out = []
    if BREW.search(code):
        out.append(f"{name}: names brew (a root agent must not run a user-writable script)")
    if SPAWN.search(code):
        out.append(f"{name}: uses the subprocess runner (pkg_inventory spawns nothing)")
    return out


def self_check() -> list[str]:
    """The matcher must flag the bad shapes and pass the good ones, or the gate is a no-op."""
    errs = []
    for bad in ('run("/opt/homebrew/bin/brew");', 'run_bounded_subprocess(x);', 'x = "brew list";',
                'auto s = subprocess_runner{};'):
        if not findings("self", bad):
            errs.append(f"self-check: did not flag {bad!r}")
    for good in ('auto p = "/opt/homebrew";', 'auto r = parse_brew_receipt(x);', 'BrewReceipt r;',
                 '// brew in a comment\nint x;', 'auto d = ".homebrew";'):
        if findings("self", good):
            errs.append(f"self-check: flagged {good!r}")
    return errs


def main() -> int:
    errs = self_check()
    if errs:
        for e in errs:
            print("FAIL:", e)
        return 1
    files = sorted(list(PLUGIN.glob("*.cpp")) + list(PLUGIN.glob("*.hpp")))
    if not files:
        print(f"FAIL: no sources under {PLUGIN}")
        return 1
    for f in files:
        errs += findings(f.name, f.read_text(encoding="utf-8"))
    if MANIFEST_ROW.search(MANIFEST.read_text(encoding="utf-8")):
        errs.append("sink manifest registers a pkg_inventory spawn row")
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
