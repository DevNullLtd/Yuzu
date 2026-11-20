#!/usr/bin/env python3
"""WP13/F19 lexical tripwire: the installed_apps plugin must never execute Homebrew's brew.

The macOS agent runs as root and a Homebrew prefix is owned by the installing (non-root) user,
so exec'ing `<prefix>/bin/brew` runs a user-controlled file as root. do_list_per_user is
`#if __APPLE__`, so a behavioural test cannot run on Linux; pin the source text instead
(best-effort, comments stripped). Also pins the removed sink-manifest row.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "agents/plugins/installed_apps/src"
MANIFEST = ROOT / "docs/agent-spawn-sink-manifest.md"


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def main() -> int:
    errs = []
    for f in sorted(PLUGIN.glob("*.[ch]pp")):
        code = strip_comments(f.read_text())
        if re.search(r"homebrew|/bin/brew|\"brew\"|parse_brew_list", code, flags=re.I):
            errs.append(f"{f.name}: executes or parses brew (root agent must not run a user-owned script)")
    if "installed_apps/do_list_per_user#1" in MANIFEST.read_text():
        errs.append("sink manifest still registers installed_apps/do_list_per_user#1 (brew)")
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
