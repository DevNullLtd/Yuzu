#!/usr/bin/env python3
"""WP13c/C-2 lexical tripwire: the vuln_scan plugin must never execute Homebrew's brew.

The macOS agent runs as root and a Homebrew prefix is owned by the installing (non-root) user,
so running `brew` executes a user-controlled script as root (same defect as WP13/F19 in
installed_apps). get_installed_apps is `#elif defined(__APPLE__)`, so a behavioural test cannot
run on Linux; pin the source text instead (best-effort, comments stripped).
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "agents/plugins/vuln_scan/src"


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def main() -> int:
    errs = []
    files = sorted(PLUGIN.glob("*.[ch]pp"))
    if not files:
        errs.append("no vuln_scan sources found")
    for f in files:
        code = strip_comments(f.read_text())
        if re.search(r"homebrew|/bin/brew|\bbrew\b", code, flags=re.I):
            errs.append(f"{f.name}: executes or names brew (root agent must not run a user-owned script)")
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
