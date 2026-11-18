#!/usr/bin/env python3
"""Self-test for tests/test_vuln_scan_no_brew_lexical.py.

Copies the real vuln_scan source tree to a temp dir, injects each mutation there (nothing tracked
is touched) and requires the gate to go RED; the unmodified tree must be GREEN. Stdlib only.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "vuln_scan_no_brew_lexical", os.path.join(HERE, "test_vuln_scan_no_brew_lexical.py"))
g = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = g
spec.loader.exec_module(g)

FAILURES: list[str] = []


def expect(cond: bool, what: str) -> None:
    if not cond:
        FAILURES.append(what)
        print(f"FAIL: {what}", file=sys.stderr)


# (name, relative file, text appended to it). Every one must be detected.
RED = [
    ("plain re-add", "extra.cpp", 'void f(){ run_command("brew list --versions"); }\n'),
    ("URL in string then brew", "extra.cpp",
     'void f(){ auto u = "https://example.test"; run_command("brew list"); }\n'),
    ("block-comment opener in string", "extra.cpp",
     'void f(){ auto u = "/*"; run_command("brew list"); auto v = "*/"; }\n'),
    ("string concatenation", "extra.cpp", 'void f(){ run_command("br" "ew list"); }\n'),
    ("concatenation across a comment and newline", "extra.cpp",
     'void f(){ run_command("br" /* x */\n  "ew list"); }\n'),
    ("hex escape", "extra.cpp", 'void f(){ run_command("\\x62rew list"); }\n'),
    ("raw string", "extra.cpp", 'void f(){ run_command(R"x(brew list)x"); }\n'),
    ("objective-c++ file", "mac_helper.mm", 'void f(){ run_command("brew list"); }\n'),
    ("subdirectory file", "sub/deep/extra.hpp", 'inline const char* k = "brew";\n'),
    ("absolute homebrew path", "extra.cpp", 'const char* p = "/opt/homebrew/bin/brew";\n'),
    ("intel homebrew prefix", "extra.cpp", 'const char* p = "/usr/local/Homebrew/bin/x";\n'),
    ("brew as bare identifier", "extra.cpp", "void brew();\n"),
]

# Texts that must stay GREEN (no false positive on the shipped wording).
GREEN_TEXT = [
    ("brew only in a line comment", "// brew is never run\nint x;\n"),
    ("brew only in a block comment", "/* brew list */ int x;\n"),
    ("status token", 'const char* t = "macos:vuln_scan:homebrew_not_scanned";\n'),
    ("prose Homebrew in a string", 'const char* t = "Homebrew formulae and casks are not scanned";\n'),
]


def main() -> int:
    expect(g.scan_tree(g.PLUGIN) == [], "the real vuln_scan source tree must be GREEN")

    for name, text in GREEN_TEXT:
        expect(g.scan_source(text) == [], f"GREEN expected, got a hit: {name}")

    for name, rel, text in RED:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_vuln_brew_") as tmp:
            root = pathlib.Path(tmp) / "src"
            shutil.copytree(g.PLUGIN, root)
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "a", encoding="utf-8") as fh:
                fh.write(text)
            expect(g.scan_tree(root) != [], f"RED expected, gate stayed green: {name}")

    with tempfile.TemporaryDirectory(prefix="yuzu_test_vuln_brew_") as tmp:
        expect(g.scan_tree(pathlib.Path(tmp)) != [], "an empty tree must fail, not pass vacuously")

    if FAILURES:
        print(f"{len(FAILURES)} failure(s)", file=sys.stderr)
        return 1
    print("vuln_scan no-brew self-test: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
