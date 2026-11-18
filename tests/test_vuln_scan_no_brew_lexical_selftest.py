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
    ("line continuation inside a literal", "extra.cpp",
     'void f(){ run_command("br\\\new list"); }\n'),
    ("L-prefixed literal join", "extra.cpp", 'void f(){ run_command("br" L"ew list"); }\n'),
    ("u8-prefixed literal join", "extra.cpp", 'void f(){ run_command("br" u8"ew list"); }\n'),
    ("u-prefixed literal join", "extra.cpp", 'void f(){ run_command(u"br" "ew list"); }\n'),
    ("unicode escape", "extra.cpp", 'void f(){ run_command("\\u0062rew list"); }\n'),
    ("long unicode escape", "extra.cpp", 'void f(){ run_command("\\U00000062rew list"); }\n'),
    ("shell quoting b''rew", "extra.cpp", 'void f(){ run_command("b\'\'rew list"); }\n'),
    ("shell quoting b\"\"rew", "extra.cpp", 'void f(){ run_command("b\\"\\"rew list"); }\n'),
    ("prefixed raw string", "extra.cpp", 'void f(){ run_command(LR"x(brew list)x"); }\n'),
    ("char literal with u8 prefix before a brew call", "extra.cpp",
     "void f(){ auto c = u8'\"'; run_command(\"brew list\"); }\n"),
    ("L-prefixed char literal hides a quote", "extra.cpp",
     "void f(){ auto c = L'\"'; run_command(\"brew list\"); }\n"),
    ("splice with trailing spaces", "extra.cpp", 'void f(){ run_command("br\\  \new list"); }\n'),
]

CVE_END = "            output_findings(ctx, findings, cov);\n            emit_coverage_row(ctx, cov);\n            declare_coverage(ctx, cov);\n            ctx.report_progress(100);\n            return 0;\n        }\n\n        if (action == \"config_scan\")"

# Structural pins: (name, file, old text, new text) applied to the real source; each must go RED.
ANCHOR = "inline const MacosCheckSpec& macos_spec(MacosCheck c) {"
PIN_MUTATIONS = [
    ("pin a: bare tool literal", "config_checks.hpp", ANCHOR,
     'inline const char* kBad = "spctl --status";\n' + ANCHOR),
    ("pin a: /usr/bin/env-prefixed bare tool", "config_checks.hpp", ANCHOR,
     'inline const char* kBad = "/usr/bin/env spctl --status";\n' + ANCHOR),
    ("pin a: env-prefixed bare tool", "config_checks.hpp", ANCHOR,
     'inline const char* kBad = "env csrutil status";\n' + ANCHOR),
    ("pin a: VAR= prefixed bare tool", "config_checks.hpp", ANCHOR,
     'inline const char* kBad = "PATH=/x fdesetup status";\n' + ANCHOR),
    ("pin a: bare system_profiler literal", "vuln_scan_plugin.cpp",
     "macos_run_for(yuzu::vuln::kMacosSystemProfilerCmd, yuzu::vuln::kMacosCommandDeadlineMs)",
     'macos_run_for({"system_profiler", "SPApplicationsDataType"}, 1)'),
    ("pin b: constant unused", "config_checks.hpp", "&kMacosFdesetupCmd,", "nullptr,"),
    ("pin c: declare_coverage dropped from cve_scan", "vuln_scan_plugin.cpp",
     CVE_END,
     CVE_END.replace("            declare_coverage(ctx, cov);\n", "")),
    ("pin c: declare_coverage dropped from config_scan", "vuln_scan_plugin.cpp",
     "            emit_coverage_row(ctx, cov);\n            declare_coverage(ctx, cov);\n            ctx.report_progress(100);\n            return 0;\n        }\n\n        if (action == \"inventory\")",
     "            emit_coverage_row(ctx, cov);\n            ctx.report_progress(100);\n            return 0;\n        }\n\n        if (action == \"inventory\")"),
    ("pin c: coverage row added to inventory", "vuln_scan_plugin.cpp",
     "            declare_coverage(ctx, cov);\n            return 0;\n        }\n\n        if (action == \"summary\")",
     "            emit_coverage_row(ctx, cov);\n            declare_coverage(ctx, cov);\n            return 0;\n        }\n\n        if (action == \"summary\")"),
    ("pin c: summary row emitter dropped", "vuln_scan_plugin.cpp", "            emit_coverage_summary_row(ctx, cov);\n", ""),
    ("pin c: scan row emitter dropped", "vuln_scan_plugin.cpp",
     "output_findings(ctx, all, cov);\n            emit_coverage_row(ctx, cov);", "output_findings(ctx, all, cov);"),
    ("pin c: &cov dropped from a call", "vuln_scan_plugin.cpp", "auto findings = do_cve_scan_impl(&cov);",
     "auto findings = do_cve_scan_impl();"),
    ("pin c: fresh CoverageState handed to declare_coverage", "vuln_scan_plugin.cpp",
     CVE_END,
     CVE_END.replace("declare_coverage(ctx, cov)", "declare_coverage(ctx, yuzu::vuln::CoverageState{})")),
]

# Texts that must stay GREEN (no false positive on the shipped wording).
GREEN_TEXT = [
    ("brew only in a line comment", "// brew is never run\nint x;\n"),
    ("brew only in a block comment", "/* brew list */ int x;\n"),
    ("status token", 'const char* t = "macos:vuln_scan:homebrew_not_scanned";\n'),
    ("brew after a spliced // comment is still a comment (C++ phase 2)", "// note \\\nrun(\"brew\");\n"),
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

    for name, rel, old, new in PIN_MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_vuln_brew_") as tmp:
            root = pathlib.Path(tmp) / "src"
            shutil.copytree(g.PLUGIN, root)
            target = root / rel
            text = target.read_text()
            expect(text.count(old) == 1, f"pin mutation text not found exactly once (stale selftest): {name}")
            target.write_text(text.replace(old, new))
            expect(g.scan_tree(root) != [], f"RED expected, pin stayed green: {name}")

    with tempfile.TemporaryDirectory(prefix="yuzu_test_vuln_brew_") as tmp:
        expect(g.scan_tree(pathlib.Path(tmp)) != [], "an empty tree must fail, not pass vacuously")

    if FAILURES:
        print(f"{len(FAILURES)} failure(s)", file=sys.stderr)
        return 1
    print("vuln_scan no-brew self-test: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
