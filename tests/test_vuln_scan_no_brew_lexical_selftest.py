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
    ("popen under `linux || __MACH__`", "extra.cpp",
     '#if defined(__linux__) || defined(__MACH__)\nvoid f(){ popen("/bin/ls","r"); }\n#endif\n'),
    ("popen under `linux || 1`", "extra.cpp",
     '#if defined(__linux__) || 1\nvoid f(){ popen("/bin/ls","r"); }\n#endif\n'),
    ("popen under `linux || __GNUC__`", "extra.cpp",
     '#if defined(__linux__) || defined(__GNUC__)\nvoid f(){ popen("/bin/ls","r"); }\n#endif\n'),
    ("popen under `#elif linux || __MACH__`", "extra.cpp",
     '#if defined(__linux__)\n#elif defined(__linux__) || defined(__MACH__)\nvoid f(){ popen("/bin/ls","r"); }\n#endif\n'),
    ("popen in the #else of `__APPLE__ && FOO`", "extra.cpp",
     '#if defined(__APPLE__) && defined(YUZU_FOO)\nvoid g(){}\n#else\nvoid f(){ popen("/bin/ls","r"); }\n#endif\n'),
    ("popen after a `%:endif` digraph", "extra.cpp",
     '#ifdef __linux__\nvoid lin(){}\n%:endif\nvoid f(){ popen("/bin/ls","r"); }\n'),
    ("popen after a backslash-continued directive", "extra.cpp",
     '#if defined(__linux__) \\\n  || defined(__MACH__)\nvoid f(){ popen("/bin/ls","r"); }\n#endif\n'),
    ("unmatched #endif", "extra.cpp", '#endif\nvoid f(){}\n'),
    ("wordexp", "extra.cpp", 'void f(){ wordexp_t w; wordexp("$(/bin/ls)", &w, 0); }\n'),
    ("fexecve", "extra.cpp", 'void f(){ fexecve(3, nullptr, nullptr); }\n'),
    ("execveat", "extra.cpp", 'void f(){ execveat(3, "x", nullptr, nullptr, 0); }\n'),
    ("forkpty", "extra.cpp", 'void f(){ forkpty(nullptr, nullptr, nullptr, nullptr); }\n'),
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
     "return macos_run_for(yuzu::vuln::kMacosSystemProfilerCmd,",
     'return macos_run_for({"system_profiler", "SPApplicationsDataType"},'),
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
    ("pin d: unusable CVE-input count dropped", "vuln_scan_plugin.cpp",
     "yuzu::vuln::update_cve_inputs(cov, apps, yuzu::vuln::kCveRules);", "(void)apps;"),
    ("pin d: unusable-version skip removed", "vuln_scan_plugin.cpp",
     "yuzu::vuln::skip_unusable_for_compare(cov.macos_software, app.version)", "false"),
    ("pin d: clean placeholder not gated", "vuln_scan_plugin.cpp",
     "if (yuzu::vuln::want_clean_placeholder(cov))", "if (true)"),
    ("pin d: unrecognised-line plumbing dropped", "vuln_scan_plugin.cpp",
     "cov->software_unrecognised = parsed.readable ? parsed.suspect_lines : 0;", ""),
    ("pin d: do_cve_scan_impl takes a nullable pointer", "vuln_scan_plugin.cpp",
     "std::vector<Finding> do_cve_scan_impl(yuzu::vuln::CoverageState& cov) {",
     "std::vector<Finding> do_cve_scan_impl(yuzu::vuln::CoverageState* cov_ptr = nullptr) {\n    yuzu::vuln::CoverageState dummy; auto& cov = cov_ptr ? *cov_ptr : dummy;"),
    ("pin e: macos_software never set", "vuln_scan_plugin.cpp",
     "cov->macos_software = true;", "cov->macos_software = false;"),
    ("pin e: sp_readable set unconditionally", "vuln_scan_plugin.cpp",
     "cov->sp_readable = parsed.readable;", "cov->sp_readable = true;"),
    ("pin e: parser told the run was ok", "vuln_scan_plugin.cpp",
     "parse_system_profiler_apps(r.out, r.ok)", "parse_system_profiler_apps(r.out, true)"),
    ("pin e: runner ignores the exit code", "vuln_scan_plugin.cpp",
     "out.ok = out.ran && r.exit_code == 0;", "out.ok = out.ran;"),
    ("pin e: config scan without the bounded runner", "vuln_scan_plugin.cpp",
     "run_all_config_checks(macos_run)", "run_all_config_checks()"),
    ("pin e: config_unreadable never raised", "vuln_scan_plugin.cpp",
     "        cov->config_unreadable = true;\n", "        (void)cov;\n"),
    ("pin e: config_unreadable raised unconditionally", "vuln_scan_plugin.cpp",
     "if (cov && yuzu::vuln::any_config_unreadable(checks))", "if (cov)"),
    ("pin e: status token not derived from the coverage", "vuln_scan_plugin.cpp",
     "const auto token = yuzu::vuln::coverage_token(cov);", "const std::string token = \"x\";"),
    ("pin e: status declared never", "vuln_scan_plugin.cpp",
     "if (!token.empty())\n        ctx.set_result_status", "if (false)\n        ctx.set_result_status"),
    ("pin e: status declared always", "vuln_scan_plugin.cpp",
     "if (!token.empty())\n        ctx.set_result_status", "if (true)\n        ctx.set_result_status"),
    ("pin e: name backslash not folded", "vuln_scan_plugin.cpp",
     "yuzu::vuln::fold_backslashes(a.name)", "a.name"),
    ("pin e: version backslash not folded", "vuln_scan_plugin.cpp",
     "yuzu::vuln::fold_backslashes(a.version)", "a.version"),
    ("pin f: popen added in the macOS runner", "vuln_scan_plugin.cpp",
     "    const auto r = yuzu::agent::run_bounded_subprocess(argv, opts);",
     "    (void)popen(\"true\", \"r\");\n    const auto r = yuzu::agent::run_bounded_subprocess(argv, opts);"),
    ("pin f: system added in the macOS config checks", "config_checks.hpp",
     "inline std::vector<ConfigCheckResult> run_macos_checks(const MacosReader& reader) {\n",
     "inline std::vector<ConfigCheckResult> run_macos_checks(const MacosReader& reader) {\n    (void)system(\"true\");\n"),
    ("pin f: popen helper compiled on macOS", "config_checks.hpp",
     "#ifdef __linux__\n// popen with RAII", "#if defined(__linux__) || defined(__APPLE__)\n// popen with RAII"),
    ("pin f: exec added at the top level", "vuln_scan_plugin.cpp",
     "std::vector<Finding> do_config_scan_impl(", "int g_x = execv(\"/bin/true\", nullptr);\nstd::vector<Finding> do_config_scan_impl("),
    ("pin c: summary row emitter dropped", "vuln_scan_plugin.cpp", "            emit_coverage_summary_row(ctx, cov);\n", ""),
    ("pin c: scan row emitter dropped", "vuln_scan_plugin.cpp",
     "output_findings(ctx, all, cov);\n            emit_coverage_row(ctx, cov);", "output_findings(ctx, all, cov);"),
    ("pin c: &cov dropped from a config_scan call", "vuln_scan_plugin.cpp", "auto findings = do_config_scan_impl(&cov);",
     "auto findings = do_config_scan_impl();"),
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
