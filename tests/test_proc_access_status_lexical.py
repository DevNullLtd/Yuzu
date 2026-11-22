#!/usr/bin/env python3
"""WP13 UP14 lexical pin: the three Linux /proc walkers must declare a refused /proc read
(no CAP_SYS_PTRACE) as CONSTRAINED/PARTIAL with their own provenance token, not a clean OK.

Beyond "the token exists", each walker CALL SITE that can meet a refusal is pinned to feed the
shared ProcAccessTally from the failing call's own errno, AND the CONSUMER side is pinned (the
`tally.constrained()` test that turns the count into a CONSTRAINED/PARTIAL status, and each
walker's call to it):

  processes   both enumerations call `resolve_exe_path(p.pid, tally)` then `report_exe_gaps(ctx,
              tally)`; the Linux resolver reads through `readlink_noting(tally, ...)`
  procfetch   `resolve_exe(<link>, tally)`, its `readlink_noting` body, `tally.constrained()`
  netstat     every errno capture site (`tally.note(errno)`, two) and both
              `report_attribution_gaps(ctx, tally)` calls

Matching runs on tests/cpp_lex_helper.code_only(): comments (line AND block), `#if 0` blocks and
string-literal contents are removed first, so a pin cannot be satisfied by commented-out,
disabled or quoted text. The self-test deletes each pinned occurrence AND hides it in a block
comment, a string literal and an `#if 0` block, and requires problems() to be non-empty.
Lexical only: it cannot see control flow that keeps the tokens.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cpp_lex_helper as lexh  # noqa: E402

PINS = {
    "agents/plugins/netstat/src/netstat_plugin.cpp": "netstat:proc_fd_unreadable",
    "agents/plugins/processes/src/processes_plugin.cpp": "processes:exe_unreadable",
    "agents/plugins/procfetch/src/procfetch_plugin.cpp": "procfetch:exe_unreadable",
}
# (path, regex on code_only text, minimum count, description)
SITES = [
    ("agents/plugins/processes/src/processes_plugin.cpp", r"resolve_exe_path\(p\.pid, tally\)", 2,
     "list_hashed and list_tree each pass the tally to resolve_exe_path"),
    ("agents/plugins/processes/src/processes_plugin.cpp", r"report_exe_gaps\(ctx, tally\);", 2,
     "list_hashed and list_tree each report the gaps"),
    ("agents/plugins/processes/src/processes_plugin.cpp",
     r"if \(tally\.constrained\(\)\) ctx\.set_result_status\(YUZU_RESULT_STATUS_CONSTRAINED", 1,
     "report_exe_gaps turns the tally into CONSTRAINED"),
    ("agents/plugins/processes/src/processes_plugin.cpp",
     r"yuzu::shared::readlink_noting\(tally, link\.c_str\(\)\)", 1,
     "the Linux resolver reads through readlink_noting (one call, its own errno)"),
    ("agents/plugins/procfetch/src/procfetch_plugin.cpp", r'resolve_exe\(entry\.path\(\) / "", tally\)', 1,
     "the procfetch walk passes the tally to resolve_exe"),
    ("agents/plugins/procfetch/src/procfetch_plugin.cpp",
     r"yuzu::shared::readlink_noting\(tally, link\.c_str\(\)\)", 1,
     "resolve_exe reads through readlink_noting"),
    ("agents/plugins/procfetch/src/procfetch_plugin.cpp",
     r"if \(tally\.constrained\(\)\) ctx\.set_result_status\(YUZU_RESULT_STATUS_CONSTRAINED", 1,
     "procfetch turns the tally into CONSTRAINED"),
    ("agents/plugins/netstat/src/netstat_plugin.cpp", r"tally\.note\(errno\)", 2,
     "both netstat walkers note the errno of the failing call"),
    ("agents/plugins/netstat/src/netstat_plugin.cpp", r"report_attribution_gaps\(ctx, tally\);", 2,
     "both netstat actions report the gaps"),
    ("agents/plugins/netstat/src/netstat_plugin.cpp",
     r"if \(t\.constrained\(\)\) ctx\.set_result_status\(YUZU_RESULT_STATUS_CONSTRAINED", 1,
     "report_attribution_gaps turns the tally into CONSTRAINED"),
]


def problems(sources):
    errs = []
    for path, token in PINS.items():
        src = sources[path]
        live = lexh.live_text(src)  # string contents kept, comments / #if 0 removed
        if token not in live:
            errs.append(f"{path}: missing {token}")
        if "proc_access.hpp" not in src or "ProcAccessTally" not in lexh.code_only(src):
            errs.append(f"{path}: does not use the shared ProcAccessTally")
        if "YUZU_RESULT_STATUS_CONSTRAINED" not in lexh.code_only(src):
            errs.append(f"{path}: no CONSTRAINED status")
    for path, pat, n, what in SITES:
        found = len(re.findall(pat, lexh.code_only(sources[path])))
        if found < n:
            errs.append(f"{path}: {what} (expected >= {n} of /{pat}/, found {found})")
    return errs


def selftest(sources):
    errs = []
    hiders = {
        "deleted": lambda t: "UNTALLIED_CALL",
        "block comment": lambda t: "/* " + t + " */",
        "string literal": lambda t: '"' + t.replace('"', "'") + '"',
        "#if 0": lambda t: "\n#if 0\n" + t + "\n#endif\n",
    }
    for path, pat, n, what in SITES:
        # code_only() empties string literals and collapses whitespace; undo both for the raw text
        raw_pat = pat.replace('""', '"[^"]*"').replace(" ", r"\s*")
        occurrences = list(re.finditer(raw_pat, sources[path]))
        if len(occurrences) < n:
            errs.append(f"selftest: stale pattern /{raw_pat}/ in {path} (found {len(occurrences)})")
        for i, m in enumerate(occurrences):
            for hname, hide in hiders.items():
                mutated = dict(sources)
                s = sources[path]
                mutated[path] = s[:m.start()] + hide(m.group(0)) + s[m.end():]
                if not problems(mutated):
                    errs.append(f"selftest: {hname} of occurrence {i} of /{pat}/ in {path} was NOT detected")
    return errs


def main():
    sources = {p: (ROOT / p).read_text(encoding="utf-8") for p in {x[0] for x in SITES} | set(PINS)}
    errs = problems(sources) + selftest(sources)
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
