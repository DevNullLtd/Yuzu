#!/usr/bin/env python3
"""WP13 UP14 lexical pin: the three Linux /proc walkers must declare a refused /proc read
(no CAP_SYS_PTRACE) as CONSTRAINED/PARTIAL with their own provenance token, not a clean OK.

Beyond "the token exists", each walker CALL SITE that can meet a refusal is pinned to feed the
shared ProcAccessTally from the failing call's own errno:

  processes   both enumerations (list_hashed, list_tree) call `resolve_exe_path(p.pid, tally)`,
              and the Linux resolver reads through `yuzu::shared::readlink_noting(tally, ...)`
  procfetch   `resolve_exe(<link>, tally)` and its `readlink_noting(tally, ...)` body
  netstat     every errno capture site (`tally.note(errno)`): the inode walk and the
              per-process walk, two sites

A deleted or bypassed call site fails this gate; the self-test mutates each pin in memory and
requires problems() to be non-empty (a stale pattern fails loudly instead of passing vacuously).
Lexical only: it cannot see control flow that keeps the tokens.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PINS = {
    "agents/plugins/netstat/src/netstat_plugin.cpp": "netstat:proc_fd_unreadable",
    "agents/plugins/processes/src/processes_plugin.cpp": "processes:exe_unreadable",
    "agents/plugins/procfetch/src/procfetch_plugin.cpp": "procfetch:exe_unreadable",
}
# (path, regex, minimum count, description)
SITES = [
    ("agents/plugins/processes/src/processes_plugin.cpp", r"resolve_exe_path\(p\.pid, tally\)", 2,
     "list_hashed and list_tree each pass the tally to resolve_exe_path"),
    ("agents/plugins/processes/src/processes_plugin.cpp",
     r"yuzu::shared::readlink_noting\(tally, link\.c_str\(\)\)", 1,
     "the Linux resolver reads through readlink_noting (one call, its own errno)"),
    ("agents/plugins/procfetch/src/procfetch_plugin.cpp", r'resolve_exe\(entry\.path\(\) / "exe", tally\)', 1,
     "the procfetch walk passes the tally to resolve_exe"),
    ("agents/plugins/procfetch/src/procfetch_plugin.cpp",
     r"yuzu::shared::readlink_noting\(tally, link\.c_str\(\)\)", 1,
     "resolve_exe reads through readlink_noting"),
    ("agents/plugins/netstat/src/netstat_plugin.cpp", r"tally\.note\(errno\)", 2,
     "both netstat walkers note the errno of the failing call"),
]


def strip_comments(src):
    return re.sub(r"//.*", "", src)


def problems(sources):
    errs = []
    for path, token in PINS.items():
        src = sources[path]
        if token not in src:
            errs.append(f"{path}: missing {token}")
        if "proc_access.hpp" not in src or "ProcAccessTally" not in src:
            errs.append(f"{path}: does not use the shared ProcAccessTally")
        if "YUZU_RESULT_STATUS_CONSTRAINED" not in src:
            errs.append(f"{path}: no CONSTRAINED status")
    for path, pat, n, what in SITES:
        found = len(re.findall(pat, strip_comments(sources[path])))
        if found < n:
            errs.append(f"{path}: {what} (expected >= {n} of /{pat}/, found {found})")
    return errs


def selftest(sources):
    errs = []
    for path, pat, n, what in SITES:
        for i, m in enumerate(re.finditer(pat, sources[path])):
            mutated = dict(sources)
            s = sources[path]
            mutated[path] = s[:m.start()] + "UNTALLIED_CALL" + s[m.end():]
            if not problems(mutated):
                errs.append(f"selftest: removing occurrence {i} of /{pat}/ in {path} was NOT detected")
    return errs


def main():
    sources = {p: (ROOT / p).read_text(encoding="utf-8") for p in {x[0] for x in SITES} | set(PINS)}
    errs = problems(sources) + selftest(sources)
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
