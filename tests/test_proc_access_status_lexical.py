#!/usr/bin/env python3
"""WP13 UP14 lexical pin: the three Linux /proc walkers must declare a refused /proc read
(no CAP_SYS_PTRACE) as CONSTRAINED/PARTIAL with their own provenance token, not a clean OK."""
import pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
PINS = {
    "agents/plugins/netstat/src/netstat_plugin.cpp": "netstat:proc_fd_unreadable",
    "agents/plugins/processes/src/processes_plugin.cpp": "processes:exe_unreadable",
    "agents/plugins/procfetch/src/procfetch_plugin.cpp": "procfetch:exe_unreadable",
}
errs = []
for path, token in PINS.items():
    src = (ROOT / path).read_text()
    if token not in src:
        errs.append(f"{path}: missing {token}")
    if "proc_access.hpp" not in src or "ProcAccessTally" not in src:
        errs.append(f"{path}: does not use the shared ProcAccessTally")
    if "YUZU_RESULT_STATUS_CONSTRAINED" not in src:
        errs.append(f"{path}: no CONSTRAINED status")
for e in errs:
    print("FAIL:", e)
sys.exit(1 if errs else 0)
