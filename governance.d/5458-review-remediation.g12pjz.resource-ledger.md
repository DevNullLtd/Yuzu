# Resource Ledger - PR #5458 review remediation (mgmt_posture)

Run: `governance.d/5458-review-remediation.g12pjz.jsonl`
Range: `dbc890a07..7a72d9970` (4 commits), plus the governance fix-up commits that follow it.

## Summary

This range introduces **no new or modified fd / HANDLE / SOCKET / `FILE*` / `sqlite3_stmt*` /
`sqlite3*` / OpenSSL object / BCrypt handle / allocated C string / mapped library / temp path /
subprocess / callback context / thread.** The macOS subprocess argv and options are untouched. The new
code is pure value logic (`sssd_facts` section filtering, a status mapping in `posture_macos`, one
`std::string` temporary in the unknown-action error path) and test code; the only test-side resource is
the existing `g_fail_alloc` stub, which the new OOM case resets. No manual cleanup exists to wrap in RAII.

Confirmed independently by cpp-safety (Gate 3) and compliance-officer (Gate 6). The ownership of the
plugin's original file and directory helpers (`ScopedFd`, `DIR` deleter) is outside this range.
