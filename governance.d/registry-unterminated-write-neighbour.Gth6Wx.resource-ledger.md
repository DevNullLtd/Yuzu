# Resource Ledger - test(registry) unterminated REG_SZ write neighbour

Run: `governance.d/registry-unterminated-write-neighbour.Gth6Wx.jsonl`
Range: `origin/dev..HEAD` (2 code commits), `tests/unit/test_registry_win_internals.cpp` only.

## Summary

This range introduces **no new or modified fd / HANDLE / SOCKET / `FILE*` / `sqlite3*` object / OpenSSL object / allocated C string / mapped library / temp path / subprocess / callback context / thread.** It changes one stack array (`const wchar_t stored[3]`) and the byte count passed to one `RegSetValueExW` on the test's existing RAII `yuzu::win::RegKey raw`.

Confirmed independently by cpp-safety (Gate 3). No manual cleanup exists to wrap in RAII.
