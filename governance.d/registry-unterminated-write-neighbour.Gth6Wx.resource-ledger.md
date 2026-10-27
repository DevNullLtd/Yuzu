# Resource Ledger - test(registry) unterminated REG_SZ write neighbour

Run: `governance.d/registry-unterminated-write-neighbour.Gth6Wx.jsonl`
Range: `origin/dev..HEAD` (2 code commits plus the ledger commit), `tests/unit/test_registry_win_internals.cpp` only.

## Summary

This range introduces **no new or modified fd / HANDLE / SOCKET / `FILE*` / `sqlite3*` object / OpenSSL object / allocated C string / mapped library / temp path / subprocess / callback context / thread.** It changes one stack array (`const wchar_t stored[3]`) and the byte count passed to one `RegSetValueExW` on the test's existing RAII `yuzu::win::RegKey raw` (unchanged; it still closes on every exit, a failed REQUIRE included, and `ScratchTree cleanup` still removes the key).

Confirmed independently by cpp-safety (Gate 3) in both the reduced run and the full governance run. No manual cleanup exists to wrap in RAII.
