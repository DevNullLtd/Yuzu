# Resource Ledger - test(registry) unterminated REG_SZ write neighbour

Run: `governance.d/registry-unterminated-write-neighbour.Gth6Wx.jsonl` (the reduced run) and `governance.d/registry-unterminated-full-run.pIIgp3.jsonl` (the full governance run)
Range: `origin/dev..HEAD`, `tests/unit/test_registry_win_internals.cpp` only (plus these governance records); see `git log origin/dev..HEAD` for the commit list.

## Summary

This range introduces **no new or modified fd / HANDLE / SOCKET / `FILE*` / `sqlite3*` object / OpenSSL object / allocated C string / mapped library / temp path / subprocess / callback context / thread.**

- `2830c93e4`: one stack array (`const wchar_t stored[3]`) and the byte count passed to one `RegSetValueExW` on the test's existing RAII `yuzu::win::RegKey raw` (unchanged; it closes on every exit, a failed REQUIRE included, and `ScratchTree cleanup` still removes the key).
- `fdfa6168b`: one `DWORD stored_bytes` local and one `RegQueryInfoKeyW` call on that same open key. It queries an open handle and acquires nothing.

Confirmed by cpp-safety: Gate 3 of the reduced run, Gate 3 of the full governance run on `7f6c95bcf`, and Gate 8 of the full run on the fix diff including `fdfa6168b`. No manual cleanup exists to wrap in RAII.
