# Resource Ledger: shares plugin Windows leg (`NetShareEnum`)

New owned resources introduced by `agents/plugins/shares/src/shares_win.cpp`. Every path
(normal return, early return, `bad_alloc` unwind) releases exactly the resource listed.

## Resources

### `NetShareEnum` result buffer (`LPBYTE`)
- **Site:** `one_page<Info>` in `shares_win.cpp`, one allocation per page.
- **Allocated by:** the `bufptr` out-parameter of `NetShareEnum` (level 1 or 2), allocated by the
  system; success, `ERROR_MORE_DATA` and failure all go through the same guard.
- **Owner type:** `NetApiBuf`, a local non-copyable, non-movable RAII guard whose destructor calls
  `NetApiBufferFree`. It is a deliberate small duplicate of the Echo guard (owner decision; Echo's
  header is untouched).
- **Release point:** `~NetApiBuf` when `one_page` returns, on every exit including the
  `std::bad_alloc` unwind to `execute_list`'s catch.
- **Transfer:** never. Every wide string is copied into a `WinShareRec` before the page returns;
  no pointer into the buffer escapes. The `reinterpret_cast<const Info*>` array stays valid until
  `~NetApiBuf` (documented at the cast; `level` is derived from `Info`).
- **Failure cleanup:** a failed call leaves the guard empty; `NetApiBufferFree(nullptr)` is not
  called.

### Resume handle and level (`DWORD`, stack locals)
- **Owner:** `run_windows` stack frame; no heap, no OS handle. Reset to zero when the leg falls
  back from level 2 to level 1.

### Dedupe set (`std::set<std::string>`)
- **Owner:** `list_windows` stack frame. One entry per kept row, full lower-cased name; bounded
  by the 512-row / 1 MiB budget (duplicates are skipped before any charge). Cleared on the
  level-1 fallback.

## Not introduced
No thread, subprocess, file, socket, temp path, callback context or library handle. The
`NetShareEnum` call itself has no deadline (#3925; see the hazard banner in `shares_win.cpp`).
