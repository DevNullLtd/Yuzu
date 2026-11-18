# Resource Ledger - #8210 (Echo test standard, lexical gate and first sweep)

Run: `8210-echo-test-standard.p8CeRG`. Range `f4cc683af1bf2041008001d2d02152c7edec9ba1..5da77013cb`. This diff changes no production C++; the resources below are all in TEST code (`tests/unit/`), recorded because the diff contains C++. Each was independently proved by the security-guardian and cpp-safety reviews.

## Test code

| # | Resource | Kind and owner | Acquired | Released | Transferred or aliased | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | watchdog thread and promise in `must_return_within_ms` | `std::thread` plus `std::promise<void>` local to the call frame (`tests/unit/test_bounded_return.hpp`) | before the bounded call runs | a `ScopeExit` sets the promise then joins, on normal return, on a throw, and while the expiry action runs | none; the future is moved into the thread, `what` and `limit` are copied | a call that never returns trips the watchdog: flush, then `hard_exit(3)` (the repo's termination primitive) |
| R2 | plugin context and descriptor in `EchoSession` | members of the fixture in `test_echo_local_dispatcher.cpp` | constructor (`REQUIRE` on init) | `shutdown()`, idempotent through `live_`, called by the destructor; bounded by `must_return_within` | none | a failed init throws from the constructor so no destructor runs; `shutdown` uses `CHECK` only because it also runs during unwind |
| R3 | loopback listener, client and server sockets in `LoopbackPair` | POSIX `int` fds or Windows `SOCKET`, members initialised to `kNoSock`; copy and move deleted | `open()` (bind 127.0.0.1 port 0, listen, connect, accept) | the destructor closes each member once | none | every early return in `open()` leaves what it opened in the members, so the destructor closes it; `open()` returns `<call>: OS error N` |
| R4 | Winsock reference | one function-local static `WSAStartup` in the `_WIN32` branch of `open()` | first `open()` | never; reclaimed at process exit (intentional) | none | a failure returns the error string on every later `open()`; no `WSACleanup` pairing exists, corrected from the Gate 1 wording |
| R5 | GC and fold worker threads in `test_echo_fold.cpp` | two `std::thread` locals of the case | inside the case | a `ScopeExit` declared after what it releases sets the release promise once, then joins | none | a failed `REQUIRE` unwinds through the guard |
| R6 | temp database and directory | `TempDbFile`, `TempDir` with the `yuzu_test_` prefix | per case | their destructors | none | removed by the destructors |

No subprocess is spawned and no shell string is built by any test in the diff. The new python gate only reads source text.
