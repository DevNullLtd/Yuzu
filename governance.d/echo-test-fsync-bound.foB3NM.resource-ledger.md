# Resource Ledger: echo unit tests fsync-bound fix

Range: `f2cba09b20..HEAD` (branch `test/echo-unit-tests-fsync-bound`, test-only)

## Summary

This diff adds no thread, callback, subprocess, socket, `FILE*`, `sqlite3*` or `sqlite3_stmt*` of its own, no OpenSSL or BCrypt object and no mapped library. Its only new owned resources are temp files, owned through `TempDbFile` and the existing per-test fixtures. Nothing here ships in a binary: the new header is included only by the `yuzu_echo_tests` executable.

## Table 1: new owned state

| ID | Resource | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Template DB file (`yuzu_test_echo_template_<salt>_<n>`) plus its `-wal`, `-shm`, `-journal` companions | `yuzu::test::TempDbFile` member `file` of `detail::EchoDbTemplate`, which is a function-local `static const` | the path is chosen in the `TempDbFile` member initialiser, before the constructor body runs; `EchoDatabase::open` creates the file in the body | `~TempDbFile` at static destruction on a normal exit of `yuzu_echo_tests` (it links Catch2WithMain, so `main` returns); a SIGKILL or the meson timeout kill skips it and leaves one file of about 416 KB, salted per process so it never collides | none (non-movable, non-copyable) | every early return in the constructor (open failed, checkpoint not kOk, `-wal` size unreadable, `-wal` non-empty) leaves `file` owning the path, so the dtor removes whatever was created; `ready` stays false and each caller falls back to a plain fresh open after a stderr line |
| R2 | `EchoDatabase` of the template build | `std::expected<EchoDatabase, std::string>` local in an inner block | `EchoDatabase::open` | end of the inner block (RAII: both the write and the read-only query connection close before the `-wal` size is read and before any copy) | none | RAII on every path, including the early returns |
| R3 | Per-test copy `<dest>` and its staging file `<dest>.tmp` | `<dest>`: the calling fixture's existing owner (`TestEchoDb`, `TempDbFile` or manual removal of path, `-wal`, `-shm`, `-journal`). `<dest>.tmp`: `seed_echo_db_from_template` (function-local path, no handle) | `std::filesystem::copy_file(template, <dest>.tmp, none, ec)` | `std::filesystem::rename(<dest>.tmp, <dest>, ec)` consumes the staging file on success; a failed copy removes `<dest>.tmp` (except on `file_exists`, where it belongs to someone else); a failed rename removes it | none | dest is complete or absent, never partial. A SIGKILL or abort between the copy and the rename can strand one `<dest>.tmp`; the name embeds a per-process random salt plus a counter, so a later run cannot collide with it |
| R4 | Test `EchoDatabase` opened on the copy | the fixture's `EchoDatabase` value | `open_echo_db` returns it | the fixture's destructor | returned by value (`std::expected` move) | unchanged from before; the `REQUIRE` after the `PRAGMA` runs inside the test thread and unwinds through the same RAII |
| R5 | Raw `sqlite3*` in `test_echo_v10_migration.cpp` `open_raw` | pre-existing `Db` struct (unchanged) | `sqlite3_open` | `Db` destructor | none | the added `REQUIRE(PRAGMA synchronous=OFF)` throws through `Db`'s RAII |

## Notes

- `PRAGMA synchronous=OFF` is per connection and never persisted. It is applied in test code only (`open_echo_db` and `open_raw`); no shipped file sets it.
- The only manual cleanup is the rollback `remove` of a staging file the same function created. It is not an acquire/release pair of a raw resource, so there is no RAII wrapper to add. Cleanup that is a destructor on `TempDbFile` follows the existing fixture convention.
- Exceptions: none claimed.
