# Resource Ledger: 7287-echo-usage-generation-strict

Every owning boundary the C++ in `b7a9905e6..HEAD` (fix/echo-usage-generation-and-migration-sweep) adds or changes: `agents/plugins/echo/src/echo_usage.{cpp,hpp}`, `agents/plugins/echo/src/echo_db_v10_migration.cpp`, `tests/unit/test_echo_usage.cpp` and `tests/unit/test_echo_v10_migration.cpp`.

No new or modified owning raw resource: no fd, HANDLE, SOCKET, `FILE*`, `sqlite3*`, `sqlite3_stmt*`, OpenSSL or BCrypt object, allocated C string, mapped library, subprocess, thread, callback context or temp path; no manual cleanup.

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `usage_generation` value read | `std::expected<int64_t, std::string>` returned by value from `read_usage_generation_strict`, over `EchoDatabase::try_get_config` (an owned `std::string`; the statement sits in its `StmtPtr`) | each call | the temporary dies with the call | none | a failed read or a malformed value is the `std::unexpected` arm; nothing is written |
| R2 | `parse_i64_exact` | pure `std::from_chars` over a caller-owned `std::string_view` | each call | n/a | none | n/a |
| R3 | `UsageSweep` (`kRun`, `kDefer`, `kClose`) | scoped enum passed by value | n/a | n/a | none | n/a |
| R4 | Closing `usage_fold_in` call of the v10 usage walk | runs on the migration's existing `TransactionHandle`, inside its single transaction | after the chunk loop, only when the walk fed at least one row | with the migration transaction | none | a failure returns `std::unexpected` out of the migration, the transaction rolls back and the file stays at v9 |
| R5 | `col_text` return value | `std::string_view` over the statement's column buffer, now with its byte length (`sqlite3_column_bytes`) | each call | valid until the statement is stepped or reset | none | every caller copies it at once into a `std::string` (`read_config_raw`, and the open-run `exe_key` and `user` loads) |
| R6 | Test fixtures | `TestEchoDb` and `Seeded` (RAII temp database files with the `yuzu_test_` prefix); a second `SqliteHandleOwner<sqlite3>` for the unreadable-key injection and for dropping the injected triggers | per test case | scope exit | none | RAII on every path |

No thread, descriptor, socket, `FILE*`, callback or temp path is added outside the test fixtures above.
