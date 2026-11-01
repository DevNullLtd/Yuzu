# Resource Ledger: dex-apps-platform-scope-api (range d0ad54474..feat/dex-apps-platform-scope-api)

Every owning boundary and every borrow the diff adds or changes in C++ (server/core/src/dex_read_model.{hpp,cpp}, dex_read_builders.hpp, dex_api.cpp, rest_api_v1.cpp, server.cpp and the test files test_dex_api.cpp, test_dex_apps_stability.cpp, test_dex_perf_model.cpp, test_rest_guaranteed_state.cpp). The diff adds no new owning raw resource.

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Scope strings: the handler's `platform` (copy of the query value) and `scope` (normalised copy), `platform_scope` parameters, `DexAppsModel::platform_scope` | `std::string` values (copies) | request parse / normalisation / assignment | handler scope exit / model destruction | value semantics; no `string_view` is stored or returned past the call (`dex_apps_crash_source_coverage` takes a `string_view` for the call only and returns owned strings) | none needed (no raw owner) |
| R2 | Coverage pairs from `dex_apps_crash_source_coverage` | `std::vector<std::pair<std::string, std::string>>` (local, RAII) | in `dex_apps_json` | end of the function | copied into a local `json` object | an exception unwinds the vector |
| R3 | Connected-agent token `nos` in the server fleet lambda | `std::string` (local copy of `norm_os` or `os`) | per connected agent | end of the loop iteration | moved into `f.connected_agents` via `emplace_back` | none (value type) |
| R4 | spdlog default-logger capture in the invalid_scope warn test (`yuzu::test::LogCapture`) | RAII test helper (`tests/unit/test_log_capture.hpp`), local to the test | constructor swaps in a capture logger over a local `std::ostringstream` | `cap.stop()` before reading the text, else the destructor at scope exit; both restore the previous default logger and level and drop the capture logger from the registry | none (non-copyable, non-movable); the previous logger is held by `shared_ptr` | RAII: a failed `CHECK` or exception unwinds through the destructor, which restores the logger |

No new fd, HANDLE, SOCKET, `FILE*`, sqlite3 object, OpenSSL or BCrypt object, thread, subprocess, callback context, mapped library or temp path. No manual cleanup in new C++.

## Addendum: MCP leg (5b10913d9, 5049e0988, and the fix round that follows them)

Adds `server/core/src/mcp_server.cpp` (the `list_dex_apps` handler) and `tests/unit/server/test_mcp_server.cpp` to the files above. Supplements R1; nothing above is changed.

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R5 | The MCP handler's `platform` (`std::optional<std::string>`, from `param_string_strict`) and `scope` (normalised copy) | `std::optional<std::string>` and `std::string` values, locals of the `list_dex_apps` branch | argument parse | end of the branch | `scope` is passed by const reference to `DexApi::apps`; no view outlives the call | none (value types; every early return answers and returns) |

No new fd, HANDLE, SOCKET, `FILE*`, sqlite3 object, OpenSSL or BCrypt object, thread, subprocess, callback context, mapped library or temp path. No manual cleanup in new C++.
