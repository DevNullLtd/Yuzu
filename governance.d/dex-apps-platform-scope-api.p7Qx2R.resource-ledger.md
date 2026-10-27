# Resource Ledger: dex-apps-platform-scope-api (range d0ad54474..feat/dex-apps-platform-scope-api)

Every owning boundary and every borrow the diff adds or changes in C++ (server/core/src/dex_read_model.{hpp,cpp}, dex_read_builders.hpp, dex_api.cpp, rest_api_v1.cpp, server.cpp and the test files test_dex_api.cpp, test_dex_apps_stability.cpp, test_dex_perf_model.cpp, test_rest_guaranteed_state.cpp). The diff adds no new owning raw resource.

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Scope strings: the handler's `platform` (copy of the query value) and `scope` (normalised copy), `platform_scope` parameters, `DexAppsModel::platform_scope` | `std::string` values (copies) | request parse / normalisation / assignment | handler scope exit / model destruction | value semantics; no `string_view` is stored or returned past the call (`dex_apps_crash_source_coverage` takes a `string_view` for the call only and returns owned strings) | none needed (no raw owner) |
| R2 | Coverage pairs from `dex_apps_crash_source_coverage` | `std::vector<std::pair<std::string, std::string>>` (local, RAII) | in `dex_apps_json` | end of the function | copied into a local `json` object | an exception unwinds the vector |
| R3 | Connected-agent token `nos` in the server fleet lambda | `std::string` (local copy of `norm_os` or `os`) | per connected agent | end of the loop iteration | moved into `f.connected_agents` via `emplace_back` | none (value type) |

No new fd, HANDLE, SOCKET, `FILE*`, sqlite3 object, OpenSSL or BCrypt object, thread, subprocess, callback context, mapped library or temp path. No manual cleanup in new C++.
