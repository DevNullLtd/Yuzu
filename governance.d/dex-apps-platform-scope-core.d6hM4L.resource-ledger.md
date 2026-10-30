# Resource Ledger: dex-apps-platform-scope-core (range d460f7618..feat/dex-apps-platform-scope-core)

Every owning boundary and every borrow the diff adds or changes in C++ (server/core/src/dex_read_model.{hpp,cpp}, dex_read_builders.hpp, dex_api.{hpp,cpp}, dex_types.hpp, guaranteed_state_store.{hpp,cpp} and the test files test_dex_api.cpp, test_dex_api_double.hpp, test_dex_apps_stability.cpp). Each row was checked by `cpp-safety` in governance round 1 (lifetime proof of every string_view, temporary and static). The diff adds no new owning raw resource.

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Per-request vector of in-scope agent ids (`dex_apps_online_ids`, held as `online` in `LocalDexApi::apps`) | `std::vector<std::string>` (local, RAII) | `online.emplace(dex_apps_online_ids(fleet_fn_(), scope))` after the scope and policy checks | end of `LocalDexApi::apps` | moved into the builder call by const reference; copied into the store's text[] parameter inside the call, not retained | the invalid-scope early return precedes the allocation; an exception unwinds the vector |
| R2 | Scope strings: `scope` (normalised copy), `platform_scope` parameters, `DexAppsModel::platform_scope` | `std::string` values (copies) | normalisation / assignment | scope exit / model destruction | value semantics; no `string_view` is stored or returned past the call | none needed (no raw owner) |
| R3 | Empty-id fallback `kNoIds` in `build_dex_apps_model` | function-local `static const std::vector<std::string>` | first call (thread-safe static init) | process exit | borrowed by const reference for the store call only | none (empty, never mutated) |
| R4 | Temporary `DexFleet` from `fleet_fn_()` | prvalue bound to a const reference parameter | `dex_apps_online_ids(fleet_fn_(), scope)` | end of the full expression | ids copied out before the temporary dies (the old code moved them out of a by-value snapshot; the copy is the dispositioned K4 note) | none (value type) |

No new fd, HANDLE, SOCKET, `FILE*`, sqlite3 or libpq object (the PGconn use is unchanged inside `dex_read_checked`), OpenSSL or BCrypt object, thread, subprocess, callback context, mapped library or temp path. No manual cleanup in new C++.
