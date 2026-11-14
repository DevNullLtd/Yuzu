# Resource Ledger: 5712-roster-truncation (range 7088f0cf2b..d3a8a98864)

Every owning boundary the diff adds or changes in C++ (server/core/src/offline_endpoint_store.{hpp,cpp}, offline_endpoint_types.hpp, hardware_*.{hpp,cpp}, home_routes.*, server.cpp, viz_routes.cpp, mcp_*.cpp, and tests/unit/server).

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | libpq connection lease in `query_stale_within` and the new `find_within` | the RAII lease returned by `pool_.try_acquire_for(kQueryAcquireTimeout)` | top of each method | scope exit | none | every early `std::unexpected` return unwinds the lease; no manual release |
| R2 | `PGresult` in both reads | `pg::PgResult` (RAII, `PQclear` in its destructor) | `pg::exec_params` | scope exit | none | RAII on every path; no raw `PQclear` |
| R3 | `read_endpoint_row(const PGresult*, int)` (new shared helper) | borrows the result for the call only | n/a | n/a | returns an owning `OfflineEndpoint` by value (every field copied into `std::string`/`int64_t`) | no view or pointer escapes; `PQgetvalue` never returns null for an in-range cell |
| R4 | `OfflineRoster{rows, truncated}` (up to 100,000 rows) | the `std::expected<OfflineRoster, PresenceReadError>` the caller holds | built in `query_stale_within` | caller scope | moved out by `return out;` (P1825 implicit move, no vector copy) | RAII |
| R5 | `agent_id_cannot_be_stored(std::string_view)` (new) | none: pure, allocation-free, `noexcept` | n/a | n/a | n/a | runs before the lease is taken, so there is nothing to release on its early return |
| R6 | `metrics_` (`yuzu::MetricsRegistry*`, non-owning) in the store | `ServerImpl::metrics_`, declared (server.cpp ~24223) before `offline_endpoint_store_` (~24362), so it outlives the store; the store is also reset explicitly in `stop()` before member destruction | `set_metrics(&metrics_)` right after construction (server.cpp ~5421), before serving threads | n/a | none | reads are null-guarded; `counter()` takes the registry mutex and returns a node-stable reference |
| R7 | tests: `std::thread` x2 in the concurrent counter case | local `std::vector<std::thread>` guarded by a `JoinAll` RAII struct | `emplace_back` after `reserve` | `JoinAll` destructor and the explicit join loop | none | joined on every exit path including a throw (std::jthread is not available on Apple Clang) |
| R8 | tests: the seeded 100,000-row ephemeral Postgres database | `YUZU_REQUIRE_PG_DB_TPL` fixture (`yuzu_test_` prefix, dropped `WITH (FORCE)` on scope exit even when a REQUIRE fails) | per test case | fixture destructor | none | fixture-owned; no fixed port, path or name (#1871) |

No new fd, HANDLE, SOCKET, `FILE*`, SQLite handle, OpenSSL object, BCrypt handle, allocated C string, mapped library, temp path, subprocess, callback context or production thread is added. `set_metrics` lost `noexcept` (it calls `describe` and `counter`, which can throw `bad_alloc`); it runs once at boot. No manual resource cleanup is added.
