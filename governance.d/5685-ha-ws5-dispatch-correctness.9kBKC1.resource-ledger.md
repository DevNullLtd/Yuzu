# Resource Ledger — HA WS-5 slice 3 and WS-13 13.7

Range: `2c3d0ac148..HEAD` (branch `feat/ha-ws5-gate-items-ws13-7`)

## Summary

This diff adds **no thread, subprocess, socket, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt handle,
mapped library or temp path**, and no raw `new`/`delete`, `release()`, `reinterpret_cast` or `const_cast`
in production code. The owning boundaries are: Postgres pool leases (RAII), `std::shared_ptr`
copies of `AgentSession`, three mutexes and one `try_to_lock` guard, a `grpc::ChannelArguments` value, and
one callback context holding a BORROWED raw pointer. Independently re-verified by `cpp-safety` in rounds 1,
2 and 3 (no policy-floor item in any round).

## Table 1 — owned state

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Pool lease in `OfflineEndpointStore::publish_plugins`, `query_live_ids_without_plugin`, `clear_plugins_of_other_sessions` | the pool's RAII lease type | `pool_.try_acquire_for(...)` after input validation | scope exit | none | every early return happens before the lease or releases it by scope; a failed statement returns a typed error or `false`, counted under `yuzu_server_agent_presence_store_failed_total{op=...}` |
| R2 | `std::shared_ptr<AgentSession>` copies in `needs_directory_consult`, `lacks_local_delivery_path`, `has_remote_presence`, `send_via_directory`, `heartbeat_ingestion.cpp` (`published_sess`) | value-owned `shared_ptr` locals | copied under `mu_` | scope end (after `mu_` is released) | none | RAII |
| R3 | `missing_plugin_mu_` (guards `missing_plugin_cache_`, `missing_plugin_inflight_`, the reader and its ttl) | `std::mutex` member of `AgentRegistry`, taken with `lock_guard` | brief, twice per cache miss | scope exit | none | never held across the database read, nor together with `mu_`, `stream_mu` or `presence_cache_mu_` (the only nesting is `presence_cache_mu_` then `missing_plugin_mu_` in a test-only hook) |
| R4 | Cached plugin-absence results (`MissingPluginIds = shared_ptr<const vector<string>>`) | the cache entry plus any in-flight caller | after a successful read | when replaced or evicted, OFF the lock (`replaced`/`evicted` are declared before the guard) | shared, never copied out | RAII; the in-flight marker is erased FIRST inside the lock so an allocation failure cannot wedge a plugin |
| R5 | `std::unique_lock(stream_mu, std::try_to_lock)` in `no_delivery_path` and `send_via_directory` | the lock guard | try-lock | scope exit, or an explicit `unlock()` before delegating to `send_to` | none | RAII; lock order `stream_mu` then `gw_pending_mu_` (the order `send_to` uses); a failed try-lock reads as "has a path" |
| R6 | Callback context: the `PluginMissingReadFn` lambda built in `configure_presence(OfflineEndpointStore*, ttl)` | `std::function` member `presence_missing_plugin_reader_` | `configure_presence` at wiring | `configure_presence(nullptr)` at stop | none | the lambda captures a BORROWED `OfflineEndpointStore*` (owner `ServerImpl::offline_endpoint_store_`). The unwire is NOT a barrier for an in-flight read; what keeps the store alive is that every dispatch and heartbeat thread is joined before the unwire (server.cpp stop()). A throwing reader is caught and fails open |
| R7 | `grpc::ChannelArguments` in `GatewayMgmtStubPool::default_channel_arguments()` and the `ChannelCreateFn` seam | value types | per channel creation | passed by const reference; `CreateCustomChannel` copies the arguments | none | RAII; `default_channel_factory`'s lambda captures nothing |
| R8 | `std::atomic<bool> presence_plugins_published`, `std::atomic<int64_t> presence_plugins_retry_after_ms` on `AgentSession` | members of the session object | with the session | with the session | none | relaxed atomics: once-per-session optimisation flags with no data dependency |
| R9 | Names `std::vector<std::string_view>` in `publish_plugins` | function-local | built from the caller's `plugin_names` | function exit | none | views point into the caller's strings, valid for the whole call; `pg::to_text_array` copies |

## Table 2 — what is NOT introduced

No new background loop, sampler or thread (WS-10 classification unchanged). The arrival mirror runs inline on
the existing Subscribe-establishment and `NotifyStreamStatus` CONNECTED paths and takes no lock across its
single bounded (250 ms acquire) Postgres statement.

## Known limits recorded elsewhere

No TSan/ASan run was done on the new locking (finding `fu-tsan-and-chaos-not-run`). The direct Subscribe call
site of the arrival mirror is pinned by a source-text gate, not a behavioural test (finding
`fu-direct-subscribe-arrival-site-lexically-pinned-only`).
