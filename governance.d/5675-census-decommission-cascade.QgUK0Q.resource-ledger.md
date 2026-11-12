# Resource Ledger, #5675 (Guardian census survives decommission)

Run ledger: `5675-census-decommission-cascade.QgUK0Q.jsonl`. Range `74980cec81..HEAD` (C++: `guaranteed_state_store.{hpp,cpp}`, `agent_decommission.{hpp,cpp}`, `server.cpp`, `sle_routes.{hpp,cpp}`, `device_estate_render.cpp`, `rest_api_v1.cpp` literals, tests).

| Resource | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|
| Pool lease and transaction in `GuaranteedStateStore::delete_agent` | `PgPool::with_txn_for` (`PgTxn` declared after the lease) | entry of `with_txn_for(kWriteTimeout, ...)` | scope exit of `run_in_txn` | none | any `return false` or throw rolls back in `~PgTxn`; COMMIT only when the callback returned true and the transaction is in progress |
| `pg::PgResult locked / retired / census` | `PgResult` (RAII, `PQclear` in the destructor) | each `pg::exec_params` | end of the lambda scope | none (`PgResult` is not copied) | destructor on every path, including a throw |
| `std::string id` | local value | copy of `agent_id` at entry | scope exit | none | n/a |
| `std::vector<std::string> pending_ids` and `std::vector<std::string_view> views` | locals | filled from `PQgetvalue` (copied) while `locked` is alive; `views` built once, after `pending_ids` is complete | scope exit | `views` borrows `pending_ids`; `pg::to_text_array(views)` returns an owning `std::string` consumed within the same full expression | n/a |
| `log_step_failure` lambda (captures `agent_id` by reference) and the `const char*` from `PQresultErrorMessage` / `PQerrorMessage` | lambda local; the pointer is owned by the `PGresult` or the connection | at the failing step | consumed by `log_key_token` (copies into an owning `std::string`) before the `spdlog::warn` call returns | none | n/a (synchronous, no retention) |
| Non-owning `GuaranteedStateStore*` in `AgentDecommission::targets_` | `ServerImpl::guaranteed_state_store_` (`unique_ptr`) | `stores.guaranteed_state` read in `ServerImpl::decommission_agent` | the stack-local cascade is destroyed at the end of that call | none | shutdown order: `web_server_->stop()` and the listener join precede `guaranteed_state_store_.reset()` |
| Test threads (`WriterThreads`) and raw lock-holding `PgConn holder` | `WriterThreads` (joins in the destructor, clears the barrier); `PgConn` RAII | the concurrency case | scope exit; `holder` is declared after `writers`, so it is destroyed (lock released) before the join | none | joined on every path including a failed `REQUIRE` |

No fds, HANDLEs, sockets, `FILE*`, sqlite objects, OpenSSL or BCrypt objects, subprocesses, temp paths, new threads or callbacks with lifetime in production code. The reviewers (cpp-safety rounds 1 and 2) independently proved the above.
