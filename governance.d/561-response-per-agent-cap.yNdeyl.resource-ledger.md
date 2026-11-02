# Resource Ledger: 561-response-per-agent-cap (range origin/dev..fix/561-response-per-agent-cap)

Every owning boundary the diff adds or changes in C++ (server/core/src/response_store.{hpp,cpp}, response_cap_rules.hpp, main.cpp, server.cpp, tests/unit/server/test_response_store.cpp).

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | per-pair count and terminal probe result in `ResponseStore::store` | `pg::PgResult` (RAII, `PQclear` in its destructor) | `pg::exec_params` at the top of the `with_txn_for` lambda, before the INSERT | scope exit of the lambda on every path (probe failure, refusal, admit) | none | RAII; a failed probe returns false so `with_txn_for` rolls back and the row is counted as `query_error` |
| R2 | the transaction lease the probe runs in | UNCHANGED `with_txn_for` lease (`kIngestTimeout` bounded acquire) | unchanged | unchanged | none | unchanged; a cap refusal returns true and commits an empty transaction (nothing inserted, no rollback) |
| R3 | `cap_log_budget_` in `ResponseStore` | `DenialAuditBudget` member (bounded_audit_budget.hpp): one mutex, a map bounded by `max_keys` per window, emptied at each window close | member construction | `ResponseStore` destruction | none (non-copyable, non-movable, as is the store) | RAII; no heap beyond the bounded maps |
| R4 | tests: `ResponseStore` instances in the new cap cases | `std::unique_ptr`/stack `ResponseStore` and `MetricsRegistry` over the pre-migrated PgTestTemplate clone | per test | scope exit | none | RAII; the clone is dropped by the existing fixture |

No manual resource cleanup is added. No new thread, descriptor, socket, `FILE*`, SQLite handle or callback is added.
