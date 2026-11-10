# Resource Ledger: result-set-incomplete-scope

Every owning boundary the diff adds or changes in C++ (server/core/src/result_set_store.hpp, server/core/src/result_set_store.cpp, server/core/src/agent_registry.cpp, server/core/src/server.cpp and their unit tests).

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `result_sets.agents_unanswered` column (migration v5) | existing `result_set_store` schema; lives and dies with its row | migration under the migration runner; written by `ResultSetStore::materialize` in its existing transaction | row deletion (existing GC sweep and `delete_set`) | none; read into `ResultSet::agents_unanswered` by value | migration is its own transaction and idempotent (`IF NOT EXISTS`); a `materialize` failure rolls the count back with the membership |
| R2 | `OwnedMembers` returned by `member_set_owned` | value type deriving from `std::unordered_set<std::string>` plus a `bool` | built per call | scope exit of the caller | moved into the registry's per-evaluation membership map | RAII only |
| R3 | `needs_complete` local `std::vector<std::string>` in `AgentRegistry::evaluate_scope_impl` | the vector, per evaluation | filled by the expression walk | scope exit | none | RAII only |

No thread, socket, descriptor, `FILE*`, SQLite handle or callback is added.
