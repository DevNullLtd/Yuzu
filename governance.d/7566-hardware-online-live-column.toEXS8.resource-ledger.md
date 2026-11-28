# Resource Ledger — #7566 / #7551 Hardware Online from the roster statement

Range: `2c49b4ea0f..c814231f3a` (branch `feat/hw-online-live-column-7566`)

## Summary

This diff adds **no thread, subprocess, socket, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt handle, mapped
library, temp path, file descriptor or callback context of its own**, and no manual cleanup. The only owned
resources on the changed paths already existed and are unchanged in shape: one pooled Postgres connection
(`PgPool::Lease`, move-only RAII) and one `pg::PgResult` (RAII, `PQclear` in the destructor) per read.
Independently proven by cpp-safety at Gate 3 and again at Gate 8.

## Table 1: changed or new constructs

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Pooled connection in `query_stale_within` / `find_within` | `PgPool::Lease` (`pool_.try_acquire_for`), unchanged | before the statement, after the closed-store and malformed-id early returns | scope exit on every return | none | unchanged: the failure branches still call `record_presence_store_failure` and return the typed error |
| R2 | Statement result | `pg::PgResult res` (RAII), unchanged | `pg::exec_params(lease.get(), sql.c_str(), params)` | end of the function | none | destroyed on every return |
| R3 | SQL text | `const std::string sql` (local), built by `endpoint_columns(3)` + fixed text | before `exec_params` | function exit | none | `exec_params` consumes the text and parameters synchronously (`PQexecParams`), so `sql.c_str()` and the temporary parameter vector only have to outlive the call; a `bad_alloc` building it unwinds through the RAII lease. Only the placeholder number is concatenated; the TTL is a bound `$3::bigint` |
| R4 | `AgentRegistry::local_ids()` result | `std::vector<std::string>` returned by value | built under `std::lock_guard lock(mu_)` | caller scope | moved to the caller | RAII; no presence read and no call out while `mu_` is held, so no new lock edge |
| R5 | Local membership set | `std::unordered_set<std::string> online` (local to the roster closure), built from R4 | before the row loop | closure exit | passed to `roster_row_online` by const reference | RAII; `roster_row_online` is pure and stores no reference or view |
| R6 | `OfflineEndpoint::live` | `bool` value member | set by `read_endpoint_row` from column 7 (`'t'`) | with the row | copied | value type; a NULL or empty text reads as `false` (the expression cannot be NULL: both columns are `NOT NULL`) |

## Tests

The store test uses `YUZU_REQUIRE_PG_DB_TPL` (a throwaway database cloned per test), so the ids it uses are
private to that clone (no shared-identity collision, CI invariant #1871); staleness is set DB-side
(`now() - interval '2 hours'`). The registry test uses a stack `AgentRegistry` declared after the locals its
presence-reader lambda captures by reference, so destruction order is safe.

## Residuals (disclosed, not changed here)

None for ownership. Behavioural residuals (Online for up to the presence TTL after an unclean drop; Offline on
other replicas for up to one heartbeat after a reconnect; Online-but-not-reachable on the record page) are in
`docs/user-manual/inventory.md` and the ledger (#7724, #7725, #7726, #5888).
