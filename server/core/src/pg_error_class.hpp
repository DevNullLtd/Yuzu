#pragma once

/// @file pg_error_class.hpp
/// Postgres analogue of `sqlite_error_class.hpp` (which this file replaces
/// for `ApprovalManager` — ADR-0065). Classifies a Postgres SQLSTATE as
/// permanent (will NOT clear on an unchanged retry — the store is
/// degraded, not merely contended) or transient (BUSY-equivalent
/// conditions that clear once contention/connectivity recovers), for the
/// same caller-facing "escalate to an operator" vs. "retry unchanged"
/// split `mcp_approval_error.hpp` makes.
///
/// Deliberately narrow, matching this repo's existing SQLSTATE-classifier
/// precedent (`engine_principal_store.cpp`'s file-local `is_permanent_
/// sqlstate`, #2456 UP-17): every class NOT matched here — 08 (connection),
/// 40/55 (serialization/lock contention), 57/58 (operator intervention/
/// system) — stays classified transient, which is the existing, correct
/// default for anything not matched.
///
/// The specific classes matched here are the closest Postgres analogues of
/// the four SQLite extended-errcode families `is_permanent_sqlite_error`
/// matched (CORRUPT, NOTADB, READONLY, FULL) — this store's error contract
/// predates the Postgres port and is preserved, not redesigned, by it:
///  - Class 42 (Syntax Error or Access Rule Violation) — schema drift (a
///    missing table/column, a revoked grant); the same family
///    `engine_principal_store.cpp` matches, and the closest analogue of
///    SQLITE_NOTADB ("this isn't the database I expect").
///  - XX001/XX002 (data_corrupted / index_corrupted) — analogue of
///    SQLITE_CORRUPT.
///  - 53100 (disk_full) — analogue of SQLITE_FULL.
///  - 25006 (read_only_sql_transaction) — analogue of SQLITE_READONLY.
/// All four share the SQLite classifier's operating fact: retrying the
/// identical statement will fail identically until an operator intervenes.

#include <string_view>

namespace yuzu::server {

/// True for a Postgres SQLSTATE that will NOT clear on an unchanged retry.
/// Empty (no Postgres origin — store not open, missing argument) is FALSE:
/// callers combine this with their own `!is_open()` check, exactly as
/// `sqlite_error_class.hpp`'s 0-extended-errcode case did.
[[nodiscard]] constexpr bool is_permanent_pg_error(std::string_view sqlstate) {
    if (sqlstate.size() != 5)
        return false;
    if (sqlstate.substr(0, 2) == "42")
        return true;
    return sqlstate == "XX001" || sqlstate == "XX002" || sqlstate == "53100" ||
           sqlstate == "25006";
}

} // namespace yuzu::server
