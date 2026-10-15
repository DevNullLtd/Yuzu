#pragma once

/// @file rbac_store_sql_helpers.hpp
/// Internal OWN-SCHEMA libpq helpers shared by `RbacStore` (rbac_store.cpp) and
/// `RbacAdminAuthorityOwner` (rbac_admin_authority_owner.cpp). Moved verbatim out of
/// rbac_store.cpp's anonymous namespaces so the ADR-0012 §3 query owner and the
/// store use ONE definition of each, never a second copy. Not a public API. Cross-schema SQL
/// never belongs here: it lives in the query owner, in its own translation unit.

#include "pg/pg_exec.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::rbac_sql {

// Bounded acquires (ADR-0012 §2(a)). Reads back interactive REST/dashboard/MCP
// callers; writes get a slightly wider budget.
inline constexpr std::chrono::milliseconds kReadTimeout{2000};
inline constexpr std::chrono::milliseconds kWriteTimeout{4000};

inline std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
inline std::uint64_t to_u64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::uint64_t>(std::strtoull(s, nullptr, 10));
}
inline bool to_bool(const char* s) {
    return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1');
}

inline std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

/// Strict canonical-boolean parser for `rbac_meta.value` (rbac_enabled):
/// unlike `to_bool` above (the loose native-PG-boolean-text convention —
/// 't'/'T'/'1'), this column is application-level TEXT storing the EXACT
/// literal "true"/"false" this store itself writes. fjarvis F2 (#2703): a
/// loose `== "true"` comparison silently treats ANY other value ("TRUE",
/// "1", corruption, a hand-edit) as false with no error — the RBAC-disabled
/// fail-open direction. `nullopt` means the value is neither canonical
/// string; every call site must treat that identically to an
/// unreadable/missing flag (fail closed), never coerce it to false.
inline std::optional<bool> parse_canonical_bool(std::string_view s) {
    if (s == "true")
        return true;
    if (s == "false")
        return false;
    return std::nullopt;
}

// "SELECT value FROM rbac_store.rbac_meta WHERE key = 'rbac_enabled' FOR UPDATE"
// Absent row or a non-canonical value is an ERROR (fail closed), never
// coerced — mirrors the store's own boot-time posture. Own-schema only.
inline std::optional<bool> read_rbac_enabled_for_update(PGconn* c, std::string& err) {
    pg::PgResult r = pg::exec_params(
        c, "SELECT value FROM rbac_store.rbac_meta WHERE key = 'rbac_enabled' FOR UPDATE",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    const auto parsed = parse_canonical_bool(text_col(r.get(), 0, 0));
    if (!parsed) {
        err = "rbac_enabled holds a non-canonical value";
        return std::nullopt;
    }
    return *parsed;
}

// "SELECT value FROM rbac_store.rbac_meta WHERE key = 'rbac_enabled'" (no
// FOR UPDATE). Lock-free sibling of read_rbac_enabled_for_update — Gate 8
// HIGH: RbacAdminAuthorityOwner::regime_authority's own fresh read, called
// from a REST/MCP handler outside any write transaction, so there is
// nothing to protect with a row lock here.
inline std::optional<bool> read_rbac_enabled_lockfree(PGconn* c, std::string& err) {
    pg::PgResult r = pg::exec_params(
        c, "SELECT value FROM rbac_store.rbac_meta WHERE key = 'rbac_enabled'",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    const auto parsed = parse_canonical_bool(text_col(r.get(), 0, 0));
    if (!parsed) {
        err = "rbac_enabled holds a non-canonical value";
        return std::nullopt;
    }
    return *parsed;
}

// The one INSERT ... ON CONFLICT DO UPDATE for the flag, shared by both
// RbacStore::set_rbac_enabled and RbacAdminAuthorityOwner::set_enforcement.
inline bool write_rbac_enabled_in_txn(PGconn* c, bool enabled, std::string& err) {
    pg::PgResult r = pg::exec_params(
        c,
        "INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('rbac_enabled', $1) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        std::vector<std::string>{enabled ? "true" : "false"});
    if (r.status() != PGRES_COMMAND_OK) {
        err = PQerrorMessage(c);
        return false;
    }
    return true;
}

// Bump `write_generation` inside an already-open txn on `c`; return the new
// value, or nullopt on any error. The mutation and this bump commit atomically
// (ADR-0041: the durable counter advances in the SAME txn as the write).
inline std::optional<std::uint64_t> bump_generation_in_txn(PGconn* c) {
    pg::PgResult r = pg::exec_params(
        c,
        "INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('write_generation','1') "
        "ON CONFLICT (key) DO UPDATE SET value = "
        "(rbac_store.rbac_meta.value::bigint + 1)::text RETURNING value::bigint",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
        return std::nullopt;
    return to_u64(PQgetvalue(r.get(), 0, 0));
}

} // namespace yuzu::server::rbac_sql
