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
