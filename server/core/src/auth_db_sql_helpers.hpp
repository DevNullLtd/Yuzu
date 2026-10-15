#pragma once

/// @file auth_db_sql_helpers.hpp
/// Internal OWN-SCHEMA libpq helpers over `auth.users`, shared by `AuthDB`
/// (auth_db.cpp) and `RbacAdminAuthorityOwner` (rbac_admin_authority_owner.cpp).
/// The mirror of rbac_store_sql_helpers.hpp: a statement that both the store
/// and the ADR-0012 §3 cross-schema query owner must run lives here ONCE, so
/// `AuthDB::remove_user` / `AuthDB::update_role` and the owner's
/// last-Administrator-guarded `deactivate_account` / `set_local_role` cannot
/// drift into two copies of the soft-delete or of the role write. Not a public
/// API. Only `auth.*` SQL belongs here: cross-schema SQL (anything naming
/// `rbac_store.*`) lives in the query owner, in its own translation unit, and
/// tests/test_rbac_query_owner_seam.py fails if an `rbac_store.` literal
/// appears in any auth_db* file or in this header.
///
/// Every function runs on an already-open connection `c` and issues
/// parameterised SQL only. The `_in_txn` functions are meant for a caller that
/// holds a transaction; `AuthDB::update_role` runs `set_role_in_txn` on a
/// single autocommit lease, where the statement is simply its own transaction
/// (the name marks "does not open or close one", not "requires one").

#include "pg/pg_exec.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>

#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::auth_sql {

/// THE definition of "an active local administrator account": the literal
/// `role = 'admin'` AND `is_active`. This is the durable Administrator
/// population while RBAC enforcement is OFF, and the COLUMN floor's protected
/// population in BOTH regimes (a Settings admin route gates on the session's
/// effective role, which for a local account is this column). ONE copy under
/// `server/`: `count_active_local_admin_accounts` below, the owner's survivor
/// list, and the owner's per-target membership read all embed it by name, so
/// the population a refusal protects and the population a recount counts
/// cannot drift apart. Only column names appear, so it is valid with or
/// without a table alias.
inline constexpr std::string_view kActiveLocalAdminPredicate = "role = 'admin' AND is_active";

/// The soft-delete statement pair, moved verbatim out of `AuthDB::remove_user`:
/// deactivate the row (wiping MFA enrollment material in the same UPDATE) and
/// delete its recovery codes. Runs inside an already-open transaction on `c`.
/// Returns whether a row was actually deactivated (`false` for an unknown or
/// already-inactive username: the UPDATE matches nothing and no recovery-code
/// DELETE runs), or `nullopt` on a statement failure (`err` set from the
/// connection; the caller must abort the transaction).
inline std::optional<bool> soft_delete_user_in_txn(PGconn* c, const std::string& username,
                                                   std::string& err) {
    // AND is_active = TRUE: re-removing an already-inactive row must be a
    // no-op (matches zero rows -> removed=false), never a spurious
    // "re-removal" success. The test/caller contract is idempotent-false,
    // not idempotent-true, on an already-soft-deleted user.
    pg::PgResult upd = pg::exec_params(
        c,
        "UPDATE auth.users SET is_active = FALSE, mfa_totp_secret = NULL, mfa_enrolled_at = NULL, "
        "mfa_disabled_at = now(), mfa_last_counter = 0, updated_at = now() "
        "WHERE username = $1 AND is_active = TRUE RETURNING id",
        std::vector<std::string>{username});
    if (upd.status() != PGRES_TUPLES_OK) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    if (PQntuples(upd.get()) == 0)
        return false; // user not found is not a write failure
    pg::PgResult del = pg::exec_params(c, "DELETE FROM auth.mfa_recovery_codes WHERE username = $1",
                                       std::vector<std::string>{username});
    if (del.status() != PGRES_COMMAND_OK) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    return true;
}

/// The ONE role-column write, shared by `AuthDB::update_role` and the owner's
/// guarded `set_local_role`. Sets `role` (`"admin"` or `"user"`, the literals
/// the column stores) and `updated_at` for `username` on `c`. `match_inactive`
/// false is the original `AuthDB::update_role` statement byte for byte (it
/// requires `is_active`); true drops that match so an INACTIVE row can be
/// rewritten (the owner passes true ONLY when demoting to `user`, never when
/// promoting, so an inactive account is never re-armed as an administrator by
/// a role write). Returns whether a row was written (`false` = nothing
/// matched), or `nullopt` on a statement failure (`err` set; the caller must
/// abort any transaction it holds).
inline std::optional<bool> set_role_in_txn(PGconn* c, const std::string& username,
                                           const std::string& role_literal, bool match_inactive,
                                           std::string& err) {
    const char* sql =
        match_inactive
            ? "UPDATE auth.users SET role = $1, updated_at = now() WHERE username = $2 "
              "RETURNING id"
            : "UPDATE auth.users SET role = $1, updated_at = now() WHERE username = $2 AND "
              "is_active = TRUE RETURNING id";
    pg::PgResult upd = pg::exec_params(c, sql, std::vector<std::string>{role_literal, username});
    if (upd.status() != PGRES_TUPLES_OK) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    return PQntuples(upd.get()) > 0;
}

/// Count of local accounts matching `kActiveLocalAdminPredicate`. Lock-free.
/// `nullopt` on a query error or an unexpected row count (`err` is the
/// connection's error text, empty for an unexpected row count).
inline std::optional<std::int64_t> count_active_local_admin_accounts(PGconn* c, std::string& err) {
    const std::string sql =
        "SELECT count(*) FROM auth.users WHERE " + std::string(kActiveLocalAdminPredicate);
    pg::PgResult r = pg::exec_params(c, sql.c_str(), std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    return static_cast<std::int64_t>(std::strtoll(PQgetvalue(r.get(), 0, 0), nullptr, 10));
}

} // namespace yuzu::server::auth_sql
