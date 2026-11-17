#pragma once

/// @file auth_db_sql_helpers.hpp
/// Internal OWN-SCHEMA libpq helpers over `auth.users`, shared by `AuthDB`
/// (auth_db.cpp) and `RbacAdminAuthorityOwner` (rbac_admin_authority_owner.cpp).
/// The mirror of rbac_store_sql_helpers.hpp: a statement that both the store
/// and the ADR-0012 §3 cross-schema query owner must run lives here ONCE, so
/// `AuthDB::remove_user` / `AuthDB::update_role` and the owner's
/// last-Administrator-guarded `deactivate_account` / `set_local_role` cannot
/// drift into two copies of the soft-delete or of the role write. The MFA factor
/// clear (`clear_mfa_factor_in_txn`) is likewise shared by `AuthDB::mfa_disable_report`
/// and `MfaDisableOwner` (mfa_disable_owner.cpp). Not a public
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

/// What `clear_mfa_factor_in_txn` found under the row lock.
enum class MfaClearStatus : std::uint8_t {
    kCleared,       ///< an active row was locked and its factor columns cleared
    kNoActiveRow,   ///< no ACTIVE row by that name (unknown or inactive): nothing was cleared
    kFactorChanged, ///< an active row at another factor generation: nothing cleared, codes kept
};
struct MfaClearReport {
    MfaClearStatus status{MfaClearStatus::kNoActiveRow};
    /// The pre-image of the same row lock: whether a verified factor existed at the moment of
    /// the clear. `true` when no active row matched, so a caller deciding whether to end the
    /// account's sessions fails safe.
    bool was_enrolled{true};
};

/// The ONE MFA factor clear, moved verbatim out of `AuthDB::mfa_disable_report` so that
/// function and `MfaDisableOwner::commit` cannot drift into two copies. Runs inside an
/// already-open transaction on `c`: it locks the account's row, optionally compares the
/// admitted factor generation INSIDE that locking read (READ COMMITTED re-evaluates the
/// predicate against the row a concurrent writer committed), clears `mfa_totp_secret`,
/// `mfa_enrolled_at`, `mfa_last_counter` (stamping `mfa_disabled_at`) and deletes the account's
/// `auth.mfa_recovery_codes`. The `users_mfa_factor_gen` trigger redraws the generation on the
/// enrolment change. Two compile-time statement texts, chosen in C++: `pg::exec_params` passes
/// strings, so no SQL NULL is ever bound.
///
/// With an expected generation, zero updated rows are classified in the SAME transaction: an
/// ACTIVE row at another generation is `kFactorChanged` and the function returns BEFORE the
/// recovery-code DELETE (the caller must roll back; the committed code set is untouched);
/// anything else keeps the fail-safe `was_enrolled = true`. The recovery-code DELETE otherwise
/// runs even when no active row matched (the historical behaviour, kept byte-identical).
/// Returns `nullopt` on a statement failure (`err` set from the connection; the caller must
/// abort the transaction).
inline std::optional<MfaClearReport>
clear_mfa_factor_in_txn(PGconn* c, const std::string& username,
                        std::optional<std::int64_t> expected_factor_gen, std::string& err) {
    static constexpr const char* kClearSql =
        "WITH pre AS (SELECT id, (mfa_enrolled_at IS NOT NULL) AS was_enrolled "
        "FROM auth.users WHERE username = $1 AND is_active = TRUE FOR UPDATE) "
        "UPDATE auth.users u SET mfa_totp_secret = NULL, mfa_enrolled_at = NULL, "
        "mfa_disabled_at = now(), mfa_last_counter = 0, updated_at = now() "
        "FROM pre WHERE u.id = pre.id RETURNING pre.was_enrolled";
    static constexpr const char* kClearAtGenSql =
        "WITH pre AS (SELECT id, (mfa_enrolled_at IS NOT NULL) AS was_enrolled "
        "FROM auth.users WHERE username = $1 AND is_active = TRUE "
        "AND mfa_factor_gen = $2::bigint FOR UPDATE) "
        "UPDATE auth.users u SET mfa_totp_secret = NULL, mfa_enrolled_at = NULL, "
        "mfa_disabled_at = now(), mfa_last_counter = 0, updated_at = now() "
        "FROM pre WHERE u.id = pre.id RETURNING pre.was_enrolled";
    MfaClearReport report;
    std::vector<std::string> params{username};
    if (expected_factor_gen)
        params.push_back(std::to_string(*expected_factor_gen));
    pg::PgResult upd = pg::exec_params(c, expected_factor_gen ? kClearAtGenSql : kClearSql, params);
    if (upd.status() != PGRES_TUPLES_OK) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    if (PQntuples(upd.get()) == 1) {
        const char* v = PQgetisnull(upd.get(), 0, 0) ? "" : PQgetvalue(upd.get(), 0, 0);
        report.status = MfaClearStatus::kCleared;
        report.was_enrolled = v[0] == 't' || v[0] == 'T' || v[0] == '1';
    } else if (expected_factor_gen) {
        // Zero rows with a guard engaged: an ACTIVE row at another generation is a refusal
        // (nothing cleared, the recovery codes untouched); an absent or inactive row keeps the
        // fail-safe `was_enrolled = true`.
        pg::PgResult cls = pg::exec_params(
            c, "SELECT is_active, mfa_factor_gen FROM auth.users WHERE username = $1",
            std::vector<std::string>{username});
        if (cls.status() != PGRES_TUPLES_OK) {
            err = PQerrorMessage(c);
            return std::nullopt;
        }
        if (PQntuples(cls.get()) == 1) {
            const char* active = PQgetisnull(cls.get(), 0, 0) ? "" : PQgetvalue(cls.get(), 0, 0);
            const char* gen = PQgetisnull(cls.get(), 0, 1) ? "" : PQgetvalue(cls.get(), 0, 1);
            const bool is_active = active[0] == 't' || active[0] == 'T' || active[0] == '1';
            const std::int64_t stored = gen[0] == '\0' ? 0 : std::strtoll(gen, nullptr, 10);
            if (is_active && stored != *expected_factor_gen) {
                report.status = MfaClearStatus::kFactorChanged;
                return report; // the caller rolls back before any recovery-code DELETE
            }
        }
    }
    pg::PgResult del = pg::exec_params(c, "DELETE FROM auth.mfa_recovery_codes WHERE username = $1",
                                       std::vector<std::string>{username});
    if (del.status() != PGRES_COMMAND_OK) {
        err = PQerrorMessage(c);
        return std::nullopt;
    }
    return report;
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
