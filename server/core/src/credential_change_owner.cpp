/**
 * credential_change_owner.cpp -- see credential_change_owner.hpp (#5342).
 *
 * The ADR-0012 §3 query owner for a local account's credential change: ONE
 * lease, ONE transaction, schema-qualified SQL across `auth`, `session_store`
 * and `audit_store`, no nested acquire, no external work inside the
 * transaction except the test-only pre-commit hook.
 */

#include "credential_change_owner.hpp"

#include "audit_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "session_store_sql_helpers.hpp"

#include <yuzu/server/auth.hpp>    // AuthManager::constant_time_compare
#include <yuzu/server/auth_db.hpp> // is_valid_username / is_valid_principal / kProvisioningSourceLocal

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <exception>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

using Kind = CredentialChangeRequest::Kind;
using Result = CredentialChangeResult;

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

bool bool_col(PGresult* res, int row, int col) {
    const char* v = PQgetvalue(res, row, col);
    return v != nullptr && (v[0] == 't' || v[0] == 'T' || v[0] == '1');
}

// (a) Classification read, under the row lock. Every column the classifier and
// the post-commit report need, read ONCE, by the transaction that will write.
constexpr const char* kLockRowSql =
    "SELECT password_hash, salt_hex, role, identity_source, provisioning_source, "
    "(locked_until IS NOT NULL OR failed_login_count > 0) AS was_locked, "
    "(mfa_enrolled_at IS NULL AND mfa_totp_secret IS NOT NULL) AS had_provisional "
    "FROM auth.users WHERE username = $1 AND is_active = TRUE FOR UPDATE";

// (b) The credential write. The WHERE clause re-states the local-account gate
// the classifier just checked under the same lock (defence in depth: a zero-row
// result here is a store fault, not a classification). The provisional (never
// enrolled) TOTP secret is wiped — an attacker who started an enrolment under
// the retired credential must not be able to finish it, and the account's next
// enrolment gets a FRESH secret, not the one already revealed (F1). An
// ENROLLED secret is kept (F3). Two parameter-free compile-time statements —
// the literals are constants, never interpolated input.
#define YUZU_CRED_UPDATE_HEAD                                                                      \
    "UPDATE auth.users SET password_hash = $2, salt_hex = $3, updated_at = now(), "                \
    "mfa_totp_secret = CASE WHEN mfa_enrolled_at IS NULL THEN NULL ELSE mfa_totp_secret END, "     \
    "mfa_last_counter = CASE WHEN mfa_enrolled_at IS NULL THEN 0 ELSE mfa_last_counter END"
#define YUZU_CRED_UPDATE_TAIL                                                                      \
    " WHERE username = $1 AND is_active = TRUE AND identity_source = 'local' "                     \
    "AND provisioning_source = 'local' RETURNING id"
constexpr const char* kSelfUpdateSql = YUZU_CRED_UPDATE_HEAD YUZU_CRED_UPDATE_TAIL;
// Admin reset also clears the lockout in the SAME statement — the reset and the
// unlock are one recorded act, not a write followed by a best-effort unlock.
constexpr const char* kAdminUpdateSql =
    YUZU_CRED_UPDATE_HEAD
    ", failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL" YUZU_CRED_UPDATE_TAIL;
#undef YUZU_CRED_UPDATE_HEAD
#undef YUZU_CRED_UPDATE_TAIL

} // namespace

CredentialChangeOutcome CredentialChangeOwner::commit(const CredentialChangeRequest& req) const {
    CredentialChangeOutcome out;
    const bool self = req.kind == Kind::kSelf;
    const char* action = self ? "user.password_change" : "user.password_reset";

    // An SSO principal ("oidc:..."/"saml:...") is never a local account; a
    // malformed name can match no row. Classified before any I/O, so a
    // principal-shaped name answers the same whether or not such a row exists.
    if (!is_valid_username(req.username)) {
        out.result = is_valid_principal(req.username) ? Result::kNotLocal : Result::kNotFound;
        return out;
    }
    // A self-change without the anchor its verify produced is a caller bug —
    // never "write without the CAS".
    if (self && (!req.expected_current_hash_hex || req.expected_current_hash_hex->empty())) {
        out.result = Result::kConflict;
        return out;
    }
    if (req.new_hash_hex.empty() || req.new_salt_hex.empty()) {
        spdlog::error("{}: refusing an empty credential for '{}' (caller bug)", action,
                      req.username);
        out.result = Result::kStoreUnavailable;
        return out;
    }
    // No evidence store, no credential change (never "commit and hope").
    if (audit_ == nullptr || !audit_->is_open()) {
        spdlog::error("{}: audit store unavailable - refusing to change the credential for '{}'",
                      action, req.username);
        out.result = Result::kAuditUnavailable;
        return out;
    }

    std::optional<Result> refusal; // set inside the txn ⇒ rolled back with this answer
    std::string err;
    std::string role;
    int revoked = 0;
    bool had_provisional = false;
    bool was_locked = false;
    int audit_rows = 0;

    bool committed = false;
    try {
        committed = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
            // 0. Bound every lock wait in this transaction (txn-scoped:
            //    is_local=true, never leaks to the pooled connection) — the
            //    pool's connect-time default could otherwise be longer than the
            //    acquire bound. Bound parameter, never interpolation.
            pg::PgResult lt = pg::exec_params(
                c, "SELECT set_config('lock_timeout', $1, true)",
                std::vector<std::string>{std::to_string(kWriteTimeout.count()) + "ms"});
            if (lt.status() != PGRES_TUPLES_OK) {
                err = PQerrorMessage(c);
                return false;
            }

            // a. Lock the row FIRST and classify under the lock.
            pg::PgResult row =
                pg::exec_params(c, kLockRowSql, std::vector<std::string>{req.username});
            if (row.status() != PGRES_TUPLES_OK) {
                err = PQerrorMessage(c);
                return false;
            }
            if (PQntuples(row.get()) == 0) {
                refusal = Result::kNotFound;
                return false;
            }
            const std::string stored_hash = text_col(row.get(), 0, 0);
            role = text_col(row.get(), 0, 2);
            if (text_col(row.get(), 0, 3) != "local" ||
                text_col(row.get(), 0, 4) != kProvisioningSourceLocal) {
                refusal = Result::kNotLocal;
                return false;
            }
            if (self &&
                !auth::AuthManager::constant_time_compare(stored_hash,
                                                          *req.expected_current_hash_hex)) {
                refusal = Result::kConflict;
                return false;
            }
            was_locked = bool_col(row.get(), 0, 5);
            had_provisional = bool_col(row.get(), 0, 6);

            // b. The write (guarded; zero rows under our own lock is a fault).
            pg::PgResult upd = pg::exec_params(
                c, self ? kSelfUpdateSql : kAdminUpdateSql,
                std::vector<std::string>{req.username, req.new_hash_hex, req.new_salt_hex});
            if (upd.status() != PGRES_TUPLES_OK) {
                err = PQerrorMessage(c);
                return false;
            }
            if (PQntuples(upd.get()) != 1) {
                err = "guarded credential UPDATE matched no row under its own row lock";
                return false;
            }

            // c. Every session of the account, durably, + the generation bump.
            const auto deleted = session_sql::invalidate_user_in_txn(c, req.username, err);
            if (!deleted)
                return false;
            revoked = *deleted;

            // d. The evidence, in the same transaction.
            AuditEvent ev = req.audit_template;
            ev.action = action;
            ev.result = "ok";
            ev.detail = std::string(self ? "self_service" : "admin_reset target_role=" + role) +
                        " sessions_revoked=" + std::to_string(revoked) +
                        " provisional_mfa_cleared=" + (had_provisional ? "true" : "false");
            if (!audit_->log_in_txn(c, ev)) {
                refusal = Result::kAuditUnavailable;
                return false;
            }
            audit_rows = 1;
            if (!self && was_locked) {
                AuditEvent lock_ev = req.audit_template;
                lock_ev.action = "auth.lockout.cleared";
                lock_ev.result = "ok";
                lock_ev.detail = "password_reset";
                if (!audit_->log_in_txn(c, lock_ev)) {
                    refusal = Result::kAuditUnavailable;
                    return false;
                }
                audit_rows = 2;
            }

            // e. TEST-ONLY seam, every lock still held.
            if (pre_commit_hook_for_test_)
                pre_commit_hook_for_test_();
            return true;
        });
    } catch (const std::exception& e) {
        // with_txn_for rolled back before the exception propagated.
        committed = false;
        err = e.what();
    } catch (...) {
        committed = false;
        err = "unknown exception";
    }

    if (!committed) {
        out.result = refusal.value_or(Result::kStoreUnavailable);
        if (out.result == Result::kStoreUnavailable)
            spdlog::error("{} for '{}' did not commit ({}) - rolled back; nothing changed unless "
                          "the connection was lost at COMMIT",
                          action, req.username, err.empty() ? "lease/COMMIT failure" : err);
        else if (out.result == Result::kAuditUnavailable)
            spdlog::error("{} for '{}': the audit row could not be written - the whole credential "
                          "change rolled back",
                          action, req.username);
        return out;
    }

    // Post-commit, outside the lease: count the rows that are now durable.
    for (int i = 0; i < audit_rows; ++i)
        audit_->count_committed("ok");
    spdlog::info("{} committed for local account '{}' (sessions_revoked={})", action,
                 req.username, revoked);
    out.result = Result::kOk;
    out.target_role = std::move(role);
    out.sessions_revoked = revoked;
    out.provisional_mfa_cleared = had_provisional;
    out.lockout_cleared = !self && was_locked;
    return out;
}

} // namespace yuzu::server
