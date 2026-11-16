/**
 * mfa_disable_owner.cpp -- see mfa_disable_owner.hpp (#6079 PR 2c).
 *
 * The ADR-0012 §3 query owner for clearing a local account's second factor: ONE
 * lease, ONE transaction, schema-qualified SQL across `auth`, `session_store`
 * and `audit_store`, no nested acquire, no external work inside the
 * transaction except the test-only pre-commit hook.
 */

#include "mfa_disable_owner.hpp"

#include "audit_store.hpp"
#include "auth_db_sql_helpers.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "session_store_sql_helpers.hpp"

#include <yuzu/server/auth_db.hpp> // is_valid_username

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <exception>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

using Result = MfaDisableResult;

} // namespace

MfaDisableOutcome MfaDisableOwner::commit(const MfaDisableRequest& req) const {
    MfaDisableOutcome out;

    // A malformed name can match no row. Classified before any I/O, so it answers
    // the same whether or not such a row exists.
    if (!is_valid_username(req.username)) {
        out.result = Result::kNotFound;
        return out;
    }
    // No evidence store, no factor clear (never "commit and hope").
    if (audit_ == nullptr || !audit_->is_open()) {
        spdlog::error("mfa disable: audit store unavailable - refusing to clear the factor for "
                      "'{}'",
                      req.username);
        out.result = Result::kAuditUnavailable;
        return out;
    }

    std::optional<Result> refusal; // set inside the txn ⇒ rolled back with this answer
    std::string err;
    bool was_enrolled = false;
    int ended = 0;

    bool committed = false;
    try {
        committed = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
            // 0. Bound every lock wait in this transaction (txn-scoped:
            //    is_local=true, never leaks to the pooled connection), the
            //    pool's connect-time default could otherwise be longer than the
            //    acquire bound. Bound parameter, never interpolation.
            pg::PgResult lt = pg::exec_params(
                c, "SELECT set_config('lock_timeout', $1, true)",
                std::vector<std::string>{std::to_string(kWriteTimeout.count()) + "ms"});
            if (lt.status() != PGRES_TUPLES_OK) {
                err = PQerrorMessage(c);
                return false;
            }

            // a. Lock the row FIRST, compare the admitted generation under that
            //    lock, clear the factor and delete the recovery codes (the one
            //    shared copy). Classification is in the same transaction.
            const auto cleared =
                auth_sql::clear_mfa_factor_in_txn(c, req.username, req.expected_factor_gen, err);
            if (!cleared)
                return false;
            if (cleared->status == auth_sql::MfaClearStatus::kNoActiveRow) {
                refusal = Result::kNotFound;
                return false;
            }
            if (cleared->status == auth_sql::MfaClearStatus::kFactorChanged) {
                refusal = Result::kFactorChanged;
                return false;
            }
            was_enrolled = cleared->was_enrolled;

            // b. Every session of the account, durably (the count feeds the
            //    audit detail). The generation bump is NOT here, see d.
            const auto deleted = session_sql::delete_user_sessions_in_txn(c, req.username, err);
            if (!deleted)
                return false;
            ended = *deleted;

            // c. The evidence, in the same transaction. The caller owns every
            //    field but the session count.
            AuditEvent ev = req.audit_template;
            const std::string count = "sessions_ended=" + std::to_string(ended);
            ev.detail = ev.detail.empty() ? count : ev.detail + " " + count;
            if (!audit_->log_in_txn(c, ev)) {
                refusal = Result::kAuditUnavailable;
                return false;
            }

            // d. The write-generation bump LAST, after the audit INSERT: its
            //    `session_meta` row lock is taken by every session create/revoke
            //    in the fleet, so nothing may be waited on after it but COMMIT
            //    (see CredentialChangeOwner for the incident this order closes).
            if (!session_sql::bump_generation_in_txn(c)) {
                err = std::string("session write-generation bump failed: ") + PQerrorMessage(c);
                return false;
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
            spdlog::error("mfa disable for '{}' did not commit ({}) - rolled back; nothing "
                          "changed unless the connection was lost at COMMIT",
                          req.username, err.empty() ? "lease/COMMIT failure" : err);
        else if (out.result == Result::kAuditUnavailable)
            spdlog::error("mfa disable for '{}': the audit row could not be written - the whole "
                          "clear rolled back",
                          req.username);
        return out;
    }

    // Post-commit, outside the lease: count the row that is now durable.
    audit_->count_committed(req.audit_template.result);
    spdlog::info("mfa disable committed for local account '{}' (was_enrolled={}, "
                 "sessions_ended={})",
                 req.username, was_enrolled, ended);
    out.result = Result::kOk;
    out.was_enrolled = was_enrolled;
    out.sessions_ended = ended;
    return out;
}

} // namespace yuzu::server
