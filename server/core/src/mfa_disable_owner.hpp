#pragma once

/// @file mfa_disable_owner.hpp
/// #6079 PR 2c: the ADR-0012 §3 cross-store query owner for clearing a LOCAL
/// account's second factor: the Settings disable (`POST /api/settings/mfa/disable`)
/// and the host break-glass `--mfa-reset`. It is the sibling of
/// `CredentialChangeOwner` (#5342) and copies its shape, lock order and
/// invariants; read that banner for the reasoning this one does not repeat.
///
/// INVARIANT: a local account's factor clear (secret, enrolment marker, replay
/// counter), its recovery codes, its durable session set and the OUTCOME audit
/// row for the clear commit or abort TOGETHER, in ONE transaction on ONE pool
/// lease, holding the `auth.users` row lock first. There is no compensating
/// write: a failure anywhere (including the audit INSERT) rolls everything
/// back, so no factor, session or audit state can be observed half-applied. This
/// closes the two-commit window the two callers used to have (the clear
/// committed, then a separate session delete that could fail, leaving a session
/// made under the cleared factor alive).
///
/// `commit()`'s ONE `with_txn_for`, in order:
///   0. `set_config('lock_timeout', <kWriteTimeout>, true)`, every lock wait
///      below is bounded (txn-scoped, never leaks to the pooled connection).
///   a. `auth_sql::clear_mfa_factor_in_txn`, the ONE copy of the clear
///      statements, shared with `AuthDB::mfa_disable_report`: lock the ACTIVE
///      row `FOR UPDATE`, compare the optional admitted factor generation INSIDE
///      that locking read, clear the factor columns, delete the recovery codes.
///      No active row → `kNotFound`; an active row at another generation →
///      `kFactorChanged`; both roll back with nothing written. The
///      `users_mfa_factor_gen` trigger redraws the generation on the enrolment
///      change, so a proof made under the cleared factor stops binding even to a
///      session that somehow survived.
///   b. `session_sql::delete_user_sessions_in_txn`, DELETE every durable
///      session of the account (the ONE copy of the statement); its count is
///      `sessions_ended` and the audit detail's `sessions_ended=N`.
///   c. `AuditStore::log_in_txn`, the OUTCOME row. The caller fills the
///      template (`action`, `result`, principal, target, ...); the owner only
///      completes `detail` by appending `sessions_ended=<n>`: an empty template
///      detail becomes exactly `sessions_ended=<n>`, otherwise
///      `<template detail> sessions_ended=<n>`. Any INSERT failure aborts the
///      whole transaction → `kAuditUnavailable`.
///   d. `session_sql::bump_generation_in_txn`, bump
///      `session_meta.write_generation` LAST (same reason as the precedent:
///      every session create/revoke takes that row, so nothing may be waited on
///      after it).
///   e. the TEST-ONLY pre-commit hook, then COMMIT.
/// Post-commit (outside the lease): `AuditStore::count_committed` for the row.
/// The caller then drops its own in-process session cache (a replica's
/// validate-cache learns of the delete through the generation bump).
///
/// LOCK ORDER (a change that inverts it can deadlock): the `auth.users` row →
/// `session_store.sessions` rows → `audit_store.audit_events` (INSERT only) →
/// the `session_store.session_meta` `write_generation` row → COMMIT. This is
/// byte-for-byte the order `CredentialChangeOwner` takes (its banner holds the
/// acyclicity argument against every other holder, which applies unchanged:
/// the recovery-code DELETE is `auth` schema, taken in step a with the row).
/// Safe ONLY because `AuthDB`, `SessionStore` and `AuditStore` share ONE
/// PgPool/database (ADR-0006; server.cpp constructs all three on `*pg_pool_`):
/// a split onto separate databases fails every statement here closed (SQL error
/// → rollback), never a silent partial write, but still needs this owner
/// re-plumbed.
///
/// NOT covered here, on purpose: the `attempted` INTENT rows the callers write
/// BEFORE calling `commit()` (an intent that cannot be recorded stops the
/// clear; it is evidence that a clear was requested even if the process dies
/// mid-way) remain the CALLERS' job, as do the `denied`/`error` rows for the
/// outcomes that wrote nothing (`kFactorChanged`, `kStoreUnavailable`).
///
/// Holds no in-process lock and never calls back into `AuthManager`; it borrows
/// the pool and the audit store (both outlive it).

#include "audit_store.hpp" // AuditEvent

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// What the caller asks the owner to commit.
struct MfaDisableRequest {
    std::string username;
    /// The factor generation a gate ADMITTED this request at (Settings), compared
    /// under the row lock inside the clearing statement. `nullopt` for the host
    /// break-glass CLI, which has no gate and clears whatever is there.
    std::optional<std::int64_t> expected_factor_gen;
    /// The OUTCOME audit row. The caller fills `action`, `result` and the
    /// identity fields (principal, principal_role, target_type, target_id,
    /// source_ip, ...); the owner only completes `detail` (see the banner).
    AuditEvent audit_template;
};

enum class MfaDisableResult : std::uint8_t {
    kOk,
    kNotFound,         ///< no ACTIVE account by that name (nothing written)
    kFactorChanged,    ///< the expected generation is no longer current (nothing written)
    kStoreUnavailable, ///< lease/lock/statement/COMMIT failure, nothing written, UNLESS the
                       ///< connection was lost at COMMIT (then the clear, the session delete and
                       ///< the audit row landed together)
    kAuditUnavailable, ///< the audit INSERT failed (or no audit store), the whole transaction
                       ///< rolled back, nothing written
};

struct MfaDisableOutcome {
    MfaDisableResult result{MfaDisableResult::kStoreUnavailable};
    bool was_enrolled{false}; ///< a VERIFIED factor existed at the clear, kOk only
    int sessions_ended{0};    ///< durable sessions deleted, kOk only
};

class MfaDisableOwner {
public:
    /// Bounded acquire for the one lease, and the txn-scoped `lock_timeout`.
    /// MUST stay strictly below `AuthDB::recheck_role_locked`'s lock_timeout
    /// (auth_db.cpp kWriteTimeout, 2000 ms): a same-account sign-in queued behind
    /// a stalled disable must wait out its abort, never fail closed and sweep the
    /// account's sessions (the same rule, and the same value, as
    /// `CredentialChangeOwner::kWriteTimeout`).
    static constexpr std::chrono::milliseconds kWriteTimeout{1500};

    /// `audit` may be null (an audit-off wiring), then every `commit()` answers
    /// `kAuditUnavailable` without touching the database: a factor is never
    /// cleared without its evidence row.
    MfaDisableOwner(pg::PgPool& pool, AuditStore* audit) : pool_(pool), audit_(audit) {}

    MfaDisableOwner(const MfaDisableOwner&) = delete;
    MfaDisableOwner& operator=(const MfaDisableOwner&) = delete;
    MfaDisableOwner(MfaDisableOwner&&) = delete;
    MfaDisableOwner& operator=(MfaDisableOwner&&) = delete;

    /// The one transaction (see the file banner). Caller must hold NO lock
    /// (in-process or database), this takes the `auth.users` row lock.
    [[nodiscard]] MfaDisableOutcome commit(const MfaDisableRequest& req) const;

    /// TEST-ONLY: fired inside `commit()`'s transaction AFTER the audit row was
    /// inserted and BEFORE COMMIT, every lock in the banner's order is HELD. A
    /// hook may throw (→ rollback, `kStoreUnavailable`) to force an abort; it
    /// must NOT synchronously wait on anything that needs the held `auth.users`
    /// row or `session_meta` row (a session mint does), or it self-deadlocks
    /// until `lock_timeout`. Production code MUST NOT call this. Not
    /// thread-safe: set it before the racing requests start.
    void set_pre_commit_hook_for_test(std::function<void()> hook) {
        pre_commit_hook_for_test_ = std::move(hook);
    }

private:
    pg::PgPool& pool_;
    AuditStore* audit_;
    std::function<void()> pre_commit_hook_for_test_;
};

} // namespace yuzu::server
