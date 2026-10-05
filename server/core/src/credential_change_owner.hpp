#pragma once

/// @file credential_change_owner.hpp
/// #5342 (Gate 8 class fix): the ADR-0012 §3 cross-store query owner for a
/// LOCAL account's credential change — the self-service change
/// (`POST /api/v1/users/me/password`) and the administrative reset
/// (`POST /api/v1/users/{name}/password`). It is the ONLY writer of
/// `auth.users.password_hash` outside the first-boot/seed paths (there is no
/// `AuthDB::set_password` any more — no second write path exists to drift).
///
/// INVARIANT: a local account's credential, its session set, its provisional
/// (un-enrolled) MFA state, its lockout state (admin reset) and the audit
/// evidence for the change commit or abort TOGETHER, in ONE transaction on ONE
/// pool lease, holding the `auth.users` row lock first. There is no
/// compensating write: a failure anywhere (including the audit INSERT) rolls
/// everything back, so nothing is ever "rolled back by hand" and no
/// credential, session or audit state can be observed half-applied. Every
/// session MINT re-reads that same row under `FOR UPDATE` after persisting the
/// session (`AuthManager::post_mint_role_recheck` → `AuthDB::recheck_role_locked`),
/// so a session proven with a retired credential is either swept by this
/// transaction's DELETE (minted before it) or denied by the locking re-read
/// (minted after the UPDATE, which it must wait behind) — nothing proven under
/// a retired credential is honoured.
///
/// `commit()`'s ONE `with_txn_for`, in order:
///   0. `set_config('lock_timeout', <kWriteTimeout>, true)` — every lock wait
///      below is bounded (txn-scoped, never leaks to the pooled connection).
///   a. `SELECT ... FROM auth.users WHERE username=$1 AND is_active FOR UPDATE`
///      — classification UNDER the lock: 0 rows → `kNotFound`; a non-local
///      identity or provisioning source → `kNotLocal`; a self-change whose
///      verified anchor is no longer the stored hash → `kConflict`.
///   b. `UPDATE auth.users` — new hash/salt, `updated_at = now()`, and the
///      PROVISIONAL TOTP secret wiped (`mfa_totp_secret`/`mfa_last_counter`
///      cleared only `WHERE mfa_enrolled_at IS NULL`; an ENROLLED second factor
///      and its recovery codes are untouched). Admin reset only: the lockout
///      columns are cleared too. Guarded `WHERE ... AND is_active AND
///      identity_source='local' AND provisioning_source='local' RETURNING id`.
///   c. `session_sql::delete_user_sessions_in_txn` — DELETE every durable
///      session of the account (the ONE copy of the statement, shared with
///      `SessionStore::invalidate_user` via `invalidate_user_in_txn`); its
///      count is the audit detail's `sessions_revoked=N`.
///   d. `AuditStore::log_in_txn` — the success row (`user.password_change` /
///      `user.password_reset`, detail carries `sessions_revoked=N` and
///      `provisional_mfa_cleared=`); admin reset of a previously-locked
///      account also writes `auth.lockout.cleared` (detail `password_reset`).
///      Any INSERT failure aborts the whole transaction → `kAuditUnavailable`.
///   e. `session_sql::bump_generation_in_txn` — bump
///      `session_meta.write_generation` LAST (#5342 Gate 8 T1′): every session
///      create/revoke takes that row, so nothing may be waited on after it.
///   f. the TEST-ONLY pre-commit hook, then COMMIT.
/// Post-commit (outside the lease): `AuditStore::count_committed` per row. The
/// caller (`AuthManager::commit_password_change`) then refreshes its own
/// `users_`/`sessions_` caches.
///
/// LOCK ORDER (a change that inverts it can deadlock): the `auth.users` row →
/// `session_store.sessions` rows → `audit_store.audit_events` (INSERT only) →
/// the `session_store.session_meta` `write_generation` row → COMMIT. The
/// generation row is LAST on purpose (#5342 Gate 8 T1′): it is the one lock
/// every session create/revoke in the fleet shares, so a wait taken while
/// holding it (formerly the audit INSERT behind a lock on `audit_events`)
/// stalled every unrelated sign-in and sign-out. Verified acyclic against every
/// other holder: no `session_store` transaction touches any other schema
/// (session_store.cpp / session_store_sql_helpers.hpp), so nothing holds
/// `session_meta` or a `sessions` row and then waits on an `auth.users` row or
/// `audit_events`; no audit writer touches `session_store`; the
/// post-mint re-read takes `auth.users` only AFTER its session INSERT has
/// committed (releasing `session_meta`); `RbacAdminAuthorityOwner` takes
/// `principal_roles` → `auth.users` and never a `session_store`/`audit_store`
/// lock. Safe ONLY because `AuthDB`, `SessionStore` and `AuditStore` share ONE
/// PgPool/database (ADR-0006; server.cpp constructs all three on `*pg_pool_`)
/// — a split onto separate databases fails every statement here closed (SQL
/// error → rollback → 503), never a silent partial write, but still needs this
/// owner re-plumbed.
///
/// Holds no in-process lock and never calls back into `AuthManager`; it borrows
/// the pool and the audit store (both outlive it — server.cpp declares this
/// owner after them and nulls `AuthManager`'s pointer at teardown).

#include "audit_store.hpp" // AuditEvent

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// What the caller asks the owner to commit. Credential material (the new
/// hash/salt and the self-change anchor) is never logged, audited or
/// serialised by the owner.
struct CredentialChangeRequest {
    enum class Kind : std::uint8_t {
        kSelf,       ///< self-service change: CAS on `expected_current_hash_hex`
        kAdminReset, ///< administrative reset: no CAS; also clears the lockout
    };
    Kind kind{Kind::kSelf};
    std::string username;
    std::string new_hash_hex; ///< PBKDF2 of the new password (computed by the caller, no lock held)
    std::string new_salt_hex;
    /// kSelf: REQUIRED — the stored hash the caller's lockout-accounted
    /// `verify_password` proved the CURRENT password against. Compared under
    /// the row lock; absent or empty on kSelf ⇒ `kConflict` (nothing written).
    /// Ignored on kAdminReset.
    std::optional<std::string> expected_current_hash_hex;
    /// Identity/request fields for the audit row(s) — principal, principal_role,
    /// principal_class, source_ip, user_agent, session_id, target_type,
    /// target_id. The owner sets `action`, `result` and `detail` itself.
    AuditEvent audit_template;
};

enum class CredentialChangeResult : std::uint8_t {
    kOk,
    kNotFound,         ///< no ACTIVE account by that name (nothing written)
    kNotLocal,         ///< SSO- or SCIM-managed account (nothing written)
    kConflict,         ///< self-change anchor is no longer the stored hash (nothing written)
    kStoreUnavailable, ///< lease/lock/statement/COMMIT failure — nothing written, UNLESS the
                       ///< connection was lost at COMMIT (then the change and its audit row
                       ///< landed together; a sign-in with the new password confirms it)
    kAuditUnavailable, ///< an audit INSERT failed (or no audit store) — the whole
                       ///< transaction rolled back, nothing written
};

struct CredentialChangeOutcome {
    CredentialChangeResult result{CredentialChangeResult::kStoreUnavailable};
    std::string target_role;           ///< the row's stored role ("admin"/"user"), kOk only
    int sessions_revoked{0};           ///< durable sessions deleted, kOk only
    bool provisional_mfa_cleared{false}; ///< an un-enrolled TOTP secret was wiped, kOk only
    bool lockout_cleared{false};       ///< kAdminReset kOk only: a lockout existed and was cleared
};

class CredentialChangeOwner {
public:
    /// Bounded acquire for the one lease, and the txn-scoped `lock_timeout`.
    /// MUST stay strictly below `AuthDB::recheck_role_locked`'s lock_timeout
    /// (auth_db.cpp kWriteTimeout, 2000 ms): a same-account sign-in queued behind
    /// a stalled change must wait out the change's abort, never fail closed and
    /// sweep the account's sessions (#5342 Gate 8 R22e).
    static constexpr std::chrono::milliseconds kWriteTimeout{1500};

    /// `audit` may be null (an audit-off wiring) — then every `commit()` answers
    /// `kAuditUnavailable` without touching the database: a credential change is
    /// never committed without its evidence row.
    CredentialChangeOwner(pg::PgPool& pool, AuditStore* audit) : pool_(pool), audit_(audit) {}

    CredentialChangeOwner(const CredentialChangeOwner&) = delete;
    CredentialChangeOwner& operator=(const CredentialChangeOwner&) = delete;
    CredentialChangeOwner(CredentialChangeOwner&&) = delete;
    CredentialChangeOwner& operator=(CredentialChangeOwner&&) = delete;

    /// The one transaction (see the file banner). Caller must hold NO lock
    /// (in-process or database) — this takes the `auth.users` row lock.
    [[nodiscard]] CredentialChangeOutcome commit(const CredentialChangeRequest& req) const;

    /// TEST-ONLY: fired inside `commit()`'s transaction AFTER the audit row(s)
    /// were inserted and BEFORE COMMIT — every lock in the banner's order is
    /// HELD. A hook may throw (→ rollback, `kStoreUnavailable`) to force an
    /// abort, or spawn a thread that races the commit; it must NOT
    /// synchronously wait on anything that needs the held `auth.users` row or
    /// `session_meta` row (a session mint does), or it self-deadlocks until
    /// `lock_timeout`. Production code MUST NOT call this. Not thread-safe:
    /// set it before the racing requests start.
    void set_pre_commit_hook_for_test(std::function<void()> hook) {
        pre_commit_hook_for_test_ = std::move(hook);
    }

private:
    pg::PgPool& pool_;
    AuditStore* audit_;
    std::function<void()> pre_commit_hook_for_test_;
};

} // namespace yuzu::server
