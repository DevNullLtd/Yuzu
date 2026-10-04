#pragma once

/**
 * auth_db.hpp — Postgres-backed authentication persistence for Yuzu Server
 * (ADR-0006 server substrate migration; schema `auth`).
 *
 * Born-on-Postgres (no `migrate_from_sqlite()` — the legacy `auth.db` is
 * retired by the release that ships this; server.cpp's construction helper
 * fails startup closed on `!is_open()`, same pattern as every other PG
 * store, ADR-0012 §1). Posture: AUTHORITATIVE — a runtime DB error is
 * surfaced via the typed `std::expected` channel, never papered over as a
 * quiet success/empty-result.
 *
 * Provides persistent storage for users, enrollment tokens, and pending
 * agents. Sessions are NOT persisted here (v1 status unchanged from the
 * SQLite era — see AuthManager's in-memory `sessions_` map, which is the
 * sole authoritative session store; this class carries no session surface
 * at all, dead-write mirror included, per the PG-migration cleanup).
 *
 * Security features:
 * - All SQL is parameterized via `pg::exec_params` (no string concatenation)
 * - `mfa_totp_secret` is envelope-encrypted at rest via `pg::SecretCodec`
 *   (ADR-0010) — never a plaintext BYTEA column
 * - Input validation on all user-controlled data
 * - Separate update_role() method (never touches credentials)
 */

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "yuzu/server/auth.hpp"  // For Role, UserEntry, PendingAgent, etc.
#include "yuzu/server/enrollment_cfg_import.hpp" // legacy-import row/result types (pure)

namespace yuzu::server::pg {
class PgPool;
class SecretCodec;
} // namespace yuzu::server::pg

namespace yuzu::server {

/// Canonical `users.provisioning_source` values (auth.db migration v7,
/// carried unchanged into the `auth.users` Postgres schema). Every
/// read/write site MUST go through these constants rather than a raw string
/// literal — a typo in either fails the SCIM provenance guard OPEN (S-PROV-
/// CONST, consistency S2): a mismatched write would tag a fresh account with
/// an unrecognised source (never revivable by SCIM), and a mismatched read in
/// `provenance_ok` would refuse to recognise a legitimately SCIM-owned row.
inline constexpr std::string_view kProvisioningSourceScim = "scim";
inline constexpr std::string_view kProvisioningSourceLocal = "local";

// ── Error Types ──────────────────────────────────────────────────────────────

// Explicit underlying type — locks ABI/serialization width so adding new
// values can never silently widen the enum across the plugin/wire boundary.
enum class AuthDBError : std::uint8_t {
    WriteFailed,
    QueryFailed,
    UserNotFound,
    InvalidUsername,
    InvalidCredentials,
    UserAlreadyExists,
    /// Returned when an MFA-domain operation finds the user already
    /// enrolled (e.g. mfa_init_enrollment called twice). Distinct from
    /// `UserAlreadyExists` (which is a create-time conflict for the
    /// users row) so SIEM rules and call-site error handlers can
    /// distinguish "you already have MFA — disable first" from "user
    /// account already exists at creation" — both surface as 409 to
    /// the wire, but the audit-detail and operator messaging differ.
    MfaAlreadyEnrolled,
    /// ★ SECURITY: an MFA operation could not confirm the state of
    /// `mfa_totp_secret` — the row's `mfa_enrolled_at` says enrolled but the
    /// stored envelope is NULL/malformed, or `pg::SecretCodec::decrypt`
    /// failed (tamper, wrong/rotated KEK unresolvable, corrupt blob). This is
    /// a DISTINCT outcome from "not enrolled" (`MfaStatus::enrolled = false`)
    /// and from "code didn't match" (`false`) — every MFA reader that touches
    /// the secret (`mfa_status`, `mfa_verify_login_code`,
    /// `mfa_verify_enrollment`, and `mfa_init_enrollment`'s provisional-reuse
    /// arm) returns this rather than silently reporting "not enrolled" or
    /// "code invalid". A caller that collapses this into either of those
    /// would let a corrupted/undecryptable secret degrade a privileged
    /// account's second factor to effectively disabled without an operator
    /// ever being told. Callers MUST surface this distinctly (503-class —
    /// retry/alert, never "reduced security posture and proceed").
    SecretUnavailable,
    /// ★ The pool lease could not be acquired (an empty lease) — a TRANSIENT
    /// store outage (pool saturation, or the shared pool's connect-backoff
    /// breaker fast-failing every acquire for its 200ms..5s window after a
    /// connectivity hiccup), NOT a query that ran and errored. Distinct from
    /// `QueryFailed`/`WriteFailed` (a SELECT/UPDATE that executed against a live
    /// connection and came back non-`PGRES_TUPLES_OK`) so the fail-closed 503
    /// site can label its degrade metric `reason=pool_acquire_timeout` vs
    /// `reason=query_error` (#2396/#2401). It is a store-unavailable outcome —
    /// `is_store_unavailable()` returns true for it and every existing 503
    /// mapping is preserved. StoreBusy means "empty lease", period: the bounded
    /// acquire-retry (`acquire_with_retry`) is orthogonal — it just reduces how
    /// often StoreBusy is returned on the two off-stripe login-decision reads
    /// (`mfa_status`/`load_mfa_row`) that can afford to wait, and there StoreBusy
    /// follows retry-exhaustion; the stripe-held login acquires
    /// (`lockout_status`/`record_failed_login`/`clear_failed_logins`) return it
    /// on a single un-retried acquire (retrying under the login stripe would
    /// amplify an outage into worker starvation — see `acquire_with_retry`).
    /// Either way it never weakens fail-closed: a genuine outage still 503s.
    /// (Other AuthDB methods outside this login set still report an acquire
    /// timeout as `QueryFailed`/`WriteFailed`; they emit no degrade metric, so
    /// the reason split does not reach them — see `is_store_unavailable`.)
    StoreBusy,
};

/// True iff `e` reflects the AuthDB store itself being unavailable (PG
/// unreachable, pool-lease timeout, secret-decrypt failure) rather than a
/// genuine business-logic outcome (bad credentials, not found, etc.). Every
/// MFA/auth call site that needs to distinguish "the store is down — 503,
/// retry" from "the request was legitimately rejected" MUST route through
/// this helper rather than inlining its own `==` chain — `WriteFailed` is
/// included because the MFA write-lease acquire (login-code consume,
/// recovery-code consume, enrollment init/verify) surfaces a PG lease-acquire
/// outage as `WriteFailed`, and a caller that only checked
/// `SecretUnavailable`/`QueryFailed` would let that outage fall through to a
/// wrong-code 401 (burning a lockout attempt) or an unhandled 500 instead of
/// the intended fail-closed 503.
[[nodiscard]] inline bool is_store_unavailable(AuthDBError e) noexcept {
    return e == AuthDBError::SecretUnavailable || e == AuthDBError::QueryFailed ||
           e == AuthDBError::WriteFailed || e == AuthDBError::StoreBusy;
}

/// `list_users_including_inactive()` row — same fields as `auth::UserEntry`
/// plus the `is_active` flag `list_users()` deliberately filters out. A NEW
/// type rather than extending `auth::UserEntry` itself: that struct is a
/// broadly-shared read contract (session/login paths never care about
/// disabled accounts), so adding a field there would be a cross-cutting
/// change out of scope for the one caller (periodic access reviews, CC6.2)
/// that needs to see disabled-but-still-granted users.
struct UserWithStatus {
    std::string username;
    auth::Role role;
    std::string identity_source{"local"};
    bool is_active{true};
};

// ── AuthDB Class ─────────────────────────────────────────────────────────────

class AuthDB {
public:
    /// Construct against the shared server `PgPool` + the shared
    /// `pg::SecretCodec` (ADR-0010) — the ctor never calls
    /// `secret_codec.init()` itself. Runs the `auth` schema migration on a
    /// pinned (unbounded, construction-only) lease and registers
    /// `mfa_totp_secret` as a secret column; the CALLER (server.cpp /
    /// main.cpp's bootstrap) runs `secret_codec.init()` AFTER this
    /// constructor returns, not before — `init()` validates every registered
    /// secret column exists, so it must run once this ctor has both migrated
    /// `auth.users` and registered the column, never ahead of it (authdb
    /// MEDIUM, governance hardening round — register-then-init, not
    /// init-then-register). `is_ready()`/
    /// `is_open()` reflects construction success (fail-CLOSED per ADR-0012
    /// §1 — a reachable database whose schema can't migrate, or a lease that
    /// can't be acquired, leaves the store closed; server.cpp's construction
    /// helper turns that into a fatal startup error, never a silent
    /// degraded-serve).
    explicit AuthDB(pg::PgPool& pool, pg::SecretCodec& secret_codec);

    /// Construct with an explicit background-reaper cadence (the reaper now
    /// sweeps ONLY stale provisional MFA enrollments — session expiry reaping
    /// is gone along with the session surface, see the file header note).
    /// `cleanup_interval_secs` ≤ 0 disables the background reaper entirely —
    /// used by unit tests that construct + destruct many AuthDB instances
    /// back-to-back (see PR #1199 for the historical macOS-arm64 rationale;
    /// still applicable to any tight construct/destruct loop). Production
    /// callers use the two-argument overload and inherit the 60-second
    /// default.
    AuthDB(pg::PgPool& pool, pg::SecretCodec& secret_codec, int cleanup_interval_secs);

    ~AuthDB();

    /// Signal the background provisional-MFA reaper to stop, WITHOUT joining.
    /// Idempotent and thread-safe; the join still happens in the destructor.
    /// `ServerImpl::stop()` calls this early — alongside the other pool-leasing
    /// background threads it stops up front — so the reaper has the whole
    /// teardown window to wind down (it checks the stop flag each 1s), making
    /// the later `auth_db_.reset()` join near-instant instead of potentially
    /// waiting out an in-flight cleanup UPDATE (which is itself bounded by the
    /// pool's statement_timeout/lock_timeout, but need not be waited on inline).
    void request_stop() noexcept;

    // Non-copyable, non-movable
    AuthDB(const AuthDB&) = delete;
    AuthDB& operator=(const AuthDB&) = delete;
    AuthDB(AuthDB&&) = delete;
    AuthDB& operator=(AuthDB&&) = delete;

    /// True iff construction succeeded (schema migrated, secret column
    /// registered) — wired into `/readyz` so an operator can detect a
    /// half-migrated `auth` schema without scraping spdlog. Lock-free.
    bool is_ready() const noexcept;

    /// Alias for `is_ready()` — the naming convention every other born-on-PG
    /// store (`ApiTokenStore`, `EnginePrincipalStore`, ...) uses. Kept as a
    /// distinct name (not a rename) because `AuthManager::is_auth_db_ok()`
    /// already calls `is_ready()`; both names reflect the identical
    /// construction-success flag.
    bool is_open() const noexcept;

    // ── User Operations ──────────────────────────────────────────────────

    /// Create a user. Username is validated (alphanumeric + ._- only, 1-64
    /// chars); `password_hash` and `salt_hex` are required.
    ///
    /// INSERT-ONLY despite the name: the statement is `INSERT ... ON CONFLICT
    /// (username) DO NOTHING`, so an EXISTING row is never touched — not its
    /// password, not its role — and the call returns `UserAlreadyExists`.
    /// (Never DO UPDATE: that reopens the TOCTOU where two concurrent creates
    /// both pass a `user_exists()` check and one silently overwrites the
    /// other's credentials.) Role changes go through `update_role()`;
    /// password changes go through `set_password()` (#5342).
    std::expected<void, AuthDBError> upsert_user(
        const std::string& username,
        const std::string& password_hash,
        const std::string& salt_hex,
        auth::Role role
    );

    /// Seed the very first (admin) user, atomically, iff the `users` table
    /// is genuinely empty — the born-on-PG replacement for the config-file/
    /// first-boot admin bootstrap. **Production seeding calls
    /// `RbacStore::provision_first_admin` instead** — `main.cpp`'s
    /// fresh-start block atomically inserts this same account plus its
    /// Administrator RBAC grant via that method, and no longer calls THIS
    /// function at all (a redundant second no-op call was removed;
    /// governance round, 2026-09-28). This function stays exported for its
    /// own unit tests and as an available primitive should a genuine
    /// "seed the first admin, no grant" need ever arise elsewhere — but it
    /// has no production caller today. Do NOT add a new fresh-start-seeding
    /// call site here — the grant-less account it would create is the exact
    /// stranded-account hazard `provision_first_admin` exists to close.
    /// `INSERT ... SELECT ... WHERE NOT EXISTS`
    /// alone is NOT race-free under READ COMMITTED (two concurrent server
    /// instances racing first boot can both see zero rows and both insert);
    /// the statement runs inside a transaction guarded by a
    /// `pg_advisory_xact_lock`, so the two processes serialize and the loser
    /// re-evaluates `WHERE NOT EXISTS` against the winner's already-committed
    /// row and correctly no-ops (governance hardening round, unhappy F2).
    ///   * `true`  — the table was empty; `username` is now the sole row,
    ///     role='admin'.
    ///   * `false` — the table already had ≥1 row; no-op, no write.
    ///   * `unexpected(msg)` — fail-CLOSED: the lease/query/write failed, or
    ///     `username` is not a valid local username. The caller MUST treat
    ///     this as "cannot determine/seed" — never as "already seeded".
    std::expected<bool, AuthDBError> seed_admin_if_empty(const std::string& username,
                                                          const std::string& password_hash,
                                                          const std::string& salt_hex);

    /// Auto-provision (or refresh) a durable row for an SSO-authenticated
    /// principal (#1852). The gate is `is_valid_principal` — a SUPERSET of
    /// `is_valid_username`: it accepts EITHER a strict local username OR a
    /// `"oidc:"`/`"saml:"`/`"ad:"`-reserved-prefixed identity; it does NOT
    /// require the reserved prefix (a bare local-shaped string is also
    /// accepted — rejected only when neither shape matches, InvalidUsername).
    /// `source` is NOT validated against `{oidc,saml,ad}` — it is written
    /// verbatim into `identity_source`, so a caller can construct a row
    /// with any `identity_source` string (a security test deliberately does
    /// this, passing `source="local"`, to build a legacy-shaped attack row
    /// for the elevate handler's source-scope guard — see
    /// `docs/security-reviews/sso-durable-identity-2026-07-03.md`).
    /// TODO(#1915): tighten this seam to enforce a reserved prefix
    /// on `principal` and `source ∈ {oidc,saml,ad}` — this call site is the
    /// ONLY intended caller (the OIDC callback), so today's looseness is
    /// latent, not actively exploitable, but it is a landmine for any future
    /// caller.
    /// On first login this INSERTs a row with `password_hash`/`salt_hex` = ''
    /// (never resolvable on the local login path — see file header note),
    /// `role='user'`, `elevation_eligible=false`. On every subsequent login
    /// the `ON CONFLICT` arm refreshes ONLY `display_name`/`last_seen_at` —
    /// it deliberately does NOT touch `role` or `elevation_eligible`, so an
    /// admin's standing role grant and JIT-elevation eligibility for this
    /// principal survive re-login. Call from the OIDC callback AFTER minting
    /// the session (independent DB I/O, not under AuthManager's `mu_`); a
    /// failure here degrades to "this principal cannot elevate", never
    /// "cannot log in" (fail-soft — see `AuthManager::provision_sso_identity`).
    std::expected<void, AuthDBError> upsert_sso_identity(const std::string& principal,
                                                          const std::string& iss,
                                                          const std::string& sub,
                                                          const std::string& display_name,
                                                          const std::string& source);

    /// Get a user by username. Returns UserEntry on success.
    std::expected<auth::UserEntry, AuthDBError> get_user(const std::string& username);

    /// List all active users.
    std::expected<std::vector<auth::UserEntry>, AuthDBError> list_users();

    /// List EVERY user row (active AND disabled), each carrying its
    /// `is_active` flag. Mirrors `list_users()`'s query with no `WHERE
    /// is_active` filter — deliberately does NOT modify or replace
    /// `list_users()` (other callers depend on its active-only contract).
    /// The sole intended caller is the periodic access review builder
    /// (`access_review_model.cpp`): a disabled user still holding a grant is
    /// materially different CC6.2 evidence than an "orphan" grant with no
    /// matching roster row at all, so the reviewer needs the full roster,
    /// not just the active slice.
    std::expected<std::vector<UserWithStatus>, AuthDBError> list_users_including_inactive();

    /// Read-only prefix scan over `users.username` (active AND soft-deleted)
    /// — backs the T8 startup collision-scan preflight (auth-engine-
    /// principals design decision log #3). `prefix` must be a code-
    /// controlled literal (e.g. `"engine:"`) — see the `.cpp` for the
    /// LIKE-metacharacter fail-closed guard. Returns nullopt on a scan error
    /// (lease/query failure) so the collision-scan preflight can fail CLOSED
    /// — an empty vector means a genuinely-completed scan with no collision,
    /// never a failed scan (symmetric with `RbacStore::find_local_groups_
    /// with_prefix`; governance G3 residual).
    std::optional<std::vector<std::string>> find_reserved_prefix_users(const std::string& prefix);

    /// Stamp `users.last_login_at = now()` for the named user. Called by
    /// AuthManager after every successful local / recovery-code login (the
    /// MFA-verified login path stamps it as part of the same UPDATE that
    /// advances mfa_last_counter, so this method is only needed for the
    /// no-MFA and OIDC paths). SOC 2 CC7.2 — without it, `last_login_at`
    /// reports stale data on dashboards and access reviews. Best-effort;
    /// failure is logged but not surfaced to the caller (session creation
    /// has already succeeded at the call site).
    void touch_last_login(const std::string& username);

    /// Soft-delete a user (sets is_active = false), clears MFA enrollment
    /// state (SOC 2 CC6.8 credential revocation on termination). Does NOT
    /// touch sessions (no session surface on this class — see file header;
    /// AuthManager wipes its own in-memory `sessions_` map for this
    /// username).
    std::expected<bool, AuthDBError> remove_user(const std::string& username);

    /// Check if a user exists (active only).
    std::expected<bool, AuthDBError> user_exists(const std::string& username);

    /// Change a user's role. ONLY updates the role column — never touches
    /// password_hash or salt_hex. This is critical for security: role changes
    /// must never overwrite credentials (C1 fix, Red Team finding).
    std::expected<void, AuthDBError> update_role(
        const std::string& username,
        auth::Role new_role
    );

    /// Set a LOCAL account's password (#5342) — the ONLY writer of
    /// `password_hash`/`salt_hex` on an existing row. One guarded
    /// `UPDATE ... RETURNING` (modelled on `update_role`), matching only a row
    /// that is ACTIVE and a genuine local account on BOTH axes —
    /// `identity_source = 'local'` (it authenticates with a local password)
    /// AND `provisioning_source = 'local'` (it is not SCIM-managed; a SCIM row
    /// carries a discarded random hash and its lifecycle belongs to the IdP).
    /// An SSO principal additionally fails `is_valid_username` up front.
    ///
    /// The same statement clears the lockout state (`failed_login_count`,
    /// `last_failed_login_at`, `locked_until`): a fresh credential must not
    /// inherit a lock armed against the old one — the same reasoning
    /// `reactivate_user` applies.
    ///
    /// `expected_current_hash`, when engaged, adds `AND password_hash = $n` — a
    /// compare-and-swap so a caller overwrites only the exact credential it
    /// last read/verified (the self-change path's "you proved THIS password"
    /// guard, and the audit-failure rollback's "restore only if nobody wrote
    /// since" guard).
    ///
    /// `forbid_admin_target`, when true, adds `AND role <> 'admin'` — the
    /// write itself refuses an admin row, so a caller that was NOT permitted
    /// to overwrite an admin's credential (`AuthManager::reset_password` with
    /// `permit_admin_target=false`) cannot be raced past by a promotion that
    /// commits between its read and this UPDATE. The role check and the write
    /// are one statement, so there is no window between them.
    ///
    /// Returns `UserNotFound` when ZERO rows matched — absent, inactive, not
    /// local, the role guard refused an admin row, OR the CAS predicate
    /// failed. The store deliberately draws no
    /// distinction (no oracle at this layer); a caller that must answer 404
    /// vs 409 reads the row (`get_user` + `get_provisioning_source`) BEFORE the
    /// write. `InvalidUsername` for a malformed username, `InvalidCredentials`
    /// for an empty hash/salt, `WriteFailed` on a lease/query failure. Never
    /// logs the hash.
    std::expected<void, AuthDBError>
    set_password(const std::string& username, const std::string& password_hash,
                 const std::string& salt_hex,
                 const std::optional<std::string>& expected_current_hash = std::nullopt,
                 bool forbid_admin_target = false);

    /// Row-locked role + credential re-check (#4107, extended by #5274):
    /// `SELECT role, password_hash FROM auth.users WHERE username = $1 AND
    /// is_active FOR UPDATE`, same technique
    /// `mfa_verify_login_code` already uses to close ITS OWN replay race.
    /// Serializes against ANY concurrent `update_role()` write to this row:
    /// if one is already committed, this call's SELECT sees it directly; if
    /// one is mid-flight (issued, not yet committed), this call's SELECT FOR
    /// UPDATE blocks until it commits, then reads the fresh row (standard
    /// Postgres row-lock semantics — a plain `UPDATE` already takes an
    /// equivalent row lock for its own transaction's duration, so the writer
    /// side needs no changes). Either way, the value handed to
    /// `under_row_lock` is never a value some OTHER writer's already-
    /// in-flight commit could invalidate a moment later.
    ///
    /// `reactivate_user()` is asymmetric (authdb Gate 8 finding), because its
    /// `UPDATE` deliberately carries no `is_active` filter (it's the only
    /// writer allowed to flip a row from inactive back to active) while THIS
    /// SELECT is filtered to `is_active = TRUE`. So: if the row is active
    /// when this call runs, it genuinely serializes against a concurrent
    /// `reactivate_user()` exactly like `update_role()` (either blocks
    /// behind that UPDATE's in-flight lock, or that UPDATE blocks behind
    /// this one). But if the row's last-COMMITTED state is already inactive,
    /// this SELECT's `is_active = TRUE` qualifier excludes it under its own
    /// READ COMMITTED snapshot — zero rows, `UserNotFound`, immediately, with
    /// nothing to wait on. That holds regardless of whether a
    /// `reactivate_user()` happens to be concurrently uncommitted at that
    /// exact instant (authdb Gate 8 correction: an earlier draft attributed
    /// this to "no writer in flight," which isn't the actual discriminator —
    /// READ COMMITTED never sees another transaction's uncommitted write in
    /// the first place, so the row's last-committed value is what decides
    /// this, not in-flight timing). That's not a missed serialization, it's
    /// the correct fail-closed answer (a recheck on an inactive account
    /// should deny), but it means this call never blocks a *fresh*
    /// `reactivate_user()` call starting against an already-inactive row —
    /// there is no lock to contend for at that point.
    ///
    /// #5274: `under_row_lock` also receives the row's CURRENT
    /// `password_hash`, read under the same lock, so the credential check can
    /// deny when the hash it just verified the password against is no longer
    /// the stored one (a `set_password` committed between the caller's read
    /// and this lock — a password change racing a login). `set_password`'s
    /// UPDATE takes the same row lock, so the hash seen here is never one
    /// another writer's in-flight commit can invalidate a moment later.
    ///
    /// `under_row_lock` runs WHILE the row lock is held, immediately before
    /// this call commits (releasing the lock) — use it to update
    /// AuthManager's in-process cache under `mu_` before the lock is
    /// released, so nothing else can commit a role change to this row while
    /// the cache write is happening. Do NOT do any additional DB I/O inside
    /// the callback (same rule `with_txn_on`'s doc states for its own
    /// callers) — only fast, local, in-process work.
    ///
    /// This closes the SAME-PROCESS divergence residual (#4107) that an
    /// in-memory-only version counter could only detect after the fact, not
    /// prevent — but it does NOT close the separate, narrower "check-then-
    /// mint" gap between this call returning and the caller actually minting
    /// a session (`persist_new_session`): that gap is inherent to any
    /// recheck that isn't ITSELF serialized all the way through session
    /// creation, which this is not (external adversarial review, fjarvis,
    /// PR #4076 — "an inherent check-then-mint gap no non-serialized recheck
    /// can close").
    ///
    /// Returns `UserNotFound` (callback not invoked) if the account is not
    /// active — mirrors `get_user()`'s filter, including for a
    /// `remove_user()` that lands first (its soft-delete UPDATE sets
    /// `is_active = FALSE`, participating in the SAME row-lock protocol, so
    /// this SELECT's `WHERE ... AND is_active` correctly sees zero rows once
    /// a concurrent removal has committed, or blocks until one in flight
    /// does). `InvalidUsername` / `QueryFailed` on the usual input/store
    /// failures, callback not invoked either way.
    std::expected<void, AuthDBError>
    recheck_role_locked(
        const std::string& username,
        const std::function<void(auth::Role, const std::string& password_hash)>& under_row_lock);

    /// Set/clear the per-user JIT-elevation eligibility flag (SOC 2 CC6.3/CC6.6):
    /// who may activate a time-boxed admin elevation via POST /api/v1/elevate,
    /// distinct from holding standing admin. Admin-managed. Single
    /// UPDATE ... RETURNING (RETURNING is the mutate-and-return idiom on this
    /// store — never `sqlite3_changes()`-equivalent row-count polling).
    /// UserNotFound when no active row matched, InvalidUsername for malformed
    /// input. Never touches credentials or role.
    std::expected<void, AuthDBError> set_elevation_eligible(const std::string& username,
                                                            bool eligible);

    /// Read the per-user JIT-elevation eligibility flag. Returns false for an
    /// absent/inactive user (fail-closed — not eligible). InvalidUsername for
    /// malformed input.
    std::expected<bool, AuthDBError> is_elevation_eligible(const std::string& username);

    /// Set the provenance marker for a user (SCIM v2 provisioning, slice 1 —
    /// storage layer only). Distinct from `identity_source` (v6, how a user
    /// authenticates): this is the security seam that lets a future SCIM
    /// deprovisioning path refuse to deactivate/delete a user it did not
    /// create. `source` is caller-supplied ("local" | "scim") — this
    /// storage-layer accessor does not itself enforce the enum; the SCIM
    /// route layer is the trusted caller. Single UPDATE ... RETURNING.
    /// UserNotFound when no active row matched, InvalidUsername for malformed
    /// input. Never touches credentials or role.
    std::expected<void, AuthDBError> set_provisioning_source(const std::string& username,
                                                              const std::string& source);

    /// Read the provenance marker for a user. UNLIKE most accessors on this
    /// class, this deliberately reads REGARDLESS of `is_active` (soft-deleted
    /// rows included) — the SCIM provenance guard must be able to approve a
    /// PATCH/PUT active=true reactivation while the row is still inactive,
    /// i.e. exactly the moment before `reactivate_user` flips it back.
    /// UserNotFound only when no row (active or not) matched; InvalidUsername
    /// for malformed input.
    std::expected<std::string, AuthDBError>
    get_provisioning_source(const std::string& username);

    /// Set the `identity_source` marker (auth.db migration v6, carried
    /// unchanged into `auth.users`) directly — distinct from
    /// `set_provisioning_source` (WHO manages the account's lifecycle) —
    /// this is HOW the account authenticates, the same column
    /// `upsert_sso_identity` writes for OIDC rows and the Settings user list
    /// reads to render the "SSO" badge (S-IDENTITY-SRC). SCIM provisioning is
    /// its own login surface (IdP-driven, no local password usable — see
    /// `scim_routes.cpp`), so it gets its own value rather than being rendered
    /// as `'local'`-login-capable. `source` is caller-supplied; this storage-
    /// layer accessor does not itself enforce an enum. Single UPDATE ...
    /// RETURNING. UserNotFound when no active row matched, InvalidUsername
    /// for malformed input. Never touches credentials, role, or
    /// provisioning_source.
    std::expected<void, AuthDBError> set_identity_source(const std::string& username,
                                                          const std::string& source);

    /// Reactivate a soft-deleted (`is_active = false`) user row — the SCIM v2
    /// PATCH/PUT `active: true` (un-suspend) path, and the only writer of
    /// `is_active = true` on an EXISTING row (every other UPDATE in this
    /// file filters `WHERE ... AND is_active = TRUE`, and `upsert_user` is
    /// INSERT ... ON CONFLICT DO NOTHING — neither can revive a soft-deleted
    /// row).
    ///
    /// Semantics (deliberate, do not "improve" without a fresh security
    /// review): clears `failed_login_count` / `last_failed_login_at` /
    /// `locked_until` — a returning user must not inherit a stale lockout
    /// from before they were deprovisioned. Does NOT touch
    /// `mfa_totp_secret` / MFA enrollment state — `remove_user` wiped that
    /// deliberately on deactivation (see its header comment) and this does
    /// NOT restore it; the user re-enrolls per the configured MFA
    /// enforcement mode. Does NOT touch `provisioning_source` or `role` —
    /// both stay whatever they were before deactivation.
    ///
    /// UserNotFound when no row (active OR inactive) matched `username`,
    /// InvalidUsername for malformed input. Reactivating an ALREADY-active
    /// user is a harmless no-op (still returns success).
    std::expected<void, AuthDBError> reactivate_user(const std::string& username);

    /// Reap provisional MFA enrollment rows (init'd but never verified)
    /// older than `older_than`. Clears `mfa_totp_secret` to NULL on any
    /// row whose `mfa_enrolled_at IS NULL` AND `updated_at` is older
    /// than the cutoff. Returns the count of rows cleared. SOC 2 CC6.6 —
    /// dangling provisional secrets are usable until verified, and a
    /// stale provisional row that survives indefinitely is a CC6.6
    /// finding. Called on the background-reaper cadence (constructor's
    /// `cleanup_interval_secs`).
    std::expected<int, AuthDBError>
    cleanup_provisional_mfa(std::chrono::seconds older_than = std::chrono::hours(1));

    // ── Account-lockout Operations ───────────────────────────────────────
    //
    // SOC 2 CC6.3 — brute-force / credential-stuffing protection on the
    // local-password login path. See `/auth-and-authz` skill gap matrix
    // entry P0 #2 and docs/auth-architecture.md. Lockout state lives as
    // three columns on `auth.users`: failed_login_count,
    // last_failed_login_at, locked_until. A non-existent username has no
    // row, so spraying random usernames cannot grow storage and cannot lock
    // a non-existent account. Policy (threshold + window) is owned by the
    // caller (ServerConfig) and passed in, so AuthDB stays policy-free and
    // an operator can retune without a schema change. The lockout is
    // temporary/auto-expiring (locked_until is a future timestamp), so it
    // cannot be weaponised to permanently DoS a legitimate principal.
    // `locked_until > now()` is evaluated in SQL, never a parsed string.

    struct LockoutStatus {
        bool locked{false};       // locked_until is set AND still in the future
        int failed_count{0};      // current consecutive-failure counter
        std::string locked_until; // UTC timestamp text, or "" when unlocked
    };

    struct LockoutRecord {
        int failed_count{0};      // counter value AFTER this failure
        bool locked{false};       // account is locked after this failure
        bool just_locked{false};  // this failure is the one that crossed the threshold
        std::string locked_until; // UTC timestamp text, or "" when not locked
    };

    /// Read-only lockout pre-check. Returns a zero-initialised LockoutStatus
    /// (locked=false) when the user row is absent — callers treat "no such
    /// user" as "not locked" so the bad-username path is indistinguishable
    /// from the bad-password path (anti-enumeration). Returns InvalidUsername
    /// for malformed input.
    std::expected<LockoutStatus, AuthDBError> lockout_status(const std::string& username);

    /// Record one failed local-password attempt. Increments the counter,
    /// stamps last_failed_login_at, and sets locked_until = now + window the
    /// moment the counter reaches `threshold`. Single UPDATE ... RETURNING.
    /// No-op (failed_count=0, not locked) when `threshold <= 0` or the user
    /// row is absent.
    std::expected<LockoutRecord, AuthDBError>
    record_failed_login(const std::string& username, int threshold, int window_secs);

    /// Clear lockout state on a successful login or admin unlock. Resets the
    /// counter to 0 and NULLs both timestamps. Idempotent; no-op on absent
    /// rows. Returns InvalidUsername for malformed input.
    std::expected<void, AuthDBError> clear_failed_logins(const std::string& username);

    // ── Break-glass arming (hardened mode) ───────────────────────────────
    //
    // SOC 2 CC6.6. See docs/auth-architecture.md "Hardened mode". The single
    // configured break-glass account (Config::break_glass_user) is exempt from
    // --auth-mode=sso-only ONLY while armed. "Armed" is a future timestamp in
    // users.break_glass_armed_until, evaluated in SQL against now() exactly
    // like locked_until, so the exemption auto-expires and is never a
    // permanent standing bypass. Arming is an out-of-band host operation
    // (--break-glass-arm), not a session-authenticated route, so it works when
    // the IdP is down (the case break-glass exists for).

    struct BreakGlassStatus {
        bool armed{false};        // break_glass_armed_until set AND still in the future
        std::string armed_until;  // UTC timestamp text, or "" when dormant
    };

    /// Read-only break-glass arm check. Returns a zero-initialised
    /// BreakGlassStatus (armed=false) when the user row is absent. Returns
    /// InvalidUsername for malformed input.
    std::expected<BreakGlassStatus, AuthDBError> break_glass_status(const std::string& username);

    /// Arm the break-glass account for `window_secs` from now. Single
    /// UPDATE ... RETURNING. Returns UserNotFound when no active user row
    /// matched (so the host operator gets a clear error rather than a silent
    /// no-op), InvalidUsername for malformed input.
    std::expected<BreakGlassStatus, AuthDBError> arm_break_glass(const std::string& username,
                                                                 int window_secs);

    /// Disarm the break-glass account (set break_glass_armed_until = NULL).
    /// Used as the compensating un-arm when the mandatory `auth.breakglass.armed`
    /// audit row fails to persist after `arm_break_glass` succeeded — so the
    /// exemption is never left standing without an evidence row (review #1735
    /// HIGH-2; honours the "never granted without a record" guarantee in
    /// docs/ops-runbooks/auth-db-recovery.md). Idempotent; InvalidUsername for
    /// malformed input.
    std::expected<void, AuthDBError> disarm_break_glass(const std::string& username);

    // ── MFA / TOTP Operations ────────────────────────────────────────────
    //
    // SOC 2 CC6.6 (privileged access). See docs/auth-mfa-design.md and
    // `/auth-and-authz` skill gap matrix entry P0 #1.
    //
    // `mfa_totp_secret` is envelope-encrypted at rest (ADR-0010,
    // `pg::SecretCodec`, `SecretId{"auth","users","mfa_totp_secret",<id>}`) —
    // every reader below that TOUCHES the secret (as opposed to only the
    // `mfa_enrolled_at`/`mfa_disabled_at` markers) attempts a decrypt and
    // returns `AuthDBError::SecretUnavailable` — DISTINCT from "not
    // enrolled" / "code didn't match" — on ANY decrypt failure. See
    // `AuthDBError::SecretUnavailable`'s doc comment for why this matters:
    // collapsing a decrypt failure into "not enrolled" would silently
    // degrade a privileged account's second factor.
    //
    // Lifecycle: mfa_init_enrollment writes a fresh 20-byte HMAC-SHA1
    // secret (envelope-encrypted) to users.mfa_totp_secret but leaves
    // mfa_enrolled_at NULL — the row is "provisional" until
    // mfa_verify_enrollment lands a code that proves the user has actually
    // scanned the otpauth URI. Calling mfa_init_enrollment again on a
    // provisional row REUSES (decrypts and re-reveals) the existing secret
    // rather than rotating it — and on a decrypt failure of that provisional
    // secret, FAILS CLOSED (`SecretUnavailable`) rather than silently
    // minting a fresh one, which would silently invalidate an
    // already-in-progress enrollment the operator believes is still valid.
    // Calling it on an already-enrolled row returns
    // AuthDBError::MfaAlreadyEnrolled (caller must mfa_disable first).
    //
    // Replay protection: mfa_verify_login_code persists the matched
    // counter as mfa_last_counter and rejects any subsequent code <= that
    // value within the ±skew window. The skew is hard-coded to ±1 step
    // (90 s effective window) — RFC 6238 recommends a small skew and the
    // server clock is assumed to be NTP-synced.

    struct MfaStatus {
        bool enrolled{false};
        // UTC timestamp text ("YYYY-MM-DD HH:MM:SS") or empty. Returned as
        // strings rather than parsed time_points because v1 only displays
        // them; converting at the DB boundary would require chrono parsing
        // helpers that aren't yet in tree.
        std::string enrolled_at;
        std::string disabled_at;
        int recovery_codes_remaining{0};
    };

    struct MfaEnrollmentInit {
        std::string secret_base32;
        std::string otpauth_uri;
    };

    /// Read MFA status for a user. TRI-STATE contract (★ security-critical —
    /// see `AuthDBError::SecretUnavailable`):
    ///   * `MfaStatus{enrolled=true, ...}`  — the row is enrolled AND the
    ///     secret decrypted cleanly.
    ///   * `MfaStatus{enrolled=false, ...}` — the row genuinely has no MFA
    ///     configured (`mfa_enrolled_at IS NULL`; a provisional secret, if
    ///     any, is not "enrolled").
    ///   * `unexpected(SecretUnavailable)`  — the row IS enrolled
    ///     (`mfa_enrolled_at` set) but the secret is NULL/malformed or fails
    ///     to decrypt. NEVER collapsed into `enrolled=false` — a caller that
    ///     did so would report a privileged account as having no second
    ///     factor when it actually has one that is merely unreadable right
    ///     now.
    ///   * `unexpected(QueryFailed)` / `UserNotFound` / `InvalidUsername` —
    ///     unchanged from the SQLite-era contract.
    std::expected<MfaStatus, AuthDBError> mfa_status(const std::string& username);

    /// Generate a fresh TOTP secret and write it as provisional (encrypted).
    /// Returns the base32 form + otpauth URI for the enrollment UI.
    /// Idempotent on provisional rows (reuse, not rotate — see the file
    /// header MFA note); returns UserAlreadyExists — er, MfaAlreadyEnrolled —
    /// on already-enrolled rows; returns SecretUnavailable (never a fresh
    /// mint) if an existing provisional secret fails to decrypt.
    std::expected<MfaEnrollmentInit, AuthDBError>
    mfa_init_enrollment(const std::string& username, std::string_view issuer);

    /// Verify the first code against the provisional secret. On success,
    /// stamps mfa_enrolled_at = now(), generates 10 recovery codes (returned
    /// raw, hashed in DB), and returns the codes for the one-time reveal.
    /// Idempotent on already-enrolled rows: returns MfaAlreadyEnrolled.
    /// Returns SecretUnavailable if the provisional secret fails to decrypt
    /// (never silently rejects the code as wrong).
    std::expected<std::vector<std::string>, AuthDBError>
    mfa_verify_enrollment(const std::string& username, std::string_view code);

    /// Verify a TOTP code for login or step-up. Persists the matched
    /// counter to mfa_last_counter on success. Returns `true` on match,
    /// `false` on no-match OR on a user with no MFA configured at all (no
    /// row / no secret present — genuinely nothing to verify against).
    /// Returns `unexpected(SecretUnavailable)` — NEVER silently `false` — if
    /// the user IS enrolled but the secret fails to decrypt: a caller that
    /// treated a decrypt failure as "code didn't match" would let a
    /// SecretCodec/KEK outage silently lock every MFA-enrolled user out
    /// indistinguishably from a bad code, instead of surfacing the real
    /// (retryable) fault.
    std::expected<bool, AuthDBError> mfa_verify_login_code(const std::string& username,
                                                          std::string_view code);

    /// Consume a single recovery code for login or step-up. Returns true
    /// if the code matched an unconsumed row (and that row is now
    /// consumed). False on no-match (also false if the user has no
    /// recovery codes / is not enrolled). Recovery codes are PBKDF2-hashed,
    /// not envelope-encrypted (verify-only, ADR-0010 — no SecretCodec
    /// involvement, no SecretUnavailable outcome here).
    std::expected<bool, AuthDBError> mfa_consume_recovery_code(const std::string& username,
                                                               std::string_view raw_code);

    /// Wipe the user's existing recovery codes and issue 10 fresh ones.
    /// Returns the raw codes for one-time display. Serialized on the
    /// `auth.users` row (`SELECT … FOR UPDATE`) so concurrent regenerates — and
    /// a regenerate racing an enrollment/disable/remove — are ordered rather
    /// than interleaving into a torn 20-row set with the returned codes not
    /// matching storage (#3779). Returns `UserNotFound` when no ACTIVE user row
    /// matches (a deactivated account never receives fresh codes);
    /// `QueryFailed`/`WriteFailed` on a store outage (fail-closed 503).
    std::expected<std::vector<std::string>, AuthDBError>
    mfa_regenerate_recovery_codes(const std::string& username);

    /// Disable MFA for a user. Clears the secret column, stamps
    /// mfa_disabled_at, and deletes all recovery codes. Idempotent on
    /// not-enrolled rows.
    std::expected<void, AuthDBError> mfa_disable(const std::string& username);

    // ── Enrollment tokens + pending agents (WS-6 slice 6.2, ADR-2002 §8) ─────
    //
    // Authoritative, fleet-wide (every replica shares one PG), and FAIL-CLOSED:
    // every method returns `std::expected<_, StoreError>` so a store outage is a
    // typed error the caller maps to gRPC UNAVAILABLE / HTTP 503 — NEVER an empty
    // list, a `0` count, "absent", or "rejected" (an unreadable pending row that
    // read as "absent" would let a denied agent fall through to add_pending/
    // consume, #3401). Timestamps are authored from PG `now()` in SQL and token
    // expiry is evaluated in SQL (DB-clock authority, ADR-2002 §4) — never the
    // replica's `system_clock`. Raw tokens are hashed on entry (SHA-256) and are
    // never logged, never a column; only the 8-hex `token_id` appears in logs.
    // Text inputs are length-capped (`kMaxEnrollmentTextLength`) and rejected on
    // an embedded NUL (`StoreError::InvalidInput`), never silently truncated.

    /// Shared with `auth::AuthManager` (defined in auth.hpp, which must not
    /// include this header): the create result and the atomic-consume outcome.
    using CreatedEnrollmentToken = auth::CreatedEnrollmentToken;
    using ConsumeEnrollResult = auth::ConsumeEnrollResult;

    /// Maximum length of any free-text field (label, hostname, os, arch,
    /// agent_version, principal) accepted by the enrollment/pending store.
    /// `agent_id` uses `auth::kMaxAgentIdLength`, the raw token
    /// `auth::kMaxEnrollmentTokenLength`.
    static constexpr std::size_t kMaxEnrollmentTextLength = auth::kMaxEnrollmentTextLength;

    /// Upper bound on a token TTL (~100 years). `0` = never expires.
    static constexpr std::int64_t kMaxEnrollmentTtlSeconds = 3'153'600'000;

    /// Create a token. `max_uses` 0 = unlimited; `ttl` 0 = never expires.
    /// The token_id (8 hex of the hash) is regenerated on a UNIQUE violation —
    /// an existing token is never overwritten.
    std::expected<CreatedEnrollmentToken, StoreError>
    create_token(const std::string& label, int max_uses, std::chrono::seconds ttl,
                 const std::string& created_by);

    /// Test seam for `create_token`'s regenerate-on-collision loop: `entropy`
    /// supplies the 32 raw bytes for each attempt. Production callers use
    /// `create_token` (CSPRNG).
    std::expected<CreatedEnrollmentToken, StoreError>
    create_token_with_entropy(const std::string& label, int max_uses, std::chrono::seconds ttl,
                              const std::string& created_by,
                              const std::function<std::vector<std::uint8_t>()>& entropy);

    /// Revoke by token_id. true = a row exists (idempotent), false = unknown id.
    std::expected<bool, StoreError> revoke_token(const std::string& token_id);

    /// All tokens, newest first. `expires_at == time_point::max()` = never.
    std::expected<std::vector<auth::EnrollmentToken>, StoreError> list_tokens();

    /// THE atomic enrollment claim: ONE transaction that (1) counts a use of the
    /// token (single guarded UPDATE — exactly-N winners across replicas), then
    /// (2) upserts the agent row to `approved` unless an admin denied it; a
    /// denial ROLLS BACK step 1. A miss on step 1 is classified in the same txn.
    std::expected<ConsumeEnrollResult, StoreError>
    consume_and_enroll(std::string_view raw_token, const std::string& agent_id,
                       const std::string& hostname, const std::string& os,
                       const std::string& arch, const std::string& agent_version);

    /// Five-state pending lookup: a value = approved/denied/pending; `nullopt` =
    /// absent; `unexpected` = ERROR (callers MUST NOT treat as absent).
    std::expected<std::optional<auth::PendingStatus>, StoreError>
    pending_status(const std::string& agent_id);

    /// Queue an unenrolled agent as `pending`. `true` = NEWLY added (gates the
    /// analytics event + SSE publish); `false` = a row already existed (unchanged).
    std::expected<bool, StoreError> add_pending(const auth::PendingAgent& agent);

    /// No-token enrollment path: upsert to `approved` unless denied. `true` =
    /// enrolled, `false` = admin-denied (tokens/no-token paths never override a
    /// denial). `by` is recorded as `status_changed_by`.
    std::expected<bool, StoreError> ensure_enrolled(const auth::PendingAgent& agent,
                                                    const std::string& by);

    /// Rows newest-first; `only` filters to one status.
    std::expected<std::vector<auth::PendingAgent>, StoreError>
    list_pending(std::optional<auth::PendingStatus> only = std::nullopt);

    /// Set status approved/denied for an existing row. `true` = row existed.
    std::expected<bool, StoreError> approve_pending(const std::string& agent_id,
                                                    const std::string& principal);
    std::expected<bool, StoreError> deny_pending(const std::string& agent_id,
                                                 const std::string& principal);

    /// Bulk: every currently-`pending` row -> approved/denied in one statement
    /// (`UPDATE .. WHERE status='pending' RETURNING agent_id`). Returns the
    /// agent_ids affected (for audit + SSE).
    std::expected<std::vector<std::string>, StoreError>
    approve_all_pending(const std::string& principal);
    std::expected<std::vector<std::string>, StoreError>
    deny_all_pending(const std::string& principal);

    /// Hard-delete a row, but ONLY when its status is `pending` — see
    /// `auth::RemovePendingOutcome`'s doc comment for why an `approved`/`denied`
    /// row is refused instead of deleted.
    std::expected<auth::RemovePendingOutcome, StoreError>
    remove_pending(const std::string& agent_id);

    // ── One-time legacy .cfg import (WS-6 6.2; see enrollment_cfg_import.hpp) ──
    //
    // Each call is ONE transaction under a dedicated advisory lock
    // (`pg_advisory_xact_lock(2037545589, 2)`, auth_db.cpp), so two replicas racing
    // first boot with identical files serialise: the loser sees the winner's marker
    // and returns `already_imported`. `marker_key` is the per-FILE-KIND key in
    // `auth.import_meta`; `fingerprint` the sha256 of the file bytes. Marker
    // present + same fingerprint => `already_imported`; present + DIFFERENT =>
    // `fingerprint_mismatch` (nothing written - restored-old-backup case, "refused,
    // not merged"); absent => rows inserted and the marker stamped in the SAME txn.
    // Rows are INSERT .. ON CONFLICT DO NOTHING keyed on token_hash / agent_id, so
    // Postgres state (a higher use_count, a revoke, a deny, a removal) ALWAYS wins
    // over the file. Any PG error rolls the whole txn back (no marker) and returns
    // `StoreError` - the caller refuses to start. Never uses the file's token_id:
    // the id is the hash prefix, lengthened per row on a collision with a DIFFERENT
    // token so both survive.
    std::expected<enrollment_import::ImportDbResult, StoreError>
    import_legacy_tokens(std::string_view marker_key, std::string_view fingerprint,
                         const std::vector<enrollment_import::LegacyToken>& rows,
                         std::string_view imported_by);
    std::expected<enrollment_import::ImportDbResult, StoreError>
    import_legacy_pending(std::string_view marker_key, std::string_view fingerprint,
                          const std::vector<enrollment_import::LegacyPending>& rows,
                          std::string_view imported_by);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ── Utility Functions ────────────────────────────────────────────────────────

/// Validate username format.
/// Rules: 1-64 chars, alphanumeric + . _ - only, no ':' (config injection).
bool is_valid_username(const std::string& username);

/// True iff `username` begins with a reserved SSO-principal or engine-
/// principal namespace prefix (`oidc:`, `saml:`, `ad:`, `engine:`; case-
/// insensitive). Defense-in-depth for the LOCAL-user CREATE path only —
/// `is_valid_username`'s existing ':' rejection already makes the exact
/// stable-principal string `oidc:<iss>#<sub>` (or `engine:<slug>`)
/// unconstructable as a local username, but an explicit reservation
/// documents the intent and survives a future loosening of that charset.
/// `engine:` reservation is the auth-engine-principals design §3.3 / PR 4.2.
/// Without it, an admin could otherwise create a local user that collides
/// with (or is later made to collide with) an SSO-derived principal — that
/// local user's row would supply the eligibility/TOTP an SSO principal
/// deliberately lacks (#1837), re-opening the elevation-borrow hazard.
/// Deliberately NOT folded into `is_valid_username` (used at ~20 sites; its
/// contract must stay charset-only). Callers apply this ONLY at user-creation
/// chokepoints, never at target-lookup/validation sites for existing users.
bool is_reserved_identity_prefix(const std::string& username);

/// Validate a value that may be EITHER a strict local username OR a durable
/// SSO principal (`"oidc:"`/`"saml:"`/`"ad:"` + issuer + `#` + subject,
/// #1852). A strict superset of `is_valid_username`: anything the strict
/// validator accepts is accepted here unchanged; a reserved-prefixed string
/// is additionally accepted after a narrow control-byte / SQL-metacharacter
/// blocklist (permits `: # / . _ - @ ~ % |` — the IdP issuer URL + opaque
/// sub alphabet), capped at 255 bytes. Use ONLY at target-lookup/validation
/// chokepoints for an EXISTING user (elevation eligibility, session revoke)
/// — never at user-creation chokepoints, which must keep using
/// `is_valid_username` (+ `is_reserved_identity_prefix` to reserve the SSO
/// namespace) so a local account can never be created inside it.
/// `is_reserved_identity_prefix` now also reserves `engine:` — this widens
/// the *format* this validator accepts, but no `users` row can ever actually
/// carry that prefix: local creation stays blocked by `is_valid_username`'s
/// ':' ban, and `upsert_sso_identity`'s principal is always
/// `source + ":" + iss + "#" + sub` with `source` a caller-controlled
/// literal in {"oidc","saml","ad"} — never "engine".
bool is_valid_principal(const std::string& s);

/// Validate that `username` is usable as the hardened-mode break-glass account:
/// a syntactically valid username naming an existing ACTIVE user that has MFA
/// enrolled. Returns std::nullopt when usable, otherwise an operator-facing
/// reason string. Mandatory-MFA is enforced here, fail-closed (SOC 2 CC6.6) so
/// the sso-only escape hatch can never be a bare-password account; a store read
/// error is also a problem (never report a broken account as usable). Because
/// `mfa_status` filters `is_active = true`, a soft-deleted user reads as
/// not-enrolled and is correctly rejected. Shared by the server boot guard and
/// the `--break-glass-arm` one-shot so both apply one contract.
std::optional<std::string> break_glass_account_problem(AuthDB& db, const std::string& username);

} // namespace yuzu::server
