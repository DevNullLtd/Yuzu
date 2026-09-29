#pragma once

/**
 * session_store.hpp -- Durable operator sessions in Postgres (HA WS-1/1a, ADR-2002 §4)
 *
 * Moves operator sessions from `AuthManager`'s process-local `sessions_` map
 * (steady_clock, in-memory) to durable Postgres rows, so a session survives a
 * core-replica restart/failover and validates identically on any replica.
 *
 * This store is AUTHORITATIVE (ADR-0012 / postgres-store-playbook "Authoritative
 * reads"): a database error is type-distinguishable from "no such session" —
 * reads return `std::expected<std::optional<SessionRow>, Error>` where `nullopt`
 * means "definitively absent" and `unexpected` means "cannot tell" (a caller in
 * the auth path must NEVER treat a degraded read as "not a valid session" in a
 * way that silently grants; it fails the request rather than guessing).
 *
 * WALL-CLOCK, DB-CLOCK AUTHORITY (ADR-2002 §4, the reversal — completed WS-1/1a).
 * Sessions were in-memory on a MONOTONIC (steady_clock) clock specifically for
 * NTP-step resistance. Durability forces wall-clock. Every durable timestamp is
 * AUTHORED from Postgres `now()` (this store, in SQL), NOT the calling replica's
 * `system_clock` — so any replica dates a session in the ONE DB clock domain,
 * which is what fixes cross-HOST skew. Reads (`find`) return `db_now_ms` in the
 * same atomic SELECT; the caller adjudicates absolute expiry / idle / elevation /
 * MFA against `db_now_ms` and then derives a LOCAL MONOTONIC (steady_clock)
 * remaining-duration deadline for its per-request validate cache (AuthManager),
 * so the hot path touches neither the DB nor the local wall clock.
 *
 * A backward clock step on the DB primary is the residual the reversal admits (it
 * would lower `now()`, inflating a derived remaining, and un-expiring a session).
 * Four layered defences bound it (the store authors + reaps; AuthManager derives
 * + enforces):
 *   (1) the caller CLAMPS every derived remaining so a lowered `db_now` cannot
 *       inflate the LIVED duration past its authored maximum — elevation against
 *       `elevation_issued_ms + kMaxElevationWindow`, MFA against its window
 *       ceiling, the base session against `created_at_ms` (H2 in the design
 *       review — the ceilings clamp the derived remaining, not merely validate
 *       the stored width);
 *   (2) elevation carries an `elevation_issued_ms` anchor: `is_elevated()`
 *       rejects a window `elevated_until_ms - elevation_issued_ms` over the hard
 *       `kMaxElevationWindow` ceiling, AND a future issued-at; MFA rejects a
 *       future-dated proof (`mfa_verified_ms > db_now` treated as absent);
 *   (3) a LOCAL wall-clock sanity ceiling backstops steady_clock's suspend-
 *       blindness (a suspended replica's monotonic clock pauses and would else
 *       over-live a cached session — H5);
 *   (4) DB-primary clock integrity is a monitored security dependency: `reap`
 *       declines and raises `clock_anomaly` on a backward `now()`, alerted on
 *       (ADR-2002 §4 mitigation (a)).
 *
 * SECRET-AT-REST. The row key is a verify-only SHA-256 of the bearer session
 * token, never the raw token (a DB read must not yield a usable session cookie).
 * The caller hashes the token; this store only ever sees the hash.
 *
 * VALIDATE-CACHE (the rbac_store pattern). Per-request session validation must
 * not hit Postgres every call. AuthManager keeps a process-local cache validated
 * against a durable generation counter (`session_meta.write_generation`) that is
 * bumped IN THE SAME TXN as every membership/authz-affecting mutation (create,
 * invalidate, elevate, revoke-elevation, mfa-verify). `touch_activity` is a
 * sliding idle update and deliberately does NOT bump the generation. This store
 * owns the durable side (mutations bump; `read_generation()` reads); the cache
 * itself lives in AuthManager.
 *
 * RETENTION. `reap_expired()` is a wall-clock bulk delete, so once sessions are
 * durable it joins the clock-guarded-retention set (routed concern #2360/#2361 —
 * previously the in-memory monotonic sweep was exempt "by construction"). It is
 * single-writer-safe across replicas via a `pg_advisory_xact_lock` taken as its
 * own statement before the check-and-delete, and it is capped + guarded.
 */

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// A durable session row, in wall-clock epoch-milliseconds. Mirrors the
/// authz-relevant fields of `struct Session` (auth.hpp); presentation-only
/// fields the map held but auth never keys on are carried verbatim.
struct SessionRow {
    std::string token_hash; ///< SHA-256 (hex) of the bearer token — the primary key
    std::string username;   ///< stable auth principal
    std::string display_name;
    std::string role; ///< serialized Role (auth::role_to_string)
    std::string auth_source{"local"};
    std::string oidc_sub;
    std::string token_scope_service;
    std::string mcp_tier;
    std::string principal_kind{"human"};
    std::int64_t created_at_ms{0};       ///< wall-clock session creation (the session issue anchor)
    std::int64_t expires_at_ms{0};       ///< absolute wall-clock lifetime ceiling
    std::int64_t last_activity_ms{0};    ///< sliding idle anchor (wall-clock)
    std::int64_t mfa_verified_ms{0};     ///< 0 = no MFA proof
    std::int64_t elevated_until_ms{0};   ///< 0 = not elevated
    std::int64_t elevation_issued_ms{0}; ///< wall-clock at elevation grant — the max-delta anchor
};

/// Parameters for authoring a NEW session. The time-derived fields are NOT
/// passed as absolutes — the store authors created/expires/last_activity from
/// Postgres `now()` so every replica dates a session in the ONE DB clock domain
/// (ADR-2002 §4 DB-clock authority; the fix for cross-host skew). The MFA proof
/// time is the sole exception: for a federated (OIDC/SAML) login it is the IdP's
/// asserted proof instant, not a local authoring, so it is passed through in
/// `mfa_verified_ms_abs`; a LOCAL step-up at login sets `mfa_verified_now` to
/// stamp `now()` instead. At most one MFA option is set.
struct SessionWriteParams {
    std::string token_hash;
    std::string username;
    std::string display_name;
    std::string role;
    std::string auth_source{"local"};
    std::string oidc_sub;
    std::string token_scope_service;
    std::string mcp_tier;
    std::string principal_kind{"human"};
    std::int64_t session_lifetime_ms{0};  ///< expires_at = now() + this
    std::int64_t mfa_verified_ms_abs{0};  ///< 0 = no proof; >0 = absolute IdP proof time
    bool mfa_verified_now{false};         ///< true = stamp mfa_verified = now() (local login step-up)
};

/// The DB-authored timestamps a mutation stamped, plus `db_now_ms` — the `now()`
/// instant they were authored at. Returned so the caller seeds its validate
/// cache with the EXACT durable values and derives its local monotonic deadline
/// against `db_now_ms`, never its own clock.
struct AuthoredTimes {
    std::int64_t created_at_ms{0};
    std::int64_t expires_at_ms{0};
    std::int64_t last_activity_ms{0};
    std::int64_t mfa_verified_ms{0};
    std::int64_t elevated_until_ms{0};
    std::int64_t elevation_issued_ms{0};
    std::int64_t db_now_ms{0}; ///< (extract(epoch from now())*1000)::bigint at authoring
};

/// A durable row plus the DB clock at the instant it was read, in ONE atomic
/// SELECT. Adjudication (absolute expiry, idle, elevation, MFA) is computed
/// against `db_now_ms`, never the replica's local wall clock (ADR-2002 §4). A
/// caller MUST fail closed if the read degrades — never treat a missing
/// `db_now_ms` as "0 elapsed", which would extend every session.
struct FoundSession {
    SessionRow row;
    std::int64_t db_now_ms{0};
};

class SessionStore {
public:
    struct Error {
        std::string message;
    };

    /// Borrows the shared pool and runs the schema migration on a pinned lease.
    /// is_open() is false if the lease was empty or the migration failed —
    /// fail-closed, no fallback (ADR-0007).
    explicit SessionStore(pg::PgPool& pool);

    SessionStore(const SessionStore&) = delete;
    SessionStore& operator=(const SessionStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    // ── Mutations (each bumps the durable generation in the same txn) ──────────

    /// Insert (or replace) a session, authoring created/expires/last_activity
    /// (and, for a local step-up, mfa_verified) from Postgres `now()`. Overwrites
    /// any prior row for the same token_hash (a token collision cannot
    /// legitimately occur; last-write-wins is safe and matches the map's
    /// `operator[]`). Returns the DB-authored timestamps so the caller seeds its
    /// cache with the exact durable values.
    [[nodiscard]] std::expected<AuthoredTimes, Error> create(const SessionWriteParams& params);

    /// Delete one session. Returns whether a row was removed.
    [[nodiscard]] std::expected<bool, Error> invalidate(const std::string& token_hash);

    /// Delete every session for a username (logout-all / user removal / role
    /// change). Returns the number removed.
    [[nodiscard]] std::expected<int, Error> invalidate_user(const std::string& username);

    /// Grant/extend elevation, authored in the DB clock domain: the store stamps
    /// `elevation_issued_ms = now()` and `elevated_until_ms = LEAST(now() +
    /// elevation_duration_ms, expires_at_ms)` — the "never past absolute expiry"
    /// clamp is done in SQL against the row's own expiry, atomically (no TOCTOU),
    /// and the dead-window case (computed until <= now()) matches NO row. Returns
    /// the authored times (incl. db_now_ms) to seed the cache, or nullopt when no
    /// row was updated (session absent OR the grant would already be expired).
    [[nodiscard]] std::expected<std::optional<AuthoredTimes>, Error>
    set_elevation(const std::string& token_hash, std::int64_t elevation_duration_ms);

    /// Clear elevation on one session. Returns whether it existed.
    [[nodiscard]] std::expected<bool, Error> clear_elevation(const std::string& token_hash);

    /// Clear elevation on every session for a username. Returns the count cleared.
    [[nodiscard]] std::expected<int, Error> clear_user_elevations(const std::string& username);

    /// Stamp an MFA step-up proof time = Postgres `now()` (DB clock domain).
    /// Returns the authored times (incl. db_now_ms) to seed the cache, or nullopt
    /// when the session did not exist.
    [[nodiscard]] std::expected<std::optional<AuthoredTimes>, Error>
    mark_mfa(const std::string& token_hash);

    // ── Sliding activity update (NO generation bump — not an authz change) ─────

    /// Advance the idle anchor to Postgres `now()` (GREATEST-clamped, monotonic —
    /// a cross-replica-skewed or out-of-order write cannot regress it). The caller
    /// decides WHEN to touch (throttled by elapsed idle); the store stamps the DB
    /// clock. Deliberately does not bump the generation (a slide is not a
    /// membership/authz change), so it does not invalidate other replicas' caches.
    /// Returns whether the session existed.
    [[nodiscard]] std::expected<bool, Error> touch_activity(const std::string& token_hash);

    // ── Reads ──────────────────────────────────────────────────────────────────

    /// Fetch one session by token hash, WITH the DB clock at read time in the same
    /// atomic SELECT. nullopt = definitively absent; unexpected = DB degraded (the
    /// caller must NOT treat this as "invalid session", and must NOT treat a
    /// missing db_now_ms as 0 — both fail the request instead).
    [[nodiscard]] std::expected<std::optional<FoundSession>, Error>
    find(const std::string& token_hash) const;

    /// The durable write-generation the validate-cache validates against.
    [[nodiscard]] std::expected<std::uint64_t, Error> read_generation() const;

    // ── Retention (clock-guarded, single-writer across replicas) ───────────────

    /// Outcome of one reap pass. `clock_anomaly` is set when the pass was
    /// DECLINED because a clock-guard-critical reading (the DB `now()` value or
    /// the persisted anchor) was unusable — implausibly ahead of, or behind, the
    /// persisted anchor, OR unparseable/negative/overflowed (#3785) — the
    /// DB-clock-integrity signal ADR-2002 §4 mitigation (a) requires the caller to
    /// monitor/alert on (a backward DB clock step is exactly this). A declined
    /// pass has `deleted == 0`.
    struct ReapOutcome {
        int deleted = 0;
        bool clock_anomaly = false;
    };

    /// Delete sessions whose absolute lifetime has passed. Guarded per the
    /// clock-guarded-retention rule and serialized cluster-wide by an advisory
    /// lock. The cutoff, the anchor comparison, and the anchor update ALL read one
    /// in-SQL `now()` (the DB clock domain — the same clock that authored
    /// expires_at), so the anomaly signal corresponds to the clock that actually
    /// deletes. Returns {deleted, clock_anomaly} (deleted==0 on a declined pass;
    /// clock_anomaly true iff the decline was clock-driven — a backward DB step is
    /// exactly this, the ADR-2002 §4 mitigation-(a) signal).
    [[nodiscard]] std::expected<ReapOutcome, Error> reap_expired();

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
