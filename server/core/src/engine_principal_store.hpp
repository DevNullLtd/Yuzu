#pragma once

/// @file engine_principal_store.hpp
/// Born-on-Postgres store (ADR-0006, schema `engine_principal_store`) for
/// ENGINE PRINCIPALS — the durable identity behind an autonomous use-case
/// engine module (design doc `docs/auth-engine-principals-design.md` §3.1).
/// A dedicated store, not columns bolted onto `ApiTokenStore`: the identity
/// (owner, justification, classification, lifecycle) outlives any one
/// credential. No secret material lives here (credentials stay hash-only in
/// `ApiTokenStore`) — no ADR-0010 SecretCodec involvement.
///
/// Posture per ADR-0012 §1: **authoritative / fail-hard**, both at
/// construction AND at runtime. Construction is fail-CLOSED — a reachable
/// database whose schema can't migrate leaves the store `!is_open()`, which
/// server.cpp wires to `startup_failed_` (a later task; this store's
/// `is_open()` is the signal). At runtime, `get_for_auth` — the auth-lookup
/// chokepoint every consumer of this store must use — returns a **three-state**
/// result:
///
///   - `Active`      — a live row; the request may proceed.
///   - `MissingOrRevoked` — no row, or a row whose `lifecycle_state` is not
///     'active'. Terminal, 401-class: the credential is dead, stop and alert.
///   - `StoreUnreachable` — the store is closed, or a lease/query failed.
///     Retryable, 503-class: back off and retry, this is not a credential
///     problem.
///
/// **Both non-Active outcomes DENY the request.** The distinction changes
/// retry behavior ONLY, never the authorization outcome — there is no
/// downgrade path from "unreachable" to "admitted". Conflating the two risks
/// a transient PG blip reading as "credential revoked", which could make an
/// autonomous module abandon a healthy credential; conflating them the other
/// way (treating unreachable as admitted) would be a fail-open bypass, which
/// this design forbids outright. See design doc §3.1 / §12 decision 1.
///
/// Revoke is TERMINAL (never un-revoked — a false-positive compromise
/// response mints a successor principal instead, recorded via
/// `superseded_by`) and SOFT-RETAINED (a revoked row is never hard-deleted,
/// so audit attribution survives). `get()`/`revoke()`/`transfer_owner()` are
/// likewise authoritative (ADR-0012 §1): each returns a typed
/// `std::expected<..., std::string>` — mirroring `ApiTokenStore::get_token`/
/// `revoke_token` — so a genuine lease/query failure surfaces as
/// `unexpected(msg)` and is never conflated with the legitimate not-found /
/// no-op case (`nullopt` / `false`). A lease/query failure is NEVER a silent
/// success and NEVER reads as "no such row".
///
/// Substrate contract (ADR-0008/0012): holds a `PgPool&`, runs its migration
/// at construction on a pinned lease, schema-qualifies every runtime
/// statement, `RETURNING` is the mutate-and-return idiom. Bounded acquires
/// everywhere.
///
/// Operator-facing REST/MCP/console CRUD wrapping this store's API is PR
/// 4.3 scope — this header adds no routes.
///
/// ## The revalidation cache (#2367) — deliberately NOT on the auth chokepoint
///
/// Every live MCP/SSE stream re-validates its credential on each ~3 s pump
/// tick. The token row itself is served from `ApiTokenStore`'s 60 s cache, so
/// for an ENGINE principal the extra `get_for_auth` hop was, in steady state,
/// the only uncached read on that path: one Postgres round-trip per engine
/// stream per tick,
/// each a bounded `try_acquire_for` on a pool of ~16 connections. That is
/// absorbable in steady state and self-amplifying under a pool brownout —
/// `StoreUnreachable` -> `kIndeterminate` -> every engine stream stays in its
/// grace window and KEEPS retrying, N waiters starving ordinary
/// `validate_token` and the fleet data plane with it. (Past 60 s of a
/// sustained outage the TOKEN half of the same tick resumes reading through
/// too, since it has no equivalent backoff — so this removes one of the two
/// amplifiers, not both. Tracked with #2447; #2454 (global revoke generation)
/// and #2456 (lease timeout vs permanent error) are FIXED — see the
/// per-principal generation map and `EngineLookup::confirmed_unreachable`
/// below. Residual sharp edges: #2455 (no single-flight), #2457 (unbounded
/// read on the writer thread), #2458 (silent ceiling / config binding).)
///
/// So `get_for_auth_revalidate()` adds a short-TTL positive cache — and ONLY
/// that method. `get_for_auth()` stays uncached and authoritative. Which
/// question is being asked decides whether a cached answer is admissible:
///
///   - A LIVENESS RE-CHECK asks "may this already-authenticated stream keep
///     running?". The stream was authenticated authoritatively at attach, and
///     the pump grants it a bounded grace window when the store cannot be
///     reached at all — so a recent answer is proportionate here.
///   - A FRESH AUTHORIZATION DECISION tolerates no staleness. Session
///     synthesis (`synthesize_token_session`) and the MCP/REST on-behalf-of
///     target checks keep reading through to Postgres every time, so revoking
///     a principal still stops new sessions and new delegations instantly.
///
/// A cached answer is NOT reported as a re-confirmation. `EngineRevalidate`
/// carries `from_cache`, the caller turns that into
/// `auth::CredentialCheck::kValidStale`, and the pump measures its grace
/// budget from the last AUTHORITATIVE confirmation. Without that, cache
/// residency and the grace window would ADD: a stream would ride the cache and
/// then collect a full fresh grace window once it expired. With it, total
/// survival past a real confirmation stays bounded by the grace window, and
/// `kAuthCacheTtl` is sized well under that window so an aged entry still
/// leaves useful grace (see the constant).
///
/// Only `Active` is cached. `MissingOrRevoked` is not (terminal and rare — the
/// alerting path — and negative-caching it would need `create()` invalidation
/// to avoid masking a fresh principal). `StoreUnreachable` is not cached
/// either, but a CONFIRMED one (#2456: the store was never open, or a query
/// actually ran and failed, or `PgPool`'s own connect-failure breaker is
/// open — see `EngineLookup::confirmed_unreachable`) IS rate-limited: a short
/// jittered backoff repeats that answer without taking a lease, because
/// otherwise the positive cache fixes only the warm steady state and the
/// per-tick amplifier returns intact the moment entries age out during a
/// sustained brownout. An AMBIGUOUS `StoreUnreachable` (a bare lease-acquire
/// timeout with the breaker still closed — a pool briefly saturated by
/// unrelated load, not a confirmed outage) does NOT arm the backoff — arming
/// it there would suppress probing a perfectly healthy database.
///
/// Revocation latency on the cached path: the writing replica invalidates
/// synchronously in `revoke()`/`transfer_owner()`, so a single-server
/// deployment (the shipped posture) cuts the stream on the next tick. Across
/// replicas the window is bounded by `kAuthCacheTtl` — the same residual
/// property `ApiTokenStore`'s token cache already carries.

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

class AuthRoutes;
struct EngineLivenessTestAccess;

/// One persisted engine-principal identity row.
struct EnginePrincipalRow {
    std::string principal_id;     ///< "engine:<slug>" — reserved namespace, §3.3.
    std::string display_name;     ///< UI/audit label.
    std::string owner_username;   ///< Named responsible human (must reference an existing user).
    std::string justification;    ///< Grant justification captured at creation.
    std::string classification;   ///< "internal" | "external" — required at creation, no default.
    std::string lifecycle_state;  ///< "active" | "revoked" — terminal, not reversible.
    std::string superseded_by;    ///< Predecessor→successor link on revoke-and-replace; "" if none.
    std::int64_t created_at = 0;  ///< Epoch seconds.
    std::int64_t revoked_at = 0;  ///< Epoch seconds; 0 while active.
    std::string created_by;       ///< Audit anchor — who minted this principal.
};

/// Outcome of the authoritative auth-lookup chokepoint (`get_for_auth`).
/// See the file doc comment — the StoreUnreachable/MissingOrRevoked split
/// changes retry behavior ONLY, never the authorization outcome.
// G8 (governance hardening, cpp-expert N1): explicit `: int` underlying type
// — self-documenting, and keeps the forward-declaration in api_token_store.hpp
// and this definition ODR-compatible (a forward-declared scoped enum with no
// fixed underlying type is ill-formed to use before its definition is visible;
// pinning the type here removes any ambiguity for either TU).
enum class EngineLookupStatus : int {
    Active,            ///< A live row exists; the request may proceed.
    MissingOrRevoked,  ///< No row, or lifecycle_state != 'active'. Terminal (401-class), deny+stop.
    StoreUnreachable,  ///< Store closed or a lease/query failed. Retryable (503-class), deny+retry.
};

/// Result of `get_for_auth`. `row` is set if and only if `status == Active`.
///
/// `confirmed_unreachable` (#2456) is a hint for `get_for_auth_revalidate`'s
/// failure-backoff decision ONLY — every other consumer of `get_for_auth`
/// ignores it and the three-state `status` contract above is unchanged for
/// all of them. A `StoreUnreachable` result carries `true` from THREE
/// sources: the store was never open; a query actually ran and failed; or a
/// bare lease-acquire timeout (`try_acquire_for` returning nothing within
/// `kReadTimeout`) where `PgPool`'s own connect-failure breaker
/// (`connect_breaker_open()`) is open — the breaker fires only on recent
/// CONNECT failures, never on pool saturation alone, so an open breaker at
/// that point IS confirmed evidence of a real outage. It carries `false`
/// ONLY for a bare lease-acquire timeout with the breaker still CLOSED, which
/// is genuinely ambiguous — a briefly-saturated pool under unrelated load
/// looks identical to a real outage at that exact point, and the breaker
/// hasn't (yet) confirmed either way. Arming a 5-10 s backoff on the
/// ambiguous case suppresses probing a perfectly healthy database; arming it
/// on any of the three confirmed cases is the whole point of the backoff.
struct EngineLookup {
    EngineLookupStatus status = EngineLookupStatus::StoreUnreachable;
    std::optional<EnginePrincipalRow> row;
    bool confirmed_unreachable = false;
};

/// Result of `get_for_auth_revalidate` (#2367) — liveness only, no row.
///
/// `from_cache` is not a diagnostic: it is the difference between "the store
/// confirmed this principal just now" and "the store confirmed it up to
/// `kAuthCacheTtl` ago". The caller must propagate that distinction (as
/// `auth::CredentialCheck::kValidStale`) so a held-open stream keeps measuring
/// its grace budget from the last AUTHORITATIVE confirmation. Collapsing it
/// into a plain "valid" makes cache residency and the grace window additive.
/// It is only ever true alongside `Active` — a miss reads through, so
/// `MissingOrRevoked` and `StoreUnreachable` are always authoritative.
struct EngineRevalidate {
    EngineLookupStatus status = EngineLookupStatus::StoreUnreachable;
    bool from_cache = false;
};

class EnginePrincipalStore {
public:
    /// Clock used for revalidation-cache TTL, jitter, and failure backoff.
    /// Injectable for tests only — see `set_clock_for_test`.
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    /// How long a positive liveness answer may be reused (#2367). PUBLIC
    /// because it is not an implementation detail: it is the staleness bound
    /// a consumer needs in order to keep its own freshness arithmetic honest,
    /// and it is COUPLED to `McpStreamPump`'s revalidate grace window — the
    /// TTL must stay well under it, or an aged entry leaves no usable grace
    /// and an outage cuts engine streams instantly. `mcp_stream.cpp` carries
    /// a static_assert pinning that relationship so a future edit to either
    /// constant fails the build instead of silently degrading availability.
    static constexpr auto kAuthCacheTtl = std::chrono::seconds(15);

    explicit EnginePrincipalStore(pg::PgPool& pool);

    EnginePrincipalStore(const EnginePrincipalStore&) = delete;
    EnginePrincipalStore& operator=(const EnginePrincipalStore&) = delete;
    EnginePrincipalStore(EnginePrincipalStore&&) = delete;
    EnginePrincipalStore& operator=(EnginePrincipalStore&&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// THE central auth-lookup chokepoint — see the file doc comment for the
    /// three-state contract. Every session-synthesis / delegation-redemption
    /// caller MUST route through this, never a plain `get()` (which returns
    /// any lifecycle_state and does not distinguish store-unreachable from
    /// not-found — it is for admin/test reads only). Always reads through to
    /// Postgres: a fresh authorization decision is never served from cache.
    [[nodiscard]] EngineLookup get_for_auth(const std::string& principal_id) const;

    /// Drop `principal_id` from the revalidation cache (empty string = clear
    /// all). Called synchronously by this store's own lifecycle writers; also
    /// public so a future replication/notify hook can invalidate on a peer's
    /// write without reaching into internals.
    void invalidate_revalidate_cache(const std::string& principal_id = {});

    /// Revalidation-cache counters (observability parity with
    /// `ApiTokenStore::cache_hits`/`cache_misses`). A miss is any lookup that
    /// had to read Postgres — absent, expired, or non-Active.
    [[nodiscard]] std::uint64_t revalidate_cache_hits() const noexcept {
        return revalidate_cache_hits_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t revalidate_cache_misses() const noexcept {
        return revalidate_cache_misses_.load(std::memory_order_relaxed);
    }
    /// Lookups answered `StoreUnreachable` from the failure backoff without
    /// taking a pool lease. This is the brownout-damping counter: a climbing
    /// value means the store is down AND the amplifier is being held off.
    [[nodiscard]] std::uint64_t revalidate_backoff_suppressed() const noexcept {
        return revalidate_backoff_suppressed_.load(std::memory_order_relaxed);
    }
    /// #2454: how often the per-principal poisoning-guard map was full (even
    /// after a #3385 TTL sweep) and a NEW principal's invalidate fell back to
    /// the coarse global epoch instead of getting its own slot. Not expected
    /// under ordinary load (`max_entries_` defaults to 1024, and now needs
    /// that many DISTINCT principals bumped within the same
    /// `kRevokeGenerationEntryTtl` window, not merely ever); a climbing value
    /// means the per-principal guard is running at reduced precision for new
    /// invalidations and the ceiling may need raising — see
    /// `docs/ops-runbooks/engine-principal-store-recovery.md`.
    [[nodiscard]] std::uint64_t revoke_generation_capacity_fallback() const noexcept {
        return revoke_generation_capacity_fallback_.load(std::memory_order_relaxed);
    }

    /// Number of principals with a LIVE (unexpired) cache entry. Expired but
    /// not-yet-swept entries are not counted — "resident" and "currently
    /// cached" are different facts, and reporting the former as the latter
    /// would overstate what the cache is actually serving.
    [[nodiscard]] std::size_t revalidate_cache_size() const;

    /// Test seam: override the clock used for TTL, jitter, and backoff. Call
    /// before any concurrent use. Passing an empty function restores the
    /// default `steady_clock::now`.
    void set_clock_for_test(ClockFn fn);

    /// Test seams for the RESIDENCY bound. `revalidate_cache_size()` reports
    /// what the cache is currently SERVING (unexpired only), which is the
    /// right operator-facing number but cannot observe the ceiling — an
    /// expired-but-unswept entry still occupies a slot. These report physical
    /// occupancy, so a test can prove the sweep and the decline-to-insert
    /// actually run rather than inferring it from a filtered count.
    [[nodiscard]] std::size_t revalidate_cache_resident_for_test() const;
    [[nodiscard]] std::size_t revalidate_backoff_resident_for_test() const;
    /// #2454: physical occupancy of `revoke_generation_by_principal_`, for
    /// proving the ceiling and the capacity-fallback path actually engage.
    [[nodiscard]] std::size_t revoke_generation_resident_for_test() const;

    /// Test seam: shrink the entry ceiling so the full-after-sweep path is
    /// reachable without materialising `kAuthCacheMaxEntries` principals.
    /// 0 restores the default.
    void set_max_entries_for_test(std::size_t n);

    /// Test seam (#3385, breaker-open confirmed-unreachable coverage): force
    /// `open_` without a working construction-time connect. Reaching
    /// `get_for_auth`'s breaker-open branch needs `open_ == true` (the
    /// `!open_` branch is checked first and short-circuits it) but a lease
    /// acquire that genuinely arms `PgPool`'s connect-failure breaker — a
    /// combination construction alone cannot produce against an
    /// always-unreachable pool, since a failed construction-time connect
    /// leaves `open_` false. This represents an equally real production
    /// case construction-time failure doesn't cover: the store opened
    /// successfully once, and connectivity was lost afterward.
    void set_open_for_test(bool open) noexcept { open_ = open; }

    // Test-only seam (#2367), mirroring ApiTokenStore's
    // `test_hook_after_validate_select_`. Null in production (zero overhead).
    // Fires in get_for_auth_revalidate AFTER the read-through and BEFORE the
    // generation re-check + cache-write, letting a test deterministically
    // interleave a revoke at the exact poisoning point.
    std::function<void()> test_hook_after_revalidate_read_;

    /// Mint a new engine principal. Validates BEFORE inserting:
    ///  - `classification` must be exactly "internal" or "external" (empty or
    ///    any other value is rejected — §3.1: required at creation, no
    ///    silent fallback on this write path).
    ///  - `principal_id` must start with "engine:" and carry a non-empty slug
    ///    (reserved namespace, §3.3).
    [[nodiscard]] std::expected<EnginePrincipalRow, std::string>
    create(const std::string& display_name, const std::string& owner_username,
          const std::string& justification, const std::string& classification,
          const std::string& created_by, const std::string& principal_id);

    /// Plain read by id, ANY lifecycle_state (admin/test surface — not the
    /// auth chokepoint; use `get_for_auth` for authorization decisions).
    /// Authoritative (ADR-0012 §1), mirrors `ApiTokenStore::get_token`'s typed
    /// result — a bare `optional` conflated "no such row" with "the store
    /// couldn't be asked":
    ///   * value `nullopt`   — genuine not-found; caller may 404.
    ///   * value (has row)   — the row, any lifecycle_state.
    ///   * `unexpected(msg)` — the store is closed, or a lease/query failed;
    ///     caller MUST surface this (503 / retry), never read it as
    ///     not-found.
    [[nodiscard]] std::expected<std::optional<EnginePrincipalRow>, std::string>
    get(const std::string& principal_id) const;

    /// Terminal revoke: active → revoked, `revoked_at` stamped,
    /// `superseded_by` recorded if given. Never un-revocable, never a
    /// hard-delete (soft-retain — audit attribution survives). Authoritative
    /// (ADR-0012 §1), mirrors `ApiTokenStore::revoke_token`'s typed result —
    /// a bare `bool` conflated "the write didn't land" with "there was
    /// nothing to revoke":
    ///   * value `true`      — the row existed (active) and is now revoked.
    ///   * value `false`     — the DB write ran fine but was a no-op — the
    ///     row is absent or already revoked. Not an error.
    ///   * `unexpected(msg)` — the write did NOT persist (store closed /
    ///     lease timeout / query error). The caller MUST surface this
    ///     (503 / retry), never audit or report success.
    [[nodiscard]] std::expected<bool, std::string>
    revoke(const std::string& principal_id, const std::string& superseded_by = "");

    /// Reassign ownership of an active principal (admin-forced — the design
    /// deliberately does not gate this on the outgoing owner's cooperation;
    /// that policy decision lives in the PR 4.3 route, this is the store
    /// primitive). Authoritative (ADR-0012 §1), same typed-result posture as
    /// `revoke`:
    ///   * value `true`      — the row existed (active) and is now
    ///     reassigned.
    ///   * value `false`     — the DB write ran fine but was a no-op — the
    ///     row is absent or not active. Not an error.
    ///   * `unexpected(msg)` — the write did NOT persist (store closed /
    ///     lease timeout / query error). The caller MUST surface this
    ///     (503 / retry), never a silent success.
    [[nodiscard]] std::expected<bool, std::string>
    transfer_owner(const std::string& principal_id, const std::string& new_owner);

    /// Admin/auditor list surface — every engine principal, ANY lifecycle_state
    /// by default, ordered by created_at. Pass `include_revoked=false` to
    /// filter to `lifecycle_state='active'` only. Bounded (few engine
    /// principals exist), parameterised, read-only. Best-effort: a lease/query
    /// failure is logged at warn and returns an empty vector rather than
    /// propagating the error — callers (admin list, auditor query) treat this
    /// as a best-effort read, not an authorization chokepoint (unlike
    /// `get_for_auth`, which fails closed with a distinct StoreUnreachable
    /// state).
    [[nodiscard]] std::vector<EnginePrincipalRow> list_all(bool include_revoked = true) const;

    /// Authoritative variant of `list_all` (ADR-0012 §1 read posture) for
    /// consumers that must NOT treat a lease/query failure as "zero engine
    /// principals exist" — e.g. the periodic-access-review export
    /// (`access_review_model.cpp`), where exporting a partial principal
    /// population as if it were complete is a SOC 2 evidence bug.
    /// `unexpected(msg)` on a closed store or a lease/query failure; a value
    /// (possibly empty) is a genuine, fully-read result.
    [[nodiscard]] std::expected<std::vector<EnginePrincipalRow>, std::string>
    list_all_checked(bool include_revoked = true) const;

    /// Count of ACTIVE engine principals owned by `owner_username` (uses
    /// `engine_principals_owner_idx`). Backs the owner-delete guard: a user
    /// cannot be deleted while owning an active engine principal. Returns
    /// `std::nullopt` on a lease/query failure — NOT `0` — so the caller's
    /// guard can fail CLOSED (treat "cannot verify" as "block the delete"),
    /// mirroring the authoritative posture elsewhere in this store. A `0`
    /// return is a verified count of zero, not "unknown".
    [[nodiscard]] std::optional<std::size_t>
    count_active_owned_by(const std::string& owner_username) const;

private:
    // PRIVATE ON PURPOSE (#2367). The cached/uncached split is the security
    // argument of this whole feature, and a doc comment is not an enforcement
    // mechanism -- three independent reviewers predicted the same failure: a
    // future admission gate greps this header, sees two auth-shaped methods,
    // and picks the one named "revalidate" because its code is a poll. Access
    // is therefore restricted in the type system to the ONE legitimate caller.
    // Anything needing the engine gate somewhere new must call `get_for_auth`.
    friend class AuthRoutes;
    friend struct EngineLivenessTestAccess;

    /// LIVENESS RE-CHECK ONLY — the per-tick "is this already-authenticated
    /// stream's backing principal still alive?" question, served from a
    /// `kAuthCacheTtl` positive cache (#2367; rationale in the file doc
    /// comment). Same three-state status contract as `get_for_auth`.
    ///
    /// NEVER use this to make a FRESH authorization decision — not for
    /// session synthesis, not for an on-behalf-of target check, not for a
    /// route's admission gate. Those must call `get_for_auth`. A cached
    /// `Active` is evidence that the principal was live within the TTL; that
    /// is enough to let an EXISTING stream keep running, and not enough to
    /// admit anything new.
    ///
    /// Returns NO row, deliberately. The only consumer branches on status, and
    /// withholding the row means a cached answer can never be mistaken for
    /// authoritative metadata (a cached `owner_username` is exactly the kind of
    /// thing a future caller would read without noticing it may be a minute
    /// old). It also keeps a cache hit allocation-free.
    [[nodiscard]] EngineRevalidate
    get_for_auth_revalidate(const std::string& principal_id) const;

    /// One cached Active lookup. The liveness fact and when it stops counting —
    /// no row: the consumer branches on status only, and not retaining the row
    /// removes any chance of a stale `owner_username` being read as current.
    /// `expires_at` carries its jitter baked in (see the insert path).
    struct CachedAuth {
        std::chrono::steady_clock::time_point expires_at;
    };

    pg::PgPool& pool_;
    bool open_{false};

    /// Revalidation cache (#2367) — positive entries only, see the file doc
    /// comment for why this is not on `get_for_auth`.
    ///
    /// The TTL is deliberately WELL BELOW the pump's revalidate grace window
    /// (60 s), not equal to it. Total survival past the last authoritative
    /// confirmation is `cache residency + remaining grace`, and the consumer
    /// backdates its grace deadline to that last authoritative confirmation
    /// (`CredentialCheck::kValidStale`), so the sum is bounded by the grace
    /// window itself. Sizing the TTL at the full 60 s would make that bound
    /// technically hold while leaving a fully-aged entry with ZERO remaining
    /// grace — an outage would then cut engine streams instantly, strictly
    /// worse than the uncached behaviour this replaced. At 15 s the worst case
    /// still leaves 45 s of grace, while collapsing a 3 s tick 5x (and, with
    /// misses coalesced, further still).

    /// Up to `kAuthCacheTtlJitter` is subtracted per entry at insert, so entries
    /// warmed together (every stream revalidating after one outage recovers, or
    /// after a boot) do not all expire on the same tick and re-stampede the
    /// pool. Subtracted, never added — jitter must not push an entry past the
    /// TTL bound the grace arithmetic above depends on.
    /// NOTE the integer-duration arithmetic: seconds(15)/4 truncates to
    /// seconds(3), not 3.75 s. Spelled in milliseconds so the value is what it
    /// says it is.
    static constexpr auto kAuthCacheTtlJitter = std::chrono::milliseconds{3750};

    /// After a read-through that CONFIRMED the store unreachable (#2456: the
    /// store was never open, or a query actually ran and failed, or the
    /// connect-failure breaker is open — never a bare, ambiguous lease-acquire
    /// timeout with the breaker closed), further reads for that principal are
    /// suppressed and answered `StoreUnreachable` without touching the pool.
    /// Jitter is ADDITIVE here (unlike the TTL's, which is subtractive), so
    /// the real window is `kAuthFailureBackoff` to twice it — 5 s to 10 s.
    /// Extending a backoff is safe; shortening a positive TTL is the direction
    /// that must never overshoot, hence the opposite signs.
    ///
    /// This is a RATE LIMITER for CONFIRMED failures, not a negative cache and
    /// not armed on ambiguous ones. The distinction matters: it repeats an
    /// answer we obtained moments ago from the authoritative store, for a
    /// window far shorter than the positive TTL, and it re-probes promptly so
    /// recovery is detected fast. Without it a sustained, CONFIRMED brownout
    /// would have every stream read through on every ~3 s tick once positive
    /// entries expire, each blocking up to the 1500 ms lease timeout — which
    /// is precisely the amplifier #2367 exists to remove, merely postponed by
    /// one TTL. Arming it on an AMBIGUOUS failure instead would suppress
    /// probing a perfectly healthy, merely-busy database — the gap #2456
    /// found and closed.
    static constexpr auto kAuthFailureBackoff = std::chrono::seconds(5);

    /// Hard ceiling on resident entries. Engine principals are created through
    /// a live REST/MCP surface with no store-level count limit, and an entry is
    /// otherwise only removed when that same principal is looked up again — so
    /// a principal whose streams all ended would sit resident for the process
    /// lifetime. On a full map the insert path first sweeps expired entries and
    /// then, if still full, simply declines to cache: degrading to read-through
    /// is slower, never wrong.
    static constexpr std::size_t kAuthCacheMaxEntries = 1024;
    /// Effective ceiling; `kAuthCacheMaxEntries` unless a test shrinks it.
    /// Applies to all THREE maps below — the backoff map is filled precisely
    /// when the positive map is not, so bounding only one of them bounds
    /// neither; the per-principal generation map (#2454) shares the same
    /// ceiling but a different eviction story (see its own field comment).
    std::size_t max_entries_{kAuthCacheMaxEntries};

    mutable std::mutex revalidate_cache_mu_;
    mutable std::unordered_map<std::string, CachedAuth> revalidate_cache_;
    /// principal_id -> "do not touch the pool for this key before". Swept and
    /// ceiling-checked on ITS OWN insert path: an outage is the only thing
    /// that fills this map, and the positive-insert path (the other sweep
    /// site) by definition does not run during one.
    mutable std::unordered_map<std::string, std::chrono::steady_clock::time_point>
        revalidate_backoff_;

    /// Clock seam. Production leaves this as `steady_clock::now`; tests inject a
    /// controllable clock so TTL expiry, jitter bounds, and backoff windows are
    /// testable without sleeping through them. Set once before any concurrent
    /// use (there is no lock around the function object itself).
    ClockFn clock_{[] { return std::chrono::steady_clock::now(); }};
    mutable std::atomic<std::uint64_t> revalidate_cache_hits_{0};
    mutable std::atomic<std::uint64_t> revalidate_cache_misses_{0};
    mutable std::atomic<std::uint64_t> revalidate_backoff_suppressed_{0};

    /// Drop expired positive entries and elapsed backoffs. Caller holds
    /// `revalidate_cache_mu_`.
    void sweep_expired_locked(std::chrono::steady_clock::time_point now) const;

    /// TOCTOU guard against cache POISONING (#2454: per-principal, not the
    /// single global counter this started as — see the issue for the failure
    /// mode a global counter has: any write to ANY principal skips every
    /// OTHER principal's concurrent cache-insert, so a revoke burst silently
    /// disables the whole liveness cache for its duration).
    ///
    /// Entirely lock-protected by `revalidate_cache_mu_` (unlike the field
    /// this replaced, which was atomic specifically so a writer could bump it
    /// BEFORE taking the lock — a per-principal map has no such need: writer
    /// and reader now serialize on the SAME mutex for both the bump and the
    /// check, so ordering follows directly from mutex serialization instead
    /// of a separate atomic-ordering argument. A reader snapshots its
    /// key's current value under a lock BEFORE the slow store read, and
    /// re-checks the SAME key under the lock at insert time, in the same
    /// critical section as the insert — a writer's invalidate_revalidate_cache
    /// either fully precedes the reader's snapshot (reader sees the bumped
    /// value, skips), or fully follows the reader's insert (the writer's own
    /// erase removes what the reader just inserted). Neither leaves a stale
    /// entry, and there is no window where a bump is visible without its
    /// paired erase, or vice versa — both now live in the writer's ONE
    /// critical section instead of two separately-ordered steps.
    ///
    /// Ceiling-capped at `max_entries_`, AND (fix for #3385: the original
    /// #2454 shipped this map with no reclaim path at all) swept on its own
    /// insert path exactly like the cache/backoff maps — an entry whose
    /// `last_bumped_at` is older than `kRevokeGenerationEntryTtl` is evicted,
    /// so residency no longer depends on process lifetime.
    ///
    /// The tricky part sweeping introduces: a principal whose entry was
    /// evicted and is later bumped again gets a FRESH map slot — if that
    /// fresh slot's `generation` value could equal some OLDER value a
    /// still-in-flight reader's stale snapshot happens to hold, the guard
    /// would silently pass a poisoning race it exists to catch (a stale
    /// snapshot from BEFORE the evicted entry existed, coincidentally
    /// matching a NEW entry created after — a reused-value aliasing bug, not
    /// present before sweeping existed because nothing was ever evicted).
    /// `next_generation_value_` below closes that: every bump (existing slot
    /// or fresh one) draws its new value from ONE shared, ever-increasing
    /// counter, never a per-principal restart-at-1 — so no two bumps at any
    /// point in this process's lifetime, for any principal, ever produce the
    /// same value, and a reused map slot is safe by construction rather than
    /// by argument about timing. Evicting the MAP ENTRY reclaims memory;
    /// evicting the shared counter is never needed because it isn't sized
    /// per-principal.
    ///
    /// Why not reuse `last_bumped_at` itself as the generation value, instead
    /// of adding a second field (architect, Gate 3)? `clock_` is an
    /// injectable seam (`set_clock_for_test`), and even a real
    /// `steady_clock` has finite resolution — two rapid successive bumps to
    /// the SAME principal can land on an identical `time_point` on a
    /// coarse-resolution clock (real or mocked), which would silently
    /// reintroduce the exact aliasing collision this counter exists to rule
    /// out. A dedicated monotonic integer has no such failure mode.
    ///
    /// The general rule for whether a store method may skip
    /// `invalidate_revalidate_cache` on a "no rows changed" outcome (used by
    /// `transfer_owner`, see its own comment) — for a FUTURE mutator of this
    /// store to check before copying either pattern: skipping is safe ONLY
    /// when the method's own WHERE clause already requires
    /// `lifecycle_state='active'`, so that zero rows affected conclusively
    /// means the principal doesn't exist or is already revoked and no
    /// Active-status race exists for THAT call to guard against.
    ///
    /// `revoke()` (below) carries that IDENTICAL WHERE-clause shape (also
    /// `lifecycle_state='active'`) — consistency-auditor caught an earlier
    /// draft of this comment claiming otherwise (Gate 4 fold) — so the
    /// narrower rule would be formally sound for it too. `revoke()` stays
    /// fully unconditional anyway, as a DELIBERATE conservative choice, not
    /// because its precondition differs: it is the security-critical
    /// Active→Revoked transition itself, and unconditional invalidation
    /// there is a backstop against every other race this store's callers
    /// might not have reasoned through as carefully as this comment has —
    /// cheap insurance on the one call that flips `lifecycle_state` at all.
    /// When in doubt, or when a mutator's blast radius is this central,
    /// invalidate unconditionally; reserve the narrower, WHERE-clause-backed
    /// skip for a call like `transfer_owner` that never touches
    /// `lifecycle_state`.
    ///
    /// `kRevokeGenerationEntryTtl` must exceed the true worst-case in-flight
    /// window of a reader's own `get_for_auth()` call for eviction to be
    /// sound (an entry must not be swept while a reader who snapshotted it
    /// could still be mid-flight) — that window is bounded by `kReadTimeout`
    /// (lease acquire) PLUS whatever the query itself can take once a lease
    /// IS held, which today is `PgPool`'s `statement_timeout_ms` (30 s
    /// default) and NOTHING tighter — #2457 (no client-side query deadline)
    /// is still open. The chosen TTL doubles that sum for margin; if #2457
    /// lands a tighter client-side bound, or an operator raises
    /// `statement_timeout_ms` well past its default, this TTL should be
    /// re-derived rather than assumed to still be safe.
    ///
    /// Capacity exhaustion (the map is still at `max_entries_` even after a
    /// sweep pass — now a narrower case than before: it requires
    /// `max_entries_` DISTINCT principals bumped within the SAME TTL window,
    /// not merely `max_entries_` distinct-ever-revoked over the whole
    /// process lifetime) still falls back to bumping
    /// `revoke_generation_global_epoch_` below rather than silently
    /// declining, for the same reason as before: declining permanently
    /// disables the guard for the affected principal, while the epoch
    /// fallback only degrades it, coarsely, until the fallback stops being
    /// needed (which sweeping now makes a recoverable condition, not a
    /// process-lifetime-permanent one — the trigger for the fallback keeps
    /// moving as old entries age out and free slots for new ones).
    ///
    /// Be precise about what "coarse" means here (Gate 4, unhappy-path):
    /// this is not a narrowing of impact to the triggering principal. Every
    /// snapshot taken via `snapshot_revoke_generation_locked` embeds the
    /// SAME shared epoch, so one bump — from invalidating ANY principal, not
    /// just the one that tripped the fallback — defeats every OTHER
    /// principal's concurrent cache-write too, for as long as the epoch
    /// keeps moving. See #3385 for the fuller history of this fallback.
    ///
    /// A principal absent from this map has an implicit generation of 0,
    /// matching a principal that has never been revoked or transferred.
    ///
    /// `revoke_generation_global_epoch_` is the coarse fallback signal:
    /// bumped by a full-cache clear (`invalidate_revalidate_cache`
    /// with an empty principal_id — not used by any production caller today,
    /// reserved for tests/future admin use), which by definition must
    /// invalidate every in-flight reader regardless of which principal it is
    /// reading, since a full clear has no per-key identity to target, AND by
    /// the capacity-exhaustion fallback above. `revoke_generation_capacity_fallback_`
    /// counts how often that fallback fires — architect (Gate 3): an
    /// operator-visible signal that per-principal capacity is being
    /// exhausted, mirroring `revalidate_backoff_suppressed_`'s
    /// instrument-on-degrade pattern.
    struct GenerationEntry {
        std::uint64_t generation = 0;
        std::chrono::steady_clock::time_point last_bumped_at{};
    };
    /// #3385: sized to exceed kReadTimeout (1.5 s) + PgPool's default
    /// statement_timeout_ms (30 s) with a 2x margin — see the field comment
    /// on `revoke_generation_by_principal_` for why this bound must hold for
    /// eviction to be sound, and #2457 for the open issue that could someday
    /// tighten it.
    static constexpr auto kRevokeGenerationEntryTtl = std::chrono::seconds(63);
    mutable std::unordered_map<std::string, GenerationEntry> revoke_generation_by_principal_;
    mutable std::uint64_t revoke_generation_global_epoch_ = 0;
    /// Shared monotonic source for every `GenerationEntry::generation` value
    /// this store ever assigns, regardless of principal — see the field
    /// comment on `revoke_generation_by_principal_` for why a per-principal
    /// restart-at-1 scheme is unsound once entries can be evicted and
    /// recreated.
    mutable std::uint64_t next_generation_value_ = 1;
    mutable std::atomic<std::uint64_t> revoke_generation_capacity_fallback_{0};

    /// Read `revoke_generation_by_principal_[principal_id]`'s generation (0
    /// if absent) plus `revoke_generation_global_epoch_`, both under
    /// `revalidate_cache_mu_`. The pairing IS the poisoning-guard token: a
    /// reader is unpoisoned iff BOTH compare equal at insert time to what
    /// this returned at snapshot time.
    struct RevokeGeneration {
        std::uint64_t per_principal = 0;
        std::uint64_t global_epoch = 0;
        bool operator==(const RevokeGeneration&) const = default;
    };
    RevokeGeneration snapshot_revoke_generation_locked(const std::string& principal_id) const;
};

/// Test-only door to the private liveness path (#2367). Production code
/// reaches it exclusively through `AuthRoutes::engine_credential_state`; this
/// exists so the store's cache behaviour stays directly testable without
/// widening the production surface.
struct EngineLivenessTestAccess {
    [[nodiscard]] static EngineRevalidate revalidate(const EnginePrincipalStore& store,
                                                     const std::string& principal_id);
};

} // namespace yuzu::server
