#pragma once

/// @file api_token_store.hpp
/// Born-on-Postgres store (ADR-0006, schema `api_token_store`) for API
/// Bearer tokens (human PATs, service-scoped change-window tokens, MCP
/// tier tokens, and — per `docs/auth-engine-principals-design.md` §6 — the
/// `principal_kind` seam for future engine-principal-issued tokens). FRESH
/// START (no `migrate_from_sqlite()`): the legacy `<db_dir>/api-tokens.db`
/// is no longer opened; existing tokens are invalidated on upgrade (see the
/// PR 4.1 rollout note in the design doc / changelog fragment).
///
/// Posture (ADR-0012 §1): CONSTRUCTION is fail-CLOSED — a reachable
/// database whose schema can't migrate/open sets `startup_failed_` in
/// server.cpp (same pattern as every other born-on-PG store). RUNTIME is
/// authoritative for revocation/deletion: a lease timeout or query error on
/// `revoke_token`/`revoke_for_principal`/`delete_token` MUST return
/// false/0, never a silent success — those calls back "Sign out
/// everywhere" and the stolen-laptop response path (ADR-0012 §1
/// authoritative posture; do not soften to fail-open). Reads split by
/// role: `validate_token` is the auth hot path and degrades to `nullopt`
/// on a DB error (the per-request status label already carries the 401);
/// `get_token`/`list_tokens` are authoritative (ADR-0012 §1) and surface
/// a runtime DB error as `std::unexpected` rather than an empty/not-found
/// that would paper over an outage — see their per-method contracts below.
///
/// Substrate contract (ADR-0008/0012): holds a `PgPool&`, runs its
/// migration at construction on a pinned lease, schema-qualifies every
/// runtime statement (`api_token_store.api_tokens`), `RETURNING` is the
/// mutate-and-return idiom (never `sqlite3_changes()`, issue #1033).
/// Bounded acquires everywhere at runtime; unbounded `acquire()` is
/// construction-only.
///
/// Substrate-independent state (in-memory `token_cache_`, the
/// `revoke_generation_` TOCTOU guard, hit/miss counters) survives the port
/// unchanged — see the .cpp for why the generation counter narrowly guards a
/// cache-write racing a concurrent revoke (cache-poisoning only, NOT full
/// validate/revoke serialization — the pool has no
/// single connection-wide mutex serializing SELECT + cache-write the way
/// the old `db_mtx_` did).

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

// PGconn is a typedef of libpq's PRIVATE struct tag `pg_conn` — this header
// includes libpq-fe.h directly rather than forward-declaring `pg_conn`
// itself (as an earlier revision did) per `pg_migration_runner.hpp`'s
// documented rule: re-declaring a third party's internal name pins it, and a
// libpq rename would break the build here last and least legibly. The
// include costs nothing in practice — every consumer of this header already
// pulls in the PG store stack (pg_pool.hpp/pg_raii.hpp or this store's own
// .cpp) which includes it directly, so this is not a new transitive
// dependency, only an explicit one. Applies even though the only use here is
// a test-only hook signature (`PGconn*` below) — the rule has no carve-out
// for that, and adding one would be a second exception to litigate per call
// site instead of one `#include`.
#include <libpq-fe.h>

// STL -> third-party -> project (docs/cpp-conventions.md) — this project
// header sits last, below the libpq-fe.h third-party include above.
#include <yuzu/audit_retention_rules.hpp> // Facts/Anomaly/classify — this store's rotation sweep
                                     // REUSES the shared pure decision function rather than
                                     // forking a second copy, the same way
                                     // result_set_store.cpp/guaranteed_state_store.cpp/
                                     // response_store.cpp already do (each contributes its own
                                     // probe SQL/meta table/dedup serialisation around the SAME
                                     // Facts/classify pair; the truth table itself needs no
                                     // per-store retest — test_audit_retention_rules.cpp already
                                     // pins it exhaustively and it has no store-specific
                                     // behaviour). This is the routed clock-guarded-retention
                                     // concern's own "Reference impl for the DECISION rule" note
                                     // (`audit_retention_rules.hpp::classify` +
                                     // `AuditStore::cleanup_once`) — not tied to one of its
                                     // seven numbered parts.

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

// Part 7 (clock-guarded-retention routed concern): ABSOLUTE elapsed-step
// threshold for the T12 rotation sweep's clock guard (#2964), never scaled
// to a retention window (this store has none to scale against — only a 60s
// tick cadence, `server.cpp`).
//
// A bare copy of `audit_store`'s constant (86'400, one day) fails the
// routed concern's own "copy the SHAPE, never the numbers" rule:
// `audit_store` re-anchors far less often than every 60s, so a one-day
// floor on a 60-second cadence would silently tolerate a forward jump of
// just under 24 hours — precisely the sub-86400 hole this store's
// (now-removed) would-wipe probe was being asked to cover instead (see the
// DELIBERATE NON-ADOPTION comment in the .cpp). The value below is instead
// derived from THIS store's own re-anchor cadence: 60 consecutive missed
// re-anchors at the 60s tick cadence (`server.cpp`'s sweep-thread loop
// period) is itself remarkable — either the sweep has gone genuinely unable
// to reach a verdict for an hour straight (a real outage) or the clock
// moved by more than an hour, and either warrants a decline+report rather
// than a silent drain. An ordinary transient blip (one failed pool
// acquire, one skipped-lock tick) is one to a handful of ticks, nowhere
// near this floor, so this does not fire on routine contention.
//
// DOMINANT TRIGGER: at the 86'400 floor a planned no-verdict gap (a
// maintenance window, a DB failover, a dev instance left off overnight)
// was rare enough to ignore; at this 3'600 floor it is the MOST COMMON
// `Step` trigger — an hour of `Failed` ticks reaches this threshold on its
// own, no clock fault required. Every operator-facing surface for this
// guard (`describe()` below, the user-manual/metrics/alert-runbook docs)
// must present "clock fault" as ONE possible cause of `Step`, never the
// only one.
//
// RESIDUAL: a forward jump strictly UNDER this floor is undetected by
// every detector in this store's fact set and can retire predecessors up
// to just under an hour early. This is a DELIBERATE, bounded gap, not an
// oversight — UP-5 (the per-pair re-assertion under the row lock) proves
// the successor was actually presented before any predecessor in the pair
// is touched, and `kOverlapCeilSecs` (10 years) means no legitimate
// overlap window is anywhere near this floor's scale, so the earliest a
// sub-floor jump can cut a window short is still bounded by that window's
// own length, never by an unbounded amount.
//
// MULTIPLIER: "60 ticks" is a CHOSEN point for this store, not a derived
// one — the routed concern requires the number be argued from THIS
// store's own substrate (done above), not that the multiplier itself be
// self-evident. Sibling guards choose their own multiples of their own
// cadences for the same reason (e.g. `audit_store.hpp`'s
// `kAuditMinBigStepSec`, 7 days against a re-anchor cadence far coarser
// than this store's 60s) — copy the SHAPE (derive from this store's own
// cadence), never a sibling's chosen multiplier.
//
// Namespace-scope (not a class member) so a test can reference it without
// duplicating the magic number.
inline constexpr std::int64_t kRotationSweepBigStepSecs = 60 * 60; // 60 ticks x 60s/tick = 1h

// Forward-declared rather than pulling in engine_principal_store.hpp here —
// a scoped enum's underlying type defaults to `int`, so an opaque
// enum-class-declaration is a valid, self-consistent forward reference. The
// full definition (and the `.cpp`'s actual use of the enum values) lives in
// engine_principal_store.hpp, included only by api_token_store.cpp.
//
// G8 (governance hardening, cpp-expert N1): the underlying type is pinned
// `: int` explicitly (rather than relying on the implicit default) on BOTH
// this forward-declaration and the definition in engine_principal_store.hpp
// — self-documenting, and removes any ambiguity for either translation unit
// (a mismatched underlying type between a forward-declaration and its
// definition is ill-formed, no diagnostic required).
enum class EngineLookupStatus : int;

struct ApiToken {
    std::string token_id;      // Short display ID (prefix of hash)
    std::string token_hash;    // SHA-256 hash of raw token (stored, never the raw token)
    std::string name;          // Human-readable label
    std::string principal_id;  // Username (or engine principal id) who created it
    std::string scope_service; // Non-empty = scoped to this IT service (change window token)
    std::string mcp_tier;      // "readonly", "operator", "supervised", or "" (not MCP)
    int64_t created_at{0};
    int64_t expires_at{0}; // 0 = never
    int64_t last_used_at{0};
    bool revoked{false};
    // "human" | "engine" — set at creation, immutable thereafter (design doc
    // §6). Appended last so existing aggregate-initializer callers are
    // unaffected. Legacy/human-issued tokens are "human".
    std::string principal_kind{"human"};

    // Overlap-pair rotation (design doc §7, schema v2, plan PR 4.3). Empty /
    // 0 for every token that has never participated in a rotation.
    std::string rotation_group;      // Links a predecessor/successor pair; shared by both.
    std::string supersedes_token_id; // Successor -> predecessor token_id; empty on the predecessor.
    int64_t overlap_expires_at{0};   // Predecessor's scheduled auto-revoke instant; 0 = not rotating.
    int64_t confirmed_at{0};         // Set when an operator confirms cutover; 0 = unconfirmed.

    // #2961, migration v3 (additive). Durable twin of the RAM-only grace
    // cache's `requesting_user` — stamped ONLY on the SUCCESSOR row, inside
    // the same locked mint transaction that inserts it (never backfilled onto
    // the predecessor, and never heuristically backfilled onto a pre-v3 pair).
    // Empty on every row that has never been a rotation successor, and on a
    // pair that started rotating before this migration shipped. NEVER
    // treated as a wildcard by the confirm-identity resolver — see
    // `resolve_rotation_initiator`'s doc comment. Deliberately NOT consulted
    // by `try_reserve`'s raw-secret re-serve (F4 stays RAM-only); it exists
    // solely to survive a restart for `confirm_rotation`/
    // `confirm_token_rotation`'s identity check (F5).
    //
    // Cleared back to '' on the SURVIVING row at all FOUR sites that resolve
    // rotation state, alongside `rotation_group`/`supersedes_token_id`/
    // `overlap_expires_at`: both confirm arms' in-txn cleanup,
    // `resolve_rotation_pair_after_revoke`'s partner clear, and the T12
    // sweep's auto-revoke clear. (An earlier revision of this comment named
    // only three and was corrected — the sweep site was missed by the fix
    // brief, not by the implementer.)
    //
    // What that does NOT cover, stated because the earlier revision claimed
    // otherwise: a row that is itself REVOKED keeps its stamp. Every clear is
    // scoped to the partner or the pinned successor, so
    // `revoke_token(<successor_id>)` clears the predecessor and leaves the
    // revoked successor stamped, and `revoke_for_principal` resolves no pair
    // at all. Rows are removed only by `delete_token`, so on the ENGINE arm a
    // dead row can retain a third-party admin's username indefinitely. It is
    // inert — no serializer, log, audit detail or metric label emits this
    // field, and the resolver is only ever reached for a LIVE successor — but
    // "a resolved row does not keep it for the row's remaining life" was too
    // strong a claim and is withdrawn.
    std::string rotation_initiator;
};

class ApiTokenStore {
public:
    explicit ApiTokenStore(pg::PgPool& pool);

    ApiTokenStore(const ApiTokenStore&) = delete;
    ApiTokenStore& operator=(const ApiTokenStore&) = delete;

    bool is_open() const;

    /// Create a new API token. Returns the raw token string (shown to user once).
    /// If scope_service is non-empty, the token is scoped to that IT service.
    /// If mcp_tier is non-empty, the token is an MCP token with the given tier.
    /// `principal_kind` defaults to `"human"`; passing `"engine"` mints an
    /// engine-principal credential and triggers the engine block (design doc
    /// §§6-8): the mcp_tier must be `"readonly"`, the token must expire within
    /// the 90-day ceiling, and the injected referent check
    /// (`set_engine_referent_check`) must report the principal Active — else the
    /// mint fails closed. A C++-side allowlist rejects any other kind ahead of
    /// the DB `CHECK (principal_kind IN ('human','engine'))`.
    std::expected<std::string, std::string>
    create_token(const std::string& name, const std::string& principal_id, int64_t expires_at = 0,
                 const std::string& scope_service = {}, const std::string& mcp_tier = {},
                 std::string principal_kind = "human");

    /// Validate a raw Bearer token. Returns the ApiToken if valid and not expired/revoked.
    std::optional<ApiToken> validate_token(const std::string& raw_token);

    /// Outcome of `validate_token_checked` — the tri-state `validate_token`
    /// deliberately collapses. A held-open SSE stream must be able to tell
    /// "this credential is definitively gone" (kill the stream NOW) from "we
    /// cannot reach the store to find out" (ride out a bounded grace window
    /// rather than cut every live stream on the fleet at once) — ADR-1005
    /// Decision 15(i) / chaos CH-4. Ordinary request auth has no such need:
    /// there, "cannot tell" and "no" both mean 401, which is why
    /// `validate_token` folds them together.
    enum class TokenCheck {
        kValid,        ///< token exists, unrevoked, unexpired
        kInvalid,      ///< DEFINITIVELY absent / revoked / expired
        kUnavailable,  ///< store unreachable — indeterminate, NOT a revocation
    };

    struct CheckedToken {
        TokenCheck status = TokenCheck::kInvalid;
        std::optional<ApiToken> token;  ///< engaged iff kValid
    };

    /// `validate_token` with the failure mode preserved. The extra store probe
    /// runs ONLY on the negative path (a valid token — the steady state for a
    /// live stream — is served from the same 60 s cache as `validate_token`, so
    /// re-validation stays O(cache-refresh), not O(streams × tick)).
    CheckedToken validate_token_checked(const std::string& raw_token);

    /// List all tokens (for admin UI). Raw token values are never returned.
    /// Authoritative read (ADR-0012 §1): `unexpected` on a runtime DB error, a
    /// value (possibly empty) on success — never an empty vector papering over
    /// an outage.
    std::expected<std::vector<ApiToken>, std::string>
    list_tokens(const std::string& principal_id = {}) const;

    /// Look up a single token by its short display ID. The raw token and
    /// `token_hash` are NOT populated — only metadata. Used by the REST API
    /// to verify ownership before revoke so a caller with `ApiToken:Delete`
    /// cannot revoke another user's token by guessing its ID. Authoritative
    /// read (ADR-0012 §1): `unexpected` on a runtime DB error (caller 503s),
    /// value `nullopt` on a genuine no-such-row (caller 404s).
    std::expected<std::optional<ApiToken>, std::string>
    get_token(const std::string& token_id) const;

    /// Revoke a token by ID. Returns a typed result that distinguishes the
    /// two outcomes a bare `bool` conflated (ADR-0030 §Posture — a revoke
    /// that did not land must never read as success):
    ///   * value `true`  — the token existed and is now revoked.
    ///   * value `false` — the DB write succeeded but no such token existed
    ///                     (already gone / unknown id) — a genuine 404.
    ///   * `unexpected(msg)` — the write did NOT persist (lease timeout /
    ///                     query error). The caller MUST surface this
    ///                     (503 / "retry"), never audit or toast success.
    std::expected<bool, std::string> revoke_token(const std::string& token_id);

    /// Active credentials for one principal: not revoked AND (expires_at==0
    /// OR expires_at>now). `token_hash` is masked ('') same as `list_tokens`.
    /// Used to enforce the design doc §7 "at most two active credentials"
    /// ceiling and to drive `rotate_engine_credential`'s state machine, and
    /// by the admin console to show live credential counts.
    [[nodiscard]] std::vector<ApiToken>
    list_active_for_principal(const std::string& principal_id) const;

    /// Overlap-pair credential rotation for an engine principal (design doc
    /// §7). `now` is caller-supplied epoch seconds (not read from the wall
    /// clock internally) so callers control the instant every window/floor
    /// check is evaluated against. `requesting_user` is the human operator
    /// driving this call (route layer's authenticated session) — it is
    /// stamped on a fresh mint's grace-cache entry and enforced on a
    /// same-window re-serve (Hermes F4): a DIFFERENT operator may never
    /// re-serve another admin's in-flight successor secret.
    ///
    /// Hermes F1: the ENTIRE check -> mint -> stamp sequence below runs
    /// inside ONE `pg::PgPool::with_txn_for` transaction that opens with
    /// `SELECT pg_advisory_xact_lock(hashtext($principal_id))` — this
    /// serializes concurrent `rotate_engine_credential`/`confirm_rotation`
    /// calls for the SAME principal (across server instances, since it's a
    /// Postgres-side lock, not an in-process mutex) so the active-credential
    /// count this function branches on is re-read fresh, under the lock,
    /// never the caller's own pre-lock snapshot. The ≤2 ceiling holds even
    /// under concurrent rotate calls for the same principal.
    ///
    /// Hermes F2: the successor's INSERT and the predecessor's pair-stamp
    /// UPDATE commit inside that SAME locked transaction — never two
    /// separate transactions — so a crash between mint and stamp is
    /// impossible; a successful rotate always leaves both rows linked. The
    /// engine-referential-integrity check (`engine_referent_check_`) and raw
    /// secret generation (CSPRNG) run BEFORE the transaction opens (as a
    /// speculative "candidate successor"), never inside it: both call back
    /// into shared infrastructure (`engine_referent_check_` acquires its own
    /// lease from this store's same `pg::PgPool`) that would nest a second
    /// connection acquire under the txn's already-held connection —
    /// documented in `pg_pool.hpp` as self-starving a small/size-1 pool
    /// (the standard shape this store's own unit tests use). The candidate
    /// is used only if the lock-held re-read below actually finds the
    /// 1-active mint case; otherwise it's silently discarded, so a
    /// transient referent-check hiccup never blocks a re-serve or a
    /// ceiling rejection that never needed it.
    ///
    /// State machine, keyed on the principal's current active-credential
    /// count, re-read fresh under the advisory lock (see the .cpp for the
    /// full commentary):
    ///   0 active  -> rejected; caller must mint the first credential via
    ///                `create_token` directly.
    ///   1 active  -> mints a successor (§6/§7/§8 validation + the
    ///                referential check all run), stamps both rows into one
    ///                rotation pair atomically (F1/F2 above), caches the
    ///                successor's raw secret + `requesting_user` for the
    ///                grace window, and returns the raw secret (one-time-
    ///                reveal contract).
    ///   2 active  -> a rotation is already in flight. Within
    ///                `kRotationGraceSecs` of the successor's mint AND while
    ///                its raw secret is still cached, re-serves the SAME raw
    ///                value (idempotent retry, design doc §7 bullet 1) — but
    ///                ONLY to the SAME `requesting_user` who initiated it
    ///                (F4); a different operator is rejected with
    ///                "rotation in progress by a different operator"
    ///                regardless of the grace window's remaining time. The
    ///                per-reveal audit + step-up re-validation that gates a
    ///                replay happen at the ROUTE layer, not here. Once the
    ///                grace window lapses (or the cache entry is gone),
    ///                rejected — the caller falls back to the compromise
    ///                runbook (principal-level revoke) or an explicit
    ///                re-mint, never an indefinite retry.
    ///   >2 active -> defensive rejection; this function's own 1-active arm
    ///                is the only mint path it drives, so this state means a
    ///                credential was minted outside `rotate_engine_credential`
    ///                (e.g. a direct `create_token` call) and must be
    ///                resolved manually, not silently arbitrated.
    ///
    /// The overlap window itself is rejected outright — never silently
    /// truncated — if `overlap_secs` is below the 24h floor, or if
    /// `now + overlap_secs` would exceed either credential's own expiry.
    [[nodiscard]] std::expected<std::string, std::string>
    rotate_engine_credential(const std::string& principal_id, int64_t overlap_secs, int64_t now,
                             const std::string& requesting_user);

    /// Operator-confirmed cutover (design doc §7 bullet 3, Hermes F5): while
    /// a rotation pair is in flight, sets the successor's `confirmed_at =
    /// now`, immediately revokes the predecessor (rather than waiting for
    /// the overlap window to elapse), clears the successor's rotation state
    /// (`rotation_group`/`supersedes_token_id`/`overlap_expires_at` ->
    /// defaults, `confirmed_at` retained as a historical marker), and evicts
    /// the grace-cache entry. Advisory-locked exactly like
    /// `rotate_engine_credential` (same `pg_advisory_xact_lock` on
    /// `principal_id`, same single-transaction commit for the confirm +
    /// revoke + clear triple) so it can't race a concurrent rotate/confirm/
    /// sweep for the same principal.
    ///
    /// Only the `requesting_user` who initiated the rotation (the operator
    /// bound into the grace-cache entry at mint time, F4) may confirm it —
    /// a different operator's call is rejected with "rotation in progress
    /// by a different operator", the same message F4 uses, never a silent
    /// no-op. Unlike the raw-secret re-serve, this identity check is NOT
    /// time-bounded to `kRotationGraceSecs` — the overlap window (default 7
    /// days) vastly outlives the short raw-reveal grace window, so the
    /// grace-cache entry's `requesting_user` is retained (not pruned by
    /// elapsed time, only evicted explicitly — see `grace_entry_owner`'s
    /// doc comment) for as long as the rotation stays unresolved.
    ///
    /// #2961: a process restart no longer forfeits this binding. The RAM-only
    /// grace cache is still the primary path (and the raw-secret re-serve, F4,
    /// stays RAM-only — restart still forfeits THAT), but the identity check
    /// falls back to `ApiToken::rotation_initiator`, a durable column stamped
    /// on the successor row at mint time — see `resolve_rotation_initiator`.
    /// Confirm is rejected with "rotation confirmation unavailable" when
    /// `resolve_rotation_initiator` returns `nullopt` — NEITHER the cache
    /// entry nor the durable column resolves an initiator (e.g. a pair that
    /// began rotating before this migration shipped, whose durable column is
    /// empty). That is not the only rejection cause: the cache entry and the
    /// durable column can both be present and DISAGREE, which is also
    /// refused (fail closed, never prefer either) — see
    /// `resolve_rotation_initiator`'s doc comment for the full resolution
    /// table. Either way, never silently allowed for any caller.
    ///
    /// Rejected (no DB mutation) when there is no in-flight, recognizable
    /// rotation pair for `principal_id`. Since #2404 the rejection is
    /// state-discriminated (classifier: `rotation_confirm_state.hpp`) so a
    /// replay after the rotation already resolved gets a TERMINAL conflict the
    /// caller maps to 409/kInvalidParams, NOT the old blanket retryable error:
    ///   - 0 active, or 2 active that aren't a linked pair -> "no in-flight
    ///     rotation to confirm" (RETRYABLE/Transient: 0-active is ambiguous
    ///     with a swallowed read failure, and a malformed pair is kept
    ///     conservative);
    ///   - >2 active -> "more than two active credentials ..." (terminal,
    ///     manual resolution) — mirrors `rotate_engine_credential`;
    ///   - 1 active with UNCLEARED rotation linkage -> "... unresolved
    ///     rotation metadata ... do not rotate ..." (terminal; rotating would
    ///     strand a malformed pair, #2404 F1);
    ///   - 1 active, linkage clear, pin matches -> "rotation already
    ///     confirmed ..." (`confirmed_at != 0`) or "no rotation in flight ...
    ///     already the sole active credential ..." (`confirmed_at == 0`,
    ///     resolved by never-rotated / sweep / revoke) — both terminal;
    ///   - 1 active, linkage clear, pin does NOT match -> "... the rotation
    ///     was resolved ..." (terminal).
    /// `confirmed_at` is a sound discriminator ONLY on the pin-MATCH arm: it
    /// is written solely by confirm, solely on a successor row, and a row is a
    /// successor exactly once — so `row.confirmed_at != 0` means precisely
    /// "the rotation in which THIS row was successor was confirmed". It is a
    /// historical marker retained across later rotations, so it is NEVER used
    /// to attribute a non-matching pin's resolution cause.
    ///
    /// `token_id` pins the exact rotation being confirmed (#2384): it must
    /// equal the pending pair's SUCCESSOR `token_id` — the value the rotate
    /// call returned to the caller — or the confirm is rejected (no DB
    /// mutation) with "token_id does not match the pending rotation
    /// successor". Without the pin, a blind same-operator retry of an old
    /// confirm could land after a SECOND rotation started and revoke that
    /// later rotation's still-live predecessor early. With it, a replay can
    /// only ever target the pair it was issued for: while that pair is
    /// pending it confirms it (once); after cutover — or once a later
    /// rotation is in flight — the stale id mismatches and nothing is
    /// written.
    ///
    /// #3015 PROOF OF POSSESSION: `presented_secret` is the raw successor
    /// secret the caller claims to hold (the value `rotate_engine_credential`
    /// returned). Confirm — unlike rotate itself — REVOKES the predecessor
    /// immediately, so requiring only the non-secret `token_id` + session
    /// identity let any caller who could name the successor's id (never
    /// secret) force an immediate cutover without ever having received the
    /// new credential. Verified via
    /// `constant_time_hex_equal(sha256_hex(presented_secret), successor.token_hash)`
    /// against the AUTHORITATIVE successor row read fresh inside this call's
    /// own advisory-locked transaction (never a list/lookup projection —
    /// every OTHER reader in this file masks `token_hash` behind a literal
    /// `''`, see `kTokenColsTail`'s own comment). The raw secret is never
    /// persisted or logged — used only to compute this one hash comparison.
    ///
    /// ORDERING IS LOAD-BEARING (governance/architect review): PoP is
    /// checked LAST, strictly after every other admission check — ownership/
    /// principal-kind, pair-state, the `token_id` pin above, and the
    /// initiator binding below — all pass. On this arm the caller is a
    /// third-party admin, not the rotation's own initiator, so checking PoP
    /// any earlier would let a non-initiator admin distinguish "wrong
    /// secret" from "valid secret, not your rotation" — a cross-admin
    /// oracle over who initiated a rotation. Every earlier failure folds
    /// into the SAME non-disclosing wording it already used; only a caller
    /// who has already cleared every other gate can reach the PoP check, and
    /// only THAT caller gets the distinguishable "rotation secret mismatch"
    /// outcome on a wrong secret.
    [[nodiscard]] std::expected<void, std::string>
    confirm_rotation(const std::string& principal_id, const std::string& token_id,
                     const std::string& presented_secret, const std::string& requesting_user);

    // ── Human arm: token-keyed overlap-pair rotation (P2 #11, SOC 2 CC6.3) ──
    //
    // `rotate_engine_credential`/`confirm_rotation` above arbitrate on a
    // ≤2-ACTIVE-CREDENTIALS-PER-PRINCIPAL invariant, which is true for an
    // engine principal (one credential by design) and FALSE for a human
    // (`principal_id` is their username, and one user routinely holds N
    // concurrent unrelated named tokens). `rotate_token`/`confirm_token_rotation`
    // therefore key on the TOKEN being rotated, not the principal, and enforce
    // the ≤2 ceiling PER ROTATION GROUP — never a principal-wide count. They
    // reuse the same overlap-window floor/ceiling, grace-cache, and double-bump
    // TOCTOU machinery as the engine arm; the advisory lock is still taken on
    // `hashtext(principal_id)` (derived from the resolved token row), the SAME
    // key `sweep_expired_rotations`/`resolve_rotation_pair_after_revoke` use, so
    // the two arms still serialize against each other and against the sweep for
    // a shared principal. Human-only: both reject a non-"human" `principal_kind`
    // row (the engine arm's own analogous kind guard).
    //
    // SELF-SERVICE ONLY (deliberate asymmetry with the engine arm, where
    // `requesting_user` is a third-party admin by design): both functions
    // reject unless `requesting_user == <resolved token row>.principal_id` —
    // enforced HERE, in the store, not merely at a route layer, the same
    // "store is the chokepoint, route filtering is defense-in-depth only"
    // posture `ResponsesFn` threading `agent_id` into `ResponseQuery` uses
    // (#1634). A human token's raw successor secret authenticates AS that
    // user; an admin re-serving or confirming another user's rotation would
    // be handed (or complete the cutover of) a credential impersonating
    // someone else — identity takeover, not a permission gap an admin
    // override could legitimately cross. Admins already have `revoke_token`
    // / `revoke_for_principal` as the correct lever for another user's
    // credential. The rejection is folded into the SAME wording the
    // genuine-token-does-not-exist case uses (never a distinguishable
    // "not yours" message) so the surface is not an ownership-enumeration
    // oracle — the same posture the human `DELETE /api/v1/tokens/{id}`
    // route takes for a non-owner (`rest_api_v1.cpp`).

    /// Mint (or idempotently re-serve) a successor for `predecessor_token_id`,
    /// a human-owned credential. `now`/`overlap_secs` carry the same contract
    /// as `rotate_engine_credential` (caller-supplied instant; window rejected
    /// — never truncated — below the 24h floor, above the 10y ceiling, or if it
    /// would outlive either credential's own expiry).
    ///
    /// State machine, keyed on the PREDECESSOR ROW's own rotation linkage
    /// (re-read fresh under the principal-scoped advisory lock, never a
    /// pre-lock snapshot):
    ///   `rotation_group` empty  -> mint arm: validates the candidate successor
    ///       through `validate_human_mint` (candidate prep happens BEFORE the
    ///       transaction opens, mirroring Hermes F2), inserts it linked via
    ///       `supersedes_token_id`, and stamps the predecessor's own
    ///       `rotation_group`/`overlap_expires_at` — both writes commit in the
    ///       SAME transaction (Hermes F2's "mint and stamp together" guarantee).
    ///   `rotation_group` non-empty -> re-serve/conflict arm: reads every
    ///       active row sharing that `rotation_group` (never a principal-wide
    ///       scan) and, if it is a recognized 2-row pair within the grace
    ///       window and the SAME `requesting_user` who initiated it (Hermes
    ///       F4 equivalent), re-serves the cached raw secret; otherwise
    ///       rejected as a conflict (grace elapsed / different operator /
    ///       group state not a recognized pair / defensively >2 in-group).
    ///
    /// Successor TTL: inherits the predecessor's absolute `expires_at`
    /// VERBATIM (perpetual stays perpetual) unless `successor_expires_at`
    /// overrides it — never recomputed as `now + 90d`, which would silently
    /// extend authorization lifetime (the exact thing a CC6.3 auditor must not
    /// find fused into rotation). The (possibly-overridden) value is validated
    /// through `validate_human_mint`, the same policy gate `create_token`
    /// uses for a fresh human mint.
    ///
    /// AUTHORITY-INHERITANCE GUARD (governance Gate 7 CRITICAL fix): the
    /// predecessor is caller-chosen (any of a human's own tokens, resolved
    /// only by `predecessor_token_id`) and `mcp_tier`/`scope_service` are
    /// copied VERBATIM into the successor — so without this guard an
    /// operator-tier caller could rotate their OWN untiered/perpetual
    /// sibling token and mint a fresh untiered credential with full
    /// authority, no tier gate. `caller_mcp_tier`/`caller_scope_service`
    /// are the CALLER's own current, server-synthesized authority
    /// (`auth::Session::mcp_tier`/`token_scope_service` from
    /// `synthesize_token_session` — never client-controllable); rotation is
    /// refused unless they are EQUAL (not "no broader than" — an ordering
    /// needs a tier-lattice assumption a future tier could break) to the
    /// freshly-read predecessor's own `mcp_tier`/`scope_service`, WITH ONE
    /// #2963 exception: a caller presenting empty `""`/`""` (a plain cookie
    /// or JIT-elevated interactive session, holding no standing tier/scope
    /// authority at all) may rotate ANY of its own tokens regardless of
    /// THAT token's tier/scope — see `caller_may_act_on_tiered_token`'s doc
    /// comment (api_token_store.cpp) for why this is a single special case,
    /// not a tier lattice: such a caller already holds a strict superset of
    /// what any tiered/scoped token can do, and the successor still
    /// inherits the TOKEN's own narrower tier/scope verbatim, never the
    /// caller's — nothing is escalated. This is what makes it possible to
    /// rotate a possibly-compromised MCP-tiered or service-scoped token
    /// from an ordinary dashboard session, which could not reach it before
    /// #2963 (the tier-equality check made it structurally unrotatable
    /// except by presenting that exact token's own credential — backwards
    /// precisely when the reason to rotate is that the secret may be
    /// compromised). Every OTHER pairing (a caller holding SOME non-empty
    /// tier/scope against a predecessor with a DIFFERENT one) still refuses
    /// on exact equality, no lattice. The refusal is folded into the SAME
    /// "no such token to rotate" wording used for absent/not-owned so this
    /// is not an authority-probing oracle. Enforced authoritatively under
    /// the advisory-locked transaction against a FRESH re-read of the
    /// predecessor row; the pre-txn check below is an early-rejection
    /// mirror only.
    ///
    /// `caller_mcp_tier`/`caller_scope_service` are REQUIRED, not defaulted
    /// (governance Gate 8 fix) — an untiered `""`/`""` is the predecessor
    /// that matches the HIGHEST-authority token an account can hold, not
    /// the strictest one, so a default would make an omitted argument at
    /// any future call site silently mean "untiered caller", reproducing
    /// the exact CRITICAL this guard exists to close. Also load-bearing:
    /// `successor_expires_at` sits between the legacy four-argument form
    /// and this pair in call-site history, so a copied four-arg call would
    /// otherwise still compile and still mean "untiered". A caller with a
    /// genuinely untiered/cookie session passes `""`/`""` explicitly — that
    /// is self-documenting, never a synonym for "didn't set it".
    [[nodiscard]] std::expected<std::string, std::string>
    rotate_token(const std::string& predecessor_token_id, int64_t overlap_secs, int64_t now,
                const std::string& requesting_user, const std::string& caller_mcp_tier,
                const std::string& caller_scope_service,
                std::optional<int64_t> successor_expires_at = std::nullopt);

    /// Operator-confirmed cutover for a human token-keyed rotation — same
    /// contract as `confirm_rotation` (immediate predecessor revoke +
    /// successor rotation-state clear + grace-cache eviction, all inside one
    /// advisory-locked transaction; only the initiating `requesting_user` may
    /// confirm; the double revoke-generation bump around the predecessor's
    /// revoke UPDATE, same TOCTOU contract as every other revoke path here) —
    /// but keyed by `successor_token_id` alone rather than
    /// `principal_id`+`token_id`: the principal (and thus the advisory-lock
    /// key) and the rotation group are both RESOLVED FROM the pinned row.
    ///
    /// State discrimination reuses `confirm_rotation`'s #2404 taxonomy, but
    /// through the group-aware sibling classifier
    /// (`rotation_confirm_state.hpp`'s `classify_confirm_state_in_group`) —
    /// see that header for why a group-scoped filter needs its own positive-
    /// read reasoning, distinct from the principal-scoped original.
    ///
    /// `caller_mcp_tier`/`caller_scope_service` re-check the SAME
    /// authority-inheritance invariant `rotate_token` enforces, INCLUDING
    /// the #2963 empty-tier/scope exception (see that doc comment) — as
    /// DEFENCE IN DEPTH ONLY — a successor's tier/scope are fixed at mint
    /// time and cannot legitimately diverge from the authority a caller
    /// confirming it currently holds (NOT necessarily the same SESSION that
    /// initiated the rotation — ownership + the #3015 proof-of-possession
    /// check are what actually gate who may confirm; a second session
    /// belonging to the same principal, with a matching or empty tier/scope
    /// AND the raw successor secret, may legitimately confirm a rotation a
    /// different session started), so `rotate_token`'s own guard is the
    /// load-bearing one; this catches only a hypothetical future bypass of
    /// it, never a live path today (governance Gate 4 UP-4). Both checks
    /// MUST stay in sync — a caller presenting a given tier/scope that can
    /// successfully `rotate_token` a pair must also be able to
    /// `confirm_token_rotation` it presenting the SAME tier/scope, or the
    /// two calls disagree on an identical caller/token. REQUIRED, not defaulted, for the same
    /// reason as `rotate_token`'s own pair (governance Gate 8 fix) — see
    /// that doc comment.
    ///
    /// #3015 PROOF OF POSSESSION — same contract as `confirm_rotation`'s own
    /// `presented_secret` parameter (see that doc comment for the full
    /// rationale and the ordering-is-load-bearing note): verified via
    /// `constant_time_hex_equal(sha256_hex(presented_secret), successor.token_hash)`
    /// against the authoritative successor row, checked LAST — after
    /// ownership, pair-state, the `token_id` pin, tier/scope, and the
    /// initiator binding all pass — so a caller who fails any earlier gate
    /// gets the SAME non-disclosing outcome regardless of what secret they
    /// present. This arm is self-service only (the caller IS the rotation's
    /// own initiator by construction), so the cross-admin oracle
    /// `confirm_rotation` guards against does not apply here the same way —
    /// the ordering is kept identical anyway, for the same reason every
    /// other invariant in this pair of functions is kept identical: one
    /// contract, two arms, never a silent divergence.
    [[nodiscard]] std::expected<void, std::string>
    confirm_token_rotation(const std::string& successor_token_id,
                           const std::string& presented_secret,
                           const std::string& requesting_user,
                           const std::string& caller_mcp_tier,
                           const std::string& caller_scope_service);

    /// One rotation pair currently in flight, as read by the T12 maintenance
    /// sweep (design doc §7). `predecessor.supersedes_token_id` is always
    /// empty; `successor.supersedes_token_id == predecessor.token_id`.
    struct RotationPair {
        ApiToken predecessor;
        ApiToken successor;
    };

    /// Outcome of one `sweep_expired_rotations` call — a TYPED result (#2964),
    /// never the pair of bools this replaced. The two bools could not distinguish "the clock
    /// guard declined the whole pass" from "nothing happened to be
    /// eligible" (both left `tick_failed=false` and an empty vector), and
    /// could not distinguish "another replica is sweeping this tick"
    /// (routine leader-election contention, never worth a warning) from a
    /// genuine fault.
    enum class SweepOutcome {
        Failed,      ///< Pool/query/txn failure — this tick did not run to completion.
        SkippedLock, ///< Another replica holds the store-wide sweep lock this tick.
        Declined,    ///< The clock guard declined the pass — see `decline_reason`.
        Ok,          ///< The pass ran to completion (possibly zero eligible).
    };

    /// Return value of `sweep_expired_rotations` — see `SweepOutcome` above
    /// and the method's own doc comment for what each field means per
    /// outcome.
    struct SweepResult {
        SweepOutcome outcome = SweepOutcome::Failed;
        /// Predecessors actually revoked this call (`principal_id`/
        /// `token_id` populated, `token_hash` masked same as every other
        /// read here). Only ever non-empty when `outcome == Ok`.
        std::vector<ApiToken> revoked;
        /// True when more eligible predecessors existed than
        /// `kMaxAutoRevokesPerTick` allowed this tick and the remainder was
        /// deferred to later ticks. Only meaningful when `outcome == Ok`
        /// (a `Declined`/`SkippedLock`/`Failed` pass processes nothing, so
        /// this stays `false` on all three).
        bool capped = false;
        /// Actionable text for the caller's log line / audit row. Populated
        /// (never blank) iff `outcome == Declined`.
        std::string decline_reason;
        /// GOVERNANCE CHAOS-INJECTION FINDING (#2964 fix round): a stage tag
        /// plus the underlying libpq error text (or a fixed diagnostic for a
        /// pre-connection failure — store not open, pool exhausted) for
        /// `outcome == Failed`. Before this field existed, EVERY internal
        /// failure inside the classification transaction — including a
        /// genuinely permanent schema defect, e.g. a missing
        /// `rotation_retention_meta` table from a botched migration-number
        /// reconciliation (#3013) — surfaced identically as the caller's own
        /// generic "pool contention / query failure" text, which is neither
        /// accurate nor actionable for that case: an operator staring at
        /// that message cannot tell a transient blip from a permanent defect
        /// that will repeat every tick forever. Populated (never blank) iff
        /// `outcome == Failed`; empty for every other outcome.
        std::string fail_reason;
        /// The classified anomaly behind a `Declined` outcome
        /// (`audit_retention::Anomaly::None` for every other outcome) —
        /// lets the caller choose a human-readable decline REASON without
        /// re-parsing `decline_reason`.
        ///
        /// #2964 round 3 review (finding 2): do NOT route a metric on this
        /// field alone. `classify`'s precedence is `BadState > Step > Wipe >
        /// NoAnchor` (`audit_retention_rules.hpp`), so a bootstrap tick that
        /// ALSO observes another anomaly classifies as that other anomaly,
        /// not `NoAnchor` — even though `facts.no_anchor` is still true and
        /// the routed-concern policy floor ("a bootstrap decline counts to
        /// its own series, never the clock-anomaly one, because it asserts
        /// only that nothing can yet be ruled out") still applies. Use
        /// `no_anchor` below for that routing decision instead; this field
        /// is for the human-readable reason only.
        audit_retention::Anomaly decline_anomaly = audit_retention::Anomaly::None;
        /// The RAW `Facts::no_anchor` bit behind a `Declined` outcome
        /// (`false` for every other outcome) — the routing key for the
        /// bootstrap-vs-clock-anomaly metric split (see `decline_anomaly`'s
        /// own doc comment for why the collapsed enum is the wrong thing to
        /// switch on for this). Correct even when another anomaly outranks
        /// `NoAnchor` in `decline_anomaly`, because this is the fact itself,
        /// never the classified precedence winner.
        bool no_anchor = false;
        /// Count of predecessors whose per-pair revoke transaction genuinely
        /// FAILED (pool acquire / lock / query / execution fault, at ANY
        /// point in that transaction's lifecycle — INCLUDING a COMMIT that
        /// fails after the transaction's own work already succeeded, #2964
        /// round 3 review finding 6) rather than resolving as the expected
        /// idempotent no-op (already revoked, or resolved out from under the
        /// sweep by a concurrent manual revoke/confirm under the same
        /// principal-scoped lock). Only meaningful when `outcome == Ok`.
        /// Before this field existed a tick that selected N candidates and
        /// failed EVERY per-pair transaction returned `{Ok, revoked={},
        /// capped=false}` — byte-identical to a genuinely idle tick —
        /// because the loop's success branch had no `else`; this is what
        /// lets the caller tell the two apart, PROVIDED the counting
        /// condition covers every way a per-pair transaction can fail — the
        /// round-2 shape counted only an in-lambda failure and silently
        /// dropped a pair whose COMMIT failed after the lambda itself
        /// reported success, which is the specific gap round 3 closed (see
        /// the counting site in `sweep_expired_rotations`'s own comment).
        /// This conflation was PRE-EXISTING (the two-bool `SweepResult` this
        /// type replaced had the same gap).
        ///
        /// GOVERNANCE CHAOS-INJECTION FINDING (#2964 fix round): this is not
        /// a rare/exceptional path — it is ORDINARY pool contention.
        /// Reproduced against live Postgres with a size-2 pool, 5 eligible
        /// pairs, and one unrelated caller holding a single lease: the sweep
        /// pins one connection for its store-wide session lock, each per-pair
        /// `pool_.with_txn_for` call needs a SECOND connection, and with only
        /// one free, every per-pair call timed out — `outcome=Ok
        /// revoked={} capped=false`, all 5 predecessors still live, with
        /// neither the accepted-pass verdict nor the last-pass liveness
        /// gauge showing anything wrong. `--postgres-pool-size 1` makes it
        /// unconditional. This field, being a TYPED `SweepResult` member
        /// rather than only a log line, is what makes a tick that lost
        /// revocations distinguishable BY THE CALLER — server.cpp's own
        /// rendering of it is `yuzu_rotation_sweep_lost_revocations_total`
        /// (see that metric's own describe() text), but any caller reading
        /// `SweepResult` directly (a test, a future diagnostic surface) can
        /// act on this field without needing that counter to exist.
        std::size_t failed_pairs = 0;
    };

    /// T12 sweep, half 1 — auto-revoke (design doc §7 bullet 3), now the
    /// FULL clock-guarded-retention shape (routed concern, all seven parts;
    /// #2964) rather than only the unconditional cap (part 5) it shipped
    /// with. Revokes every ELIGIBLE predecessor whose overlap window has
    /// elapsed (`overlap_expires_at > 0 AND overlap_expires_at <=` <em>
    /// PostgreSQL's own clock</em> — see below — not yet revoked, live
    /// successor that has itself been presented at least once) and clears
    /// the SURVIVING successor's rotation state
    /// (`rotation_group`/`supersedes_token_id`/`overlap_expires_at` ->
    /// defaults — "revocation during overlap ... resolves the rotation
    /// state", §7) so a fresh rotation may begin.
    ///
    /// `now` is CALLER-supplied but is NOT what drives the eligibility
    /// decision — part 2 of the routed concern: the decision reads
    /// PostgreSQL's own clock (`SELECT EXTRACT(EPOCH FROM now())::bigint`,
    /// read once per call, inside the classification transaction below),
    /// the same reasoning `AuditStore::cleanup_once` documents (N server
    /// replicas would otherwise compare against N independently-drifting
    /// process clocks). `now`'s ONLY remaining role is the cheap
    /// pre-transaction implausibility check (an upper-bound sanity floor
    /// shared with every other clock-guarded store in this codebase) — it
    /// reaches no arithmetic and stamps no liveness signal of its own. (The
    /// sweep's actual liveness signal is `rotation_sweep_last_pass_now()`,
    /// which reads PostgreSQL's own persisted `last_pass_now` directly — see
    /// that accessor's doc comment for why a caller-clock reading would not
    /// do.) Pass any plausible reading, e.g. the caller's own
    /// `std::chrono::system_clock::now()`.
    ///
    /// LOCKING SHAPE (the part a simpler design gets wrong): a NEW
    /// store-wide SESSION advisory lock (`hashtextextended
    /// ('api_token_store:rotation_sweep', 0)`, its own key namespace — never
    /// `hashtext(principal_id)`, the per-PRINCIPAL key `rotate_engine_
    /// credential`/`confirm_rotation`/the per-row revoke below all use),
    /// acquired with a bounded TRY on one leased connection and held for
    /// the WHOLE call. Holding it: the clock read, the durable meta
    /// read/write, the eligibility probes, and — if the pass is accepted —
    /// a SELECT of at most 201 eligible candidates (201, not 200: enough to
    /// tell "more than the cap" from "exactly the cap") all run as ONE
    /// transaction on that connection. The (at most 200) actual revokes
    /// then run as up to 200 SEPARATE per-pair transactions — the existing
    /// per-principal-locked shape below, UNCHANGED — never folded into the
    /// classification transaction: ~600 statements holding locks against a
    /// 2s pool-acquire budget and a 30s statement timeout would block
    /// interactive rotation for the whole batch's duration, for the sake of
    /// one commit fate shared by 200 UNRELATED rotations. Lock order is
    /// fixed — global sweep lock -> per-principal lock -> mutation — and
    /// the global lock is NEVER acquired from inside a per-principal
    /// transaction. Released via `pg::PgSessionAdvisoryLockGuard`
    /// (`pg/pg_session_advisory_lock.hpp`) — the same reusable release
    /// protocol `KekOpLockGuard` uses — before the connection returns to the
    /// pool: a leaked session lock on a pooled connection wedges every
    /// future sweep permanently (a session lock persists until explicitly
    /// unlocked or the connection closes — unlike the per-PRINCIPAL
    /// `pg_advisory_xact_lock` this same file's rotate/confirm/per-row-revoke
    /// paths take, which is transaction-scoped and self-releases at
    /// COMMIT/ROLLBACK).
    ///
    /// POOL-SIZE FLOOR: the session-lock connection above is held for the
    /// WHOLE call, spanning the up-to-200 per-pair `pool_.with_txn_for` calls
    /// that follow it — each of those acquires its OWN, second connection
    /// from the SAME pool while the first is still leased. A pool configured
    /// with fewer than 2 connections can therefore never make progress on
    /// this sweep: every per-pair `with_txn_for` call would time out
    /// acquiring its connection against the one already pinned by the
    /// session lock (`pg_pool.hpp`'s own nested-`with_txn`-on-a-size-1-pool
    /// warning is the same hazard from the other direction). Not a
    /// hypothetical regression risk in practice today (production pool 16,
    /// test fixtures 4) — recorded here because the pre-#2964 design held
    /// only a transaction-scoped per-principal lock released before this
    /// per-pair loop began, so it needed just 1 connection; #2964
    /// deliberately widened that to a store-wide SESSION lock held across
    /// the whole call (the paragraph above), and that widening is what
    /// raises the floor to 2. This is the correct trade, not an oversight —
    /// see the LOCKING SHAPE paragraph for why the lock must be session- and
    /// whole-call-scoped rather than released before the per-pair revokes.
    ///
    /// The eligibility PROBE measures the ELIGIBLE set only — pairs this
    /// sweep could actually revoke — never every syntactically-elapsed
    /// predecessor. A pair whose successor has never been presented
    /// (`last_used_at == 0`, UP-5) is PERMANENTLY ineligible (see below) and
    /// plays no part in this probe's outcome, since such a pair never
    /// becomes eligible no matter how much time passes. This store does NOT
    /// adopt the clock-guarded-retention routed concern's part 1 would-wipe
    /// half (`Facts::would_wipe` is hardcoded `false`) — see the DELIBERATE
    /// NON-ADOPTION comment in the .cpp, near where `kMinWipeProbePopulation`
    /// used to live, for the measured reason: a would-wipe predicate whose
    /// true positive (a genuine clock jump) and single most common false
    /// positive (an ordinary drain tick) are the same observable outcome
    /// swallows a later genuine anomaly through fact-set dedup regardless of
    /// any population floor, and this store's per-pair UP-5 re-assertion
    /// already bounds the harm of accepting that mis-fit.
    ///
    /// Never revokes a predecessor whose successor has NEVER been presented
    /// (`last_used_at == 0`, read fresh under THIS row's own locked
    /// transaction, not the unlocked scan above it) — a lost/dropped
    /// successor secret must never leave the principal at zero usable
    /// credentials (the clock-guarded-retention routed concern's spirit,
    /// applied to a per-principal availability floor rather than a bulk
    /// delete). The pair stays fully live past its overlap window in that
    /// case; `list_rotations_nearing_expiry_unused` keeps surfacing it as an
    /// operational warning until an operator resolves it explicitly (confirm
    /// or revoke). Cadence of the three signals is NOT uniform and is owned
    /// solely by `rotation_warn_dedup.hpp` — the log line repeats per tick,
    /// the audit row and metric fire once per pair per state.
    ///
    /// Bounded per tick at `kMaxAutoRevokesPerTick` — cap every accepted
    /// pass UNCONDITIONALLY (routed concern part 5): the cap is the
    /// guarantee, the anomaly detectors above are best-effort. A single
    /// forward clock step degrades to a bounded multi-tick drain instead of
    /// a fleet-wide cutover in one tick.
    ///
    /// A MISSING durable anchor (no pass on this database has ever reached
    /// a verdict) DECLINES rather than proceeding (routed concern part 6,
    /// the `AuditStore` answer, not `ResultSetStore`'s) — both credentials
    /// in an affected pair stay active, which is already the supported,
    /// warned-about UP-5 state, so this never locks anyone out. The cost is
    /// real, not free: for a pair whose successor HAS been used, the
    /// predecessor stays valid past its promised overlap window for at
    /// least one more sweep tick (60s, `server.cpp`), extending exposure to
    /// a possibly-compromised credential. Accepted because clock-driven
    /// revocation of a live credential on an unverified reading is worse,
    /// and because fact-set dedup (never a latch bool) means the decline is
    /// not permanent — an identical repeat on the next tick drains, paced
    /// by the cap.
    ///
    /// Idempotent: re-running finds nothing to revoke once every eligible
    /// predecessor is already revoked (the per-row UPDATE is itself
    /// `WHERE revoked = FALSE`, so a race with a concurrent manual revoke
    /// degrades to a no-op, never a double-revoke or an error). Each
    /// predecessor's revoke + its successor's rotation-state clear commit
    /// atomically together — Hermes F3: the clear UPDATE's own result is
    /// checked; a genuine execution failure on it (not merely "matched zero
    /// rows", which is the expected idempotent case when the successor is
    /// already gone/resolved) rolls back the WHOLE transaction, including
    /// the predecessor's revoke, so "revocation ... resolves the rotation
    /// state, or neither" (§7) is a real guarantee, not just a comment.
    /// Each per-row transaction also opens with the same principal-scoped
    /// `pg_advisory_xact_lock` `rotate_engine_credential`/`confirm_rotation`
    /// take, so this sweep can't race a concurrent manual rotate/confirm
    /// for the same principal (never a revoked predecessor left with a
    /// successor still mid-rotation).
    ///
    /// A `SkippedLock` outcome (another replica is sweeping) is routine
    /// leader-election contention — the caller MUST NOT warn/audit on it
    /// every tick, only count it. A `Declined` outcome MUST be visible as
    /// something happened — never indistinguishable from "nothing expired"
    /// — via a dedicated metric plus an actionable log/audit event.
    [[nodiscard]] SweepResult sweep_expired_rotations(int64_t now);

    /// Best-effort, cluster-wide read of the sweep's own durable liveness
    /// anchor (`rotation_retention_meta.last_pass_now` — the same value
    /// `sweep_expired_rotations`'s classification transaction re-anchors on
    /// EVERY pass it reaches a verdict on, accepted or declined). Unlike a
    /// process-local liveness gauge (which would only ever move on the
    /// replica that happens to win the store-wide sweep lock — every other
    /// replica sees `SkippedLock` and never touches it), this reads the ONE
    /// shared row every replica's clock guard writes, so every replica's
    /// gauge reports the identical cluster-wide last-verdict instant
    /// regardless of which replica actually held the lock that tick. This
    /// is part 2 of the routed concern (compare against PostgreSQL's OWN
    /// clock, not N independently-drifting replica clocks) plus its
    /// unnumbered SINGLE-WRITER clause ("on a Postgres store the reading and
    /// the dedup state must become SHARED rows under an ... advisory lock,
    /// because process-local state paces at N x cap across replicas"),
    /// applied to this sweep's own observability: a store-wide session lock
    /// serialises the sweep, so `SkippedLock` on N-1 replicas is routine and
    /// staleness must be judged against the ONE shared anchor, never a
    /// per-replica one.
    /// `nullopt` on a lease/query failure or when no pass has ever reached a
    /// verdict (fresh install) — the caller must not fabricate a reading.
    [[nodiscard]] std::optional<int64_t> rotation_sweep_last_pass_now() const;

    /// Result of `list_rotations_nearing_expiry_unused` below.
    struct NearingExpiryResult {
        std::vector<RotationPair> pairs;
        /// PostgreSQL's own clock reading (`SELECT EXTRACT(EPOCH FROM
        /// now())::bigint`) THIS call used to decide `pairs`' lead-time
        /// window. The caller MUST derive any "has this pair's overlap
        /// window already elapsed" judgement from THIS value, never its own
        /// process clock — finding 7 of the #2964 fix round: the two halves
        /// of the T12 sweep used to compare against two DIFFERENT clocks
        /// (this half's own query vs the caller's process clock in
        /// `server.cpp`), so under exactly the skew this whole guard exists
        /// to survive, the caller could log/audit an "auto-revoke declined,
        /// past its overlap window" state for a pair `sweep_expired_
        /// rotations` does not (yet) consider elapsed at all. 0 when
        /// `pairs` is empty because the read failed (lease/query error) —
        /// in that case `pairs` is also empty, so there is nothing to
        /// derive `elapsed` for.
        int64_t pg_now = 0;
    };

    /// T12 sweep, half 2 (operational-health signal, design doc §7 bullet 2)
    /// — read-only. Returns every in-flight rotation pair whose predecessor
    /// overlap window ends within `warn_within_secs` of PostgreSQL's OWN
    /// current time (`NearingExpiryResult::pg_now`, read once per call — see
    /// that struct's doc comment for why this half no longer takes a
    /// caller-supplied `now`) — INCLUDING one that has already elapsed —
    /// AND whose successor has never been presented (`last_used_at == 0`).
    /// Before the never-used-successor carve-out in `sweep_expired_
    /// rotations` above, an already-elapsed window was exclusively that
    /// function's job and never appeared here; now that
    /// `sweep_expired_rotations` deliberately leaves such a pair alone, this
    /// half is the ONLY thing that keeps surfacing it, so it must keep
    /// matching past `pg_now` too (no upper-bound-only pairs are lost to the
    /// old `> now` floor). The caller (server.cpp's maintenance loop)
    /// turns each returned pair into an `engine_principal.rotation.
    /// successor_unused` audit row plus a bounded `reason="successor_unused"`
    /// Prometheus counter — deliberately NOT `event="security"` (this is an
    /// operational health signal, not a theft signal, per the design doc).
    /// A pair still returned here past its own `overlap_expires_at` is one
    /// `sweep_expired_rotations` is deliberately NOT resolving, and that is
    /// a distinct fact from the lead-time heads-up, so the caller warns
    /// again on crossing into it.
    ///
    /// CADENCE IS NOT UNIFORM, and `rotation_warn_dedup.hpp` is the single
    /// authority — do not infer it from this contract. The **log line**
    /// repeats every tick while the pair stays stuck; the **audit row and
    /// the counter named above** fire ONCE per pair per state (once
    /// pre-elapse, once on elapsing), process-local, so a restart re-emits
    /// once. An earlier revision of this comment said they re-fired on
    /// every tick "so a stuck pair cannot go silent" — that shipped, and
    /// was the defect: ~1440 audit rows/day for ONE stuck pair, into a
    /// store whose retention pass caps at 25 000 deletions per run.
    /// Indefinite loudness lives on the log channel; an alertable
    /// current-state signal is tracked in #2969 and does not exist yet, so
    /// do not build a stuck-pair alert on the counter.
    /// Best-effort, mirrors `list_all`: a lease/query failure logs at warn
    /// and returns an empty vector rather than propagating — this is a
    /// maintenance-loop read, not an authorization chokepoint.
    NearingExpiryResult list_rotations_nearing_expiry_unused(int64_t warn_within_secs) const;

    /// Revoke every non-revoked token belonging to a principal. Used by the
    /// session-revocation REST surface so "Sign out everywhere" actually
    /// revokes everywhere (cookie sessions + API tokens), not just browser
    /// cookies — a stolen-laptop incident otherwise leaves the on-laptop API
    /// token fully functional while the operator UX silently lies.
    ///
    /// #2961 residual A: the DB write runs inside the SAME per-principal
    /// advisory lock (`pg_advisory_xact_lock(hashtext(principal_id))`)
    /// `rotate_engine_credential`/`rotate_token`/`confirm_rotation`/
    /// `confirm_token_rotation` all take, so this deactivation can't
    /// interleave mid-flight with a concurrent rotate/confirm for the same
    /// principal. It also collects every `rotation_group` the revoked rows
    /// belonged to (the cache is keyed by rotation_group, not principal, so
    /// this maps principal -> groups first) and, after commit, calls
    /// `evict_rotation_raw` on each — scrubbing (`yuzu::secure_zero`, never
    /// a bare erase) any raw successor secret still resident in the
    /// RAM-only grace cache. Without this, "sign out everywhere" left an
    /// already-cached raw secret from a recent rotate re-servable via a
    /// grace-window replay for up to `kRotationGraceSecs` AFTER every
    /// credential for the principal was just revoked. This does NOT close
    /// every conceivable interleaving with `store_rotation_raw`'s own
    /// post-commit, outside-the-lock cache write (see that function's own
    /// doc comment and `successor_rotation_still_pending` — a genuinely
    /// concurrent in-flight mint racing this call is bounded by that
    /// existing guard, not by this one) — reworking that RAM re-serve
    /// design further is explicitly out of scope here (#2961 residual B).
    ///   * value — the number of tokens marked revoked (0 = the principal had
    ///             none; the DB write still succeeded).
    ///   * `unexpected(msg)` — the write did NOT persist; the caller MUST
    ///             record a partial/failed revoke, never a clean success
    ///             (ADR-0030 §Posture).
    std::expected<std::size_t, std::string> revoke_for_principal(const std::string& principal_id);

    /// Delete a token permanently. Same authoritative typed result as
    /// `revoke_token` (ADR-0030 §Posture names delete_token in the
    /// error-is-surfaced list): `unexpected` on a DB write failure, value
    /// `false` on no-such-token, `true` on delete.
    std::expected<bool, std::string> delete_token(const std::string& token_id);

    /// Cumulative count of validate_token calls served from the in-memory cache.
    /// Exposed for Prometheus scraping; set via gauge in server.cpp's periodic loop.
    /// #2974 review (K7): count of swallowed `resolve_rotation_pair_after_revoke`
    /// partner-clear failures. That path cannot fail the caller — the revoke it
    /// follows has already committed — so before this it was log-only and
    /// therefore unalertable. NOT a lockout risk (the sweep provably cannot
    /// auto-revoke a stranded partner; see the call site), but it leaves stale
    /// rotation metadata and a silent failure path is worth a signal.
    uint64_t rotation_pair_resolve_failures() const noexcept {
        return rotation_pair_resolve_failures_.load(std::memory_order_relaxed);
    }

    /// #2961 fix-round finding 4: count of `resolve_rotation_initiator`
    /// RAM-vs-durable DISAGREEMENTS. Both sources are written from the SAME
    /// `requesting_user` in the SAME mint call, and the durable column is
    /// stamped inside the same locked transaction the RAM entry is only
    /// ever populated FROM after (`store_rotation_raw` runs strictly after
    /// that mint commits) — so this branch is not reachable through any
    /// live code path in this store; the only way to produce it is an
    /// out-of-band write to `api_tokens.rotation_initiator` (direct SQL, a
    /// restored/edited backup) or a future bug. A non-zero count is
    /// therefore a TAMPER/CORRUPTION signal on an authorization input, not
    /// an operational condition — see the call site's log line, which
    /// carries `rotation_group` only, never either disputed username.
    uint64_t rotation_initiator_disagreements() const noexcept {
        return rotation_initiator_disagreements_.load(std::memory_order_relaxed);
    }

    uint64_t cache_hits() const noexcept { return cache_hits_.load(std::memory_order_relaxed); }

    /// Cumulative count of validate_token calls that fell through to Postgres.
    uint64_t cache_misses() const noexcept { return cache_misses_.load(std::memory_order_relaxed); }

    /// Current number of distinct tokens cached in memory.
    std::size_t cache_size() const;

    /// Current number of in-flight rotation-pair entries held in the RAM-only
    /// grace cache (`rotation_grace_cache_`, keyed by `rotation_group`) —
    /// mirrors `cache_size()`'s role for the validated-token cache. Exists so
    /// a test can assert the cache is EMPTY after a rejected rotate/confirm
    /// (in particular a mint whose transaction failed to commit AFTER the
    /// callback itself returned true — `store_rotation_raw` must never run
    /// ahead of that outcome being known, see `rotate_token`'s ordering
    /// comment) — a leaked entry here is invisible to LeakSanitizer (it stays
    /// reachable from this live member map), so this accessor is the only
    /// detector.
    std::size_t rotation_grace_cache_size() const;

    // Test-only seams (#2179) for the revoke/validate TOCTOU regression test.
    // Null in production (zero overhead). Let a test deterministically
    // interleave a concurrent revoke at the exact cache-poisoning point.
    std::function<void()> test_hook_after_first_revoke_bump_;   // fired in revoke_token, right after the FIRST generation bump, before the lease/UPDATE
    std::function<void()> test_hook_after_validate_select_;     // fired in validate_token, right after the SELECT (+last_used update), before the generation re-check block

    /// Fired in `rotate_token`'s re-serve/conflict arm, right before the
    /// principal-wide active-set re-read — receives the transaction's own
    /// `PGconn*` so a test can deterministically poison it (e.g. run an
    /// invalid statement on the same connection) and exercise the "the
    /// active-set read fails mid-transaction" path. That path MUST classify
    /// Transient/retryable, never the terminal "not a recognized rotation
    /// pair" conflict below it — see the call site's comment.
    ///
    /// BORROW CONTRACT (the only hook here that hands out a resource handle,
    /// so the shape does not speak for itself): the `PGconn*` is valid ONLY
    /// for the duration of this call — pool-owned, mid-transaction — and the
    /// callee must not retain it past return, nor close/commit/rollback it
    /// (that is `with_txn_for`'s job; a callee that does so races or
    /// double-frees the connection). As with the two hooks above, this
    /// `std::function` is read unsynchronized on the store's own request
    /// threads, so it may only be assigned before the store is shared across
    /// threads (single-threaded test setup, never a live-traffic toggle).
    std::function<void(PGconn*)> test_hook_before_rotate_group_read_;

    /// Fired in `rotate_token`'s MINT arm, right before `return true` — after
    /// the successor INSERT and the predecessor's overlap-window UPDATE have
    /// both already succeeded, but before `with_txn_for` attempts `COMMIT`.
    /// Same borrow contract as `test_hook_before_rotate_group_read_` above.
    /// Exists so a test can force the COMMIT itself (or the
    /// aborted/idle-transaction refusal ahead of it — `PgPool::run_in_txn`,
    /// `pg/pg_pool.cpp`) to fail AFTER this callback has returned `true`, and
    /// assert `store_rotation_raw` never ran for that attempt — the ordering
    /// bug class this hook exists to catch (a cache write racing ahead of
    /// the commit outcome leaves a permanently unevictable grace-cache entry,
    /// invisible to LeakSanitizer since it stays reachable from
    /// `rotation_grace_cache_`).
    std::function<void(PGconn*)> test_hook_before_mint_commit_;

    /// #2961 fix-round finding 2: fired once per SUCCESSFUL mint attempt
    /// (`rotate_engine_credential`'s 1-active arm, `rotate_token`'s mint
    /// arm), AFTER `with_txn_for` has returned true — the mint's INSERT +
    /// pair-stamp UPDATE are already committed and the mint's advisory lock
    /// is already RELEASED — but BEFORE `store_rotation_raw` caches the raw
    /// secret + initiating operator into `rotation_grace_cache_` for the
    /// grace window (Hermes F4). Lets a test deterministically interleave a
    /// confirm/sweep/revoke-partner-clear for the SAME rotation group in the
    /// exact window `successor_rotation_still_pending` exists to close: once
    /// the mint's transaction commits, its advisory lock is free, so a
    /// confirm arriving here can resolve the initiator from the
    /// JUST-COMMITTED durable `rotation_initiator` column (RAM is still
    /// empty — the cache write hasn't run yet) and fully resolve the
    /// rotation before this function ever reaches the cache write below.
    /// Without the guard this hook lets a test exercise, that cache write
    /// would go ahead regardless and insert an entry for an
    /// already-resolved rotation group that no future confirm/sweep call
    /// will ever touch again — permanently unevictable (not a
    /// credential-disclosure risk on its own: see
    /// `successor_rotation_still_pending`'s doc comment). No `PGconn*`
    /// argument, unlike `test_hook_before_mint_commit_`/
    /// `test_hook_before_rotate_group_read_` above: this point in the code
    /// holds no live connection — the mint's transaction already returned
    /// its lease to the pool by the time this fires. Same
    /// single-threaded-setup-only contract as every other hook here.
    std::function<void()> test_hook_before_store_rotation_raw_;

    /// Injects the engine-principal referential-integrity check used by
    /// `create_token`'s engine block (design doc §6). Unset by default —
    /// `create_token` fails closed (rejects every `principal_kind=="engine"`
    /// mint) until this is wired. server.cpp wires the real resolver
    /// (`EnginePrincipalStore::get_for_auth`) after both stores open; this
    /// setter exists so `ApiTokenStore` never constructs an
    /// `EnginePrincipalStore` itself (would couple two independently-owned
    /// stores at construction time).
    void set_engine_referent_check(std::function<EngineLookupStatus(const std::string&)> fn);

private:
    pg::PgPool& pool_;
    bool open_{false};

    // LRU cache for validated tokens: token_hash -> (ApiToken, expiry_time)
    struct CachedToken {
        ApiToken token;
        std::chrono::steady_clock::time_point cached_at;
    };
    mutable std::mutex cache_mtx_;
    mutable std::unordered_map<std::string, CachedToken> token_cache_;
    static constexpr auto kTokenCacheTtl = std::chrono::seconds(60);

    // Cache hit/miss counters (atomic, lock-free read for Prometheus scraping).
    std::atomic<uint64_t> rotation_pair_resolve_failures_{0};
    // #2961 fix-round finding 4 — see rotation_initiator_disagreements()'s
    // doc comment above: a tamper/corruption signal, not an operational one.
    // `mutable`: bumped from resolve_rotation_initiator, which is `const`
    // (a read-path helper; the atomic counter itself is the exception to
    // that constness, same shape as cache_hits_/cache_misses_ below).
    mutable std::atomic<uint64_t> rotation_initiator_disagreements_{0};
    mutable std::atomic<uint64_t> cache_hits_{0};
    mutable std::atomic<uint64_t> cache_misses_{0};

    // Defense-in-depth against a cache TOCTOU on revocation. Incremented
    // bumped TWICE per revoke in `revoke_token`, `revoke_for_principal`, and
    // `delete_token`: once BEFORE the UPDATE/DELETE and once AFTER it commits
    // (before `invalidate_cache`). `validate_token` snapshots the value before
    // its DB SELECT and re-reads it UNDER `cache_mtx_`, in the same critical
    // section as the cache write — if it moved, a revoke raced with us and we
    // MUST NOT populate the cache with a stale (revoked=false) view that would
    // survive for `kTokenCacheTtl` (60 s) and silently lie about "Sign out
    // everywhere". The re-check being under the lock is load-bearing:
    // `invalidate_cache` takes the same mutex and the generation bump precedes
    // it, so a check-BEFORE-lock ordering left a window in which a revoke's
    // erase ran between the check and the insert and the token re-authenticated
    // for the full TTL (fixed 2026-07; the re-check + insert are now one locked
    // step).
    //
    // Why TWO bumps (PR #2188 round-3 review). The pre-UPDATE bump only catches
    // a validate that snapshotted the generation BEFORE it. A validate that
    // starts AFTER the pre-bump captures the already-incremented value as its
    // baseline, and under Postgres READ COMMITTED its SELECT can still read the
    // row's pre-commit revoked=false; with only one bump its post-SELECT
    // re-check would match its own snapshot and cache the stale row for the full
    // TTL. The post-commit bump moves the generation past that snapshot too, so
    // BOTH classes of racing validate skip the stale cache write. The cache is
    // therefore never poisoned past the TTL.
    //
    // Under the pool there is no single connection-wide mutex serializing a
    // caller's SELECT against another caller's UPDATE the way the old sqlite
    // `db_mtx_` did — a Postgres pool hands out independent connections per
    // lease. The generation counter's job is NARROW: it stops a racing validate
    // from CACHING a stale entry. It does NOT restore the validate<->revoke
    // serialization db_mtx_ gave, so two bounded SINGLE-in-flight-request
    // windows remain (see validate_token in the .cpp): (A) a cache-MISS validate
    // may still RETURN (once, uncached) a token whose revoke committed during
    // its own execution, and (B) the cache-HIT path may return a validly-cached
    // value during the revoke's UPDATE->invalidate_cache gap. Neither permits a
    // NEW authentication after the revoke's invalidate runs, and neither leaves
    // a stale cache entry. A full close of (A)/(B) (SELECT ... FOR UPDATE in the
    // revoke txn, or a per-token version column) is tracked in #2173.
    // Keep every fetch_add (both per call) and every snapshot/re-check.
    std::atomic<uint64_t> revoke_generation_{0};

    // Engine-principal referential-integrity resolver (design doc §6),
    // injected via `set_engine_referent_check`. Null until server.cpp wires
    // it post-construction — `create_token` treats null as fail-closed
    // (never mints an engine token without this check available).
    std::function<EngineLookupStatus(const std::string&)> engine_referent_check_;

    // ── Overlap-pair rotation (design doc §7) ───────────────────────────
    //
    // Floor below which an overlap window is rejected outright rather than
    // silently truncated — a module that never gets a chance to pick up the
    // successor within the window is a worse failure than a rejected
    // `rotate` call.
    static constexpr int64_t kOverlapFloorSecs = 24 * 3600;

    // Ceiling above which an overlap window is rejected outright — without
    // this, an unfloored-but-unbounded caller value fed into
    // `now + overlap_secs` is an unchecked signed int64 add (UB on
    // overflow, and a wrapped-negative `window_end` would slip past the
    // expiry guards it's meant to enforce). 10 years is generously above
    // any legitimate overlap (the credential itself is capped to 90 days,
    // §7), so this never constrains a real caller.
    static constexpr int64_t kOverlapCeilSecs = 3650LL * 24 * 3600;

    // Grace window shape reused from §5's redemption-retry bound
    // (minutes-scale, single-digit default): how long a `rotate` retry may
    // re-serve the same successor secret, and how long its raw value stays
    // in the in-memory cache below. Deliberately NOT "until the module
    // presents the successor" — that condition is attacker-influenceable.
    static constexpr std::chrono::seconds kRotationGraceSecs{120};

    // Raw secret cache for the rotation grace window, keyed by
    // `rotation_group`. RAM-only, process-local — the raw value is NEVER
    // persisted (same one-time-reveal contract as `create_token`), and a
    // process restart forfeits re-serve (acceptable per §7: the caller falls
    // back to an explicit re-mint or the compromise runbook). `raw` reveal
    // is refused (by `try_reserve`, on lookup) once older than
    // `kRotationGraceSecs`, and the plaintext itself is actively scrubbed
    // (`yuzu::secure_zero`, not just left unreachable) by
    // `scrub_elapsed_grace_secrets` — called from `sweep_expired_rotations`'s
    // maintenance tick — the moment it crosses that same age, rather than
    // sitting resident in RAM for the rest of the (much longer) overlap
    // window. The entry itself, notably `requesting_user` (Hermes F4), is
    // NOT erased by either the staleness check or the scrub: `confirm_rotation`
    // (F5) needs the initiator binding to stay resolvable for the whole
    // overlap window (default 7 days), far outliving the short raw-reveal
    // grace window. The entry is only removed by an explicit
    // `evict_rotation_raw` call (confirm_rotation on success, or the sweep's
    // auto-revoke resolving the pair) — never a background timer.
    struct RotationGraceEntry {
        std::string raw;
        // Hermes F4/F5: the operator (route-layer authenticated session)
        // who initiated this rotation via `rotate_engine_credential`'s
        // 1-active mint arm. Binds both the grace-window re-serve (F4) and
        // `confirm_rotation` (F5) to that SAME caller — never served to,
        // or confirmable by, a different operator.
        std::string requesting_user;
        std::chrono::steady_clock::time_point minted;
    };
    mutable std::mutex rotation_cache_mtx_;
    mutable std::unordered_map<std::string, RotationGraceEntry> rotation_grace_cache_;

    /// Grace-cache accessor: true + `out_raw`/`out_requesting_user` set when
    /// `rotation_group` has an entry AND it is still within
    /// `kRotationGraceSecs` of its mint. Past the grace window (but the
    /// entry still present) returns false with `out_requesting_user` still
    /// populated (so a caller that wants identity-only, not the raw reveal,
    /// can still resolve it — see `grace_entry_owner` below for that use).
    /// Used internally by `rotate_engine_credential`'s 2-active re-serve
    /// arm. Never erases the entry — see the `RotationGraceEntry` doc
    /// comment for why.
    bool try_reserve(const std::string& rotation_group, std::string& out_raw,
                     std::string& out_requesting_user) const;

    /// Identity-only grace-cache accessor, NOT time-bounded to
    /// `kRotationGraceSecs` (unlike `try_reserve`'s raw reveal) — its sole
    /// caller is `resolve_rotation_initiator`, which folds it with the
    /// durable column to bind confirm (Hermes F5) to the same operator who
    /// initiated the rotation, for as long as the entry remains (until
    /// explicitly evicted). False if no entry exists for `rotation_group`
    /// (e.g. a process restart since the mint, or the rotation already
    /// resolved).
    bool grace_entry_owner(const std::string& rotation_group,
                           std::string& out_requesting_user) const;

    /// #2961 — the SINGLE chokepoint `confirm_rotation`/`confirm_token_rotation`
    /// (Hermes F5) use to resolve the operator who initiated a rotation,
    /// combining the RAM-only grace cache with the durable
    /// `ApiToken::rotation_initiator` fallback so the binding survives a
    /// server restart. `successor` is the ALREADY-READ, in-flight successor
    /// row from THIS SAME locked transaction's positive read (never a fresh
    /// query here) — the caller only reaches this once the surrounding
    /// state-classifier has confirmed a genuine pair exists, so there is no
    /// new read-failure mode to disambiguate: the row's `rotation_initiator`
    /// is either the value stamped at mint, or empty because it predates the
    /// v3 migration — never "unknown due to a swallowed read".
    ///
    /// F5-ONLY, never F4: `try_reserve`'s raw-secret re-serve MUST NEVER call
    /// this — it stays RAM-only. Calling this from `try_reserve` would NOT,
    /// by itself, resurrect the one-time-reveal contract: this function
    /// returns an identity string only, never the raw secret, which is
    /// still never persisted anywhere — so `try_reserve` would still fail
    /// on its own grace-cache lookup before an identity check could even
    /// matter. The boundary is still the correct one to keep (F4 and F5 are
    /// deliberately different questions — "can I re-serve the secret" vs.
    /// "who may confirm"), just not for that overstated consequence.
    ///
    /// Returns `std::nullopt` — never a wildcard match, never a distinguishable
    /// "failed read" (`successor` is already-read, per above) — on every
    /// ambiguous or unresolved case; `std::optional<std::string>` per
    /// `docs/cpp-conventions.md`'s ban on output parameters in new code
    /// (this function conveys no error, only resolved / not-resolved). The
    /// empty guard below applies to WHICHEVER branch produced the value —
    /// not just the durable one — so an empty resolved value can never
    /// escape as though it were a real identity, in this branch or a future
    /// one (e.g. #2946's read-only accessor, which has no `requesting_user`
    /// of its own to compare against).
    ///
    /// Resolution, fails closed on every ambiguous case:
    ///   - RAM present, durable present (non-empty), and they DIFFER ->
    ///     `nullopt` — RAM is the primary source, durable is a RAM-absent
    ///     recovery path only; never prefer either on conflict.
    ///   - RAM present (durable absent/empty/agreeing) -> the RAM value,
    ///     UNLESS it is empty, in which case `nullopt`.
    ///   - RAM absent, durable present (non-empty) -> the durable value
    ///     (the restart-recovery path this function exists for).
    ///   - RAM absent, durable EMPTY (pre-v3 pair, or a row that was somehow
    ///     never stamped) -> `nullopt`. Empty is NOT a wildcard that matches
    ///     any caller.
    ///   - Neither present -> `nullopt`.
    [[nodiscard]] std::optional<std::string>
    resolve_rotation_initiator(const ApiToken& successor) const;

    /// Removes a grace-cache entry outright. Called once a rotation
    /// resolves (`confirm_rotation` on success; the T12 sweep's auto-revoke
    /// on the predecessor's window elapsing) so the entry doesn't linger in
    /// RAM after it can no longer be looked up by any live rotation state
    /// (rotation_group values are derived from a fresh token hash each
    /// mint, so a stale unevicted entry is otherwise inert, not a
    /// correctness risk — this is hygiene, not a security fix).
    void evict_rotation_raw(const std::string& rotation_group);

    /// Design §7 ("revocation during overlap ... resolves the rotation
    /// state"): when `revoke_token`/`delete_token` removes ONE credential of an
    /// in-flight rotation pair, the surviving partner must not be left mid-
    /// rotation. Clears the partner's rotation columns
    /// (`rotation_group`/`supersedes_token_id`/`overlap_expires_at` -> defaults)
    /// so (a) a revoked-predecessor's successor becomes a standalone active
    /// credential, and (b) a revoked-successor's predecessor is no longer a
    /// sweep target (its `overlap_expires_at` is cleared) — without which the
    /// T12 sweep would later auto-revoke the principal's ONLY remaining
    /// credential as routine `overlap_window_elapsed`. Advisory-locked on
    /// `principal_id` (serializes with rotate/confirm/sweep) and evicts the
    /// grace-cache entry. No-op when `rotation_group` is empty (the common
    /// non-rotation revoke). Best-effort: a failure here does not un-revoke the
    /// token the caller already committed.
    void resolve_rotation_pair_after_revoke(const std::string& principal_id,
                                            const std::string& rotation_group,
                                            const std::string& revoked_token_id);

    /// Caches a freshly-minted successor's raw secret + initiating operator
    /// for the grace window (Hermes F4).
    void store_rotation_raw(const std::string& rotation_group, const std::string& raw,
                            const std::string& requesting_user);

    /// #2961 fix-round finding 2: a fresh, OUTSIDE-the-lock re-read of a
    /// just-minted successor row, called immediately before
    /// `store_rotation_raw` below — both `rotate_engine_credential`'s
    /// 1-active mint arm and `rotate_token`'s mint arm cache the raw secret
    /// AFTER `with_txn_for` commits and RELEASES the principal's advisory
    /// lock (deliberately, so the cache write never outruns the commit
    /// outcome — see `store_rotation_raw`'s call-site comments). That
    /// leaves a window, between the commit and the cache write, where a
    /// confirm/sweep/revoke-partner-clear for the SAME rotation group can
    /// slip in on the now-free lock and resolve/clear the pair BEFORE the
    /// cache entry exists — `resolve_rotation_initiator` happily resolves
    /// the initiator from the durable `rotation_initiator` column this same
    /// commit just wrote, since RAM is still empty. That confirm's own
    /// `evict_rotation_raw` call is then a no-op (nothing to evict yet), and
    /// the cache write that follows inserts an entry for a rotation group
    /// that is ALREADY fully resolved — permanently unevictable, since every
    /// eviction site requires the pair to resolve AGAIN, which it never
    /// will. Not a credential-disclosure risk: the caller's own raw secret
    /// was already returned via the mint's own return value, so there is
    /// nothing live left for `try_reserve`'s grace-window re-serve (F4) to
    /// leak — this is a residue/lifetime defect (an unevictable map entry,
    /// its `raw` still scrubbed by `scrub_elapsed_grace_secrets`'s own
    /// timeout, same as any other entry), not a re-disclosure one.
    ///
    /// The successor's OWN `rotation_group` column is stamped to its OWN
    /// `token_id` at mint time (see the mint INSERT in the .cpp) and
    /// cleared to `''` by every site that resolves a rotation — both
    /// confirm arms, `resolve_rotation_pair_after_revoke`, and the sweep's
    /// auto-revoke (see `ApiToken::rotation_initiator`'s "cleared on the
    /// surviving row" doc comment for the closed four-site list). So an
    /// empty `rotation_group` on a fresh re-read means the rotation this
    /// cache entry would be for was ALREADY resolved in the gap above.
    ///
    /// This check is itself a narrower instance of the SAME class of window
    /// (a fresh, unlocked read followed by a decision) — it cannot close the
    /// race outright without re-taking the advisory lock around the cache
    /// write, which would reintroduce the very "cache write can outrun the
    /// commit" ordering hazard `test_hook_before_mint_commit_` exists to
    /// catch. Narrowing a residual window this far, rather than closing it
    /// with a lock, matches this file's existing posture on comparably
    /// narrow single-request races (see `revoke_generation_`'s own doc
    /// comment in the header above).
    ///
    /// Fails OPEN (returns true — "still pending", i.e. cache it) on a lease
    /// timeout or an ambiguous read, the same "we asked and did not get an
    /// answer, so don't act on it" posture `list_active_for_principal`
    /// takes: under-caching a legitimate in-flight rotation (refusing a
    /// valid grace-window re-serve) is an availability regression this check
    /// must never cause on a merely-contended store; the failure mode this
    /// check exists to close (a permanently stranded entry) is comparatively
    /// benign and already tolerated elsewhere in this class of race.
    [[nodiscard]] bool successor_rotation_still_pending(const std::string& successor_token_id) const;

    /// Secret-hygiene sweep, distinct from `sweep_expired_rotations`'s
    /// DB-side auto-revoke half: scrubs (`yuzu::secure_zero`) every
    /// grace-cache entry's `raw` once it is past `kRotationGraceSecs`,
    /// WITHOUT erasing the entry itself — `requesting_user` (Hermes F4/F5)
    /// must stay resolvable for the whole overlap window. Without this, the
    /// plaintext successor secret would otherwise sit resident in RAM for
    /// up to the full overlap window (default days), long after
    /// `try_reserve` stops re-serving it. Called from
    /// `sweep_expired_rotations`'s maintenance tick; safe to call more
    /// often (idempotent — an already-empty `raw` is a no-op).
    void scrub_elapsed_grace_secrets();

    /// §6/§7/§8 engine-mint validation shared by `create_token`'s engine
    /// block and `rotate_engine_credential`'s candidate-successor prep
    /// (Hermes F2 — see the .cpp for why this runs OUTSIDE the locked
    /// transaction rather than being folded into it). Pure/cheap checks
    /// (scope/tier/TTL) plus the one external call, `engine_referent_check_`
    /// (referential integrity against `EnginePrincipalStore`, §6).
    [[nodiscard]] std::expected<void, std::string>
    validate_engine_mint(const std::string& principal_id, const std::string& scope_service,
                        const std::string& mcp_tier, int64_t expires_at, int64_t now) const;

    /// Human-mint validation shared by `create_token`'s common checks
    /// (unconditional, both principal_kind values) and `rotate_token`'s
    /// candidate-successor prep — the exact anti-drift pattern
    /// `validate_engine_mint` establishes for the engine mint paths. Pure/
    /// cheap: name non-empty, scope-service requires an expiry, MCP tier
    /// validity + expiry requirement + 90-day ceiling. No external referent
    /// check (unlike the engine arm — a human token has no referential
    /// integrity requirement against another store).
    [[nodiscard]] std::expected<void, std::string>
    validate_human_mint(const std::string& name, const std::string& scope_service,
                        const std::string& mcp_tier, int64_t expires_at, int64_t now) const;

    /// Generate a fresh `yuzu_` Bearer token from the platform CSPRNG.
    /// Returns the raw token on success; std::unexpected when the system
    /// entropy source is unavailable (caller must surface as 503, never
    /// fall back to weak entropy). See `secure_random.hpp` for details.
    std::expected<std::string, std::string> generate_raw_token() const;
    std::string sha256_hex(const std::string& input) const;
    void invalidate_cache(const std::string& token_hash);
};

} // namespace yuzu::server
