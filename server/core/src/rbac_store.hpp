#pragma once

/// @file rbac_store.hpp
/// Authorization substrate — role definitions, role→permission grants,
/// principal→role assignments, RBAC groups + membership, and the global
/// `rbac_enabled` flag. Born on SQLite (`rbac.db`), migrated to PostgreSQL
/// (ADR-0006/0007/0008/0009/0012, schema `rbac_store`; migration ADR-0041).
/// The LARGEST and highest-blast-radius store on the ladder: a migration
/// defect here is a FLEET-WIDE authorization failure.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement
/// (`rbac_store.roles`). No `sqlite3_changes()` (#1033) — mutators use
/// `RETURNING` / `PQcmdTuples`.
///
/// Failure posture (ADR-0041), the load-bearing invariant:
///  - **Authz reads FAIL CLOSED.** `check_permission` /
///    `check_scoped_permission` / `holds_permission_via_any_group` /
///    `check_role_has_permission` keep their `bool`/DENY-on-error contract: a
///    store-not-open, pool-acquire timeout, or query error returns `false`
///    (deny), NEVER `true`. The list/scope reads return the empty /
///    most-restrictive result on degrade. Callers that must distinguish
///    "denied" from "store degraded" (403 vs 503) use the `_checked`
///    (`std::expected`) accessors — the plain `bool`/vector paths stay
///    deny-on-error so no chokepoint can regress to fail-open.
///  - **Permission cache → shared durable generation token.** The
///    process-local `write_generation_` becomes a durable
///    `rbac_meta.write_generation` counter bumped IN THE SAME TXN as every
///    mutation. Each replica keeps its in-process `perm_cache_` but validates
///    it against the durable generation, refreshed at most once per
///    `kRbacGenerationRefreshMs`; on a generation change (a mutation on ANY
///    replica) or on ANY generation-read error it clears the cache (fail
///    toward "assume changed", never extend trust). Bounds cross-replica
///    stale-allow to the refresh interval.
///  - **`migrate_from_sqlite()` retired (#3623, ADR-0041 Update).** No
///    production fleet ever ran a pre-Postgres build of this store, so the
///    mandatory, read-back-verified `rbac_enabled`-flag-first backfill it
///    implemented never had real legacy data to protect. `server.cpp` now
///    runs `legacy_sqlite_probe::warn_if_legacy_rows` over `rbac_config`
///    (the legacy table holding the enabled flag — the row that matters
///    most) plus `securable_types`/`operations`/`roles`/`role_permissions`/
///    `principal_roles`/`groups`/`group_members` instead — silent unless
///    real rows are found, never blocks boot.

#include <atomic>
#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
class Histogram;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

class ManagementGroupStore; // forward declaration

struct RbacRole {
    std::string name;
    std::string description;
    bool is_system{false};
    int64_t created_at{0};
};

struct Permission {
    std::string role_name;
    std::string securable_type;
    std::string operation;
    std::string effect; // "allow" or "deny"
};

struct PrincipalRole {
    std::string principal_type; // "user", "group", or "engine" (PR 4.2, design §4.1)
    std::string principal_id;
    std::string role_name;
};

struct RbacGroup {
    std::string name;
    std::string description;
    std::string source; // "local", "ad", "entra"
    std::string external_id;
    int64_t created_at{0};
};

/// Membership counts changed by a `reconcile_idp_memberships` call — how many
/// asserted memberships were newly ADDED and how many stale memberships were
/// REMOVED. Both are 0 for a no-op reconcile (the asserted set exactly
/// matched what was already on record), which callers use to skip writing a
/// provisioning audit row for a login that changed nothing. #1832 hardening.
struct ReconcileResult {
    size_t added{0};
    size_t removed{0};
};

/// Discriminated result of `RbacStore::authorize_list_read` — the ADR-0017
/// admit-then-filter list gate for per-agent list/fan-out reads.
enum class ListReadDecision {
    DenyAll,     ///< no grant anywhere — 403 (REST) / empty (dashboard)
    AdmitAll,    ///< global grant, or RBAC loaded-and-disabled → unfiltered read
    AdmitScoped, ///< management-group-confined — read ONLY `visible_agents`
};

struct ListReadAuthorization {
    ListReadDecision decision{ListReadDecision::DenyAll}; ///< fail-closed default (INV-1)
    /// Populated ONLY for `AdmitScoped`; the management-group-visible agent set
    /// (possibly empty ⇒ zero rows, INV-2). Left empty for Deny/AdmitAll.
    std::vector<std::string> visible_agents;
};

/// Result of a successful `RbacStore::set_rbac_enforcement` call.
struct RbacEnforcementTransition {
    bool previous_enabled{false};   ///< durable value read under the row lock
    bool enabled{false};            ///< durable value after the call
    bool changed{false};            ///< false = already in the requested state (no write, no bump)
    std::int64_t post_transition_administrators{0}; ///< enable: authenticatable Administrator
                                                     ///< grants; disable: active local
                                                     ///< role=admin accounts
};

/// Outcome of `RbacStore::check_caller_authorized_under_current_regime` —
/// see that method's own doc comment for the full reasoning (Gate 8 HIGH:
/// `assign_role`/`unassign_role` share `set_rbac_enforcement`'s exact
/// cross-replica cache-staleness root cause). A tri-state, matching
/// `RbacAdminGate`'s own shape (`rbac_admin_predicate.hpp`) rather than
/// collapsing "denied" and "could not confirm" into one boolean.
enum class RbacRegimeAuthority {
    kAuthorized,    ///< caller holds authority under the regime read fresh, right now
    kNotAuthorized, ///< caller confirmed NOT in that regime's authority set — 403-class
    kUnavailable,   ///< could not confirm (pool/query failure) — 503-class, NEVER treat as
                    ///< either of the above
};

/// Refusal/failure of `RbacStore::set_rbac_enforcement`.
struct RbacEnforcementError {
    enum class Kind {
        kStoreFailure,      ///< pool/txn/query failure, absent or non-canonical flag row → 503-class
        kCallerNotSurvivor, ///< the caller would not remain a durable administrator under the
                            ///< DESTINATION regime → 409-class (a post-transition survival
                            ///< conflict — the transition itself is legitimate, but this
                            ///< particular caller would be locked out by it)
        kCallerNotAuthorizedUnderCurrentRegime, ///< Gate 7 Fix 1 (security-guardian,
                                                 ///< cross-replica cache staleness): the caller
                                                 ///< does not hold authority under the SOURCE
                                                 ///< (durably current, freshly re-read) regime —
                                                 ///< a plain authority failure, not a survival
                                                 ///< conflict → 403-class. Only ever evaluated on
                                                 ///< a real transition (never the idempotent
                                                 ///< no-op path — see set_rbac_enforcement's own
                                                 ///< doc comment).
    };
    Kind kind{Kind::kStoreFailure};
    std::string message; ///< human-readable; no caller-supplied text is ever embedded
};

class RbacStore {
public:
    /// Borrows the shared pool and runs the `rbac_store` schema migration on a
    /// pinned lease, then seeds defaults + loads the durable enabled flag.
    /// `is_open()` is false if the lease was empty or the migration failed
    /// (fail-closed — every authz read then DENIES, the right posture for the
    /// authorization substrate).
    explicit RbacStore(pg::PgPool& pool);
    ~RbacStore();

    RbacStore(const RbacStore&) = delete;
    RbacStore& operator=(const RbacStore&) = delete;
    RbacStore(RbacStore&&) = delete;
    RbacStore& operator=(RbacStore&&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for `yuzu_server_rbac_read_degrade_total{reason}`.
    /// Set ONCE during single-threaded startup before serving; read without
    /// synchronisation on serving threads. Null (the
    /// default, e.g. unit tests) disables emission; every emit site is guarded.
    /// Also resolves and caches `authz_check_seconds_hist_` here (#2703 Gate 7
    /// item Commit B) — a `Histogram&` obtained from a `MetricsRegistry` is
    /// stable for that registry's lifetime (`MetricFamily` stores instances in
    /// an `unordered_map`, which the standard guarantees does not invalidate
    /// references on insertion/rehash), so resolving it once here, rather than
    /// by name on every `check_permission()` call, is safe as long as the
    /// pointer is never read before this has run. It is deliberately NOT a
    /// function-local `static`: a static would bind to whichever
    /// `MetricsRegistry` happened to call first and keep writing into it for
    /// every later `RbacStore` instance/registry pairing — silently wrong
    /// under multiple registries (e.g. sequential unit tests, each with its
    /// own short-lived registry), and a dangling write once the first
    /// registry is destroyed.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept;

    // ── Global toggle ────────────────────────────────────────────────────
    /// The cached view of the durable `rbac_enabled` flag, refreshed at most
    /// once per `kRbacGenerationRefreshMs`. Raw and NOT fail-closed on its
    /// own: a failed refresh leaves this returning whatever was last
    /// observed, which can be a stale `false` while the durable flag has
    /// since flipped `true` elsewhere (adversarial-review round, #2703).
    /// Confinement-critical callers MUST use `rbac_enforcement_in_effect()`
    /// instead, which additionally fails closed on a degraded view — this
    /// raw accessor is for callers that only display or log the toggle.
    bool is_rbac_enabled() const;

    /// UNGUARDED seed/test primitive: writes the durable flag unconditionally,
    /// with no last-administrator/caller-survives guard of any kind. Reports
    /// the write outcome; deliberately NOT `[[nodiscard]]` — ~70 existing test
    /// call sites across `tests/unit/server/` seed with this deliberately
    /// UNguarded ("enforcement in effect; no roles/grants created") and a
    /// nodiscard would force every one of them into a discard/REQUIRE wrapper
    /// for a test-only primitive (`meson.build` sets `werror=false`, so the
    /// warning would never fail a build, only add 20 files of noise). NEW
    /// callers (including new tests) MUST still check the result explicitly.
    /// NEVER call this from a route or MCP handler — the production,
    /// caller-survives-guarded path is `set_rbac_enforcement` below.
    std::expected<void, std::string> set_rbac_enabled(bool enabled);

    /// THE route/MCP-callable toggle. On a REAL transition (requested state
    /// differs from the durable, freshly-locked current state), refuses
    /// (without writing) unless the CALLER (`caller_username`) passes BOTH:
    ///
    ///  1. A SOURCE-regime authority check (Gate 7 Fix 1) — the caller must
    ///     hold authority under the regime that is durably true RIGHT NOW:
    ///     an authenticatable fleet-wide `Administrator` grant while
    ///     currently ON, or the caller's own local `role='admin' AND
    ///     is_active` while currently OFF. This exists because the outer
    ///     `is_rbac_administrator` gate (the route/MCP-handler's own
    ///     admission check) reads a replica-LOCAL cached view of the flag
    ///     that can lag a real commit by up to `kRbacGenerationRefreshMs` —
    ///     this route is the thing that FLIPS the value that gate reads, so
    ///     it cannot rely on that gate as its sole regime check for itself.
    ///  2. A DESTINATION-regime survival check (pre-existing) — would the
    ///     caller remain a durable administrator AFTER the switch: enabling
    ///     requires an authenticatable fleet-wide `Administrator` grant;
    ///     disabling requires the caller's own local `role='admin' AND
    ///     is_active`.
    ///
    /// Both checks run INSIDE the same transaction as the flag write, under
    /// the `rbac_meta` row lock and (enable direction only) the same `FOR
    /// UPDATE OF pr` lock `unassign_role` takes over the identical candidate
    /// rows — the enable direction's membership/count are decided FROM that
    /// locked result set, never a second, unlocked query. The disable
    /// direction's source check reads the same `principal_roles` rows
    /// WITHOUT locking them (`list_authenticatable_admin_grants`) — a real
    /// transition never needs BOTH the locked and unlocked reads of the same
    /// set, because source and destination regimes are always opposite on a
    /// genuine transition. See the .cpp for the full rule, including the
    /// accepted point-in-time (not enduring) nature of BOTH the destination
    /// guarantee AND the disable direction's lock-free source check — the
    /// same property, not a stricter one, since the source check is also an
    /// unlocked read observed inside this transaction, never "still holds it
    /// at commit."
    ///
    /// Idempotent: requesting the current state returns `changed=false`
    /// WITHOUT evaluating either guard or bumping `write_generation` — this
    /// is a DELIBERATE, tested contract (a caller with no authority at all
    /// may still learn "already in that state"), not an oversight; the
    /// source-regime check above is reached only past that early return.
    [[nodiscard]] std::expected<RbacEnforcementTransition, RbacEnforcementError>
    set_rbac_enforcement(bool enabled, const std::string& caller_username);
    /// True when the cached `rbac_enabled` view is no longer trustworthy —
    /// checked as: `!generation_valid_` (a refresh attempt actually completed
    /// and found itself past `kRbacStaleServeBoundMs`), OR, independently,
    /// the last successful refresh is more than `kRbacStaleServeBoundMs`
    /// (bounded stale-serve, #2703 Gate 7, an operator-adjudicated
    /// availability-vs-strictness tradeoff) in the past even with NO refresh
    /// attempt ever completing — e.g. one stuck in flight on PG-side lock
    /// contention (#3016) for longer than the bound (G11-CPPEXPERT-B2, #2703
    /// Gate 8). This is an OR of two independent triggers, not an AND — a
    /// refresh failure shorter than the bound does NOT degrade the view — the
    /// cache keeps serving last-known-good state through a short blip rather
    /// than dropping trust on every transient Postgres timeout.
    /// `rbac_enforcement_in_effect()` treats a genuinely degraded view the
    /// same as "enabled" — a refresh failure that HAS exceeded the bound must
    /// not extend trust in a cached `false` any more than it may extend trust
    /// in a cached permission verdict (ADR-0041 "must NOT extend trust").
    /// Implemented via `generation_view_stale_locked()`, which is also the
    /// chokepoint `check_permission()` uses for its own perm-cache trust
    /// decision — do not reintroduce a second, divergent copy of this check.
    [[nodiscard]] bool rbac_enabled_view_degraded() const;

    // ── Roles CRUD ───────────────────────────────────────────────────────
    std::vector<RbacRole> list_roles() const;
    std::optional<RbacRole> get_role(const std::string& name) const;
    std::expected<void, std::string> create_role(const RbacRole& role);
    std::expected<void, std::string> update_role(const std::string& name,
                                                 const std::string& description);
    std::expected<void, std::string> delete_role(const std::string& name);

    // ── Permissions CRUD ─────────────────────────────────────────────────
    std::vector<Permission> get_role_permissions(const std::string& role_name) const;

    /// Authoritative variant of `get_role_permissions` (ADR-0012 read
    /// posture) for bulk-read consumers — e.g. the periodic-access-review
    /// export (`access_review_model.cpp`) — that must distinguish "this role
    /// genuinely grants no permissions" from "the store degraded". A bare
    /// vector conflates the two; `unexpected(msg)` here is a closed store,
    /// pool-acquire timeout, or a query error. A value (possibly empty) is a
    /// genuine, fully-read result.
    std::expected<std::vector<Permission>, std::string>
    get_role_permissions_checked(const std::string& role_name) const;

    /// Bulk variant of `get_role_permissions_checked` — every row in
    /// `role_permissions`, for every role, in ONE query. Same fail-closed
    /// posture as the other `_checked` accessors.
    std::expected<std::vector<Permission>, std::string>
    list_all_role_permissions_checked() const;

    std::expected<void, std::string> set_permission(const Permission& perm);
    /// Revokes by DELETEing the role_permissions row (restoring the exact
    /// legacy contract — absence, not a 'deny' row) AND recording the
    /// revocation in `revoked_seed_defaults`, a bookkeeping-only table
    /// consulted solely by `seed_defaults()`'s reseed so the built-in
    /// default cannot silently return on the next restart. Never an
    /// `effect='deny'` upsert: `check_permission()`/`check_scoped_permission()`/
    /// `authorize_list_read()` apply "deny overrides everything, across ALL
    /// of a principal's held roles" — a real deny row here would veto an
    /// allow the same principal holds via a DIFFERENT role, which the
    /// legacy store never did (see the implementation comment, #2703).
    /// `role_name`/`securable_type`/`operation` must already be valid FK
    /// targets (an unrecognised triple fails with `unexpected`).
    ///
    /// Has NO REST/MCP route today (#2703). Whoever wires one MUST audit
    /// both outcomes exactly as `assign_role`'s route wiring does — see
    /// `rest_api_v1.cpp`'s `engine_principal.role.assigned` denied/success
    /// pair (~line 2277-2299) for the precedent: audit the denial with its
    /// specific reason before the uniform client-facing error, then audit
    /// success separately.
    std::expected<void, std::string> remove_permission(const std::string& role_name,
                                                       const std::string& securable_type,
                                                       const std::string& operation);

    // ── Principal-role assignments ────────────────────────────────────────
    std::vector<PrincipalRole> get_principal_roles(const std::string& principal_type,
                                                   const std::string& principal_id) const;

    /// Authoritative variant of `get_principal_roles` — same posture as
    /// `get_role_permissions_checked`.
    std::expected<std::vector<PrincipalRole>, std::string>
    get_principal_roles_checked(const std::string& principal_type,
                                const std::string& principal_id) const;

    /// Bulk variant of `get_principal_roles_checked` — EVERY `(principal_type,
    /// principal_id, role_name)` grant row on record, across all three
    /// principal types, in ONE query. This is the authoritative set: the grant
    /// table, not any roster, is the source of truth for "who currently holds
    /// a role". Same fail-closed posture as the other `_checked` accessors.
    std::expected<std::vector<PrincipalRole>, std::string>
    list_all_principal_roles_checked() const;

    std::vector<PrincipalRole> get_role_members(const std::string& role_name) const;

    /// Shared assignment guard called by BOTH `RbacStore::assign_role` AND
    /// `ManagementGroupStore::assign_role` — a single chokepoint per design
    /// §4.2 "no admin, ever" so a future assignment call site can never
    /// re-derive its own, possibly looser, copy. Deliberately static/
    /// DB-independent (name-based, not an `is_system` lookup).
    ///
    /// - Any `principal_type` other than `"engine"` is a no-op pass.
    /// - `principal_type == "engine"` REQUIRES `principal_id` to carry the
    ///   reserved `"engine:<slug>"` namespace (§3.3).
    /// - `principal_type == "engine"` REJECTS `role_name` naming a built-in
    ///   full-access role ("Administrator" or the literal "admin").
    static std::expected<void, std::string> validate_assignment(const std::string& principal_type,
                                                                 const std::string& principal_id,
                                                                 const std::string& role_name);

    /// Gate 8 HIGH (security-guardian): `assign_role`/`unassign_role` take
    /// no caller identity and perform no equivalent of
    /// `set_rbac_enforcement`'s own source-regime check (Gate 7 Fix 1) — a
    /// caller admitted by `is_rbac_administrator` under a STALE cached view
    /// of `rbac_enabled_` (which can lag a real commit by up to
    /// `kRbacGenerationRefreshMs`, or the wider `kRbacStaleServeBoundMs`
    /// while degraded) could mint or revoke a DURABLE `principal_roles`
    /// Administrator grant — unlike the toggle's own transient window, this
    /// persists indefinitely once written.
    ///
    /// Deliberately NOT a parameter added to `assign_role`/`unassign_role`
    /// themselves — those are store-level primitives with many existing
    /// direct-store-level tests that neither supply nor need a caller
    /// identity; forcing one on would churn every one of them for a check
    /// that is really about REST/MCP call-CONTEXT, not store-level
    /// semantics. This is instead a HANDLER-level convenience: a FRESH,
    /// uncached, lock-free read of the durable `rbac_enabled` flag,
    /// followed by a membership check against whichever authority set that
    /// regime requires — reusing the SAME two sets
    /// `set_rbac_enforcement`'s own source-regime check reads
    /// (`list_authenticatable_admin_grants` while durably on,
    /// `list_active_local_admin_accounts` while durably off), never a third
    /// copy of that logic. Call this AFTER `is_rbac_administrator` and
    /// BEFORE `assign_role`/`unassign_role`, at all four call sites (REST
    /// `POST`/`DELETE .../rbac/roles/{name}/assignments`, MCP
    /// `assign_rbac_role`/`unassign_rbac_role`).
    ///
    /// Point-in-time, not enduring — the SAME accepted residual
    /// `set_rbac_enforcement`'s own source/destination checks carry (#4966):
    /// the durable regime, or the caller's own authority, could change
    /// between this call returning and the actual mutation landing a moment
    /// later. This is not a new gap this method introduces; it is the same
    /// window every other caller-survives-style check in this file already
    /// accepts, just at a different call boundary (handler-to-store instead
    /// of store-internal).
    [[nodiscard]] RbacRegimeAuthority
    check_caller_authorized_under_current_regime(const std::string& caller_username) const;

    /// Takes no caller identity — any REST/MCP handler-layer caller acting on
    /// behalf of a human (`principal_type == "user"`) operator MUST call
    /// `check_caller_authorized_under_current_regime` (above) first and
    /// refuse before reaching here; this method itself enforces no
    /// equivalent check, so skipping that call site re-opens the exact
    /// cross-replica cache-staleness gap it exists to close.
    std::expected<void, std::string> assign_role(const PrincipalRole& pr);

    /// The guard's transaction lives in `RbacAdminAuthorityOwner`
    /// (rbac_admin_authority_owner.cpp), an ADR-0012 §3 query owner; this method
    /// delegates to it.
    ///
    /// A2 last-Administrator guard: when `role_name == "Administrator"`,
    /// refuses (and rolls back) a delete that would leave ZERO
    /// `principal_roles` rows naming `role_name = 'Administrator'` AND
    /// `principal_type = 'user'` for a genuinely AUTHENTICATABLE
    /// administrator — deliberately NOT a bare grant-row count. The guard
    /// JOINs `auth.users` (`u.username = pr.principal_id AND u.is_active`)
    /// so a pre-provisioned grant on a nonexistent username, or a
    /// deactivated/(soft-)deleted account, never counts as a "surviving"
    /// administrator — see rbac_admin_authority_owner.cpp for the full reasoning (this is safe
    /// only because `RbacStore` and `AuthDB` always share one PgPool in
    /// production, ADR-0006). Also matches
    /// `rbac_admin_predicate.hpp::is_rbac_administrator`'s gate exactly on
    /// the `principal_type` axis — it never resolves a group-held
    /// Administrator row either (a documented A2 scope exclusion),
    /// deliberately NOT `principal_type IN ('user', 'group')`. The count
    /// runs INSIDE the same transaction as the delete, under a
    /// `FOR UPDATE OF pr` row lock on the candidate `principal_roles` rows
    /// (the candidate `auth.users` rows are never locked; only the deleted
    /// principal's own row is, by the post-DELETE recheck), so two concurrent
    /// unassigns racing to remove the last two Administrator grants serialize
    /// instead of both observing "1 remaining" and both committing. The
    /// guard does NOT cover an `auth.users` row created concurrently for a
    /// pre-provisioned grant, nor deactivation of a surviving Administrator
    /// between the recount and COMMIT (#4966). Every other
    /// role/principal_type combination — including both existing
    /// engine-only callers (the engine-principal unassign in `rest_api_v1.cpp`
    /// and `mcp_server.cpp`) — is unaffected: a pure idempotent DELETE, exactly as
    /// before (an Administrator grant held by a non-user principal still runs the
    /// candidate lock query but is never counted). The
    /// refusal's error string always contains `kRbacLastAdminRefusalMarker`
    /// (below) — callers that need to distinguish this business-rule
    /// refusal from a genuine store/query failure match on that constant
    /// rather than inventing their own substring.
    ///
    /// Returns `true` iff a row was actually removed (idempotent — an
    /// unassign of a role the principal never held returns `false`, not an
    /// error) — surfaced so a caller's audit trail can distinguish an actual
    /// revoke from a no-op, rather than auditing both identically.
    ///
    /// Same caller-identity contract as `assign_role` above: takes none of
    /// its own, so a REST/MCP handler acting on behalf of a human operator
    /// MUST call `check_caller_authorized_under_current_regime` first.
    std::expected<bool, std::string> unassign_role(const std::string& principal_type,
                                                    const std::string& principal_id,
                                                    const std::string& role_name);

    /// Fresh-install RBAC-safe-by-default bootstrap (third
    /// `RbacAdminAuthorityOwner` consumer, same delegation shape as
    /// `unassign_role`/`set_rbac_enforcement` above). Inserts the FIRST
    /// `auth.users` row (iff the table is genuinely empty, TOCTOU-free via
    /// the same advisory lock `AuthDB::seed_admin_if_empty` uses) and grants
    /// that account `Administrator`, atomically in one transaction — see
    /// `RbacAdminAuthorityOwner::provision_first_admin`'s own doc comment
    /// for the full contract, including why callers MUST invoke this
    /// BEFORE `AuthDB::seed_admin_if_empty` rather than after.
    ///
    /// Returns `true` iff THIS call actually provisioned the account+grant,
    /// `false` on the ordinary no-op (not the first account — not an
    /// error), `unexpected` on a genuine store/query failure OR an invalid
    /// `username`. Safe to call unconditionally on every boot: the no-op
    /// path is cheap and harmless on a non-fresh database.
    std::expected<bool, std::string> provision_first_admin(const std::string& username,
                                                            const std::string& password_hash,
                                                            const std::string& salt_hex);

    // ── Groups CRUD (minimal — for future AD/Entra) ──────────────────────
    std::vector<RbacGroup> list_groups() const;

    /// Authoritative variant of `list_groups` — same posture as
    /// `get_role_permissions_checked`. Added for the periodic-access-review
    /// export, which must never export a partial grant set as if complete.
    std::expected<std::vector<RbacGroup>, std::string> list_groups_checked() const;

    /// Rejects a `source=="local"` create whose `name` collides with a reserved
    /// IdP or engine-principal namespace prefix (`local:`/`entra:`/`saml:`/
    /// `ad:`/`engine:`). An IdP-sourced create (any other `source`) is exempt.
    std::expected<void, std::string> create_group(const RbacGroup& group);
    std::expected<void, std::string> delete_group(const std::string& name);

    /// Read-only prefix scan over LOCALLY-sourced group names — backs the T8
    /// startup collision-scan preflight. `prefix` must be a code-controlled
    /// literal (e.g. `"engine:"`).
    ///
    /// G3 (governance hardening, UP-2): returns `std::nullopt` on a scan error
    /// (store not open, pool-acquire timeout, or query error) so a scan failure
    /// can never be misread as "no collisions found" by the boot preflight — an
    /// empty-but-`has_value()` result means the scan genuinely completed and
    /// found nothing. Callers MUST treat `nullopt` as fail-closed.
    std::optional<std::vector<std::string>>
    find_local_groups_with_prefix(const std::string& prefix) const;
    std::vector<std::string> get_group_members(const std::string& group_name) const;
    std::expected<void, std::string> add_group_member(const std::string& group_name,
                                                      const std::string& username);
    std::expected<void, std::string> remove_group_member(const std::string& group_name,
                                                         const std::string& username);

    /// Upper bound on the number of IdP-asserted groups reconciled for a single
    /// login. Defends `reconcile_idp_memberships` against a malicious/compromised
    /// IdP response turning one login into an unbounded write storm. #1832.
    static constexpr size_t kMaxIdpGroupsPerLogin = 200;

    /// Reconcile the IdP-asserted group memberships for `username` under
    /// `source` ("entra"/"saml"/"ad" — never "local"/empty) against what
    /// `group_members` currently records. See the .cpp for the full contract
    /// (#1832). Returns `unexpected` WITHOUT mutating on an over-cap or
    /// invalid-source call; callers MUST treat any `unexpected` as fail-closed.
    std::expected<ReconcileResult, std::string>
    reconcile_idp_memberships(const std::string& username, const std::string& source,
                              const std::vector<std::pair<std::string, std::string>>& asserted);

    // ── Authorization check ──────────────────────────────────────────────
    /// FAIL-CLOSED: false (deny) on store-not-open / pool timeout / query error.
    bool check_permission(const std::string& username, const std::string& securable_type,
                          const std::string& operation) const;

    /// Scoped permission check: first tries global, then checks group-scoped
    /// roles. FAIL-CLOSED: false on any store error.
    bool check_scoped_permission(const std::string& username, const std::string& securable_type,
                                 const std::string& operation, const std::string& agent_id,
                                 const ManagementGroupStore* mgmt_store) const;

    // ── ADR-0017 admit-then-filter list gate ─────────────────────────────
    /// The single chokepoint for list/fan-out reads of per-agent data under
    /// management-group confinement (ADR-0017). FAIL-CLOSED (INV-1/INV-5): any
    /// store/mgmt-store error, `!is_open()`, or unresolvable scope yields
    /// `DenyAll`, never `AdmitAll`.
    ListReadAuthorization authorize_list_read(const std::string& username,
                                              const std::string& securable_type,
                                              const std::string& operation,
                                              const ManagementGroupStore* mgmt_store) const;

    /// "Does this user hold `<securable>:<op>` via ANY management group?"
    /// FAIL-CLOSED: false on any store error.
    bool holds_permission_via_any_group(const std::string& username,
                                        const std::string& securable_type,
                                        const std::string& operation,
                                        const ManagementGroupStore* mgmt_store) const;

    /// The permission-specific visible set (ADR-0017 INV-4). FAIL-CLOSED
    /// (INV-1/INV-5): `unexpected(msg)` on any store error, so a partial read
    /// never over-discloses.
    std::expected<std::vector<std::string>, std::string>
    visible_agents_for_permission(const std::string& username, const std::string& securable_type,
                                  const std::string& operation,
                                  const ManagementGroupStore* mgmt_store) const;

    /// Check if a specific role grants a permission (for service-scoped token
    /// validation). FAIL-CLOSED: false on any store error.
    bool check_role_has_permission(const std::string& role_name, const std::string& securable_type,
                                   const std::string& operation) const;

    /// All effective permissions for a user (for UI display).
    std::vector<Permission> get_effective_permissions(const std::string& username) const;

    // ── Reference data ───────────────────────────────────────────────────
    std::vector<std::string> list_securable_types() const;
    std::vector<std::string> list_operations() const;

private:
    // #2703 Gate 7 item 3 — same shape as PreflightRoutesTestAccess /
    // DashboardResultsColumnsTestAccess: user_rbac_group_names/role_effects_for
    // are legitimately private (internal helpers `resolve_perm_groups` shares),
    // but their OWN degrade-emission sites are what this fix adds, and
    // resolve_perm_groups short-circuits on the FIRST failure — so a black-box
    // test through the public `authorize_list_read()` chokepoint can only ever
    // exercise user_rbac_group_names's sites, never role_effects_for's. The
    // friend seam lets the test drive each directly.
    friend struct RbacStoreTestAccess;

    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
    // Cached by set_metrics() — see that method's doc comment. Null whenever
    // metrics_ is null (never observed).
    yuzu::Histogram* authz_check_seconds_hist_{nullptr};

    // Durable-generation-validated view of the global enabled flag. The atomic
    // is the hot-path answer; `maybe_refresh_generation()` re-reads the durable
    // `rbac_meta.rbac_enabled` at most once per refresh interval and updates it
    // (never flips it to disabled on a read error — that would be fail-open).
    mutable std::atomic<bool> rbac_enabled_{false};
    // Gate 7 Fix 2 (cpp-safety, CRITICAL): the generation `rbac_enabled_`
    // itself is gated on — DELIBERATELY separate from `cached_generation_`
    // below, which belongs to `perm_cache_` and is bumped by EVERY RBAC
    // writer (assign_role/unassign_role/group CRUD/...), not just a toggle.
    // `perm_cache_` self-heals on the next refresh regardless of who bumped
    // the generation (it is empty until repopulated on demand), but
    // `rbac_enabled_` does not — nothing repopulates it except a toggle's own
    // `publish_local_toggle` or the next periodic refresh's adopt branch. Pre-fix,
    // `publish_local_toggle` gated on the SHARED `cached_generation_`, so an
    // unrelated writer's flag-less generation bump (which advances
    // `cached_generation_` via `apply_local_generation` alone) could race
    // ahead of a toggle's own commit and make the toggle's OWN publish look
    // "behind", silently masking it — this replica's `rbac_enabled_` then
    // stayed wrong until the next refresh interval elapsed. Written ONLY by
    // `publish_local_toggle` and `maybe_refresh_generation`'s flag-adoption
    // branch — the two places that ever change `rbac_enabled_`.
    mutable std::atomic<std::uint64_t> flag_generation_{0};

    void seed_defaults();     // idempotent (ON CONFLICT DO NOTHING)
    // Loads rbac_enabled_ + the generation anchor from the durable rbac_meta
    // rows. Returns false (→ ctor refuses boot, fail-closed) if the flag cannot
    // be read — never leaves rbac_enabled_ at a default while open_ stays true.
    [[nodiscard]] bool load_enabled_flag();

    /// Collect all role names for a principal (direct user grant + via group
    /// membership + direct engine-principal grant, §4.1) using `conn`. Returns
    /// empty on a query error (fail-closed: an empty role set denies).
    std::vector<std::string> collect_roles(void* conn, const std::string& username) const;

    // ── ADR-0017 shared list-gate resolver (INV-7) ───────────────────────
    struct PermGroups {
        std::vector<std::string> allow_groups;
        std::vector<std::string> deny_groups;
    };
    std::expected<PermGroups, std::string> resolve_perm_groups(
        const std::string& username, const std::string& securable_type,
        const std::string& operation, const ManagementGroupStore* mgmt_store) const;

    std::expected<std::vector<std::string>, std::string>
    expand_visible_set(const PermGroups& pg, const ManagementGroupStore* mgmt_store) const;

    std::expected<std::vector<std::string>, std::string>
    user_rbac_group_names(const std::string& username) const;

    std::expected<std::unordered_map<std::string, int>, std::string>
    role_effects_for(const std::string& securable_type, const std::string& operation) const;

    // ── Permission cache — durable generation token (ADR-0041) ───────────
    mutable std::mutex cache_mtx_;
    mutable std::unordered_map<std::string, bool> perm_cache_; // "user:type:op" -> allow/deny
    mutable uint64_t cached_generation_{0};   // durable generation perm_cache_ is valid for
    mutable bool generation_valid_{false};    // false ⇒ assume-changed, do not trust cache
    // fjarvis F3 (#2703): split from a single timestamp. `refresh_started_ms_`
    // gates whether a NEW refresh attempt may begin (stampede/retry-storm
    // prevention) and is bumped BEFORE the query runs. `last_successful_refresh_ms_`
    // is bumped ONLY when a refresh actually lands (or on a local write via
    // `apply_local_generation`) and is the honest measure of cache freshness —
    // a single shared timestamp bumped pre-query let a concurrent reader
    // during an in-flight refresh believe the cache was fresh-as-of-now when
    // it was really fresh-as-of-the-PREVIOUS successful refresh, silently
    // falsifying the accepted ~kRbacGenerationRefreshMs staleness bound for
    // however long the in-flight query took.
    mutable int64_t refresh_started_ms_{0};
    mutable int64_t last_successful_refresh_ms_{0};

    /// At most once per `kRbacGenerationRefreshMs`, re-read the durable
    /// `write_generation` + `rbac_enabled` in ONE query; on a generation change
    /// clear `perm_cache_`; on ANY error clear the cache and mark it invalid
    /// (assume-changed — never extend trust). Leaves `rbac_enabled_` unchanged
    /// on a read error (never flips a cached `true` to disabled/fail-open) —
    /// the OTHER direction (a cached `false` while the durable flag has since
    /// become `true`) is left to the caller: `rbac_enforcement_in_effect()`
    /// checks `rbac_enabled_view_degraded()` (which now ALSO checks elapsed
    /// time, not just `generation_valid_` alone — see
    /// `generation_view_stale_locked()`, G11-CPPEXPERT-B2) and treats a
    /// degraded view as enforced, closing that direction without this
    /// function needing to guess at a value it could not read. A concurrent
    /// caller that misses the gate while a refresh is in flight AND finds the
    /// cache already past the accepted bound counts a `stale_beyond_accepted_bound`
    /// degrade (fjarvis F3) — the acceptance is measured, not assumed.
    void maybe_refresh_generation() const;

    /// The single source of truth for "is the generation/perm-cache view
    /// currently trustworthy" — `!generation_valid_`, OR (generation_valid_
    /// but) the last successful refresh is more than `kRbacStaleServeBoundMs`
    /// in the past (G11-CPPEXPERT-B2, #2703 Gate 8: closes the gap where a
    /// refresh stuck in flight past the bound — e.g. PG-side lock contention,
    /// #3016 — left `generation_valid_` true and stale indefinitely, since
    /// nothing else ever completes to flip it). MUST be called with
    /// `cache_mtx_` already held — it does not lock itself, so every raw read
    /// of `generation_valid_` that decides whether to TRUST existing cached
    /// state (as opposed to deciding whether to CACHE a value just fetched
    /// live, which is a different, unaffected question) must route through
    /// this, not the bare field. `rbac_enabled_view_degraded()`,
    /// `check_permission()`'s perm-cache trust check, and
    /// `maybe_refresh_generation()`'s own `within_stale_serve_bound` check
    /// all do.
    [[nodiscard]] bool generation_view_stale_locked() const;

    /// Apply a locally-committed durable generation: clear `perm_cache_`, set
    /// `cached_generation_`, mark valid, and re-anchor the refresh clock (the
    /// writing replica is immediately coherent with itself).
    void apply_local_generation(uint64_t new_gen) const;

    /// Publish a locally-committed `(generation, enabled)` pair from
    /// `set_rbac_enabled`/`set_rbac_enforcement`. Generation-gated (A1,
    /// #2703-adjacent): does the same cache-clear/re-anchor work as
    /// `apply_local_generation`, in the SAME critical section, ALWAYS (the
    /// perm-cache half is unconditional except for the pre-existing
    /// not-behind-`cached_generation_` check, untouched by Gate 7 Fix 2)
    /// PLUS a SEPARATELY-gated `rbac_enabled_.store(enabled)` guarded by its
    /// own dedicated `flag_generation_` — `if (new_gen <
    /// flag_generation_.load()) return;` (skip only the flag write)
    /// otherwise `rbac_enabled_.store(enabled); flag_generation_.store(new_gen);`.
    ///
    /// Gate 7 Fix 2 (cpp-safety, CRITICAL — corrected from the original A1
    /// design, which gated the flag write on the SAME `cached_generation_`
    /// the perm-cache half uses): `cached_generation_`/`perm_cache_` SELF-HEAL
    /// on the next refresh regardless of which writer bumped the durable
    /// generation — the cache is just empty until repopulated on demand, so
    /// an unrelated writer racing ahead costs nothing but a redundant clear.
    /// `rbac_enabled_` does NOT share that property: nothing repopulates it
    /// except a toggle's own publish or the next periodic refresh's adopt.
    /// Gating the flag write on the shared `cached_generation_` meant an
    /// UNRELATED, flag-less writer (`assign_role`/`unassign_role`/group
    /// CRUD/...) committing at N+1 and calling `apply_local_generation(N+1)`
    /// on this replica BEFORE a toggle's OWN thread reached
    /// `publish_local_toggle(N, ...)` made the toggle's publish look "behind"
    /// (`N < N+1`) and skip ENTIRELY — this replica's `rbac_enabled_` then
    /// stayed wrong for a full refresh interval, restarted by a commit that
    /// had nothing to do with the toggle. `flag_generation_` is written ONLY
    /// by this method and `maybe_refresh_generation`'s flag-adoption branch,
    /// so a flag-less writer's generation bump can never mask a real toggle's
    /// publish again. `bump_generation_in_txn` runs inside the writer's own
    /// transaction and holds the `write_generation` row lock until COMMIT, so
    /// generation order equals commit order — the same soundness argument
    /// that justified the original `cached_generation_` gate for `perm_cache_`
    /// applies identically to `flag_generation_` for `rbac_enabled_`, just
    /// evaluated against its own counter. `apply_local_generation` itself and
    /// its other callers are unchanged — they never touch `flag_generation_`.
    void publish_local_toggle(std::uint64_t new_gen, bool enabled) const;

    /// Publish `yuzu_server_rbac_enforcement_enabled` (gauge, no labels, per
    /// replica) from the current `rbac_enabled_` atomic. Called after
    /// `set_metrics()`, after `publish_local_toggle`'s adopt (outside
    /// `cache_mtx_` — same after-release pattern as the breaker gauge, see
    /// `breaker_note_result`), and from `maybe_refresh_generation`'s adopt
    /// site. Reads the atomic at call time rather than taking a captured
    /// local, so two racing publishes both end up reporting the latest
    /// adopted value.
    void publish_enforcement_gauge() const noexcept;

    std::string perm_cache_key(const std::string& user, const std::string& type,
                               const std::string& op) const;

    // ── Fail-fast breaker (#2703 Gate 7 merge-slice item 1 commit B,
    // operator-adjudicated: trip fast at 2 consecutive failures) ──────────
    // Separate from `cache_mtx_` deliberately: a warm-cache HIT must never
    // contend on breaker state — the ordering this implements is refresh
    // (breaker-gated) -> cache lookup (never breaker-gated) -> pool fallback
    // (breaker-gated), so `breaker_mtx_` is touched only on the two gated
    // paths, never on the fast cache-hit path. Per-process, per-replica
    // state (like `refresh_started_ms_` above) — deliberately NOT
    // cross-replica; this protects only THIS process's own worker pool from
    // wasting `kAuthzAcquireTimeout` on a Postgres it already knows is bad.
    // "Breaker open/closed" (standard circuit-breaker terminology: open =
    // tripped, blocking; closed = healthy, passing) is unrelated to RBAC's
    // own "fail closed" (deny-by-default) — a denial from an OPEN breaker is
    // still a fail-CLOSED (deny) authz outcome, same as any other degrade.
    mutable std::mutex breaker_mtx_;
    mutable int breaker_consecutive_failures_{0}; // >= kBreakerTripThreshold ⇒ open
    mutable int64_t breaker_last_probe_started_ms_{0}; // claim gate, bumped BEFORE the attempt

    /// True (admitted) when the breaker is closed (`breaker_consecutive_failures_
    /// < kBreakerTripThreshold`), OR this call wins the one-probe-per-cooldown
    /// half-open slot (claimed by advancing `breaker_last_probe_started_ms_`
    /// before returning, same claim-then-attempt idiom as
    /// `maybe_refresh_generation`'s `refresh_started_ms_` gate). False
    /// (denied) means: do not touch the pool for this attempt — the caller's
    /// existing fail-closed handling applies without an actual acquire/query.
    bool breaker_admit() const;

    /// Record the outcome of a pool touch this instance's own `breaker_admit()`
    /// admitted (never call for a denied/skipped attempt — there is nothing
    /// to record). `success` resets the streak to 0 (closes the breaker);
    /// failure increments it (opens/keeps it open past the trip threshold).
    /// On a closed<->open TRANSITION, also sets the
    /// `yuzu_server_rbac_breaker_open` gauge (0/1) — AFTER releasing
    /// `breaker_mtx_`, never while holding it (#2703 Gate 7 item 1 commit C).
    void breaker_note_result(bool success) const;
};

/// Visibility policy for device-listing call sites that fall back to the full
/// enrolled fleet when RBAC enforcement is OFF. Returns true when RBAC
/// enforcement is IN EFFECT (caller must use its role-scoped, fail-closed
/// path); false only for a store that is loaded, explicitly disabled, AND
/// whose disabled view is currently FRESH (`is_open() && !is_rbac_enabled()
/// && !rbac_enabled_view_degraded()`). A null / load-failed store returns
/// true and so fails CLOSED (#1498); a DEGRADED view (the last durable-
/// generation refresh failed) also returns true — a failed refresh must not
/// extend trust in a cached "disabled" any more than a cached permission
/// verdict (adversarial-review round, #2703).
[[nodiscard]] bool rbac_enforcement_in_effect(const RbacStore* store) noexcept;

/// Three-way classification of RBAC enforcement state — strictly more
/// granular than `rbac_enforcement_in_effect`'s plain enforced/not-enforced
/// boolean, which deliberately conflates "genuinely enabled" with "degraded
/// view, deny by default" (both gate DENY, so the boolean is right for
/// authorization).
///
/// THE TEST for whether a NEW use of this label is permitted: does it change
/// the SET OF INPUTS THAT ADMIT a request? If yes — forbidden. Use
/// `rbac_enforcement_in_effect()`'s boolean directly; the admit/deny outcome
/// must always equal what that boolean alone gives (see the documented
/// equivalence below). If no — the use only stamps an audit label, or picks
/// between two outcomes that are BOTH already non-admitting — it is
/// permitted, subject to two further conditions: (1) a SINGLE snapshot read
/// per logical decision (call `rbac_enforcement_label()` exactly once and
/// branch on that one result — never decompose into this call plus a
/// separate `rbac_enforcement_in_effect()` call, or two calls to this
/// function, "to satisfy the letter" of a narrower use: the underlying view
/// can self-heal between calls — a healthy pool's next refresh clears a
/// stale cache — so two calls can observe two different states across one
/// logical decision); (2) a `security-guardian` review, via this file's
/// routed-concerns row (`.claude/routed-concerns-access-control.md`, the A2
/// row's trigger list names this enum/function explicitly) — adding a new
/// consumer is a security decision, not a routine edit, and that row is
/// where consumers satisfying this test are tracked, not a hardcoded count
/// in this comment.
///
/// PRIMARY use: an AUDIT-FACING label for export/evidence surfaces
/// (`access_review_model.cpp`, A3, the Periodic Access Review export, SOC 2
/// CC6.2). An auditor reading an evidence export needs the distinction a
/// bare boolean erases: a `kDegraded` stamp says "we could not confirm the
/// state, gates denied defensively" — NOT "an administrator turned RBAC on".
///
/// WORKED EXAMPLE of a sanctioned non-export use, satisfying the test above:
/// `rbac_admin_predicate.hpp`'s `is_rbac_administrator` (Doomgoose external
/// review, PR #4985 IMPORTANT #2, reconciled with A3 above at merge time —
/// both PRs independently built this identical shape against this branch's
/// own primitives before either merged). It reads the label TWICE from one
/// snapshot: once to pick which authority source to consult (`!= kDisabled`
/// — this IS the same routing decision `rbac_enforcement_in_effect()`'s own
/// boolean makes, by the documented equivalence below, so it changes nothing
/// about which inputs admit), and once — only after that source's own row
/// lookup has already found no matching grant, i.e. only on an
/// already-non-admitting path — to choose WHICH non-admitting failure to
/// return: a retryable `kUnavailable` (503) for `kDegraded`, versus a
/// terminal `kDenied` (403) otherwise. It was previously conflating those
/// two "no row" cases and returning a terminal 403 for a transient store
/// hiccup, exactly the failure mode this enum exists to let a caller avoid.
/// Neither read ever returns `kAdmin` by itself — an actual grant/role match
/// is still required on every path.
enum class RbacEnforcementLabel {
    kEnabled,  ///< store open, `is_rbac_enabled() == true`.
    kDisabled, ///< store open, `is_rbac_enabled() == false`, view FRESH — the
               ///< one case `rbac_enforcement_in_effect()` returns `false` for.
    kDegraded, ///< everything else `rbac_enforcement_in_effect()` returns
               ///< `true` for WITHOUT a confirmed enable: a null/not-open
               ///< store, or an open-and-disabled store whose view is STALE
               ///< (`rbac_enabled_view_degraded() == true`).
};

/// Maps `store` to one of the three `RbacEnforcementLabel` states above.
/// Deliberately mirrors `rbac_enforcement_in_effect`'s own branch order and
/// short-circuiting EXACTLY (same three accessors, same precedence) so the
/// two can never silently drift apart: `rbac_enforcement_in_effect(store) ==
/// (rbac_enforcement_label(store) != RbacEnforcementLabel::kDisabled)` holds
/// for every input. One asymmetry worth stating explicitly because a
/// reviewer will ask: a store that is cached-ENABLED but whose generation
/// view also happens to be stale classifies as `kEnabled`, not `kDegraded` —
/// `is_rbac_enabled()` short-circuits before `rbac_enabled_view_degraded()`
/// is ever consulted, exactly like `rbac_enforcement_in_effect()` itself;
/// gates still deny either way, so this is the same fail-closed answer, just
/// a less granular label for that one case. `is_rbac_administrator` inherits
/// this asymmetry unchanged (a cached-enabled+stale RBAC-off admin still
/// gets a definitive `kDenied`, never `kUnavailable`) — this is the
/// platform's existing accepted fail-closed posture for that direction
/// (#2703 addressed the cached-*disabled* direction only), not a new gap
/// this reconciliation introduces.
[[nodiscard]] RbacEnforcementLabel rbac_enforcement_label(const RbacStore* store) noexcept;

/// "enabled" | "disabled" | "degraded" — the wire/DB string form of
/// `RbacEnforcementLabel`, used verbatim as the access-review export's
/// `rbac_enforcement` field and the frozen campaign row's column of the same
/// name (`access_review_store.hpp`). `constexpr`, header-inline — matches
/// every other enum-to-string mapper in this codebase
/// (`authz_model.hpp::to_string(Operation/McpTierClass/RiskTier)`,
/// `agent_registry.hpp::to_string(DispatchDenialReason)`,
/// `schedule_params_parsers.hpp::to_string(ScheduleParamsError)`); nothing
/// here depends on anything not visible at header-parse time.
[[nodiscard]] constexpr std::string_view to_string(RbacEnforcementLabel label) noexcept {
    switch (label) {
    case RbacEnforcementLabel::kEnabled:
        return "enabled";
    case RbacEnforcementLabel::kDisabled:
        return "disabled";
    case RbacEnforcementLabel::kDegraded:
        return "degraded";
    }
    return "degraded"; // unreachable for a valid enumerator; fail closed on the label too
}

/// The fixed marker substring `RbacStore::unassign_role`'s error string
/// always contains when refusing the A2 last-Administrator guard (see that
/// method's doc comment). The REST route (POST/DELETE
/// `/api/v1/rbac/roles/{name}/assignments`) and its MCP twin both match
/// against this ONE constant — via `is_rbac_last_admin_refusal` below — to
/// distinguish the business-rule refusal (409/Conflict-class) from a genuine
/// store/query failure (503/Transient-class). EXTEND this, never invent a
/// second copy of the wording to match against.
inline constexpr std::string_view kRbacLastAdminRefusalMarker = "zero administrators";

/// True iff `msg` (an `unassign_role` error string) is the last-Administrator
/// refusal above, rather than a genuine store/query failure.
[[nodiscard]] inline bool is_rbac_last_admin_refusal(const std::string& msg) noexcept {
    return msg.find(kRbacLastAdminRefusalMarker) != std::string::npos;
}

/// True iff `msg` (an `RbacStore::assign_role` error string) is a genuine
/// CLIENT-facing validation rejection — one of `validate_assignment`'s own
/// messages, or `assign_role`'s own built-in-system-role rejection (F1) —
/// rather than a store/query fault (`"database not open"`, a raw
/// `PQerrorMessage` string, or the ambiguous `"assign_role failed"`
/// fallback). Doomgoose external review, PR #4985 IMPORTANT finding #3: both
/// the REST and MCP `assign_rbac_role` twins previously mapped EVERY
/// `!assign_role(...)` outcome to a 400/`kInvalidParams` client error
/// unconditionally — a genuine store fault (a dropped connection, a Postgres
/// error) was misreported as "your input was rejected" rather than the
/// retryable 503/`kInternalError` it actually is.
///
/// ALLOWLIST, not a denylist, by design: an unrecognized FUTURE error string
/// from `assign_role` (one this list has not been updated for) defaults to
/// the SAFER "store fault, retryable" classification rather than silently
/// masquerading as a permanent client rejection. EXTEND this allowlist
/// whenever `validate_assignment`/`assign_role` grows a new genuine
/// client-validation message — match the FIXED, non-interpolated wording
/// only, never a caller-controlled substring (`role_name`/`principal_id` are
/// interpolated into several of these messages).
///
/// Scoped to `assign_role` only — `unassign_role`'s error vocabulary is
/// different (no `validate_assignment` call) and is already correctly
/// classified via `is_rbac_last_admin_refusal` above; do not reuse this
/// helper for unassign's errors.
[[nodiscard]] inline bool rbac_assign_error_is_client_fault(std::string_view msg) noexcept {
    return msg.find("reserved 'engine:' namespace may only be assigned under") !=
               std::string_view::npos ||
           msg.find("unrecognized principal_type '") != std::string_view::npos ||
           msg.find("must be in the reserved 'engine:<slug>' namespace") !=
               std::string_view::npos ||
           msg.find("cannot be granted the admin/full-access role") != std::string_view::npos ||
           msg.find("cannot be granted a built-in system role") != std::string_view::npos;
}

/// Build the `groups.name` used for an IdP-sourced group: `source:external_id`.
/// `source == "local"` groups are NOT namespaced — returns `external_id`
/// unchanged. The confused-deputy fix for #1832.
[[nodiscard]] std::string namespaced_group_name(const std::string& source,
                                                const std::string& external_id);

} // namespace yuzu::server
