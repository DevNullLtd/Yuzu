#include "rbac_store.hpp"

#include "management_group_store.hpp"
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_admin_authority_owner.hpp"
#include "rbac_generation_rules.hpp"
#include "rbac_store_sql_helpers.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <functional>
#include <optional>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "rbac_store";

// Bounded acquires (ADR-0012 §2(a)). Reads back interactive REST/dashboard/MCP
// callers; writes get a slightly wider budget. Backfill runs single-threaded at
// construction before serving, so a wide deadline is fine. Defined in
// rbac_store_sql_helpers.hpp (shared with RbacAdminAuthorityOwner).
using rbac_sql::kReadTimeout;
using rbac_sql::kWriteTimeout;
// Availability hardening (governance re-review, #2703 Gate 7 — Fable-reviewed
// merge slice, item 1 commit A). The hot authz path (`maybe_refresh_generation`,
// `check_permission`'s own acquire, and `resolve_perm_groups`'s two acquires via
// `user_rbac_group_names`/`role_effects_for`) is on the request-serving critical
// path for EVERY confined operator action, so it uses this short acquire budget
// instead of `kReadTimeout` (2 s). PgPool clamps a bounded acquire that finds the
// pool already saturated at entry to its `saturated_fast_fail` (500ms by default),
// so `kReadTimeout` alone would wait up to ~500ms there, and the full 2 s only for
// a pool that saturates after the call entered it. This budget bounds the acquire
// wait at ~250ms in both cases, limiting how much of the shared `http_worker`
// pool a Postgres degrade can exhaust before the breaker below trips (an open
// breaker answers without a pool touch). CRUD/admin RbacStore calls
// (`assign_role`, `set_permission`, catalogue listings, etc.) are operator-driven,
// not per-request, and keep the wider `kReadTimeout` — matches
// `docs/postgres-store-playbook.md`'s hot-path-vs-admin acquire-budget split.
constexpr std::chrono::milliseconds kAuthzAcquireTimeout{250};
// chaos-injector (Gate 5, #2703, HIGH — CHAOS-1, verified against live PG):
// serializes every writer of the seed/revoke pair — seed_defaults()'s
// grant() and remove_permission() — against each other (migrate_from_sqlite()'s
// former F1 revoke block was retired, #3623). Without this, grant()'s `INSERT ... SELECT ... WHERE
// NOT EXISTS (marker) ... ON CONFLICT DO NOTHING` can resurrect an
// already-revoked permission: if grant()'s statement snapshot is taken
// BEFORE a concurrent revoke's marker-insert+DELETE commits, but grant()
// then blocks on the ON-CONFLICT arbiter waiting for that same uncommitted
// DELETE, Postgres only re-checks the CONFLICT TARGET after the wait — it
// does NOT re-evaluate the WHERE NOT EXISTS subquery, which is fixed at the
// original (pre-revoke) snapshot. Once the revoke's DELETE commits, the
// conflict is gone and grant()'s already-computed INSERT lands anyway,
// leaving the marker AND the resurrected row both present, permanently
// (nothing ever re-syncs role_permissions against revoked_seed_defaults).
// The LOCK must be acquired in its OWN statement, in an explicit
// transaction, strictly BEFORE the statement that checks-and-mutates —
// embedding the lock in the same statement via a CTE does NOT work: a
// single statement's READ COMMITTED snapshot is fixed at that statement's
// start, before any of its own function calls (including a blocking
// pg_advisory_xact_lock) run, so blocking mid-statement never refreshes it.
// Verified empirically both ways. Coarse-grained (one fixed key, not
// per-triple): RBAC writes are boot-time seeding + rare admin actions, never
// a hot path, so cluster-wide serialization across all triples is cheap and
// avoids needing per-triple lock keys for the backfill's bulk (multi-row,
// array-parameterized) F1 statement. Two-int32 form + the "yuzu" namespace
// constant matches house convention (pg_migration_runner.cpp, auth_db.cpp,
// secret_codec.cpp, kek_op_lock.hpp) — 2037545589 is "yuzu" as big-endian
// ASCII, hashtext() of a descriptive string differentiates the feature.
constexpr const char* kRevokeCoordLockSql =
    "SELECT pg_advisory_xact_lock(2037545589, hashtext('rbac_store:revoke_coordination'))";

// Cross-replica permission-cache coherence (ADR-0041): re-validate the durable
// generation token at most this often on the read hot path.
constexpr std::int64_t kRbacGenerationRefreshMs = 1000;

// Bounded stale-serve (governance re-review, #2703 Gate 7 — operator-adjudicated
// design decision, availability-vs-strictness tradeoff): when a generation
// refresh FAILS (pool timeout, query error — distinct from the gated/in-flight
// case above, which never touches this), keep serving the last-known-good
// cache/enabled-state for up to this long past the last successful refresh
// before dropping trust in it. A refresh failure shorter than this window no
// longer forces perm_cache_ to empty (avoiding a fleet-wide cache-miss storm on
// a short Postgres blip) and no longer flips rbac_enforcement_in_effect() to
// "enforce" for an RBAC-disabled fleet (avoiding a spurious deny-all on a
// fleet that never turned RBAC on). Deliberately several multiples of
// kRbacGenerationRefreshMs: it bounds how stale a cross-replica revocation can
// observably be UNDER DEGRADE ONLY (the ~1s target above is for the healthy
// case), not the routine steady-state latency.
constexpr std::int64_t kRbacStaleServeBoundMs = 5000;

// Fail-fast breaker (#2703 Gate 7 merge-slice item 1 commit B, operator-
// adjudicated: trip fast). 2 consecutive failed pool touches on the authz
// hot path (acquire timeout OR a query error once acquired — e.g. a
// statement cancelled by PgPool's injected lock_timeout, the measured
// table-lock scenario, where the ACQUIRE succeeds and the query itself
// blocks) opens the breaker: every subsequent authz call is denied WITHOUT
// touching the pool until one probe per cooldown succeeds. Deliberately
// small (2, not e.g. 5) — the goal is bounding the FIRST wave's exposure,
// not waiting for a confident failure signal; kAuthzAcquireTimeout above
// bounds a single failed acquire at ~250ms, so trip-fast costs little even on
// a false-positive (one genuinely-slow-but-healthy query). The count is of
// CONSECUTIVE failures: any success on the authz path, including the
// ITServiceOwner ceiling read, resets it (see breaker_note_result).
constexpr int kBreakerTripThreshold = 2;

// Read-degrade reason labels (ADR-0037 convention). A !open_ store fails boot
// closed (never serves), so only the pool-timeout / query-error hot-path
// degrades are counted here.
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
// DENYING: fires only once a failed refresh is past kRbacStaleServeBoundMs
// and the cache is actually cleared (see maybe_refresh_generation). Must
// stay denial-only — YuzuRbacReadDegraded (docs/prometheus/yuzu-alerts.yml)
// is a severity:critical alert whose own design rationale is "never fold in
// a reason that can fire without denying anyone"; that rationale is exactly
// why kReasonRefreshFailedWithinBound below exists as a separate value
// rather than sharing this one (#2703 Gate 7 merge-slice, found during doc
// cross-check: the pre-split single reason violated that same rationale the
// moment the bounded stale-serve window shipped).
constexpr const char* kReasonRefreshFailed = "generation_refresh_failed";
// fjarvis F2 (#2703): the durable rbac_enabled row read back as neither
// exactly "true" nor "false" — see parse_canonical_bool.
constexpr const char* kReasonNonCanonicalFlag = "rbac_enabled_non_canonical";
// fjarvis F3 (#2703): a reader observed the cache past the accepted
// kRbacGenerationRefreshMs bound while a refresh was already in flight — see
// RbacStore::maybe_refresh_generation.
constexpr const char* kReasonStaleBeyondBound = "stale_beyond_accepted_bound";
// OBSERVE-ONLY: a refresh failed but the bounded stale-serve window
// (kRbacStaleServeBoundMs) has not yet elapsed, so the existing cache keeps
// serving unchanged and nothing is denied — early warning only. See
// kReasonRefreshFailed's comment above for why this cannot share that
// reason value.
constexpr const char* kReasonRefreshFailedWithinBound = "generation_refresh_failed_within_bound";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

// ── IdP / engine namespace guards (ported verbatim from the SQLite store) ────

constexpr std::array<std::string_view, 3> kRecognizedIdpSources = {"entra", "saml", "ad"};
constexpr std::string_view kLocalPrefix = "local:";
constexpr std::string_view kEnginePrefix = "engine:";

bool has_reserved_idp_prefix(std::string_view name) {
    if (name.size() >= kLocalPrefix.size() && name.compare(0, kLocalPrefix.size(), kLocalPrefix) == 0)
        return true;
    if (name.size() >= kEnginePrefix.size() &&
        name.compare(0, kEnginePrefix.size(), kEnginePrefix) == 0)
        return true;
    for (auto source : kRecognizedIdpSources) {
        if (name.size() > source.size() && name[source.size()] == ':' &&
            name.compare(0, source.size(), source) == 0)
            return true;
    }
    return false;
}

bool is_blank(std::string_view s) {
    for (unsigned char c : s) {
        if (!std::isspace(c))
            return false;
    }
    return true;
}

constexpr size_t kMaxExternalIdLength = 512;

/// Built-in role names an engine-principal assignment must never receive —
/// `RbacStore::validate_assignment`'s "no admin, ever" bar (design §4.2).
/// EXTEND this set — never fork a second bar elsewhere.
constexpr std::array<std::string_view, 2> kEngineDisallowedRoles = {"admin", "Administrator"};

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

using rbac_sql::to_i64;             // defined in rbac_store_sql_helpers.hpp
using rbac_sql::to_u64;             // defined in rbac_store_sql_helpers.hpp
using rbac_sql::to_bool;            // defined in rbac_store_sql_helpers.hpp
using rbac_sql::parse_canonical_bool; // defined in rbac_store_sql_helpers.hpp

using rbac_sql::text_col; // defined in rbac_store_sql_helpers.hpp

// sanitize_utf8_strict scrubs invalid UTF-8 to U+FFFD but keeps embedded NUL (a
// valid ASCII byte). PostgreSQL TEXT cannot store a NUL and libpq's text-format
// bind C-string-truncates at the first one. So after the UTF-8 scrub, replace
// every NUL with U+FFFD too. Ported verbatim from audit_store.cpp (ADR-0040) —
// applied to every free-text column, INCLUDING the backfill path (a bad byte
// at-rest in a legacy rbac.db must not brick the MANDATORY backfill).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

// ── Read-degrade observability (mirrors AuditStore/InventoryStore) ───────────
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason, DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_server_rbac_read_degrade_total", {{"reason", reason}}).increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

// #2703 Gate 7 merge-slice item 1 commit C: observes on EVERY exit from its
// enclosing scope (regardless of which return statement fires), so a single
// instance at the top of check_permission covers every outcome — cache hit,
// breaker-denied, pool timeout, query error, and success — without touching
// each return site individually. The observe() call runs in the destructor,
// which fires after every `{ std::lock_guard ... }` block in the caller has
// already released, so this never holds cache_mtx_/breaker_mtx_ while
// touching the Histogram's own lock (the same hazard note_read_degrade's
// call sites are already careful about, above).
//
// #2703 Gate 7 item Commit B (cpp-expert + performance, Gate 3 — 2 independent
// reporters): takes a pre-resolved `Histogram*` rather than a
// `MetricsRegistry*` + name pair, so a cache HIT — the common case — no
// longer takes the registry's family-map lock or heap-allocates a
// `std::string` from `metric_name` on every single call. The pointer is
// resolved once by `RbacStore::set_metrics()` (see its doc comment) and
// stays valid for the registry's lifetime; passing null (unwired metrics, the
// default in unit tests) disables observation exactly as before.
class ScopedLatencyObserver {
public:
    explicit ScopedLatencyObserver(yuzu::Histogram* hist)
        : hist_(hist), start_(std::chrono::steady_clock::now()) {}
    ~ScopedLatencyObserver() {
        if (!hist_)
            return;
        const auto elapsed = std::chrono::steady_clock::now() - start_;
        hist_->observe(std::chrono::duration<double>(elapsed).count());
    }
    ScopedLatencyObserver(const ScopedLatencyObserver&) = delete;
    ScopedLatencyObserver& operator=(const ScopedLatencyObserver&) = delete;

private:
    yuzu::Histogram* hist_;
    std::chrono::steady_clock::time_point start_;
};

// ── PostgreSQL schema (ADR-0041): the final column set of the SQLite store's
// four migrations, collapsed into one v1. Migrations v3/v4 were data cleanups
// against a live rbac.db — a fresh PG database needs neither (nothing to clean),
// and backfill copies an already-cleaned legacy DB, so they are not replayed.
// Unqualified DDL — the runner sets search_path to `rbac_store`; runtime
// statements below schema-qualify explicitly. `is_system` is BOOLEAN in PG.
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE securable_types (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   BOOLEAN NOT NULL DEFAULT FALSE
            );

            CREATE TABLE operations (
                id          TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   BOOLEAN NOT NULL DEFAULT FALSE
            );

            CREATE TABLE roles (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   BOOLEAN NOT NULL DEFAULT FALSE,
                created_at  BIGINT NOT NULL DEFAULT 0
            );

            CREATE TABLE role_permissions (
                role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                securable_type  TEXT NOT NULL REFERENCES securable_types(name),
                operation       TEXT NOT NULL REFERENCES operations(id),
                effect          TEXT NOT NULL DEFAULT 'allow',
                PRIMARY KEY (role_name, securable_type, operation)
            );

            CREATE TABLE principal_roles (
                principal_type  TEXT NOT NULL,
                principal_id    TEXT NOT NULL,
                role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                PRIMARY KEY (principal_type, principal_id, role_name)
            );
            CREATE INDEX idx_principal_roles_lookup
                ON principal_roles(principal_type, principal_id);

            CREATE TABLE groups (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                source      TEXT NOT NULL DEFAULT 'local',
                external_id TEXT,
                created_at  BIGINT NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_groups_source ON groups(source);

            CREATE TABLE group_members (
                group_name  TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
                username    TEXT NOT NULL,
                PRIMARY KEY (group_name, username)
            );
            CREATE INDEX idx_group_members_username ON group_members(username);

            -- Durable k/v (ADR-0041): the global `rbac_enabled` flag AND the
            -- cross-replica `write_generation` counter (bumped in the same txn
            -- as every mutation). Also holds the one-time `backfill_complete`/
            -- `backfill_source_fingerprint` rows — their sole writer,
            -- migrate_from_sqlite, was retired (#3623), but v4 below POISONS
            -- rather than deletes them (see that migration's own comment for
            -- why: deleting them is unsafe for THIS store specifically).
            CREATE TABLE rbac_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        )"},
        // NOTE (#2376 task A, and any future securable addition): adding the
        // `EnginePrincipal` securable deliberately did NOT get a migration
        // here. `seed_defaults()` runs unconditionally on every construction
        // and its `types[]` / Viewer-read-loop / Administrator-CRUD inserts
        // are all ON CONFLICT DO NOTHING, so an EXISTING deployment picks up
        // the new securable and its grants on the next boot with no
        // migration at all — the same idempotent-additive-reseed path
        // `AccessReview` and `SoftwareLicensing` used. A migration is needed
        // only when a change cannot be expressed as an idempotent additive
        // re-seed (e.g. deleting rows).
        // fjarvis F2 (#2703): guard rbac_enabled at the schema level too — a
        // hand-edit or a future bug could otherwise write a non-canonical
        // value that the C++-side `parse_canonical_bool()` strict parser
        // would then correctly refuse to trust, but only at READ time
        // (refusing boot / dropping the cache). A CHECK constraint rejects
        // the bad value at WRITE time instead, which is strictly better: the
        // write itself fails loudly rather than silently landing and waiting
        // to be discovered on the next boot or refresh. Scoped to the one
        // key this applies to — every other `rbac_meta` value
        // (`write_generation`, `backfill_complete`, `backfill_source_fingerprint`)
        // is not a boolean and must not be constrained.
        {2, R"(
            ALTER TABLE rbac_meta ADD CONSTRAINT rbac_meta_enabled_canonical
                CHECK (key <> 'rbac_enabled' OR value IN ('true', 'false'));
        )"},
        // fable (Gate 4, #2703): a revoked BUILT-IN DEFAULT permission needs to
        // suppress seed_defaults()'s next reseed WITHOUT ever appearing as a
        // real `role_permissions` row — an earlier round of this fix used an
        // explicit `effect='deny'` tombstone instead, which is a real
        // authorization fact and inherits check_permission()/
        // check_scoped_permission()/authorize_list_read()'s pre-existing
        // "deny overrides everything, across ALL of a principal's held
        // roles" semantics. That silently changed the authorization OUTCOME
        // for any principal holding a second role that independently grants
        // the same (securable_type, operation) — legacy's plain DELETE never
        // created a deny row, so legacy computed ALLOW there; the tombstone
        // computes DENY. This table separates "reseed bookkeeping" from
        // "operator-authored authorization fact": it is consulted ONLY by
        // seed_defaults()'s grant() and by remove_permission()/the backfill's
        // equivalent cleanup, and is NEVER read by any authorization-decision
        // code path (check_permission, check_scoped_permission,
        // get_effective_permissions, role_effects_for, authorize_list_read,
        // holds_permission_via_any_group) — role_permissions absence goes
        // back to meaning exactly what it meant in the legacy store: this
        // role grants nothing for this (type, op), full stop, and other
        // roles' independent grants are untouched.
        // Same FK shape as role_permissions (deliberately — an unrecognized
        // role/type/op must still fail remove_permission() outright, and a
        // deleted CUSTOM role's stray markers should not linger forever;
        // system roles, the only ones seed_defaults() ever consults this
        // table for, can never be deleted).
        {3, R"(
            CREATE TABLE revoked_seed_defaults (
                role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                securable_type  TEXT NOT NULL REFERENCES securable_types(name),
                operation       TEXT NOT NULL REFERENCES operations(id),
                PRIMARY KEY (role_name, securable_type, operation)
            );
        )"},
        // migrate_from_sqlite() retired (#3623, ADR-0041 Update) — backfill_complete /
        // backfill_source_fingerprint were its sole idempotency markers, stored as ROWS in
        // rbac_meta rather than a dedicated table (rbac_enabled/write_generation live in the
        // same table and are NOT touched). Appended at the next free slot, never renumbering
        // v1-v3 (PgMigrationRunner applies only version > current — renumbering an
        // already-shipped version re-applies it against a database that already ran it).
        //
        // POISONS, does NOT delete, the two marker rows -- unlike the other 5 retired stores
        // (CaStore/ManagementGroupStore/QuarantineStore/InventoryStore/WebhookStore), whose
        // marker is a whole TABLE a DROP removes entirely. Deleting these ROWS from a table
        // that otherwise stays live (rbac_meta) is unsafe specifically for RbacStore: a
        // pre-#3623 binary's own migrate_from_sqlite() (deleted from THIS codebase, but still
        // the one running on any replica rolled back to an older release) treats marker ABSENCE
        // as "never migrated" and falls through past its own fingerprint-verification safety
        // net straight into an UNCONDITIONAL overwrite of the live rbac_enabled flag from
        // whatever a local legacy rbac.db file's rbac_config.enabled column holds --
        // `INSERT ... ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, no gate. The
        // other 5 stores don't have this failure mode: an old binary's marker SELECT against a
        // DROPped table fails outright (42P01) and that binary refuses to boot -- a loud
        // outage, the accepted risk class this whole retirement already takes on (PR #3898
        // precedent). Deleting these two rows instead reproduced a SILENT one: RBAC could be
        // disabled (or unexpectedly re-enabled) fleet-wide with no error, on any replica that
        // still has a legacy rbac.db sitting at its configured path un-migrated on its OWN
        // local disk -- realistic on a multi-replica deployment (each replica has its own
        // db_dir) if one replica rolls back, or a fresh/volume-reset replica joins a fleet
        // whose Postgres has already run v4. Governance unhappy-path caught this (2026-09-03).
        //
        // The fix: force backfill_source_fingerprint to the EXACT literal the retired (pre-#3623)
        // code compared against for its own "no real source" sentinel -- `kSourcelessFingerprint
        // = "sourceless"`, verified via `git show e2f745606:server/core/src/rbac_store.cpp`; that
        // constant no longer exists in THIS codebase, only in whatever old binary might roll
        // back -- rather than deleting the row. An old binary rolling back then
        // sees marker_present=true and takes its own existing fail-closed branches: no local
        // legacy file -> returns immediately, silent, safe (the ordinary case, matching every
        // other store); a local legacy file WITH real content -> refuses to auto-migrate
        // ("no legacy rbac.db has been migrated for this fleet yet... refusing"), the same loud
        // outage the other 5 stores already accept, never the silent overwrite. backfill_complete
        // only needs to exist (old code checks presence, never reads its value).
        {4, "INSERT INTO rbac_meta (key, value) VALUES "
            "('backfill_complete', 'retired-see-adr-0041-update-2026-09-03') "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;"
            "INSERT INTO rbac_meta (key, value) VALUES "
            "('backfill_source_fingerprint', 'sourceless') "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;"},
    };
    return kMigrations;
}

} // namespace

std::string namespaced_group_name(const std::string& source, const std::string& external_id) {
    if (source == "local")
        return external_id;
    return source + ":" + external_id;
}

// ── Construction / teardown ──────────────────────────────────────────────────

RbacStore::RbacStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("RbacStore: no database connection at construction ({}) — authorization "
                      "substrate disabled (fail-closed: every authz read will DENY)",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("RbacStore: schema migration failed — authorization substrate disabled "
                      "(fail-closed)");
        return;
    }
    lease.reset(); // seed_defaults/load_enabled_flag re-acquire their own leases
    open_ = true;
    seed_defaults();
    // load_enabled_flag() is now fail-closed: if the durable rbac_enabled /
    // write_generation rows can't be read (lease/query error or absent — a
    // failed seed also lands here), it returns false and we refuse to serve
    // rather than boot RBAC-off on a fleet that enabled it (Gate 2 CRITICAL /
    // Gate 4 R1). is_open()==false → server sets startup_failed_ and refuses boot.
    if (!load_enabled_flag()) {
        open_ = false;
        return;
    }
    spdlog::info("RbacStore initialized (schema {})", kStoreName);
}

RbacStore::~RbacStore() = default;

void RbacStore::set_metrics(yuzu::MetricsRegistry* m) noexcept {
    metrics_ = m;
    // See the doc comment on the declaration for why this is resolved once
    // here rather than cached as a function-local static. The buckets
    // overload is idempotent with server.cpp's own zero-seed call — whichever
    // runs first fixes the series' boundaries (Prometheus semantics), and
    // both request the same extended buckets, so call order doesn't matter.
    authz_check_seconds_hist_ =
        m ? &m->histogram("yuzu_server_rbac_authz_check_seconds", yuzu::Histogram::seconds_buckets_60s())
          : nullptr;
    // A1: publish the enforcement gauge now that a registry is wired — the
    // store is constructed and loads the durable flag (load_enabled_flag())
    // BEFORE set_metrics() is ever called, so this is what makes the series
    // present from boot rather than only after the first toggle/refresh.
    publish_enforcement_gauge();
}

// ── Seed data (idempotent — ON CONFLICT DO NOTHING) ──────────────────────────

void RbacStore::seed_defaults() {
    if (!open_)
        return;
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("RbacStore: seed_defaults: no connection ({})", pool_.last_error());
        return;
    }
    PGconn* c = lease.get();

    const auto exec = [&](const char* sql,
                          const std::vector<std::string>& params = {}) -> bool {
        pg::PgResult r = pg::exec_params(c, sql, params);
        if (!r.ok()) {
            spdlog::error("RbacStore: seed_defaults statement failed: {}", PQerrorMessage(c));
            return false;
        }
        return true;
    };

    // Durable meta defaults — never clobber a migrated value (DO NOTHING),
    // so this literal ONLY ever takes effect on a database that has never
    // run this code before (a genuine fresh install) — an existing
    // install's row is already written and untouched by this INSERT.
    // Still 'false' here: main.cpp's fresh-start bootstrap
    // (`RbacStore::provision_first_admin`, the sole production seeder)
    // already guarantees a fresh install's first operator ends up with a
    // durable Administrator grant before the server ever starts serving,
    // so flipping this literal to 'true' would
    // be MECHANICALLY safe on its own — but a large, separately-scoped
    // swath of the existing test suite implicitly depends on a freshly
    // constructed RbacStore seeding 'false' (rather than setting the flag
    // explicitly), and bringing that suite up to date is deliberately
    // deferred to a follow-up change rather than riding along here. See
    // docs/adr/1008-rbac-management-groups-target-architecture.md's
    // fresh-install bootstrap delivery note for what is and is not shipped
    // in this delivery.
    exec("INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('rbac_enabled','false') "
         "ON CONFLICT (key) DO NOTHING");
    exec("INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('write_generation','0') "
         "ON CONFLICT (key) DO NOTHING");

    // Securable types.
    const std::array<std::string_view, 38> types = {
        "Infrastructure",  "UserManagement",  "InstructionDefinition",
        "InstructionSet",  "Execution",       "Schedule",
        "Approval",        "Tag",             "AuditLog",
        "Response",        "ManagementGroup", "ApiToken",
        "Security",        "Policy",          "DeviceToken",
        "SoftwareDeployment", "License",      "FileRetrieval",
        "GuaranteedState", "Inventory",       "AccessReview",
        // #2376 (task A) — engine-principal INVENTORY + grant-graph reads
        // (list/get engine principals, list their fleet-wide roles) cut away
        // from the over-broad Security:Read, which also gates unrelated
        // operational reads (quarantine visibility, CA issued-certs, KEK
        // status) that a follow-up change floors to admin-only when RBAC is
        // disabled — flooring all of Security:Read would sweep those in too.
        // Seeded to Administrator (CRUD via the loop below) + Viewer (Read,
        // below) — the same two roles that reached the migrated routes via
        // Security:Read before this cut.
        "SoftwareLicensing", "EnginePrincipal",
        // PR1.5/1.6 (ADR-3005/ADR-3004 operator surface): the plugin
        // config/secret/kill-switch plane and the upload-grant lifecycle.
        "PluginConfig",   // plugin kill-switch config (PluginConfig:Write)
        "PluginSecret",   // plugin secret material — never Operator-readable
        "UploadGrant",    // upload-grant mint/revoke lifecycle
        // Wave 6 W1B: power_health's set_power_plan (the plugin's only
        // mutating action). Administrator-only via the CRUD loop below —
        // same PluginConfig/UploadGrant precedent, deliberately absent from
        // the explicit Viewer read-list further down this function.
        "PowerManagement",
        // #4030/#4032: WorkflowEngine's multi-step-orchestration securable.
        // `workflow_routes.cpp` has gated `GET/POST/DELETE /api/workflows*`
        // + `POST .../execute` on `perm_fn(req, res, "Workflow", <op>)`
        // since WorkflowEngine's introduction, but "Workflow" was never
        // added here (or mirrored into mcp_server.cpp's `kRbacSecurables[]`)
        // — `securable_types` carries no FK from `role_permissions`, so a
        // `grant(role, "Workflow", op)` call silently inserted a row naming
        // a type RBAC's own catalogue didn't recognise: no role, including
        // Administrator, could ever be granted Workflow:* while RBAC was
        // enabled. Scoped to Workflow ONLY — the identical bug also exists
        // on ProductPack/Directory (tracked generally by #4032), fixed
        // independently by #4029/#4031 in their own worktrees to avoid a
        // cross-worktree merge conflict on this shared array.
        "Workflow",
        // #4029 prerequisite fix: `ProductPack` is used as an RBAC securable
        // string by the already-shipped `/api/product-packs*` routes
        // (workflow_routes.cpp, `perm_fn(req, res, "ProductPack", "Read"/
        // "Write"/"Delete")`) but was never seeded here or into
        // mcp_server.cpp's `kRbacSecurables[]` mirror — `role_permissions.
        // securable_type` carries a hard FK to `securable_types(name)`, so no
        // role, not even Administrator, could ever be granted ProductPack:*
        // while RBAC is enabled. Administrator gets full CRUD for free via
        // the types-loop below; Read is additionally granted to Operator/
        // PlatformEngineer/Viewer further down (the same population that
        // already holds InstructionDefinition:Read) — Write/Delete stay
        // Administrator-only, matching the issue's scoped ask.
        "ProductPack",
        // #4028 (api-parity programme #2146) — Settings read-twins, split
        // along sensitivity lines rather than one blanket Settings:Read
        // (per the issue's own scoping note). All four are Administrator-
        // only via the CRUD loop below, deliberately absent from every
        // other role's explicit grant list further down (incl. Viewer's
        // blanket read-list) — matching today's admin_fn_-only gate on the
        // 8 /fragments/settings/* routes this PR twins. Every (securable,
        // "Read") pair here is ALSO added to authz_topology_floor.hpp's
        // kTopologyFloor[], so an RBAC-off deployment stays admin-gated
        // instead of silently widening to any authenticated user.
        "TlsConfig",       // TLS + HTTPS listener config (tls/https fragments)
        "PluginSigning",   // plugin code-signing trust bundle (distinct from
                           // PluginConfig, which gates per-plugin runtime
                           // kill-switch config — a different domain)
        "ServerConfig",    // gateway/server-config/mcp/data-retention fragments
        "AnalyticsConfig", // analytics fragment (ClickHouse integration)
        // #4031 prerequisite 1: "Directory" is called at discovery_routes.cpp
        // (perm_fn(..., "Directory", "Read"/"Write")) but was NEVER seeded
        // here — role_permissions.securable_type has a hard FK to
        // securable_types(name), so no role, including Administrator, could
        // ever be granted Directory:Read/Write. Seeded to Administrator (CRUD
        // via the loop below) + Viewer (Read, below) — same precedent as
        // UserManagement (also PII-bearing identity data; Operator/
        // PlatformEngineer deliberately do NOT get it, narrower than the
        // Inventory/SoftwareLicensing fleet-metadata pattern since this is
        // AD/Entra-synced email/UPN/group-membership PII, not device
        // inventory). Scoped to ONLY this securable — the identical bug on
        // ProductPack/Workflow is #4029/#4030's job, not this PR's (#4032
        // tracks the general pattern).
        "Directory",
        // #4031 routes 3-4 (auto-approve rules + pending-agent visibility):
        // previously admin_fn_-gated (a role check, not RBAC), so no
        // securable existed at all. Read granted to Administrator ONLY via
        // the CRUD loop below, matching today's admin-only gate — see
        // authz_topology_floor.hpp for why this pair must ALSO be floored so
        // RBAC-off doesn't silently widen admin-only to any-authenticated-user.
        "Enrollment",
        // #4031 route 5 (OIDC SSO config read, GET /fragments/settings/directory
        // despite the path). Deliberately NOT named "Directory" — that would
        // collide with the AD/Entra directory-sync securable seeded above for
        // a wholly unrelated capability (the naming trap the issue calls out).
        // Read granted to Administrator ONLY, same admin-only-gate parity and
        // same topology-floor requirement as Enrollment above.
        "OidcConfig",
        // Wave 7 forensics class: execution_artifacts, app_usage, later
        // shell_history/yara_scan. Administrator CRUD via the loop below;
        // deliberately ABSENT from the Viewer read-list.
        "Forensics",
        // Wave 7 PR7.2: the device-level securable ADR-0024 Decision 9
        // promoted when the erasure gate's conjunction reached a fourth
        // securable (app_usage_store, Forensics). `Decommission:Delete` is
        // the ONLY consumed operation (the DELETE /sle/agents/{id} cascade,
        // sle_routes.cpp); Administrator gets CRUD via the loop (the
        // PowerManagement/PluginConfig precedent — unused ops are harmless
        // and keep the loop uniform); ITServiceOwner gets a TARGETED
        // Decommission:Delete grant below (see that grant's comment).
        "Decommission"
    };
    for (auto t : types)
        exec("INSERT INTO rbac_store.securable_types (name, is_system) VALUES ($1, TRUE) "
             "ON CONFLICT (name) DO NOTHING",
             {std::string(t)});
    // R18 (ADR-0024 Decision 9): defuse the SoftwareLicensing name (does NOT
    // gate the /inventory catalog). Set only when empty — never clobber an
    // operator-set value.
    exec("UPDATE rbac_store.securable_types SET description = "
         "'gates the /api/v1/sle/* detected-licence reads and the agent-decommission erasure; "
         "the /inventory software catalog remains under Inventory:Read' "
         "WHERE name = 'SoftwareLicensing' AND description = ''");
    // Wave 7 PR7.2: describe the Decommission securable — set only when
    // empty, same shape as the SoftwareLicensing UPDATE above.
    exec("UPDATE rbac_store.securable_types SET description = "
         "'gates the whole-device erasure cascade behind DELETE "
         "/api/v1/sle/agents/{id}; per-device scoped; Delete is the only "
         "consumed operation' "
         "WHERE name = 'Decommission' AND description = ''");

    // Operations. "Rotate" (dev P2 #11, SOC 2 CC6.3, merged from origin/dev):
    // ApiToken-specific self-service rotation
    // (ApiTokenStore::rotate_token/confirm_token_rotation). Same treatment as
    // Push/Attest below — a first-class operation, deliberately EXCLUDED from
    // crud_ops so no cross-type loop ever widens it onto an unrelated
    // securable, and deliberately distinct from ApiToken's own "Write": a
    // security-critical round on dev found that reusing Write to admit the
    // MCP rotation tools at the operator tier silently widened every OTHER
    // ApiToken:Write route/tool too (mcp_policy.hpp's tier_allows()
    // operator-tier comment is the narrative home for that finding). Granted
    // below to Administrator and ApiTokenManager only — the SAME population
    // that already holds ApiToken:Write.
    const std::array<std::string_view, 8> ops = {"Read",  "Write", "Execute", "Delete",
                                                 "Approve", "Push", "Attest",  "Rotate"};
    for (auto o : ops)
        exec("INSERT INTO rbac_store.operations (id, is_system) VALUES ($1, TRUE) "
             "ON CONFLICT (id) DO NOTHING",
             {std::string(o)});
    const std::array<std::string_view, 5> crud_ops = {"Read", "Write", "Execute", "Delete",
                                                      "Approve"};

    const std::int64_t now = now_secs();

    struct RoleSeed {
        std::string_view name;
        std::string_view desc;
    };
    const std::array<RoleSeed, 7> roles = {
        RoleSeed{"Administrator", "Full access to all operations"},
        {"PlatformEngineer", "Author and manage YAML instruction definitions, sets, and schemas"},
        {"Operator", "Execute and manage instructions, schedules, and tags"},
        {"ApiTokenManager", "Create, revoke, and manage API tokens for programmatic access"},
        {"ITServiceOwner", "Admin control over devices tagged with the same IT Service"},
        {"Viewer", "Read-only access to operational data"},
        {"Reviewer", "Read audit evidence and attest/flag access-review grants (SOC 2 CC6.2)"}};
    for (const auto& r : roles)
        exec("INSERT INTO rbac_store.roles (name, description, is_system, created_at) "
             "VALUES ($1, $2, TRUE, $3::bigint) ON CONFLICT (name) DO NOTHING",
             {std::string(r.name), std::string(r.desc), std::to_string(now)});

    // fable (Gate 4, #2703): skip a triple an operator explicitly revoked via
    // remove_permission() — revoked_seed_defaults is bookkeeping-only (never
    // read by any authorization decision), so this is the ONLY place its
    // absence-suppression takes effect. A re-grant via set_permission()
    // recreates the role_permissions row directly and does not touch this
    // table; the (now-redundant, harmless) marker just means a future
    // seed_defaults() no-ops against an already-restored row either way.
    // chaos-injector (Gate 5, #2703, HIGH — CHAOS-1): the lock MUST be its own
    // statement, in its own explicit transaction, strictly before the
    // check-and-insert — see kRevokeCoordLockSql's comment for why a CTE in
    // the same statement does not work. Each grant() call gets its own
    // mini-transaction rather than wrapping the whole seed_defaults() pass:
    // every other statement here stays a fire-and-forget auto-commit
    // (existing, deliberate — a single failed seed statement must not abort
    // the rest of the reseed), and this preserves that for grant() too.
    const auto grant = [&](std::string_view role, std::string_view type, std::string_view op) {
        if (!exec("BEGIN"))
            return;
        pg::PgTxn txn(c);
        if (!exec(kRevokeCoordLockSql))
            return; // txn destructor rolls back
        // security-guardian (Gate 8, #2703): check the INSERT's result before
        // committing, matching the UP-3 discipline PgPool::run_in_txn enforces
        // centrally for every OTHER write path in this store — a failed
        // statement must not be followed by commit() (PgTxn::commit() on an
        // aborted transaction still returns PGRES_COMMAND_OK while silently
        // performing a rollback; calling it unconditionally would have been
        // correct-by-accident, not by contract).
        if (!exec("INSERT INTO rbac_store.role_permissions (role_name, securable_type, "
                  "operation, effect) SELECT $1, $2, $3, 'allow' WHERE NOT EXISTS ("
                  "  SELECT 1 FROM rbac_store.revoked_seed_defaults "
                  "  WHERE role_name = $1 AND securable_type = $2 AND operation = $3"
                  ") ON CONFLICT DO NOTHING",
                  {std::string(role), std::string(type), std::string(op)}))
            return; // txn destructor rolls back
        txn.commit();
    };

    // Administrator: CRUD on everything + targeted Push + Attest + Rotate
    // (Rotate merged from origin/dev, P2 #11 — same targeted-grant treatment
    // as Push/Attest, see the "Rotate" catalogue comment above).
    for (auto t : types)
        for (auto o : crud_ops)
            grant("Administrator", t, o);
    grant("Administrator", "GuaranteedState", "Push");
    grant("Administrator", "AccessReview", "Attest");
    grant("Administrator", "ApiToken", "Rotate");

    // PlatformEngineer.
    for (std::string_view t : {"InstructionDefinition", "InstructionSet"})
        for (std::string_view o : {"Read", "Write", "Execute", "Delete"})
            grant("PlatformEngineer", t, o);
    for (std::string_view t : {"Execution", "Schedule", "Approval", "Tag", "AuditLog", "Response",
                               "SoftwareLicensing", "Inventory",
                               // #4030: Workflow — read-only, matching Schedule's footprint. Not
                               // added to the InstructionDefinition/InstructionSet CRUD loop above:
                               // the issue scopes this prerequisite to granting Read only.
                               "Workflow",
                               // #4029: read visibility on installed product packs, matching the
                               // existing InstructionDefinition:Read population's consistency.
                               "ProductPack"})
        grant("PlatformEngineer", t, "Read");
    for (std::string_view o : {"Read", "Write", "Delete"})
        grant("PlatformEngineer", "Policy", o);
    for (std::string_view o : {"Read", "Write", "Delete", "Push"})
        grant("PlatformEngineer", "GuaranteedState", o);
    // PR1.5/1.6: PlatformEngineer manages the plugin config/secret plane and
    // the upload-grant lifecycle (no Execute exists on any of the three).
    for (std::string_view t : {"PluginConfig", "PluginSecret", "UploadGrant"})
        for (std::string_view o : {"Read", "Write", "Delete"})
            grant("PlatformEngineer", t, o);

    // Operator.
    for (std::string_view t : {"InstructionDefinition", "InstructionSet", "Execution", "Schedule",
                               "Tag"}) {
        for (std::string_view o : {"Read", "Write", "Execute", "Delete"})
            grant("Operator", t, o);
    }
    grant("Operator", "Approval", "Read");
    grant("Operator", "Approval", "Approve");
    grant("Operator", "AuditLog", "Read");
    grant("Operator", "Response", "Read");
    grant("Operator", "Policy", "Read");
    grant("Operator", "Policy", "Execute");
    grant("Operator", "SoftwareDeployment", "Read");
    grant("Operator", "SoftwareDeployment", "Execute");
    grant("Operator", "DeviceToken", "Read");
    grant("Operator", "License", "Read");
    grant("Operator", "Inventory", "Read");
    grant("Operator", "SoftwareLicensing", "Read");
    grant("Operator", "SoftwareLicensing", "Write");
    grant("Operator", "FileRetrieval", "Read");
    grant("Operator", "FileRetrieval", "Write");
    grant("Operator", "GuaranteedState", "Read");
    grant("Operator", "GuaranteedState", "Push");
    // #4029: read visibility on installed product packs.
    grant("Operator", "ProductPack", "Read");
    // PR1.5/1.6: read visibility only — config and grant LIFECYCLE stay
    // privileged operations, and PluginSecret is deliberately absent here
    // (secret material is never Operator-readable).
    grant("Operator", "PluginConfig", "Read");
    grant("Operator", "UploadGrant", "Read");
    // #4030: Workflow — read-only (the issue's prerequisite scopes this fix to
    // granting Read; not added to the CRUD loop above, unlike Schedule/Execution).
    grant("Operator", "Workflow", "Read");

    // ApiTokenManager. "Rotate" merged from origin/dev (P2 #11, SOC 2 CC6.3
    // — self-service human token rotation; same population that already
    // holds Write).
    for (std::string_view o : {"Read", "Write", "Delete", "Rotate"})
        grant("ApiTokenManager", "ApiToken", o);

    // ITServiceOwner.
    for (std::string_view t : {"Infrastructure", "InstructionDefinition", "InstructionSet",
                               "Execution", "Schedule", "Approval", "Tag", "AuditLog", "Response",
                               "ManagementGroup", "Policy", "DeviceToken", "SoftwareDeployment",
                               "License", "FileRetrieval", "GuaranteedState", "Inventory",
                               "SoftwareLicensing"}) {
        for (auto o : crud_ops)
            grant("ITServiceOwner", t, o);
    }
    grant("ITServiceOwner", "GuaranteedState", "Push");
    // #4030: Workflow — read-only (issue's prerequisite scope is Read only; not
    // added to the CRUD loop above, unlike Schedule/Execution).
    grant("ITServiceOwner", "Workflow", "Read");
    // Wave 7 PR7.2: preserves the SEEDED population that could decommission
    // under the old SoftwareLicensing∧Inventory∧GuaranteedState:Delete
    // conjunction (ITSO held CRUD on all three above) — scoped per-device
    // by the route's gate as before. Deliberately NOT in the ITSO crud_ops
    // list above: Read/Write/Execute/Approve on Decommission are
    // meaningless — do not widen.
    //
    // Adversarial review finding: grant()'s revoked_seed_defaults check only
    // matches the EXACT (role, securable, operation) triple, and
    // Decommission:Delete never existed before this migration, so an
    // operator who had revoked ANY of the three OLD conjunct grants
    // specifically to strip ITServiceOwner's decommission ability would
    // otherwise regain it silently the moment this seed runs. Carry that
    // prior intent forward onto the new securable BEFORE calling grant():
    // if any of the three old grants is recorded revoked for
    // ITServiceOwner, record the SAME revocation against Decommission:Delete
    // and — critically — also DELETE any role_permissions row already
    // granted for it. Round 1's fix inserted only the marker: on an
    // UPGRADING replica, seed_defaults() had already run once before this
    // block existed (or runs the CRUD/targeted-grant sequence earlier in
    // THIS same pass, above), so a Decommission:Delete row can already be
    // present in role_permissions — grant()'s `WHERE NOT EXISTS` guard only
    // stops a FUTURE (re-)insert, it does not retroactively strip a row
    // that's already there. Mirror remove_permission()'s own marker+DELETE
    // pair exactly (same rationale: a hard DELETE with a separate bookkeeping
    // marker, never a fabricated 'deny' row — see remove_permission()'s own
    // comment for why) rather than relying on grant()'s guard alone.
    //
    // Governance round 5 (Blocker 1): the marker-insert + DELETE pair above
    // used to run unconditionally on EVERY seed_defaults() call (every server
    // boot), gated only on the marker's presence — never on whether the row
    // had since been explicitly RE-GRANTED by an operator via set_permission()
    // (which writes role_permissions directly and never touches
    // revoked_seed_defaults). Reproduced: revoke an old grant -> first boot
    // carries the marker forward and deletes the row (correct, one-time
    // migration) -> operator explicitly re-grants Decommission:Delete ->
    // next restart's seed_defaults() deleted the just-re-granted row again,
    // because the DELETE's only gate was "does the marker exist", and the
    // marker is permanent bookkeeping, not a one-shot flag.
    //
    // The carry-forward is a MIGRATION, not a standing invariant. Detect
    // "already migrated" the same way the rest of this file treats one-time
    // state (schema_meta-style: presence of the marker row IS the completion
    // flag) — probe for the marker BEFORE inserting it, and only run the
    // insert+DELETE pair when it is not yet present. On the common
    // no-prior-revocation install this WHERE EXISTS clause is always false,
    // so the marker row is never inserted and the whole probe/insert/delete
    // sequence re-runs as a harmless no-op on EVERY boot, not once — "fires
    // exactly once" describes only the revoked-conjunction install, not the
    // ordinary case (governance Gate 4 happy-path finding). Once the marker
    // DOES exist (the revoked-conjunction install), grant()'s own `WHERE NOT
    // EXISTS` guard is what keeps suppressing a FUTURE reseed of a row an
    // operator explicitly removed; it does not care about the marker's age,
    // so it stays correct with the DELETE gone.
    // Governance round 6: the marker-presence probe below used to conflate a
    // query FAILURE (transient PG connection/timeout error) with genuine
    // ABSENCE — both left `decommission_marker_present == false`, silently
    // re-entering the insert+DELETE branch on a boot that merely hit a PG
    // hiccup, which reopens round 5's exact bug on a narrower trigger. A
    // failed probe must SKIP this migration attempt for the current boot
    // (logged, like every other statement in this function), never be
    // read as "not yet migrated, do the migration."
    //
    // Adversarial review Wave 7 PR7.2b fix round 1 (third instance of this
    // fail-open class, after rounds 5/6 above): the probe, the marker
    // INSERT, and the permission DELETE used to run as three SEPARATE
    // autocommit statements outside any lock, with the INSERT/DELETE bool
    // results discarded entirely. A transient failure between the marker
    // INSERT and the permission DELETE durably recorded "migration
    // complete" via the marker while silently failing to honor the
    // operator's revocation — grant()'s WHERE NOT EXISTS guard then saw the
    // marker and skipped re-inserting, so the pre-migration grant the
    // operator revoked survived, unrevoked, with no error anywhere. Now one
    // transaction under kRevokeCoordLockSql (the SAME lock grant()/
    // remove_permission() take for this identical revoke/grant coherence
    // problem — see that constant's own comment), every statement's result
    // checked, and the trailing grant() call runs ONLY once this boot's
    // attempt was decisive (committed, whether or not there was anything to
    // carry forward) — never after an ambiguous partial failure.
    bool decommission_migrated = false;
    if (exec("BEGIN")) {
        pg::PgTxn txn(c);
        if (exec(kRevokeCoordLockSql)) {
            pg::PgResult marker = pg::exec_params(
                c,
                "SELECT 1 FROM rbac_store.revoked_seed_defaults WHERE role_name = "
                "'ITServiceOwner' AND securable_type = 'Decommission' AND operation = 'Delete'",
                std::vector<std::string>{});
            if (marker.status() != PGRES_TUPLES_OK) {
                spdlog::error(
                    "RbacStore: seed_defaults Decommission carry-forward probe failed: {}",
                    PQerrorMessage(c));
            } else if (PQntuples(marker.get()) > 0) {
                decommission_migrated = true; // already migrated on an earlier boot
            } else if (exec("INSERT INTO rbac_store.revoked_seed_defaults (role_name, "
                            "securable_type, operation) SELECT 'ITServiceOwner', "
                            "'Decommission', 'Delete' WHERE EXISTS ("
                            "  SELECT 1 FROM rbac_store.revoked_seed_defaults WHERE role_name = "
                            "'ITServiceOwner' AND "
                            "  ((securable_type = 'SoftwareLicensing' AND operation = 'Delete') "
                            "OR "
                            "   (securable_type = 'Inventory' AND operation = 'Delete') OR "
                            "   (securable_type = 'GuaranteedState' AND operation = 'Delete'))"
                            ") ON CONFLICT DO NOTHING") &&
                      exec("DELETE FROM rbac_store.role_permissions WHERE role_name = "
                          "'ITServiceOwner' AND "
                          "securable_type = 'Decommission' AND operation = 'Delete' AND EXISTS ("
                          "  SELECT 1 FROM rbac_store.revoked_seed_defaults WHERE role_name = "
                          "'ITServiceOwner' AND "
                          "  securable_type = 'Decommission' AND operation = 'Delete'"
                          ")")) {
                // Succeeds (as valid, zero-or-one-row SQL statements) whether
                // or not an old revocation actually existed to carry forward
                // -- the WHERE EXISTS clauses correctly no-op either way, so
                // reaching here always means this boot's attempt is decisive.
                decommission_migrated = true;
            }
            // Reassign, don't just call: `commit()` can itself fail (e.g. a
            // connection loss at exactly the COMMIT statement) even after
            // every preceding statement succeeded (governance Gate 3
            // cpp-safety finding) -- PQexec("COMMIT") returning anything but
            // PGRES_COMMAND_OK means the txn destructor's ROLLBACK is what
            // actually ran, so `decommission_migrated` must reflect that or
            // the trailing grant() below runs unconditionally on a migration
            // that never durably committed.
            if (decommission_migrated)
                decommission_migrated = txn.commit();
            // else: probe, insert, delete, or commit failed -- txn
            // destructor rolls back everything (including a lock-only
            // transaction with no writes); decommission_migrated stays
            // false either way.
        }
    }
    if (decommission_migrated)
        grant("ITServiceOwner", "Decommission", "Delete");
    else
        spdlog::warn("RbacStore: seed_defaults Decommission carry-forward not migrated this "
                    "boot; ITServiceOwner Decommission:Delete grant deferred, will retry next "
                    "boot");

    // Viewer: read on all except Infrastructure.
    // #2376 (task A) — Viewer held Security:Read (the only non-Administrator
    // role that did), so it keeps equivalent access on the new
    // EnginePrincipal securable.
    // #4031: Directory (AD/Entra-synced user/group PII) joins on the same
    // reasoning as UserManagement just above it — both are identity data,
    // and Viewer already reads UserManagement. Enrollment/OidcConfig
    // deliberately do NOT join this list — see their seeding comment in
    // types[] above ("Administrator ONLY, matching today's admin-only gate").
    for (std::string_view t : {"UserManagement", "Directory", "InstructionDefinition",
                               "InstructionSet", "Execution", "Schedule", "Approval", "Tag",
                               "AuditLog", "Response", "ManagementGroup", "ApiToken", "Security",
                               "Policy", "DeviceToken", "SoftwareDeployment", "License",
                               "FileRetrieval", "GuaranteedState", "Inventory",
                               "SoftwareLicensing", "EnginePrincipal",
                               "Workflow", // #4030: read-only, matching Schedule's footprint.
                               // #4029: read visibility on installed product packs.
                               "ProductPack"})
        grant("Viewer", t, "Read");

    // Reviewer.
    grant("Reviewer", "AccessReview", "Read");
    grant("Reviewer", "AccessReview", "Attest");
}

bool RbacStore::load_enabled_flag() {
    if (!open_)
        return false;
    auto lease = pool_.acquire();
    if (!lease) {
        // CRITICAL fail-closed (Gate 2 security / Gate 4 R1): we could NOT read
        // the durable rbac_enabled flag. Leaving `rbac_enabled_` at its ctor
        // default (false) while `open_` stays true would serve a fleet that had
        // ENABLED RBAC with RBAC OFF — authorize_list_read → AdmitAll, a
        // fleet-wide confined-operator bypass. Refuse boot instead; the next
        // start retries. NEVER default-to-enabled either (that would break the
        // legitimate RBAC-off fresh install) — refuse-boot is the only safe
        // posture when the authoritative flag is unreadable.
        spdlog::error("RbacStore: could not acquire a connection to read the durable rbac_enabled "
                      "flag ({}) — refusing to start rather than risk serving RBAC-off on a fleet "
                      "that enabled it (fail-closed)",
                      pool_.last_error());
        return false;
    }
    pg::PgResult r = pg::exec_params(
        lease.get(), "SELECT value FROM rbac_store.rbac_meta WHERE key='rbac_enabled'",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1) {
        // The row is seeded by the migration/seed_defaults (and read-back-verified
        // by the backfill), so a query error OR a missing row means the durable
        // flag is unreadable/absent — fail closed, same reasoning as above.
        spdlog::error("RbacStore: durable rbac_enabled flag is unreadable/absent (status={}) — "
                      "refusing to start (fail-closed)",
                      static_cast<int>(r.status()));
        return false;
    }
    // fjarvis F2 (#2703): the row EXISTS and the query succeeded, so the
    // branch above doesn't fire — but a value that isn't exactly "true" or
    // "false" (a hand-edit, corruption, a future writer using a different
    // convention) previously coerced silently to false via `== "true"`. That
    // is boot-succeeds-RBAC-off on a fleet that enabled it — the same
    // fail-open class the branch above exists to close, one level down.
    // Treat a non-canonical value identically: refuse to start.
    const auto enabled_parsed = parse_canonical_bool(text_col(r.get(), 0, 0));
    if (!enabled_parsed) {
        spdlog::error("RbacStore: durable rbac_enabled flag holds a non-canonical value "
                      "(expected exactly \"true\" or \"false\") — refusing to start "
                      "(fail-closed; coercing an unrecognised value to false would silently "
                      "disable RBAC on a fleet that enabled it)");
        return false;
    }
    rbac_enabled_.store(*enabled_parsed, std::memory_order_relaxed);
    // Anchor the generation cache from the durable counter so the first read
    // does not immediately re-query. This row is likewise init-guaranteed.
    pg::PgResult g = pg::exec_params(
        lease.get(), "SELECT value FROM rbac_store.rbac_meta WHERE key='write_generation'",
        std::vector<std::string>{});
    if (g.status() != PGRES_TUPLES_OK || PQntuples(g.get()) != 1) {
        spdlog::error("RbacStore: durable write_generation is unreadable/absent — refusing to "
                      "start (fail-closed)");
        return false;
    }
    std::lock_guard lock(cache_mtx_);
    cached_generation_ = to_u64(PQgetvalue(g.get(), 0, 0));
    generation_valid_ = true;
    // Boot-time load is itself a genuine completed refresh — both timestamps
    // are honestly "now" (fjarvis F3, #2703 — see the member comments).
    refresh_started_ms_ = last_successful_refresh_ms_ = now_ms();
    return true;
}

// ── Durable generation token (ADR-0041 cross-replica coherence) ──────────────

void RbacStore::maybe_refresh_generation() const {
    if (!open_)
        return;
    bool gated = false;
    bool beyond_bound = false;
    {
        std::lock_guard lock(cache_mtx_);
        gated = (now_ms() - refresh_started_ms_) < kRbacGenerationRefreshMs;
        if (gated) {
            // fjarvis F3 (#2703): a refresh recently started (or is still in
            // flight) elsewhere, so THIS thread must not also fire a query —
            // that's the stampede this gate exists to prevent. But "someone
            // recently started a refresh" is not the same claim as "the cache
            // is fresh as of now" — the in-flight query may still be running.
            // Measure against `last_successful_refresh_ms_` (bumped only on
            // actual completion, never pre-emptively) so a slow in-flight
            // refresh under load is COUNTED rather than silently trusted: the
            // accepted ~kRbacGenerationRefreshMs bound stays honest instead of
            // being falsified by whichever thread happens to check first.
            // Computed here (still under the lock, a plain read of another
            // `mutable` member) but the degrade FIRES after the lock is
            // released — see below.
            beyond_bound = rbac_generation::is_stale_beyond_bound(
                now_ms(), last_successful_refresh_ms_, kRbacGenerationRefreshMs);
        } else {
            // Claim the refresh for THIS thread by advancing refresh_started_ms_
            // ATOMICALLY under the SAME lock as the gate check above (Gate 3
            // perf — this is what makes exactly one thread win per interval).
            // Otherwise every concurrent authz thread that crosses the interval
            // boundary at once fires the SELECT + grabs a pool lease — an N-way
            // refresh stampede once per interval under load, competing with
            // real permission queries. NOT last_successful_refresh_ms_ — that
            // one earns its update on actual completion, below.
            refresh_started_ms_ = now_ms();
        }
    }
    if (gated) {
        // performance (Gate 3, #2703): note_read_degrade()'s metrics-counter
        // call acquires MetricsRegistry's own multi-level lock chain and can
        // block for the duration of a Prometheus scrape (`serialize()` holds
        // the same registry lock). This branch is reachable by EVERY losing
        // thread on the fast/early-return path, not just the one thread per
        // interval that wins the refresh — so it must NOT run while holding
        // `cache_mtx_`, the sole authz-check serialization point, or a scrape
        // colliding with a degraded window could stall every check_permission
        // fleet-wide. Matches the existing pattern at check_permission's
        // pool-timeout branch (note_read_degrade called outside any lock).
        if (beyond_bound) {
            static DegradeSampler sampler;
            if (note_read_degrade(metrics_, kReasonStaleBeyondBound, sampler))
                spdlog::warn(
                    "RbacStore: cache read while a generation refresh is in flight AND "
                    "already past the accepted {}ms staleness bound — serving the "
                    "pre-refresh cache regardless (no cache to fail over to); this "
                    "replica's rbac view may be stale beyond the accepted bound",
                    kRbacGenerationRefreshMs);
        }
        return;
    }
    // Read the durable generation + enabled flag WITHOUT holding cache_mtx_.
    std::optional<std::uint64_t> durable_gen;
    std::optional<bool> durable_enabled;
    bool saw_non_canonical_enabled = false;
    // Breaker-gated (#2703 Gate 7 item 1 commit B): a denied attempt here
    // leaves durable_gen at nullopt WITHOUT touching the pool, which the
    // existing `!durable_gen` handling below already treats identically to
    // a real failed refresh — the stale-serve bound composes for free.
    if (breaker_admit()) {
        if (auto lease = pool_.try_acquire_for(kAuthzAcquireTimeout)) {
            pg::PgResult r = pg::exec_params(
                lease.get(),
                "SELECT key, value FROM rbac_store.rbac_meta WHERE key IN "
                "('write_generation','rbac_enabled')",
                std::vector<std::string>{});
            if (r.status() == PGRES_TUPLES_OK) {
                for (int i = 0; i < PQntuples(r.get()); ++i) {
                    const std::string k = text_col(r.get(), i, 0);
                    if (k == "write_generation")
                        durable_gen = to_u64(PQgetvalue(r.get(), i, 1));
                    else if (k == "rbac_enabled") {
                        // fjarvis F2 (#2703): parse strictly. A non-canonical
                        // value leaves durable_enabled at nullopt, and the
                        // existing "if (durable_enabled)" below already does the
                        // right thing (leave rbac_enabled_ untouched) — the loose
                        // `== "true"` this replaces silently coerced anything
                        // non-canonical to false instead.
                        durable_enabled = parse_canonical_bool(text_col(r.get(), i, 1));
                        saw_non_canonical_enabled = !durable_enabled;
                    }
                }
                breaker_note_result(true);
            } else {
                breaker_note_result(false);
            }
        } else {
            breaker_note_result(false);
        }
    }
    // consistency-auditor (Gate 4, #2703): the Gate 3 fix moved the
    // stale-beyond-bound degrade outside cache_mtx_ specifically because
    // note_read_degrade()'s metrics-registry lock chain can block for a
    // whole Prometheus scrape, and cache_mtx_ is the sole authz-check
    // serialization point — every concurrent check_permission() call (even
    // a cache HIT) needs it too. That same reasoning applies to these two
    // sibling branches; only the STATE MUTATIONS stay under the lock, and
    // which degrade(s) to fire is decided as plain bools first — except the
    // row-absent case below, which sets this same flag from INSIDE the
    // lock's durable_gen-confirmed branch, deliberately: it must only fire
    // when durable_gen was ALSO confirmed this round (see the fjarvis
    // MEDIUM comment there), a condition not yet known at this point.
    bool fire_non_canonical_degrade = saw_non_canonical_enabled;
    bool fire_refresh_failed_degrade = false;
    bool refresh_failed_cache_dropped = false;
    bool adopted_enabled = false; // A1: gauge published after releasing cache_mtx_, below
    {
        std::lock_guard lock(cache_mtx_);
        if (!durable_gen) {
            // Bounded stale-serve (#2703 Gate 7): a refresh failure inside
            // kRbacStaleServeBoundMs of the last confirmed-good refresh keeps
            // serving what we already trusted — perm_cache_ stays populated
            // and generation_valid_/rbac_enabled_ stay as last observed,
            // instead of unconditionally dropping trust on every transient
            // blip. Still fires the degrade metric either way (below) so
            // on-call sees the refresh is failing before the bound is
            // actually exceeded. Do NOT touch rbac_enabled_ in EITHER branch
            // — flipping it to disabled would be fail-open.
            // Security-guardian (#2703 Gate 8, second re-review): this was a
            // hand-written third copy of generation_view_stale_locked()'s
            // exact formula (De Morgan's-equivalent to its negation) — the
            // same drift risk the chokepoint exists to eliminate, sitting
            // right next to a doc comment claiming there wasn't one.
            // cache_mtx_ is already held here (line 1241), so the lock-free
            // helper is safe to call.
            const bool within_stale_serve_bound = !generation_view_stale_locked();
            fire_refresh_failed_degrade = true;
            refresh_failed_cache_dropped = !within_stale_serve_bound;
            if (!within_stale_serve_bound) {
                // Fail toward "assume changed": drop the cache and stop
                // trusting it — the bound is exceeded, or we never had a
                // confirmed-good refresh to begin with (generation_valid_
                // false, e.g. right after construction on a broken pool).
                perm_cache_.clear();
                generation_valid_ = false;
            }
        } else {
            // fjarvis (PR #2703 re-review, MEDIUM, residual in the F2 fix):
            // last_successful_refresh_ms_ used to bump here whenever
            // write_generation alone was read, regardless of whether
            // rbac_enabled was ALSO confirmed this round -- durable_enabled
            // is nullopt both when the value was non-canonical (counted via
            // saw_non_canonical_enabled below) AND when the row was simply
            // absent from the result set (never counted at all, since the
            // per-row loop above only sets saw_non_canonical_enabled inside
            // its `k == "rbac_enabled"` branch). Either way, the freshness
            // clock this store's OWN staleness check relies on
            // (generation_view_stale_locked(), consulted by both perm_cache_
            // trust and rbac_enabled_view_degraded()) was advancing on a
            // round that never actually confirmed rbac_enabled -- a replica
            // cached at rbac_enabled_=false could then keep
            // rbac_enforcement_in_effect() returning false (legacy-open)
            // indefinitely instead of degrading after kRbacStaleServeBoundMs,
            // the asymmetric-with-write_generation direction that matters.
            // Only advance the freshness clock, and adopt the enabled value,
            // when BOTH rows were confirmed this round.
            const bool row_absent = !durable_enabled && !saw_non_canonical_enabled;
            if (row_absent)
                fire_non_canonical_degrade = true; // same degrade class: rbac_enabled unconfirmed
            if (durable_enabled) {
                last_successful_refresh_ms_ = now_ms();
                // A1 (generation-gated publication, publish_local_toggle's sibling
                // half). Gate 7 Fix 2 (cpp-safety, CRITICAL): gated on the
                // DEDICATED flag_generation_, not the shared cached_generation_ —
                // see flag_generation_'s own doc comment (rbac_store.hpp) for why
                // rbac_enabled_ cannot share perm_cache_'s self-healing property.
                // `durable_gen` is non-null here (the `else` of `if (!durable_gen)`
                // above). Skip ONLY when the durable generation just read is not
                // AHEAD of what this replica's flag already reflects (`<=`, not
                // `<`): an equal generation means either this toggle's own
                // publish_local_toggle already applied it, or a previous refresh
                // round already adopted it — either way, re-adopting is a pure
                // no-op safe to skip — flag_generation_ is already at least
                // `*durable_gen` in that case, so the single condition below
                // both decides adoption AND is the correct "advance the
                // counter forward" test; an unrelated writer's flag-less
                // generation bump never touches flag_generation_, so it can
                // never make a later, genuinely-newer refresh look like it is
                // regressing.
                // cache_mtx_ is already held for this whole branch (both
                // flag_generation_ writers — this site and
                // publish_local_toggle — always hold it), so a plain
                // load-then-conditional-store is race-free; no CAS needed.
                if (*durable_gen > flag_generation_.load(std::memory_order_relaxed)) {
                    rbac_enabled_.store(*durable_enabled, std::memory_order_relaxed);
                    flag_generation_.store(*durable_gen, std::memory_order_relaxed);
                    adopted_enabled = true;
                }
            }
            // Adopt the durable generation only when it moves FORWARD (Gate 3
            // cpp-safety): the SELECT above ran lock-free, so a concurrent
            // local apply_local_generation may have advanced cached_generation_
            // past what we read — never regress it (that would wrongly clear a
            // just-populated cache and re-anchor to a stale value). Generations
            // are monotonic, so `>` is the correct adopt test. This half is
            // independent of rbac_enabled's own confirmation above — a
            // successfully-read write_generation still anchors perm_cache_
            // validity even on a round where rbac_enabled specifically
            // couldn't be confirmed.
            if (!generation_valid_ || *durable_gen > cached_generation_) {
                perm_cache_.clear();
                cached_generation_ = *durable_gen;
                generation_valid_ = true;
            }
        }
    }
    if (adopted_enabled)
        publish_enforcement_gauge(); // after releasing cache_mtx_ — same pattern as the breaker gauge
    if (fire_non_canonical_degrade) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonNonCanonicalFlag, sampler))
            spdlog::warn("RbacStore: durable rbac_enabled refresh could not confirm this round "
                         "(row read as non-canonical, or absent entirely) — leaving the cached "
                         "enabled-state unchanged (never coercing to false)");
    }
    if (fire_refresh_failed_degrade) {
        // Count the degrade so on-call can see that the cross-replica
        // generation + enabled-flag refresh is failing (Gate 3 architect /
        // Gate 6 sre): a persistent refresh failure means this replica's
        // rbac_enabled view can go stale, the more-sensitive fail-open
        // dimension. Two DISTINCT reasons (own sampler each, matching this
        // file's one-sampler-per-call-site convention — see check_permission's
        // pool-timeout/query-error sites): kReasonRefreshFailed fires ONLY
        // when the cache was actually dropped (denying, alert-eligible);
        // kReasonRefreshFailedWithinBound fires while the bounded stale-serve
        // window still protects the cache (observe-only, nobody denied). See
        // the reason constants' comments above for why they must not merge.
        if (refresh_failed_cache_dropped) {
            static DegradeSampler sampler;
            if (note_read_degrade(metrics_, kReasonRefreshFailed, sampler))
                spdlog::warn(
                    "RbacStore: durable generation/enabled-flag refresh failed — cache "
                    "dropped (assume-changed); rbac_enabled view may be stale on this replica");
        } else {
            static DegradeSampler sampler;
            if (note_read_degrade(metrics_, kReasonRefreshFailedWithinBound, sampler))
                spdlog::warn(
                    "RbacStore: durable generation/enabled-flag refresh failed — still within "
                    "the {}ms bounded stale-serve window, serving the existing cache "
                    "unchanged; rbac_enabled view may be stale on this replica",
                    kRbacStaleServeBoundMs);
        }
    }
}

void RbacStore::apply_local_generation(std::uint64_t new_gen) const {
    std::lock_guard lock(cache_mtx_);
    perm_cache_.clear();
    cached_generation_ = new_gen;
    generation_valid_ = true;
    // A locally-committed write is genuinely fresh data as of now — both
    // timestamps earn the update (fjarvis F3, #2703).
    refresh_started_ms_ = last_successful_refresh_ms_ = now_ms();
}

// A1: generation-gated publication. DB serialization does not serialize
// cache publication — without this gate, two opposite toggles committing at
// generations N and N+1 could publish their `rbac_enabled_.store()` calls in
// the REVERSE commit order on the same replica, leaving the cache disagreeing
// with the durable flag until the next successful refresh
// (kRbacGenerationRefreshMs). Soundness: bump_generation_in_txn runs INSIDE
// the writer's own transaction and holds the write_generation row lock until
// COMMIT, so generation order equals commit order; a cache cleared at
// generation N and repopulated afterwards already reflects every commit <=
// N, so skipping a pair whose generation is not ahead of the cached one
// loses nothing.
//
// Gate 7 Fix 2 (cpp-safety, CRITICAL): the perm-cache clear/re-anchor below
// stays gated on the SHARED cached_generation_ (perm_cache_ self-heals
// regardless of who bumped the generation — it is empty until repopulated on
// demand, so racing behind another writer here costs only a redundant
// clear). The flag write is now gated SEPARATELY on its own
// flag_generation_, because rbac_enabled_ does NOT self-heal the same way:
// nothing repopulates it except this method or the next periodic refresh's
// adopt. Pre-fix, both were gated on the ONE cached_generation_ check below —
// an unrelated, flag-less writer (assign_role/unassign_role/group CRUD/...)
// committing at N+1 and calling apply_local_generation(N+1) on this replica
// BEFORE this toggle's own publish_local_toggle(N, ...) call landed made
// `N < cached_generation_(N+1)` true and skipped the ENTIRE method, including
// the flag write — this replica's rbac_enabled_ then stayed wrong for a full
// refresh interval, restarted by a commit that had nothing to do with the
// toggle. See maybe_refresh_generation's flag-adoption branch for the
// sibling half of this fix.
void RbacStore::publish_local_toggle(std::uint64_t new_gen, bool enabled) const {
    std::lock_guard lock(cache_mtx_);
    if (!generation_valid_ || new_gen >= cached_generation_) {
        perm_cache_.clear();
        cached_generation_ = new_gen;
        generation_valid_ = true;
        refresh_started_ms_ = last_successful_refresh_ms_ = now_ms();
    }
    if (new_gen < flag_generation_.load(std::memory_order_relaxed))
        return;
    rbac_enabled_.store(enabled, std::memory_order_relaxed);
    flag_generation_.store(new_gen, std::memory_order_relaxed);
}

void RbacStore::publish_enforcement_gauge() const noexcept {
    if (metrics_)
        metrics_->gauge("yuzu_server_rbac_enforcement_enabled")
            .set(rbac_enabled_.load(std::memory_order_relaxed) ? 1.0 : 0.0);
}

bool RbacStore::breaker_admit() const {
    std::lock_guard lock(breaker_mtx_);
    if (breaker_consecutive_failures_ < kBreakerTripThreshold) {
        // Closed. Still stamp the timestamp on every ADMITTED attempt (not
        // only the half-open probe below) — otherwise the very first
        // cooldown check right after a trip measures against whatever
        // `breaker_last_probe_started_ms_` last held (0 at construction, or
        // a stale value from a prior open episode), which is not "how long
        // since we last actually tried" and can let the cooldown gate fail
        // open on its very first evaluation.
        breaker_last_probe_started_ms_ = now_ms();
        return true; // closed — proceed normally
    }
    // Open. Allow exactly one probe per kRbacGenerationRefreshMs (half-open),
    // claimed the same way maybe_refresh_generation claims its refresh slot:
    // advance the gate timestamp BEFORE the attempt so a concurrent caller
    // sees the claim immediately, not after the probe completes — otherwise
    // every authz call arriving in the same instant as the winning probe
    // would also read "not gated yet" and each fire its own pool attempt.
    const bool gated =
        (now_ms() - breaker_last_probe_started_ms_) < kRbacGenerationRefreshMs;
    if (gated)
        return false; // still cooling down — deny without touching the pool
    breaker_last_probe_started_ms_ = now_ms();
    return true; // this call wins the probe
}

void RbacStore::breaker_note_result(bool success) const {
    // #2703 Gate 7 item 1 commit C: compute the closed<->open TRANSITION as a
    // plain optional<bool> under the lock (mirrors maybe_refresh_generation's
    // existing fire_refresh_failed_degrade split, above) and fire the gauge
    // only after releasing it — breaker_mtx_ sits on every authz call's
    // gated paths, so it must never be held while touching MetricsRegistry's
    // own lock (the same hazard note_read_degrade's call sites already
    // avoid). Firing only on a TRANSITION (not on every call) also means
    // this never adds registry-lock contention to the common closed/healthy
    // path — a gauge doesn't need refreshing on every success once it is
    // already known to be 0.
    std::optional<bool> new_open_state;
    {
        std::lock_guard lock(breaker_mtx_);
        const bool was_open = breaker_consecutive_failures_ >= kBreakerTripThreshold;
        if (success)
            breaker_consecutive_failures_ = 0;
        else
            ++breaker_consecutive_failures_;
        const bool is_open = breaker_consecutive_failures_ >= kBreakerTripThreshold;
        if (was_open != is_open)
            new_open_state = is_open;
    }
    if (new_open_state && metrics_)
        metrics_->gauge("yuzu_server_rbac_breaker_open").set(*new_open_state ? 1.0 : 0.0);
}

namespace {
// Defined in rbac_store_sql_helpers.hpp (shared with RbacAdminAuthorityOwner).
// The cross-schema "authenticatable Administrator" helpers
// (kAuthenticatableAdminGrantsFrom and its lock_/list_/count_ siblings,
// list_active_local_admin_accounts) live ONLY in
// rbac_admin_authority_owner.cpp (ADR-0012 §3) — RbacStore no longer calls
// any of them directly; set_rbac_enforcement/
// check_caller_authorized_under_current_regime are thin wrappers over
// RbacAdminAuthorityOwner::set_enforcement/regime_authority below.
using rbac_sql::bump_generation_in_txn;
using rbac_sql::write_rbac_enabled_in_txn;
} // namespace

// ── Global toggle ────────────────────────────────────────────────────────────

bool RbacStore::is_rbac_enabled() const {
    maybe_refresh_generation();
    return rbac_enabled_.load(std::memory_order_relaxed);
}

bool RbacStore::generation_view_stale_locked() const {
    // G11-CPPEXPERT-B2 (#2703 Gate 8): `generation_valid_` alone is not a
    // sufficient staleness signal. It only flips false once SOME thread's
    // maybe_refresh_generation() call actually completes a failed attempt
    // past kRbacStaleServeBoundMs -- but a query stuck on PG-side lock
    // contention (#3016, up to lock_timeout ~10s) can leave generation_valid_
    // TRUE, stale, and untouched for the whole stall: every OTHER caller in
    // that window either takes the gated fast-return path (no state change)
    // or is itself still blocked inside its own query. Checking elapsed time
    // here directly (matching rbac_enabled_view_degraded()'s own doc comment,
    // which already promised this bound) closes the gap without depending on
    // any in-flight refresh attempt ever completing. This is the ONE
    // chokepoint for that decision -- originally added only inside
    // rbac_enabled_view_degraded(), then found (architect, Gate 3 re-review
    // of this same fix) to have a sibling raw read of generation_valid_ in
    // check_permission()'s perm-cache trust decision that bypassed it
    // entirely, serving a stale cached ALLOW/DENY through the identical
    // stuck-refresh window. Extracted here so both readers share one
    // definition of "stale" rather than risking a second copy drifting.
    if (!generation_valid_)
        return true;
    return rbac_generation::is_stale_beyond_bound(now_ms(), last_successful_refresh_ms_,
                                                   kRbacStaleServeBoundMs);
}

bool RbacStore::rbac_enabled_view_degraded() const {
    std::lock_guard lock(cache_mtx_);
    return generation_view_stale_locked();
}

std::expected<void, std::string> RbacStore::set_rbac_enabled(bool enabled) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        if (!write_rbac_enabled_in_txn(c, enabled, err)) {
            // Gate 7 Fix 8 (cpp-expert): re-added — the refactor to
            // std::expected dropped this pre-existing log call. ~70 existing
            // test call sites deliberately discard this function's result
            // (its own "unguarded seed primitive" contract), so without this,
            // a PG hiccup during test seeding was fully silent.
            spdlog::error("RbacStore::set_rbac_enabled: write failed: {}", err);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        if (!new_gen) {
            if (err.empty())
                err = "write_generation bump failed";
            spdlog::error("RbacStore::set_rbac_enabled: transaction failed; flag unchanged");
            return false;
        }
        return true;
    });
    if (!ok)
        return std::unexpected(err.empty() ? "set_rbac_enabled transaction failed; flag unchanged"
                                            : err);
    publish_local_toggle(*new_gen, enabled);
    publish_enforcement_gauge();
    return {};
}

// See rbac_store.hpp for the full rule (the idempotent no-op short-circuit,
// the SOURCE-then-DESTINATION guard order, the lock order and its
// point-in-time-not-enduring guarantee). The guarded transaction itself
// lives in `RbacAdminAuthorityOwner::set_enforcement`
// (rbac_admin_authority_owner.cpp) — the ADR-0012 §3 cross-schema query
// owner, which shares `kAuthenticatableAdminGrantsFrom` with
// `unassign_role`'s last-Administrator guard from ONE definition. This is a
// thin translation from the owner's `EnforcementOutcome` to this method's
// own `RbacEnforcementTransition`/`RbacEnforcementError` public shape,
// mirroring `unassign_role`'s own delegation pattern exactly.
std::expected<RbacEnforcementTransition, RbacEnforcementError>
RbacStore::set_rbac_enforcement(bool enabled, const std::string& caller_username) {
    if (!open_)
        return std::unexpected(RbacEnforcementError{RbacEnforcementError::Kind::kStoreFailure,
                                                     "database not open"});

    const RbacAdminAuthorityOwner::EnforcementOutcome outcome =
        RbacAdminAuthorityOwner{pool_}.set_enforcement(enabled, caller_username);

    if (outcome.refused) {
        const auto kind =
            outcome.refusal_kind ==
                    RbacAdminAuthorityOwner::EnforcementOutcome::RefusalKind::kSourceRegime
                ? RbacEnforcementError::Kind::kCallerNotAuthorizedUnderCurrentRegime
                : RbacEnforcementError::Kind::kCallerNotSurvivor;
        return std::unexpected(RbacEnforcementError{kind, outcome.refusal_message});
    }
    if (!outcome.ok)
        return std::unexpected(RbacEnforcementError{
            RbacEnforcementError::Kind::kStoreFailure,
            outcome.err.empty() ? "set_rbac_enforcement transaction failed; flag unchanged"
                                : outcome.err});

    RbacEnforcementTransition result{};
    result.previous_enabled = outcome.previous_enabled;
    result.enabled = outcome.enabled;
    result.changed = outcome.changed;
    result.post_transition_administrators = outcome.post_transition_administrators;

    if (result.changed) {
        // `!outcome.new_gen` is unreachable while the owner's lambda always
        // bumps generation on a real applied transition; guards the
        // dereference below if that ever changes — mirrors unassign_role's
        // own `!outcome.new_gen` unreachable note.
        if (!outcome.new_gen)
            return std::unexpected(RbacEnforcementError{
                RbacEnforcementError::Kind::kStoreFailure,
                "internal error: applied transition missing its generation bump"});
        publish_local_toggle(*outcome.new_gen, enabled);
        publish_enforcement_gauge();
    }
    return result;
}

RbacEnforcementLabel rbac_enforcement_label(const RbacStore* store) noexcept {
    // THE single derivation of enforcement state from the 3 raw accessors —
    // rbac_enforcement_in_effect() below is now a one-line PROJECTION of
    // THIS function's result (security-guardian re-review, PR #4985 merge
    // reconciliation: the two were previously two independently-written
    // function bodies kept in sync by a "keep any future change... in sync
    // here" comment alone — a real risk once this label became load-bearing
    // for is_rbac_administrator's own RBAC-on/off branch routing, not just
    // an export string. Delegating makes "the two can never silently drift
    // apart" true by CONSTRUCTION instead of by convention).
    //
    // Permit the fresh-disabled outcome (kDisabled) ONLY for a store that is
    // loaded, explicitly disabled, AND whose disabled view is currently
    // FRESH. Null / load-failed (!is_open()) fails CLOSED (kDegraded) — see
    // the header for the #1498 rationale.
    if (!store || !store->is_open())
        return RbacEnforcementLabel::kDegraded;
    if (store->is_rbac_enabled())
        return RbacEnforcementLabel::kEnabled;
    // adversarial-review round (#2703): is_rbac_enabled()==false is not, on
    // its own, proof RBAC is genuinely disabled — maybe_refresh_generation()
    // (just invoked by the call above) deliberately never touches a stale
    // cached rbac_enabled_ on a failed refresh, so a replica that has never
    // itself observed a remote enable stays cached false indefinitely
    // through an outage. A degraded view (the refresh did not land) reads as
    // kDegraded here, never kDisabled — the one place this distinction is
    // security-relevant, unlike the raw is_rbac_enabled() accessor other
    // (non-confinement) callers use.
    //
    // (cpp-safety re-review, PR #4985 fix round, corrected by a security-
    // guardian follow-up pass: `noexcept` here is honest only to the same
    // degree as `is_rbac_enabled()`/`rbac_enabled_view_degraded()` not
    // throwing in practice — `is_open()` IS itself `noexcept`, those two are
    // not. Not a new risk this delegation introduces.)
    return store->rbac_enabled_view_degraded() ? RbacEnforcementLabel::kDegraded
                                                : RbacEnforcementLabel::kDisabled;
}

bool rbac_enforcement_in_effect(const RbacStore* store) noexcept {
    return rbac_enforcement_label(store) != RbacEnforcementLabel::kDisabled;
}

// to_string(RbacEnforcementLabel) is constexpr and header-inline (rbac_store.hpp) —
// matches every other enum-to-string mapper in this codebase.

// ── Roles CRUD ───────────────────────────────────────────────────────────────

std::vector<RbacRole> RbacStore::list_roles() const {
    std::vector<RbacRole> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name, description, is_system, created_at FROM rbac_store.roles "
        "ORDER BY is_system DESC, name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        RbacRole role;
        role.name = text_col(r.get(), i, 0);
        role.description = text_col(r.get(), i, 1);
        role.is_system = to_bool(PQgetvalue(r.get(), i, 2));
        role.created_at = to_i64(PQgetvalue(r.get(), i, 3));
        result.push_back(std::move(role));
    }
    return result;
}

std::optional<RbacRole> RbacStore::get_role(const std::string& name) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name, description, is_system, created_at FROM rbac_store.roles WHERE name = $1",
        std::vector<std::string>{name});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
        return std::nullopt;
    RbacRole role;
    role.name = text_col(r.get(), 0, 0);
    role.description = text_col(r.get(), 0, 1);
    role.is_system = to_bool(PQgetvalue(r.get(), 0, 2));
    role.created_at = to_i64(PQgetvalue(r.get(), 0, 3));
    return role;
}

std::expected<void, std::string> RbacStore::create_role(const RbacRole& role) {
    if (!open_)
        return std::unexpected("database not open");
    if (role.name.empty())
        return std::unexpected("role name cannot be empty");
    const std::int64_t now = now_secs();
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.roles (name, description, is_system, created_at) "
            "VALUES ($1, $2, FALSE, $3::bigint)",
            std::vector<std::string>{sanitize_pg_text(role.name),
                                     sanitize_pg_text(role.description), std::to_string(now)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = std::string("role already exists or DB error: ") + PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "role create failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::update_role(const std::string& name,
                                                        const std::string& description) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    bool not_found = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c, "UPDATE rbac_store.roles SET description = $1 WHERE name = $2 RETURNING name",
            std::vector<std::string>{sanitize_pg_text(description), name});
        if (r.status() != PGRES_TUPLES_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        if (PQntuples(r.get()) == 0) {
            not_found = true;
            return false; // roll back — nothing changed, no generation bump
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (not_found)
        return std::unexpected("role not found");
    if (!ok)
        return std::unexpected(err.empty() ? "role update failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::delete_role(const std::string& name) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    bool not_found = false;
    bool is_system = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult chk = pg::exec_params(
            c, "SELECT is_system FROM rbac_store.roles WHERE name = $1",
            std::vector<std::string>{name});
        if (chk.status() != PGRES_TUPLES_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        if (PQntuples(chk.get()) == 0) {
            not_found = true;
            return false;
        }
        if (to_bool(PQgetvalue(chk.get(), 0, 0))) {
            is_system = true;
            return false;
        }
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM rbac_store.roles WHERE name = $1 AND is_system = FALSE",
            std::vector<std::string>{name});
        if (del.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (not_found)
        return std::unexpected("role not found");
    if (is_system)
        return std::unexpected("cannot delete system role");
    if (!ok)
        return std::unexpected(err.empty() ? "role delete failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

// ── Permissions CRUD ─────────────────────────────────────────────────────────

namespace {
Permission read_perm(PGresult* r, int i) {
    Permission p;
    p.role_name = text_col(r, i, 0);
    p.securable_type = text_col(r, i, 1);
    p.operation = text_col(r, i, 2);
    p.effect = text_col(r, i, 3);
    return p;
}
} // namespace

std::vector<Permission> RbacStore::get_role_permissions(const std::string& role_name) const {
    std::vector<Permission> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT role_name, securable_type, operation, effect FROM rbac_store.role_permissions "
        "WHERE role_name = $1 ORDER BY securable_type, operation",
        std::vector<std::string>{role_name});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_perm(r.get(), i));
    return result;
}

namespace {
// The one SELECT behind both per-role checked reads (the admin read and the breaker-gated
// authz read below); they differ only in the acquire budget and breaker bookkeeping.
std::expected<std::vector<Permission>, std::string>
select_role_permissions(PGconn* conn, const std::string& role_name) {
    pg::PgResult r = pg::exec_params(
        conn,
        "SELECT role_name, securable_type, operation, effect FROM rbac_store.role_permissions "
        "WHERE role_name = $1 ORDER BY securable_type, operation",
        std::vector<std::string>{role_name});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(conn));
    std::vector<Permission> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_perm(r.get(), i));
    return result;
}
} // namespace

std::expected<std::vector<Permission>, std::string>
RbacStore::get_role_permissions_checked(const std::string& role_name) const {
    if (!open_)
        return std::unexpected(std::string(kRbacErrStoreNotOpen));
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kRbacErrPoolAcquireTimeout));
    return select_role_permissions(lease.get(), role_name);
}

std::expected<std::vector<Permission>, std::string>
RbacStore::get_role_permissions_authz_checked(const std::string& role_name) const {
    if (!open_)
        return std::unexpected(std::string(kRbacErrStoreNotOpen));
    // Same contract as the hot authz reads (user_rbac_group_names / role_effects_for):
    // breaker-gated, short acquire budget, outcome fed back to the breaker. The degrade
    // metric is NOT bumped here; the gate that consumes the error owns the counter.
    if (!breaker_admit())
        return std::unexpected(std::string(kRbacErrCircuitBreakerOpen));
    auto lease = pool_.try_acquire_for(kAuthzAcquireTimeout);
    if (!lease) {
        breaker_note_result(false);
        return std::unexpected(std::string(kRbacErrPoolAcquireTimeout));
    }
    auto result = select_role_permissions(lease.get(), role_name);
    breaker_note_result(result.has_value());
    return result;
}

std::expected<std::vector<Permission>, std::string>
RbacStore::list_all_role_permissions_checked() const {
    if (!open_)
        return std::unexpected(std::string(kRbacErrStoreNotOpen));
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kRbacErrPoolAcquireTimeout));
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT role_name, securable_type, operation, effect FROM rbac_store.role_permissions "
        "ORDER BY role_name, securable_type, operation",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<Permission> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_perm(r.get(), i));
    return result;
}

std::expected<void, std::string> RbacStore::set_permission(const Permission& perm) {
    if (perm.effect != "allow" && perm.effect != "deny")
        return std::unexpected("effect must be 'allow' or 'deny'");
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.role_permissions (role_name, securable_type, operation, effect) "
            "VALUES ($1, $2, $3, $4) ON CONFLICT (role_name, securable_type, operation) "
            "DO UPDATE SET effect = EXCLUDED.effect",
            std::vector<std::string>{sanitize_pg_text(perm.role_name),
                                     sanitize_pg_text(perm.securable_type),
                                     sanitize_pg_text(perm.operation), perm.effect});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "set_permission failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::remove_permission(const std::string& role_name,
                                                              const std::string& securable_type,
                                                              const std::string& operation) {
    if (!open_)
        return std::unexpected("database not open");
    // security-guardian (#2703, HIGH — the F1 disease recurring outside the
    // one-time backfill): a hard DELETE here does not stick against a
    // built-in default. seed_defaults() runs UNCONDITIONALLY on every
    // RbacStore construction (every server boot/restart — that is the
    // documented mechanism new securables rely on to reseed with no
    // migration) and its grant() calls are `ON CONFLICT DO NOTHING`. A
    // deleted row leaves nothing to conflict with, so the very next restart
    // silently re-inserts the seeded 'allow' — the operator's revocation is
    // undone forever, on ordinary restart/redeploy, no attacker required.
    //
    // fable (Gate 4, #2703, HIGH — this round's fix REVISED again): an
    // earlier fix upserted an explicit 'deny' row instead of deleting, on
    // the theory that "the authorization OUTCOME is identical either way
    // (no matching allow row -> deny)". That theory is false. 'deny' is a
    // REAL, operator-authored authorization fact, and check_permission() /
    // check_scoped_permission() / authorize_list_read() all apply "deny
    // overrides everything, across ALL of a principal's held roles" — a
    // pre-existing, deliberate invariant, identical in the legacy SQLite
    // store. A deny row from THIS role therefore vetoes an allow this same
    // principal holds via a DIFFERENT role — legacy never hit this, because
    // its DELETE left nothing to veto with; the tombstone does. Fix:
    // restore the plain DELETE, and record the revocation SEPARATELY, as
    // pure reseed-suppression bookkeeping in revoked_seed_defaults — a
    // table seed_defaults()'s grant() consults and no authorization-decision
    // code path ever reads. Both statements share one transaction (and the
    // same generation bump) so a crash between them can never leave the
    // row deleted with no marker to stop it resurrecting on the next boot.
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // chaos-injector (Gate 5, #2703, HIGH — CHAOS-1): must be the FIRST
        // statement in this transaction — see kRevokeCoordLockSql's comment.
        // Serializes against seed_defaults()'s grant() and the backfill's F1
        // revoke block for the same coordination window.
        pg::PgResult lk = pg::exec_params(c, kRevokeCoordLockSql, std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        pg::PgResult marker = pg::exec_params(
            c,
            "INSERT INTO rbac_store.revoked_seed_defaults (role_name, securable_type, "
            "operation) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            std::vector<std::string>{sanitize_pg_text(role_name), sanitize_pg_text(securable_type),
                                     sanitize_pg_text(operation)});
        if (marker.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        pg::PgResult del = pg::exec_params(
            c,
            "DELETE FROM rbac_store.role_permissions WHERE role_name = $1 AND "
            "securable_type = $2 AND operation = $3",
            std::vector<std::string>{sanitize_pg_text(role_name), sanitize_pg_text(securable_type),
                                     sanitize_pg_text(operation)});
        if (del.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "remove_permission failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

// ── Principal-role assignments ───────────────────────────────────────────────

namespace {
PrincipalRole read_pr(PGresult* r, int i) {
    PrincipalRole pr;
    pr.principal_type = text_col(r, i, 0);
    pr.principal_id = text_col(r, i, 1);
    pr.role_name = text_col(r, i, 2);
    return pr;
}
} // namespace

std::vector<PrincipalRole> RbacStore::get_principal_roles(const std::string& principal_type,
                                                          const std::string& principal_id) const {
    std::vector<PrincipalRole> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT principal_type, principal_id, role_name FROM rbac_store.principal_roles "
        "WHERE principal_type = $1 AND principal_id = $2 ORDER BY role_name",
        std::vector<std::string>{principal_type, principal_id});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_pr(r.get(), i));
    return result;
}

std::expected<std::vector<PrincipalRole>, std::string>
RbacStore::get_principal_roles_checked(const std::string& principal_type,
                                       const std::string& principal_id) const {
    if (!open_)
        return std::unexpected(std::string(kRbacErrStoreNotOpen));
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kRbacErrPoolAcquireTimeout));
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT principal_type, principal_id, role_name FROM rbac_store.principal_roles "
        "WHERE principal_type = $1 AND principal_id = $2 ORDER BY role_name",
        std::vector<std::string>{principal_type, principal_id});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<PrincipalRole> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_pr(r.get(), i));
    return result;
}

std::expected<std::vector<PrincipalRole>, std::string>
RbacStore::list_all_principal_roles_checked() const {
    if (!open_)
        return std::unexpected(std::string(kRbacErrStoreNotOpen));
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        // sre (Gate 6, governance round 2026-09-28): this read had no
        // route-specific metric AND didn't bump the generic degrade
        // counter either — a sustained-poll retry storm against this route
        // was invisible even though the mechanism (note_read_degrade) was
        // already available on every other RbacStore read path.
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("RbacStore::list_all_principal_roles_checked: pool acquire timed out");
        return std::unexpected(std::string(kRbacErrPoolAcquireTimeout));
    }
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT principal_type, principal_id, role_name FROM rbac_store.principal_roles "
        "ORDER BY principal_type, principal_id, role_name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("RbacStore::list_all_principal_roles_checked: query failed");
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    }
    std::vector<PrincipalRole> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_pr(r.get(), i));
    return result;
}

std::vector<PrincipalRole> RbacStore::get_role_members(const std::string& role_name) const {
    std::vector<PrincipalRole> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT principal_type, principal_id, role_name FROM rbac_store.principal_roles "
        "WHERE role_name = $1 ORDER BY principal_type, principal_id",
        std::vector<std::string>{role_name});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_pr(r.get(), i));
    return result;
}

std::expected<void, std::string> RbacStore::validate_assignment(const std::string& principal_type,
                                                                const std::string& principal_id,
                                                                const std::string& role_name) {
    // F2: an `engine:`-prefixed principal_id must ONLY be assigned under
    // principal_type=="engine" (else a shadow ('user','engine:x',role) row
    // would attribute an engine identity's perms to a user lookup).
    if (principal_type != "engine" && principal_id.starts_with(kEnginePrefix))
        return std::unexpected(
            "principal_id in the reserved 'engine:' namespace may only be assigned under "
            "principal_type=\"engine\"");

    if (principal_type != "user" && principal_type != "group" && principal_type != "engine")
        return std::unexpected("unrecognized principal_type '" + principal_type + "'");

    if (principal_type != "engine")
        return {};

    if (!principal_id.starts_with(kEnginePrefix) || principal_id.size() == kEnginePrefix.size())
        return std::unexpected(
            "engine principal_id must be in the reserved 'engine:<slug>' namespace with a "
            "non-empty slug");

    for (auto disallowed : kEngineDisallowedRoles) {
        if (role_name == disallowed)
            return std::unexpected("engine principals cannot be granted the admin/full-access "
                                   "role '" +
                                   role_name + "' — no admin, ever (design §4.2)");
    }
    return {};
}

// See rbac_store.hpp for the full rule. The fresh, lock-free two-statement
// read lives in `RbacAdminAuthorityOwner::regime_authority`
// (rbac_admin_authority_owner.cpp) — see that method's own doc comment for
// why it is a single lease across two autocommit statements rather than one
// transaction (a deliberately accepted, already-reviewed residual, not an
// oversight).
RbacRegimeAuthority
RbacStore::check_caller_authorized_under_current_regime(const std::string& caller_username) const {
    if (!open_)
        return RbacRegimeAuthority::kUnavailable;
    return RbacAdminAuthorityOwner{pool_}.regime_authority(caller_username);
}

std::expected<void, std::string> RbacStore::assign_role(const PrincipalRole& pr) {
    if (!open_)
        return std::unexpected("database not open");
    if (auto v = validate_assignment(pr.principal_type, pr.principal_id, pr.role_name); !v)
        return std::unexpected(v.error());

    std::optional<std::uint64_t> new_gen;
    bool builtin_reject = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // F1: for an engine principal, reject ANY built-in (is_system) role via
        // its own `is_system` flag — generalizes the static "no admin, ever"
        // bar to "no built-in role, ever" for the fleet-wide path.
        if (pr.principal_type == "engine") {
            pg::PgResult chk = pg::exec_params(
                c, "SELECT is_system FROM rbac_store.roles WHERE name = $1",
                std::vector<std::string>{pr.role_name});
            if (chk.status() != PGRES_TUPLES_OK) {
                err = PQerrorMessage(c);
                return false;
            }
            if (PQntuples(chk.get()) == 1 && to_bool(PQgetvalue(chk.get(), 0, 0))) {
                builtin_reject = true;
                return false;
            }
        }
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.principal_roles (principal_type, principal_id, role_name) "
            "VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            std::vector<std::string>{sanitize_pg_text(pr.principal_type),
                                     sanitize_pg_text(pr.principal_id),
                                     sanitize_pg_text(pr.role_name)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (builtin_reject)
        return std::unexpected("engine principals cannot be granted a built-in system role '" +
                               pr.role_name + "' — no built-in role, ever (design §4.2)");
    if (!ok)
        return std::unexpected(err.empty() ? "assign_role failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<bool, std::string> RbacStore::unassign_role(const std::string& principal_type,
                                                           const std::string& principal_id,
                                                           const std::string& role_name) {
    if (!open_)
        return std::unexpected("database not open");
    const RbacAdminAuthorityOwner::UnassignOutcome outcome =
        RbacAdminAuthorityOwner{pool_}.unassign_role(principal_type, principal_id, role_name);
    if (outcome.last_admin_reject)
        return std::unexpected("cannot remove the last remaining Administrator role grant — "
                               "the fleet would be left with " +
                               std::string(kRbacLastAdminRefusalMarker));
    // `!outcome.new_gen` is unreachable while the owner's lambda returns
    // `new_gen.has_value()`; it guards the dereference below if that ever changes.
    if (!outcome.ok || !outcome.new_gen)
        return std::unexpected(outcome.err.empty() ? "unassign_role failed" : outcome.err);
    apply_local_generation(*outcome.new_gen);
    return outcome.removed;
}

// See rbac_store.hpp for the full contract. Thin delegation to
// `RbacAdminAuthorityOwner::provision_first_admin` (rbac_admin_authority_owner.cpp),
// the ADR-0012 §3 cross-schema query owner — mirrors `unassign_role`'s own
// delegation pattern exactly (this file constructs the owner per call,
// never caches it).
std::expected<bool, std::string> RbacStore::provision_first_admin(const std::string& username,
                                                                   const std::string& password_hash,
                                                                   const std::string& salt_hex) {
    if (!open_)
        return std::unexpected("database not open");
    const RbacAdminAuthorityOwner::ProvisionFirstAdminOutcome outcome =
        RbacAdminAuthorityOwner{pool_}.provision_first_admin(username, password_hash, salt_hex);
    if (!outcome.ok) {
        // `outcome.err` is empty when `run_in_txn` (via `with_txn_for`)
        // returns false without the lambda itself having set it. That
        // covers a PRE-lambda failure (pool-acquire timeout, connect
        // backoff, BEGIN failure) AND a POST-lambda failure the lambda
        // never observes: the PQTRANS_INTRANS abort-guard, or a later
        // `PgTxn::commit()` failure (`PgTxn` holds only a bare `PGconn*`,
        // no `PgPool&`, so it cannot call `set_error`). In the commit-
        // failure case the mutation may already be durably committed
        // server-side (ack loss — see the pre-flight/post-write comment
        // above) even though this branch reports failure. `pool_.last_error()`
        // is best-effort extra detail, not a reliable diagnosis of which of
        // these occurred, so the fallback message names the symptom
        // ("transaction did not complete") rather than a specific cause.
        if (outcome.err.empty()) {
            const std::string pool_err = pool_.last_error();
            return std::unexpected(pool_err.empty() ? "provision_first_admin failed: "
                                                       "transaction did not complete "
                                                       "(no further detail)"
                                                     : "provision_first_admin failed: " + pool_err);
        }
        return std::unexpected(outcome.err);
    }
    if (!outcome.provisioned)
        return false; // ordinary no-op — not the first account, nothing to apply
    // `!outcome.new_gen` is unreachable while `provisioned` (set by the
    // outer `result.provisioned = provisioned && ok;` tail assignment, not
    // by the lambda directly) implies the WHOLE transaction — grant INSERT
    // and generation bump both — committed successfully; guards the
    // dereference below if that ever changes — mirrors unassign_role's own
    // `!outcome.new_gen` unreachable note.
    if (!outcome.new_gen)
        return std::unexpected("internal error: applied provisioning missing its generation bump");
    apply_local_generation(*outcome.new_gen);
    return true;
}

// ── Groups CRUD ──────────────────────────────────────────────────────────────

std::vector<RbacGroup> RbacStore::list_groups() const {
    std::vector<RbacGroup> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name, description, source, external_id, created_at FROM rbac_store.groups "
        "ORDER BY name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        RbacGroup g;
        g.name = text_col(r.get(), i, 0);
        g.description = text_col(r.get(), i, 1);
        g.source = text_col(r.get(), i, 2);
        g.external_id = text_col(r.get(), i, 3); // NULL → ""
        g.created_at = to_i64(PQgetvalue(r.get(), i, 4));
        result.push_back(std::move(g));
    }
    return result;
}

std::expected<std::vector<RbacGroup>, std::string> RbacStore::list_groups_checked() const {
    if (!open_)
        return std::unexpected(std::string(kRbacErrStoreNotOpen));
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kRbacErrPoolAcquireTimeout));
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name, description, source, external_id, created_at FROM rbac_store.groups "
        "ORDER BY name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<RbacGroup> result;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        RbacGroup g;
        g.name = text_col(r.get(), i, 0);
        g.description = text_col(r.get(), i, 1);
        g.source = text_col(r.get(), i, 2);
        g.external_id = text_col(r.get(), i, 3);
        g.created_at = to_i64(PQgetvalue(r.get(), i, 4));
        result.push_back(std::move(g));
    }
    return result;
}

std::optional<std::vector<std::string>>
RbacStore::find_local_groups_with_prefix(const std::string& prefix) const {
    // A closed/unopened store, a pool timeout, or a query error is a scan
    // FAILURE, not "nothing to match" — signal it distinctly (nullopt) so the T8
    // preflight fails closed instead of trusting an engaged-but-empty result.
    if (!open_)
        return std::nullopt;
    // `prefix` is code-controlled — fail closed (empty result) if it ever
    // carries a LIKE metacharacter.
    if (prefix.empty() || prefix.find_first_of("%_\\") != std::string::npos)
        return std::vector<std::string>{};
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name FROM rbac_store.groups WHERE source = 'local' AND name LIKE $1",
        std::vector<std::string>{prefix + "%"});
    if (r.status() != PGRES_TUPLES_OK) {
        spdlog::error("find_local_groups_with_prefix: scan of prefix '{}' failed: {}", prefix,
                      PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::vector<std::string> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

std::expected<void, std::string> RbacStore::create_group(const RbacGroup& group) {
    if (!open_)
        return std::unexpected("database not open");
    if (group.name.empty())
        return std::unexpected("group name cannot be empty");
    if (group.source == "local" && has_reserved_idp_prefix(group.name))
        return std::unexpected(
            "group name uses a reserved identity-provider or engine-principal namespace prefix "
            "(local:/entra:/saml:/ad:/engine:)");
    const std::int64_t now = now_secs();
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.groups (name, description, source, external_id, created_at) "
            "VALUES ($1, $2, $3, $4, $5::bigint)",
            std::vector<std::string>{sanitize_pg_text(group.name),
                                     sanitize_pg_text(group.description),
                                     sanitize_pg_text(group.source),
                                     sanitize_pg_text(group.external_id), std::to_string(now)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = std::string("group already exists or DB error: ") + PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "create_group failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::delete_group(const std::string& name) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r =
            pg::exec_params(c, "DELETE FROM rbac_store.groups WHERE name = $1",
                            std::vector<std::string>{name});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "delete_group failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::vector<std::string> RbacStore::get_group_members(const std::string& group_name) const {
    std::vector<std::string> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT username FROM rbac_store.group_members WHERE group_name = $1 ORDER BY username",
        std::vector<std::string>{group_name});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

std::expected<void, std::string> RbacStore::add_group_member(const std::string& group_name,
                                                             const std::string& username) {
    if (!open_)
        return std::unexpected("database not open");
    // G5: reject an `engine:`-prefixed username at this write surface too
    // (the group-resolution arm would otherwise hand it the group's roles).
    if (username.starts_with(kEnginePrefix))
        return std::unexpected(
            "principal_id in the reserved 'engine:' namespace cannot be added as a group member");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.group_members (group_name, username) VALUES ($1, $2) "
            "ON CONFLICT DO NOTHING",
            std::vector<std::string>{sanitize_pg_text(group_name), sanitize_pg_text(username)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "add_group_member failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::remove_group_member(const std::string& group_name,
                                                                const std::string& username) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c, "DELETE FROM rbac_store.group_members WHERE group_name = $1 AND username = $2",
            std::vector<std::string>{group_name, username});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "remove_group_member failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<ReconcileResult, std::string> RbacStore::reconcile_idp_memberships(
    const std::string& username, const std::string& source,
    const std::vector<std::pair<std::string, std::string>>& asserted) {
    if (asserted.size() > kMaxIdpGroupsPerLogin)
        return std::unexpected("group_count_exceeded");

    bool recognized_source = false;
    for (auto s : kRecognizedIdpSources) {
        if (source == s) {
            recognized_source = true;
            break;
        }
    }
    if (!recognized_source)
        return std::unexpected("invalid_source");

    // UP-9: drop asserted entries whose external_id can't produce a sane group
    // name — blank/whitespace-only or implausibly long.
    std::vector<std::pair<std::string, std::string>> valid;
    valid.reserve(asserted.size());
    for (const auto& a : asserted) {
        if (is_blank(a.first)) {
            spdlog::warn("reconcile_idp_memberships: skipping asserted entry with blank "
                         "external_id (user='{}', source='{}')",
                         username, source);
            continue;
        }
        if (a.first.size() > kMaxExternalIdLength) {
            spdlog::warn("reconcile_idp_memberships: skipping asserted external_id exceeding {} "
                         "bytes (user='{}', source='{}')",
                         kMaxExternalIdLength, username, source);
            continue;
        }
        valid.push_back(a);
    }

    if (!open_)
        return std::unexpected("database not open");

    const std::int64_t now = now_secs();

    // Namespaced names computed once: reused for the upsert loop AND the
    // stale-membership DELETE's NOT IN list.
    std::vector<std::string> namespaced;
    namespaced.reserve(valid.size());
    for (const auto& a : valid)
        namespaced.push_back(namespaced_group_name(source, a.first));

    ReconcileResult result;
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        for (size_t i = 0; i < valid.size(); ++i) {
            const auto& external_id = valid[i].first;
            const auto& display = valid[i].second;
            const auto& name = namespaced[i];
            const auto description = std::string("IdP-provisioned group (") + source + "): " +
                                     (display.empty() ? external_id : display);

            pg::PgResult ins_group = pg::exec_params(
                c,
                "INSERT INTO rbac_store.groups (name, description, source, external_id, created_at) "
                "VALUES ($1, $2, $3, $4, $5::bigint) ON CONFLICT (name) DO NOTHING",
                std::vector<std::string>{sanitize_pg_text(name), sanitize_pg_text(description),
                                         sanitize_pg_text(source), sanitize_pg_text(external_id),
                                         std::to_string(now)});
            if (ins_group.status() != PGRES_COMMAND_OK) {
                err = std::string("group upsert failed: ") + PQerrorMessage(c);
                return false;
            }

            // sec-L1: verify the (possibly pre-existing) row's source before
            // joining a membership — never leak a different-source group's roles.
            pg::PgResult chk = pg::exec_params(
                c, "SELECT source FROM rbac_store.groups WHERE name = $1",
                std::vector<std::string>{sanitize_pg_text(name)});
            if (chk.status() != PGRES_TUPLES_OK) {
                err = std::string("group source check failed: ") + PQerrorMessage(c);
                return false;
            }
            bool source_mismatch = false;
            if (PQntuples(chk.get()) == 1) {
                const std::string existing = text_col(chk.get(), 0, 0);
                if (source != existing)
                    source_mismatch = true;
            }
            if (source_mismatch) {
                spdlog::warn("reconcile_idp_memberships: NOT joining '{}' to pre-existing group "
                             "'{}' — row source differs from reconcile source '{}' "
                             "(confused-deputy guard)",
                             username, name, source);
                continue;
            }

            pg::PgResult ins_member = pg::exec_params(
                c,
                "INSERT INTO rbac_store.group_members (group_name, username) VALUES ($1, $2) "
                "ON CONFLICT DO NOTHING RETURNING 1",
                std::vector<std::string>{sanitize_pg_text(name), sanitize_pg_text(username)});
            if (ins_member.status() != PGRES_TUPLES_OK) {
                err = std::string("membership upsert failed: ") + PQerrorMessage(c);
                return false;
            }
            if (PQntuples(ins_member.get()) == 1)
                ++result.added;
        }

        // Remove stale IdP memberships: any group_members row for this user
        // whose group is owned by THIS source and was NOT re-asserted.
        std::string sql = "DELETE FROM rbac_store.group_members WHERE username = $1 "
                          "AND group_name IN (SELECT name FROM rbac_store.groups WHERE source = $2)";
        std::vector<std::string> params{username, source};
        if (!namespaced.empty()) {
            sql += " AND group_name NOT IN (";
            for (size_t i = 0; i < namespaced.size(); ++i) {
                sql += (i == 0 ? "$" : ",$") + std::to_string(3 + i);
                params.push_back(sanitize_pg_text(namespaced[i]));
            }
            sql += ")";
        }
        sql += " RETURNING group_name";
        pg::PgResult del = pg::exec_params(c, sql.c_str(), params);
        if (del.status() != PGRES_TUPLES_OK) {
            err = std::string("stale-membership delete failed: ") + PQerrorMessage(c);
            return false;
        }
        result.removed = static_cast<size_t>(PQntuples(del.get()));

        // Bump the durable generation ONLY when membership actually changed
        // (Gate 4 consistency SHOULD-1). A no-op reconcile runs on EVERY IdP
        // login re-asserting unchanged groups; an unconditional bump would clear
        // the perm cache fleet-wide on every login, defeating the very cache the
        // generation-token compromise was chosen to preserve.
        if (result.added || result.removed) {
            new_gen = bump_generation_in_txn(c);
            return new_gen.has_value();
        }
        return true; // no-op reconcile: commit, no generation churn
    });
    if (!ok)
        return std::unexpected(err.empty() ? "reconcile transaction failed" : err);
    if (new_gen)
        apply_local_generation(*new_gen);
    return result;
}

// ── Authorization check ──────────────────────────────────────────────────────

std::vector<std::string> RbacStore::collect_roles(void* conn, const std::string& username) const {
    std::vector<std::string> roles;
    auto* c = static_cast<PGconn*>(conn);
    // Three-way UNION: direct user grant, group-membership grant, and (§4.1)
    // direct engine-principal grant. $1 reused for all three arms.
    pg::PgResult r = pg::exec_params(
        c,
        "SELECT role_name FROM rbac_store.principal_roles "
        "WHERE principal_type = 'user' AND principal_id = $1 "
        "UNION "
        "SELECT pr.role_name FROM rbac_store.principal_roles pr "
        "JOIN rbac_store.group_members gm ON pr.principal_type = 'group' AND "
        "pr.principal_id = gm.group_name WHERE gm.username = $1 "
        "UNION "
        "SELECT role_name FROM rbac_store.principal_roles "
        "WHERE principal_type = 'engine' AND principal_id = $1",
        std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK)
        return roles; // fail-closed: empty role set → deny
    for (int i = 0; i < PQntuples(r.get()); ++i)
        roles.push_back(text_col(r.get(), i, 0));
    return roles;
}

std::string RbacStore::perm_cache_key(const std::string& user, const std::string& type,
                                      const std::string& op) const {
    return user + ":" + type + ":" + op;
}

bool RbacStore::check_permission(const std::string& username, const std::string& securable_type,
                                 const std::string& operation) const {
    if (!open_)
        return false; // fail-closed

    // #2703 Gate 7 item 1 commit C: observes on every exit below, whichever
    // return statement fires — excludes the trivial !open_ short-circuit
    // above (a structural/administrative state, not a real check attempt).
    ScopedLatencyObserver latency_obs(authz_check_seconds_hist_);

    maybe_refresh_generation();

    const auto key = perm_cache_key(username, securable_type, operation);
    std::uint64_t gen_at_check = 0;
    bool gen_ok = false;
    {
        std::lock_guard lock(cache_mtx_);
        // G11-CPPEXPERT-B2 (#2703 Gate 8): route through the same
        // staleness check rbac_enabled_view_degraded() uses, not the raw
        // generation_valid_ flag directly -- a stuck-in-flight refresh
        // (PG-side lock contention, #3016) can leave generation_valid_ true
        // and stale for the whole stall, and a raw read here would keep
        // serving a stale cached ALLOW/DENY verdict through that window
        // exactly like the already-fixed rbac_enabled path did.
        gen_ok = !generation_view_stale_locked();
        gen_at_check = cached_generation_;
        if (gen_ok) {
            auto it = perm_cache_.find(key);
            if (it != perm_cache_.end())
                return it->second;
        }
    }

    // Breaker-gated (#2703 Gate 7 item 1 commit B): an open breaker denies
    // this pool fallback without an acquire attempt — the cache lookup above
    // ran regardless (never breaker-gated), so this line is reached only on
    // a genuine cache miss.
    if (!breaker_admit()) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn(
                "RbacStore::check_permission: circuit breaker open — DENY without pool touch");
        return false; // fail-closed
    }

    auto lease = pool_.try_acquire_for(kAuthzAcquireTimeout);
    if (!lease) {
        breaker_note_result(false);
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("RbacStore::check_permission: pool acquire timed out — DENY");
        return false; // fail-closed
    }
    PGconn* conn = lease.get();

    const auto roles = collect_roles(conn, username);
    if (roles.empty()) {
        // collect_roles() cannot distinguish "genuinely no roles" (the
        // common case for any least-privilege user) from "the query
        // failed" — both return empty. Recording this as a breaker SUCCESS
        // is the deliberate, safer default: treating it as a failure would
        // trip the breaker on ordinary confined-user traffic while Postgres
        // is perfectly healthy, which is worse than under-counting the
        // narrower same-shape connection-failure case this leaves uncovered.
        breaker_note_result(true);
        return false;
    }

    std::string sql = "SELECT effect FROM rbac_store.role_permissions "
                      "WHERE securable_type = $1 AND operation = $2 AND role_name IN (";
    std::vector<std::string> params{securable_type, operation};
    for (size_t i = 0; i < roles.size(); ++i) {
        sql += (i == 0 ? "$" : ",$") + std::to_string(3 + i);
        params.push_back(roles[i]);
    }
    sql += ")";

    pg::PgResult r = pg::exec_params(conn, sql.c_str(), params);
    if (r.status() != PGRES_TUPLES_OK) {
        breaker_note_result(false);
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("RbacStore::check_permission: query failed: {} — DENY",
                         PQerrorMessage(conn));
        return false; // fail-closed
    }
    breaker_note_result(true);
    bool has_allow = false;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        const std::string effect = text_col(r.get(), i, 0);
        if (effect == "deny")
            return false; // deny overrides everything
        if (effect == "allow")
            has_allow = true;
    }

    // Store only if the generation we validated against is still current — a
    // mutation racing this read (local or cross-replica) must not persist a
    // stale verdict under the new generation.
    {
        std::lock_guard lock(cache_mtx_);
        if (generation_valid_ && gen_ok && cached_generation_ == gen_at_check)
            perm_cache_[key] = has_allow;
    }
    return has_allow;
}

std::vector<Permission> RbacStore::get_effective_permissions(const std::string& username) const {
    std::vector<Permission> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    PGconn* conn = lease.get();

    const auto roles = collect_roles(conn, username);
    if (roles.empty())
        return result;

    std::string sql =
        "SELECT role_name, securable_type, operation, effect FROM rbac_store.role_permissions "
        "WHERE role_name IN (";
    std::vector<std::string> params;
    for (size_t i = 0; i < roles.size(); ++i) {
        sql += (i == 0 ? "$" : ",$") + std::to_string(1 + i);
        params.push_back(roles[i]);
    }
    sql += ") ORDER BY securable_type, operation";

    pg::PgResult r = pg::exec_params(conn, sql.c_str(), params);
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_perm(r.get(), i));
    return result;
}

// ── Reference data ───────────────────────────────────────────────────────────

std::vector<std::string> RbacStore::list_securable_types() const {
    std::vector<std::string> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(), "SELECT name FROM rbac_store.securable_types ORDER BY name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

std::vector<std::string> RbacStore::list_operations() const {
    std::vector<std::string> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(lease.get(), "SELECT id FROM rbac_store.operations ORDER BY id",
                                     std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

// ── Scoped permission check ──────────────────────────────────────────────────

bool RbacStore::check_scoped_permission(const std::string& username,
                                        const std::string& securable_type,
                                        const std::string& operation, const std::string& agent_id,
                                        const ManagementGroupStore* mgmt_store) const {
    // 1. Global permission first (a global ALLOW short-circuits, #1715(b)).
    if (check_permission(username, securable_type, operation))
        return true;

    // 2. No mgmt store or agent → cannot do the scoped check.
    if (!mgmt_store || agent_id.empty())
        return false;

    // 3. Resolve allow/deny groups via the shared INV-7 resolver, intersect
    //    with the agent's reachable groups. Deny wins within the scoped set.
    //    Fail-closed: any store error → false.
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg)
        return false;

    // CONFINEMENT reads are now degrade-distinguishable (ADR-0042): a `nullopt`
    // means the mgmt-store degraded (store-not-open / pool-acquire timeout /
    // query error), NOT a genuine empty. Treat it as DenyAll (fail-closed) — a
    // silent empty here would drop the agent's reachable groups and could admit
    // a scoped grant that a DENY assignment should have blocked (fail-open).
    auto groups = mgmt_store->get_agent_groups(agent_id);
    if (!groups)
        return false; // mgmt-store degrade → deny
    std::unordered_set<std::string> reachable;
    for (const auto& gid : *groups) {
        reachable.insert(gid);
        auto ancestors = mgmt_store->get_ancestor_ids(gid);
        if (!ancestors)
            return false; // mgmt-store degrade → deny
        for (const auto& aid : *ancestors)
            reachable.insert(aid);
    }
    if (reachable.empty())
        return false;

    for (const auto& g : pg->deny_groups)
        if (reachable.contains(g))
            return false;
    for (const auto& g : pg->allow_groups)
        if (reachable.contains(g))
            return true;
    return false;
}

// ── ADR-0017 admit-then-filter list gate ─────────────────────────────────────

std::expected<std::vector<std::string>, std::string>
RbacStore::user_rbac_group_names(const std::string& username) const {
    std::vector<std::string> groups;
    if (!open_)
        return std::unexpected(std::string(kRbacErrStoreNotOpen));
    // Breaker-gated (#2703 Gate 7 item 1 commit B) — see check_permission's
    // pool-fallback gate for the shared rationale.
    if (!breaker_admit()) {
        // #2703 Gate 7 item 3: this is the ADR-0017 admit-then-filter
        // chokepoint (authorize_list_read) — a degrade here is invisible to
        // yuzu_server_rbac_read_degrade_total / YuzuRbacReadDegraded without
        // this call. Reuses check_permission's reason label so the alert's
        // existing regex needs no change.
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn(
                "RbacStore::user_rbac_group_names: circuit breaker open — DENY without pool touch");
        return std::unexpected(std::string(kRbacErrCircuitBreakerOpen));
    }
    auto lease = pool_.try_acquire_for(kAuthzAcquireTimeout);
    if (!lease) {
        breaker_note_result(false);
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("RbacStore::user_rbac_group_names: pool acquire timed out — DENY");
        return std::unexpected(std::string(kRbacErrPoolAcquireTimeout));
    }
    pg::PgResult r = pg::exec_params(
        lease.get(), "SELECT group_name FROM rbac_store.group_members WHERE username = $1",
        std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK) {
        breaker_note_result(false);
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("RbacStore::user_rbac_group_names: query failed: {} — DENY",
                         PQerrorMessage(lease.get()));
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    }
    breaker_note_result(true);
    for (int i = 0; i < PQntuples(r.get()); ++i)
        groups.push_back(text_col(r.get(), i, 0));
    return groups;
}

std::expected<std::unordered_map<std::string, int>, std::string>
RbacStore::role_effects_for(const std::string& securable_type, const std::string& operation) const {
    std::unordered_map<std::string, int> role_effect; // -1 deny (wins), 1 allow, 0 none
    if (!open_)
        return std::unexpected(std::string(kRbacErrStoreNotOpen));
    // Breaker-gated (#2703 Gate 7 item 1 commit B) — see check_permission's
    // pool-fallback gate for the shared rationale.
    if (!breaker_admit()) {
        // #2703 Gate 7 item 3 — see user_rbac_group_names' matching call for
        // the ADR-0017 chokepoint-visibility rationale; same reason labels.
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn(
                "RbacStore::role_effects_for: circuit breaker open — DENY without pool touch");
        return std::unexpected(std::string(kRbacErrCircuitBreakerOpen));
    }
    auto lease = pool_.try_acquire_for(kAuthzAcquireTimeout);
    if (!lease) {
        breaker_note_result(false);
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("RbacStore::role_effects_for: pool acquire timed out — DENY");
        return std::unexpected(std::string(kRbacErrPoolAcquireTimeout));
    }
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT role_name, effect FROM rbac_store.role_permissions "
        "WHERE securable_type = $1 AND operation = $2",
        std::vector<std::string>{securable_type, operation});
    if (r.status() != PGRES_TUPLES_OK) {
        breaker_note_result(false);
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("RbacStore::role_effects_for: query failed: {} — DENY",
                         PQerrorMessage(lease.get()));
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    }
    breaker_note_result(true);
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        const std::string role = text_col(r.get(), i, 0);
        const std::string effect = text_col(r.get(), i, 1);
        if (role.empty())
            continue;
        int& e = role_effect[role];
        if (effect == "deny")
            e = -1;
        else if (effect == "allow" && e == 0)
            e = 1;
    }
    return role_effect;
}

std::expected<RbacStore::PermGroups, std::string>
RbacStore::resolve_perm_groups(const std::string& username, const std::string& securable_type,
                               const std::string& operation,
                               const ManagementGroupStore* mgmt_store) const {
    if (!mgmt_store)
        return std::unexpected("management group store unavailable");

    auto rbac_groups = user_rbac_group_names(username);
    if (!rbac_groups)
        return std::unexpected(rbac_groups.error());

    auto assignments = mgmt_store->get_assignments_for_principal(username, *rbac_groups);
    if (!assignments)
        return std::unexpected(assignments.error());

    auto role_effect_r = role_effects_for(securable_type, operation);
    if (!role_effect_r)
        return std::unexpected(role_effect_r.error());
    const auto& role_effect = *role_effect_r;

    PermGroups pg;
    std::unordered_set<std::string> allow_seen, deny_seen;
    for (const auto& a : *assignments) {
        auto it = role_effect.find(a.role_name);
        if (it == role_effect.end() || it->second == 0)
            continue;
        if (it->second == -1) {
            if (deny_seen.insert(a.group_id).second)
                pg.deny_groups.push_back(a.group_id);
        } else if (allow_seen.insert(a.group_id).second) {
            pg.allow_groups.push_back(a.group_id);
        }
    }
    return pg;
}

std::expected<std::vector<std::string>, std::string>
RbacStore::expand_visible_set(const PermGroups& pg, const ManagementGroupStore* mgmt_store) const {
    if (!mgmt_store)
        return std::unexpected("management group store unavailable");
    if (pg.allow_groups.empty())
        return std::vector<std::string>{}; // holds nothing via groups → empty (INV-2)

    auto allow_agents = mgmt_store->get_member_agents_in_subtrees(pg.allow_groups);
    if (!allow_agents)
        return std::unexpected(allow_agents.error());

    if (!pg.deny_groups.empty()) {
        auto deny_agents = mgmt_store->get_member_agents_in_subtrees(pg.deny_groups);
        if (!deny_agents)
            return std::unexpected(deny_agents.error());
        std::unordered_set<std::string> denied(deny_agents->begin(), deny_agents->end());
        std::vector<std::string> visible;
        visible.reserve(allow_agents->size());
        for (auto& a : *allow_agents)
            if (!denied.contains(a))
                visible.push_back(std::move(a));
        allow_agents = std::move(visible);
    }
    std::sort(allow_agents->begin(), allow_agents->end());
    allow_agents->erase(std::unique(allow_agents->begin(), allow_agents->end()),
                        allow_agents->end());
    return allow_agents;
}

bool RbacStore::holds_permission_via_any_group(const std::string& username,
                                               const std::string& securable_type,
                                               const std::string& operation,
                                               const ManagementGroupStore* mgmt_store) const {
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg)
        return false; // fail-closed on any store error
    return !pg->allow_groups.empty();
}

std::expected<std::vector<std::string>, std::string>
RbacStore::visible_agents_for_permission(const std::string& username,
                                         const std::string& securable_type,
                                         const std::string& operation,
                                         const ManagementGroupStore* mgmt_store) const {
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg)
        return std::unexpected(pg.error());
    return expand_visible_set(*pg, mgmt_store);
}

ListReadAuthorization RbacStore::authorize_list_read(const std::string& username,
                                                     const std::string& securable_type,
                                                     const std::string& operation,
                                                     const ManagementGroupStore* mgmt_store) const {
    ListReadAuthorization out; // DenyAll by default — the INV-1 fail-closed default.

    // Legacy-open: RBAC loaded AND explicitly disabled → full-fleet read. A
    // null / load-failed store returns true from rbac_enforcement_in_effect and
    // falls through to the RBAC path, which denies (INV-1).
    if (!rbac_enforcement_in_effect(this)) {
        out.decision = ListReadDecision::AdmitAll;
        return out;
    }

    // #1715(b): a global ALLOW overrides any group deny → unfiltered read.
    if (check_permission(username, securable_type, operation)) {
        out.decision = ListReadDecision::AdmitAll;
        return out;
    }

    // #1715(a): additive — a group allow admits even against a global deny/absent.
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg || pg->allow_groups.empty()) {
        out.decision = ListReadDecision::DenyAll; // INV-1/INV-5: error or no grant → deny
        return out;
    }
    auto visible = expand_visible_set(*pg, mgmt_store);
    if (!visible) {
        out.decision = ListReadDecision::DenyAll; // fail-closed on a subtree-read error
        return out;
    }
    out.decision = ListReadDecision::AdmitScoped;
    out.visible_agents = std::move(*visible);
    return out;
}

std::expected<bool, std::string>
RbacStore::role_permission_allowed_checked(const std::string& role_name,
                                           const std::string& securable_type,
                                           const std::string& operation) const {
    // THE one row loop for "does this role grant this pair" (extend, never fork):
    // `check_role_has_permission` and `authz::service_ceiling_check` (authz_gates.cpp)
    // both delegate here. First row for the pair decides: `allow` admits, `deny` or an
    // absent pair (a revoked default is a DELETEd row) refuses. A failed read is an error,
    // never a false allow. The read is the breaker-gated authz read: this runs on the
    // request path of every service-token fleet read.
    auto perms = get_role_permissions_authz_checked(role_name);
    if (!perms)
        return std::unexpected(std::move(perms.error()));
    for (const auto& p : *perms) {
        if (p.securable_type == securable_type && p.operation == operation) {
            if (p.effect == "deny")
                return false;
            if (p.effect == "allow")
                return true;
        }
    }
    return false;
}

bool RbacStore::check_role_has_permission(const std::string& role_name,
                                          const std::string& securable_type,
                                          const std::string& operation) const {
    // Thin fail-closed wrapper: a store error (unexpected) folds into DENY.
    return role_permission_allowed_checked(role_name, securable_type, operation).value_or(false);
}

} // namespace yuzu::server
