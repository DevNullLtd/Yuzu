#include "audit_store.hpp"
#include "config_secret_keys.hpp"

#include <yuzu/audit_retention_rules.hpp>
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <limits>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "audit_store";

// Bounded acquires (ADR-0012 §2(a)). Writes fail-HARD but must still give up
// eventually so a saturated pool cannot wedge a serving thread indefinitely;
// reads back interactive REST/dashboard/MCP callers.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
// Retention runs on the background thread; a generous deadline is fine.
constexpr std::chrono::milliseconds kReapTimeout{8000};

// Read-degrade reason labels (ADR-0037 convention).
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
// Sample the per-site degrade WARN so a sustained PG outage cannot flood the log
// — the counter is the continuous signal, the log a sampled breadcrumb.
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
bool to_bool(const char* s) { return s != nullptr && s[0] == 't'; }

// Overflow guard shared by every consumer of a persisted or caller-supplied
// clock reading: `now + window + slack` (cleanup_once, below) is signed-
// overflow UB near INT64_MAX. UPPER bound only — a NEGATIVE reading is the
// legitimate dead-CMOS case this file's clock guard exists for and must never
// be rejected on sign alone.
constexpr std::int64_t kMaxPlausibleNow = std::numeric_limits<std::int64_t>::max() / 4;

// Strict integer parse for a durable meta-table TEXT value — no trailing
// junk (checked: `*end != '\0'`), no partial parse. NOT locale-independent
// and NOT leading-junk-free in the way this comment used to imply: `strtoll`
// silently accepts and skips LEADING whitespace (" 123" parses to 123, per
// the C standard), and its digit-grouping/sign handling follows the process
// locale. Neither matters for this file's actual writers — `std::to_string`
// on an `int64_t` (this file) and `sqlite3_column_int64`-derived text (the
// legacy backfill) never produce leading whitespace or locale-formatted
// output — but a hand-edited row could, and would be silently accepted
// rather than rejected as this comment once claimed. `std::from_chars`
// would close that gap; not done here (#2854 fold round 3 found it, not
// fixed it — low value against this file's actual writers).
//
// Shared by the retention decision (`cleanup_once`'s `last_pass_now` read)
// and the liveness-gauge seed (`seed_last_pass_from_anchor`, #2854) so both
// treat "not a clean integer" as the same anomaly rather than two
// independently maintained `strtoll` call sites drifting apart.
[[nodiscard]] std::optional<std::int64_t> parse_meta_i64(const std::string& val) {
    errno = 0;
    char* end = nullptr;
    const long long v = std::strtoll(val.c_str(), &end, 10);
    if (val.empty() || errno != 0 || end == val.c_str() || *end != '\0')
        return std::nullopt;
    return static_cast<std::int64_t>(v);
}

// Nonzero and deliberately outside any range a real clock reading — caller's
// or PostgreSQL's — could plausibly produce, so it can never be confused with
// a genuine (even wildly wrong) dead-CMOS timestamp on a dashboard. Seeded by
// `seed_last_pass_from_anchor` when the durable anchor exists but cannot be
// trusted as an integer: distinct from `0` ("no pass has ever run on this
// database"), because laundering corruption into `0` would silently hand it
// the liveness family's "never ran" grace instead of surfacing it (#2854).
constexpr std::int64_t kLivenessAnomalySeed = std::numeric_limits<std::int64_t>::min();

// sanitize_utf8_strict scrubs invalid UTF-8 to U+FFFD but keeps embedded NUL
// (a valid ASCII byte). PostgreSQL TEXT cannot store a NUL and libpq's
// text-format bind C-string-truncates at the first one, silently dropping the
// rest. On the FAIL-HARD audit path a hostile or mis-encoded value would
// otherwise fail the INSERT (SQLSTATE 22021 / truncation) and take a real audit
// event down — the exact evidence-integrity hole this closes (ADR-0040 /
// #1593). So after the UTF-8 scrub, replace every NUL with U+FFFD too. We do
// NOT touch utf8_sanitize.hpp itself — NUL handling is a PG-bind concern local
// to the PG stores.
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col));
}

// ── Read-degrade observability (mirrors ResponseStore/InventoryStore) ────────
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason, DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_server_audit_read_degrade_total", {{"reason", reason}}).increment();
    const std::int64_t now = now_epoch();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

// Serialize the five guard facts to a stable string — the durable dedup key
// (mirrors ResponseStore's `facts_ser`). Compares the whole FACT SET, not the
// classified enum, so a Wipe arriving underneath a standing BadState (the
// dead-CMOS-then-NTP sequence that silently wiped the whole trail) is NOT
// suppressed: the fact set differs, so the pass declines again.
// The `no_anchor` character is part of the set on purpose (#2579): the pass that
// declines for it also settles the bootstrap marker, so the NEXT pass differs in
// this very field and is a different set — which is what lets the trigger decline
// once and then stand down without any anti-latch special case. There is no
// four-character legacy value to worry about here: migration v1 creates this
// table fresh, and the SQLite predecessor's meta table held only an INTEGER
// `last_pass_now`, never a fact-set string. (An earlier revision of this comment
// reasoned about upgrading from a four-character value, carried over from a
// store where that was possible.)
std::string serialize_facts(const audit_retention::Facts& f) {
    return std::string(f.has_expired ? "e" : "-") + (f.would_wipe ? "w" : "-") +
           (f.big_step ? "s" : "-") + (f.prev_unusable ? "u" : "-") + (f.no_anchor ? "b" : "-");
}

// ── Postgres schema (ADR-0040): the FINAL column set of the SQLite store's
// three migrations, collapsed into one v1. Unqualified DDL — the migration
// runner sets search_path to `audit_store` for the migration transaction.
// Runtime statements below schema-qualify explicitly. Unlike SQLite, the
// partial retention index is created IN the migration: a PG index build runs
// inside the migration txn and a failure correctly fails the migration, which
// for an evidence store is the right fail-closed posture (ADR-0040).
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE audit_events (
                id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                timestamp       BIGINT  NOT NULL,
                principal       TEXT    NOT NULL,
                principal_role  TEXT    NOT NULL,
                action          TEXT    NOT NULL,
                target_type     TEXT    NOT NULL DEFAULT '',
                target_id       TEXT    NOT NULL DEFAULT '',
                detail          TEXT    NOT NULL DEFAULT '',
                source_ip       TEXT    NOT NULL DEFAULT '',
                user_agent      TEXT    NOT NULL DEFAULT '',
                session_id      TEXT    NOT NULL DEFAULT '',
                result          TEXT    NOT NULL,
                ttl_expires_at  BIGINT  NOT NULL DEFAULT 0,
                principal_class TEXT    NOT NULL DEFAULT ''
            );
            CREATE INDEX idx_audit_ts ON audit_events(timestamp);
            CREATE INDEX idx_audit_principal_ts ON audit_events(principal, timestamp);
            CREATE INDEX idx_audit_action_ts ON audit_events(action, timestamp);
            CREATE INDEX idx_audit_target_ts ON audit_events(target_type, target_id, timestamp);
            CREATE INDEX idx_audit_ttl_id
                ON audit_events(ttl_expires_at, id) WHERE ttl_expires_at > 0;

            -- Durable state for the reap clock-guard (#2360, ADR-0040). SHARED
            -- k/v rows (not process-local) — N server replicas each run the
            -- sweep, so the persisted reading + anomaly-dedup fact set must be
            -- one shared truth under the sweep's advisory lock. `value` is TEXT
            -- (holds the integer `last_pass_now`, the `last_anomaly_facts`
            -- string, and the one-time `backfill_complete` marker).
            CREATE TABLE audit_retention_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        )"},
        // ADR-0009 hard-cutover Update (2026-09-04): retires `migrate_from_sqlite()`,
        // the last of 19 stores to lose it (#3623 PR A/B did the other 18). `audit_retention_meta`
        // stays -- it holds the clock-guard's PERMANENT durable state (`last_pass_now`,
        // `last_anomaly_facts`, `bootstrap_settled`), so this is a plain DELETE of the two
        // marker rows, never a DROP TABLE, plus a CHECK constraint closing a race the DELETE
        // alone leaves open (Gate 4 unhappy-path UP-1, round 4, below).
        //
        // DELETE, not poison, unlike RbacStore's v4 (same PR family, `rbac_meta`): the two
        // stores' old-binary-rollback failure modes differ. RbacStore's retired code fell
        // through marker-absence into an UNCONDITIONAL overwrite of a live security flag --
        // silent and dangerous, so that migration POISONS the marker to force old code down
        // its own existing safe branches instead. AuditStore's retired `migrate_from_sqlite()`
        // was already engineered against exactly this (Gate 3/4/5/8, `#2661`/`#2854`/ADR-0040,
        // three governance rounds): its marker-absent path either re-stamps sourcelessly (no
        // local legacy file -- the ordinary case) or re-inserts idempotently
        // (`ON CONFLICT (id) DO NOTHING`, verified against `whole_legacy_fp` before ever
        // stamping complete -- a real legacy file), and its marker-present-but-mismatched-
        // fingerprint path REFUSES to serve rather than trust unproven content (`git show
        // 8992b5274:server/core/src/audit_store.cpp` lines ~906-921, the pre-retirement HEAD
        // on `origin/dev`).
        //
        // Gate 4 unhappy-path UP-1 (round 4): a plain DELETE alone is NOT DROP TABLE's safety
        // bar. An old binary that boots while `audit_events` is still empty (the near-guaranteed
        // window immediately after this migration, before any native write) takes the
        // marker-ABSENT branch, finds `pg_rows_before == 0`, and re-stamps
        // `backfill_complete='sourceless'` via its own `Sourceless::StampIfEmpty` default. If
        // nothing else acted, that stamp would be permanent -- no later run of this migration
        // ever revisits it -- so every LATER old-binary boot, on any replica, at any later time,
        // would take the marker-PRESENT branch instead, which returns success with ZERO
        // row-count check (same pre-retirement source, lines ~928-940): one lost race
        // permanently disarms the refusal, silently. UP-2: the break-glass CLI
        // (`--mfa-reset`/`--break-glass-arm`) constructs a full `AuditStore` unconditionally, so
        // it can manufacture this window directly against a live, not-yet-upgraded fleet.
        //
        // The CHECK constraint closes this deterministically: it rejects an INSERT of either
        // marker key outright (23514 check_violation) independent of `ON CONFLICT` arbitration
        // (Postgres validates CHECK constraints before conflict resolution, so
        // `stamp_complete`'s `ON CONFLICT (key) DO NOTHING` shape does not bypass it). Old-binary
        // `stamp_complete` reaches this INSERT from exactly two of its four branches --
        // marker-absent-empty-table (the UP-1 window) and a real local legacy file -- and both
        // now fail at the write; the other two never reach an INSERT at all: a non-empty
        // `audit_events` was already refused by the pre-existing `pg_rows_before` guard,
        // unrelated to this fix, and marker-PRESENT is structurally unreachable once the marker
        // can never be (re-)inserted. `migrate_from_sqlite` returns false on every one of the
        // four, and `server.cpp` sets `startup_failed_` -- deterministically, not merely in the
        // realistic case. Same shape as RbacStore's own v2 constraint
        // (`rbac_meta_enabled_canonical`, `rbac_store.cpp`) on the same key/value-meta table
        // pattern. Nothing in the current codebase writes either key any more
        // (`migrate_from_sqlite` and its helpers are fully deleted, grep-verified) so the
        // constraint can never reject legitimate current-binary activity -- only an old binary's
        // retired write path.
        //
        // DELETE and ADD CONSTRAINT MUST stay ONE migration, DELETE first, never split into two
        // separately-numbered migrations -- Gate 5 chaos-injector (round 1) found the reason: an
        // interim commit on this branch briefly split them into v2 (DELETE) + v3 (ADD
        // CONSTRAINT) to sidestep having to verify every local/dev rig for drift from an even
        // earlier commit's DELETE-only v2 (a real but purely theoretical concern -- verified
        // clean on the two Postgres instances reachable from this box, recorded below). That
        // split reopened a WORSE, real race: crash a boot between v2's COMMIT and v3's BEGIN,
        // and an old binary -- which does not take `PgMigrationRunner`'s advisory lock, by its
        // own design -- can land a marker INSERT into the v2-but-not-yet-v3 gap. v3's `ALTER
        // TABLE ADD CONSTRAINT` then fails validating that row, so the CURRENT binary's own
        // `AuditStore` refuses to open too -- not a rollback inconvenience but a wedge, until an
        // operator manually deletes the row. Folded into one transaction, this can't happen: DELETE
        // and ADD CONSTRAINT commit together or roll back together, so there is no durable state
        // where the marker could be absent but the constraint not yet in force. The DELETE
        // ordered FIRST is what makes a retry self-healing rather than merely atomic: if an old
        // binary's insert lands and this transaction's own ALTER blocks on it and then fails, the
        // NEXT attempt's DELETE clears that very row before its ALTER validates -- a split
        // migration has no DELETE in the second step to do this. Drift-check record instead of
        // the split: this SQL (identical since `bec24602e`) was verified via
        // `git merge-base --is-ancestor <ancestor> origin/main`/`origin/dev` (neither is an
        // ancestor -- this branch has never shipped) plus a direct `schema_meta` query against
        // the two Postgres instances reachable from this box, both still at v1 (Gate 6
        // security-guardian, round 1) -- no rig anywhere has run a build with a different v2.
        {2, "DELETE FROM audit_retention_meta WHERE key IN "
            "('backfill_complete', 'backfill_source_fingerprint');"
            "ALTER TABLE audit_retention_meta ADD CONSTRAINT "
            "audit_retention_meta_no_retired_backfill_markers "
            "CHECK (key NOT IN ('backfill_complete', 'backfill_source_fingerprint'));"},
    };
    return kMigrations;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

AuditStore::AuditStore(pg::PgPool& pool, int retention_days, int cleanup_interval_min)
    : pool_(pool), retention_days_(retention_days), cleanup_interval_min_(cleanup_interval_min) {
    {
        // Scoped: `seed_last_pass_from_anchor()` below acquires its OWN lease
        // (#2854), and this one must be released first — held open, it
        // self-deadlocks a size-1 pool (`pg_pool.hpp`'s own warning against a
        // nested acquire, and exactly the fixture every PG-gated AuditStore
        // test uses).
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("AuditStore: no database connection at construction ({}) — audit "
                          "persistence disabled",
                          pool_.last_error());
            return;
        }
        if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
            spdlog::error("AuditStore: schema migration failed — audit persistence disabled");
            return;
        }
    }
    open_ = true;
    // Restores the liveness gauge across a restart on an ALREADY-migrated
    // database — the anchor from a previous `cleanup_once` pass already
    // exists. On the first-ever Postgres boot no anchor row exists yet
    // either, so this is a no-op (`0`, "never ran") — the legacy-SQLite
    // continuity path that used to backdate this seed on a mid-cutover
    // upgrade is retired (ADR-0009 hard-cutover Update, 2026-09-04); no
    // production fleet ever had a pre-Postgres reading to carry forward
    // (#2854).
    seed_last_pass_from_anchor();
    spdlog::info("AuditStore initialized (schema {}, retention={}d, liveness anchor {})",
                 kStoreName, retention_days_, last_pass_unixtime_.load(std::memory_order_relaxed));
}

void AuditStore::seed_last_pass_from_anchor() {
    // Restores `last_pass_unixtime_` (the EXPORTED liveness gauge) from the
    // durable `audit_retention_meta['last_pass_now']` anchor `cleanup_once`
    // writes — PostgreSQL's OWN clock (see the long note above that
    // function), not the caller's. Read-only and NOT a decision: no advisory
    // lock, no `pg_now()` read, just restoring a value this same store
    // already persisted. #2854.
    //
    // NEVER FATAL, deliberately asymmetric with this store's OTHER
    // construction-time checks (lease-acquire and schema migration both fail
    // closed). Those fail closed because failure there means audit events
    // genuinely cannot be written or read correctly — the SOC 2-critical
    // path. A failed or
    // unreadable read HERE does not touch that: audit ingestion is
    // unaffected either way, and the anomaly sentinel below already makes
    // both the liveness alert and the never-ran alert behave safely without
    // refusing to boot the whole evidence pipeline over one metrics-gauge
    // read. Do not "fix" this toward fail-closed for consistency with the
    // neighbouring checks — it was considered and rejected.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::warn("AuditStore: could not acquire a connection to seed the retention "
                     "liveness gauge ({}); it starts at the anomaly sentinel and "
                     "self-corrects at the next pass whose own clock reading is plausible",
                     pool_.last_error());
        last_pass_unixtime_.store(kLivenessAnomalySeed, std::memory_order_relaxed);
        return;
    }
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT value FROM audit_store.audit_retention_meta WHERE key = 'last_pass_now'",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK) {
        spdlog::warn("AuditStore: could not read the retention liveness anchor ({}); the "
                     "liveness gauge starts at the anomaly sentinel and self-corrects at "
                     "the next pass whose own clock reading is plausible",
                     PQerrorMessage(lease.get()));
        last_pass_unixtime_.store(kLivenessAnomalySeed, std::memory_order_relaxed);
        return;
    }
    if (PQntuples(r.get()) == 0)
        return; // no row yet — 0 is correct: "no pass has ever run on this database"
    const std::string val = text_col(r.get(), 0, 0);
    const auto parsed = parse_meta_i64(val);
    if (!parsed) {
        spdlog::warn("AuditStore: the retention liveness anchor is not an integer ({:.64}); "
                     "seeding the anomaly sentinel rather than laundering it into 0",
                     val);
        last_pass_unixtime_.store(kLivenessAnomalySeed, std::memory_order_relaxed);
        return;
    }
    if (*parsed > kMaxPlausibleNow) {
        spdlog::warn("AuditStore: the retention liveness anchor is implausible ({}); seeding "
                     "the anomaly sentinel rather than laundering it into 0",
                     *parsed);
        last_pass_unixtime_.store(kLivenessAnomalySeed, std::memory_order_relaxed);
        return;
    }
    // Any sign accepted, unclamped: a negative reading is a legitimate
    // dead-CMOS anchor and must stay distinguishable from `0` ("never ran").
    last_pass_unixtime_.store(*parsed, std::memory_order_relaxed);
}

AuditStore::~AuditStore() {
    // Join FIRST: the cleanup thread leases `pool_` every pass, so it must be
    // stopped before this object (and, upstream, the pool) is torn down.
    stop_cleanup();
}

void AuditStore::set_metrics(yuzu::MetricsRegistry* m) {
    metrics_ = m;
    if (!m)
        return;
    // Pre-seed the closed label set this store owns, per
    // docs/observability-conventions.md: a bounded-label counter is initialised
    // at startup so the family is present on a healthy server and `absent()`
    // alerts stay meaningful.
    m->describe("yuzu_server_audit_read_degrade_total",
                "Audit READ queries that could not be served and returned 503 instead of a "
                "false-empty 200 (deny-on-degrade), by reason",
                "counter");
    for (const char* reason : {kReasonStoreNotOpen, kReasonPoolTimeout, kReasonQueryError})
        m->counter("yuzu_server_audit_read_degrade_total", {{"reason", reason}});
}

// ── Write (FAIL-HARD) ────────────────────────────────────────────────────────

bool AuditStore::log(const AuditEvent& event) {
    if (!open_) {
        // Audit DB not open — surface as a failure so callers can flag the gap
        // on the response (HIGH-2, PR #883). Operators running audit-off never
        // reach here (AuthRoutes short-circuits on a null store).
        emit_failed_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        emit_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::error("AuditStore::log: no connection for action={} ({}); event lost",
                      event.action, pool_.last_error());
        return false;
    }
    PGconn* conn = lease.get();

    const int64_t now = now_epoch();
    const int64_t ts = event.timestamp > 0 ? event.timestamp : now;
    const int64_t ttl = retention_days_ > 0 ? now + static_cast<int64_t>(retention_days_) * 86400 : 0;

    // Sanitize EVERY text column, including `result` and `principal_class`.
    // They were bound verbatim on the claim that they are enum-controlled. All
    // the assignment sites in the tree today do use literals — but the
    // failure modes are not symmetric with the free-text ones: MEASURED on
    // PG 18, `result="\xff\xfe"` fails the INSERT and LOSES the event on a
    // fail-hard write path, and `result="suc\0cess"` stores `"suc"` — a
    // SILENTLY TRUNCATED audit result. A convention enforced only by every
    // caller remembering is not what should stand between an audit event and
    // being dropped (Gate 3 cpp-expert, who ran the bytes).
    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO audit_store.audit_events (timestamp, principal, principal_role, action, "
        "target_type, target_id, detail, source_ip, user_agent, session_id, result, "
        "ttl_expires_at, principal_class) "
        "VALUES ($1::bigint,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::bigint,$13) RETURNING id",
        std::vector<std::string>{std::to_string(ts), sanitize_pg_text(event.principal),
                                 sanitize_pg_text(event.principal_role),
                                 sanitize_pg_text(event.action),
                                 sanitize_pg_text(event.target_type),
                                 sanitize_pg_text(event.target_id), sanitize_pg_text(event.detail),
                                 sanitize_pg_text(event.source_ip),
                                 sanitize_pg_text(event.user_agent),
                                 sanitize_pg_text(event.session_id),
                                 sanitize_pg_text(event.result), std::to_string(ttl),
                                 sanitize_pg_text(event.principal_class)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
        emit_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::error("AuditStore::log: insert failed for action={}: {}; event lost", event.action,
                      PQerrorMessage(conn));
        return false;
    }

    // Bucket the write into a Prometheus-friendly counter. Result vocabulary is
    // open-ended at call sites — collapse anything unrecognised into "other".
    if (event.result == "success")
        events_success_.fetch_add(1, std::memory_order_relaxed);
    else if (event.result == "failure")
        events_failure_.fetch_add(1, std::memory_order_relaxed);
    else if (event.result == "denied")
        events_denied_.fetch_add(1, std::memory_order_relaxed);
    else
        events_other_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

uint64_t AuditStore::events_written(const std::string& result) const noexcept {
    if (result == "success")
        return events_success_.load(std::memory_order_relaxed);
    if (result == "failure")
        return events_failure_.load(std::memory_order_relaxed);
    if (result == "denied")
        return events_denied_.load(std::memory_order_relaxed);
    if (result == "other")
        return events_other_.load(std::memory_order_relaxed);
    return 0;
}

// ── Reads (degrade-distinguishable, DENY on degrade) ─────────────────────────

std::optional<std::vector<AuditEvent>> AuditStore::query(const AuditQuery& q,
                                                         std::size_t* out_pool_size) const {
    static DegradeSampler sampler;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, sampler))
            spdlog::warn("AuditStore::query: store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("AuditStore::query: pool acquire timed out");
        return std::nullopt;
    }
    PGconn* conn = lease.get();

    std::string sql =
        "SELECT id, timestamp, principal, principal_role, action, target_type, target_id, detail, "
        "source_ip, user_agent, session_id, result, principal_class FROM audit_store.audit_events "
        "WHERE 1=1";
    std::vector<std::string> binds;
    int idx = 1;
    if (!q.principal.empty()) {
        sql += " AND principal = $" + std::to_string(idx++);
        binds.push_back(q.principal);
    }
    if (!q.action.empty()) {
        sql += " AND action = $" + std::to_string(idx++);
        binds.push_back(q.action);
    }
    if (!q.target_type.empty()) {
        sql += " AND target_type = $" + std::to_string(idx++);
        binds.push_back(q.target_type);
    }
    if (!q.target_id.empty()) {
        sql += " AND target_id = $" + std::to_string(idx++);
        binds.push_back(q.target_id);
    }
    if (q.since > 0) {
        sql += " AND timestamp >= $" + std::to_string(idx++) + "::bigint";
        binds.push_back(std::to_string(q.since));
    }
    if (q.until > 0) {
        sql += " AND timestamp <= $" + std::to_string(idx++) + "::bigint";
        binds.push_back(std::to_string(q.until));
    }
    // Prefix OR-group (auth./mfa./session. for the auth-log sample, #4).
    // Prefixes are code-controlled constants; each binds as `<prefix>%`. Any
    // prefix carrying a LIKE metacharacter is dropped (fails closed for that
    // prefix); an all-empty group emits an always-false guard so it never
    // silently widens to "all actions" (Hermes M-2).
    if (!q.action_prefixes.empty()) {
        sql += " AND (";
        bool first = true;
        for (const auto& p : q.action_prefixes) {
            if (p.empty() || p.find_first_of("%_\\") != std::string::npos)
                continue;
            sql += first ? "action LIKE $" + std::to_string(idx)
                         : " OR action LIKE $" + std::to_string(idx);
            binds.push_back(p + "%");
            ++idx;
            first = false;
        }
        sql += first ? "1=0)" : ")";
    }

    // Always order by the indexed timestamp — never ORDER BY RANDOM() (a full
    // scan of the window). For random_sample, over-fetch a bounded candidate
    // pool and shuffle+truncate in C++ (Hermes M-1). OFFSET is meaningless under
    // random order, so it is skipped there.
    // The random-sample pool is ALWAYS exactly the cap, never the caller's
    // limit: below the cap a smaller pool would collapse the sample into "the N
    // most recent" (no randomness left to draw), and above it the pool would
    // breach the `<= kAuditSampleScanCap` bound the header promises and the REST
    // layer reports to an auditor as `recency_capped`. Was `std::max(limit,
    // cap)`, which honoured the first half and broke the second — a limit above
    // the cap fetched `limit` rows. No shipped caller reaches it (REST clamps to
    // 1000, MCP to 500 and does not set random_sample), so nothing was exposed;
    // it is the store contract that was wrong.
    // Clamp at the SINK. A negative limit reaches PostgreSQL as `LIMIT -1`,
    // which errors (`LIMIT must not be negative`) — and this store reports a
    // query error as a DEGRADE: 503 plus
    // `yuzu_server_audit_read_degrade_total{reason="query_error"}`, the series
    // `YuzuAuditReadDegraded` pages on. So any read-privileged client could make
    // the evidence-availability control fire at will, and send the on-call after
    // a database fault that does not exist (Gate 2 security). The parsers below
    // reject it as the 400 it is; this is the defence-in-depth half, and it uses
    // the same `std::max(q.limit, 0)` idiom the sample truncation already uses.
    //
    // `offset` needs no clamp here: the OFFSET clause is emitted only under
    // `q.offset > 0`, so a negative offset is already inert at this seam.
    const int64_t fetch_limit = q.random_sample ? static_cast<int64_t>(kAuditSampleScanCap)
                                                : static_cast<int64_t>(std::max(q.limit, 0));
    sql += " ORDER BY timestamp DESC LIMIT $" + std::to_string(idx++) + "::bigint";
    binds.push_back(std::to_string(fetch_limit));
    if (q.offset > 0 && !q.random_sample) {
        sql += " OFFSET $" + std::to_string(idx++) + "::bigint";
        binds.push_back(std::to_string(q.offset));
    }

    pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("AuditStore::query: query failed: {}", PQerrorMessage(conn));
        return std::nullopt;
    }
    std::vector<AuditEvent> results;
    const int n = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AuditEvent e;
        e.id = to_i64(PQgetvalue(res.get(), i, 0));
        e.timestamp = to_i64(PQgetvalue(res.get(), i, 1));
        e.principal = text_col(res.get(), i, 2);
        e.principal_role = text_col(res.get(), i, 3);
        e.action = text_col(res.get(), i, 4);
        e.target_type = text_col(res.get(), i, 5);
        e.target_id = text_col(res.get(), i, 6);
        // Read-time redaction of credentials captured in pre-fix
        // `config.update` rows (see sanitized_detail). Applied at the ROW
        // MATERIALISATION point so every reader gets it — the SQLite store
        // did this and the port must not drop it.
        e.detail = sanitized_detail(e.target_type, e.target_id, text_col(res.get(), i, 7));
        e.source_ip = text_col(res.get(), i, 8);
        e.user_agent = text_col(res.get(), i, 9);
        e.session_id = text_col(res.get(), i, 10);
        e.result = text_col(res.get(), i, 11);
        e.principal_class = text_col(res.get(), i, 12);
        results.push_back(std::move(e));
    }

    if (q.random_sample) {
        if (out_pool_size)
            *out_pool_size = results.size();
        const auto keep = static_cast<std::size_t>(std::max(q.limit, 0));
        if (results.size() > keep) {
            static thread_local std::mt19937_64 rng{std::random_device{}()};
            std::shuffle(results.begin(), results.end(), rng);
            results.resize(keep);
        }
    }
    return results;
}

std::string AuditStore::sanitized_detail(std::string_view target_type, std::string_view target_id,
                                         std::string detail) {
    // Keyed on the TARGET (a runtime-config row naming a secret key), not on one
    // writer's action string. `config.update` is the only such writer today, but
    // keying on it would leave a future writer -- a settings handler recording the
    // same key under its own verb -- outside the rule, and nothing would fail.
    // Still narrow: a blanket "redact anything that looks secret" across every audit
    // detail would gut the evidence value of the log, which is what this store is for.
    if (target_type != "RuntimeConfig" || !is_secret_config_key(target_id))
        return detail;
    if (detail.empty())
        return detail;

    // ONLY the exact shape today's writer emits -- a detail that STARTS `value=` --
    // keeps its `value=` label. Anything else is replaced wholesale.
    //
    // An earlier revision preserved `detail.substr(0, pos)` for a `value=` found at
    // ANY offset, to keep a future writer's surrounding context. Two reviewers
    // independently rejected that, and both were right: a writer that placed the
    // credential BEFORE a `value=` token would have had it preserved verbatim, and
    // the comment promising that context is kept held only for one token ordering
    // that nothing enforces. No writer of either shape exists today, so this gives
    // up nothing real and removes a trap that fires the moment someone trusts the
    // comment. If a future writer needs context to survive, give `detail` structure
    // (named JSON fields) rather than adding a second string-surgery rule.
    if (detail.rfind("value=", 0) == 0)
        return "value=" + std::string(kRedactedPlaceholder);
    return std::string(kRedactedPlaceholder);
}

std::optional<std::size_t> AuditStore::total_count() const {
    static DegradeSampler sampler;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, sampler))
            spdlog::warn("AuditStore::total_count: store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("AuditStore::total_count: pool acquire timed out");
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(lease.get(), "SELECT COUNT(*) FROM audit_store.audit_events",
                                       std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("AuditStore::total_count: query failed: {}", PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

// ── Retention (clock-guarded, single-sweeper advisory lease — #2360/ADR-0040) ─

std::size_t AuditStore::cleanup_once(std::int64_t now) {
    // Liveness, stamped for EVERY pass (attempted) — including declines,
    // failures, and lock-skips. A reaper that runs and declines is healthy; one
    // that never runs is the failure these expose. Stamped BEFORE any return.
    retention_passes_.fetch_add(1, std::memory_order_relaxed);

    // Sanitise the CALLER's clock: `now + window + slack` below is signed-
    // overflow UB near INT64_MAX. UPPER bound only — a NEGATIVE `now` is the
    // legitimate dead-CMOS case this guard exists for. `kMaxPlausibleNow` is
    // file-scope (shared with the liveness-gauge seed, #2854).
    if (now > kMaxPlausibleNow) {
        cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("AuditStore: retention pass called with an implausible clock reading ({}); "
                     "declining the pass",
                     now);
        return 0;
    }
    // Stamped only for a reading the guard will reason about. The ATTEMPT is
    // counted above; stamping a value just declared unusable would poison the
    // staleness gauge permanently.
    last_pass_unixtime_.store(now, std::memory_order_relaxed);

    if (!open_) {
        // A store that never opened has stopped retaining permanently; count a
        // failed pass rather than silence (else an ever-growing table reads as a
        // healthy guard).
        cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }

    const std::int64_t window =
        retention_days_ > 0 ? static_cast<std::int64_t>(retention_days_) * 86400 : 0;

    // Outcomes captured under the txn, acted on after it commits so counters
    // only move for committed passes and no spdlog formatting runs under lock.
    std::size_t deleted = 0;
    bool skipped_lock = false;
    bool declined = false;
    bool declined_no_anchor = false;
    bool cap_backlog = false;
    bool persist_failed = false;
    std::string decline_msg;

    const bool ok = pool_.with_txn_for(kReapTimeout, [&](PGconn* conn) -> bool {
        // Exactly one replica sweeps per tick fleet-wide.
        pg::PgResult lk = pg::exec_params(
            conn, "SELECT pg_try_advisory_xact_lock(hashtextextended('audit_store:reap', 0))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: reap lock probe failed: {}", PQerrorMessage(conn));
            return false;
        }
        if (!to_bool(PQgetvalue(lk.get(), 0, 0))) {
            skipped_lock = true;
            return true; // another replica is sweeping; not a failure
        }

        // PostgreSQL's OWN clock, not the caller's, for every DECISION below.
        // The caller-supplied `now` remains a liveness signal only
        // (`last_pass_unixtime_`, stamped before this transaction even runs)
        // and still gates the cheap pre-txn implausibility check.
        //
        // Gate 4 unhappy-path UP-2 / Sol: comparing one replica's PROCESS
        // clock against `last_pass_now` — itself stamped by whichever
        // replica's process clock swept last — means clock disagreement
        // BETWEEN replicas, not just an NTP jump on one machine, can make two
        // sweepers alternate distinct fact sets forever, each declining a
        // pass the other just anchored. PostgreSQL is the ONE authority every
        // sweeper already serialises through (the advisory lock above), so
        // reading its clock HERE — after the lock, inside this transaction —
        // gives every replica the identical comparison point regardless of
        // its own process clock's accuracy. `EXTRACT(EPOCH FROM now())::bigint`
        // is SQL this codebase already runs (`software_inventory_store.cpp`'s
        // migration backfill), and the single-sweeper advisory lease itself is
        // precedented in `result_set_store.cpp`/`software_inventory_store.cpp`
        // — but reading PG's clock to DRIVE an ongoing retention verdict is new
        // here: `ResultSetStore::gc_sweep` (the same `#2360`-class guard,
        // `result_set_store.cpp:1312`) still compares against its own process
        // clock via `now_epoch()`, carrying the identical cross-replica
        // divergence this fix closes for AuditStore. That sibling is a
        // deferred follow-up, not a precedent this fix is copying. `now()` is
        // the transaction's start time, stable and adequate for a
        // single-statement read.
        pg::PgResult clk = pg::exec_params(conn, "SELECT EXTRACT(EPOCH FROM now())::bigint",
                                           std::vector<std::string>{});
        if (clk.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: reap clock read failed: {}", PQerrorMessage(conn));
            return false;
        }
        const std::int64_t pg_now = to_i64(PQgetvalue(clk.get(), 0, 0));
        // Same overflow guard as the pre-txn check on the caller's clock,
        // applied to PG's — `datable_horizon` below adds `window + slack` to
        // this value, and it is cheap to bound both sources the same way
        // rather than trust one implicitly because it is "the database".
        if (pg_now > kMaxPlausibleNow) {
            spdlog::error("AuditStore: reap declined — PostgreSQL's own clock reading ({}) is "
                          "implausible",
                          pg_now);
            return false;
        }

        // Durable dedup state (shared across replicas + restarts).
        pg::PgResult meta = pg::exec_params(
            conn,
            "SELECT key, value FROM audit_store.audit_retention_meta WHERE key IN ('last_pass_now',"
            "'last_anomaly_facts','bootstrap_settled')",
            std::vector<std::string>{});
        if (meta.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: reap meta read failed: {}", PQerrorMessage(conn));
            return false;
        }
        std::optional<std::int64_t> prev;
        bool prev_unusable = false;
        std::string last_facts;
        // #2579: has ANY pass on this database ever reached a verdict? Durable
        // and SHARED rather than the per-process flag the SQLite store carries,
        // because on Postgres N replicas sweep the same table and a process-local
        // trigger would be spent by whichever replica happened to boot first
        // (ADR-0012 / the routed clock-guard concern's single-writer caveat).
        bool bootstrap_settled = false;
        for (int i = 0; i < PQntuples(meta.get()); ++i) {
            const std::string key = text_col(meta.get(), i, 0);
            const std::string val = text_col(meta.get(), i, 1);
            if (key == "last_pass_now") {
                // A stored reading that is not an integer is corrupted/hand-
                // edited durable state — an anomaly, not a clean slate.
                if (const auto parsed = parse_meta_i64(val))
                    prev = *parsed;
                else
                    prev_unusable = true;
            } else if (key == "last_anomaly_facts") {
                last_facts = val;
            } else if (key == "bootstrap_settled") {
                bootstrap_settled = true;
            }
        }
        // A reading ahead of the clock (backward NTP correction) or negative
        // (corruption) cannot be reasoned about — decline either way.
        if (prev && (*prev < 0 || *prev > pg_now)) {
            prev_unusable = true;
            prev.reset();
        }

        // Re-anchor the reading for the next pass BEFORE any early return, so a
        // decline still updates the comparison point and a poisoned value
        // self-heals. Persisting it is the only half of the guard that works
        // when the clock was already wrong before the process started.
        pg::PgResult stamp = pg::exec_params(
            conn,
            "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES ('last_pass_now', $1) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{std::to_string(pg_now)});
        if (stamp.status() != PGRES_COMMAND_OK) {
            spdlog::error("AuditStore: reap meta stamp failed: {}", PQerrorMessage(conn));
            persist_failed = true;
            return false; // fail closed — roll back the whole pass
        }

        // Detect by OUTCOME: two probes answer the whole question, both
        // index-eligible. The two halves are deliberately different SHAPES —
        // see `kAuditRetentionProbeSql`'s own comment (1f) for why the
        // survivor half is `ORDER BY ... LIMIT 1` rather than a second bare
        // EXISTS, and don't re-derive it here; this is the read site, not the
        // definition. A forward-skewed row past
        // `now + window + slack` can never expire, so it is EXCLUDED from the
        // survivor question — else one bad row vetoes the guard for the store's
        // life.
        //
        // EXISTS, NOT `count(*) FILTER (...)`. The guard only ever asks "any?",
        // and the counting form has no statement-level WHERE, so every row —
        // including the `ttl_expires_at = 0` majority, which sits OUTSIDE the
        // partial index `idx_audit_ttl_id ... WHERE ttl_expires_at > 0` declared
        // in kMigrations above — must be visited before either count is known.
        // That is a full scan of the audit trail on every pass, on the one table
        // designed to grow without bound (Gate 3 performance PERF-1; plan
        // evidence in the commit message). EXISTS carries the `> 0` predicate
        // into the index and stops at the first matching row.
        //
        // The SQLite-side note about `BETWEEN` being load-bearing does NOT
        // transfer: Postgres expands BETWEEN to exactly these two comparisons,
        // and either way the pair is one index range condition on the leading
        // column.
        const std::int64_t datable_horizon = pg_now + window + kAuditTtlFutureSlackSec;
        pg::PgResult probe = pg::exec_params(
            conn, std::string(kAuditRetentionProbeSql).c_str(),
            std::vector<std::string>{std::to_string(pg_now), std::to_string(datable_horizon)});
        if (probe.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: reap probe failed: {}", PQerrorMessage(conn));
            return false;
        }
        const bool has_expired = to_bool(PQgetvalue(probe.get(), 0, 0));
        const bool has_survivor = to_bool(PQgetvalue(probe.get(), 0, 1));

        const bool would_wipe = has_expired && !has_survivor;
        // Supplement to would_wipe: a half-window jump expires a large slice
        // while leaving survivors, which the cap bounds but nothing else reports.
        // Gated on window > 0 and strictly greater than the absolute floor.
        const bool big_step = prev.has_value() && window > 0 && has_expired &&
                              (pg_now - *prev) > kAuditMinBigStepSec;

        const audit_retention::Facts facts{.has_expired = has_expired,
                                           .would_wipe = would_wipe,
                                           .big_step = big_step,
                                           .prev_unusable = prev_unusable,
                                           .no_anchor = !bootstrap_settled};
        const audit_retention::Anomaly anomaly = audit_retention::classify(facts);
        const std::string facts_ser = serialize_facts(facts);

        // The pass has now REACHED A VERDICT, so settle the bootstrap marker —
        // and settle it HERE, not at the re-anchor above. The re-anchor happens
        // before the probes, so deriving the trigger from the stored reading
        // would let one transient probe failure spend it permanently: the next
        // pass would see a reading, call itself anchored, and delete with every
        // detector false — the exact defect #2579 closes. Every early return
        // above this line rolls the whole transaction back, so a pass that never
        // reached a verdict leaves the trigger armed.
        if (!bootstrap_settled) {
            pg::PgResult settle = pg::exec_params(
                conn,
                "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                "('bootstrap_settled', '1') ON CONFLICT (key) DO NOTHING",
                std::vector<std::string>{});
            if (settle.status() != PGRES_COMMAND_OK) {
                spdlog::error("AuditStore: reap bootstrap settle failed: {}", PQerrorMessage(conn));
                persist_failed = true;
                return false;
            }
        }

        if (anomaly != audit_retention::Anomaly::None) {
            // Decline-once per DISTINCT fact set: a new anomaly declines and
            // records; an identical repeat is suppressed and drains (paced by
            // the cap), so a legitimately all-expired store still ages out.
            if (facts_ser != last_facts) {
                pg::PgResult rec = pg::exec_params(
                    conn,
                    "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                    "('last_anomaly_facts', $1) ON CONFLICT (key) DO UPDATE SET value = "
                    "EXCLUDED.value",
                    std::vector<std::string>{facts_ser});
                if (rec.status() != PGRES_COMMAND_OK) {
                    spdlog::error("AuditStore: reap anomaly record failed: {}",
                                  PQerrorMessage(conn));
                    return false;
                }
                declined = true;
                // A missing-anchor decline is counted APART from the clock
                // anomalies (#2579). It asserts only that nothing can yet be
                // ruled out — a weaker claim than "the clock moved in a way that
                // would have wiped evidence", which is what the sibling counter's
                // alert says. Sharing the counter would make that alert's own
                // description untrue for this case and fire it on every server
                // carrying a backlog through an upgrade.
                declined_no_anchor = (anomaly == audit_retention::Anomaly::NoAnchor);
                decline_msg =
                    declined_no_anchor
                        ? std::string(
                              "AuditStore: no usable previous retention clock reading and rows are "
                              "already expired — declining this pass and anchoring; the next pass "
                              "has a comparison point and proceeds (#2579)")
                        : "AuditStore: retention clock anomaly (facts=" + facts_ser +
                              ") — declining this pass; an identical next pass will drain, capped";
                return true; // commit the stamp + anomaly record
            }
            // Suppressed repeat of the same fact set — fall through to drain.
        } else if (!last_facts.empty()) {
            pg::PgResult clr = pg::exec_params(
                conn, "DELETE FROM audit_store.audit_retention_meta WHERE key = 'last_anomaly_facts'",
                std::vector<std::string>{});
            if (clr.status() != PGRES_COMMAND_OK) {
                spdlog::error("AuditStore: reap anomaly clear failed: {}", PQerrorMessage(conn));
                return false;
            }
        }
        if (!has_expired)
            return true; // nothing to do

        // Bounded, oldest-first delete so even an allowed wipe ages out at a
        // paced rate. RETURNING carries the count (no sqlite3_changes()/#1033).
        pg::PgResult del = pg::exec_params(
            conn,
            "DELETE FROM audit_store.audit_events WHERE id IN (SELECT id FROM "
            "audit_store.audit_events WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint "
            "ORDER BY ttl_expires_at ASC, id ASC LIMIT $2::bigint) RETURNING id",
            std::vector<std::string>{std::to_string(pg_now),
                                     std::to_string(static_cast<std::int64_t>(
                                         kMaxAuditDeletesPerPass))});
        if (del.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: reap delete failed: {}", PQerrorMessage(conn));
            return false;
        }
        deleted = static_cast<std::size_t>(PQntuples(del.get()));

        // Hitting the cap does NOT prove a backlog remains (an exact-boundary
        // pass drained the last row). Probe for a real remainder, and ONLY when
        // the cap bound, so the healthy path pays nothing.
        if (deleted >= kMaxAuditDeletesPerPass) {
            pg::PgResult more = pg::exec_params(
                conn,
                "SELECT EXISTS(SELECT 1 FROM audit_store.audit_events WHERE ttl_expires_at > 0 AND "
                "ttl_expires_at < $1::bigint)",
                std::vector<std::string>{std::to_string(pg_now)});
            if (more.status() != PGRES_TUPLES_OK) {
                spdlog::error("AuditStore: reap backlog probe failed: {}", PQerrorMessage(conn));
                return false;
            }
            cap_backlog = to_bool(PQgetvalue(more.get(), 0, 0));
        }
        return true;
    });

    if (!ok) {
        if (persist_failed)
            persist_failed_.fetch_add(1, std::memory_order_relaxed);
        cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("AuditStore: retention pass aborted (statement failed or txn rolled back — "
                     "see the preceding error line)");
        return 0;
    }
    if (skipped_lock)
        return 0; // another replica swept this tick
    if (declined) {
        if (declined_no_anchor)
            bootstrap_declines_.fetch_add(1, std::memory_order_relaxed);
        else
            clock_anomaly_skips_.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("{}", decline_msg);
        return 0;
    }
    if (deleted > 0) {
        rows_deleted_.fetch_add(deleted, std::memory_order_relaxed);
        if (cap_backlog) {
            cap_reached_.fetch_add(1, std::memory_order_relaxed);
            spdlog::info("AuditStore: expired {} rows (per-pass cap reached; the remainder ages "
                         "out on subsequent passes)",
                         deleted);
        } else {
            spdlog::info("AuditStore: expired {} rows", deleted);
        }
    }
    return deleted;
}

void AuditStore::start_cleanup() {
    if (!open_ || cleanup_interval_min_ <= 0)
        return;
#ifdef __cpp_lib_jthread
    cleanup_thread_ = std::jthread([this](std::stop_token stop) { run_cleanup(stop); });
#else
    stop_requested_ = false;
    cleanup_thread_ = std::thread([this]() { run_cleanup(); });
#endif
}

void AuditStore::stop_cleanup() {
#ifdef __cpp_lib_jthread
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.request_stop();
        cleanup_thread_.join();
    }
#else
    stop_requested_ = true;
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
#endif
}

// `wait_s` is recomputed after every pass: the full interval normally, but
// kAuditBacklogRearmSec while the per-pass cap is BINDING and a real backlog
// remains. Draining at one capped pass per hour is what turns the cap into a
// permanent growth ceiling rather than a per-pass bound (see the constant).
// The signal is `cap_reached_` moving, which `cleanup_once` increments only when
// the cap bound AND its post-delete probe found a genuine remainder — so a
// declined pass, or an exact-boundary pass that drained the last row, returns to
// the full interval rather than spinning.
#ifdef __cpp_lib_jthread
void AuditStore::run_cleanup(std::stop_token stop) {
    int wait_s = cleanup_interval_min_ * 60;
    while (!stop.stop_requested()) {
        for (int i = 0; i < wait_s && !stop.stop_requested(); ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (stop.stop_requested())
            break;
#else
void AuditStore::run_cleanup() {
    int wait_s = cleanup_interval_min_ * 60;
    while (!stop_requested_.load()) {
        for (int i = 0; i < wait_s && !stop_requested_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (stop_requested_.load())
            break;
#endif
        const auto now = now_epoch();
        const uint64_t caps_before = cap_reached_.load(std::memory_order_relaxed);
        // NOTHING may escape a thread function: an exception here is
        // std::terminate. cleanup_once allocates and formats, so the surface is
        // real (#2037 class).
        try {
            cleanup_once(now);
        } catch (...) {
            cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
            try {
                try {
                    throw;
                } catch (const std::exception& e) {
                    spdlog::error("AuditStore: retention pass threw ({}); abandoned, retried at "
                                  "the next interval",
                                  e.what());
                } catch (...) {
                    spdlog::error("AuditStore: retention pass threw a non-std exception; "
                                  "abandoned, retried at the next interval");
                }
            } catch (...) {
                // Nothing escapes a thread function, not even a failure to report.
            }
        }
        wait_s = audit_next_wait_s(cap_reached_.load(std::memory_order_relaxed) > caps_before,
                                   cleanup_interval_min_);
    }
}

} // namespace yuzu::server
