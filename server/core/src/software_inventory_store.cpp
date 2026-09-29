#include "software_inventory_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "software_inventory_store";
constexpr const char* kSourceInstalledSoftware = "installed_software";

// Bounded acquires (ADR-0012 lease discipline). Ingest runs on the gRPC thread
// (direct ReportInventory / gateway ProxyInventory) so it must give up fast on a
// saturated pool — best-effort, the agent retries next cycle + weekly floor.
constexpr std::chrono::milliseconds kIngestAcquireTimeout{500};
constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};
// The stale-agents freshness gauge runs on the metrics sweep, whose serial
// budget is shared with security-relevant revocation teardown (server.cpp). Use
// a SHORT acquire — well under the ingest/query timeouts — so a saturated pool
// (the condition this gauge instruments) can never delay teardown; a degrade
// returns nullopt and the caller leaves the gauge at its previous value.
constexpr std::chrono::milliseconds kStaleCountAcquireTimeout{250};
// Hard ceiling on rows a single fleet query will materialise, independent of the
// caller's `limit`, so the store can never allocate an unbounded result set.
constexpr int kFleetQueryRowCap = 100000;
// Hard ceiling on catalogue / version-drill rows, independent of the caller's
// `limit`. The catalogue is one row per distinct title; the drill is one per
// distinct version of a title — both bounded sets.
constexpr int kCatalogRowCap = 2000;
// Execution BUDGET (not a guarantee) for the BACKGROUND catalogue recompute
// (refresh_catalog_rollup) — the single expensive full-table GROUP BY. It runs off the
// request path on the SoftwareCatalogRollup thread (the page never waits on it) and
// overrides the pool's 30s default for that one txn. 60s bounds BOTH the worst-case
// pooled-connection hold AND the shutdown-join stall (stop() can't cancel an in-flight
// statement, so the join waits up to this long). KEEP-LAST-GOOD on a timeout: the txn
// rolls back, the prior rollup + freshness stamp survive (the "as of" stamp ages, and
// yuzu_inventory_catalog_rollup_total{outcome="error"} increments). If a genuine 400k
// recompute ever exceeds 60s it stays "building"/stale until it fits — observable via the
// metrics; raise this then. The page READS hit the small precomputed tables, no bound.
constexpr const char* kRollupStatementTimeout = "60s";

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for the
    // migration transaction, so these tables land in `software_inventory_store`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         // Generic per-source parent (one row per agent+source). Source-agnostic
         // so future typed sources reuse it; the typed projection is the child.
         "CREATE TABLE inventory_state ("
         "  agent_id     TEXT NOT NULL,"
         "  source       TEXT NOT NULL,"
         "  content_hash TEXT NOT NULL DEFAULT '',"
         "  first_seen   BIGINT NOT NULL,"
         "  last_seen    BIGINT NOT NULL,"
         "  PRIMARY KEY (agent_id, source));"
         // Typed child for source #1. Machine-scope only (no per-user/PII).
         "CREATE TABLE installed_software ("
         "  agent_id     TEXT NOT NULL,"
         "  name         TEXT NOT NULL,"
         "  version      TEXT NOT NULL DEFAULT '',"
         "  publisher    TEXT NOT NULL DEFAULT '',"
         "  install_date TEXT NOT NULL DEFAULT '');"
         "CREATE INDEX installed_software_agent_idx ON installed_software (agent_id);"
         // Composite (name, agent_id): the flagship fleet query is
         // `WHERE name=$1 ORDER BY name, agent_id LIMIT N`. A single-column (name)
         // index satisfies the equality but forces a sort by agent_id before LIMIT
         // over the whole matching set (perf S-1); the composite serves equality AND
         // order → ordered index scan + early LIMIT termination. Leading `name`
         // subsumes the old single-column index, so the index count is unchanged.
         "CREATE INDEX installed_software_name_idx  ON installed_software (name, agent_id);"},
        {2,
         // (source, last_seen) serves the freshness count (count_stale_agents):
         // `WHERE source=$1 AND last_seen<$2`. Without it the count is a full
         // seq-scan of inventory_state on every metrics sweep; with it the count
         // is an index range scan touching only the stale rows — stale-proportional,
         // not fleet-proportional. This bounds the count's execution time on the
         // metrics-sweep thread that also runs the revocation-teardown backstop
         // (CH-IN3/UP-2), complementing the per-statement statement_timeout cap in
         // count_stale_agents. Leading `source` matches the equality predicate;
         // `last_seen` serves the range.
         "CREATE INDEX inventory_state_source_lastseen_idx "
         "ON inventory_state (source, last_seen);"},
        {3,
         // #1685 data-backfill. The WRITE fix (apply_installed_software now stamps
         // last_seen/first_seen with the server receipt time, not the agent's
         // collected_at) is forward-only: a dark agent can't re-stamp itself. Any
         // PRE-FIX row whose last_seen was written from a future-skewed agent clock
         // sits AHEAD of now and would never satisfy `last_seen < now − 2d`, so a
         // disappeared endpoint stays hidden from the freshness gauge forever (the
         // issue's exact worst case, persisting in live data). Clamp every future
         // timestamp down to now with LEAST — honest past/now values are untouched —
         // so those rows re-enter the staleness window (a fresh 2d grace from deploy,
         // after which a still-dark agent flags correctly). first_seen is clamped too
         // (governance UP-10): it was also seeded from collected_at pre-fix, so a
         // future content-age consumer could otherwise read now − first_seen as
         // negative; first_seen has no consumer today, this is forward defence.
         // NOTE: this one-time backfill uses the Postgres server clock (now()), while
         // the runtime write + the staleness cutoff (server.cpp) use the app-process
         // system_clock. Co-located / NTP-synced they agree; any residual app↔PG skew
         // is immaterial against the 2-day window (governance UP-1, NICE). DML, not
         // DDL — runs in the migration txn.
         "UPDATE inventory_state SET "
         "  last_seen  = LEAST(last_seen,  EXTRACT(EPOCH FROM now())::bigint), "
         "  first_seen = LEAST(first_seen, EXTRACT(EPOCH FROM now())::bigint) "
         "WHERE last_seen  > EXTRACT(EPOCH FROM now())::bigint "
         "   OR first_seen > EXTRACT(EPOCH FROM now())::bigint;"},
        {4,
         // Catalogue ROLLUP tables — the /inventory Software tab reads these precomputed
         // aggregates, NOT an on-demand GROUP BY (the underlying installed_software only
         // changes on the daily sync, so recomputing per page-load is wasteful + degrades
         // at fleet scale). A background thread refreshes them on a cadence via
         // refresh_catalog_rollup(); the page reads are cheap indexed scans of these small
         // tables. The rollup is FLEET-WIDE by construction — it cannot be per-operator
         // scoped (see the software_catalog header + ADR-0017): the catalogue MUST stay
         // global-gated.
         //   catalog_rollup   — one row per distinct title.
         //   version_rollup   — one row per (title, version).
         //   catalog_rollup_meta — single row (id=1): the freshness stamp + headline counts
         //     so the page never runs a COUNT either. refreshed_at=0 ⇒ never refreshed yet
         //     ("building"), distinct from a refreshed-but-empty fleet.
         // IF NOT EXISTS / ON CONFLICT DO NOTHING — idempotent so a partial-migration
         // retry (or a white-box schema_meta rewind in tests) re-runs cleanly.
         // UNIQUE(name) / UNIQUE(name,version): the rollup is keyed by title (and
         // version) — one row each. The unique constraint is LOAD-BEARING for
         // multi-instance safety (gov ARCH-1/UP-1): two server instances sharing one
         // Postgres both run their hourly recompute; without a unique key a racing
         // DELETE+INSERT under READ COMMITTED can leave DUPLICATE title rows (B's
         // pre-A-commit snapshot doesn't see A's rows to delete, then inserts its own).
         // The unique key makes the duplicate INSERT fail → that recompute rolls back →
         // keep-last-good. (refresh_catalog_rollup also takes a cluster-wide advisory
         // lock so the loser skips cleanly rather than churning a unique violation.)
         "CREATE TABLE IF NOT EXISTS catalog_rollup ("
         "  name          TEXT   NOT NULL,"
         "  publisher     TEXT   NOT NULL DEFAULT '',"
         "  device_count  BIGINT NOT NULL,"
         "  version_count BIGINT NOT NULL,"
         "  CONSTRAINT catalog_rollup_name_key UNIQUE (name));"
         "CREATE INDEX IF NOT EXISTS catalog_rollup_rank_idx "
         "ON catalog_rollup (device_count DESC, name);"
         "CREATE TABLE IF NOT EXISTS version_rollup ("
         "  name          TEXT   NOT NULL,"
         "  version       TEXT   NOT NULL DEFAULT '',"
         "  device_count  BIGINT NOT NULL,"
         "  CONSTRAINT version_rollup_nv_key UNIQUE (name, version));"
         "CREATE INDEX IF NOT EXISTS version_rollup_name_idx "
         "ON version_rollup (name, device_count DESC);"
         "CREATE TABLE IF NOT EXISTS catalog_rollup_meta ("
         "  id           INT    PRIMARY KEY,"
         "  refreshed_at BIGINT NOT NULL DEFAULT 0,"
         "  total_titles BIGINT NOT NULL DEFAULT 0,"
         "  total_devices BIGINT NOT NULL DEFAULT 0);"
         // Seed the singleton row with refreshed_at=0 so a read before the first refresh
         // returns the explicit "building" state, not an empty result.
         "INSERT INTO catalog_rollup_meta (id, refreshed_at, total_titles, total_devices) "
         "VALUES (1, 0, 0, 0) ON CONFLICT (id) DO NOTHING;"},
        {5,
         // Blob contract v2 (ADR-0016 Update): package-manager fields. All TEXT
         // NOT NULL DEFAULT '' — the "empty, never synthesised" contract maps
         // exactly to '' (and pg::to_text_array cannot emit SQL NULL). `epoch`
         // is TEXT, not INT: an integer column cannot represent "this ecosystem
         // stores no epoch" as ''. Constant defaults are metadata-only in PG11+
         // (no table rewrite), so this is safe on a live fleet table. Pre-v2
         // rows read back with '' in every new column until the agent's next
         // full resend (the one-time rekey herd) replaces them.
         "ALTER TABLE installed_software ADD COLUMN IF NOT EXISTS kind             TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE installed_software ADD COLUMN IF NOT EXISTS ecosystem        TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE installed_software ADD COLUMN IF NOT EXISTS epoch            TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE installed_software ADD COLUMN IF NOT EXISTS release          TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE installed_software ADD COLUMN IF NOT EXISTS arch             TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE installed_software ADD COLUMN IF NOT EXISTS signature_status TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE installed_software ADD COLUMN IF NOT EXISTS distro_id        TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE installed_software ADD COLUMN IF NOT EXISTS distro_version   TEXT NOT NULL DEFAULT '';"},
        {6,
         // (source, agent_id) serving index for list_agent_ids' keyset pager:
         // `WHERE source=$1 AND agent_id>$2 ORDER BY agent_id ASC LIMIT`. The PK is
         // (agent_id, source) — leading `agent_id` — so it CANNOT serve a `source=`
         // equality + `agent_id>` range; without this index the planner falls back
         // to a seq-scan of inventory_state + Filter + Sort on every page. Leading
         // `source` matches the equality and `agent_id` serves BOTH the `> $2`
         // keyset seek and the ORDER BY, so the plan becomes an Index-Cond ordered
         // scan with early LIMIT termination — per-page cost proportional to the
         // page, not the fleet. The PR-4 backfill loops this pager once per page,
         // so the difference is fleet-scale. IF NOT EXISTS → idempotent under a
         // white-box schema_meta rewind, matching migration v4's style.
         "CREATE INDEX IF NOT EXISTS inventory_state_source_agent_idx "
         "ON inventory_state (source, agent_id);"},
    };
    return kMigrations;
}

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// SHA-256 hex of a byte string (OpenSSL EVP one-shot). Kept local so the store
// has no dependency on AuthManager; identical bytes in → identical hex out as
// the agent's OpenSSL hash, which is what makes the hash-skip comparison work.
std::string sha256_hex(const std::string& in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return {};
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

// Sort/dedup key walks ALL v2 fields in blob order (name..distro_version) so
// two entries differing only in a v2 field are distinct rows, not duplicates.
// MUST mirror the agent's entry_less/entry_equal (sync_source_installed_software.cpp)
// or the two sides' canonical hashes diverge → permanent always-full.
bool entry_less(const SoftwareEntry& a, const SoftwareEntry& b) {
    if (a.name != b.name)
        return a.name < b.name;
    if (a.version != b.version)
        return a.version < b.version;
    if (a.publisher != b.publisher)
        return a.publisher < b.publisher;
    if (a.install_date != b.install_date)
        return a.install_date < b.install_date;
    if (a.kind != b.kind)
        return a.kind < b.kind;
    if (a.ecosystem != b.ecosystem)
        return a.ecosystem < b.ecosystem;
    if (a.epoch != b.epoch)
        return a.epoch < b.epoch;
    if (a.release != b.release)
        return a.release < b.release;
    if (a.arch != b.arch)
        return a.arch < b.arch;
    if (a.signature_status != b.signature_status)
        return a.signature_status < b.signature_status;
    if (a.distro_id != b.distro_id)
        return a.distro_id < b.distro_id;
    return a.distro_version < b.distro_version;
}

bool entry_equal(const SoftwareEntry& a, const SoftwareEntry& b) {
    return a.name == b.name && a.version == b.version && a.publisher == b.publisher &&
           a.install_date == b.install_date && a.kind == b.kind && a.ecosystem == b.ecosystem &&
           a.epoch == b.epoch && a.release == b.release && a.arch == b.arch &&
           a.signature_status == b.signature_status && a.distro_id == b.distro_id &&
           a.distro_version == b.distro_version;
}

// Sort + dedup in place so both the canonical hash and the persisted rows are
// order- and duplicate-independent (the 64-bit/WOW6432 hive can list a package
// twice; that is not a content change).
void normalize(std::vector<SoftwareEntry>& entries) {
    std::sort(entries.begin(), entries.end(), entry_less);
    entries.erase(std::unique(entries.begin(), entries.end(), entry_equal), entries.end());
}

// ── Read-degrade observability (#1675) ───────────────────────────────────────
// The authoritative reads return nullopt on a store/pool/query degrade, but
// /readyz stays green under pure pool saturation (it trips only on connection
// failure, to avoid false LB evictions), so a read-degrade is otherwise
// dashboard-invisible. These reason labels match the alert rule
// (YuzuInventoryReadDegraded) and the docs.
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
// Sample the per-site WARN: log a new outage episode's leading edge then every
// Nth within it. Under a sustained read outage at agentic fan-out (10k queries)
// an unsampled per-read WARN floods the log; the counter is the authoritative
// continuous signal, the log a sampled breadcrumb.
constexpr std::uint64_t kReadDegradeLogSample = 100;
// Quiet gap (seconds) after which the next degrade at a site is treated as a new
// outage EPISODE, re-logging its leading edge. Without this, process-lifetime
// sampling spends its one "1st" on the first-ever outage, so a second distinct
// outage (after recovery) stays silent until the next %N — its onset invisible
// (UP-6). The lifetime counter is never reset; this governs log fidelity only.
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

// Per-site degrade-WARN state: lifetime occurrence count + the last degrade's
// timestamp (for episode-boundary detection). One `static` instance per call
// site.
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};
struct DegradeLog {
    bool should_log;
    std::uint64_t occurrence;
};

// Parse a Postgres text-format integer cell into int64 (count(*) etc. are text on
// the wire). Mirrors the count_stale_agents from_chars pattern.
std::int64_t result_i64(const pg::PgResult& res, int row, int col) {
    const char* txt = PQgetvalue(res.get(), row, col);
    const auto len = static_cast<std::size_t>(PQgetlength(res.get(), row, col));
    std::int64_t v = 0;
    std::from_chars(txt, txt + len, v); // leaves v=0 on parse failure (count cells never fail)
    return v;
}

// Bump the read-degrade counter (always), advance the sampler, and decide whether
// this degrade should emit a sampled WARN: the leading edge of a new episode, or
// every Nth within one. The count/timestamp updates are two independent atomics,
// so under concurrent degrades at one site a benign duplicate leading-edge WARN
// is possible — acceptable for a log breadcrumb; the counter stays exact.
DegradeLog note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason,
                             DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_inventory_read_degrade_total",
                         {{"reason", reason}, {"source", "installed_software"}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return {new_episode || (n % kReadDegradeLogSample) == 0, n};
}

} // namespace

std::string SoftwareInventoryStore::canonical_hash(std::vector<SoftwareEntry> entries) {
    normalize(entries);
    // Blob contract v2: 12 fields, 0x1F-separated, in this exact order, record-
    // terminated 0x1E — byte-identical to the agent's canonical blob builder
    // (installed_software_canonical_blob). The v1→v2 reformat is the one-time
    // rekey herd: even all-empty new fields add separators, so every stored v1
    // hash mismatches on the first post-upgrade report (need_full, self-heals).
    std::string canon;
    canon.reserve(entries.size() * 96);
    for (const auto& e : entries) {
        canon += e.name;
        canon += '\x1f';
        canon += e.version;
        canon += '\x1f';
        canon += e.publisher;
        canon += '\x1f';
        canon += e.install_date;
        canon += '\x1f';
        canon += e.kind;
        canon += '\x1f';
        canon += e.ecosystem;
        canon += '\x1f';
        canon += e.epoch;
        canon += '\x1f';
        canon += e.release;
        canon += '\x1f';
        canon += e.arch;
        canon += '\x1f';
        canon += e.signature_status;
        canon += '\x1f';
        canon += e.distro_id;
        canon += '\x1f';
        canon += e.distro_version;
        canon += '\x1e';
    }
    return sha256_hex(canon);
}

SoftwareInventoryStore::SoftwareInventoryStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("SoftwareInventoryStore: no database connection at construction ({}) — "
                      "software inventory persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("SoftwareInventoryStore: schema migration failed — software inventory "
                      "persistence disabled");
        return;
    }
    open_ = true;
}

InventoryIngestOutcome SoftwareInventoryStore::apply_installed_software(
    std::string_view agent_id, std::string_view claimed_hash,
    std::optional<std::vector<SoftwareEntry>> rows, [[maybe_unused]] std::int64_t collected_at) {
    if (!open_ || agent_id.empty())
        return InventoryIngestOutcome::kError;

    // last_seen / first_seen are the SERVER receipt time, NOT the agent-supplied
    // collected_at. The stale-agents freshness gauge compares last_seen against
    // `server_now − 2d` (server.cpp), so both sides of that comparison must be on
    // ONE clock; trusting collected_at let a future-skewed or hostile agent pin
    // last_seen ahead of now so it never counted as stale — hiding a dark endpoint
    // (#1685, ADR-0016 Update 2026-06-27). collected_at stays in the ingest
    // contract (proto-carried) but no longer drives any persisted timestamp;
    // migration v3 clamps pre-fix rows whose last_seen was stamped into the future.
    const std::int64_t ts = now_secs();

    // ── Hash-only report: compare against the stored (server-recomputed) hash ──
    if (!rows.has_value()) {
        auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
        if (!lease) {
            spdlog::warn("SoftwareInventoryStore: hash-only ingest skipped for agent={}, no "
                         "connection ({})",
                         agent_id, pool_.last_error());
            return InventoryIngestOutcome::kError;
        }
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "SELECT content_hash FROM software_inventory_store.inventory_state "
            "WHERE agent_id = $1 AND source = $2",
            std::vector<std::string>{std::string(agent_id), kSourceInstalledSoftware});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::warn("SoftwareInventoryStore: hash lookup failed for agent={}: {}", agent_id,
                         PQerrorMessage(lease.get()));
            return InventoryIngestOutcome::kError;
        }
        if (PQntuples(res.get()) == 0)
            return InventoryIngestOutcome::kNeedFull; // cold cache: nothing to match
        const std::string stored = PQgetvalue(res.get(), 0, 0);
        if (stored != std::string(claimed_hash))
            return InventoryIngestOutcome::kNeedFull; // drifted: ask for the full list
        // Match — bump last_seen only (RETURNING carries the result, #1033).
        pg::PgResult upd = pg::exec_params(
            lease.get(),
            "UPDATE software_inventory_store.inventory_state SET last_seen = $3::bigint "
            "WHERE agent_id = $1 AND source = $2 RETURNING agent_id",
            std::vector<std::string>{std::string(agent_id), kSourceInstalledSoftware,
                                     std::to_string(ts)});
        if (upd.status() != PGRES_TUPLES_OK) {
            spdlog::warn("SoftwareInventoryStore: last_seen bump failed for agent={}: {}", agent_id,
                         PQerrorMessage(lease.get()));
            return InventoryIngestOutcome::kError;
        }
        return InventoryIngestOutcome::kTouched;
    }

    // ── Full payload: recompute the hash from the rows, replace atomically ─────
    // Move out of the by-value optional — no copy of the (up to kMaxEntries) rows.
    std::vector<SoftwareEntry> entries = std::move(*rows);
    normalize(entries);
    const std::string server_hash = SoftwareInventoryStore::canonical_hash(entries);
    const std::string agent_id_s{agent_id};

    const bool ok = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        // Serialise concurrent full-replaces for THIS agent. Without it, two
        // in-flight fulls for one agent_id under READ COMMITTED interleave: txn B's
        // DELETE cannot see txn A's freshly-inserted rows, so A's and B's rows both
        // survive and the parent content_hash matches neither (governance UP-IN2/3,
        // reachable when a slow ingest outlives the agent's 30s client deadline and
        // the scheduler retries). The lock is transaction-scoped (auto-released at
        // COMMIT/ROLLBACK); distinct agents hash to distinct keys, so steady-state
        // contention is nil. hashtextextended() gives a native 64-bit key (vs the
        // 32-bit hashtext) so cross-agent false contention is negligible (gov fjarvis
        // LOW); correctness never depended on it (the DELETE+INSERT is agent-scoped).
        //
        // Blocking (not try_) on purpose: same-agent contention is the rare
        // post-restart-retry case; the loser WAITS for the winner to commit, then
        // does its own clean replace → outcome="stored", no alert noise. A
        // try-lock would return kError on benign contention and trip
        // YuzuInventorySustainedIngestErrors (gov Gate-8 advisor — the error/alert
        // taxonomy is sre's gate, out of scope for this round). The wait is
        // transaction-scoped + bounded by the pool's statement_timeout; a distinct
        // "contended" outcome label is the right pool-hygiene follow-up.
        pg::PgResult lk = pg::exec_params(c, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                                          std::vector<std::string>{agent_id_s});
        if (lk.status() != PGRES_TUPLES_OK)
            return false;
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM software_inventory_store.installed_software WHERE agent_id = $1",
            std::vector<std::string>{agent_id_s});
        if (del.status() != PGRES_COMMAND_OK)
            return false;
        // Batched insert (#1664): one statement carrying the per-row columns as
        // four parallel text[] arrays — agent_id is the scalar $1, so the param
        // count is a constant 5 regardless of row count. A multi-row VALUES would
        // hit libpq's 65535-parameter ceiling at ~13k rows (5 params/row); up to
        // kMaxEntries (20k) rows arrive here. unnest() pairs the arrays
        // positionally and they are equal-length by construction. Collapsing up
        // to 20k single-row INSERTs into one statement shrinks the transaction's
        // connection-hold + statement_timeout exposure, which is the UP-IN4/5
        // pool-saturation blast (a need_full herd flipping healthy agents
        // touched→full) this change targets. Skip entirely when empty (a
        // legitimate empty inventory): the DELETE above already cleared the rows.
        if (!entries.empty()) {
            // One parallel text[] per column (blob-order, v2 = 12 columns).
            std::vector<std::string_view> cols[12];
            for (auto& col : cols)
                col.reserve(entries.size());
            for (const auto& e : entries) {
                cols[0].emplace_back(e.name);
                cols[1].emplace_back(e.version);
                cols[2].emplace_back(e.publisher);
                cols[3].emplace_back(e.install_date);
                cols[4].emplace_back(e.kind);
                cols[5].emplace_back(e.ecosystem);
                cols[6].emplace_back(e.epoch);
                cols[7].emplace_back(e.release);
                cols[8].emplace_back(e.arch);
                cols[9].emplace_back(e.signature_status);
                cols[10].emplace_back(e.distro_id);
                cols[11].emplace_back(e.distro_version);
            }
            // push_back (not a braced init-list) so each large to_text_array
            // prvalue is MOVED into params, not copied — an init_list's backing
            // array is `const std::string[]`, forcing copies of these up-to-MB
            // literals on the hot path (cpp-expert). Param count is a constant
            // 13 ($1 scalar agent_id + 12 arrays) regardless of row count.
            std::vector<std::string> params;
            params.reserve(13);
            params.push_back(agent_id_s);
            for (const auto& col : cols)
                params.push_back(pg::to_text_array(col));
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO software_inventory_store.installed_software "
                "(agent_id, name, version, publisher, install_date, kind, ecosystem, epoch, "
                "release, arch, signature_status, distro_id, distro_version) "
                "SELECT $1, n, v, p, d, k, e, ep, r, a, s, di, dv "
                "FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], "
                "$7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::text[], "
                "$13::text[]) AS t(n, v, p, d, k, e, ep, r, a, s, di, dv)",
                params);
            if (ins.status() != PGRES_COMMAND_OK)
                return false;
        }
        // Upsert parent: $4 seeds first_seen on insert; on conflict keep
        // first_seen, refresh content_hash + last_seen.
        pg::PgResult par = pg::exec_params(
            c,
            "INSERT INTO software_inventory_store.inventory_state "
            "(agent_id, source, content_hash, first_seen, last_seen) "
            "VALUES ($1, $2, $3, $4::bigint, $4::bigint) "
            "ON CONFLICT (agent_id, source) DO UPDATE SET "
            "  content_hash = EXCLUDED.content_hash, last_seen = EXCLUDED.last_seen "
            "RETURNING agent_id",
            std::vector<std::string>{agent_id_s, kSourceInstalledSoftware, server_hash,
                                     std::to_string(ts)});
        return par.status() == PGRES_TUPLES_OK;
    });
    if (!ok) {
        spdlog::warn("SoftwareInventoryStore: full ingest transaction failed for agent={}",
                     agent_id);
        return InventoryIngestOutcome::kError;
    }
    return InventoryIngestOutcome::kStored;
}

std::optional<std::int64_t> SoftwareInventoryStore::source_last_seen(std::string_view agent_id,
                                                                     std::string_view source) {
    // AUTHORITATIVE read (ADR-0016 §7): a degrade returns nullopt, never a silent 0.
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: source_last_seen degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    if (agent_id.empty() || source.empty())
        return 0;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: source_last_seen degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT last_seen FROM software_inventory_store.inventory_state "
        "WHERE agent_id = $1 AND source = $2",
        std::vector<std::string>{std::string(agent_id), std::string(source)});
    if (!res.ok()) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: source_last_seen degraded — query failed: {} "
                         "(occurrence {})",
                         PQresultErrorMessage(res.get()), d.occurrence);
        return std::nullopt;
    }
    if (PQntuples(res.get()) == 0)
        return 0;
    return std::strtoll(PQgetvalue(res.get(), 0, 0), nullptr, 10);
}

std::optional<std::vector<SoftwareEntry>>
SoftwareInventoryStore::get_agent_software(std::string_view agent_id) {
    // AUTHORITATIVE read (ADR-0016 §7): a degrade returns nullopt, never a silent
    // empty. !open_ / no-lease / query-error are degrades; an empty agent_id is a
    // precondition miss (genuine empty, not a degrade).
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: get_agent_software degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    std::vector<SoftwareEntry> out;
    if (agent_id.empty())
        return out;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: get_agent_software degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT name, version, publisher, install_date, kind, ecosystem, epoch, release, "
        "arch, signature_status, distro_id, distro_version "
        "FROM software_inventory_store.installed_software "
        "WHERE agent_id = $1 ORDER BY name, version LIMIT $2::bigint",
        std::vector<std::string>{std::string(agent_id), std::to_string(kFleetQueryRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: get_agent_software degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        SoftwareEntry e;
        e.name = PQgetvalue(res.get(), i, 0);
        e.version = PQgetvalue(res.get(), i, 1);
        e.publisher = PQgetvalue(res.get(), i, 2);
        e.install_date = PQgetvalue(res.get(), i, 3);
        e.kind = PQgetvalue(res.get(), i, 4);
        e.ecosystem = PQgetvalue(res.get(), i, 5);
        e.epoch = PQgetvalue(res.get(), i, 6);
        e.release = PQgetvalue(res.get(), i, 7);
        e.arch = PQgetvalue(res.get(), i, 8);
        e.signature_status = PQgetvalue(res.get(), i, 9);
        e.distro_id = PQgetvalue(res.get(), i, 10);
        e.distro_version = PQgetvalue(res.get(), i, 11);
        out.push_back(std::move(e));
    }
    return out;
}

std::optional<std::vector<SoftwareFleetRow>>
SoftwareInventoryStore::query_software(const SoftwareFleetQuery& q) {
    // AUTHORITATIVE read (ADR-0016 §7): a store/pool/query failure returns nullopt
    // (degraded), never a silent empty — a fleet vuln query must not read a PG hiccup
    // as "installed nowhere". An empty value = genuinely no matches.
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: query_software degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: query_software degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    int limit = q.limit > 0 ? q.limit : 1000;
    if (limit > kFleetQueryRowCap)
        limit = kFleetQueryRowCap;

    std::string sql =
        "SELECT agent_id, name, version, publisher, install_date, kind, ecosystem, epoch, "
        "release, arch, signature_status, distro_id, distro_version "
        "FROM software_inventory_store.installed_software WHERE 1=1";
    std::vector<std::string> params;
    int p = 0;
    if (!q.agent_id.empty()) {
        sql += " AND agent_id = $" + std::to_string(++p);
        params.push_back(q.agent_id);
    }
    if (!q.name.empty()) {
        sql += " AND name = $" + std::to_string(++p);
        params.push_back(q.name);
    }
    sql += " ORDER BY name, agent_id LIMIT $" + std::to_string(++p) + "::bigint";
    params.push_back(std::to_string(limit));
    // No OFFSET: offset-paging over a fleet table that mutates on sync cadence, with
    // the scope filter applied after LIMIT, yields unstable/duplicating windows
    // (gov consistency N1). Complete >cap collection is the keyset follow-up (#1634).

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: query_software degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    std::vector<SoftwareFleetRow> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        SoftwareFleetRow row;
        row.agent_id = PQgetvalue(res.get(), i, 0);
        row.entry.name = PQgetvalue(res.get(), i, 1);
        row.entry.version = PQgetvalue(res.get(), i, 2);
        row.entry.publisher = PQgetvalue(res.get(), i, 3);
        row.entry.install_date = PQgetvalue(res.get(), i, 4);
        row.entry.kind = PQgetvalue(res.get(), i, 5);
        row.entry.ecosystem = PQgetvalue(res.get(), i, 6);
        row.entry.epoch = PQgetvalue(res.get(), i, 7);
        row.entry.release = PQgetvalue(res.get(), i, 8);
        row.entry.arch = PQgetvalue(res.get(), i, 9);
        row.entry.signature_status = PQgetvalue(res.get(), i, 10);
        row.entry.distro_id = PQgetvalue(res.get(), i, 11);
        row.entry.distro_version = PQgetvalue(res.get(), i, 12);
        out.push_back(std::move(row));
    }
    return out;
}

std::optional<std::vector<SoftwareCatalogRow>>
SoftwareInventoryStore::software_catalog(const SoftwareCatalogQuery& q) {
    // AUTHORITATIVE read of the PRECOMPUTED catalog_rollup — a cheap indexed scan of a
    // small table, NOT an on-demand GROUP BY (refresh_catalog_rollup writes it on a
    // cadence). FLEET-WIDE (global rollup; caller gates GLOBAL Inventory:Read). nullopt on
    // degrade, never a silent empty; an empty value = the rollup has no rows (pair with
    // catalog_rollup_meta() to tell "building" from a genuinely empty fleet).
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: software_catalog degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    int limit = q.limit > 0 ? q.limit : 200;
    if (limit > kCatalogRowCap)
        limit = kCatalogRowCap;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: software_catalog degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    // Cheap read of the rollup. ILIKE '%'||$n||'%' is the optional case-insensitive
    // filter, matched against EITHER title or publisher (round-3 item 8 — a search
    // for "adobe" should surface every Adobe title, not just ones with "adobe" in
    // the name) — ONE bind reused in both arms (Postgres allows repeating a
    // parameter placeholder), never two separate params for the same input. Over a
    // small (one-row-per-title) table the scan+sort is trivial either way.
    std::string sql = "SELECT name, publisher, device_count, version_count "
                      "FROM software_inventory_store.catalog_rollup ";
    std::vector<std::string> params;
    int p = 0;
    if (!q.name_filter.empty()) {
        const std::string ph = "$" + std::to_string(++p);
        sql += "WHERE (name ILIKE '%' || " + ph + " || '%' OR publisher ILIKE '%' || " + ph +
              " || '%') ";
        params.push_back(q.name_filter);
    }
    sql += "ORDER BY device_count DESC, name LIMIT $" + std::to_string(++p) + "::bigint";
    params.push_back(std::to_string(limit));
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: software_catalog degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    std::vector<SoftwareCatalogRow> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        SoftwareCatalogRow r;
        r.name = PQgetvalue(res.get(), i, 0);
        r.publisher = PQgetvalue(res.get(), i, 1);
        r.device_count = result_i64(res, i, 2);
        r.version_count = result_i64(res, i, 3);
        out.push_back(std::move(r));
    }
    return out;
}

std::optional<std::vector<SoftwareVersionCount>>
SoftwareInventoryStore::software_versions(std::string_view name, int limit) {
    // AUTHORITATIVE read of the precomputed version_rollup (title-scoped, name index). An
    // empty name is a precondition miss → empty value, not a degrade.
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: software_versions degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    if (name.empty())
        return std::vector<SoftwareVersionCount>{};
    int lim = limit > 0 ? limit : 200;
    if (lim > kCatalogRowCap)
        lim = kCatalogRowCap;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: software_versions degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT version, device_count FROM software_inventory_store.version_rollup "
        "WHERE name = $1 ORDER BY device_count DESC, version LIMIT $2::bigint",
        std::vector<std::string>{std::string(name), std::to_string(lim)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: software_versions degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    std::vector<SoftwareVersionCount> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        SoftwareVersionCount v;
        v.version = PQgetvalue(res.get(), i, 0);
        v.device_count = result_i64(res, i, 1);
        out.push_back(std::move(v));
    }
    return out;
}

bool SoftwareInventoryStore::refresh_catalog_rollup() {
    if (!open_)
        return false;
    // ONE transaction: bound execution with a GENEROUS background statement_timeout,
    // recompute both rollup tables + the meta from installed_software, atomic replace.
    // KEEP-LAST-GOOD: any lease/SQL failure (incl. timeout) returns false → with_txn_for
    // ROLLs back → the prior rollup + freshness stamp survive untouched.
    return pool_.with_txn_for(kQueryAcquireTimeout, [&](PGconn* c) -> bool {
        pg::PgResult t = pg::exec_params(c, std::string("SET LOCAL statement_timeout = '")
                                                .append(kRollupStatementTimeout)
                                                .append("'")
                                                .c_str(),
                                         std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK)
            return false;
        // Cluster-wide serialization (gov ARCH-1/UP-1): on a multi-instance shared-PG
        // deploy, only one server recomputes the SHARED rollup at a time. try_ (not
        // blocking): if a peer holds the lock it is already recomputing the shared table,
        // so this instance SKIPS — not a failure (the rollup will be fresh via the peer),
        // avoiding a redundant recompute AND the unique-violation churn two racing
        // DELETE+INSERTs would otherwise produce. Transaction-scoped → auto-released at
        // COMMIT/ROLLBACK and self-healing if the holder dies. The UNIQUE constraints on
        // the rollup tables are the belt-and-braces correctness backstop behind this lock.
        pg::PgResult lk =
            pg::exec_params(c,
                            "SELECT pg_try_advisory_xact_lock(hashtextextended('"
                            "software_catalog_rollup', 0))",
                            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK)
            return false;
        if (PQntuples(lk.get()) == 1 && std::string_view(PQgetvalue(lk.get(), 0, 0)) == "f")
            return true; // a peer instance is refreshing the shared rollup — skip, success
        // catalog_rollup: one row per title (device_count, version_count). max(publisher)
        // picks a representative when a title carries >1 publisher across the fleet.
        if (pg::exec_params(c, "DELETE FROM software_inventory_store.catalog_rollup",
                            std::vector<std::string>{})
                .status() != PGRES_COMMAND_OK)
            return false;
        if (pg::exec_params(
                c,
                "INSERT INTO software_inventory_store.catalog_rollup "
                "(name, publisher, device_count, version_count) "
                "SELECT name, max(publisher), count(DISTINCT agent_id), count(DISTINCT version) "
                "FROM software_inventory_store.installed_software GROUP BY name",
                std::vector<std::string>{})
                .status() != PGRES_COMMAND_OK)
            return false;
        // version_rollup: one row per (title, version).
        if (pg::exec_params(c, "DELETE FROM software_inventory_store.version_rollup",
                            std::vector<std::string>{})
                .status() != PGRES_COMMAND_OK)
            return false;
        if (pg::exec_params(
                c,
                "INSERT INTO software_inventory_store.version_rollup (name, version, device_count) "
                "SELECT name, version, count(DISTINCT agent_id) "
                "FROM software_inventory_store.installed_software GROUP BY name, version",
                std::vector<std::string>{})
                .status() != PGRES_COMMAND_OK)
            return false;
        // meta: server receipt clock (now()), titles from the just-built rollup, devices
        // from the source table. RETURNING to carry the result (no sqlite3_changes-style
        // count needed; #1033 idiom).
        pg::PgResult m = pg::exec_params(
            c,
            "INSERT INTO software_inventory_store.catalog_rollup_meta "
            "(id, refreshed_at, total_titles, total_devices) "
            "VALUES (1, EXTRACT(EPOCH FROM now())::bigint, "
            "  (SELECT count(*) FROM software_inventory_store.catalog_rollup), "
            "  (SELECT count(DISTINCT agent_id) FROM software_inventory_store.installed_software)) "
            "ON CONFLICT (id) DO UPDATE SET refreshed_at = EXCLUDED.refreshed_at, "
            "  total_titles = EXCLUDED.total_titles, total_devices = EXCLUDED.total_devices "
            "RETURNING id",
            std::vector<std::string>{});
        return m.status() == PGRES_TUPLES_OK;
    });
}

std::optional<CatalogRollupMeta> SoftwareInventoryStore::catalog_rollup_meta() {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: catalog_rollup_meta degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: catalog_rollup_meta degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT refreshed_at, total_titles, total_devices "
        "FROM software_inventory_store.catalog_rollup_meta WHERE id = 1",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareInventoryStore: catalog_rollup_meta degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    CatalogRollupMeta m; // migration seeds id=1 with refreshed_at=0; default if absent.
    if (PQntuples(res.get()) == 1) {
        m.refreshed_at = result_i64(res, 0, 0);
        m.total_titles = result_i64(res, 0, 1);
        m.total_devices = result_i64(res, 0, 2);
    }
    return m;
}

bool SoftwareInventoryStore::delete_agent(std::string_view agent_id) {
    if (!open_ || agent_id.empty())
        return false;
    const std::string id{agent_id};
    // Both deletes in one transaction so an agent removal can't leave a parent
    // inventory_state row without its child rows, or vice versa (Gate 2 INFO).
    const bool committed = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        pg::PgResult d1 = pg::exec_params(
            c, "DELETE FROM software_inventory_store.installed_software WHERE agent_id = $1",
            std::vector<std::string>{id});
        pg::PgResult d2 = pg::exec_params(
            c, "DELETE FROM software_inventory_store.inventory_state WHERE agent_id = $1",
            std::vector<std::string>{id});
        return d1.status() == PGRES_COMMAND_OK && d2.status() == PGRES_COMMAND_OK;
    });
    if (!committed)
        spdlog::debug("SoftwareInventoryStore: delete_agent did not commit for agent={} ({})",
                      agent_id, pool_.last_error());
    return committed;
}

std::vector<std::string> SoftwareInventoryStore::list_agent_ids(std::string_view source,
                                                               std::string_view after_id,
                                                               int limit) {
    // KEYSET page over inventory_state for one source. The (agent_id, source) PK
    // makes agent_id unique per source, so a plain `agent_id > $2 ORDER BY
    // agent_id ASC LIMIT` walks the fleet with no DISTINCT and no unstable OFFSET.
    // The (source, agent_id) index (migration v6) is the SERVING index for this
    // plan: the PK leads with agent_id and so cannot seek on the `source=` equality
    // — v6 makes `agent_id > $2` an Index Cond seek + ordered scan (verified via
    // EXPLAIN) rather than a seq-scan + Filter + Sort. Bounded lease; empty on
    // !open_ / no-lease / query error (degrade).
    std::vector<std::string> out;
    if (!open_ || source.empty())
        return out;
    int cap = limit > 0 ? limit : 1000;
    if (cap > kFleetQueryRowCap)
        cap = kFleetQueryRowCap;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease)
        return out;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id FROM software_inventory_store.inventory_state "
        "WHERE source = $1 AND agent_id > $2 ORDER BY agent_id ASC LIMIT $3::bigint",
        std::vector<std::string>{std::string(source), std::string(after_id), std::to_string(cap)});
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.emplace_back(PQgetvalue(res.get(), i, 0));
    return out;
}

std::optional<std::int64_t>
SoftwareInventoryStore::count_stale_agents(std::int64_t stale_before_secs) {
    if (!open_)
        return std::nullopt;
    std::optional<std::int64_t> result;
    // Run inside a txn so a `SET LOCAL statement_timeout` caps the count's
    // EXECUTION, not merely the lease acquire. This runs on the metrics-sweep
    // thread that next runs the revocation-teardown backstop (server.cpp), so a
    // bloated-table seq-scan must NOT be allowed to run to the pool's 30s
    // statement_timeout (CH-IN3/UP-2) — the 250ms acquire bounds only the wait
    // for a connection, never the query. SET LOCAL reverts at COMMIT/ROLLBACK; a
    // timeout makes the SELECT error → with_txn_for ROLLs back → nullopt → the
    // caller holds the gauge at its prior value. The (source,last_seen) index
    // (migration v2) keeps the steady-state plan an index scan so the cap is
    // never reached; the cap defends against bloat / plan regression.
    pool_.with_txn_for(kStaleCountAcquireTimeout, [&](PGconn* c) -> bool {
        pg::PgResult t = pg::exec_params(c, "SET LOCAL statement_timeout = '250ms'",
                                         std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK)
            return false;
        pg::PgResult res = pg::exec_params(
            c,
            "SELECT count(*) FROM software_inventory_store.inventory_state "
            "WHERE source = $1 AND last_seen < $2::bigint",
            std::vector<std::string>{kSourceInstalledSoftware, std::to_string(stale_before_secs)});
        if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
            return false;
        const char* txt = PQgetvalue(res.get(), 0, 0);
        const auto len = static_cast<std::size_t>(PQgetlength(res.get(), 0, 0));
        std::int64_t count = 0;
        if (std::from_chars(txt, txt + len, count).ec != std::errc{})
            return false;
        result = count;
        return true;
    });
    return result;
}

} // namespace yuzu::server
