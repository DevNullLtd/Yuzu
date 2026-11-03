#include "product_registry_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_normalization_pack.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "product_registry_store";

// Bounded acquires (ADR-0012 lease discipline). Nothing here runs on the gRPC
// ingest hot path: writes come from the background evaluator's matcher pass,
// reads from dashboard/REST requests — both can wait a little, neither may
// block unboundedly on a saturated pool.
constexpr std::chrono::milliseconds kAcquireTimeout{3000};
// Hard ceiling on rows a single list read will materialise, independent of the
// caller's `limit`, so the store can never allocate an unbounded result set.
// The registry is one row per distinct product — a bounded set in practice.
constexpr int kListRowCap = 20000;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so these tables land in
    // `product_registry_store`. Runtime statements below schema-qualify
    // explicitly. v2 is the SAM.4 normalisation layer; the product_tags
    // migration (PR4) is the next version, not part of v2.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         // Canonical product identities (roadmap §7.1). norm_key is the
         // deterministic product_normalize key — UNIQUE is load-bearing: the
         // upsert keys on it, and two evaluator instances racing the same
         // birth converge on one row (the loser's INSERT conflicts → DO
         // UPDATE). Timestamps are server receipt time (epoch seconds).
         "CREATE TABLE products ("
         "  product_id BIGSERIAL PRIMARY KEY,"
         "  norm_key   TEXT NOT NULL UNIQUE,"
         "  vendor     TEXT NOT NULL DEFAULT '',"
         "  title      TEXT NOT NULL DEFAULT '',"
         "  edition    TEXT NOT NULL DEFAULT '',"
         "  platform   TEXT NOT NULL DEFAULT '',"
         "  created_at BIGINT NOT NULL,"
         "  updated_at BIGINT NOT NULL);"
         // Match links (ADR-0024 Decision 6): how each raw (source, name,
         // publisher) triple resolved onto a canonical row. Same-schema FK
         // ON DELETE CASCADE (cross-schema FKs are banned — ADR-0024
         // Decision 4; within one store's schema they are the normal tool):
         // curating away a product row drops its stale links atomically.
         "CREATE TABLE product_aliases ("
         "  source           TEXT NOT NULL,"
         "  raw_name         TEXT NOT NULL,"
         "  raw_publisher    TEXT NOT NULL,"
         "  product_id       BIGINT NOT NULL REFERENCES products (product_id) ON DELETE CASCADE,"
         "  method           TEXT NOT NULL DEFAULT '',"
         "  confidence       DOUBLE PRECISION NOT NULL DEFAULT 0,"
         "  first_matched_at BIGINT NOT NULL,"
         "  last_seen_at     BIGINT NOT NULL,"
         "  PRIMARY KEY (source, raw_name, raw_publisher));"
         // The reverse lookup ("which raw names map onto this product") — the
         // posture rollup's install_count join walks aliases by product_id.
         "CREATE INDEX product_aliases_product_idx ON product_aliases (product_id);"},
        {2,
         // SAM.4 software-title normalisation layer. ONLINE: every ALTER adds a
         // constant-default column (metadata-only, no table rewrite, the same
         // precedent as software_inventory_store's additive columns) and every
         // CREATE TABLE is a new empty table, so nothing here needs a rewrite or
         // CREATE INDEX CONCURRENTLY.
         "ALTER TABLE products "
         "  ADD COLUMN IF NOT EXISTS purl_type   TEXT NOT NULL DEFAULT '',"
         "  ADD COLUMN IF NOT EXISTS cpe_product TEXT NOT NULL DEFAULT '',"
         "  ADD COLUMN IF NOT EXISTS origin      TEXT NOT NULL DEFAULT 'matcher',"
         "  ADD COLUMN IF NOT EXISTS category    TEXT NOT NULL DEFAULT 'other';"
         "ALTER TABLE product_aliases "
         "  ADD COLUMN IF NOT EXISTS status       TEXT NOT NULL DEFAULT 'active',"
         "  ADD COLUMN IF NOT EXISTS pack_version TEXT NOT NULL DEFAULT '';"
         // The one loaded alias pack (id pinned to 1: a singleton).
         "CREATE TABLE normalization_pack ("
         "  id           INT PRIMARY KEY CHECK (id = 1),"
         "  pack_version TEXT NOT NULL,"
         "  sha256       TEXT NOT NULL,"
         "  body         TEXT NOT NULL,"
         "  loaded_by    TEXT NOT NULL,"
         "  loaded_at    BIGINT NOT NULL);"
         // The permanent title dimension: one row per distinct installed-software
         // (raw_name, raw_publisher, ecosystem) triple. product_id is nullable
         // with ON DELETE SET NULL (curating a product away must not leave a
         // dangling identity); a 'normalized' row with a NULL product is re-queued.
         // pack_version = '' is the stale sentinel (see the header).
         "CREATE TABLE title_dimension ("
         "  raw_name       TEXT NOT NULL,"
         "  raw_publisher  TEXT NOT NULL,"
         "  ecosystem      TEXT NOT NULL,"
         "  norm_status    TEXT NOT NULL CHECK (norm_status IN ('normalized', 'unnormalized')),"
         "  method         TEXT NOT NULL DEFAULT '' "
         "                 CHECK (method IN ('', 'curated', 'pack', 'exact_norm', 'birth')),"
         "  product_id     BIGINT REFERENCES products (product_id) ON DELETE SET NULL,"
         "  vendor         TEXT NOT NULL DEFAULT '',"
         "  product        TEXT NOT NULL DEFAULT '',"
         "  edition        TEXT NOT NULL DEFAULT '',"
         "  title_version  TEXT NOT NULL DEFAULT '',"
         "  category       TEXT NOT NULL DEFAULT 'other' CHECK (category IN "
         "                 ('web_server', 'database', 'message_broker', 'runtime', 'other')),"
         "  purl_type      TEXT NOT NULL DEFAULT '',"
         "  cpe_product    TEXT NOT NULL DEFAULT '',"
         "  pack_version   TEXT NOT NULL,"
         "  first_seen_at  BIGINT NOT NULL,"
         "  updated_at     BIGINT NOT NULL,"
         "  PRIMARY KEY (raw_name, raw_publisher, ecosystem));"
         "CREATE INDEX title_dimension_product_idx ON title_dimension (product_id);"
         // Titles the pack could not resolve, weighted by device count. 'rejected'
         // is a curator decision that outlives the title's absence.
         "CREATE TABLE curation_queue ("
         "  raw_name        TEXT NOT NULL,"
         "  raw_publisher   TEXT NOT NULL,"
         "  ecosystem       TEXT NOT NULL,"
         "  device_count    BIGINT NOT NULL DEFAULT 0,"
         "  status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'rejected')),"
         "  first_queued_at BIGINT NOT NULL,"
         "  last_seen_at    BIGINT NOT NULL,"
         "  PRIMARY KEY (raw_name, raw_publisher, ecosystem));"},
    };
    return kMigrations;
}

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// ── Read-degrade observability (#1675 convention) ────────────────────────────
// Reason labels + sampled-WARN machinery mirror SoftwareInventoryStore /
// DeviceInventoryStore (a further copy is the convention — no shared
// agent/server constants exist, and the per-store static samplers must be
// per-store anyway). The counter joins the SHARED read-degrade family with a
// distinguishing source label so the existing YuzuInventoryReadDegraded alert
// covers registry reads too.
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};
struct DegradeLog {
    bool should_log;
    std::uint64_t occurrence;
};

DegradeLog note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason,
                             DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_inventory_read_degrade_total",
                         {{"reason", reason}, {"source", "product_registry"}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return {new_episode || (n % kReadDegradeLogSample) == 0, n};
}

// Parse a Postgres text-format integer cell into int64 (BIGSERIAL ids and
// count(*) are text on the wire). Leaves 0 on a parse failure.
std::int64_t result_i64(const pg::PgResult& res, int row, int col) {
    const char* txt = PQgetvalue(res.get(), row, col);
    const auto len = static_cast<std::size_t>(PQgetlength(res.get(), row, col));
    std::int64_t v = 0;
    std::from_chars(txt, txt + len, v);
    return v;
}

double result_f64(const pg::PgResult& res, int row, int col) {
    const char* txt = PQgetvalue(res.get(), row, col);
    if (txt == nullptr || txt[0] == '\0')
        return 0.0;
    return std::strtod(txt, nullptr);
}

// Shared SELECT column list for product reads, order matched by fill_product.
constexpr const char* kProductCols =
    "product_id, norm_key, vendor, title, edition, platform, created_at, updated_at, "
    "purl_type, cpe_product, origin, category";

// `c0` is the column offset of the product block (0 for a plain products read).
void fill_product(const pg::PgResult& res, int row, ProductRow& out, int c0 = 0) {
    out.product_id = result_i64(res, row, c0 + 0);
    out.norm_key = PQgetvalue(res.get(), row, c0 + 1);
    out.vendor = PQgetvalue(res.get(), row, c0 + 2);
    out.title = PQgetvalue(res.get(), row, c0 + 3);
    out.edition = PQgetvalue(res.get(), row, c0 + 4);
    out.platform = PQgetvalue(res.get(), row, c0 + 5);
    out.created_at = result_i64(res, row, c0 + 6);
    out.updated_at = result_i64(res, row, c0 + 7);
    out.purl_type = PQgetvalue(res.get(), row, c0 + 8);
    out.cpe_product = PQgetvalue(res.get(), row, c0 + 9);
    out.origin = PQgetvalue(res.get(), row, c0 + 10);
    out.category = PQgetvalue(res.get(), row, c0 + 11);
}

/// The dimension invalidation lock (see the header's "Dimension invalidation contract"): the
/// BLOCKING twin of the try-lock every `SoftwareTitleDimension` pass takes, on the same key.
/// A pass holds it for its whole transaction (each statement is bounded by the 60 s statement
/// timeout and the pass by its 60 s budget), so the wait is bounded by a transaction-local
/// statement timeout above that (`kNormalizationLockWait`); a timeout fails the write
/// (fail-soft, like every write here) and the caller retries.
bool take_normalization_lock(PGconn* c) {
    static const std::string timeout_sql =
        "SET LOCAL statement_timeout = '" + std::to_string(kNormalizationLockWait.count()) + "s'";
    static const std::string lock_sql = "SELECT pg_advisory_xact_lock(hashtextextended('" +
                                        std::string(kNormalizationLockKey) + "', 0))";
    if (pg::exec_params(c, timeout_sql.c_str(), std::vector<std::string>{}).status() !=
        PGRES_COMMAND_OK)
        return false;
    return pg::exec_params(c, lock_sql.c_str(), std::vector<std::string>{}).status() ==
           PGRES_TUPLES_OK;
}

/// The stale sentinel (`pack_version = ''`): the next normalisation pass re-selects the row.
/// `where` is a trusted literal predicate over `title_dimension`, never caller text.
bool mark_dimension_stale(PGconn* c, const char* where, const std::vector<std::string>& params) {
    const std::string sql = std::string("UPDATE product_registry_store.title_dimension "
                                        "SET pack_version = '' WHERE pack_version <> '' AND (") +
                            where + ")";
    return pg::exec_params(c, sql.c_str(), params).status() == PGRES_COMMAND_OK;
}

} // namespace

ProductRegistryStore::ProductRegistryStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("ProductRegistryStore: no database connection at construction ({}) — "
                      "product registry persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ProductRegistryStore: schema migration failed — product registry "
                      "persistence disabled");
        return;
    }

    // Post-migration projection check (postgres-store-playbook "Runner guards"): run() skips
    // any migration at or below the stored high-water mark, so a schema_meta stamped by a
    // different binary can leave a v2 column missing while run() still reports success. One
    // LIMIT 0 SELECT per table over every column the runtime uses touches no rows and fails
    // the store closed here, not as `undefined column` on the first pass or pack load.
    struct Projection {
        const char* table;
        const char* columns;
    };
    static constexpr Projection kProjections[] = {
        {"products", kProductCols},
        {"product_aliases", "source, raw_name, raw_publisher, product_id, method, confidence, "
                            "first_matched_at, last_seen_at, status, pack_version"},
        {"normalization_pack", "id, pack_version, sha256, body, loaded_by, loaded_at"},
        {"title_dimension", "raw_name, raw_publisher, ecosystem, norm_status, method, product_id, "
                            "vendor, product, edition, title_version, category, purl_type, "
                            "cpe_product, pack_version, first_seen_at, updated_at"},
        {"curation_queue", "raw_name, raw_publisher, ecosystem, device_count, status, "
                           "first_queued_at, last_seen_at"},
    };
    for (const auto& p : kProjections) {
        const std::string sql = std::string("SELECT ") + p.columns +
                                " FROM product_registry_store." + p.table + " LIMIT 0";
        pg::PgResult probe = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
        if (probe.status() != PGRES_TUPLES_OK) {
            spdlog::error("ProductRegistryStore: post-migration schema projection check failed on "
                          "{} - an expected column is missing (hypothesis: a skipped or partial "
                          "migration; could also be a dropped connection or other transient "
                          "failure) - product registry persistence disabled: {}",
                          p.table, PQresultErrorMessage(probe.get()));
            return;
        }
    }
    open_ = true;
}

std::optional<std::int64_t>
ProductRegistryStore::upsert_product(std::string_view norm_key, std::string_view vendor,
                                     std::string_view title, std::string_view edition,
                                     std::string_view platform) {
    // Fail-soft write: any failure returns nullopt - the next cycle re-derives the same
    // deterministic result (roadmap R7). It is also a registry mutation that can change how a
    // title resolves, so it follows the dimension invalidation contract: the blocking
    // normalisation lock, the upsert and the stale sentinel in ONE transaction.
    if (!open_ || norm_key.empty())
        return std::nullopt;
    std::optional<std::int64_t> id;
    bool ok = false;
    try {
        ok = pool_.with_txn_for(kAcquireTimeout, [&](PGconn* c) -> bool {
            if (!take_normalization_lock(c)) {
                spdlog::warn("ProductRegistryStore: upsert_product could not take the "
                             "normalisation lock for norm_key={}: {}",
                             norm_key, PQerrorMessage(c));
                return false;
            }
            // The row as it is now, read under the lock (every resolution-changing writer holds
            // it): a write that changes nothing leaves every resolution as it was, so it marks
            // nothing - a caller that refreshes each cycle must not re-queue the dimension.
            pg::PgResult before = pg::exec_params(
                c,
                "SELECT vendor, title, edition, platform FROM product_registry_store.products "
                "WHERE norm_key = $1",
                std::vector<std::string>{std::string(norm_key)});
            if (before.status() != PGRES_TUPLES_OK) {
                spdlog::warn("ProductRegistryStore: upsert_product could not read the current "
                             "row for norm_key={}: {}",
                             norm_key, PQerrorMessage(c));
                return false;
            }
            const bool existed = PQntuples(before.get()) == 1;
            const bool unchanged = existed && vendor == PQgetvalue(before.get(), 0, 0) &&
                                   title == PQgetvalue(before.get(), 0, 1) &&
                                   edition == PQgetvalue(before.get(), 0, 2) &&
                                   platform == PQgetvalue(before.get(), 0, 3);
            // Single-statement upsert keyed on the UNIQUE norm_key. created_at is preserved on
            // conflict; the RETURNING carries the id for both the insert and the update arm
            // (#1033 idiom).
            pg::PgResult res = pg::exec_params(
                c,
                "INSERT INTO product_registry_store.products "
                "(norm_key, vendor, title, edition, platform, created_at, updated_at) "
                "VALUES ($1, $2, $3, $4, $5, $6::bigint, $6::bigint) "
                "ON CONFLICT (norm_key) DO UPDATE SET "
                "  vendor = EXCLUDED.vendor, title = EXCLUDED.title, edition = EXCLUDED.edition, "
                "  platform = EXCLUDED.platform, updated_at = EXCLUDED.updated_at "
                "RETURNING product_id",
                std::vector<std::string>{std::string(norm_key), std::string(vendor),
                                         std::string(title), std::string(edition),
                                         std::string(platform), std::to_string(now_secs())});
            if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
                spdlog::warn("ProductRegistryStore: upsert_product failed for norm_key={}: {}",
                             norm_key, PQerrorMessage(c));
                return false;
            }
            const std::int64_t pid = result_i64(res, 0, 0);
            // A NEW product can resolve an unnormalized title (the exact-key tier); a CHANGED
            // one changes the vendor/title/edition every row resolved to it copied.
            if (!unchanged &&
                !mark_dimension_stale(
                    c, existed ? "product_id = $1::bigint" : "norm_status = 'unnormalized'",
                    existed ? std::vector<std::string>{std::to_string(pid)}
                            : std::vector<std::string>{})) {
                spdlog::warn("ProductRegistryStore: upsert_product could not mark the title "
                             "dimension stale for norm_key={}: {}",
                             norm_key, PQerrorMessage(c));
                return false;
            }
            id = pid;
            return true;
        });
    } catch (const std::exception& e) {
        spdlog::warn("ProductRegistryStore: upsert_product threw for norm_key={}: {}", norm_key,
                     e.what());
        return std::nullopt;
    }
    return ok ? id : std::nullopt;
}

bool ProductRegistryStore::upsert_alias(std::string_view source, std::string_view raw_name,
                                        std::string_view raw_publisher, std::int64_t product_id,
                                        std::string_view method, double confidence) {
    if (!open_ || source.empty() || raw_name.empty() || product_id <= 0)
        return false;
    // A registry mutation that can change how a title resolves: the dimension invalidation
    // contract applies (blocking normalisation lock, the upsert and the stale sentinel in ONE
    // transaction). The alias key is a C++ derivation of the raw title that SQL cannot
    // reproduce, so when the link is new or re-pointed the affected rows cannot be named and
    // every row is marked stale; the next passes re-resolve the dimension (idempotent). A
    // refresh that changes neither the product nor the method marks nothing.
    bool ok = false;
    try {
        ok = pool_.with_txn_for(kAcquireTimeout, [&](PGconn* c) -> bool {
            if (!take_normalization_lock(c)) {
                spdlog::warn("ProductRegistryStore: upsert_alias could not take the "
                             "normalisation lock for ({}, {}): {}",
                             source, raw_name, PQerrorMessage(c));
                return false;
            }
            pg::PgResult before = pg::exec_params(
                c,
                "SELECT product_id, method FROM product_registry_store.product_aliases "
                "WHERE source = $1 AND raw_name = $2 AND raw_publisher = $3",
                std::vector<std::string>{std::string(source), std::string(raw_name),
                                         std::string(raw_publisher)});
            if (before.status() != PGRES_TUPLES_OK) {
                spdlog::warn("ProductRegistryStore: upsert_alias could not read the current "
                             "link for ({}, {}): {}",
                             source, raw_name, PQerrorMessage(c));
                return false;
            }
            const bool unchanged = PQntuples(before.get()) == 1 &&
                                   std::to_string(product_id) == PQgetvalue(before.get(), 0, 0) &&
                                   method == PQgetvalue(before.get(), 0, 1);
            // first_matched_at is preserved on conflict; the link's target/method/confidence +
            // last_seen_at refresh each evaluator cycle (soft keys are re-derived, never frozen
            // - roadmap R7). A dangling product_id fails the FK and lands in the error branch
            // below (fail-soft, no throw).
            pg::PgResult res = pg::exec_params(
                c,
                "INSERT INTO product_registry_store.product_aliases "
                "(source, raw_name, raw_publisher, product_id, method, confidence, "
                "first_matched_at, last_seen_at) "
                "VALUES ($1, $2, $3, $4::bigint, $5, $6::double precision, $7::bigint, "
                "$7::bigint) "
                "ON CONFLICT (source, raw_name, raw_publisher) DO UPDATE SET "
                "  product_id = EXCLUDED.product_id, method = EXCLUDED.method, "
                "  confidence = EXCLUDED.confidence, last_seen_at = EXCLUDED.last_seen_at "
                "RETURNING product_id",
                std::vector<std::string>{std::string(source), std::string(raw_name),
                                         std::string(raw_publisher), std::to_string(product_id),
                                         std::string(method), std::to_string(confidence),
                                         std::to_string(now_secs())});
            if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
                spdlog::warn("ProductRegistryStore: upsert_alias failed for ({}, {}): {}", source,
                             raw_name, PQerrorMessage(c));
                return false;
            }
            if (!unchanged && !mark_dimension_stale(c, "TRUE", std::vector<std::string>{})) {
                spdlog::warn("ProductRegistryStore: upsert_alias could not mark the title "
                             "dimension stale for ({}, {}): {}",
                             source, raw_name, PQerrorMessage(c));
                return false;
            }
            return true;
        });
    } catch (const std::exception& e) {
        spdlog::warn("ProductRegistryStore: upsert_alias threw for ({}, {}): {}", source, raw_name,
                     e.what());
        return false;
    }
    return ok;
}

std::expected<std::optional<std::int64_t>, RegistryReadError>
ProductRegistryStore::resolve_alias(std::string_view source, std::string_view raw_name,
                                    std::string_view raw_publisher) {
    // AUTHORITATIVE read: a degrade is kDegraded, NEVER a silent "no alias" —
    // a degrade misread as a miss would send the matcher re-birthing rows it
    // cannot persist (and a compliance surface into the unmatched bucket).
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("ProductRegistryStore: resolve_alias degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::unexpected(RegistryReadError::kDegraded);
    }
    if (source.empty() || raw_name.empty())
        return std::optional<std::int64_t>{}; // precondition miss → absent, not a degrade
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("ProductRegistryStore: resolve_alias degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::unexpected(RegistryReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT product_id FROM product_registry_store.product_aliases "
        "WHERE source = $1 AND raw_name = $2 AND raw_publisher = $3",
        std::vector<std::string>{std::string(source), std::string(raw_name),
                                 std::string(raw_publisher)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("ProductRegistryStore: resolve_alias degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::unexpected(RegistryReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<std::int64_t>{}; // read succeeded, no link yet → absent
    return std::optional<std::int64_t>{result_i64(res, 0, 0)};
}

std::expected<std::optional<ProductRow>, RegistryReadError>
ProductRegistryStore::get_product(std::string_view norm_key) {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("ProductRegistryStore: get_product degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::unexpected(RegistryReadError::kDegraded);
    }
    if (norm_key.empty())
        return std::optional<ProductRow>{}; // precondition miss → absent, not a degrade
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("ProductRegistryStore: get_product degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::unexpected(RegistryReadError::kDegraded);
    }
    const std::string sql = std::string("SELECT ") + kProductCols +
                            " FROM product_registry_store.products WHERE norm_key = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{std::string(norm_key)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("ProductRegistryStore: get_product degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::unexpected(RegistryReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<ProductRow>{};
    ProductRow out;
    fill_product(res, 0, out);
    return std::optional<ProductRow>{std::move(out)};
}

std::optional<std::vector<ProductRow>> ProductRegistryStore::list_products(int limit) {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("ProductRegistryStore: list_products degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("ProductRegistryStore: list_products degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    const int eff = limit > 0 && limit < kListRowCap ? limit : kListRowCap;
    const std::string sql = std::string("SELECT ") + kProductCols +
                            " FROM product_registry_store.products "
                            "ORDER BY norm_key LIMIT $1::bigint";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{std::to_string(eff)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("ProductRegistryStore: list_products degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    std::vector<ProductRow> out;
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        ProductRow r;
        fill_product(res, i, r);
        out.push_back(std::move(r));
    }
    return out;
}

std::optional<std::vector<ProductAliasRow>>
ProductRegistryStore::list_aliases(std::int64_t product_id) {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("ProductRegistryStore: list_aliases degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    std::vector<ProductAliasRow> out;
    if (product_id <= 0)
        return out; // precondition miss → empty value, not a degrade
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("ProductRegistryStore: list_aliases degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT source, raw_name, raw_publisher, product_id, method, confidence, "
        "first_matched_at, last_seen_at, status, pack_version "
        "FROM product_registry_store.product_aliases "
        "WHERE product_id = $1::bigint ORDER BY source, raw_name, raw_publisher "
        "LIMIT $2::bigint",
        std::vector<std::string>{std::to_string(product_id), std::to_string(kListRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("ProductRegistryStore: list_aliases degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        ProductAliasRow r;
        r.source = PQgetvalue(res.get(), i, 0);
        r.raw_name = PQgetvalue(res.get(), i, 1);
        r.raw_publisher = PQgetvalue(res.get(), i, 2);
        r.product_id = result_i64(res, i, 3);
        r.method = PQgetvalue(res.get(), i, 4);
        r.confidence = result_f64(res, i, 5);
        r.first_matched_at = result_i64(res, i, 6);
        r.last_seen_at = result_i64(res, i, 7);
        r.status = PQgetvalue(res.get(), i, 8);
        r.pack_version = PQgetvalue(res.get(), i, 9);
        out.push_back(std::move(r));
    }
    return out;
}

std::optional<std::int64_t> ProductRegistryStore::count_products() {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("ProductRegistryStore: count_products skipped, no connection ({})",
                     pool_.last_error());
        return std::nullopt;
    }
    pg::PgResult res =
        pg::exec_params(lease.get(), "SELECT count(*) FROM product_registry_store.products",
                        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
        spdlog::warn("ProductRegistryStore: count_products failed: {}",
                     PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    return result_i64(res, 0, 0);
}

std::optional<std::int64_t> ProductRegistryStore::count_aliases() {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("ProductRegistryStore: count_aliases skipped, no connection ({})",
                     pool_.last_error());
        return std::nullopt;
    }
    pg::PgResult res =
        pg::exec_params(lease.get(), "SELECT count(*) FROM product_registry_store.product_aliases",
                        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
        spdlog::warn("ProductRegistryStore: count_aliases failed: {}", PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    return result_i64(res, 0, 0);
}

std::expected<PackLoadOutcome, std::string>
ProductRegistryStore::load_pack_if_empty(const ParsedPack& pack, std::string_view loaded_by) {
    if (!open_)
        return std::unexpected("product registry store is not open");
    PackLoadOutcome outcome = PackLoadOutcome::already_present;
    std::string error;
    const auto fail = [&](std::string_view what, PGconn* c) {
        error = std::string{what} + ": " + PQerrorMessage(c);
        return false;
    };
    const bool ok = pool_.with_txn_for(kAcquireTimeout, [&](PGconn* c) -> bool {
        // Blocking xact lock: two replicas booting together serialise here, and the
        // loser then sees the winner's pack row and returns already_present.
        pg::PgResult lk = pg::exec_params(
            c, "SELECT pg_advisory_xact_lock(hashtextextended('product_registry_pack', 0))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK)
            return fail("pack advisory lock", c);
        pg::PgResult cur = pg::exec_params(
            c, "SELECT pack_version FROM product_registry_store.normalization_pack WHERE id = 1",
            std::vector<std::string>{});
        if (cur.status() != PGRES_TUPLES_OK)
            return fail("pack read", c);
        if (PQntuples(cur.get()) == 1) {
            spdlog::info("ProductRegistryStore: alias pack {} already loaded; embedded pack {} "
                         "not applied",
                         PQgetvalue(cur.get(), 0, 0), pack.pack_version);
            return true;
        }
        const std::string now = std::to_string(now_secs());
        pg::PgResult ins = pg::exec_params(
            c,
            "INSERT INTO product_registry_store.normalization_pack "
            "(id, pack_version, sha256, body, loaded_by, loaded_at) "
            "VALUES (1, $1, $2, $3, $4, $5::bigint)",
            std::vector<std::string>{pack.pack_version, pack.sha256, pack.body, std::string{loaded_by},
                                     now});
        if (ins.status() != PGRES_COMMAND_OK)
            return fail("pack insert", c);

        // ponytail: per-row statements inside the one txn; a pack is a few hundred rows.
        // Switch to unnest() arrays past ~500 rows.
        std::unordered_map<std::string, std::string> product_ids; // norm_key -> id
        for (const auto& r : pack.rows) {
            auto pit = product_ids.find(r.norm_key);
            if (pit == product_ids.end()) {
                pg::PgResult pr = pg::exec_params(
                    c,
                    "INSERT INTO product_registry_store.products "
                    "(norm_key, vendor, title, edition, platform, created_at, updated_at, "
                    " purl_type, cpe_product, origin, category) "
                    "VALUES ($1, $2, $3, $4, '', $5::bigint, $5::bigint, $6, $7, 'pack', $8) "
                    "ON CONFLICT (norm_key) DO UPDATE SET "
                    "  category = EXCLUDED.category, "
                    "  purl_type = CASE WHEN products.purl_type = '' THEN EXCLUDED.purl_type "
                    "                   ELSE products.purl_type END, "
                    "  cpe_product = CASE WHEN products.cpe_product = '' THEN EXCLUDED.cpe_product "
                    "                     ELSE products.cpe_product END, "
                    "  origin = CASE WHEN products.origin = 'curated' THEN 'curated' "
                    "                ELSE 'pack' END, "
                    "  updated_at = EXCLUDED.updated_at "
                    "RETURNING product_id",
                    std::vector<std::string>{r.norm_key, r.vendor, r.title, r.edition, now,
                                             std::string{purl_type_for(r.ecosystem)}, r.cpe_product,
                                             r.category});
                if (pr.status() != PGRES_TUPLES_OK || PQntuples(pr.get()) != 1)
                    return fail("pack product upsert", c);
                pit = product_ids.emplace(r.norm_key, PQgetvalue(pr.get(), 0, 0)).first;
            }
            pg::PgResult al = pg::exec_params(
                c,
                "INSERT INTO product_registry_store.product_aliases "
                "(source, raw_name, raw_publisher, product_id, method, confidence, "
                " first_matched_at, last_seen_at, status, pack_version) "
                "VALUES ($1, $2, $3, $4::bigint, 'pack', 1.0, $5::bigint, $5::bigint, 'active', $6) "
                "ON CONFLICT (source, raw_name, raw_publisher) DO UPDATE SET "
                "  product_id = EXCLUDED.product_id, pack_version = EXCLUDED.pack_version, "
                "  status = 'active', last_seen_at = EXCLUDED.last_seen_at",
                std::vector<std::string>{"pack:" + r.ecosystem, r.raw_name, r.raw_publisher,
                                         pit->second, now, pack.pack_version});
            if (al.status() != PGRES_COMMAND_OK)
                return fail("pack alias upsert", c);
        }
        outcome = PackLoadOutcome::loaded;
        return true;
    });
    if (!ok)
        return std::unexpected(error.empty() ? "pack load transaction failed (no connection or "
                                               "commit failure): " + pool_.last_error()
                                             : error);
    return outcome;
}

std::optional<std::vector<NormalizationAliasRow>>
ProductRegistryStore::read_normalization_aliases(PGconn* conn,
                                                 const std::vector<std::string_view>& alias_keys,
                                                 const std::vector<std::string_view>& sources) {
    std::vector<NormalizationAliasRow> out;
    if (alias_keys.empty() || sources.empty())
        return out;
    pg::PgResult res = pg::exec_params(
        conn,
        "SELECT a.source, a.raw_name, a.raw_publisher, "
        "  p.product_id, p.norm_key, p.vendor, p.title, p.edition, p.platform, p.created_at, "
        "  p.updated_at, p.purl_type, p.cpe_product, p.origin, p.category "
        "FROM product_registry_store.product_aliases a "
        "JOIN product_registry_store.products p ON p.product_id = a.product_id "
        "WHERE a.status = 'active' AND a.source = ANY($2::text[]) "
        "  AND a.raw_name = ANY($1::text[])",
        std::vector<std::string>{pg::to_text_array(alias_keys), pg::to_text_array(sources)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("ProductRegistryStore: alias read failed: {}", PQerrorMessage(conn));
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        NormalizationAliasRow r;
        r.source = PQgetvalue(res.get(), i, 0);
        r.raw_name = PQgetvalue(res.get(), i, 1);
        r.raw_publisher = PQgetvalue(res.get(), i, 2);
        fill_product(res, i, r.product, 3);
        out.push_back(std::move(r));
    }
    return out;
}

std::optional<std::vector<ProductRow>>
ProductRegistryStore::read_products_by_norm_key(PGconn* conn,
                                                const std::vector<std::string_view>& norm_keys) {
    std::vector<ProductRow> out;
    if (norm_keys.empty())
        return out;
    const std::string sql = std::string("SELECT ") + kProductCols +
                            " FROM product_registry_store.products WHERE norm_key = ANY($1::text[])";
    pg::PgResult res =
        pg::exec_params(conn, sql.c_str(), std::vector<std::string>{pg::to_text_array(norm_keys)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("ProductRegistryStore: product read failed: {}", PQerrorMessage(conn));
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        ProductRow r;
        fill_product(res, i, r);
        out.push_back(std::move(r));
    }
    return out;
}

} // namespace yuzu::server
