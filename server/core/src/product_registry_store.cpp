#include "product_registry_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
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
    // explicitly. Migration v2 (product_tags) is PR4 — do NOT add it here.
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
    "product_id, norm_key, vendor, title, edition, platform, created_at, updated_at";

void fill_product(const pg::PgResult& res, int row, ProductRow& out) {
    out.product_id = result_i64(res, row, 0);
    out.norm_key = PQgetvalue(res.get(), row, 1);
    out.vendor = PQgetvalue(res.get(), row, 2);
    out.title = PQgetvalue(res.get(), row, 3);
    out.edition = PQgetvalue(res.get(), row, 4);
    out.platform = PQgetvalue(res.get(), row, 5);
    out.created_at = result_i64(res, row, 6);
    out.updated_at = result_i64(res, row, 7);
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
    open_ = true;
}

std::optional<std::int64_t>
ProductRegistryStore::upsert_product(std::string_view norm_key, std::string_view vendor,
                                     std::string_view title, std::string_view edition,
                                     std::string_view platform) {
    // Fail-soft write (evaluator matcher pass): any failure returns nullopt —
    // the next cycle re-derives the same deterministic result (roadmap R7).
    if (!open_ || norm_key.empty())
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("ProductRegistryStore: upsert_product skipped for norm_key={}, no "
                     "connection ({})",
                     norm_key, pool_.last_error());
        return std::nullopt;
    }
    // Single-statement upsert keyed on the UNIQUE norm_key: atomic, no txn or
    // advisory lock needed. created_at is preserved on conflict; the RETURNING
    // carries the id for both the insert and the update arm (#1033 idiom).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO product_registry_store.products "
        "(norm_key, vendor, title, edition, platform, created_at, updated_at) "
        "VALUES ($1, $2, $3, $4, $5, $6::bigint, $6::bigint) "
        "ON CONFLICT (norm_key) DO UPDATE SET "
        "  vendor = EXCLUDED.vendor, title = EXCLUDED.title, edition = EXCLUDED.edition, "
        "  platform = EXCLUDED.platform, updated_at = EXCLUDED.updated_at "
        "RETURNING product_id",
        std::vector<std::string>{std::string(norm_key), std::string(vendor), std::string(title),
                                 std::string(edition), std::string(platform),
                                 std::to_string(now_secs())});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
        spdlog::warn("ProductRegistryStore: upsert_product failed for norm_key={}: {}", norm_key,
                     PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    return result_i64(res, 0, 0);
}

bool ProductRegistryStore::upsert_alias(std::string_view source, std::string_view raw_name,
                                        std::string_view raw_publisher, std::int64_t product_id,
                                        std::string_view method, double confidence) {
    if (!open_ || source.empty() || raw_name.empty() || product_id <= 0)
        return false;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::warn("ProductRegistryStore: upsert_alias skipped for ({}, {}), no connection ({})",
                     source, raw_name, pool_.last_error());
        return false;
    }
    // first_matched_at is preserved on conflict; the link's target/method/
    // confidence + last_seen_at refresh each evaluator cycle (soft keys are
    // re-derived, never frozen — roadmap R7). A dangling product_id fails the
    // FK and lands in the error branch below (fail-soft, no throw).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO product_registry_store.product_aliases "
        "(source, raw_name, raw_publisher, product_id, method, confidence, "
        "first_matched_at, last_seen_at) "
        "VALUES ($1, $2, $3, $4::bigint, $5, $6::double precision, $7::bigint, $7::bigint) "
        "ON CONFLICT (source, raw_name, raw_publisher) DO UPDATE SET "
        "  product_id = EXCLUDED.product_id, method = EXCLUDED.method, "
        "  confidence = EXCLUDED.confidence, last_seen_at = EXCLUDED.last_seen_at "
        "RETURNING product_id",
        std::vector<std::string>{std::string(source), std::string(raw_name),
                                 std::string(raw_publisher), std::to_string(product_id),
                                 std::string(method), std::to_string(confidence),
                                 std::to_string(now_secs())});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
        spdlog::warn("ProductRegistryStore: upsert_alias failed for ({}, {}): {}", source, raw_name,
                     PQerrorMessage(lease.get()));
        return false;
    }
    return true;
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
        "first_matched_at, last_seen_at "
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

} // namespace yuzu::server
