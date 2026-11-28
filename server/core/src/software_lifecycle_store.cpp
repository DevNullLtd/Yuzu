#include "software_lifecycle_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_catalogue_model.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <map>
#include <set>
#include <tuple>
#include <unordered_map>

namespace yuzu::server {

namespace {

using Kind = SoftwareLifecycleStore::Error::Kind;
using Error = SoftwareLifecycleStore::Error;

constexpr const char* kStoreName = "software_lifecycle_store";

constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr const char* kReasonCorruptRow = "corrupt_row";
constexpr const char* kReasonRowCap = "row_cap";
constexpr const char* kReasonTxnFailed = "txn_failed";

/// Most declared rows one read returns; more is a degrade, never a truncated answer.
constexpr int kDeclaredReadCap = 20000;
/// Bound for the seed-load transaction (startup, one writer).
constexpr std::chrono::milliseconds kWriteTimeout{5000};
/// Log the first degrade of a log class (see note_degrade) and every 100th after it.
constexpr std::uint64_t kLogSample = 100;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for the migration
    // transaction. Runtime statements below schema-qualify explicitly.
    // ponytail: lifecycle_declared has no prune - a superseded date stays, a few rows per product
    // version. Nothing writes it until the host support-end source lands; that change adds
    // clock-guarded retention (docs/clock-guarded-retention.md).
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE lifecycle_rule ("
         "  rule_id        BIGSERIAL PRIMARY KEY,"
         "  product_key    TEXT NOT NULL,"
         "  version_prefix TEXT NOT NULL DEFAULT '',"
         "  event          TEXT NOT NULL CHECK (event IN ('end_of_support', 'end_of_life')),"
         "  event_date     DATE NOT NULL,"
         "  source         TEXT NOT NULL CHECK (source IN ('external', 'imported', 'shipped')),"
         "  source_ref     TEXT NOT NULL DEFAULT '',"
         "  loaded_at      BIGINT NOT NULL,"
         "  UNIQUE (source, product_key, version_prefix, event));"
         "CREATE INDEX lifecycle_rule_product_idx ON lifecycle_rule (product_key);"
         "CREATE TABLE lifecycle_declared ("
         "  product_key TEXT NOT NULL,"
         "  version     TEXT NOT NULL,"
         "  event       TEXT NOT NULL CHECK (event IN ('end_of_support', 'end_of_life')),"
         "  event_date  DATE NOT NULL,"
         "  last_seen   BIGINT NOT NULL,"
         "  PRIMARY KEY (product_key, version, event, event_date));"},
    };
    return kMigrations;
}

// The SQLSTATE only: a libpq message can quote the failing row.
std::string sqlstate(const pg::PgResult& res) {
    const char* code = res.get() ? PQresultErrorField(res.get(), PG_DIAG_SQLSTATE) : nullptr;
    return code ? std::string(code) : std::string("none");
}

std::int64_t cell_i64(const pg::PgResult& res, int row, int col) {
    return std::strtoll(PQgetvalue(res.get(), row, col), nullptr, 10);
}

constexpr const char* kReadFamily = "yuzu_server_software_lifecycle_store_read_degrade_total";
constexpr const char* kWriteFamily = "yuzu_server_software_lifecycle_store_write_degrade_total";

/// Count a degrade on `family` and report whether this occurrence should be logged: the first
/// degrade and every 100th after it, sampled separately for the two log classes in the header (the
/// `error` reasons an operator acts on, and the retryable `warn` ones), so a storm of one class
/// never suppresses the first line of the other. The counters are exact per family and reason.
bool note_degrade(yuzu::MetricsRegistry* metrics, const char* family, const char* reason) {
    static std::atomic<std::uint64_t> n[2]{};
    if (metrics)
        metrics->counter(family, {{"reason", reason}}).increment();
    const std::string_view r{reason};
    const bool error_class = r == kReasonCorruptRow || r == kReasonRowCap || r == kReasonTxnFailed;
    return (n[error_class].fetch_add(1, std::memory_order_relaxed) % kLogSample) == 0;
}

std::string event_text(LifecycleEvent e) { return std::string{to_string(e)}; }

std::vector<std::string_view> views(const std::vector<std::string>& v) {
    return std::vector<std::string_view>(v.begin(), v.end());
}

} // namespace

SoftwareLifecycleStore::SoftwareLifecycleStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("SoftwareLifecycleStore: no database connection at construction ({}) - "
                      "software lifecycle persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("SoftwareLifecycleStore: schema migration failed - software lifecycle "
                      "persistence disabled");
        return;
    }
    // Post-migration projection check (postgres-store-playbook "Runner guards"): run() skips any
    // migration at or below the stored high-water mark, so a schema_meta stamped by a different
    // binary can leave a column missing while run() still reports success. A LIMIT 0 SELECT over
    // every column the runtime uses fails the store closed here, not on the first read.
    struct Projection {
        const char* table;
        const char* columns;
    };
    static constexpr Projection kProjections[] = {
        {"lifecycle_rule",
         "rule_id, product_key, version_prefix, event, event_date, source, source_ref, loaded_at"},
        {"lifecycle_declared", "product_key, version, event, event_date, last_seen"},
    };
    for (const auto& p : kProjections) {
        const std::string sql = std::string("SELECT ") + p.columns + " FROM " + kStoreName + "." +
                                p.table + " LIMIT 0";
        pg::PgResult probe = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
        if (probe.status() != PGRES_TUPLES_OK) {
            spdlog::error("SoftwareLifecycleStore: post-migration schema projection check failed "
                          "on {} (SQLSTATE {}) - software lifecycle persistence disabled",
                          p.table, sqlstate(probe));
            return;
        }
    }
    open_ = true;
}

std::expected<std::size_t, std::string>
SoftwareLifecycleStore::replace_rules(LifecycleSource source,
                                      const std::vector<LifecycleRule>& rules) {
    if (!open_)
        return std::unexpected("software lifecycle store is not open");
    if (source == LifecycleSource::declared)
        return std::unexpected("declared is not a rule source");
    if (rules.size() > kLifecycleCsvMaxRows)
        return std::unexpected("more than " + std::to_string(kLifecycleCsvMaxRows) + " rules");
    // A rule is named by its index in the message, never by its key: the key may be the field that
    // just failed validation, and the caller logs this text.
    std::set<std::tuple<std::string, std::string, LifecycleEvent>> seen;
    for (std::size_t i = 0; i < rules.size(); ++i) {
        const auto& r = rules[i];
        if (r.source != source)
            return std::unexpected("rule " + std::to_string(i) + " carries a source other than " +
                                   std::string{to_string(source)});
        if (const auto bad = validate_lifecycle_rule(r))
            return std::unexpected("rule " + std::to_string(i) + ": " + *bad);
        if (!seen.emplace(r.product_key, r.version_prefix, r.event).second)
            return std::unexpected("rule " + std::to_string(i) +
                                   " repeats an earlier (product_key, version_prefix, event)");
    }

    std::vector<std::string> keys, prefixes, events, dates, refs;
    for (const auto& r : rules) {
        keys.push_back(r.product_key);
        prefixes.push_back(r.version_prefix);
        events.push_back(event_text(r.event));
        dates.push_back(r.date);
        refs.push_back(r.source_ref);
    }
    const std::string src{to_string(source)};
    std::string failed_state;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // One replacement at a time across replicas: two servers starting together would
        // otherwise both insert and the second would die on the unique key.
        pg::PgResult lock = pg::exec_params(
            c, "SELECT pg_advisory_xact_lock(hashtextextended('software_lifecycle_rules', 0))",
            std::vector<std::string>{});
        if (lock.status() != PGRES_TUPLES_OK) {
            failed_state = sqlstate(lock);
            return false;
        }
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM software_lifecycle_store.lifecycle_rule WHERE source = $1",
            std::vector<std::string>{src});
        if (del.status() != PGRES_COMMAND_OK) {
            failed_state = sqlstate(del);
            return false;
        }
        if (rules.empty())
            return true;
        pg::PgResult ins = pg::exec_params(
            c,
            "INSERT INTO software_lifecycle_store.lifecycle_rule "
            "(product_key, version_prefix, event, event_date, source, source_ref, loaded_at) "
            "SELECT k, p, e, d::date, $1::text, r,(EXTRACT(EPOCH FROM now()))::bigint "
            "FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) "
            "  AS t(k, p, e, d, r)",
            std::vector<std::string>{src, pg::to_text_array(views(keys)),
                                     pg::to_text_array(views(prefixes)),
                                     pg::to_text_array(views(events)),
                                     pg::to_text_array(views(dates)),
                                     pg::to_text_array(views(refs))});
        if (ins.status() != PGRES_COMMAND_OK) {
            failed_state = sqlstate(ins);
            return false;
        }
        return true;
    });
    if (!ok) {
        if (note_degrade(metrics_, kWriteFamily, kReasonTxnFailed))
            spdlog::error("SoftwareLifecycleStore: replace_rules({}) transaction failed (SQLSTATE {})",
                          src, failed_state.empty() ? "none" : failed_state);
        return std::unexpected("replace_rules transaction failed (SQLSTATE " +
                               (failed_state.empty() ? std::string{"none"} : failed_state) + ")");
    }
    return rules.size();
}

bool SoftwareLifecycleStore::upsert_declared(const std::vector<DeclaredFact>& facts) {
    if (facts.empty())
        return true;
    if (!open_) {
        if (note_degrade(metrics_, kWriteFamily, kReasonStoreNotOpen))
            spdlog::warn("SoftwareLifecycleStore: upsert_declared degraded - store not open");
        return false;
    }
    if (facts.size() > kLifecycleDeclaredBatchMax) {
        spdlog::warn("SoftwareLifecycleStore: upsert_declared refused {} facts (max {})",
                     facts.size(), kLifecycleDeclaredBatchMax);
        return false;
    }
    // One row per distinct fact, newest last_seen: a repeated key in one INSERT ... ON CONFLICT
    // statement is an error in Postgres.
    std::map<std::tuple<std::string, std::string, LifecycleEvent, std::string>, std::int64_t> distinct;
    for (const auto& f : facts) {
        if (const auto bad = validate_declared_fact(f)) {
            spdlog::warn("SoftwareLifecycleStore: upsert_declared refused a fact: {}", *bad);
            return false;
        }
        auto& seen = distinct[{f.product_key, f.version, f.event, f.date}];
        seen = std::max(seen, f.last_seen);
    }
    std::vector<std::string> keys, versions, events, dates, seens;
    for (const auto& [k, last_seen] : distinct) {
        keys.push_back(std::get<0>(k));
        versions.push_back(std::get<1>(k));
        events.push_back(event_text(std::get<2>(k)));
        dates.push_back(std::get<3>(k));
        seens.push_back(std::to_string(last_seen));
    }
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        if (note_degrade(metrics_, kWriteFamily, kReasonPoolTimeout))
            spdlog::warn("SoftwareLifecycleStore: upsert_declared degraded - no connection ({})",
                         pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO software_lifecycle_store.lifecycle_declared "
        "(product_key, version, event, event_date, last_seen) "
        "SELECT k, v, e, d::date, s::bigint "
        "FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[]) "
        "  AS t(k, v, e, d, s) "
        "ON CONFLICT (product_key, version, event, event_date) DO UPDATE SET "
        "  last_seen = GREATEST(lifecycle_declared.last_seen, EXCLUDED.last_seen)",
        std::vector<std::string>{pg::to_text_array(views(keys)), pg::to_text_array(views(versions)),
                                 pg::to_text_array(views(events)), pg::to_text_array(views(dates)),
                                 pg::to_text_array(views(seens))});
    if (res.status() != PGRES_COMMAND_OK) {
        if (note_degrade(metrics_, kWriteFamily, kReasonQueryError))
            spdlog::warn("SoftwareLifecycleStore: upsert_declared degraded - query failed "
                         "(SQLSTATE {})",
                         sqlstate(res));
        return false;
    }
    return true;
}

std::optional<std::vector<LifecycleRule>>
SoftwareLifecycleStore::rules_for(const std::vector<std::string>& product_keys) {
    if (!open_) {
        if (note_degrade(metrics_, kReadFamily, kReasonStoreNotOpen))
            spdlog::warn("SoftwareLifecycleStore: rules_for degraded - store not open");
        return std::nullopt;
    }
    if (product_keys.size() > kLifecycleBatchMax) {
        spdlog::warn("SoftwareLifecycleStore: rules_for refused {} keys (max {})",
                     product_keys.size(), kLifecycleBatchMax);
        return std::nullopt;
    }
    std::vector<LifecycleRule> out;
    if (product_keys.empty())
        return out;
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        if (note_degrade(metrics_, kReadFamily, kReasonPoolTimeout))
            spdlog::warn("SoftwareLifecycleStore: rules_for degraded - no connection ({})",
                         pool_.last_error());
        return std::nullopt;
    }
    // Bounded without a LIMIT: the table holds at most kLifecycleCsvMaxRows rows per source.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT product_key, version_prefix, event, to_char(event_date, 'YYYY-MM-DD'), source, "
        "source_ref, loaded_at FROM software_lifecycle_store.lifecycle_rule "
        "WHERE product_key = ANY($1::text[]) ORDER BY rule_id",
        std::vector<std::string>{pg::to_text_array(views(product_keys))});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_degrade(metrics_, kReadFamily, kReasonQueryError))
            spdlog::warn("SoftwareLifecycleStore: rules_for degraded - query failed (SQLSTATE {})",
                         sqlstate(res));
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        const auto ev = parse_lifecycle_event(PQgetvalue(res.get(), i, 2));
        const auto src = parse_lifecycle_source(PQgetvalue(res.get(), i, 4));
        if (!ev || !src || *src == LifecycleSource::declared) {
            if (note_degrade(metrics_, kReadFamily, kReasonCorruptRow))
                spdlog::error("SoftwareLifecycleStore: rules_for found a row with an unknown "
                              "event or source for {}",
                              PQgetvalue(res.get(), i, 0));
            return std::nullopt;
        }
        out.push_back(LifecycleRule{PQgetvalue(res.get(), i, 0), PQgetvalue(res.get(), i, 1), *ev,
                                    PQgetvalue(res.get(), i, 3), *src, PQgetvalue(res.get(), i, 5),
                                    cell_i64(res, i, 6)});
    }
    return out;
}

std::optional<std::vector<LifecycleRule>> SoftwareLifecycleStore::rules_of(LifecycleSource source) {
    if (source == LifecycleSource::declared) {
        spdlog::warn("SoftwareLifecycleStore: rules_of refused the declared source");
        return std::nullopt;
    }
    if (!open_) {
        if (note_degrade(metrics_, kReadFamily, kReasonStoreNotOpen))
            spdlog::warn("SoftwareLifecycleStore: rules_of degraded - store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        if (note_degrade(metrics_, kReadFamily, kReasonPoolTimeout))
            spdlog::warn("SoftwareLifecycleStore: rules_of degraded - no connection ({})",
                         pool_.last_error());
        return std::nullopt;
    }
    // One row past the per-source bound replace_rules enforces: seeing it means the table was
    // written outside this class, and the answer is a degrade, never a truncated list.
    const std::string sql =
        "SELECT product_key, version_prefix, event, to_char(event_date, 'YYYY-MM-DD'), source, "
        "source_ref, loaded_at FROM software_lifecycle_store.lifecycle_rule WHERE source = $1 "
        "ORDER BY product_key, version_prefix, event LIMIT " +
        std::to_string(kLifecycleCsvMaxRows + 1);
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{std::string{to_string(source)}});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_degrade(metrics_, kReadFamily, kReasonQueryError))
            spdlog::warn("SoftwareLifecycleStore: rules_of degraded - query failed (SQLSTATE {})",
                         sqlstate(res));
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    if (n > static_cast<int>(kLifecycleCsvMaxRows)) {
        if (note_degrade(metrics_, kReadFamily, kReasonRowCap))
            spdlog::error("SoftwareLifecycleStore: rules_of found more than {} {} rules",
                          kLifecycleCsvMaxRows, to_string(source));
        return std::nullopt;
    }
    std::vector<LifecycleRule> out;
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        const auto ev = parse_lifecycle_event(PQgetvalue(res.get(), i, 2));
        const auto src = parse_lifecycle_source(PQgetvalue(res.get(), i, 4));
        if (!ev || !src || *src != source) {
            if (note_degrade(metrics_, kReadFamily, kReasonCorruptRow))
                spdlog::error("SoftwareLifecycleStore: rules_of found a row with an unknown "
                              "event or source for {}",
                              PQgetvalue(res.get(), i, 0));
            return std::nullopt;
        }
        out.push_back(LifecycleRule{PQgetvalue(res.get(), i, 0), PQgetvalue(res.get(), i, 1), *ev,
                                    PQgetvalue(res.get(), i, 3), *src, PQgetvalue(res.get(), i, 5),
                                    cell_i64(res, i, 6)});
    }
    return out;
}

std::optional<std::vector<DeclaredFact>>
SoftwareLifecycleStore::declared_for(const std::vector<LifecycleLookup>& lookups) {
    if (!open_) {
        if (note_degrade(metrics_, kReadFamily, kReasonStoreNotOpen))
            spdlog::warn("SoftwareLifecycleStore: declared_for degraded - store not open");
        return std::nullopt;
    }
    if (lookups.size() > kLifecycleBatchMax) {
        spdlog::warn("SoftwareLifecycleStore: declared_for refused {} lookups (max {})",
                     lookups.size(), kLifecycleBatchMax);
        return std::nullopt;
    }
    std::vector<DeclaredFact> out;
    if (lookups.empty())
        return out;
    std::vector<std::string> keys, versions;
    for (const auto& l : lookups) {
        keys.push_back(l.product_key);
        versions.push_back(l.version);
    }
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        if (note_degrade(metrics_, kReadFamily, kReasonPoolTimeout))
            spdlog::warn("SoftwareLifecycleStore: declared_for degraded - no connection ({})",
                         pool_.last_error());
        return std::nullopt;
    }
    const std::string sql =
        "SELECT d.product_key, d.version, d.event, to_char(d.event_date, 'YYYY-MM-DD'), d.last_seen "
        "FROM software_lifecycle_store.lifecycle_declared d "
        "JOIN (SELECT DISTINCT k, v FROM unnest($1::text[], $2::text[]) AS t(k, v)) q "
        "  ON d.product_key = q.k AND d.version = q.v "
        "ORDER BY d.product_key, d.version, d.event, d.event_date LIMIT " +
        std::to_string(kDeclaredReadCap + 1);
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{pg::to_text_array(views(keys)), pg::to_text_array(views(versions))});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_degrade(metrics_, kReadFamily, kReasonQueryError))
            spdlog::warn("SoftwareLifecycleStore: declared_for degraded - query failed "
                         "(SQLSTATE {})",
                         sqlstate(res));
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    if (n > kDeclaredReadCap) {
        if (note_degrade(metrics_, kReadFamily, kReasonRowCap))
            spdlog::error("SoftwareLifecycleStore: declared_for found more than {} rows",
                          kDeclaredReadCap);
        return std::nullopt;
    }
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        const auto ev = parse_lifecycle_event(PQgetvalue(res.get(), i, 2));
        if (!ev) {
            if (note_degrade(metrics_, kReadFamily, kReasonCorruptRow))
                spdlog::error("SoftwareLifecycleStore: declared_for found a row with an unknown "
                              "event for {}",
                              PQgetvalue(res.get(), i, 0));
            return std::nullopt;
        }
        out.push_back(DeclaredFact{PQgetvalue(res.get(), i, 0), PQgetvalue(res.get(), i, 1), *ev,
                                   PQgetvalue(res.get(), i, 3), cell_i64(res, i, 4)});
    }
    return out;
}

std::expected<std::vector<LifecycleEvaluation>, Error>
SoftwareLifecycleStore::evaluate_batch(const std::vector<LifecycleLookup>& lookups,
                                       std::string_view today, std::int64_t now_secs) {
    if (lookups.size() > kLifecycleBatchMax)
        return std::unexpected(Error{Kind::TooMany, "more than " +
                                                        std::to_string(kLifecycleBatchMax) +
                                                        " lookups in one call"});
    if (!is_lifecycle_date(today) || now_secs < 0)
        return std::unexpected(
            Error{Kind::InvalidInput, "today is not a calendar date or now_secs is negative"});
    std::set<std::string> distinct_keys;
    for (const auto& l : lookups) {
        if (const auto bad = validate_lifecycle_lookup(l.product_key, l.version))
            return std::unexpected(Error{Kind::InvalidInput, "a lookup is invalid: " + *bad});
        distinct_keys.insert(l.product_key);
    }
    if (lookups.empty())
        return std::vector<LifecycleEvaluation>{};

    // Both reads must answer or nothing does; a failed first read skips the second.
    const auto rules = rules_for(std::vector<std::string>(distinct_keys.begin(), distinct_keys.end()));
    if (!rules)
        return std::unexpected(Error{Kind::Unavailable, "lifecycle rows could not be read"});
    const auto declared = declared_for(lookups);
    if (!declared)
        return std::unexpected(Error{Kind::Unavailable, "lifecycle rows could not be read"});

    std::unordered_map<std::string, std::vector<LifecycleRule>> rules_by_key;
    for (const auto& r : *rules)
        rules_by_key[r.product_key].push_back(r);
    std::unordered_map<std::string, std::vector<DeclaredFact>> declared_by_key;
    for (const auto& d : *declared)
        declared_by_key[d.product_key].push_back(d);

    static const std::vector<LifecycleRule> kNoRules;
    static const std::vector<DeclaredFact> kNoFacts;
    std::vector<LifecycleEvaluation> out;
    out.reserve(lookups.size());
    for (const auto& l : lookups) {
        const auto r = rules_by_key.find(l.product_key);
        const auto d = declared_by_key.find(l.product_key);
        out.push_back(evaluate_lifecycle(l.product_key, l.version,
                                         r == rules_by_key.end() ? kNoRules : r->second,
                                         d == declared_by_key.end() ? kNoFacts : d->second, today,
                                         now_secs, software_catalogue::kStaleWindowSecs));
    }
    return out;
}

} // namespace yuzu::server
