// test_enablement_store_pg.cpp — EnablementStore behaviour on Postgres (ADR-3006
// PM1.1b). PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset (a SKIP reports Ok,
// so these prove nothing without the DSN), fails when it is set but broken.
//
// Each case clones a pre-migrated template (plugin_config_store v1..v3 + the
// leader_elector schema the epoch fence reads) and holds a LIVE elector, so the
// epoch the store's fence accepts is a real one. The falsifier cases drive the
// races deterministically with a second raw connection holding a row lock; none
// sleeps or polls on a clock.

#include "agent_registry.hpp" // detail::scope_kind_catalog
#include "capability_decls/all_fragments.hpp"
#include "enablement_store.hpp"
#include "key_provider.hpp"
#include "leader_elector.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "plugin_config_store.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <latch>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

using namespace yuzu::server;
namespace en = yuzu::server::enablement;
namespace fs = std::filesystem;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// One migration run, cloned per case: plugin_config_store v1..v3 (the enablement
// tables) and the leader_elector schema (the fence subquery targets it).
yuzu::test::PgTestTemplate enablement_tpl{"enablement", [](const std::string& dsn) {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    pg::SecretCodec codec(provider);
    PgPool pool{{.conninfo = dsn, .size = 1}};
    PluginConfigStore pcs{pool, codec};
    if (!pcs.is_open())
        throw std::runtime_error("enablement template: plugin_config_store failed to migrate");
    LeaderElector le{LeaderElector::Config{.dsn = dsn, .holder_id = "template"}};
    if (!le.is_open())
        throw std::runtime_error("enablement template: leader_elector failed to migrate");
}};

const std::vector<std::string_view>& kinds() {
    static const auto k = en::durable_attribute_kinds(yuzu::server::detail::scope_kind_catalog());
    return k;
}

en::UnitOverlay make_overlay() {
    auto r = en::build_unit_overlay({YUZU_ALL_CAPABILITY_FRAGMENTS}, en::kProtectivePredicate);
    if (!r)
        throw std::runtime_error("overlay build failed: " + r.error());
    return std::move(*r);
}

// -- raw SQL helpers (bypass the store's API) --------------------------------

void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

std::string query1(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) >= 1);
    return PQgetisnull(r.get(), 0, 0) ? "<null>" : PQgetvalue(r.get(), 0, 0);
}

std::int64_t query_i64(const std::string& dsn, const std::string& sql) {
    return std::stoll(query1(dsn, sql));
}

// Captures spdlog output for one case (restored in the destructor).
class LogCapture {
public:
    LogCapture() : saved_(spdlog::default_logger()) {
        sink_ = std::make_shared<spdlog::sinks::ostream_sink_mt>(stream_);
        auto logger = std::make_shared<spdlog::logger>("enablement_capture", sink_);
        logger->set_level(spdlog::level::trace);
        logger->set_pattern("%v");
        spdlog::set_default_logger(logger);
    }
    ~LogCapture() { spdlog::set_default_logger(saved_); }
    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;
    [[nodiscard]] bool says(std::string_view needle) const {
        return stream_.str().find(needle) != std::string::npos;
    }
    [[nodiscard]] std::string text() const { return stream_.str(); }

private:
    std::ostringstream stream_;
    std::shared_ptr<spdlog::sinks::ostream_sink_mt> sink_;
    std::shared_ptr<spdlog::logger> saved_;
};

const std::string kH1(64, 'a');
const std::string kH2(64, 'b');

/// A database clone, a pool, a store and a live elector holding leadership.
class EnablementPg {
public:
    EnablementPg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr)
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        db_.emplace(enablement_tpl);
        INFO("[EnablementPg] fixture status (blank == OK): " << db_->error());
        REQUIRE(db_->available());
        pool_.emplace(PgPool::Options{.conninfo = db_->dsn(), .size = 8});
        REQUIRE(pool_->valid());
        store = make_store();
        REQUIRE(store->is_open());
        elector = std::make_unique<LeaderElector>(
            LeaderElector::Config{.dsn = db_->dsn(), .holder_id = "test-leader"});
        REQUIRE(elector->is_open());
        REQUIRE(elector->try_acquire());
        REQUIRE(elector->epoch().has_value());
        epoch = *elector->epoch();
    }

    std::unique_ptr<EnablementStore> make_store(PgPool* pool = nullptr) {
        auto s = std::make_unique<EnablementStore>(pool ? *pool : *pool_, make_overlay(), kinds());
        s->set_metrics(&metrics);
        return s;
    }

    [[nodiscard]] const std::string& dsn() const { return db_->dsn(); }
    [[nodiscard]] PgPool& pool() { return *pool_; }
    [[nodiscard]] fs::path anchor() const { return dir.path / "enablement-anchor"; }
    [[nodiscard]] static std::string lock() { return kServerBackgroundLeaderLock; }

    double counter(const char* name, const yuzu::Labels& labels = {}) {
        return metrics.counter(name, labels).value();
    }

    EnablementStore::Registration reg(std::uint64_t seq, const std::string& boot = "boot-a") {
        return {boot, seq};
    }
    static EnablementStore::Identity ident(const std::string& host = "h1",
                                           const std::string& os = "linux") {
        return {host, os, "x86_64", "1.0"};
    }
    /// Register `n` endpoints ep001.. with the given os; all start at resolved_version 0.
    void seed(int n, const std::string& os = "linux") {
        for (int i = 1; i <= n; ++i) {
            char id[16];
            std::snprintf(id, sizeof id, "ep%03d", i);
            store->upsert_on_registration(id, ident("h" + std::to_string(i), os), reg(1));
        }
    }
    EnablementStore::BatchWrite batch(std::vector<en::DesiredRow> changed,
                                      std::vector<en::StampRow> unchanged, std::int64_t version,
                                      std::string cursor = "ep999") const {
        return {std::move(changed), std::move(unchanged), version, std::move(cursor), lock(), epoch};
    }

    yuzu::MetricsRegistry metrics;
    yuzu::test::TempDir dir{"yuzu_test_enablement_"};
    std::unique_ptr<EnablementStore> store;
    std::unique_ptr<LeaderElector> elector;
    std::int64_t epoch{0};

private:
    std::optional<yuzu::test::PostgresTestDb> db_;
    std::optional<PgPool> pool_;
};

en::RuleRow row(std::string id, std::vector<std::string> units, std::string selector = "__all__",
                std::string prov = "operator") {
    en::RuleRow r;
    r.id = std::move(id);
    r.units = std::move(units);
    r.selector = std::move(selector);
    r.provenance = std::move(prov);
    r.actor = "alice";
    r.audit_ref = "AUD-1";
    return r;
}

void seed_rules(const std::string& dsn, int n, bool active = true) {
    exec_sql(dsn, "INSERT INTO plugin_config_store.enablement_rules (id, units, selector, "
                  "provenance, active) SELECT 'seed' || lpad(g::text, 4, '0'), "
                  "ARRAY['wol.wake'], '__all__', 'operator', " +
                      std::string(active ? "TRUE" : "FALSE") +
                      " FROM generate_series(1, " + std::to_string(n) + ") g");
}

}  // namespace

// -- Migration ---------------------------------------------------------------

TEST_CASE("EnablementStore: schema v3 applies over an existing v2 plugin_config_store",
          "[pg][store][enablement]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    // v1 + v2 exactly as they shipped, recorded at version 2.
    {
        PgPool pool{{.conninfo = db.dsn(), .size = 1}};
        auto lease = pool.acquire();
        REQUIRE(lease);
        const std::vector<pg::PgMigration> v1v2 = {
            {1, "CREATE TABLE configs (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
                " plugin TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL DEFAULT '',"
                " updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_by TEXT NOT NULL DEFAULT '',"
                " UNIQUE (plugin, key));"
                "CREATE TABLE secrets (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
                " scope_key TEXT NOT NULL UNIQUE, plugin TEXT NOT NULL, key TEXT NOT NULL,"
                " sealed_value BYTEA NOT NULL DEFAULT ''::bytea,"
                " updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_by TEXT NOT NULL DEFAULT '',"
                " UNIQUE (plugin, key));"
                "CREATE TABLE kill_switches (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
                " scope_key TEXT NOT NULL UNIQUE, plugin TEXT NOT NULL,"
                " action TEXT NOT NULL DEFAULT '', enabled BOOLEAN NOT NULL DEFAULT TRUE,"
                " reason TEXT NOT NULL DEFAULT '', set_by TEXT NOT NULL DEFAULT '',"
                " updated_at TIMESTAMPTZ NOT NULL DEFAULT now());"},
            {2, "ALTER TABLE kill_switches ADD COLUMN os TEXT NOT NULL DEFAULT '';"},
        };
        REQUIRE(pg::PgMigrationRunner::run(lease.get(), "plugin_config_store", v1v2));
    }
    CHECK(query1(db.dsn(), "SELECT to_regclass('plugin_config_store.enablement_meta') IS NULL") == "t");
    CHECK(query1(db.dsn(), "SELECT version FROM public.schema_meta WHERE store='plugin_config_store'") == "2");

    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    pg::SecretCodec codec(provider);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    {
        EnablementStore before{pool, make_overlay(), kinds()};
        CHECK_FALSE(before.is_open()); // the v3 schema is not there yet
    }
    PluginConfigStore pcs{pool, codec};
    REQUIRE(pcs.is_open());
    CHECK(query1(db.dsn(), "SELECT version FROM public.schema_meta WHERE store='plugin_config_store'") == "3");

    EnablementStore store{pool, make_overlay(), kinds()};
    REQUIRE(store.is_open());
    auto meta = store.get_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->store_id.size() == 36);
    CHECK(meta->epoch == 1);
    CHECK(meta->counter == 0);
    CHECK(meta->rules_version == 1);
    CHECK_FALSE(meta->regressed);
    // The existing tables are untouched.
    CHECK(query1(db.dsn(), "SELECT count(*) FROM plugin_config_store.kill_switches") == "0");
}

// -- Rules --------------------------------------------------------------------

TEST_CASE("EnablementStore: put_rule writes, bumps rules_version once, refuses bad input",
          "[pg][store][enablement]") {
    EnablementPg f;
    const auto v0 = f.store->get_meta()->rules_version;
    REQUIRE(f.store->put_rule(row("r1", {"wol.wake"}, R"(ostype == "linux")", "carried_over")));
    CHECK(f.store->get_meta()->rules_version == v0 + 1);
    auto rules = f.store->list_rules(true);
    REQUIRE(rules.has_value());
    REQUIRE(rules->size() == 1);
    CHECK((*rules)[0].provenance == "carried_over"); // the frozen wire spelling
    CHECK((*rules)[0].actor == "alice");
    CHECK((*rules)[0].units == std::vector<std::string>{"wol.wake"});

    // Each refusal is InvalidInput and leaves rules_version alone.
    const auto v1 = f.store->get_meta()->rules_version;
    const std::vector<en::RuleRow> bad = {
        row("b1", {"gone.unit"}),                                   // unknown unit
        row("b2", {"wol.wake"}, ""),                                // empty selector
        row("b3", {"wol.wake"}, R"(nosuchattr == "x")"),            // unknown attribute
        row("b4", {"wol.wake"}, R"(ostype == "plan9")"),            // ostype outside the closed set
        row("b5", {"wol.wake"}, "__all__", "Operator"),             // provenance spelling
        row("b6", std::vector<std::string>(65, "wol.wake")),        // 65 units
        row(std::string(65, 'x'), {"wol.wake"}),                    // id length
        row("b7", {}),                                              // no units
    };
    for (const auto& b : bad) {
        INFO(b.id);
        auto r = f.store->put_rule(b);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == EnablementStore::Error::InvalidInput);
    }
    CHECK(f.store->get_meta()->rules_version == v1);
    CHECK(f.store->list_rules(false)->size() == 1);
}

TEST_CASE("EnablementStore: the rule cap is serialised - two concurrent authors at 999 admit one",
          "[pg][store][enablement]") {
    EnablementPg f;
    seed_rules(f.dsn(), 999);
    PgPool pool_a{{.conninfo = f.dsn(), .size = 2}};
    PgPool pool_b{{.conninfo = f.dsn(), .size = 2}};
    auto a = f.make_store(&pool_a);
    auto b = f.make_store(&pool_b);
    REQUIRE(a->is_open());
    REQUIRE(b->is_open());
    std::latch start{2};
    std::expected<void, EnablementStore::Error> ra, rb;
    std::thread ta([&] { start.arrive_and_wait(); ra = a->put_rule(row("new_a", {"wol.wake"})); });
    std::thread tb([&] { start.arrive_and_wait(); rb = b->put_rule(row("new_b", {"wol.wake"})); });
    ta.join();
    tb.join();
    CHECK((ra.has_value() != rb.has_value())); // exactly one succeeded
    CHECK(query_i64(f.dsn(), "SELECT count(*) FROM plugin_config_store.enablement_rules WHERE active") == 1000);
}

TEST_CASE("EnablementStore: the cap counts active rules other than the target (edit vs add)",
          "[pg][store][enablement]") {
    EnablementPg f;
    seed_rules(f.dsn(), 1000);
    exec_sql(f.dsn(), "INSERT INTO plugin_config_store.enablement_rules (id, units, selector, "
                      "provenance, active) VALUES ('inactive1', ARRAY['wol.wake'], '__all__', "
                      "'operator', FALSE)");
    // Editing an existing ACTIVE rule at the cap passes.
    REQUIRE(f.store->put_rule(row("seed0001", {"wol.check"}, R"(ostype == "darwin")")));
    CHECK(query1(f.dsn(), "SELECT selector FROM plugin_config_store.enablement_rules WHERE id='seed0001'") ==
          R"(ostype == "darwin")");
    CHECK(query_i64(f.dsn(), "SELECT count(*) FROM plugin_config_store.enablement_rules WHERE active") == 1000);
    // A new id and a re-activation are refused.
    auto fresh = f.store->put_rule(row("brand_new", {"wol.wake"}));
    REQUIRE_FALSE(fresh.has_value());
    CHECK(fresh.error() == EnablementStore::Error::InvalidInput);
    CHECK_FALSE(f.store->put_rule(row("inactive1", {"wol.wake"})).has_value());
    // The refused authoring left no bump behind.
    const auto v = f.store->get_meta()->rules_version;
    CHECK_FALSE(f.store->put_rule(row("brand_new", {"wol.wake"})).has_value());
    CHECK(f.store->get_meta()->rules_version == v);
    // Deactivating at the cap always succeeds, and frees one slot.
    REQUIRE(f.store->deactivate_rule("seed0002"));
    REQUIRE(f.store->put_rule(row("inactive1", {"wol.wake"})));
    CHECK(query_i64(f.dsn(), "SELECT count(*) FROM plugin_config_store.enablement_rules WHERE active") == 1000);
    // A missing rule is NotFound and rolls its bump back.
    const auto v2 = f.store->get_meta()->rules_version;
    auto missing = f.store->deactivate_rule("no_such_rule");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == EnablementStore::Error::NotFound);
    CHECK(f.store->get_meta()->rules_version == v2);
}

TEST_CASE("EnablementStore: the loader keeps surviving units and never skips a bad rule silently",
          "[pg][store][enablement]") {
    EnablementPg f;
    LogCapture log;
    const std::string t = "INSERT INTO plugin_config_store.enablement_rules (id, units, selector, provenance) VALUES ";
    exec_sql(f.dsn(), t + "('mixed', ARRAY['gone.unit','wol.wake'], '__all__', 'operator')");
    exec_sql(f.dsn(), t + "('good1', ARRAY['wol.check'], 'ostype == \"linux\"', 'system')");
    exec_sql(f.dsn(), t + "('badsel', ARRAY['wol.wake'], 'from_result_set:rs_1 == \"true\"', 'operator')");
    exec_sql(f.dsn(), t + "('badpat', ARRAY['wol.wake'], 'hostname MATCHES \"(\"', 'operator')");
    exec_sql(f.dsn(), t + "('badunit', ARRAY['A.b'], '__all__', 'operator')");

    auto loaded = f.store->load_rules();
    REQUIRE(loaded.has_value());
    CHECK(loaded->rules.size() == 2);
    CHECK(loaded->quarantined == std::vector<std::string>{"badpat", "badsel", "badunit"});
    CHECK(f.counter("yuzu_server_enablement_rules_rejected_total", {{"reason", "refused"}}) == 3);
    CHECK(f.counter("yuzu_server_enablement_rules_rejected_total", {{"reason", "caps"}}) == 0);
    CHECK(loaded->unresolved_units == std::vector<std::string>{"gone.unit"});
    CHECK(f.metrics.gauge("yuzu_server_enablement_unresolved_units").value() == 1);

    // One warn line per bad rule, naming the id and the label - never the pattern text.
    for (const char* id : {"badsel", "badpat", "badunit"})
        CHECK(log.says(std::string("rule ") + id + " refused at load: refused"));
    CHECK_FALSE(log.says("MATCHES"));
    CHECK(log.says("gone.unit"));

    // Resolving the mixed rule keeps wol.wake off despite the stale name.
    std::vector<en::Rule> one;
    for (auto& r : loaded->rules)
        if (r.id == "mixed")
            one.push_back(std::move(r));
    REQUIRE(one.size() == 1);
    CHECK(one[0].units == std::vector<std::string>{"gone.unit", "wol.wake"});
    auto res = en::resolve(one, f.store->overlay(), "windows",
                           [](std::string_view) { return std::string{}; });
    REQUIRE(res.has_value());
    bool wake_off = false;
    for (const auto& o : res->off)
        wake_off = wake_off || o.unit == "wol.wake";
    CHECK(wake_off);
}

TEST_CASE("EnablementStore: a rule id carrying control bytes is quarantined and never reaches the log raw",
          "[pg][store][enablement]") {
    EnablementPg f;
    LogCapture log;
    exec_sql(f.dsn(), "INSERT INTO plugin_config_store.enablement_rules (id, units, selector, "
                      "provenance) VALUES (chr(10) || 'bad' || chr(1), ARRAY['wol.wake'], "
                      "'__all__', 'operator')");
    auto loaded = f.store->load_rules();
    REQUIRE(loaded.has_value());
    CHECK(loaded->rules.empty());
    REQUIRE(loaded->quarantined.size() == 1);
    CHECK(f.counter("yuzu_server_enablement_rules_rejected_total", {{"reason", "caps"}}) == 1);
    const std::string text = log.text();
    CHECK(text.find('\x01') == std::string::npos);
    CHECK(log.says("rule _bad_ refused at load: caps"));
}

TEST_CASE("EnablementStore: load_rules returns a version and rows from ONE snapshot",
          "[pg][store][enablement]") {
    EnablementPg f;
    // Each put adds exactly one rule and bumps the version once, in one transaction, so
    // a consistent snapshot always satisfies rules == rules_version - 1.
    auto writer = f.make_store();
    std::atomic<bool> done{false};
    std::atomic<int> write_failures{0};
    std::thread t([&] {
        for (int i = 0; i < 40; ++i)
            if (!writer->put_rule(row("w" + std::to_string(1000 + i), {"wol.wake"})))
                ++write_failures;
        done = true;
    });
    int checked = 0;
    while (!done.load() || checked == 0) {
        auto loaded = f.store->load_rules();
        REQUIRE(loaded.has_value());
        CHECK(static_cast<std::int64_t>(loaded->rules.size()) == loaded->rules_version - 1);
        ++checked;
    }
    t.join();
    CHECK(write_failures.load() == 0);
    auto last = f.store->load_rules();
    CHECK(last->rules.size() == 40);
}

// -- Endpoints -----------------------------------------------------------------------

TEST_CASE("EnablementStore: registration writes identity and bumps input_gen",
          "[pg][store][enablement]") {
    EnablementPg f;
    f.store->upsert_on_registration("ep1", EnablementPg::ident("host-a"), f.reg(1));
    auto e = f.store->get_endpoint("ep1");
    REQUIRE(e.has_value());
    CHECK(e->identity.hostname == "host-a");
    CHECK(e->identity.os == "linux");
    CHECK(e->reg_boot_id == "boot-a");
    CHECK(e->reg_seq == 1);
    CHECK(e->input_gen == 1);
    CHECK(e->resolved_version == 0);
    CHECK_FALSE(e->pending);

    // A re-registration bumps input_gen and clears resolved_version.
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_endpoints SET resolved_version = 5");
    f.store->upsert_on_registration("ep1", EnablementPg::ident("host-a"), f.reg(2));
    CHECK(f.store->get_endpoint("ep1")->input_gen == 2);
    CHECK(f.store->get_endpoint("ep1")->resolved_version == 0);
    // A changed hostname rewrites the identity.
    f.store->upsert_on_registration("ep1", EnablementPg::ident("renamed"), f.reg(3));
    CHECK(f.store->get_endpoint("ep1")->identity.hostname == "renamed");
}

TEST_CASE("EnablementStore: a retired endpoint is never written by registration",
          "[pg][store][enablement]") {
    EnablementPg f;
    f.seed(1);
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_endpoints SET retired_at = now()");
    f.store->upsert_on_registration("ep001", EnablementPg::ident("changed"), f.reg(2));
    CHECK(f.counter("yuzu_server_enablement_registration_skipped_total", {{"reason", "retired"}}) == 1);
    auto e = f.store->get_endpoint("ep001");
    REQUIRE(e.has_value());
    CHECK(e->identity.hostname == "h1");
    CHECK(e->input_gen == 1);
}

TEST_CASE("EnablementStore: an older registration's observer can never overwrite a newer one",
          "[pg][store][enablement]") {
    EnablementPg f;
    f.store->upsert_on_registration("ep1", EnablementPg::ident("h2"), f.reg(2));
    const auto gen = f.store->get_endpoint("ep1")->input_gen;
    // The older registration's observer completes AFTER the newer one's.
    f.store->upsert_on_registration("ep1", EnablementPg::ident("h1"), f.reg(1));
    auto e = f.store->get_endpoint("ep1");
    CHECK(e->identity.hostname == "h2");
    CHECK(e->reg_seq == 2);
    CHECK(e->input_gen == gen);
    CHECK(f.counter("yuzu_server_enablement_registration_skipped_total", {{"reason", "stale"}}) == 1);
    // A different process (boot id) always wins.
    f.store->upsert_on_registration("ep1", EnablementPg::ident("h3"), f.reg(1, "boot-c"));
    e = f.store->get_endpoint("ep1");
    CHECK(e->identity.hostname == "h3");
    CHECK(e->reg_boot_id == "boot-c");
    CHECK(e->input_gen == gen + 1);
}

TEST_CASE("EnablementStore: an invalid registration identity writes nothing", "[pg][store][enablement]") {
    EnablementPg f;
    f.store->upsert_on_registration("ep1", EnablementPg::ident(std::string(257, 'h')), f.reg(1));
    f.store->upsert_on_registration("ep2", EnablementPg::ident("bad\nhost"), f.reg(1));
    f.store->upsert_on_registration("ep3", EnablementPg::ident("ok"), {"", 1});
    CHECK(f.counter("yuzu_server_enablement_registration_skipped_total", {{"reason", "invalid_identity"}}) == 3);
    CHECK(query_i64(f.dsn(), "SELECT count(*) FROM plugin_config_store.enablement_endpoints") == 0);
}

// -- Reports -----------------------------------------------------------------------

TEST_CASE("EnablementStore: record_report is one conditional UPDATE", "[pg][store][enablement]") {
    EnablementPg f;
    f.seed(1);
    const auto xmin = [&] {
        return query1(f.dsn(), "SELECT xmin::text FROM plugin_config_store.enablement_endpoints");
    };
    auto first = f.store->record_report("ep001", 1, 0, "");
    REQUIRE(first.has_value());
    CHECK(*first == EnablementStore::ReportOutcome::Written);
    const auto after_first = xmin();
    for (int i = 0; i < 49; ++i) {
        auto again = f.store->record_report("ep001", 1, 0, "");
        REQUIRE(again.has_value());
        CHECK(*again == EnablementStore::ReportOutcome::Skipped);
    }
    CHECK(xmin() == after_first); // 50 identical reports, one UPDATE

    // A changed report writes; one equal to desired clears pending_since.
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_endpoints SET desired_epoch=1, "
                      "desired_counter=0, desired_hash='" + kH1 + "', pending_since=now()");
    CHECK(f.store->get_endpoint("ep001")->pending);
    CHECK(*f.store->record_report("ep001", 1, 0, kH1) == EnablementStore::ReportOutcome::Written);
    CHECK_FALSE(f.store->get_endpoint("ep001")->pending);

    // Above the store's highest: Ahead, flagged and counted, but never declared here.
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_meta SET counter = 5");
    auto ahead = f.store->record_report("ep001", 1, 9, kH1);
    REQUIRE(ahead.has_value());
    CHECK(*ahead == EnablementStore::ReportOutcome::Ahead);
    CHECK(f.counter("yuzu_server_enablement_report_ahead_total") == 1);
    CHECK(f.store->get_endpoint("ep001")->report_ahead);
    f.store->refresh_regression();
    CHECK(f.store->regression().report_ahead_endpoints == 1);
    CHECK_FALSE(f.store->regression().regressed);
    CHECK(query1(f.dsn(), "SELECT regressed_at IS NULL FROM plugin_config_store.enablement_meta") == "t");
    // A report back at or below the store's highest un-flags it.
    CHECK(*f.store->record_report("ep001", 1, 3, kH1) == EnablementStore::ReportOutcome::Written);
    CHECK_FALSE(f.store->get_endpoint("ep001")->report_ahead);

    auto unknown = f.store->record_report("nobody", 1, 0, "");
    REQUIRE_FALSE(unknown.has_value());
    CHECK(unknown.error() == EnablementStore::Error::NotFound);
    for (const auto& [e, c, h] : std::vector<std::tuple<int, int, std::string>>{
             {1, -1, ""}, {-1, 0, ""}, {1, 1, std::string(63, 'a')}, {1, 1, std::string(64, 'A')}}) {
        auto r = f.store->record_report("ep001", e, c, h);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == EnablementStore::Error::InvalidInput);
    }
}

TEST_CASE("EnablementStore: a report equal to the previous desired state never clears the next one's pending",
          "[pg][store][enablement]") {
    EnablementPg f;
    f.seed(1);
    // Issue state 1 for ep001 and let it report.
    auto issued = f.store->set_desired_batch(f.batch({{"ep001", 1, {"wol.wake"}, kH1}}, {}, 1));
    REQUIRE(issued.has_value());
    auto e1 = f.store->get_endpoint("ep001");
    REQUIRE(e1->pending);
    const auto epoch = e1->desired_epoch;
    const auto c1 = e1->desired_counter;
    REQUIRE(*f.store->record_report("ep001", epoch, c1, kH1) == EnablementStore::ReportOutcome::Written);
    REQUIRE_FALSE(f.store->get_endpoint("ep001")->pending);
    // Make the duplicate-suppression window open so the next report passes the WHERE.
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_endpoints SET "
                      "last_report_at = now() - interval '2 hours'");

    // A holds a row lock while it issues state 2 (what set_desired_batch's row UPDATE does).
    PgConn a{PQconnectdb(f.dsn().c_str())};
    REQUIRE(PQstatus(a.get()) == CONNECTION_OK);
    REQUIRE(PgResult{PQexec(a.get(), "BEGIN")}.ok());
    // (the reservation that issuing state 2 would have made on the meta row)
    REQUIRE(PgResult{PQexec(a.get(), "UPDATE plugin_config_store.enablement_meta SET counter = counter + 1")}.ok());
    REQUIRE(PgResult{PQexec(a.get(),
                            ("UPDATE plugin_config_store.enablement_endpoints SET desired_counter = " +
                             std::to_string(c1 + 1) + ", desired_hash = '" + kH2 +
                             "', pending_since = now() WHERE agent_id = 'ep001'")
                                .c_str())}
                .ok());
    // B reports the PREVIOUS state while A is uncommitted (or just after - the result is the same).
    std::expected<EnablementStore::ReportOutcome, EnablementStore::Error> b_result;
    std::thread b([&] { b_result = f.store->record_report("ep001", epoch, c1, kH1); });
    REQUIRE(PgResult{PQexec(a.get(), "COMMIT")}.ok());
    b.join();
    REQUIRE(b_result.has_value());
    // The CASE was evaluated against the committed state 2: pending is NOT cleared.
    CHECK(f.store->get_endpoint("ep001")->pending);
    // A report of state 2 clears it.
    CHECK(*f.store->record_report("ep001", epoch, c1 + 1, kH2) == EnablementStore::ReportOutcome::Written);
    CHECK_FALSE(f.store->get_endpoint("ep001")->pending);
}

// -- Batches -----------------------------------------------------------------------

TEST_CASE("EnablementStore: set_desired_batch issues ordered counters",
          "[pg][store][enablement]") {
    EnablementPg f;
    f.seed(5);
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_meta SET rules_version = 2");
    const auto stale_rows = [&] {
        return query_i64(f.dsn(), "SELECT count(*) FROM plugin_config_store.enablement_endpoints "
                                  "WHERE resolved_version < 2 AND retired_at IS NULL");
    };
    CHECK(stale_rows() == 5);

    const auto c0 = f.store->get_meta()->counter;
    auto res = f.store->set_desired_batch(
        f.batch({{"ep005", 1, {"wol.wake"}, kH1}, {"ep001", 1, {"wol.check", "wol.wake"}, kH2},
                 {"ep003", 1, {}, kH1}},
                {{"ep002", 1}, {"ep004", 1}}, 2, "ep005"));
    REQUIRE(res.has_value());
    CHECK(res->issued == 3);
    CHECK(res->written == 3);
    CHECK(res->stamped == 2);
    const auto meta = f.store->get_meta();
    CHECK(meta->counter == c0 + 3);
    CHECK(meta->job_cursor == "ep005");
    // Counters are strictly increasing in agent_id order from the reserved range.
    const auto counter_of = [&](const char* id) { return f.store->get_endpoint(id)->desired_counter; };
    CHECK(counter_of("ep001") == c0 + 1);
    CHECK(counter_of("ep003") == c0 + 2);
    CHECK(counter_of("ep005") == c0 + 3);
    CHECK(f.store->get_endpoint("ep001")->desired_units == std::vector<std::string>{"wol.check", "wol.wake"});
    CHECK(f.store->get_endpoint("ep003")->desired_units.empty());
    CHECK(f.store->get_endpoint("ep001")->pending);
    CHECK_FALSE(f.store->get_endpoint("ep002")->pending); // stamped only
    CHECK(f.store->get_endpoint("ep002")->desired_hash.empty());
    CHECK(stale_rows() == 0);

    // An identical second pass issues nothing and changes no desired_*.
    auto again = f.store->set_desired_batch(
        f.batch({}, {{"ep001", 1}, {"ep002", 1}, {"ep003", 1}, {"ep004", 1}, {"ep005", 1}}, 2));
    REQUIRE(again.has_value());
    CHECK(again->issued == 0);
    CHECK(f.store->get_meta()->counter == c0 + 3);
    CHECK(counter_of("ep001") == c0 + 1);

    // A row retired before the write is left untouched.
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_endpoints SET retired_at = now() "
                      "WHERE agent_id = 'ep001'");
    auto retired = f.store->set_desired_batch(f.batch({{"ep001", 1, {"x.y"}, kH1}}, {}, 3));
    REQUIRE(retired.has_value());
    CHECK(retired->written == 0);
    CHECK(counter_of("ep001") == c0 + 1);

    // After a declaration the batch is refused.
    REQUIRE(f.store->set_regressed("test"));
    auto frozen = f.store->set_desired_batch(f.batch({{"ep003", 1, {}, kH1}}, {}, 3));
    REQUIRE_FALSE(frozen.has_value());
    CHECK(frozen.error() == EnablementStore::Error::Regressed);
}

TEST_CASE("EnablementStore: an input change landing before the write leaves the row stale",
          "[pg][store][enablement]") {
    EnablementPg f;
    f.seed(3);
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_meta SET rules_version = 2");
    // The batch was planned at input_gen 1; ep002's input then changes (as a registration does).
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_endpoints SET input_gen = input_gen + 1, "
                      "resolved_version = 0 WHERE agent_id = 'ep002'");
    auto res = f.store->set_desired_batch(f.batch(
        {{"ep001", 1, {"wol.wake"}, kH1}, {"ep002", 1, {"wol.wake"}, kH1}}, {{"ep003", 1}}, 2));
    REQUIRE(res.has_value());
    CHECK(res->issued == 2);   // the counter was reserved ...
    CHECK(res->written == 1);  // ... but ep002's write was refused
    CHECK(res->stamped == 1);
    auto e2 = f.store->get_endpoint("ep002");
    CHECK(e2->resolved_version == 0);
    CHECK(e2->desired_hash.empty());
    CHECK(e2->input_gen == 2);
    CHECK(query_i64(f.dsn(), "SELECT count(*) FROM plugin_config_store.enablement_endpoints "
                             "WHERE resolved_version < 2") == 1);
}

TEST_CASE("EnablementStore: a batch at a stale epoch is fenced and writes nothing",
          "[pg][store][enablement]") {
    EnablementPg f;
    f.seed(2);
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_meta SET rules_version = 2");
    const auto before = f.store->get_meta();
    auto stale = f.store->set_desired_batch(
        {{{"ep001", 1, {"wol.wake"}, kH1}}, {}, 2, "ep001", f.lock(), f.epoch - 1});
    REQUIRE_FALSE(stale.has_value());
    CHECK(stale.error() == EnablementStore::Error::Fenced);
    const auto after = f.store->get_meta();
    CHECK(after->counter == before->counter);
    CHECK(after->job_cursor == before->job_cursor);
    CHECK(f.store->get_endpoint("ep001")->desired_hash.empty());

    // The live epoch writes.
    REQUIRE(f.store->set_desired_batch(f.batch({{"ep001", 1, {"wol.wake"}, kH1}}, {}, 2)));

    // After the elector hands over, the OLD epoch is fenced and the NEW one writes.
    f.elector->resign();
    LeaderElector second{LeaderElector::Config{.dsn = f.dsn(), .holder_id = "second"}};
    REQUIRE(second.is_open());
    REQUIRE(second.try_acquire());
    const auto e2 = *second.epoch();
    REQUIRE(e2 > f.epoch);
    auto old = f.store->set_desired_batch(f.batch({{"ep002", 1, {"wol.wake"}, kH1}}, {}, 2));
    REQUIRE_FALSE(old.has_value());
    CHECK(old.error() == EnablementStore::Error::Fenced);
    auto fresh = f.store->set_desired_batch(
        {{{"ep002", 1, {"wol.wake"}, kH1}}, {}, 2, "ep002", f.lock(), e2});
    REQUIRE(fresh.has_value());
    CHECK(fresh->written == 1);
}

TEST_CASE("EnablementStore: a declaration and a batch serialise on the meta row (freeze race)",
          "[pg][store][enablement]") {
    EnablementPg f;
    f.seed(2);
    const std::string fence = LeaderElector::epoch_fence_sql(f.lock(), f.epoch);

    SECTION("a batch's first statement in flight, a declaration waits, then wins") {
        PgConn a{PQconnectdb(f.dsn().c_str())};
        REQUIRE(PQstatus(a.get()) == CONNECTION_OK);
        REQUIRE(PgResult{PQexec(a.get(), "BEGIN")}.ok());
        REQUIRE(PgResult{PQexec(a.get(),
                                ("UPDATE plugin_config_store.enablement_meta SET counter = counter + 1 "
                                 "WHERE id = 1 AND regressed_at IS NULL AND " + fence +
                                 " RETURNING counter")
                                    .c_str())}
                    .status() == PGRES_TUPLES_OK);
        // B's declaration blocks on the meta row A holds.
        std::expected<void, EnablementStore::Error> declared;
        std::thread b([&] { declared = f.store->set_regressed("race"); });
        REQUIRE(PgResult{PQexec(a.get(), "ROLLBACK")}.ok());
        b.join();
        REQUIRE(declared.has_value());
        auto next = f.store->set_desired_batch(f.batch({{"ep001", 1, {}, kH1}}, {}, 1));
        REQUIRE_FALSE(next.has_value());
        CHECK(next.error() == EnablementStore::Error::Regressed);
        CHECK(f.store->get_meta()->counter == 0);
    }
    SECTION("a declaration in flight, a batch waits, then is refused - nothing commits after it") {
        PgConn b{PQconnectdb(f.dsn().c_str())};
        REQUIRE(PQstatus(b.get()) == CONNECTION_OK);
        REQUIRE(PgResult{PQexec(b.get(), "BEGIN")}.ok());
        REQUIRE(PgResult{PQexec(b.get(),
                                "UPDATE plugin_config_store.enablement_meta SET regressed_at = now(), "
                                "regressed_reason = 'race' WHERE id = 1")}
                    .ok());
        std::expected<EnablementStore::BatchResult, EnablementStore::Error> batch;
        std::thread a([&] {
            batch = f.store->set_desired_batch(f.batch({{"ep001", 1, {}, kH1}}, {}, 1));
        });
        REQUIRE(PgResult{PQexec(b.get(), "COMMIT")}.ok());
        a.join();
        REQUIRE_FALSE(batch.has_value());
        CHECK(batch.error() == EnablementStore::Error::Regressed);
        CHECK(f.store->get_endpoint("ep001")->desired_hash.empty());
        CHECK(f.store->get_meta()->counter == 0);
    }
}

// -- Continuity ---------------------------------------------------------------------

TEST_CASE("EnablementStore: the continuity anchor - unwitnessed, regressed, idempotent, never lowered",
          "[pg][store][enablement]") {
    EnablementPg f;
    const auto meta0 = f.store->get_meta();
    REQUIRE(meta0.has_value());

    // No file: unwitnessed, counted, latched, and the anchor is then written.
    auto first = f.store->check_continuity_at_boot(f.anchor());
    REQUIRE(first.has_value());
    CHECK(*first == en::Continuity::Unwitnessed);
    CHECK(f.counter("yuzu_server_enablement_anchor_unwitnessed_total") == 1);
    CHECK(f.store->regression().anchor_unwitnessed);
    CHECK_FALSE(f.store->regression().regressed);
    std::ifstream in(f.anchor(), std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    auto parsed = en::parse_anchor(text);
    REQUIRE(parsed.has_value());
    CHECK(parsed->store_id == meta0->store_id);
    CHECK(parsed->counter == meta0->counter);
    // A healthy second boot against its own anchor is Ok.
    auto healthy = f.make_store();
    CHECK(*healthy->check_continuity_at_boot(f.anchor()) == en::Continuity::Ok);

    // The file ahead of the store (a dump restored behind it): Regressed, declared once.
    {
        std::ofstream out(f.anchor(), std::ios::binary | std::ios::trunc);
        out << en::render_anchor({meta0->store_id, meta0->epoch, meta0->counter + 10});
    }
    auto second = f.make_store();
    auto verdict = second->check_continuity_at_boot(f.anchor());
    REQUIRE(verdict.has_value());
    CHECK(*verdict == en::Continuity::Regressed);
    CHECK(second->regression().regressed);
    CHECK(second->regression().reason == "store_behind");
    CHECK(f.metrics.gauge("yuzu_server_enablement_regressed").value() == 1);
    const auto when = query1(f.dsn(), "SELECT regressed_at::text FROM plugin_config_store.enablement_meta");
    auto third = f.make_store();
    CHECK(*third->check_continuity_at_boot(f.anchor()) == en::Continuity::Regressed);
    CHECK(query1(f.dsn(), "SELECT regressed_at::text FROM plugin_config_store.enablement_meta") == when);
    CHECK(query1(f.dsn(), "SELECT regressed_reason FROM plugin_config_store.enablement_meta") == "store_behind");
    // A replica that only reads the meta row sees the declaration too.
    f.store->refresh_regression();
    CHECK(f.store->regression().regressed);

    // write_anchor on a regressed store never lowers the file.
    CHECK(second->write_anchor(f.anchor()) == EnablementStore::AnchorWrite::Refused);
    {
        std::ifstream again(f.anchor(), std::ios::binary);
        std::string now((std::istreambuf_iterator<char>(again)), std::istreambuf_iterator<char>());
        CHECK(en::parse_anchor(now)->counter == meta0->counter + 10);
    }

    // Another store's id, an unparseable file and an over-long one are all regressions.
    REQUIRE(f.store->resolve_regression());
    for (const auto& [content, reason] : std::vector<std::pair<std::string, std::string>>{
             {en::render_anchor({"00000000-0000-0000-0000-000000000000", 1, 0}), "store_id_mismatch"},
             {"not an anchor", "anchor_unparseable"},
             {std::string(513, '0'), "anchor_unparseable"}}) {
        INFO(reason);
        {
            std::ofstream out(f.anchor(), std::ios::binary | std::ios::trunc);
            out << content;
        }
        auto probe = f.make_store();
        CHECK(*probe->check_continuity_at_boot(f.anchor()) == en::Continuity::Regressed);
        CHECK(probe->regression().reason == reason);
        REQUIRE(f.store->resolve_regression());
    }
}

TEST_CASE("EnablementStore: write_anchor reads the meta row, and the file, authoritatively",
          "[pg][store][enablement]") {
    EnablementPg f;
    REQUIRE(f.store->check_continuity_at_boot(f.anchor()).has_value());
    const auto read_file = [&] {
        std::ifstream in(f.anchor(), std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    };

    // A SECOND instance declares; the first has not refreshed its cache.
    auto other = f.make_store();
    REQUIRE(other->set_regressed("elsewhere"));
    REQUIRE_FALSE(f.store->regression().regressed); // A's cache is stale ...
    f.seed(1);
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_meta SET counter = counter + 4");
    const std::string untouched = read_file();
    // ... but the write is authoritative: refused, and the file is unchanged.
    CHECK(f.store->write_anchor(f.anchor()) == EnablementStore::AnchorWrite::Refused);
    CHECK(f.counter("yuzu_server_enablement_anchor_write_refused_total", {{"reason", "regressed"}}) == 1);
    CHECK(read_file() == untouched);

    // Resolve, then put the FILE ahead while the instance runs: refused, declared, not lowered.
    REQUIRE(other->resolve_regression());
    const auto meta = f.store->get_meta();
    {
        std::ofstream out(f.anchor(), std::ios::binary | std::ios::trunc);
        out << en::render_anchor({meta->store_id, meta->epoch, meta->counter + 10});
    }
    CHECK(f.store->write_anchor(f.anchor()) == EnablementStore::AnchorWrite::Refused);
    CHECK(f.counter("yuzu_server_enablement_anchor_write_refused_total", {{"reason", "file_ahead"}}) == 1);
    CHECK(en::parse_anchor(read_file())->counter == meta->counter + 10);
    CHECK(query1(f.dsn(), "SELECT regressed_reason FROM plugin_config_store.enablement_meta") == "store_behind");
}

TEST_CASE("EnablementStore: the anchor is written atomically, ignores stale temp files, matches the store",
          "[pg][store][enablement]") {
    EnablementPg f;
    f.seed(2);
    fs::create_directories(f.dir.path);
    {
        std::ofstream stale(f.anchor().string() + ".tmp.deadbeef", std::ios::binary);
        stale << "half written";
    }
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_meta SET rules_version = 2");
    REQUIRE(f.store->set_desired_batch(
        f.batch({{"ep001", 1, {"wol.wake"}, kH1}, {"ep002", 1, {}, kH2}}, {}, 2)));
    CHECK(f.store->write_anchor(f.anchor()) == EnablementStore::AnchorWrite::Written);
    std::ifstream in(f.anchor(), std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const auto parsed = en::parse_anchor(text);
    REQUIRE(parsed.has_value());
    const auto meta = f.store->get_meta();
    CHECK(*parsed == en::Anchor{meta->store_id, meta->epoch, meta->counter});
    CHECK(parsed->counter == 2);
    // Only the pre-existing stale temp remains; this write left no residue of its own.
    int temps = 0;
    for (const auto& e : fs::directory_iterator(f.dir.path))
        if (e.path().filename().string().find(".tmp.") != std::string::npos)
            ++temps;
    CHECK(temps == 1);
}

TEST_CASE("EnablementStore: a second replica answers pending-with-age from the row",
          "[pg][store][enablement]") {
    EnablementPg f;
    f.seed(1);
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_meta SET rules_version = 2");
    REQUIRE(f.store->set_desired_batch(f.batch({{"ep001", 1, {"wol.wake"}, kH1}}, {}, 2)));
    PgPool pool_b{{.conninfo = f.dsn(), .size = 2}};
    auto b = f.make_store(&pool_b);
    auto e = b->get_endpoint("ep001");
    REQUIRE(e.has_value());
    CHECK(e->pending);
    REQUIRE(e->pending_age_seconds.has_value());
    CHECK(*e->pending_age_seconds >= 0);
    CHECK(e->desired_hash == kH1);
    CHECK(e->desired_units == std::vector<std::string>{"wol.wake"});
    CHECK(e->desired_counter == 1);
}

TEST_CASE("EnablementStore: a release that changes the unit overlay makes every row stale",
          "[pg][store][enablement]") {
    EnablementPg f;
    const auto v0 = f.store->get_meta()->rules_version;
    CHECK(f.store->sync_overlay_hash(kH1).value());
    CHECK(f.store->get_meta()->rules_version == v0 + 1);
    CHECK_FALSE(f.store->sync_overlay_hash(kH1).value()); // unchanged: no bump
    CHECK(f.store->get_meta()->rules_version == v0 + 1);
    CHECK(f.store->sync_overlay_hash(kH2).value());
    CHECK(f.store->get_meta()->rules_version == v0 + 2);
}

TEST_CASE("EnablementStore: a read that cannot be served is a typed Unavailable, never an empty success",
          "[pg][store][enablement]") {
    EnablementPg f;
    PgPool short_pool{{.conninfo = f.dsn(), .size = 2, .lock_timeout_ms = 100}};
    auto store = f.make_store(&short_pool);
    REQUIRE(store->is_open());
    PgConn locker{PQconnectdb(f.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(PgResult{PQexec(locker.get(), "BEGIN")}.ok());
    REQUIRE(PgResult{PQexec(locker.get(), "LOCK TABLE plugin_config_store.enablement_rules IN ACCESS EXCLUSIVE MODE")}.ok());
    auto r = store->list_rules(true);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == EnablementStore::Error::Unavailable);
    CHECK(f.counter("yuzu_server_enablement_read_degrade_total", {{"reason", "query_error"}}) == 1);
    REQUIRE(PgResult{PQexec(locker.get(), "ROLLBACK")}.ok());
    CHECK(store->list_rules(true).has_value());
}
