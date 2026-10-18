// test_enablement_store_pg.cpp — EnablementStore behaviour on Postgres (ADR-3006).
// PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset (a SKIP reports Ok,
// so these prove nothing without the DSN), fails when it is set but broken.
//
// Each case clones a pre-migrated template (plugin_config_store v1..v3 + the
// leader_elector schema the epoch fence reads) and holds a LIVE elector, so the
// epoch the store's fence accepts is a real one. The race cases hold a row lock on a
// second raw connection and observe the blocked backend (wait_for_lock_waiter,
// test_principal_lock_gate.hpp) before releasing it, so the interleaving they claim
// is the one that ran; no case sleeps on a clock.
//
// The server's boot composition is EnablementStore::boot, tested below for each of its
// refusals (the store does not open, the overlay hash cannot be recorded, the continuity
// check cannot read the store) and for the two outcomes that must NOT refuse (a healthy
// boot, and a declared regression). Two inputs to it are process-wide facts the caller
// establishes first, so a test cannot inject them: the overlay build and its digest.
// The one-line mapping of a boot() refusal to startup_failed_ in server.cpp has no unit
// seam short of constructing a ServerImpl.

#include "agent_registry.hpp" // detail::scope_kind_catalog
#include "capability_decls/all_fragments.hpp"
#include "enablement_store.hpp"
#include "key_provider.hpp"
#include "leader_elector.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "plugin_config_store.hpp"

#include "../test_helpers.hpp"
#include "test_principal_lock_gate.hpp" // Workers, wait_for_lock_waiter, kLockWait*

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
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

/// The SQLSTATE of a statement that is expected to FAIL; empty when it succeeded.
std::string sqlstate_of(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    if (r.ok())
        return {};
    const char* state = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
    return state != nullptr ? state : "?";
}

/// Clear a regression declaration by hand. The store deliberately has no API for it:
/// accepting a regressed state starts a new ordering of states (ADR-3006 D14), which is
/// not this store's to define. The caller refreshes the instance under test afterwards.
void clear_regression(const std::string& dsn) {
    exec_sql(dsn, "UPDATE plugin_config_store.enablement_meta SET regressed_at = NULL, "
                  "regressed_reason = ''");
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + 1))
        ++n;
    return n;
}

std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

/// True once some backend of THIS database is blocked on a RELATION lock (a table lock).
/// The shared wait_for_lock_waiter covers advisory and row-lock (transactionid) waits only,
/// so the snapshot case, which parks the loader on a table lock, polls for this one itself.
/// Like that helper this is an event-style poll (there is no event to wait on in another
/// backend); the deadline only bounds a failing test.
bool wait_for_relation_waiter(PgPool& pool) {
    const auto end = std::chrono::steady_clock::now() + yuzu::test::kLockWaitDeadline;
    while (std::chrono::steady_clock::now() < end) {
        if (auto probe = pool.try_acquire_for(std::chrono::milliseconds(100))) {
            PgResult r = pg::exec_params(
                probe.get(),
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                "AND wait_event_type = 'Lock' AND wait_event = 'relation'",
                std::vector<std::string>{});
            if (r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1 &&
                std::atoi(PQgetvalue(r.get(), 0, 0)) > 0)
                return true;
        }
        std::this_thread::sleep_for(yuzu::test::kLockWaitPoll);
    }
    return false;
}

/// Release a raw connection's open transaction. Safe to call when none is open (the
/// server answers with a notice), so it can run from a Workers pre-join callback.
void end_txn(PgConn& conn, const char* verb) {
    PgResult r{PQexec(conn.get(), verb)};
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

    // Representative v2 data - a config, a sealed secret and a per-OS kill switch - that the
    // additive v3 migration must leave exactly as it found it.
    exec_sql(db.dsn(), "INSERT INTO plugin_config_store.configs (plugin, key, value, updated_by) "
                       "VALUES ('p1', 'k1', 'a value', 'alice')");
    exec_sql(db.dsn(), "INSERT INTO plugin_config_store.secrets (scope_key, plugin, key, "
                       "sealed_value, updated_by) VALUES ('p1.s1', 'p1', 's1', "
                       "'\\xdeadbeef00ff'::bytea, 'alice')");
    exec_sql(db.dsn(), "INSERT INTO plugin_config_store.kill_switches (scope_key, plugin, action, "
                       "enabled, reason, set_by, os) VALUES ('p1.act@linux', 'p1', 'act', FALSE, "
                       "'because', 'alice', 'linux')");

    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    pg::SecretCodec codec(provider);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    {
        EnablementStore before{pool, make_overlay(), kinds()};
        CHECK_FALSE(before.is_open()); // the v3 schema is not there yet
    }
    {
        // The boot composition refuses at the first step, before it touches the anchor.
        yuzu::test::TempDir anchor_dir{"yuzu_test_enablement_anchor_"};
        const auto anchor = anchor_dir.path / "enablement-anchor";
        auto refused = EnablementStore::boot(pool, make_overlay(), kH1, kinds(), anchor, nullptr);
        REQUIRE_FALSE(refused.has_value());
        CHECK(refused.error().find("open failed") != std::string::npos);
        CHECK_FALSE(fs::exists(anchor));
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

    // The existing tables are untouched: one row each, every value read back as written.
    CHECK(query1(db.dsn(), "SELECT count(*) FROM plugin_config_store.configs") == "1");
    CHECK(query1(db.dsn(), "SELECT plugin || '|' || key || '|' || value || '|' || updated_by "
                           "FROM plugin_config_store.configs") == "p1|k1|a value|alice");
    CHECK(query1(db.dsn(), "SELECT count(*) FROM plugin_config_store.secrets") == "1");
    CHECK(query1(db.dsn(), "SELECT scope_key || '|' || encode(sealed_value, 'hex') || '|' || "
                           "updated_by FROM plugin_config_store.secrets") ==
          "p1.s1|deadbeef00ff|alice");
    CHECK(query1(db.dsn(), "SELECT count(*) FROM plugin_config_store.kill_switches") == "1");
    CHECK(query1(db.dsn(), "SELECT scope_key || '|' || action || '|' || enabled::text || '|' || "
                           "reason || '|' || set_by || '|' || os "
                           "FROM plugin_config_store.kill_switches") ==
          "p1.act@linux|act|false|because|alice|linux");

    // enablement_meta is a singleton: another id fails the CHECK (23514), a second id=1 row
    // fails the primary key (23505), and the one row is still the only row.
    CHECK(sqlstate_of(db.dsn(), "INSERT INTO plugin_config_store.enablement_meta (id, store_id) "
                                "VALUES (2, 'second')") == "23514");
    CHECK(sqlstate_of(db.dsn(), "INSERT INTO plugin_config_store.enablement_meta (id, store_id) "
                                "VALUES (1, 'duplicate')") == "23505");
    CHECK(query1(db.dsn(), "SELECT count(*) FROM plugin_config_store.enablement_meta") == "1");
    CHECK(query1(db.dsn(), "SELECT store_id FROM plugin_config_store.enablement_meta") ==
          meta->store_id);
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

    // Exactly one warn line per bad rule, naming the id and the label - never the pattern
    // text - and one for the unresolved names.
    const std::string text = log.text();
    for (const char* id : {"badsel", "badpat", "badunit"}) {
        INFO(id);
        CHECK(count_of(text, std::string("rule ") + id + " refused at load: refused") == 1);
    }
    CHECK_FALSE(log.says("MATCHES"));
    CHECK(count_of(text, "unknown to this release") == 1);
    CHECK(count_of(text, "gone.unit") == 1);

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

TEST_CASE("EnablementStore: the loader refuses more than the cap of active rules and never truncates",
          "[pg][store][enablement]") {
    EnablementPg f;
    LogCapture log;
    seed_rules(f.dsn(), static_cast<int>(en::kMaxRules) + 1);
    auto over = f.store->load_rules();
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error() == EnablementStore::Error::Unavailable);
    CHECK(f.counter("yuzu_server_enablement_read_degrade_total", {{"reason", "query_error"}}) == 1);
    CHECK(log.says("load refused"));

    // One rule fewer is exactly the cap: every rule loads, none is quarantined.
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_rules SET active = FALSE "
                      "WHERE id = 'seed0001'");
    auto at_cap = f.store->load_rules();
    REQUIRE(at_cap.has_value());
    CHECK(at_cap->rules.size() == en::kMaxRules);
    CHECK(at_cap->quarantined.empty());
    CHECK(f.counter("yuzu_server_enablement_read_degrade_total", {{"reason", "query_error"}}) == 1);
}

TEST_CASE("EnablementStore: load_rules returns a version and rows from ONE snapshot",
          "[pg][store][enablement]") {
    EnablementPg f;
    REQUIRE(f.store->put_rule(row("r1", {"wol.wake"})));
    const auto version_before = f.store->get_meta()->rules_version;
    REQUIRE(f.store->list_rules(true)->size() == 1);

    // A holds ACCESS EXCLUSIVE on the rules table. The loader's version read, which fixes
    // its REPEATABLE READ snapshot, does not touch that table and runs; its rules SELECT
    // then parks on the relation lock until A commits.
    PgConn a{PQconnectdb(f.dsn().c_str())};
    REQUIRE(PQstatus(a.get()) == CONNECTION_OK);
    REQUIRE(PgResult{PQexec(a.get(), "BEGIN")}.ok());
    REQUIRE(PgResult{PQexec(a.get(), "LOCK TABLE plugin_config_store.enablement_rules IN ACCESS "
                                     "EXCLUSIVE MODE")}
                .ok());
    std::expected<EnablementStore::LoadedRules, EnablementStore::Error> parked;
    yuzu::test::Workers workers([&] { end_txn(a, "ROLLBACK"); });
    workers.add([&] { parked = f.store->load_rules(); });
    REQUIRE(wait_for_relation_waiter(f.pool()));

    // The author adds a rule and bumps the version in ONE transaction while the loader waits.
    REQUIRE(PgResult{PQexec(a.get(), "INSERT INTO plugin_config_store.enablement_rules (id, units, "
                                     "selector, provenance) VALUES ('late', ARRAY['wol.wake'], "
                                     "'__all__', 'operator')")}
                .ok());
    REQUIRE(PgResult{PQexec(a.get(), "UPDATE plugin_config_store.enablement_meta SET rules_version "
                                     "= rules_version + 1 WHERE id = 1")}
                .ok());
    REQUIRE(PgResult{PQexec(a.get(), "COMMIT")}.ok());
    workers.join_all();

    // The loader's snapshot predates that commit, so it holds the OLD version and the OLD
    // rows together. A READ COMMITTED loader would return the old version with the new rule.
    REQUIRE(parked.has_value());
    CHECK(parked->rules_version == version_before);
    CHECK(parked->rules.size() == 1);
    // A load after the commit sees the new pair.
    auto fresh = f.store->load_rules();
    REQUIRE(fresh.has_value());
    CHECK(fresh->rules_version == version_before + 1);
    CHECK(fresh->rules.size() == 2);
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
    // B reports the PREVIOUS state and parks on A's row lock; the wait is observed, so the
    // report really is evaluated against the row A is about to change.
    std::expected<EnablementStore::ReportOutcome, EnablementStore::Error> b_result;
    yuzu::test::Workers workers([&] { end_txn(a, "ROLLBACK"); });
    workers.add([&] { b_result = f.store->record_report("ep001", epoch, c1, kH1); });
    REQUIRE(yuzu::test::wait_for_lock_waiter(f.pool()));
    REQUIRE(PgResult{PQexec(a.get(), "COMMIT")}.ok());
    workers.join_all();
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
        // B's declaration blocks on the meta row A holds (the wait is observed).
        std::expected<void, EnablementStore::Error> declared;
        yuzu::test::Workers workers([&] { end_txn(a, "ROLLBACK"); });
        workers.add([&] { declared = f.store->set_regressed("race"); });
        REQUIRE(yuzu::test::wait_for_lock_waiter(f.pool()));
        REQUIRE(PgResult{PQexec(a.get(), "ROLLBACK")}.ok());
        workers.join_all();
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
        yuzu::test::Workers workers([&] { end_txn(b, "ROLLBACK"); });
        workers.add([&] {
            batch = f.store->set_desired_batch(f.batch({{"ep001", 1, {}, kH1}}, {}, 1));
        });
        REQUIRE(yuzu::test::wait_for_lock_waiter(f.pool()));
        REQUIRE(PgResult{PQexec(b.get(), "COMMIT")}.ok());
        workers.join_all();
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

    // Another store's id, an unparseable file and an over-long one are all regressions. The
    // store has no way to clear a declaration (resolution starts a new ordering and is not
    // its to define), so each round is reset by hand.
    const auto reset_by_hand = [&] {
        clear_regression(f.dsn());
        f.store->refresh_regression();
        REQUIRE_FALSE(f.store->regression().regressed);
    };
    reset_by_hand();
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
        reset_by_hand();
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

    // Clear it by hand, then put the FILE ahead while the instance runs: refused, declared,
    // not lowered.
    clear_regression(f.dsn());
    other->refresh_regression();
    REQUIRE_FALSE(other->regression().regressed);
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

TEST_CASE("EnablementStore: a successful anchor write replaces the file and leaves no temp of its own",
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

TEST_CASE("EnablementStore: an anchor write that cannot land is Failed and counted and leaves nothing behind",
          "[pg][store][enablement]") {
    EnablementPg f;
    fs::create_directories(f.dir.path);
    // A regular file where the anchor's parent directory should be: the path reads as
    // missing (ENOTDIR), so the write is attempted, and creating the temp file under a
    // non-directory fails on every platform, as root or not.
    const fs::path blocker = f.dir.path / "not_a_directory";
    {
        std::ofstream out(blocker, std::ios::binary);
        out << "keep me";
    }
    CHECK(f.store->write_anchor(blocker / "enablement-anchor") == EnablementStore::AnchorWrite::Failed);
    CHECK(f.counter("yuzu_server_enablement_anchor_write_failed_total") == 1);
    CHECK(read_file(blocker) == "keep me");
    for (const auto& e : fs::directory_iterator(f.dir.path))
        CHECK(e.path().filename().string().find(".tmp.") == std::string::npos);

    // The failure is not sticky: the next write to a usable path lands.
    CHECK(f.store->write_anchor(f.anchor()) == EnablementStore::AnchorWrite::Written);
    CHECK(en::parse_anchor(read_file(f.anchor())).has_value());
    CHECK(f.counter("yuzu_server_enablement_anchor_write_failed_total") == 1);
    // Not reproducible without a fault-injection hook in production code, and so stated
    // rather than tested: an EXISTING anchor surviving a failure between the temp write and
    // the rename, and a crash between fsync and rename. Both rest on the write order
    // (fsync the temp, then an atomic replace) described in the header banner.
}


TEST_CASE("EnablementStore: a second replica answers pending-with-age from the persisted row",
          "[pg][store][enablement]") {
    EnablementPg f;
    f.seed(1);
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_meta SET rules_version = 2");
    REQUIRE(f.store->set_desired_batch(f.batch({{"ep001", 1, {"wol.wake"}, kH1}}, {}, 2)));
    // Age the pending state in SQL, not on a clock: the age a second replica reports must come
    // from the persisted column, so a constant-zero implementation cannot satisfy this.
    exec_sql(f.dsn(), "UPDATE plugin_config_store.enablement_endpoints SET pending_since = "
                      "now() - interval '2 hours' WHERE agent_id = 'ep001'");
    PgPool pool_b{{.conninfo = f.dsn(), .size = 2}};
    auto b = f.make_store(&pool_b);
    auto e = b->get_endpoint("ep001");
    REQUIRE(e.has_value());
    CHECK(e->pending);
    REQUIRE(e->pending_age_seconds.has_value());
    CHECK(*e->pending_age_seconds >= 7100);
    CHECK(*e->pending_age_seconds <= 7300);
    CHECK(e->desired_hash == kH1);
    CHECK(e->desired_units == std::vector<std::string>{"wol.wake"});
    CHECK(e->desired_counter == 1);

    // The exact acknowledgement clears the pending state and its age.
    REQUIRE(b->record_report("ep001", e->desired_epoch, e->desired_counter, kH1));
    auto acked = f.store->get_endpoint("ep001");
    REQUIRE(acked.has_value());
    CHECK_FALSE(acked->pending);
    CHECK_FALSE(acked->pending_age_seconds.has_value());
}

TEST_CASE("EnablementStore: has_held_state is a durable latch that empty reports and "
          "re-registration and a new store never clear",
          "[pg][store][enablement]") {
    EnablementPg f;
    f.seed(2);
    REQUIRE(f.store->set_desired_batch(f.batch({{"ep001", 1, {"wol.wake"}, kH1}}, {}, 1)));
    const auto issued = f.store->get_endpoint("ep001");
    REQUIRE(issued.has_value());
    REQUIRE(issued->desired_counter > 0);
    // Being issued a state is not holding one: nothing has been reported yet.
    CHECK_FALSE(issued->has_held_state);

    // A report of a positive counter latches it, for that endpoint only.
    REQUIRE(f.store->record_report("ep001", issued->desired_epoch, issued->desired_counter, kH1));
    CHECK(f.store->get_endpoint("ep001")->has_held_state);
    CHECK_FALSE(f.store->get_endpoint("ep002")->has_held_state);

    // An empty report differs from the last one, so it IS written - and the latch holds.
    auto empty = f.store->record_report("ep001", issued->desired_epoch, 0, "");
    REQUIRE(empty.has_value());
    CHECK(*empty == EnablementStore::ReportOutcome::Written);
    CHECK(f.store->get_endpoint("ep001")->reported_counter == 0);
    CHECK(f.store->get_endpoint("ep001")->has_held_state);

    // So does a re-registration (which does run: input_gen moves) ...
    f.store->upsert_on_registration("ep001", EnablementPg::ident("h1"), f.reg(2));
    CHECK(f.store->get_endpoint("ep001")->input_gen == 2);
    CHECK(f.store->get_endpoint("ep001")->has_held_state);

    // ... and a store instance that never saw any of it reads the same durable answer.
    PgPool pool_b{{.conninfo = f.dsn(), .size = 2}};
    auto b = f.make_store(&pool_b);
    CHECK(b->get_endpoint("ep001")->has_held_state);
    CHECK_FALSE(b->get_endpoint("ep002")->has_held_state);
    CHECK(query1(f.dsn(), "SELECT has_held_state FROM plugin_config_store.enablement_endpoints "
                          "WHERE agent_id = 'ep001'") == "t");
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

// -- Boot ----------------------------------------------------------------------------
//
// EnablementStore::boot is the server's whole composition of the store, so each refusal the
// server turns into startup_failed_ is a branch here.

TEST_CASE("EnablementStore: a healthy boot opens the store and records the overlay and witnesses the anchor",
          "[pg][store][enablement]") {
    EnablementPg f;
    auto booted = EnablementStore::boot(f.pool(), make_overlay(), kH1, kinds(), f.anchor(), &f.metrics);
    REQUIRE(booted.has_value());
    REQUIRE(*booted);
    CHECK((*booted)->is_open());
    CHECK_FALSE((*booted)->regression().regressed);
    // First boot on this host: no anchor yet, so it is unwitnessed - and then written.
    CHECK((*booted)->regression().anchor_unwitnessed);
    const auto meta = f.store->get_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->overlay_hash == kH1);
    const auto parsed = en::parse_anchor(read_file(f.anchor()));
    REQUIRE(parsed.has_value());
    CHECK(parsed->store_id == meta->store_id);

    // A second boot with the same digest and the anchor now on disk is quiet: same
    // rules_version (no re-resolution), not unwitnessed.
    const auto version = meta->rules_version;
    auto again = EnablementStore::boot(f.pool(), make_overlay(), kH1, kinds(), f.anchor(), nullptr);
    REQUIRE(again.has_value());
    CHECK_FALSE((*again)->regression().anchor_unwitnessed);
    CHECK(f.store->get_meta()->rules_version == version);
}

TEST_CASE("EnablementStore: boot refuses when the overlay hash cannot be recorded and writes no anchor",
          "[pg][store][enablement]") {
    EnablementPg f;
    PgPool short_pool{{.conninfo = f.dsn(), .size = 2, .lock_timeout_ms = 100}};
    // A holds the meta row; the construction smoke read (a plain SELECT) is not blocked, the
    // overlay-hash UPDATE is, and gives up at the pool's lock timeout.
    PgConn a{PQconnectdb(f.dsn().c_str())};
    REQUIRE(PQstatus(a.get()) == CONNECTION_OK);
    REQUIRE(PgResult{PQexec(a.get(), "BEGIN")}.ok());
    REQUIRE(PgResult{PQexec(a.get(), "SELECT 1 FROM plugin_config_store.enablement_meta WHERE id = 1 "
                                     "FOR UPDATE")}
                .status() == PGRES_TUPLES_OK);
    auto refused = EnablementStore::boot(short_pool, make_overlay(), kH1, kinds(), f.anchor(), nullptr);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("overlay hash") != std::string::npos);
    CHECK_FALSE(fs::exists(f.anchor()));
    CHECK(query1(f.dsn(), "SELECT overlay_hash = '' FROM plugin_config_store.enablement_meta") == "t");

    // Control: the same call succeeds once the row is free.
    REQUIRE(PgResult{PQexec(a.get(), "ROLLBACK")}.ok());
    auto booted = EnablementStore::boot(short_pool, make_overlay(), kH1, kinds(), f.anchor(), nullptr);
    REQUIRE(booted.has_value());
    CHECK(fs::exists(f.anchor()));
}

TEST_CASE("EnablementStore: boot refuses when a disagreeing anchor cannot be declared against the store",
          "[pg][store][enablement]") {
    EnablementPg f;
    // The digest is already recorded, so the overlay-hash UPDATE matches no row and does not
    // wait; the anchor is ahead of the store, so the continuity check must DECLARE a
    // regression - and that write is the one the held row lock refuses.
    REQUIRE(f.store->sync_overlay_hash(kH1).value());
    const auto meta = f.store->get_meta();
    REQUIRE(meta.has_value());
    fs::create_directories(f.dir.path);
    {
        std::ofstream out(f.anchor(), std::ios::binary | std::ios::trunc);
        out << en::render_anchor({meta->store_id, meta->epoch, meta->counter + 10});
    }
    REQUIRE(fs::exists(f.anchor())); // an unwritable fixture would read as a MISSING anchor
    PgPool short_pool{{.conninfo = f.dsn(), .size = 2, .lock_timeout_ms = 100}};
    PgConn a{PQconnectdb(f.dsn().c_str())};
    REQUIRE(PQstatus(a.get()) == CONNECTION_OK);
    REQUIRE(PgResult{PQexec(a.get(), "BEGIN")}.ok());
    REQUIRE(PgResult{PQexec(a.get(), "SELECT 1 FROM plugin_config_store.enablement_meta WHERE id = 1 "
                                     "FOR UPDATE")}
                .status() == PGRES_TUPLES_OK);
    auto refused = EnablementStore::boot(short_pool, make_overlay(), kH1, kinds(), f.anchor(), nullptr);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("continuity") != std::string::npos);
    REQUIRE(PgResult{PQexec(a.get(), "ROLLBACK")}.ok());
    CHECK(query1(f.dsn(), "SELECT regressed_at IS NULL FROM plugin_config_store.enablement_meta") == "t");
}

TEST_CASE("EnablementStore: a declared regression does not stop the server booting",
          "[pg][store][enablement]") {
    EnablementPg f;
    const auto meta = f.store->get_meta();
    REQUIRE(meta.has_value());
    fs::create_directories(f.dir.path);
    {
        // The anchor is ahead of the store: a dump restored behind it.
        std::ofstream out(f.anchor(), std::ios::binary | std::ios::trunc);
        out << en::render_anchor({meta->store_id, meta->epoch, meta->counter + 10});
    }
    REQUIRE(fs::exists(f.anchor())); // an unwritable fixture would read as a MISSING anchor
    auto booted = EnablementStore::boot(f.pool(), make_overlay(), kH1, kinds(), f.anchor(), &f.metrics);
    // A regression is a fact the store declares and /readyz reports, not a startup refusal.
    REQUIRE(booted.has_value());
    CHECK((*booted)->regression().regressed);
    CHECK((*booted)->regression().reason == "store_behind");
    CHECK(f.metrics.gauge("yuzu_server_enablement_regressed").value() == 1);
    CHECK(query1(f.dsn(), "SELECT regressed_at IS NOT NULL FROM plugin_config_store.enablement_meta") == "t");
    // The anchor was not lowered to hide it.
    CHECK(en::parse_anchor(read_file(f.anchor()))->counter == meta->counter + 10);
}
