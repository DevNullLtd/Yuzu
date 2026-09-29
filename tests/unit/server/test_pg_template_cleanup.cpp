// PgTestTemplate lifecycle wiring + its tests.
//
// Listener (one dedicated TU — CATCH_REGISTER_LISTENER in a header would
// register one listener per including TU):
//  - testRunStarting: sweep stale yuzu_test_* databases leaked by ABNORMAL
//    exits of earlier runs (SIGKILL / OOM / CI job-timeout kill — nothing
//    re-runs those processes' teardown). Age comes from the epoch embedded
//    in every test-database name; the threshold is far beyond a server-
//    suite job's lifetime, so a live concurrent suite on the shared
//    instance can never be swept.
//  - testRunEnded: drain the shared-DB + TRUNCATE fixtures' persistent pools,
//    then drop their per-file clones and this process's template databases
//    while libpq's TLS stack is still alive. PgTestTemplate::Registry's static
//    dtor is only a backstop: its __cxa_atexit slot is claimed when the first
//    [pg] fixture runs, so on Catch2-filtered runs OpenSSL's own atexit cleanup
//    can land AFTER it and the exit-time PQconnectdb fails (see
//    PgTestTemplate::drop_all_built in test_helpers.hpp). Both the shared pools'
//    PQfinish and the clones' DROP would hit that window in function-local
//    static dtors, so they register for this same lifecycle boundary.
//
// The TEST_CASEs below are the regression net the 2091 review asked for: a
// change that no-ops the pool-drain/drop paths, breaks the shared-key replay
// verification, breaks the build-failure/retry contract, mis-ages database
// names, or breaks the sweep SQL now fails the suite itself rather than
// only an external leftover-database check.

#if defined(YUZU_TEST_ENABLE_PG)

#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include <libpq-fe.h>

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

namespace {

class PgTemplateCleanupListener : public Catch::EventListenerBase {
public:
    using Catch::EventListenerBase::EventListenerBase;

    void testRunStarting(Catch::TestRunInfo const& /*info*/) override {
        const char* dsn = yuzu::test::pg_admin_dsn_env();
        if (dsn != nullptr)
            yuzu::test::sweep_stale_test_databases(dsn);
    }

    void testRunEnded(Catch::TestRunStats const& /*stats*/) override {
        // The shared cleanup primitive drains every persistent pool BEFORE it
        // drops any clone. All libpq work runs here, while TLS is alive.
        yuzu::test::SharedPgDbRegistry::cleanup_all_shared();
        yuzu::test::PgTestTemplate::drop_all_built();
    }
};

// Probe setups for the replay-verification test. Three distinct functions
// (distinct pointers — the same shape as byte-identical lambdas in
// different TUs): two structurally equivalent, one divergent.
void probe_exec(const std::string& dsn, const char* sql) {
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error(std::string("probe connect failed: ") +
                                 PQerrorMessage(conn.get()));
    yuzu::server::pg::PgResult res{PQexec(conn.get(), sql)};
    if (!res.ok())
        throw std::runtime_error(std::string("probe sql failed: ") + PQerrorMessage(conn.get()));
}

constexpr const char* kProbeSchema = "CREATE SCHEMA IF NOT EXISTS tplprobe;"
                                     "CREATE TABLE IF NOT EXISTS tplprobe.t1 (id INTEGER)";

void probe_setup(const std::string& dsn) {
    probe_exec(dsn, kProbeSchema);
}
void probe_setup_twin(const std::string& dsn) {
    probe_exec(dsn, kProbeSchema);
}
void probe_setup_divergent(const std::string& dsn) {
    probe_exec(dsn, kProbeSchema);
    probe_exec(dsn, "CREATE TABLE IF NOT EXISTS tplprobe.t2 (id INTEGER)");
}
// Subset divergence: builds NOTHING — on a clone-based replay this would
// wrongly verify (every migration no-ops); the fresh-scratch replay must
// reject it.
void probe_setup_subset(const std::string& /*dsn*/) {}

void probe_setup_throwing(const std::string& /*dsn*/) {
    throw std::runtime_error("deliberate template build failure");
}

// Throws on the FIRST call only — the transient-failure retry probe.
void probe_setup_flaky(const std::string& dsn) {
    static bool first = true;
    if (first) {
        first = false;
        throw std::runtime_error("simulated transient outage");
    }
    probe_exec(dsn, kProbeSchema);
}

// Per-process salt for every probe identifier this file creates on the
// SHARED instance (template keys, seeded sweep names): two runner agents on
// one box running this suite concurrently must never collide (CLAUDE.md
// salted-identifier standing invariant; governance #2091 sec2-M2).
std::string probe_salt() {
    static const std::string salt = [] {
        std::mt19937_64 rng{std::random_device{}()};
        return std::to_string(rng() % 1'000'000'000);
    }();
    return salt;
}

std::optional<bool> try_database_exists(const std::string& admin_dsn,
                                        const std::string& db_name) noexcept {
    try {
        yuzu::server::pg::PgConn conn{PQconnectdb(admin_dsn.c_str())};
        if (PQstatus(conn.get()) != CONNECTION_OK)
            return std::nullopt;
        const char* values[] = {db_name.c_str()};
        yuzu::server::pg::PgResult res{PQexecParams(conn.get(),
                                                    "SELECT 1 FROM pg_database WHERE datname = $1",
                                                    1, nullptr, values, nullptr, nullptr, 0)};
        if (PQresultStatus(res.get()) != PGRES_TUPLES_OK)
            return std::nullopt;
        return PQntuples(res.get()) == 1;
    } catch (...) {
        return std::nullopt;
    }
}

bool database_exists(const std::string& admin_dsn, const std::string& db_name) {
    const auto exists = try_database_exists(admin_dsn, db_name);
    REQUIRE(exists.has_value());
    return *exists;
}

// Count databases whose name ends with the given suffix (finds a template
// whose full epoch+salt name the test cannot predict).
int databases_with_suffix(const std::string& admin_dsn, const std::string& suffix) {
    yuzu::server::pg::PgConn conn{PQconnectdb(admin_dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    const std::string pattern = "%" + suffix;
    const char* values[] = {pattern.c_str()};
    yuzu::server::pg::PgResult res{
        PQexecParams(conn.get(), "SELECT count(*) FROM pg_database WHERE datname LIKE $1", 1,
                     nullptr, values, nullptr, nullptr, 0)};
    REQUIRE(PQresultStatus(res.get()) == PGRES_TUPLES_OK);
    return std::atoi(PQgetvalue(res.get(), 0, 0));
}

void admin_exec(const std::string& admin_dsn, const std::string& sql) {
    yuzu::server::pg::PgConn conn{PQconnectdb(admin_dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult res{PQexec(conn.get(), sql.c_str())};
    REQUIRE(res.ok());
}

} // namespace

CATCH_REGISTER_LISTENER(PgTemplateCleanupListener)

TEST_CASE("test_db_is_stale: name-embedded epoch + staleness window", "[template]") {
    const std::int64_t now = 1'783'900'000; // fixed "now" — the predicate is pure
    const std::string old_epoch = std::to_string(now - 7 * 3600);
    const std::string fresh_epoch = std::to_string(now - 60);

    SECTION("stale ephemeral and template names sweep") {
        CHECK(yuzu::test::test_db_is_stale("yuzu_test_" + old_epoch + "_123456789_0", now));
        CHECK(yuzu::test::test_db_is_stale("yuzu_test_tpl_" + old_epoch + "_123456789_swinv", now));
    }
    SECTION("fresh names never sweep") {
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_" + fresh_epoch + "_123456789_0", now));
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_tpl_" + fresh_epoch + "_1_swinv", now));
    }
    SECTION("pre-epoch-format names never sweep (rollout safety: a concurrent "
            "old-binary job may own them)") {
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_987654321_0", now));
    }
    SECTION("implausible epochs and malformed names never sweep") {
        const std::string future = std::to_string(now + 7 * 86'400);
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_" + future + "_1_0", now));
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_notanumber_0", now));
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_", now));
        CHECK_FALSE(yuzu::test::test_db_is_stale("other_db", now));
        // charset guard: never splice a quotable name into DROP
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_" + old_epoch + "_1_a\"b", now));
        // overflow guard: a hostile 20+-digit run must be rejected BEFORE
        // accumulation, not wrap into a bogus epoch (UB)
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_99999999999999999999999_x", now));
    }
}

TEST_CASE("PgTestTemplate: build, shared-key replay verification, scoped drop", "[pg][template]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    }
    const std::string admin = yuzu::test::pg_admin_dsn_env();

    const std::string key = "tp" + probe_salt(); // salted: shared-instance safe
    yuzu::test::PgTestTemplate original{key, &probe_setup};
    yuzu::test::PgTestTemplate twin{key, &probe_setup_twin};
    yuzu::test::PgTestTemplate divergent{key, &probe_setup_divergent};
    yuzu::test::PgTestTemplate subset{key, &probe_setup_subset};

    std::string err;
    const std::string built = original.ensure(admin, err);
    INFO("build error: " << err);
    REQUIRE(err.empty());
    REQUIRE_FALSE(built.empty());
    CHECK(database_exists(admin, built));

    SECTION("a structurally equivalent setup under the same key verifies and shares") {
        std::string twin_err;
        CHECK(twin.ensure(admin, twin_err) == built);
        CHECK(twin_err.empty());
    }

    SECTION("an additively divergent setup under the same key is rejected; the original is "
            "untouched") {
        std::string div_err;
        CHECK(divergent.ensure(admin, div_err).empty());
        CHECK(div_err.find("shared-key setup mismatch") != std::string::npos);

        std::string again_err;
        CHECK(original.ensure(admin, again_err) == built);
        CHECK(again_err.empty());
    }

    SECTION("a SUBSET setup is rejected too (fresh-scratch replay, not clone)") {
        std::string sub_err;
        CHECK(subset.ensure(admin, sub_err).empty());
        CHECK(sub_err.find("shared-key setup mismatch") != std::string::npos);
        // and the verdict is cached: a second ensure fails identically fast
        std::string sub_err2;
        CHECK(subset.ensure(admin, sub_err2).empty());
        CHECK(sub_err2 == sub_err);
    }

    SECTION("drop_built removes only this key's template (the testRunEnded drop uses the same "
            "path per entry; scoped here so --order rand cannot wipe other files' templates)") {
        yuzu::test::PgTestTemplate::drop_built(key);
        CHECK_FALSE(database_exists(admin, built));
        // Later ensures rebuild transparently — the registry entry is gone.
        // (The rebuilt name embeds a fresh creation epoch, so it is not
        // asserted equal to the old one.)
        std::string rebuilt_err;
        const std::string rebuilt = original.ensure(admin, rebuilt_err);
        CHECK(rebuilt_err.empty());
        REQUIRE_FALSE(rebuilt.empty());
        CHECK(database_exists(admin, rebuilt));
        yuzu::test::PgTestTemplate::drop_built(key);
    }
}

TEST_CASE("PgTestTemplate: build failure fails loudly, stays reclaimable, and is retried",
          "[pg][template]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    }
    const std::string admin = yuzu::test::pg_admin_dsn_env();

    SECTION("throwing setup: error surfaces, half-built DB is registered and dropped") {
        const std::string fail_key = "fp" + probe_salt(); // salted: shared-instance safe
        yuzu::test::PgTestTemplate failing{fail_key, &probe_setup_throwing};
        std::string err;
        CHECK(failing.ensure(admin, err).empty());
        CHECK(err.find("template setup threw") != std::string::npos);
        // The CREATE succeeded before the throw — the database physically
        // exists and must be registered for cleanup, not orphaned.
        CHECK(databases_with_suffix(admin, "_" + fail_key) == 1);
        yuzu::test::PgTestTemplate::drop_built(fail_key);
        CHECK(databases_with_suffix(admin, "_" + fail_key) == 0);
    }

    SECTION("transient failure is retried on the next ensure, not cached for the process") {
        const std::string flaky_key = "fk" + probe_salt(); // salted: shared-instance safe
        yuzu::test::PgTestTemplate flaky{flaky_key, &probe_setup_flaky};
        std::string err1;
        CHECK(flaky.ensure(admin, err1).empty()); // first attempt: simulated outage
        CHECK(err1.find("simulated transient outage") != std::string::npos);
        std::string err2;
        const std::string name = flaky.ensure(admin, err2); // retry succeeds
        INFO("retry error: " << err2);
        CHECK(err2.empty());
        CHECK_FALSE(name.empty());
        CHECK(database_exists(admin, name));
        yuzu::test::PgTestTemplate::drop_built(flaky_key);
    }
}

TEST_CASE("SharedPgDbRegistry drains the pool before dropping its shared clone", "[pg][template]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    }
    const std::string admin = yuzu::test::pg_admin_dsn_env();
    const std::string key = "sh" + probe_salt(); // salted: shared-instance safe
    yuzu::test::PgTestTemplate tpl{key, &probe_setup};
    yuzu::test::PostgresTestDb db{tpl};
    INFO("shared-clone error: " << db.error());
    REQUIRE(db.available());
    const std::string db_name = db.db_name();

    struct ProbeState {
        std::optional<yuzu::server::pg::PgPool> pool;
        std::optional<bool> clone_existed_during_drain;
        bool drained{false};
    };
    const auto state = std::make_shared<ProbeState>();
    state->pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db.dsn(), .size = 1});
    REQUIRE(state->pool->valid());
    {
        auto lease = state->pool->acquire();
        REQUIRE(lease);
    }
    CHECK(state->pool->open() == 1);

    db.keep_until_run_end([state, admin, db_name]() noexcept {
        // Temporal assertion seam: reversed drop-before-drain ordering records
        // false here even though the final pool/DB state would look correct.
        state->clone_existed_during_drain = try_database_exists(admin, db_name);
        state->pool.reset();
        state->drained = true;
    });
    CHECK(database_exists(admin, db_name));

    yuzu::test::SharedPgDbRegistry::cleanup_shared(db_name);
    CHECK(state->drained);
    REQUIRE(state->clone_existed_during_drain.has_value());
    CHECK(*state->clone_existed_during_drain);
    CHECK_FALSE(state->pool.has_value());
    CHECK_FALSE(database_exists(admin, db_name));
    yuzu::test::PgTestTemplate::drop_built(key);
}

TEST_CASE("sweep_stale_test_databases: end-to-end against a live instance", "[pg][template]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    }
    const std::string admin = yuzu::test::pg_admin_dsn_env();
    const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
    // Salted (shared-instance safe): concurrent suites seed distinct names.
    const std::string stale =
        "yuzu_test_" + std::to_string(now - 7 * 3600) + "_" + probe_salt() + "_swp";
    const std::string old_format = "yuzu_test_" + probe_salt() + "_swp"; // first number < 1e9

    admin_exec(admin, "CREATE DATABASE \"" + stale + "\"");
    admin_exec(admin, "CREATE DATABASE \"" + old_format + "\"");

    yuzu::test::sweep_stale_test_databases(admin);

    CHECK_FALSE(database_exists(admin, stale)); // stale epoch-named: swept
    CHECK(database_exists(admin, old_format));  // pre-epoch format: spared
    admin_exec(admin, "DROP DATABASE IF EXISTS \"" + old_format + "\"");
}

#endif // YUZU_TEST_ENABLE_PG
