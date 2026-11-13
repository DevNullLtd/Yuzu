/// @file test_software_catalog_rollup.cpp
/// Lifecycle tests for the SoftwareCatalogRollup background thread (gov cpp-safety SHOULD).
/// The thread's memory safety was proven by static review; these exercise the live
/// lifecycle surface — start/stop join, double-stop idempotency, start-after-stop restart,
/// and destructor-joins-without-explicit-stop — so a regression (e.g. a double-join or a
/// missing reset of the stop flag) fails here. PG-gated: the thread issues a real recompute,
/// so it runs against an ephemeral test database and skips cleanly without a DSN. The
/// recompute OUTCOME is asserted in test_software_inventory_store.cpp (deterministic, no
/// thread race); here we only assert the lifecycle completes without hang or crash.

#include "software_catalog_rollup.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "software_inventory_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <yuzu/metrics.hpp>

#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::SoftwareCatalogRollup;
using yuzu::server::SoftwareInventoryStore;
using yuzu::server::pg::PgPool;

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): same key +
// identical setup as test_software_inventory_store.cpp (first build wins) —
// the store set here is exactly {SoftwareInventoryStore}.
yuzu::test::PgTestTemplate swinv_tpl{"swinv", [](const std::string& dsn) {
                                         PgPool pool{{.conninfo = dsn, .size = 1}};
                                         SoftwareInventoryStore store{pool};
                                         // Throw, don't return: a silently-unmigrated template
                                         // would make every clone fall back to in-test migration —
                                         // correct but slow, defeating the point.
                                         // PgTestTemplate::build records the throw as a fixture
                                         // error.
                                         if (!store.is_open())
                                             throw std::runtime_error(
                                                 "swinv template: store failed to migrate");
                                     }};

// The idle-wait step the worker re-checks its stop flag at, in place of production's 5 s
// (kCatalogRollupStopPoll): a stop() on a parked worker joins within one step, so the cases
// below no longer wait out 5 s per join. The joins and the cadence are otherwise production's.
constexpr std::chrono::milliseconds kTestStopPoll{50};
} // namespace

TEST_CASE("SoftwareCatalogRollup thread lifecycle", "[pg][software_inventory][rollup]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    // A long interval so the thread does its one immediate refresh then parks — the test
    // drives start()/stop() explicitly and never waits on the cadence.
    const auto interval = std::chrono::hours{1};

    SECTION("start → stop joins cleanly; double-stop is an idempotent no-op") {
        SoftwareCatalogRollup rollup{store, interval, nullptr, kTestStopPoll};
        rollup.start();
        rollup.stop(); // signals + joins
        rollup.stop(); // must not double-join / crash
        SUCCEED("start/stop/double-stop completed without hang or crash");
    }

    SECTION("start is idempotent; start-after-stop restarts") {
        SoftwareCatalogRollup rollup{store, interval, nullptr, kTestStopPoll};
        rollup.start();
        rollup.start(); // already running → no-op (guarded by thread_.joinable())
        rollup.stop();
        rollup.start(); // start-after-stop resets the stop flag and re-runs
        rollup.stop();
        SUCCEED("idempotent start + start-after-stop completed");
    }

    SECTION("destructor stops + joins a running thread without an explicit stop") {
        {
            SoftwareCatalogRollup rollup{store, interval, nullptr, kTestStopPoll};
            rollup.start();
        } // dtor → stop() → join
        SUCCEED("dtor joined the running thread");
    }
}

TEST_CASE("SoftwareCatalogRollup::request_stop — no NEW recompute starts, the thread exits, stop() "
          "still joins",
          "[pg][software_inventory][rollup]") {
    // HA WS-8 (RD-1): stop() calls request_stop() when draining begins so an hourly
    // recompute cannot START inside the drain grace and then run its full statement
    // budget after it. A 1s interval slept in 100 ms steps makes the loop re-arm after 1 s
    // (production's 5 s step would make that 5 s), so without request_stop() a second
    // recompute would run inside the 3 s window below.
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    auto recomputes = [&] {
        return metrics.counter("yuzu_inventory_catalog_rollup_total", {{"outcome", "success"}})
                   .value() +
               metrics.counter("yuzu_inventory_catalog_rollup_total", {{"outcome", "error"}})
                   .value();
    };

    SoftwareCatalogRollup rollup{store, std::chrono::seconds{1}, &metrics,
                                 std::chrono::milliseconds{100}};
    rollup.start();
    for (int i = 0; i < 100 && recomputes() < 1; ++i) // the immediate first recompute
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    REQUIRE(recomputes() == 1);

    rollup.request_stop();                                // must not block
    std::this_thread::sleep_for(std::chrono::seconds{3}); // 3x the 1 s re-arm
    CHECK(recomputes() == 1);                             // no new recompute started

    const auto t = std::chrono::steady_clock::now();
    rollup.stop(); // the thread already exited on the flag; the join is immediate
    CHECK(std::chrono::steady_clock::now() - t < std::chrono::seconds{1});
}

TEST_CASE("SoftwareCatalogRollup worker refreshes the components rollup and emits its three metrics, "
          "independently of a failed catalogue refresh",
          "[pg][software_inventory][rollup]") {
    // The hourly worker is the ONLY caller of refresh_component_rollup: delete that call and every
    // store-level test stays green while the components totals stay `building` forever. This pins
    // the wiring: one tick of a long-interval worker stamps the rollup, counts a success and sets
    // the liveness gauge. The catalogue leg of the same tick is made to fail (its table is
    // dropped), so the case also pins that the components leg does not depend on it. The test
    // polls the last thing the tick emits (the success timestamp) under a deadline, never a fixed
    // sleep (the reason for the poll is below).
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        yuzu::server::pg::PgResult r = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO software_inventory_store.software_components (agent_id, kind, path_hash, "
            "path, name, version, row_hash, first_seen) VALUES ('dev-a', 'jar', 'ph', '/a', "
            "'libfoo', '1.0', 'rh', 1)",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
        r = yuzu::server::pg::exec_params(lease.get(),
                                          "DROP TABLE software_inventory_store.catalog_rollup",
                                          std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    const auto before = store.component_rollup_meta();
    REQUIRE(before.has_value());
    REQUIRE(before->refreshed_at == 0); // never computed

    yuzu::MetricsRegistry metrics;
    constexpr const char* kStem = "yuzu_inventory_component_rollup";
    const std::string stamp = std::string(kStem) + "_last_success_timestamp";
    SoftwareCatalogRollup rollup{store, std::chrono::hours{1}, &metrics, kTestStopPoll};
    rollup.start();
    // The worker publishes a finished tick only through this gauge (it has no completion hook or
    // CV), so the wait polls it. The 60 s is a deadlock guard, not a timing assumption: the test
    // proceeds the instant the success stamp lands, and the 10 ms step keeps it off a core while
    // Postgres runs the refresh.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{60};
    while (metrics.gauge(stamp).value() <= 0 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    rollup.stop(); // joins: everything the tick wrote is visible below

    CHECK(metrics.counter(std::string(kStem) + "_total", {{"outcome", "success"}}).value() == 1);
    CHECK(metrics.counter(std::string(kStem) + "_total", {{"outcome", "error"}}).value() == 0);
    // The catalogue leg failed (keep-last-good) and the components leg still ran after it.
    constexpr const char* kCatalog = "yuzu_inventory_catalog_rollup_total";
    CHECK(metrics.counter(kCatalog, {{"outcome", "error"}}).value() == 1);
    CHECK(metrics.counter(kCatalog, {{"outcome", "success"}}).value() == 0);
    CHECK(metrics.gauge(stamp).value() > 0);
    CHECK(metrics.gauge(std::string(kStem) + "_duration_seconds").value() >= 0);
    // The exposition the scrape serves: the three component families render with their TYPE
    // lines (the HELP text is ServerImpl's describe(), server.cpp, outside this unit), and the
    // two outcome series nothing incremented in this tick still exist at 0. A zero-valued
    // `error` series beside a success (and a zero-valued catalogue `success` beside its failure)
    // can only be the construction-time seed: without it the first failure would be the birth
    // of the series, which a rate rule cannot see.
    const auto text = metrics.serialize();
    for (const char* family : {"yuzu_inventory_component_rollup_total counter",
                               "yuzu_inventory_component_rollup_duration_seconds gauge",
                               "yuzu_inventory_component_rollup_last_success_timestamp gauge"}) {
        CAPTURE(family);
        CHECK(text.find(std::string("# TYPE ") + family + "\n") != std::string::npos);
    }
    CHECK(text.find("yuzu_inventory_component_rollup_total{outcome=\"error\"} 0\n") !=
          std::string::npos);
    CHECK(text.find("yuzu_inventory_catalog_rollup_total{outcome=\"success\"} 0\n") !=
          std::string::npos);
    const auto after = store.component_rollup_meta();
    REQUIRE(after.has_value());
    CHECK(after->refreshed_at > 0);
    const auto totals = store.component_totals("jar", "libfoo", std::nullopt); // the rollup row
    REQUIRE(totals.has_value());
    CHECK(totals->installs == 1);
    CHECK(totals->devices == 1);
}
