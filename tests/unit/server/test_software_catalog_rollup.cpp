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

#include "pg/pg_pool.hpp"
#include "software_inventory_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/metrics.hpp>

#include <chrono>
#include <stdexcept>
#include <thread>

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
        SoftwareCatalogRollup rollup{store, interval};
        rollup.start();
        rollup.stop(); // signals + joins
        rollup.stop(); // must not double-join / crash
        SUCCEED("start/stop/double-stop completed without hang or crash");
    }

    SECTION("start is idempotent; start-after-stop restarts") {
        SoftwareCatalogRollup rollup{store, interval};
        rollup.start();
        rollup.start(); // already running → no-op (guarded by thread_.joinable())
        rollup.stop();
        rollup.start(); // start-after-stop resets the stop flag and re-runs
        rollup.stop();
        SUCCEED("idempotent start + start-after-stop completed");
    }

    SECTION("destructor stops + joins a running thread without an explicit stop") {
        {
            SoftwareCatalogRollup rollup{store, interval};
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
    // budget after it. A 1s interval makes the loop re-arm after one 5s sleep step,
    // so without request_stop() a second recompute would run inside the window below.
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

    SoftwareCatalogRollup rollup{store, std::chrono::seconds{1}, &metrics};
    rollup.start();
    for (int i = 0; i < 100 && recomputes() < 1; ++i) // the immediate first recompute
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    REQUIRE(recomputes() == 1);

    rollup.request_stop();                                // must not block
    std::this_thread::sleep_for(std::chrono::seconds{7}); // > one 5s re-arm step
    CHECK(recomputes() == 1);                             // no new recompute started

    const auto t = std::chrono::steady_clock::now();
    rollup.stop(); // the thread already exited on the flag; the join is immediate
    CHECK(std::chrono::steady_clock::now() - t < std::chrono::seconds{1});
}
