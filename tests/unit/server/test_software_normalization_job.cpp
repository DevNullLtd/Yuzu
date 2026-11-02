/// @file test_software_normalization_job.cpp
/// Tests for the SoftwareNormalizationJob: the pure re-arm choice, the metric series the
/// job seeds and how a tick maps onto them (via the synchronous `tick_once()`), and the
/// thread lifecycle (start/stop join, double stop, restart, destructor join, request_stop
/// without join). The PG cases are gated like the sibling test_software_catalog_rollup.cpp:
/// they run a real tick, so they need the two-store template; the tick's own outcome is
/// asserted in test_software_title_dimension.cpp.

#include "software_normalization_job.hpp"

#include "pg/pg_pool.hpp"
#include "product_registry_store.hpp"
#include "software_inventory_store.hpp"
#include "software_normalization_pack.hpp"
#include "software_title_dimension.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/metrics.hpp>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <string>

using yuzu::server::ProductRegistryStore;
using yuzu::server::SoftwareInventoryStore;
using yuzu::server::SoftwareNormalizationJob;
using yuzu::server::SoftwareTitleDimension;
using yuzu::server::TickResult;
using yuzu::server::kBacklogRearm;
using yuzu::server::rearm_interval;
using yuzu::server::pg::PgPool;

namespace {
yuzu::test::PgTestTemplate normjob_tpl{"normjob", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    SoftwareInventoryStore inv{pool};
    ProductRegistryStore reg{pool};
    if (!inv.is_open() || !reg.is_open())
        throw std::runtime_error("normjob template: a store failed to migrate");
}};
} // namespace

TEST_CASE("rearm_interval waits the short backlog floor only after a capped tick",
          "[normalization][job]") {
    const auto hour = std::chrono::seconds{3600};
    TickResult quiet;
    CHECK(rearm_interval(quiet, hour) == hour);
    TickResult capped;
    capped.capped = true;
    CHECK(rearm_interval(capped, hour) == kBacklogRearm);
    CHECK(kBacklogRearm == std::chrono::seconds{60});
    // The floor never exceeds a configured interval that is already shorter.
    CHECK(rearm_interval(capped, std::chrono::seconds{10}) == std::chrono::seconds{10});
    // A failed or cancelled tick is never capped (run_tick clears it), so it keeps `interval`.
    TickResult failed;
    failed.errored = true;
    CHECK(rearm_interval(failed, hour) == hour);
    // A tick that found the catalogue rollup's candidate source still empty looks again soon,
    // and also never waits longer than a shorter configured interval.
    TickResult pending;
    pending.source_pending = true;
    CHECK(rearm_interval(pending, hour) == kBacklogRearm);
    CHECK(rearm_interval(pending, std::chrono::seconds{10}) == std::chrono::seconds{10});
}

TEST_CASE("SoftwareNormalizationJob seeds its series at construction and maps ticks onto them",
          "[pg][product_registry][normalization]") {
    YUZU_REQUIRE_PG_DB_TPL(db, normjob_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore inv{pool};
    ProductRegistryStore reg{pool};
    REQUIRE(inv.is_open());
    REQUIRE(reg.is_open());
    yuzu::MetricsRegistry metrics;
    SoftwareTitleDimension owner{pool, reg, inv, &metrics};
    SoftwareNormalizationJob job{owner, std::chrono::hours{1}, &metrics};

    // Read BEFORE any accessor below can create a series: both outcomes and the stamp
    // already exist at 0, so the first failure is an increase the Failing rule can see.
    const std::string seeded = metrics.serialize();
    CHECK(seeded.find("yuzu_software_normalization_pass_total{outcome=\"error\"} 0") !=
          std::string::npos);
    CHECK(seeded.find("yuzu_software_normalization_pass_total{outcome=\"success\"} 0") !=
          std::string::npos);
    CHECK(seeded.find("yuzu_software_normalization_last_success_timestamp 0") != std::string::npos);

    const auto outcome = [&](const char* o) {
        return metrics.counter("yuzu_software_normalization_pass_total", {{"outcome", o}}).value();
    };
    const auto stamp = [&] {
        return metrics.gauge("yuzu_software_normalization_last_success_timestamp").value();
    };

    // No pack loaded: the tick is an error, and the success stamp stays at its seed.
    const TickResult none = job.tick_once();
    CHECK(none.errored);
    CHECK_FALSE(none.capped);
    CHECK(outcome("error") == 1);
    CHECK(outcome("success") == 0);
    CHECK(stamp() == 0);

    // With a pack the tick is clean: success counted and the stamp set.
    const auto seed = yuzu::server::parse_normalization_pack(yuzu::server::kSoftwareNormalizationSeed);
    REQUIRE(seed.has_value());
    REQUIRE(reg.load_pack_if_empty(*seed, "test").has_value());
    const TickResult ok = job.tick_once();
    CHECK_FALSE(ok.errored);
    CHECK(outcome("success") == 1);
    CHECK(outcome("error") == 1);
    CHECK(stamp() > 0);
}

TEST_CASE("SoftwareNormalizationJob counts a cancelled tick as neither success nor error",
          "[pg][product_registry][normalization]") {
    YUZU_REQUIRE_PG_DB_TPL(db, normjob_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore inv{pool};
    ProductRegistryStore reg{pool};
    REQUIRE(inv.is_open());
    REQUIRE(reg.is_open());
    yuzu::MetricsRegistry metrics;
    SoftwareTitleDimension owner{pool, reg, inv, &metrics};
    SoftwareNormalizationJob job{owner, std::chrono::hours{1}, &metrics};

    job.request_stop(); // the stop flag is the tick's cancel predicate
    const TickResult t = job.tick_once();
    CHECK(t.cancelled);
    CHECK_FALSE(t.errored);
    CHECK(metrics.counter("yuzu_software_normalization_pass_total", {{"outcome", "success"}})
              .value() == 0);
    CHECK(metrics.counter("yuzu_software_normalization_pass_total", {{"outcome", "error"}})
              .value() == 0);
    CHECK(metrics.gauge("yuzu_software_normalization_last_success_timestamp").value() == 0);
}

TEST_CASE("SoftwareNormalizationJob thread lifecycle", "[pg][product_registry][normalization]") {
    YUZU_REQUIRE_PG_DB_TPL(db, normjob_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore inv{pool};
    ProductRegistryStore reg{pool};
    REQUIRE(inv.is_open());
    REQUIRE(reg.is_open());
    SoftwareTitleDimension owner{pool, reg, inv};
    const auto interval = std::chrono::hours{1}; // one immediate tick, then park

    // Each section waits for a tick the thread actually completed (no pack is loaded in this
    // template, so that tick is a clean `errored` one) instead of assuming start() ran one.
    // A condition-variable wait with a failure deadline, never a sleep-and-poll.
    struct Ticks {
        std::mutex m;
        std::condition_variable cv;
        int count{0};
        TickResult last;
        SoftwareNormalizationJob::TickObserver observer() {
            return [this](const TickResult& r) {
                {
                    std::lock_guard<std::mutex> lk{m};
                    ++count;
                    last = r;
                }
                cv.notify_all();
            };
        }
        // True once `n` ticks have completed.
        bool wait_for_ticks(int n) {
            std::unique_lock<std::mutex> lk{m};
            return cv.wait_for(lk, std::chrono::seconds{60}, [&] { return count >= n; });
        }
    };
    const auto expect_a_tick = [](Ticks& t) {
        std::lock_guard<std::mutex> lk{t.m};
        CHECK(t.last.passes == 1);
        CHECK(t.last.errored);
        CHECK_FALSE(t.last.cancelled);
    };

    SECTION("start then stop joins cleanly and double stop is a no-op") {
        Ticks ticks;
        SoftwareNormalizationJob job{owner, interval, nullptr, ticks.observer()};
        job.start();
        job.start(); // idempotent: still exactly one thread, one first tick
        REQUIRE(ticks.wait_for_ticks(1));
        expect_a_tick(ticks);
        job.stop();
        job.stop();
    }
    SECTION("start after stop restarts the thread and it ticks again") {
        Ticks ticks;
        SoftwareNormalizationJob job{owner, interval, nullptr, ticks.observer()};
        job.start();
        REQUIRE(ticks.wait_for_ticks(1));
        job.stop();
        job.start();
        REQUIRE(ticks.wait_for_ticks(2));
        expect_a_tick(ticks);
        job.stop();
    }
    SECTION("destructor joins without an explicit stop") {
        Ticks ticks;
        {
            SoftwareNormalizationJob job{owner, interval, nullptr, ticks.observer()};
            job.start();
            REQUIRE(ticks.wait_for_ticks(1));
            expect_a_tick(ticks);
        }
    }
    SECTION("request_stop without join leaves stop to join later") {
        Ticks ticks;
        SoftwareNormalizationJob job{owner, interval, nullptr, ticks.observer()};
        job.start();
        REQUIRE(ticks.wait_for_ticks(1));
        job.request_stop();
        job.stop();
    }
}
