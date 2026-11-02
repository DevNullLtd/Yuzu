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

    SECTION("start then stop joins cleanly and double stop is a no-op") {
        SoftwareNormalizationJob job{owner, interval};
        job.start();
        job.start(); // idempotent
        job.stop();
        job.stop();
    }
    SECTION("start after stop restarts the thread") {
        SoftwareNormalizationJob job{owner, interval};
        job.start();
        job.stop();
        job.start();
        job.stop();
    }
    SECTION("destructor joins without an explicit stop") {
        SoftwareNormalizationJob job{owner, interval};
        job.start();
    }
    SECTION("request_stop without join leaves stop to join later") {
        SoftwareNormalizationJob job{owner, interval};
        job.start();
        job.request_stop();
        job.stop();
    }
}
