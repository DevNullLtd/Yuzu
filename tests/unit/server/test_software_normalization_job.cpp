/// @file test_software_normalization_job.cpp
/// Lifecycle tests for the SoftwareNormalizationJob thread (start/stop join, double stop,
/// restart, destructor join, request_stop without join). PG-gated like its sibling
/// test_software_catalog_rollup.cpp: the thread runs a real tick, so it needs the
/// two-store template; the tick OUTCOME is asserted in test_software_title_dimension.cpp.

#include "software_normalization_job.hpp"

#include "pg/pg_pool.hpp"
#include "product_registry_store.hpp"
#include "software_inventory_store.hpp"
#include "software_title_dimension.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/metrics.hpp>

#include <chrono>
#include <stdexcept>

using yuzu::server::ProductRegistryStore;
using yuzu::server::SoftwareInventoryStore;
using yuzu::server::SoftwareNormalizationJob;
using yuzu::server::SoftwareTitleDimension;
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
