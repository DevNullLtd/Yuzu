/**
 * test_legacy_shim.cpp — Unit tests for legacy plugin shim
 *
 * Covers: generate_legacy_definitions (count, id format, open schema),
 *         sync_legacy_definitions (create, skip existing, idempotency).
 */

#include "legacy_shim.hpp"

#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using yuzu::server::pg::PgPool;

namespace {
yuzu::test::PgTestTemplate legacy_shim_instr_tpl{
    "legacyshiminstr", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("legacy_shim_instr template: store failed to migrate");
    }};
} // namespace

// ── Helpers ─────────────────────────────────────────────────────────────────

static std::vector<PluginCapability> make_test_capabilities() {
    return {
        {"system_info", "1.0.0", "System information plugin", {"query", "summary"}},
        {"network", "2.1.0", "Network diagnostics plugin", {"ping", "traceroute", "dns"}},
    };
}

// ── generate_legacy_definitions ─────────────────────────────────────────────

TEST_CASE("LegacyShim: generate produces correct count", "[legacy_shim]") {
    auto caps = make_test_capabilities();
    auto defs = generate_legacy_definitions(caps);

    // system_info has 2 actions, network has 3 = 5 total
    REQUIRE(defs.size() == 5);
}

TEST_CASE("LegacyShim: generated definitions have correct id format", "[legacy_shim]") {
    auto caps = make_test_capabilities();
    auto defs = generate_legacy_definitions(caps);

    // All ids should follow "legacy.<plugin>.<action>"
    for (const auto& def : defs) {
        CHECK(def.id.substr(0, 7) == "legacy.");
    }

    // Check specific ids
    auto find_by_id = [&](const std::string& id) {
        return std::ranges::find_if(defs, [&](const auto& d) { return d.id == id; });
    };

    CHECK(find_by_id("legacy.system_info.query") != defs.end());
    CHECK(find_by_id("legacy.system_info.summary") != defs.end());
    CHECK(find_by_id("legacy.network.ping") != defs.end());
    CHECK(find_by_id("legacy.network.traceroute") != defs.end());
    CHECK(find_by_id("legacy.network.dns") != defs.end());
}

TEST_CASE("LegacyShim: generated definitions have open parameter schema", "[legacy_shim]") {
    auto caps = make_test_capabilities();
    auto defs = generate_legacy_definitions(caps);

    for (const auto& def : defs) {
        CHECK_FALSE(def.parameter_schema.empty());

        // The parameter schema should allow additionalProperties (open schema)
        CHECK(def.parameter_schema.find("additionalProperties") != std::string::npos);
    }
}

TEST_CASE("LegacyShim: generated definitions have correct fields", "[legacy_shim]") {
    PluginCapability cap{"my_plugin", "3.0.0", "My plugin", {"do_thing"}};
    auto defs = generate_legacy_definitions({cap});

    REQUIRE(defs.size() == 1);
    const auto& def = defs[0];

    CHECK(def.id == "legacy.my_plugin.do_thing");
    CHECK(def.plugin == "my_plugin");
    CHECK(def.action == "do_thing");
    CHECK(def.type == "question");
    CHECK(def.version == "1.0.0");
    CHECK(def.enabled == true);
    CHECK(def.concurrency_mode == "per-device");
    CHECK(def.approval_mode == "auto");
    CHECK_FALSE(def.yaml_source.empty());
    CHECK_FALSE(def.result_schema.empty());
}

TEST_CASE("LegacyShim: generate with empty capabilities produces nothing", "[legacy_shim]") {
    auto defs = generate_legacy_definitions({});
    CHECK(defs.empty());
}

TEST_CASE("LegacyShim: generate with empty actions produces nothing", "[legacy_shim]") {
    PluginCapability cap{"empty_plugin", "1.0.0", "Empty", {}};
    auto defs = generate_legacy_definitions({cap});
    CHECK(defs.empty());
}

// ── sync_legacy_definitions ─────────────────────────────────────────────────

TEST_CASE("LegacyShim: sync creates new definitions", "[legacy_shim][db][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, legacy_shim_instr_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto caps = make_test_capabilities();
    int created = sync_legacy_definitions(store, caps);

    CHECK(created == 5);

    // Verify they exist in the store
    auto all = store.query_definitions();
    REQUIRE(all.has_value());
    CHECK(all->size() == 5);
}

TEST_CASE("LegacyShim: sync skips existing definitions", "[legacy_shim][db][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, legacy_shim_instr_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto caps = make_test_capabilities();

    int first_run = sync_legacy_definitions(store, caps);
    CHECK(first_run == 5);

    // Second sync should skip all — they already exist
    int second_run = sync_legacy_definitions(store, caps);
    CHECK(second_run == 0);

    // Total count should still be 5
    auto all = store.query_definitions();
    REQUIRE(all.has_value());
    CHECK(all->size() == 5);
}

TEST_CASE("LegacyShim: sync is idempotent", "[legacy_shim][db][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, legacy_shim_instr_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto caps = make_test_capabilities();

    // Run sync three times
    sync_legacy_definitions(store, caps);
    sync_legacy_definitions(store, caps);
    int third = sync_legacy_definitions(store, caps);

    CHECK(third == 0);
    auto all = store.query_definitions();
    REQUIRE(all.has_value());
    CHECK(all->size() == 5);
}

TEST_CASE("LegacyShim: sync with new capability adds only new", "[legacy_shim][db][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, legacy_shim_instr_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    // First sync with one plugin
    std::vector<PluginCapability> caps1 = {{"plugin_a", "1.0.0", "Plugin A", {"action1"}}};
    int first = sync_legacy_definitions(store, caps1);
    CHECK(first == 1);

    // Second sync adds a new plugin
    std::vector<PluginCapability> caps2 = {
        {"plugin_a", "1.0.0", "Plugin A", {"action1"}},
        {"plugin_b", "1.0.0", "Plugin B", {"action2", "action3"}}};
    int second = sync_legacy_definitions(store, caps2);
    CHECK(second == 2);

    auto all = store.query_definitions();
    REQUIRE(all.has_value());
    CHECK(all->size() == 3);
}
