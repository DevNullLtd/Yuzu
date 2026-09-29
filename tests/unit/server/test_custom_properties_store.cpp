/**
 * test_custom_properties_store.cpp -- Unit tests for CustomPropertiesStore
 * (ADR-0006/ADR-0045, migrated Postgres store, schema `custom_properties_store`)
 *
 * Covers: property CRUD, schema CRUD, schema validation (type checking,
 * regex), key/value validation, agent isolation, property map, the bulk
 * get_values_for_keys preload (props.<key> scope-DSL resolution), and the
 * typed-error authoritative-read posture (kDegraded on a degrade, never a
 * silent empty).
 *
 * No legacy-SQLite backfill test coverage: the dedicated backfill TEST_CASE
 * suite (ADR-0009) was removed as part of a fresh-start-by-default policy
 * change (ADR-0009 amendment, 2026-08-25) -- no production fleet has ever
 * run a pre-Postgres build. CustomPropertiesStore::migrate_from_sqlite()
 * itself was retired (chore/retire-migrate-from-sqlite-batch-b, #3623).
 */

#include <catch2/catch_test_macros.hpp>

#include "custom_properties_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::CustomProperty;
using yuzu::server::CustomPropertiesReadError;
using yuzu::server::CustomPropertiesStore;
using yuzu::server::CustomPropertySchema;
using yuzu::server::kCustomPropertiesDbErrorPrefix;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

// ── Shared pre-migrated fixture (playbook "high-volume store-behaviour
// files" pattern) — one migrated clone + one persistent pool for the whole
// FILE, TRUNCATE-reset between tests instead of a fresh CREATE DATABASE +
// new pool per test (mirrors test_product_registry_store.cpp / the
// test_software_inventory_store.cpp rationale it cites). At testRunEnded the
// pool is drained before the clone is dropped, leaving static destruction
// inert. Backfill tests below deliberately construct their OWN store against
// their OWN per-test database (YUZU_REQUIRE_PG_DB) — they exercise
// fresh/empty-database behaviour the template's already-migrated clone
// can't.
yuzu::test::PgTestTemplate props_tpl{"customprops", [](const std::string& dsn) {
                                         PgPool pool{{.conninfo = dsn, .size = 1}};
                                         CustomPropertiesStore store{pool};
                                         if (!store.is_open())
                                             throw std::runtime_error(
                                                 "customprops template: store failed to migrate");
                                     }};

struct PropsShared {
    yuzu::test::PostgresTestDb db{props_tpl};
    std::optional<PgPool> pool;
    PropsShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
PropsShared& props_shared() {
    static PropsShared s;
    return s;
}

// custom_properties_meta was the backfill idempotency marker table;
// migrate_from_sqlite() (and the table itself) are retired (#3623) — nothing left
// to TRUNCATE there.
void props_reset() {
    auto lease = props_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc = pg::exec_params(lease.get(),
                                 "TRUNCATE custom_properties_store.custom_properties, "
                                 "custom_properties_store.custom_property_schemas "
                                 "RESTART IDENTITY CASCADE",
                                 std::vector<std::string>{});
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);
}

#define PROPS_SHARED(store, pool)                                                                 \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                              \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                           \
    }                                                                                              \
    props_reset();                                                                                 \
    [[maybe_unused]] PgPool& pool = *props_shared().pool;                                          \
    CustomPropertiesStore store{pool};                                                             \
    REQUIRE(store.is_open())

// Unwraps a get_property/get_properties/get_value/get_property_map
// std::expected result in tests, asserting it's NOT a degrade (the common
// case for well-formed CRUD tests below) and returning the success payload.
template <typename T>
T require_ok(const std::expected<T, CustomPropertiesReadError>& r) {
    REQUIRE(r.has_value());
    return *r;
}

// Asserts a set_property/upsert_schema setup call succeeded — these return
// std::expected<void, std::string>, a distinct overload from the typed-read
// one above. A silently-discarded failure here would let every assertion
// that follows test the wrong (unset) state while still passing (gov Gate 8
// finding, fjarvis review of PR #3097 — 40 MSVC C4834 sites, pre-existing,
// newly visible under the stricter [[nodiscard]] MSVC's <expected> now
// carries on std::expected<void, E> that libstdc++ does not).
void require_ok(const std::expected<void, std::string>& r) {
    REQUIRE(r.has_value());
}

} // namespace

// ============================================================================
// Lifecycle
// ============================================================================

TEST_CASE("CustomPropertiesStore: migrates at construction and reopens idempotently",
          "[pg][custom_props][db]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        CustomPropertiesStore s1{pool};
        REQUIRE(s1.is_open());
    }
    // A second construction against the already-migrated schema is a no-op
    // (versioned runner) — not a DDL re-run failure.
    CustomPropertiesStore s2{pool};
    CHECK(s2.is_open());
    auto props = s2.get_properties("agent-1");
    REQUIRE(props.has_value());
    CHECK(props->empty());
}

// ============================================================================
// Key/value validation (static methods, pure C++, unaffected by the substrate)
// ============================================================================

TEST_CASE("CustomPropertiesStore: validate_key accepts valid keys",
          "[custom_props][validation]") {
    CHECK(CustomPropertiesStore::validate_key("env") == true);
    CHECK(CustomPropertiesStore::validate_key("os.version") == true);
    CHECK(CustomPropertiesStore::validate_key("my-tag") == true);
    CHECK(CustomPropertiesStore::validate_key("tag:sub") == true);
    CHECK(CustomPropertiesStore::validate_key("a_b_c") == true);
    CHECK(CustomPropertiesStore::validate_key("ABC123") == true);
    CHECK(CustomPropertiesStore::validate_key("x") == true); // single char
}

TEST_CASE("CustomPropertiesStore: validate_key rejects invalid keys",
          "[custom_props][validation]") {
    CHECK(CustomPropertiesStore::validate_key("") == false);
    CHECK(CustomPropertiesStore::validate_key(std::string(65, 'a')) == false); // too long
    CHECK(CustomPropertiesStore::validate_key("has space") == false);
    CHECK(CustomPropertiesStore::validate_key("has/slash") == false);
    CHECK(CustomPropertiesStore::validate_key("has@at") == false);
    CHECK(CustomPropertiesStore::validate_key("has#hash") == false);
}

TEST_CASE("CustomPropertiesStore: validate_key allows max 64 chars",
          "[custom_props][validation]") {
    CHECK(CustomPropertiesStore::validate_key(std::string(64, 'a')) == true);
    CHECK(CustomPropertiesStore::validate_key(std::string(65, 'a')) == false);
}

TEST_CASE("CustomPropertiesStore: validate_value", "[custom_props][validation]") {
    CHECK(CustomPropertiesStore::validate_value("") == true);
    CHECK(CustomPropertiesStore::validate_value("hello") == true);
    CHECK(CustomPropertiesStore::validate_value(std::string(1024, 'x')) == true);
    CHECK(CustomPropertiesStore::validate_value(std::string(1025, 'x')) == false);
}

// ============================================================================
// Property CRUD
// ============================================================================

TEST_CASE("CustomPropertiesStore: set and get property", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    auto result = store.set_property("agent-1", "env", "production");
    REQUIRE(result.has_value());

    auto prop = require_ok(store.get_property("agent-1", "env"));
    REQUIRE(prop.has_value());
    CHECK(prop->agent_id == "agent-1");
    CHECK(prop->key == "env");
    CHECK(prop->value == "production");
    CHECK(prop->type == "string");
    CHECK(prop->updated_at > 0);
}

TEST_CASE("CustomPropertiesStore: get_value shortcut", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    require_ok(store.set_property("agent-1", "region", "us-east-1"));

    CHECK(require_ok(store.get_value("agent-1", "region")) == "us-east-1");
}

TEST_CASE("CustomPropertiesStore: get_value nonexistent returns nullopt (not degraded)",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);
    auto v = store.get_value("agent-1", "nonexistent");
    REQUIRE(v.has_value()); // read succeeded
    CHECK_FALSE(v->has_value()); // genuinely not found
}

TEST_CASE("CustomPropertiesStore: get_property nonexistent returns nullopt (not degraded)",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);
    auto p = store.get_property("agent-1", "nonexistent");
    REQUIRE(p.has_value());
    CHECK(*p == std::nullopt);
}

TEST_CASE("CustomPropertiesStore: set overwrites existing", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    require_ok(store.set_property("agent-1", "env", "staging"));

    require_ok(store.set_property("agent-1", "env", "production"));

    CHECK(require_ok(store.get_value("agent-1", "env")) == "production");
}

TEST_CASE("CustomPropertiesStore: set with custom type", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    require_ok(store.set_property("agent-1", "port", "8080", "int"));

    auto prop = require_ok(store.get_property("agent-1", "port"));
    REQUIRE(prop.has_value());
    CHECK(prop->type == "int");
}

TEST_CASE("CustomPropertiesStore: set with invalid key rejected", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    auto result = store.set_property("agent-1", "bad key", "value");
    REQUIRE(!result.has_value());
    CHECK(result.error().find("invalid property key") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: set with overlength value rejected",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    auto result = store.set_property("agent-1", "env", std::string(1025, 'x'));
    REQUIRE(!result.has_value());
    CHECK(result.error().find("maximum length") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: delete property", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    require_ok(store.set_property("agent-1", "env", "prod"));

    CHECK(store.delete_property("agent-1", "env") == true);
    CHECK(*store.get_property("agent-1", "env") == std::nullopt);

    // Second delete returns false
    CHECK(store.delete_property("agent-1", "env") == false);
}

TEST_CASE("CustomPropertiesStore: delete nonexistent returns false",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);
    CHECK(store.delete_property("agent-1", "nonexistent") == false);
}

TEST_CASE("CustomPropertiesStore: delete all properties for agent",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    require_ok(store.set_property("agent-1", "env", "prod"));

    require_ok(store.set_property("agent-1", "region", "us-east"));

    require_ok(store.set_property("agent-1", "role", "web"));

    store.delete_all_properties("agent-1");

    auto props = require_ok(store.get_properties("agent-1"));
    CHECK(props.empty());
}

TEST_CASE("CustomPropertiesStore: get_properties lists all for agent",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    require_ok(store.set_property("agent-1", "env", "prod"));

    require_ok(store.set_property("agent-1", "region", "us-east"));

    require_ok(store.set_property("agent-1", "role", "web"));

    auto props = require_ok(store.get_properties("agent-1"));
    REQUIRE(props.size() == 3);

    // Ordered by key
    CHECK(props[0].key == "env");
    CHECK(props[1].key == "region");
    CHECK(props[2].key == "role");
}

TEST_CASE("CustomPropertiesStore: get_properties for empty agent", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    auto props = require_ok(store.get_properties("agent-99"));
    CHECK(props.empty());
}

TEST_CASE("CustomPropertiesStore: get_property_map", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    require_ok(store.set_property("agent-1", "env", "prod"));

    require_ok(store.set_property("agent-1", "region", "eu-west"));

    auto map = require_ok(store.get_property_map("agent-1"));
    REQUIRE(map.size() == 2);
    CHECK(map["env"] == "prod");
    CHECK(map["region"] == "eu-west");
}

TEST_CASE("CustomPropertiesStore: get_property_map for empty agent",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);
    auto map = require_ok(store.get_property_map("agent-99"));
    CHECK(map.empty());
}

// ============================================================================
// Bulk preload (get_values_for_keys — props.<key> scope-DSL resolution)
// ============================================================================

TEST_CASE("CustomPropertiesStore: get_values_for_keys bulk-preloads across agents",
          "[pg][custom_props][bulk]") {
    PROPS_SHARED(store, pool);

    require_ok(store.set_property("agent-1", "env", "prod"));

    require_ok(store.set_property("agent-1", "region", "us-east"));

    require_ok(store.set_property("agent-2", "env", "staging"));

    require_ok(store.set_property("agent-3", "role", "web")); // not one of the requested keys' agents only

    auto result = require_ok(store.get_values_for_keys({"env", "region"}));
    REQUIRE(result.size() == 2); // agent-1, agent-2 (agent-3 has no env/region)
    REQUIRE(result.contains("agent-1"));
    CHECK(result["agent-1"]["env"] == "prod");
    CHECK(result["agent-1"]["region"] == "us-east");
    REQUIRE(result.contains("agent-2"));
    CHECK(result["agent-2"]["env"] == "staging");
    CHECK_FALSE(result["agent-2"].contains("region"));
}

TEST_CASE("CustomPropertiesStore: get_values_for_keys with empty keys returns empty map, no query",
          "[pg][custom_props][bulk]") {
    PROPS_SHARED(store, pool);
    require_ok(store.set_property("agent-1", "env", "prod"));

    auto result = require_ok(store.get_values_for_keys({}));
    CHECK(result.empty());
}

TEST_CASE("CustomPropertiesStore: get_values_for_keys with no matching properties",
          "[pg][custom_props][bulk]") {
    PROPS_SHARED(store, pool);
    require_ok(store.set_property("agent-1", "env", "prod"));

    auto result = require_ok(store.get_values_for_keys({"nonexistent"}));
    CHECK(result.empty());
}

// ============================================================================
// Authoritative-read posture (kDegraded on a store/pool/query failure)
// ============================================================================

TEST_CASE("CustomPropertiesStore: reads degrade to kDegraded on a closed store",
          "[custom_props][degrade]") {
    // A default-constructed PgPool pointed at an unreachable DSN never opens
    // — is_open() stays false, exercising the "store not open" degrade path
    // without needing a live Postgres instance (this case runs unconditionally).
    PgPool pool{{.conninfo = "postgresql://nonexistent-host-for-test:1/nope", .size = 1}};
    CustomPropertiesStore store{pool};
    REQUIRE_FALSE(store.is_open());

    CHECK(store.get_properties("agent-1").error() == CustomPropertiesReadError::kDegraded);
    CHECK(store.get_property("agent-1", "k").error() == CustomPropertiesReadError::kDegraded);
    CHECK(store.get_value("agent-1", "k").error() == CustomPropertiesReadError::kDegraded);
    CHECK(store.get_property_map("agent-1").error() == CustomPropertiesReadError::kDegraded);
    CHECK(store.get_values_for_keys({"k"}).error() == CustomPropertiesReadError::kDegraded);

    // get_schema/delete_schema widened to the same typed contract (gov Gate 8
    // finding, fjarvis re-review of PR #3065) — degrade on a closed store,
    // never a silent "not found".
    CHECK(store.get_schema("k").error() == CustomPropertiesReadError::kDegraded);
    CHECK(store.delete_schema("k").error() == CustomPropertiesReadError::kDegraded);

    // set_property/upsert_schema on a closed store are also errors (not
    // silently accepted) — same posture, string-error channel, now prefixed
    // with kCustomPropertiesDbErrorPrefix so a REST route can classify a
    // genuine store outage (503) apart from caller-input validation (400)
    // (gov Gate 8 finding, fjarvis re-review of PR #3065 — the route
    // previously mapped every failure, including a store outage, to 400).
    auto set_result = store.set_property("agent-1", "k", "v");
    REQUIRE(!set_result.has_value());
    CHECK(set_result.error() == std::string(kCustomPropertiesDbErrorPrefix) + "store not open");

    CustomPropertySchema schema{.key = "k", .display_name = "K", .type = "string"};
    auto schema_result = store.upsert_schema(schema);
    REQUIRE(!schema_result.has_value());
    CHECK(schema_result.error() == std::string(kCustomPropertiesDbErrorPrefix) + "store not open");
}

// ============================================================================
// Agent isolation
// ============================================================================

TEST_CASE("CustomPropertiesStore: properties isolated per agent",
          "[pg][custom_props][isolation]") {
    PROPS_SHARED(store, pool);

    require_ok(store.set_property("agent-1", "env", "production"));

    require_ok(store.set_property("agent-2", "env", "staging"));

    CHECK(require_ok(store.get_value("agent-1", "env")) == "production");
    CHECK(require_ok(store.get_value("agent-2", "env")) == "staging");

    auto props1 = require_ok(store.get_properties("agent-1"));
    REQUIRE(props1.size() == 1);
    CHECK(props1[0].value == "production");

    auto props2 = require_ok(store.get_properties("agent-2"));
    REQUIRE(props2.size() == 1);
    CHECK(props2[0].value == "staging");
}

TEST_CASE("CustomPropertiesStore: delete one agent does not affect another",
          "[pg][custom_props][isolation]") {
    PROPS_SHARED(store, pool);

    require_ok(store.set_property("agent-1", "env", "prod"));

    require_ok(store.set_property("agent-2", "env", "staging"));

    store.delete_all_properties("agent-1");

    CHECK(require_ok(store.get_properties("agent-1")).empty());
    CHECK(require_ok(store.get_value("agent-2", "env")) == "staging");
}

TEST_CASE("CustomPropertiesStore: same key different agents", "[pg][custom_props][isolation]") {
    PROPS_SHARED(store, pool);

    require_ok(store.set_property("agent-1", "role", "web"));

    require_ok(store.set_property("agent-2", "role", "db"));

    require_ok(store.set_property("agent-3", "role", "cache"));

    CHECK(require_ok(store.get_value("agent-1", "role")) == "web");
    CHECK(require_ok(store.get_value("agent-2", "role")) == "db");
    CHECK(require_ok(store.get_value("agent-3", "role")) == "cache");

    // Delete from agent-2 only
    CHECK(store.delete_property("agent-2", "role"));
    CHECK(require_ok(store.get_value("agent-1", "role")) == "web");
    CHECK_FALSE(require_ok(store.get_value("agent-2", "role")).has_value());
    CHECK(require_ok(store.get_value("agent-3", "role")) == "cache");
}

// ============================================================================
// Schema CRUD
// ============================================================================

TEST_CASE("CustomPropertiesStore: create and get schema", "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema schema;
    schema.key = "environment";
    schema.display_name = "Environment";
    schema.type = "string";
    schema.description = "Deployment environment";
    schema.validation_regex = "^(dev|staging|production)$";

    auto result = store.upsert_schema(schema);
    REQUIRE(result.has_value());

    auto retrieved = store.get_schema("environment");
    REQUIRE(retrieved.has_value());
    REQUIRE(retrieved->has_value());
    CHECK((*retrieved)->key == "environment");
    CHECK((*retrieved)->display_name == "Environment");
    CHECK((*retrieved)->type == "string");
    CHECK((*retrieved)->description == "Deployment environment");
    CHECK((*retrieved)->validation_regex == "^(dev|staging|production)$");
}

TEST_CASE("CustomPropertiesStore: list schemas", "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s1{.key = "env", .display_name = "Env", .type = "string"};
    CustomPropertySchema s2{.key = "port", .display_name = "Port", .type = "int"};
    CustomPropertySchema s3{.key = "active", .display_name = "Active", .type = "bool"};

    require_ok(store.upsert_schema(s1));

    require_ok(store.upsert_schema(s2));

    require_ok(store.upsert_schema(s3));

    auto schemas = store.list_schemas();
    REQUIRE(schemas.size() == 3);
    // Sorted by key
    CHECK(schemas[0].key == "active");
    CHECK(schemas[1].key == "env");
    CHECK(schemas[2].key == "port");
}

TEST_CASE("CustomPropertiesStore: update schema via upsert", "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s1{.key = "env", .display_name = "Env", .type = "string"};
    require_ok(store.upsert_schema(s1));

    // Update display name
    CustomPropertySchema s2{.key = "env", .display_name = "Environment", .type = "string",
                             .description = "Updated"};
    require_ok(store.upsert_schema(s2));

    auto schema = store.get_schema("env");
    REQUIRE(schema.has_value());
    REQUIRE(schema->has_value());
    CHECK((*schema)->display_name == "Environment");
    CHECK((*schema)->description == "Updated");

    // Still only one schema
    auto all = store.list_schemas();
    CHECK(all.size() == 1);
}

TEST_CASE("CustomPropertiesStore: delete schema", "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "env", .display_name = "Env", .type = "string"};
    require_ok(store.upsert_schema(s));

    auto del1 = store.delete_schema("env");
    REQUIRE(del1.has_value());
    CHECK(*del1 == true);

    auto after = store.get_schema("env");
    REQUIRE(after.has_value());
    CHECK(*after == std::nullopt);

    auto del2 = store.delete_schema("env");
    REQUIRE(del2.has_value());
    CHECK(*del2 == false);
}

TEST_CASE("CustomPropertiesStore: delete nonexistent schema", "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);
    auto del = store.delete_schema("nonexistent");
    REQUIRE(del.has_value());
    CHECK(*del == false);
}

TEST_CASE("CustomPropertiesStore: get nonexistent schema returns nullopt",
          "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);
    auto schema = store.get_schema("nonexistent");
    REQUIRE(schema.has_value());
    CHECK(*schema == std::nullopt);
}

TEST_CASE("CustomPropertiesStore: schema with invalid key rejected",
          "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "bad key", .display_name = "Bad", .type = "string"};
    auto result = store.upsert_schema(s);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("invalid schema key") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema with invalid type rejected",
          "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "env", .display_name = "Env", .type = "float"};
    auto result = store.upsert_schema(s);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("type must be one of") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema with invalid regex rejected",
          "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "env", .display_name = "Env", .type = "string",
                            .validation_regex = "[invalid("};
    auto result = store.upsert_schema(s);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("invalid validation regex") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema regex exceeding max length rejected",
          "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "env", .display_name = "Env", .type = "string",
                            .validation_regex = std::string(257, 'a')};
    auto result = store.upsert_schema(s);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("maximum length of 256") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema valid types accepted", "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    for (const auto& type : {"string", "int", "bool", "datetime"}) {
        CustomPropertySchema s{.key = std::string("k_") + type,
                                .display_name = type,
                                .type = type};
        auto result = store.upsert_schema(s);
        REQUIRE(result.has_value());
    }

    auto schemas = store.list_schemas();
    CHECK(schemas.size() == 4);
}

// ============================================================================
// Schema validation on set
// ============================================================================

TEST_CASE("CustomPropertiesStore: schema type validation -- int",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "port", .display_name = "Port", .type = "int"};
    require_ok(store.upsert_schema(s));

    // Valid int
    auto r1 = store.set_property("agent-1", "port", "8080");
    REQUIRE(r1.has_value());

    // Invalid int
    auto r2 = store.set_property("agent-1", "port", "not-a-number");
    REQUIRE(!r2.has_value());
    CHECK(r2.error().find("valid integer") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema type validation -- bool",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "active", .display_name = "Active", .type = "bool"};
    require_ok(store.upsert_schema(s));

    auto r1 = store.set_property("agent-1", "active", "true");
    REQUIRE(r1.has_value());

    auto r2 = store.set_property("agent-1", "active", "false");
    REQUIRE(r2.has_value());

    auto r3 = store.set_property("agent-1", "active", "yes");
    REQUIRE(!r3.has_value());
    CHECK(r3.error().find("'true' or 'false'") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema type validation -- string accepts anything",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "desc", .display_name = "Description", .type = "string"};
    require_ok(store.upsert_schema(s));

    auto r = store.set_property("agent-1", "desc", "anything goes here 123!@#");
    REQUIRE(r.has_value());
}

TEST_CASE("CustomPropertiesStore: schema type validation -- datetime accepts any string",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "enrolled_at", .display_name = "Enrolled At",
                            .type = "datetime"};
    require_ok(store.upsert_schema(s));

    auto r = store.set_property("agent-1", "enrolled_at", "2025-01-15T12:00:00Z");
    REQUIRE(r.has_value());
}

TEST_CASE("CustomPropertiesStore: schema regex validation", "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "env",
                            .display_name = "Environment",
                            .type = "string",
                            .validation_regex = "^(dev|staging|production)$"};
    require_ok(store.upsert_schema(s));

    // Matching values
    auto r1 = store.set_property("agent-1", "env", "production");
    REQUIRE(r1.has_value());

    auto r2 = store.set_property("agent-1", "env", "dev");
    REQUIRE(r2.has_value());

    // Non-matching value
    auto r3 = store.set_property("agent-1", "env", "testing");
    REQUIRE(!r3.has_value());
    CHECK(r3.error().find("validation pattern") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: no schema means no validation",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    // No schema for "freeform" key -- anything should be accepted
    auto r = store.set_property("agent-1", "freeform", "any value");
    REQUIRE(r.has_value());
    CHECK(require_ok(store.get_value("agent-1", "freeform")) == "any value");
}

TEST_CASE("CustomPropertiesStore: schema type overrides provided type",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    // Define schema with type "int"
    CustomPropertySchema s{.key = "port", .display_name = "Port", .type = "int"};
    require_ok(store.upsert_schema(s));

    // Set with type "string" -- schema type should win
    auto r = store.set_property("agent-1", "port", "8080", "string");
    REQUIRE(r.has_value());

    auto prop = require_ok(store.get_property("agent-1", "port"));
    REQUIRE(prop.has_value());
    CHECK(prop->type == "int");
}

TEST_CASE("CustomPropertiesStore: schema regex with int type",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    // Int schema with regex for port range
    CustomPropertySchema s{.key = "port",
                            .display_name = "Port",
                            .type = "int",
                            .validation_regex = "^[0-9]{1,5}$"};
    require_ok(store.upsert_schema(s));

    // Valid: integer that matches regex
    auto r1 = store.set_property("agent-1", "port", "8080");
    REQUIRE(r1.has_value());

    // Invalid: not an integer
    auto r2 = store.set_property("agent-1", "port", "abc");
    REQUIRE(!r2.has_value());

    // Invalid: integer but doesn't match regex (negative)
    auto r3 = store.set_property("agent-1", "port", "-1");
    REQUIRE(!r3.has_value());
}

TEST_CASE("CustomPropertiesStore: delete schema removes validation",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "env",
                            .display_name = "Env",
                            .type = "string",
                            .validation_regex = "^(dev|prod)$"};
    require_ok(store.upsert_schema(s));

    // Rejected with schema
    auto r1 = store.set_property("agent-1", "env", "testing");
    REQUIRE(!r1.has_value());

    // Delete schema
    auto del = store.delete_schema("env");
    REQUIRE(del.has_value());
    CHECK(*del == true);

    // Accepted without schema
    auto r2 = store.set_property("agent-1", "env", "testing");
    REQUIRE(r2.has_value());
}
