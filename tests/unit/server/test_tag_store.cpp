/**
 * test_tag_store.cpp — Unit tests for TagStore (Postgres substrate, ADR-0050).
 *
 * Covers: CRUD, validation, sync (incl. mid-transaction fault atomicity),
 * agents_with_tag, tag maps, bulk preloads, compliance gaps, and degrade
 * behaviour (typed reads).
 *
 * Fixture layout mirrors test_custom_properties_store.cpp: a shared
 * pre-migrated clone + persistent pool, TRUNCATE-reset per CRUD test;
 * fault-injection and degrade tests take their OWN template clone (a
 * dropped table / installed trigger must not leak into the shared clone).
 *
 * No legacy-SQLite backfill test coverage: the dedicated backfill TEST_CASE
 * suite (ADR-0009) was removed as part of a fresh-start-by-default policy
 * change (ADR-0009 amendment, 2026-08-25) -- no production fleet has ever
 * run a pre-Postgres build. TagStore::migrate_from_sqlite() itself was
 * retired (chore/retire-migrate-from-sqlite-batch-b, #3623).
 */

#include "tag_store.hpp"

#include <yuzu/metrics.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"
#include "test_tag_store_pg_helper.hpp"

#include <libpq-fe.h>

#include <optional>
#include <string>
#include <tuple>
#include <vector>

using yuzu::server::DeviceTag;
using yuzu::server::kTagDbErrorPrefix;
using yuzu::server::TagReadError;
using yuzu::server::TagStore;
using yuzu::server::get_tag_categories;
using yuzu::server::kCategoryKeys;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
namespace pg = yuzu::server::pg;

namespace {

// ── Shared pre-migrated fixture (playbook "high-volume store-behaviour
// files" pattern; template object shared via test_tag_store_pg_helper.hpp's
// "tagstore" key). At testRunEnded the pool is drained before the clone is
// dropped.
struct TagShared {
    yuzu::test::PostgresTestDb db{yuzu::test::tag_store_pg_template};
    std::optional<PgPool> pool;
    TagShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
TagShared& tag_shared() {
    static TagShared s;
    return s;
}

// tag_store_meta was the backfill idempotency marker table; migrate_from_sqlite()
// (and the table itself) are retired (#3623) — nothing left to TRUNCATE there.
void tag_reset() {
    auto lease = tag_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc = pg::exec_params(lease.get(), "TRUNCATE tag_store.tags RESTART IDENTITY CASCADE",
                                 std::vector<std::string>{});
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);
}

#define TAGS_SHARED(store)                                                                         \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                              \
    tag_reset();                                                                                   \
    [[maybe_unused]] PgPool& pool = *tag_shared().pool;                                            \
    TagStore store{pool};                                                                          \
    REQUIRE(store.is_open())

// Unwraps a typed-read std::expected in tests, asserting it's NOT a degrade
// (the common case for well-formed CRUD tests below).
template <typename T>
T require_ok(const std::expected<T, TagReadError>& r) {
    REQUIRE(r.has_value());
    return *r;
}

// Asserts a write returning std::expected<void, std::string> succeeded — a
// silently-discarded failure here would let every assertion that follows
// test the wrong (unset) state while still passing.
void require_ok(const std::expected<void, std::string>& r) {
    if (!r.has_value())
        INFO("write failed: " << r.error());
    REQUIRE(r.has_value());
}

} // namespace

// ============================================================================
// Lifecycle
// ============================================================================

TEST_CASE("TagStore: migrates at construction and reopens idempotently", "[pg][tag_store][db][pg-smoke]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        TagStore s1{pool};
        REQUIRE(s1.is_open());
    }
    // A second construction against the already-migrated schema is a no-op
    // (versioned runner) — not a DDL re-run failure.
    TagStore s2{pool};
    CHECK(s2.is_open());
    auto tags = s2.get_all_tags("agent-1");
    REQUIRE(tags.has_value());
    CHECK(tags->empty());
}

// ============================================================================
// Key/value validation (static methods, pure C++, unaffected by the substrate)
// ============================================================================

TEST_CASE("TagStore: validate_key", "[tag_store][validation]") {
    CHECK(TagStore::validate_key("env") == true);
    CHECK(TagStore::validate_key("os.version") == true);
    CHECK(TagStore::validate_key("my-tag") == true);
    CHECK(TagStore::validate_key("tag:sub") == true);
    CHECK(TagStore::validate_key("") == false);
    CHECK(TagStore::validate_key(std::string(65, 'a')) == false);
    CHECK(TagStore::validate_key("has space") == false);
    CHECK(TagStore::validate_key("has/slash") == false);
}

TEST_CASE("TagStore: validate_value", "[tag_store][validation]") {
    CHECK(TagStore::validate_value("") == true);
    CHECK(TagStore::validate_value("hello") == true);
    CHECK(TagStore::validate_value(std::string(448, 'x')) == true);
    CHECK(TagStore::validate_value(std::string(449, 'x')) == false);
}

// ============================================================================
// CRUD
// ============================================================================

TEST_CASE("TagStore: set and get", "[pg][tag_store][pg-smoke]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "env", "production"));
    auto v = require_ok(store.get_tag("agent-1", "env"));
    REQUIRE(v.has_value());
    CHECK(*v == "production");
}

TEST_CASE("TagStore: get nonexistent returns nullopt (not degraded)", "[pg][tag_store]") {
    TAGS_SHARED(store);
    auto v = require_ok(store.get_tag("agent-1", "nonexistent"));
    CHECK_FALSE(v.has_value());
}

TEST_CASE("TagStore: a present tag with an empty value is engaged, distinguishable from absent",
          "[pg][tag_store][pg-smoke]") {
    TAGS_SHARED(store);
    require_ok(store.set_tag("agent-1", "note", ""));
    auto v = require_ok(store.get_tag("agent-1", "note"));
    REQUIRE(v.has_value()); // engaged optional{""} — the pre-migration
    CHECK(v->empty());      // plain-string contract collapsed both cases
}

TEST_CASE("TagStore: set overwrites", "[pg][tag_store]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "env", "staging"));
    require_ok(store.set_tag("agent-1", "env", "production"));
    auto v = require_ok(store.get_tag("agent-1", "env"));
    REQUIRE(v.has_value());
    CHECK(*v == "production");
}

TEST_CASE("TagStore: delete_tag distinguishes deleted / not-found", "[pg][tag_store]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "env", "prod"));
    auto del1 = store.delete_tag("agent-1", "env");
    REQUIRE(del1.has_value());
    CHECK(*del1 == true);
    CHECK_FALSE(require_ok(store.get_tag("agent-1", "env")).has_value());
    auto del2 = store.delete_tag("agent-1", "env");
    REQUIRE(del2.has_value());
    CHECK(*del2 == false);
}

TEST_CASE("TagStore: get_all_tags", "[pg][tag_store]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "env", "prod"));
    require_ok(store.set_tag("agent-1", "region", "us-east"));
    require_ok(store.set_tag("agent-2", "env", "staging"));

    auto tags = require_ok(store.get_all_tags("agent-1"));
    REQUIRE(tags.size() == 2);
    // key-ordered
    CHECK(tags[0].key == "env");
    CHECK(tags[1].key == "region");

    auto tags2 = require_ok(store.get_all_tags("agent-2"));
    REQUIRE(tags2.size() == 1);
}

TEST_CASE("TagStore: get_tag_map", "[pg][tag_store]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "env", "prod"));
    require_ok(store.set_tag("agent-1", "region", "eu-west"));

    auto map = require_ok(store.get_tag_map("agent-1"));
    REQUIRE(map.size() == 2);
    CHECK(map["env"] == "prod");
    CHECK(map["region"] == "eu-west");
}

TEST_CASE("TagStore: source preserved", "[pg][tag_store]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "env", "prod", "api"));
    auto tags = require_ok(store.get_all_tags("agent-1"));
    REQUIRE(tags.size() == 1);
    CHECK(tags[0].source == "api");
}

TEST_CASE("TagStore: invalid key rejected as a caller error, nothing written",
          "[pg][tag_store]") {
    TAGS_SHARED(store);

    auto res = store.set_tag("agent-1", "has space", "value");
    REQUIRE_FALSE(res.has_value());
    // Caller-input error, NOT a db_error (#3097 classification contract).
    CHECK_FALSE(res.error().starts_with(kTagDbErrorPrefix));
    CHECK_FALSE(require_ok(store.get_tag("agent-1", "has space")).has_value());
}

TEST_CASE("TagStore: delete_all_tags", "[pg][tag_store]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "env", "prod"));
    require_ok(store.set_tag("agent-1", "region", "us"));
    require_ok(store.delete_all_tags("agent-1"));

    CHECK(require_ok(store.get_all_tags("agent-1")).empty());
}

// ============================================================================
// Sync (agent-sourced) + #1411 source precedence
// ============================================================================

TEST_CASE("TagStore: sync_agent_tags", "[pg][tag_store]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "criticality", "high", "server"));

    std::unordered_map<std::string, std::string> agent_tags = {{"os.version", "10.0.19045"},
                                                               {"hostname", "WORKSTATION-01"}};
    require_ok(store.sync_agent_tags("agent-1", agent_tags));

    // Server tag remains; agent tags present.
    CHECK(require_ok(store.get_tag("agent-1", "criticality")).value_or("") == "high");
    CHECK(require_ok(store.get_tag("agent-1", "os.version")).value_or("") == "10.0.19045");
    CHECK(require_ok(store.get_tag("agent-1", "hostname")).value_or("") == "WORKSTATION-01");
}

TEST_CASE("TagStore: sync replaces old agent tags", "[pg][tag_store]") {
    TAGS_SHARED(store);

    require_ok(store.sync_agent_tags("agent-1", {{"k1", "v1"}, {"k2", "v2"}}));
    CHECK(require_ok(store.get_tag("agent-1", "k1")).value_or("") == "v1");

    require_ok(store.sync_agent_tags("agent-1", {{"k3", "v3"}}));
    CHECK_FALSE(require_ok(store.get_tag("agent-1", "k1")).has_value());
    CHECK(require_ok(store.get_tag("agent-1", "k3")).value_or("") == "v3");
}

TEST_CASE("TagStore: agent sync cannot clobber an operator tag for the same key (#1411)",
          "[pg][tag_store][security]") {
    TAGS_SHARED(store);

    // Operator declares the benchmark-cohort value for this device.
    require_ok(store.set_tag("agent-1", "model", "executive-laptops", "server"));

    // A rogue/compromised agent reports the SAME key with a different value on
    // its Register sync. Store-first cohort precedence depends on this NOT
    // winning — and the declined write is a clean SUCCESS (precedence no-op),
    // not an error that would roll back the rest of the sync.
    require_ok(store.sync_agent_tags("agent-1", {{"model", "developer-desktops"}}));
    CHECK(require_ok(store.get_tag("agent-1", "model")).value_or("") == "executive-laptops");

    // The cohort accessor must therefore see the operator value.
    auto vals = require_ok(store.get_values_for_key("model"));
    REQUIRE(vals.count("agent-1") == 1);
    CHECK(vals["agent-1"] == "executive-laptops");

    // An agent may still set a brand-new key the operator never declared.
    require_ok(store.sync_agent_tags("agent-1",
                                     {{"model", "developer-desktops"}, {"os.version", "11.0"}}));
    CHECK(require_ok(store.get_tag("agent-1", "model")).value_or("") == "executive-laptops");
    CHECK(require_ok(store.get_tag("agent-1", "os.version")).value_or("") == "11.0");

    // A direct agent-sourced set_tag against the operator row is ALSO a clean
    // precedence no-op (success, row unchanged).
    require_ok(store.set_tag("agent-1", "model", "self-assigned", "agent"));
    CHECK(require_ok(store.get_tag("agent-1", "model")).value_or("") == "executive-laptops");

    // Operator/API writes stay authoritative — a non-'agent' source overwrites
    // an agent row.
    require_ok(store.set_tag("agent-2", "model", "agent-guess", "agent"));
    CHECK(require_ok(store.get_tag("agent-2", "model")).value_or("") == "agent-guess");
    require_ok(store.set_tag("agent-2", "model", "operator-final", "server"));
    CHECK(require_ok(store.get_tag("agent-2", "model")).value_or("") == "operator-final");
}

// ============================================================================
// #3289: sync_agent_tags must never author or move the `service` tag — a
// service-scoped token's confinement boundary — from agent-supplied data.
// ============================================================================

TEST_CASE("TagStore: sync_agent_tags drops the service key but keeps sibling "
          "keys (#3289)",
          "[pg][tag_store][security]") {
    TAGS_SHARED(store);

    require_ok(store.sync_agent_tags(
        "agent-1", {{"service", "printers"}, {"os.version", "11.0"}, {"hostname", "WS-1"}}));

    CHECK_FALSE(require_ok(store.get_tag("agent-1", "service")).has_value());
    CHECK(require_ok(store.get_tag("agent-1", "os.version")).value_or("") == "11.0");
    CHECK(require_ok(store.get_tag("agent-1", "hostname")).value_or("") == "WS-1");
}

TEST_CASE("TagStore: sync_agent_tags bumps a purge counter when it drops an "
          "agent-reported service key (#3289 Gate 5/6 hardening round)",
          "[pg][tag_store][security]") {
    TAGS_SHARED(store);
    yuzu::MetricsRegistry registry;
    store.set_metrics(&registry);

    require_ok(store.sync_agent_tags("agent-1", {{"os.version", "11.0"}})); // no service key
    CHECK(registry.counter("yuzu_server_tag_store_agent_service_purge_total").value() == 0.0);

    require_ok(store.sync_agent_tags("agent-1", {{"service", "printers"}, {"hostname", "WS-1"}}));
    CHECK(registry.counter("yuzu_server_tag_store_agent_service_purge_total").value() == 1.0);

    require_ok(store.sync_agent_tags("agent-2", {{"service", "vending"}}));
    CHECK(registry.counter("yuzu_server_tag_store_agent_service_purge_total").value() == 2.0);
}

TEST_CASE("TagStore: sync_agent_tags with ONLY a service key is a clean "
          "no-insert sync (#3289 tags.json bootstrap path)",
          "[pg][tag_store][security]") {
    TAGS_SHARED(store);

    auto sync = store.sync_agent_tags("agent-1", {{"service", "printers"}});
    REQUIRE(sync.has_value()); // not an error — the key is dropped, not refused

    CHECK_FALSE(require_ok(store.get_tag("agent-1", "service")).has_value());
    CHECK(require_ok(store.get_all_tags("agent-1")).empty());
}

TEST_CASE("TagStore: sync_agent_tags purges a pre-existing agent-sourced "
          "service row (#3289 self-heal — upgrading past a pre-fix agent claim)",
          "[pg][tag_store][security]") {
    TAGS_SHARED(store);

    // Simulate a pre-#3289 agent that already self-claimed a service tag.
    require_ok(store.set_tag("agent-1", "service", "printers", "agent"));
    CHECK(require_ok(store.get_tag("agent-1", "service")).value_or("") == "printers");

    // The agent's next Register sync (no service key survives the filter,
    // but the pre-existing agent-sourced row must still purge via the
    // unconditional agent-source DELETE).
    require_ok(store.sync_agent_tags("agent-1", {{"os.version", "11.0"}}));

    CHECK_FALSE(require_ok(store.get_tag("agent-1", "service")).has_value());
    CHECK(require_ok(store.get_tag("agent-1", "os.version")).value_or("") == "11.0");
}

TEST_CASE("TagStore: sync_agent_tags cannot resurrect service via a case "
          "variation ('Service') (#3289)",
          "[pg][tag_store][security]") {
    TAGS_SHARED(store);

    require_ok(store.sync_agent_tags("agent-1", {{"Service", "printers"}}));
    CHECK_FALSE(require_ok(store.get_tag("agent-1", "Service")).has_value());
    CHECK_FALSE(require_ok(store.get_tag("agent-1", "service")).has_value());
}

TEST_CASE("TagStore: an operator-sourced service row survives an agent sync "
          "carrying a service claim (#1411 + #3289 — belt and braces)",
          "[pg][tag_store][security]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "service", "printers", "server"));
    require_ok(store.sync_agent_tags("agent-1", {{"service", "vending"}, {"os.version", "11.0"}}));

    CHECK(require_ok(store.get_tag("agent-1", "service")).value_or("") == "printers");
    CHECK(require_ok(store.get_tag("agent-1", "os.version")).value_or("") == "11.0");
}

TEST_CASE("TagStore: sync_agent_tags rolls back to the prior set on a mid-sync write failure "
          "(UP-1 / CH-R)",
          "[pg][tag_store][atomicity][security]") {
    // OWN clone (not the shared fixture): this test installs a trigger; the
    // clone is dropped with the trigger still in place, so nothing leaks.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::tag_store_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    TagStore store{pool};
    REQUIRE(store.is_open());

    // Seed the agent's prior COMPLETE set + an operator row for the same device.
    require_ok(store.set_tag("agent-1", "model", "X1", "agent"));
    require_ok(store.set_tag("agent-1", "ring", "fast", "agent"));
    require_ok(store.set_tag("agent-1", "cohort", "ops", "server"));

    // Inject a deterministic mid-sync failure: a trigger that raises on the
    // poisoned value. The sync's DELETE runs, then the poisoned reinsert
    // aborts the transaction → the agent's PRIOR complete tag set must
    // survive (never a partial wipe). Replaces the SQLite original's
    // sqlite3_set_authorizer fault hook.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(),
                          "CREATE FUNCTION tag_store.yuzu_test_fault() RETURNS trigger AS $$ "
                          "BEGIN IF NEW.value = '__fault__' THEN RAISE EXCEPTION "
                          "'injected fault'; END IF; RETURN NEW; END $$ LANGUAGE plpgsql; "
                          "CREATE TRIGGER yuzu_test_fault_trg BEFORE INSERT OR UPDATE ON "
                          "tag_store.tags FOR EACH ROW EXECUTE FUNCTION "
                          "tag_store.yuzu_test_fault()")};
        REQUIRE(r.ok());
    }

    auto sync = store.sync_agent_tags("agent-1", {{"model", "X2"}, {"ring", "__fault__"}});
    REQUIRE_FALSE(sync.has_value());
    CHECK(sync.error().starts_with(kTagDbErrorPrefix));

    // The prior COMPLETE set survived intact — nothing partial committed, the
    // failed sync did not wipe-without-reinsert.
    CHECK(require_ok(store.get_tag("agent-1", "model")).value_or("") == "X1");
    CHECK(require_ok(store.get_tag("agent-1", "ring")).value_or("") == "fast");
    CHECK(require_ok(store.get_tag("agent-1", "cohort")).value_or("") == "ops");

    // Lift the fault: a subsequent clean sync commits normally (the pool
    // connection is not wedged by the aborted transaction).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(),
                          "DROP TRIGGER yuzu_test_fault_trg ON tag_store.tags; "
                          "DROP FUNCTION tag_store.yuzu_test_fault()")};
        REQUIRE(r.ok());
    }
    require_ok(store.sync_agent_tags("agent-1", {{"model", "X3"}}));
    CHECK(require_ok(store.get_tag("agent-1", "model")).value_or("") == "X3");
    CHECK_FALSE(require_ok(store.get_tag("agent-1", "ring")).has_value());
    CHECK(require_ok(store.get_tag("agent-1", "cohort")).value_or("") == "ops");
}

// ============================================================================
// Query surfaces
// ============================================================================

TEST_CASE("TagStore: agents_with_tag", "[pg][tag_store]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "env", "prod"));
    require_ok(store.set_tag("agent-2", "env", "staging"));
    require_ok(store.set_tag("agent-3", "env", "prod"));

    auto agents = require_ok(store.agents_with_tag("env", "prod"));
    REQUIRE(agents.size() == 2);

    auto all_env = require_ok(store.agents_with_tag("env"));
    REQUIRE(all_env.size() == 3);

    // Genuinely no agents tagged with this value: a real, present-but-empty
    // answer — not a degrade.
    auto none = require_ok(store.agents_with_tag("env", "payroll"));
    CHECK(none.empty());
}

TEST_CASE("TagStore: get_values_for_keys bulk-preloads across agents", "[pg][tag_store]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "env", "prod"));
    require_ok(store.set_tag("agent-1", "role", "web"));
    require_ok(store.set_tag("agent-2", "env", "staging"));
    require_ok(store.set_tag("agent-2", "unrelated", "x"));

    auto values = require_ok(store.get_values_for_keys({"env", "role"}));
    REQUIRE(values.size() == 2);
    CHECK(values["agent-1"].at("env") == "prod");
    CHECK(values["agent-1"].at("role") == "web");
    CHECK(values["agent-2"].at("env") == "staging");
    CHECK(values["agent-2"].count("unrelated") == 0); // key-restricted

    // Empty keys: empty map, no query.
    auto empty = require_ok(store.get_values_for_keys({}));
    CHECK(empty.empty());
}

TEST_CASE("TagStore: get_distinct_values", "[pg][tag_store][categories]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "service", "CRM"));
    require_ok(store.set_tag("agent-2", "service", "ERP"));
    require_ok(store.set_tag("agent-3", "service", "CRM"));

    auto values = require_ok(store.get_distinct_values("service"));
    REQUIRE(values.size() == 2);
    CHECK(values[0] == "CRM"); // sorted
    CHECK(values[1] == "ERP");
}

TEST_CASE("TagStore: get_distinct_keys and get_values_for_key", "[pg][tag_store]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "env", "prod"));
    require_ok(store.set_tag("agent-2", "env", "staging"));
    require_ok(store.set_tag("agent-2", "role", "db"));

    auto keys = require_ok(store.get_distinct_keys());
    REQUIRE(keys.size() == 2);
    CHECK(keys[0] == "env"); // sorted
    CHECK(keys[1] == "role");

    auto vals = require_ok(store.get_values_for_key("env"));
    REQUIRE(vals.size() == 2);
    CHECK(vals["agent-1"] == "prod");
    CHECK(vals["agent-2"] == "staging");
}

// ============================================================================
// Tag categories
// ============================================================================

TEST_CASE("TagStore: get_tag_categories returns 4 categories", "[tag_store][categories]") {
    const auto& cats = get_tag_categories();
    REQUIRE(cats.size() == 4);
    CHECK(cats[0].key == "role");
    CHECK(cats[1].key == "environment");
    CHECK(cats[2].key == "location");
    CHECK(cats[3].key == "service");
}

TEST_CASE("TagStore: set_tag_checked accepts valid environment value",
          "[pg][tag_store][categories]") {
    TAGS_SHARED(store);
    require_ok(store.set_tag_checked("agent-1", "environment", "Production"));
    CHECK(require_ok(store.get_tag("agent-1", "environment")).value_or("") == "Production");
}

TEST_CASE("TagStore: set_tag_checked rejects invalid environment value",
          "[pg][tag_store][categories]") {
    TAGS_SHARED(store);
    auto result = store.set_tag_checked("agent-1", "environment", "Staging");
    REQUIRE(!result.has_value());
    CHECK(result.error().find("allowed values") != std::string::npos);
    CHECK_FALSE(result.error().starts_with(kTagDbErrorPrefix)); // caller error, not degrade
    CHECK_FALSE(require_ok(store.get_tag("agent-1", "environment")).has_value());
}

TEST_CASE("TagStore: set_tag_checked allows free-form category", "[pg][tag_store][categories]") {
    TAGS_SHARED(store);
    require_ok(store.set_tag_checked("agent-1", "role", "Web Server"));
    CHECK(require_ok(store.get_tag("agent-1", "role")).value_or("") == "Web Server");
}

TEST_CASE("TagStore: set_tag_checked passes non-category key", "[pg][tag_store][categories]") {
    TAGS_SHARED(store);
    require_ok(store.set_tag_checked("agent-1", "custom-tag", "any value"));
    CHECK(require_ok(store.get_tag("agent-1", "custom-tag")).value_or("") == "any value");
}

TEST_CASE("TagStore: get_compliance_gaps", "[pg][tag_store][categories]") {
    TAGS_SHARED(store);

    // Agent-1 has all 4 categories
    require_ok(store.set_tag("agent-1", "role", "Web Server"));
    require_ok(store.set_tag("agent-1", "environment", "Production"));
    require_ok(store.set_tag("agent-1", "location", "US-East"));
    require_ok(store.set_tag("agent-1", "service", "CRM"));

    // Agent-2 missing environment and service
    require_ok(store.set_tag("agent-2", "role", "Database"));
    require_ok(store.set_tag("agent-2", "location", "EU-West"));

    auto gaps = require_ok(store.get_compliance_gaps());
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].first == "agent-2");
    REQUIRE(gaps[0].second.size() == 2);
    bool has_env = false, has_svc = false;
    for (const auto& k : gaps[0].second) {
        if (k == "environment")
            has_env = true;
        if (k == "service")
            has_svc = true;
    }
    CHECK(has_env);
    CHECK(has_svc);
}

TEST_CASE("TagStore: get_compliance_gaps counts an empty-valued category tag as missing "
          "(pre-migration semantics preserved)",
          "[pg][tag_store][categories]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "role", "")); // present row, empty value
    auto gaps = require_ok(store.get_compliance_gaps());
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].first == "agent-1");
    CHECK(gaps[0].second.size() == 4); // role's empty value counts as missing too
}

// ============================================================================
// Degrade behaviour — typed reads / classified writes (ADR-0036/ADR-0050)
// ============================================================================

TEST_CASE("TagStore: reads and writes degrade loudly once the store is broken",
          "[pg][tag_store][failclosed]") {
    // OWN clone: this test drops the tags table out from under the live
    // store — a reproducible stand-in for a transient connection loss /
    // botched migration (same mechanism as test_props_scope_authz.cpp).
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::tag_store_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    TagStore store{pool};
    REQUIRE(store.is_open());
    require_ok(store.set_tag("agent-1", "service", "billing"));

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE tag_store.tags CASCADE")};
        REQUIRE(r.ok());
    }

    SECTION("typed reads return kDegraded, never an empty success") {
        CHECK_FALSE(store.get_tag("agent-1", "service").has_value());
        CHECK_FALSE(store.get_all_tags("agent-1").has_value());
        CHECK_FALSE(store.get_tag_map("agent-1").has_value());
        CHECK_FALSE(store.agents_with_tag("service", "billing").has_value());
        CHECK_FALSE(store.get_values_for_keys({"service"}).has_value());
        CHECK_FALSE(store.get_compliance_gaps().has_value());
        CHECK_FALSE(store.get_distinct_values("service").has_value());
        CHECK_FALSE(store.get_distinct_keys().has_value());
        CHECK_FALSE(store.get_values_for_key("service").has_value());
        CHECK_FALSE(store.delete_tag("agent-1", "service").has_value());
    }

    SECTION("writes return the db_error prefix (degrade → 503 at the routes)") {
        auto set = store.set_tag("agent-1", "env", "prod");
        REQUIRE_FALSE(set.has_value());
        CHECK(set.error().starts_with(kTagDbErrorPrefix));

        // set_tag_checked PROPAGATES the write failure — the pre-migration
        // contract validated the value, then swallowed the failed write and
        // reported success over nothing written.
        auto checked = store.set_tag_checked("agent-1", "role", "Web");
        REQUIRE_FALSE(checked.has_value());
        CHECK(checked.error().starts_with(kTagDbErrorPrefix));

        auto sync = store.sync_agent_tags("agent-1", {{"k", "v"}});
        REQUIRE_FALSE(sync.has_value());
        CHECK(sync.error().starts_with(kTagDbErrorPrefix));

        auto del_all = store.delete_all_tags("agent-1");
        REQUIRE_FALSE(del_all.has_value());
        CHECK(del_all.error().starts_with(kTagDbErrorPrefix));
    }
}

// ── Gate 7 hardening round: sync bounds + agent_id write guard (perf-F1 /
// UP-2).

TEST_CASE("TagStore: sync_agent_tags refuses an over-cap batch whole, prior set retained",
          "[pg][tag_store][bounds]") {
    TAGS_SHARED(store);

    require_ok(store.set_tag("agent-1", "keep", "v", "agent"));

    std::unordered_map<std::string, std::string> big;
    for (int i = 0; i < 257; ++i) // kMaxSyncTags = 256
        big.emplace("k" + std::to_string(i), "v");
    auto res = store.sync_agent_tags("agent-1", big);
    REQUIRE_FALSE(res.has_value());
    // Caller error (deterministic refusal), NOT a db_error/503.
    CHECK_FALSE(res.error().starts_with(kTagDbErrorPrefix));
    CHECK(res.error().find("too many agent-reported tags") != std::string::npos);
    // Nothing was written or wiped — the refusal happens before the txn.
    CHECK(require_ok(store.get_tag("agent-1", "keep")).value_or("") == "v");
    CHECK(require_ok(store.get_all_tags("agent-1")).size() == 1);

    // Exactly at the cap is accepted (boundary).
    std::unordered_map<std::string, std::string> at_cap;
    for (int i = 0; i < 256; ++i)
        at_cap.emplace("k" + std::to_string(i), "v");
    require_ok(store.sync_agent_tags("agent-1", at_cap));
    CHECK(require_ok(store.get_all_tags("agent-1")).size() == 256);
}

TEST_CASE("TagStore: writes reject an agent_id with an embedded NUL (UP-2 identity guard)",
          "[pg][tag_store][bounds]") {
    TAGS_SHARED(store);

    const std::string nul_id{"agent\0evil", 10};
    auto set = store.set_tag(nul_id, "env", "prod");
    REQUIRE_FALSE(set.has_value());
    CHECK_FALSE(set.error().starts_with(kTagDbErrorPrefix));
    CHECK(set.error().find("invalid agent id") != std::string::npos);

    auto sync = store.sync_agent_tags(nul_id, {{"k", "v"}});
    REQUIRE_FALSE(sync.has_value());
    CHECK(sync.error().find("invalid agent id") != std::string::npos);

    auto del_all = store.delete_all_tags(nul_id);
    REQUIRE_FALSE(del_all.has_value());

    // Guard symmetry (Gate 8 round 2): delete_tag and the point reads answer
    // an invalid id as honest not-found/empty — never a truncated-identity
    // bind. Seed a row under the TRUNCATED id first to prove no leak-through.
    require_ok(store.set_tag("agent", "env", "prod"));
    auto del = store.delete_tag(nul_id, "env");
    REQUIRE(del.has_value());
    CHECK(*del == false); // not-found, and the truncated id's row survives
    CHECK_FALSE(require_ok(store.get_tag(nul_id, "env")).has_value());
    CHECK(require_ok(store.get_all_tags(nul_id)).empty());
    CHECK(require_ok(store.get_tag_map(nul_id)).empty());
    CHECK(require_ok(store.get_tag("agent", "env")).value_or("") == "prod");
    require_ok(store.delete_all_tags("agent"));

    // Nothing landed under the truncated identity libpq would have written.
    CHECK(require_ok(store.get_all_tags("agent")).empty());
}
