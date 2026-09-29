/**
 * test_props_scope_authz.cpp — the ADR-0045 fail-closed contract for
 * `props.<key>` scope-DSL resolution (AgentRegistry::evaluate_scope).
 *
 * Mirrors test_scope_walking_authz.cpp's `from_result_set:` degrade/no-store
 * coverage: this store's migration to Postgres introduced a real runtime
 * failure mode (a pool-acquire timeout, a dropped connection) where SQLite's
 * synchronous read had none, and the pre-migration resolver collapsed
 * "no such property" and "the read failed" to the same empty string —
 * exactly the fail-open shape ADR-0036 closed for from_result_set: atoms.
 * Under `NOT props.<key>` (or `!=`), a silently-empty resolution is a match,
 * so a transient Postgres blip would invert to "every agent matches" — a
 * fleet-wide dispatch/arm reachable without any operator error.
 */

#include "agent_registry.hpp"
#include "custom_properties_store.hpp"
#include "event_bus.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "scope_engine.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include "agent.pb.h"

#include <libpq-fe.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

agent_pb::AgentInfo info(const std::string& id) {
    agent_pb::AgentInfo a;
    a.set_agent_id(id);
    a.set_hostname(id + ".local");
    return a;
}

bool has(const std::vector<std::string>& v, const std::string& id) {
    return std::find(v.begin(), v.end(), id) != v.end();
}

// Shares the "customprops" template key with test_custom_properties_store.cpp
// (identical setup — the registry builds it once, replay-verified).
yuzu::test::PgTestTemplate props_authz_tpl{"customprops", [](const std::string& dsn) {
                                               PgPool pool{{.conninfo = dsn, .size = 1}};
                                               CustomPropertiesStore store{pool};
                                               if (!store.is_open())
                                                   throw std::runtime_error(
                                                       "customprops template: store failed to "
                                                       "migrate");
                                           }};

} // namespace

TEST_CASE("evaluate_scope: props.<key> resolves preloaded values, unaffected when absent",
          "[pg][scope][custom_props][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, props_authz_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    CustomPropertiesStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));
    (void)registry.register_agent(info("agent-lin"));

    REQUIRE(store.set_property("agent-win", "role", "web").has_value());
    REQUIRE(store.set_property("agent-lin", "role", "db").has_value());

    SECTION("matches only the agent with the property value") {
        auto expr = yuzu::scope::parse(R"(props.role == "web")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, /*tag_store=*/nullptr, &store);
        REQUIRE(matched.has_value());
        REQUIRE(matched->size() == 1);
        CHECK(has(*matched, "agent-win"));
        CHECK_FALSE(has(*matched, "agent-lin"));
    }

    SECTION("a scope with no props.<key> atom is unaffected by a null props_store") {
        auto expr = yuzu::scope::parse(R"(ostype == "")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, /*props_store=*/nullptr);
        REQUIRE(matched.has_value()); // no preload triggered — no abort
    }
}

// The concrete vulnerability this guards: a `NOT props.<key>` scope resolves
// the atom to "" (no match) for every agent whose property couldn't be read
// because of a transient Postgres error, and NOT inverts "no match" to
// "match" — so a degraded preload used to make every connected agent match.
// `evaluate_scope` must instead return `std::nullopt` the instant the
// preload can't be trusted, so the caller aborts rather than dispatching to
// "everyone" (mirrors test_scope_walking_authz.cpp's identical from_result_set:
// coverage).
TEST_CASE("evaluate_scope: a degraded CustomPropertiesStore ABORTS — never expands a "
          "NOT-inverted props.<key> scope to the whole fleet",
          "[pg][scope][custom_props][authz][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, props_authz_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    CustomPropertiesStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));
    (void)registry.register_agent(info("agent-lin"));

    REQUIRE(store.set_property("agent-win", "role", "web").has_value());

    // Simulate a Postgres-side degrade: drop the table get_values_for_keys
    // queries out from under the live store — a reproducible stand-in for a
    // transient connection loss / botched migration, without killing the
    // whole pool (which would also fail is_open()-style checks upstream and
    // hide the specific regression this test targets: a QUERY failure once
    // the store believes it is open).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE custom_properties_store.custom_properties CASCADE")};
        REQUIRE(r.ok());
    }

    SECTION("NOT props.<key> aborts rather than matching every agent") {
        auto expr = yuzu::scope::parse(R"(NOT props.role == "web")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, &store);
        // The regression this test exists to catch: pre-fix, a degraded read
        // silently resolved "" for every agent, so `matched` would come back
        // holding EVERY registered agent under the NOT combinator. Post-fix,
        // degrade is type-distinguishable — std::nullopt.
        REQUIRE_FALSE(matched.has_value());
    }

    SECTION("the plain (non-NOT) form also aborts, never a false empty match") {
        auto expr = yuzu::scope::parse(R"(props.role == "web")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, &store);
        REQUIRE_FALSE(matched.has_value());
    }
}

TEST_CASE("evaluate_scope: props.<key> atom with no CustomPropertiesStore ABORTS",
          "[scope][custom_props][authz][failclosed]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));

    auto expr = yuzu::scope::parse(R"(NOT props.role == "web")");
    REQUIRE(expr.has_value());
    // No store wired at all — the atom cannot be resolved AT ALL here.
    // Pre-fix this silently resolved false (empty), which NOT inverted to
    // match-all; post-fix it aborts.
    auto matched = registry.evaluate_scope(*expr, nullptr, /*props_store=*/nullptr);
    REQUIRE_FALSE(matched.has_value());
}
