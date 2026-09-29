/**
 * test_discovery_routes.cpp — HTTP-level coverage for the A2 discovery
 * surface, the `GET /api/v1/discover/` family (roadmap Issue 17.1,
 * docs/agentic-first-principle.md §A2).
 *
 * Pattern matches test_rest_guaranteed_state.cpp: register DiscoverRoutes
 * against an in-process TestRouteSink and dispatch synthesised
 * httplib::Request objects through the captured handlers. No real HTTP
 * server, no acceptor thread, no #438 TSan trap.
 *
 * Coverage:
 *   - shape + ETag/Cache-Control/304 revalidation for all five endpoints
 *   - null-store / null-registry 503 degrade for the three store-backed
 *     endpoints (permissions, instructions, plugins) — scope-kinds and
 *     routes are compiled-in and answer regardless
 *   - a CROSS-CHECK that binds the scope-kinds catalog to the
 *     AgentRegistry::evaluate_scope resolver it documents, and to the
 *     yuzu::scope::CompOp enum operator_token() exposes
 *
 * NOT covered here: the mirrored MCP discover_* tools (test_mcp_server.cpp
 * carries those — same builder functions, so this file is the primary
 * shape/behavior authority and the MCP tests mostly assert wiring).
 */

#include "agent_registry.hpp"
#include "discover_routes.hpp"
#include "event_bus.hpp"
#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "scope_engine.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "agent.pb.h"

#include <algorithm>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
namespace agent_pb = ::yuzu::agent::v1;

namespace {
// Pre-migrated template for RbacStore (PG port). Shares the "rbacstore" key
// with test_rbac_store.cpp's own template (identical setup, replay-verified
// — docs/postgres-store-playbook.md step 7). DiscoverHarness just needs an
// OPEN RbacStore to wire into DiscoverRoutes; no RBAC behavior exercised.
yuzu::test::PgTestTemplate discovery_rbac_tpl{
    "rbacstore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        yuzu::server::RbacStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("rbac template: store failed to migrate/seed");
    }};

// ── Harness ─────────────────────────────────────────────────────────────────

struct DiscoverHarness {
    yuzu::server::test::TestRouteSink sink;

    std::optional<yuzu::test::PostgresTestDb> rbac_db;
    std::optional<yuzu::server::pg::PgPool> rbac_pool;
    std::unique_ptr<RbacStore> rbac;
    std::unique_ptr<InstructionStore> instr;

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};

    bool grant_perms{true};
    /// Per-(securable, operation) denial, for routes that probe a SECOND
    /// permission beyond their own gate. Returning false denies just that pair
    /// and leaves the route's own gate intact — `grant_perms` is all-or-nothing
    /// and cannot express that. Mirrors McpTestServer::perm_override_for_test.
    std::function<bool(const std::string&, const std::string&)> perm_override{};
    std::string last_securable_type, last_operation;
    /// The route's OWN gate, i.e. the first permission it checks. A route that
    /// PROBES a second permission (#2376: /discover/permissions probes
    /// UserManagement:Read for the role grid) would otherwise leave only the
    /// probe in last_*, and a test asserting "this route is gated on X" would
    /// silently start asserting the probe instead.
    std::string first_securable_type, first_operation;

    DiscoverRoutes routes;

    // wire_rbac / wire_instr / wire_registry = false registers the route with a
    // null store/registry pointer, exercising the 503 degrade branch.
    explicit DiscoverHarness(bool wire_rbac = true, bool wire_instr = true,
                             bool wire_registry = true, bool grant_instr_read = false) {
        // Manual equivalent of YUZU_REQUIRE_PG_DB_TPL (test_helpers.hpp) — the
        // macro declares a local, non-movable PostgresTestDb, so it can't be
        // used directly to populate a data member; emplace() constructs
        // rbac_db/rbac_pool in place instead.
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        rbac_db.emplace(discovery_rbac_tpl);
        INFO("[DiscoverHarness rbac fixture] status (blank == came up OK): " << rbac_db->error());
        REQUIRE(rbac_db->available());
        rbac_pool.emplace(
            yuzu::server::pg::PgPool::Options{.conninfo = rbac_db->dsn(), .size = 4});
        REQUIRE(rbac_pool->valid());
        rbac = std::make_unique<RbacStore>(*rbac_pool);
        REQUIRE(rbac->is_open());
        // ADR-0058: InstructionStore is now a migrated Postgres store — shares
        // the same pool/database as RbacStore above (schema-per-store, ADR-0008).
        instr = std::make_unique<InstructionStore>(*rbac_pool);
        REQUIRE(instr->is_open());

        // The /discover/plugins parameter_schema enrichment is gated on the
        // caller's InstructionDefinition:Read grant (security-guardian MEDIUM).
        // Grant the synthetic "tester" principal that right (via the seeded
        // Administrator role) only when a test opts in; default OFF so unrelated
        // tests exercise the name+description (no-enrichment) path.
        if (grant_instr_read)
            (void)rbac->assign_role(PrincipalRole{"user", "tester", "Administrator"});

        // Resolves the caller for the enrichment gate. Never denies (the real
        // AuthFn writes to res on failure; here it always yields "tester").
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            return s;
        };

        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            if (first_securable_type.empty()) {
                first_securable_type = type;
                first_operation = op;
            }
            last_securable_type = type;
            last_operation = op;
            if (perm_override && !perm_override(type, op)) {
                res.status = 403;
                return false;
            }
            if (grant_perms)
                return true;
            res.status = 403;
            return false;
        };
        routes.register_routes(sink, auth_fn, perm_fn, wire_rbac ? rbac.get() : nullptr,
                               wire_instr ? instr.get() : nullptr,
                               wire_registry ? &registry : nullptr);
    }
};

agent_pb::AgentInfo make_agent_info(const std::string& id, const std::string& os,
                                    const std::string& hostname) {
    agent_pb::AgentInfo a;
    a.set_agent_id(id);
    a.set_hostname(hostname);
    a.mutable_platform()->set_os(os);
    a.mutable_platform()->set_arch("x86_64");
    a.set_agent_version("0.13.0");
    return a;
}

InstructionDefinition make_def(const std::string& name, bool enabled,
                               const std::string& parameter_schema = "") {
    InstructionDefinition def;
    def.name = name;
    def.version = "1.0";
    def.plugin = "system_info";
    def.action = "query";
    def.type = "question";
    def.description = "Test definition: " + name;
    def.enabled = enabled;
    def.platforms = "windows,linux,darwin";
    def.approval_mode = "auto";
    def.parameter_schema = parameter_schema;
    return def;
}

} // namespace

// ── /discover/permissions ────────────────────────────────────────────────────

TEST_CASE("discover.permissions: shape + ETag revalidation", "[discovery][permissions][pg]") {
    DiscoverHarness h;
    auto res = h.sink.Get("/api/v1/discover/permissions");
    REQUIRE(res);
    CHECK(res->status == 200);
    // `private`, not `public`, since #2376: this route's body varies with the
    // caller's UserManagement:Read (the role grid), so a shared cache must never
    // store one caller's representation and serve it to another. The dedicated
    // cache-boundary test below covers both representations; this line is kept
    // here so the shape test cannot silently drift back to `public`.
    CHECK(res->get_header_value("Cache-Control") == "private, max-age=300");
    const std::string etag = res->get_header_value("ETag");
    CHECK_FALSE(etag.empty());

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("securable_types"));
    REQUIRE(j.contains("operations"));
    REQUIRE(j.contains("roles"));
    CHECK(j["securable_types"].is_array());
    CHECK_FALSE(j["securable_types"].empty());
    CHECK(j["operations"].is_array());
    CHECK_FALSE(j["operations"].empty());
    CHECK(j["roles"].is_array());
    CHECK_FALSE(j["roles"].empty());
    // Every role row carries name + a permissions sub-array of
    // {securable_type, operation, effect} triples.
    for (const auto& r : j["roles"]) {
        REQUIRE(r.contains("name"));
        REQUIRE(r.contains("permissions"));
        CHECK(r["permissions"].is_array());
        if (!r["permissions"].empty()) {
            const auto& p = r["permissions"][0];
            CHECK(p.contains("securable_type"));
            CHECK(p.contains("operation"));
            CHECK(p.contains("effect"));
        }
    }

    // Gated on Infrastructure:Read — the route's OWN gate, which is the FIRST
    // permission checked. Since #2376 the handler then PROBES UserManagement:Read
    // to decide whether the role grid is included, so last_* holds the probe.
    CHECK(h.first_securable_type == "Infrastructure");
    CHECK(h.first_operation == "Read");
    CHECK(h.last_securable_type == "UserManagement"); // the grid probe ran
    CHECK(h.last_operation == "Read");
    CHECK(h.last_operation == "Read");

    auto cached = h.sink.Get("/api/v1/discover/permissions", {{"If-None-Match", etag}});
    REQUIRE(cached);
    CHECK(cached->status == 304);
}

// #2376 — the floor bypass this split closes, REST side (the MCP twin has the
// mirror of this test). /discover/permissions is gated Infrastructure:Read, which
// is NOT in the topology floor and which every authenticated session holds on an
// RBAC-off install via the legacy Read-allow. Before the split it served the
// complete role -> permission grid to a caller the floor had just refused at
// /rbac/roles — a strictly LARGER disclosure than the floored route, reached
// through an alternate transport. This is the same shape as the
// discover.plugins enrichment gate below: probe a second permission, withhold
// the richer half, keep the route itself working.
TEST_CASE("discover.permissions: role grid withheld when caller lacks UserManagement:Read",
          "[discovery][permissions][floor][pg]") {
    DiscoverHarness h;
    h.perm_override = [](const std::string& securable, const std::string& op) {
        return !(securable == "UserManagement" && op == "Read");
    };

    auto res = h.sink.Get("/api/v1/discover/permissions");
    REQUIRE(res);
    // The ROUTE still succeeds on its own Infrastructure:Read gate...
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    // ...the grid is gone — the assertion that closes the bypass...
    CHECK_FALSE(j.contains("roles"));
    // ...its absence is declared, so a caller cannot read it as "no roles exist"...
    CHECK(j.value("roles_omitted", false));
    CHECK_FALSE(j.value("roles_omitted_reason", std::string{}).empty());
    // ...and the taxonomy an agentic worker needs for A2 discovery survives.
    CHECK_FALSE(j["securable_types"].empty());
    CHECK_FALSE(j["operations"].empty());
}

TEST_CASE("discover.permissions: role grid PRESENT for a UserManagement:Read holder",
          "[discovery][permissions][floor][pg]") {
    DiscoverHarness h; // default perm_fn grants everything
    auto res = h.sink.Get("/api/v1/discover/permissions");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j.contains("roles"));
    CHECK_FALSE(j["roles"].empty());
    CHECK_FALSE(j.value("roles_omitted", false));
}

// #2376 / adversarial-review CDX-P2-002 — the cache half of the same bypass.
// Splitting the catalogue made this route serve TWO representations under ONE
// URL, chosen by the caller's UserManagement:Read. Left marked
// `Cache-Control: public`, a shared cache may store the privileged
// representation and hand the role grid to an unprivileged caller — walking the
// protected half across the boundary the probe just enforced. The handler
// returns the right body to each caller either way, so no per-caller assertion
// catches this; only the header does.
TEST_CASE("discover.permissions: permission-varying representation is never shareable",
          "[discovery][permissions][floor][cache][pg]") {
    SECTION("with the grid") {
        DiscoverHarness h;
        auto res = h.sink.Get("/api/v1/discover/permissions");
        REQUIRE(res);
        CHECK(res->get_header_value("Cache-Control") == "private, max-age=300");
        CHECK(res->get_header_value("Vary") == "Authorization, Cookie, X-Yuzu-Token");
    }
    SECTION("without the grid — same URL, different body, still unshareable") {
        DiscoverHarness h;
        h.perm_override = [](const std::string& sec, const std::string& op) {
            return !(sec == "UserManagement" && op == "Read");
        };
        auto res = h.sink.Get("/api/v1/discover/permissions");
        REQUIRE(res);
        CHECK(res->get_header_value("Cache-Control") == "private, max-age=300");
    }
}

// Pre-existing instance of the same class: /discover/plugins has varied by the
// caller's InstructionDefinition:Read since the enrichment gate landed, and was
// publicly cacheable while doing so.
TEST_CASE("discover.plugins: enrichment-varying representation is never shareable",
          "[discovery][plugins][cache][pg]") {
    DiscoverHarness h(/*wire_rbac=*/true, /*wire_instr=*/true, /*wire_registry=*/true,
                      /*grant_instr_read=*/true);
    auto res = h.sink.Get("/api/v1/discover/plugins");
    REQUIRE(res);
    CHECK(res->get_header_value("Cache-Control") == "private, max-age=300");
    CHECK(res->get_header_value("Vary") == "Authorization, Cookie, X-Yuzu-Token");
}

// The caller-independent catalogues stay shareable — the fix must be narrow, or
// it silently drops caching for the three routes that never varied.
TEST_CASE("discover: caller-independent catalogues remain publicly cacheable",
          "[discovery][cache][pg]") {
    DiscoverHarness h;
    for (const char* path : {"/api/v1/discover/instructions", "/api/v1/discover/routes",
                             "/api/v1/discover/scope-kinds"}) {
        INFO("path " << path);
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->get_header_value("Cache-Control") == "public, max-age=300");
    }
}

TEST_CASE("discover.permissions: null RbacStore -> 503", "[discovery][permissions][pg]") {
    DiscoverHarness h(/*wire_rbac=*/false);
    auto res = h.sink.Get("/api/v1/discover/permissions");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("discover.permissions: permission denied -> 403, no body leak",
          "[discovery][permissions][pg]") {
    DiscoverHarness h;
    h.grant_perms = false;
    auto res = h.sink.Get("/api/v1/discover/permissions");
    REQUIRE(res);
    CHECK(res->status == 403);
}

// ── /discover/instructions ───────────────────────────────────────────────────

TEST_CASE("discover.instructions: enabled-only subset with parsed parameter_schema",
          "[discovery][instructions][pg]") {
    DiscoverHarness h;
    auto enabled_id =
        h.instr->create_definition(make_def(
            "Get Hostname", /*enabled=*/true,
            R"({"type":"object","properties":{"path":{"type":"string"}}})"));
    REQUIRE(enabled_id.has_value());
    auto disabled_id = h.instr->create_definition(make_def("Retired Check", /*enabled=*/false));
    REQUIRE(disabled_id.has_value());
    // No parameter_schema authored -> store defaults to "{}" (see below).
    auto no_schema_id = h.instr->create_definition(make_def("No Schema", /*enabled=*/true));
    REQUIRE(no_schema_id.has_value());

    auto res = h.sink.Get("/api/v1/discover/instructions");
    REQUIRE(res);
    CHECK(res->status == 200);
    const std::string etag = res->get_header_value("ETag");
    CHECK_FALSE(etag.empty());

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("instructions"));
    const auto& arr = j["instructions"];
    CHECK(arr.is_array());

    bool saw_enabled = false, saw_disabled = false, saw_no_schema = false;
    for (const auto& d : arr) {
        REQUIRE(d.contains("id"));
        REQUIRE(d.contains("name"));
        REQUIRE(d.contains("plugin"));
        REQUIRE(d.contains("action"));
        REQUIRE(d.contains("parameter_schema"));
        REQUIRE(d.contains("platforms"));
        REQUIRE(d.contains("approval_mode"));
        if (d["id"] == *enabled_id) {
            saw_enabled = true;
            CHECK(d["parameter_schema"].is_object());
            CHECK(d["parameter_schema"]["type"] == "object");
        }
        if (d["id"] == *disabled_id)
            saw_disabled = true;
        if (d["id"] == *no_schema_id) {
            saw_no_schema = true;
            // InstructionStore::create_definition defaults an empty
            // parameter_schema to the literal "{}" (instruction_store.cpp),
            // so a definition authored with none round-trips as an empty
            // OBJECT, not null. null covers a stored value that fails to
            // parse as JSON at all, OR one that parses but isn't an object
            // (array/string/number/bool) — the latter IS reachable via
            // create/update/import (no object-shape validation on write),
            // see the "non-object parameter_schema nulls out" test below.
            CHECK(d["parameter_schema"].is_object());
            CHECK(d["parameter_schema"].empty());
        }
    }
    CHECK(saw_enabled);
    CHECK_FALSE(saw_disabled); // enabled_only=true — "published" excludes disabled
    CHECK(saw_no_schema);

    CHECK(h.last_securable_type == "InstructionDefinition");
    CHECK(h.last_operation == "Read");

    auto cached = h.sink.Get("/api/v1/discover/instructions", {{"If-None-Match", etag}});
    REQUIRE(cached);
    CHECK(cached->status == 304);
}

// Adversarial review of #2986 (2026-08-19): create/update/import bind a
// caller-supplied parameter_schema as text with no object-shape validation,
// so a non-object JSON value is reachable — the discover_instructions
// outputSchema advertises parameter_schema as object|null only, so a stored
// array/string/number/bool must null out, not forward raw. Mirrors
// discover.plugins' existing is_object() guard (UP-9).
TEST_CASE("discover.instructions: non-object parameter_schema nulls out, matching the "
          "advertised object|null outputSchema",
          "[discovery][instructions][pg]") {
    DiscoverHarness h;
    auto array_id = h.instr->create_definition(
        make_def("Array Schema", /*enabled=*/true, "[1,2,3]"));
    REQUIRE(array_id.has_value());
    auto bool_id = h.instr->create_definition(make_def("Bool Schema", /*enabled=*/true, "true"));
    REQUIRE(bool_id.has_value());
    auto string_id =
        h.instr->create_definition(make_def("String Schema", /*enabled=*/true, R"("not-a-schema")"));
    REQUIRE(string_id.has_value());

    auto res = h.sink.Get("/api/v1/discover/instructions");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    const auto& arr = j["instructions"];

    bool saw_array = false, saw_bool = false, saw_string = false;
    for (const auto& d : arr) {
        if (d["id"] == *array_id) {
            saw_array = true;
            CHECK(d["parameter_schema"].is_null());
        }
        if (d["id"] == *bool_id) {
            saw_bool = true;
            CHECK(d["parameter_schema"].is_null());
        }
        if (d["id"] == *string_id) {
            saw_string = true;
            CHECK(d["parameter_schema"].is_null());
        }
    }
    CHECK(saw_array);
    CHECK(saw_bool);
    CHECK(saw_string);
}

// json-dump-depth-guard fix (#2437-class): parameter_schema is stored
// VERBATIM at write time. instruction_store.cpp's own import-path write-side
// guard rejects a too-deep value from now on, but a row written before that
// guard shipped, or via any path that bypasses import, still reaches this
// read - build_discovery_doc's body.dump() below is the unboundedly
// recursive call that would SIGSEGV the whole response. Seeded directly via
// InstructionStore::create_definition (bypassing the now-guarded import
// route), matching this branch's established "seed the poisoned state
// directly to prove the read-side guard independently" pattern. The poisoned
// text is an OBJECT at the top level ({"a": 35-deep bracket chain}), not a
// bare array - both build_instructions_catalog and build_plugins_catalog
// below only act on a value that separately passes an existing is_object()
// filter, so an array-shaped payload would be excluded by that filter alone
// and prove nothing about the depth guard specifically. 35 levels is
// comfortably past kMcpMaxJsonDepth (32) and trivially safe to construct
// here, orders of magnitude short of the ~100,000-level depth that actually
// crashes the real dump().
TEST_CASE("discover.instructions: parameter_schema nesting too deep excludes just that "
          "definition, others unaffected (#2437-class)",
          "[discovery][instructions][depth][pg]") {
    DiscoverHarness h;
    const std::string deep = R"({"a":)" + std::string(35, '[') + std::string(35, ']') + "}";
    auto poisoned_id = h.instr->create_definition(make_def("Poisoned", /*enabled=*/true, deep));
    REQUIRE(poisoned_id.has_value());
    auto healthy_id = h.instr->create_definition(
        make_def("Healthy", /*enabled=*/true, R"({"type":"object"})"));
    REQUIRE(healthy_id.has_value());

    auto res = h.sink.Get("/api/v1/discover/instructions");
    REQUIRE(res); // no crash
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    const auto& arr = j["instructions"];
    bool saw_poisoned = false, saw_healthy = false;
    for (const auto& d : arr) {
        if (d["id"] == *poisoned_id)
            saw_poisoned = true;
        if (d["id"] == *healthy_id) {
            saw_healthy = true;
            CHECK(d["parameter_schema"]["type"] == "object");
        }
    }
    CHECK_FALSE(saw_poisoned); // excluded, never dumped
    CHECK(saw_healthy);        // other definitions in the same response unaffected
}

// Same hazard, the build_plugins_catalog enrichment join: a too-deep stored
// parameter_schema would otherwise be spliced into an action's entry and
// crash on THIS catalog's own dump(). Two distinct plugin/action pairs so the
// exclusion is provably scoped to the poisoned one.
TEST_CASE("discover.plugins: parameter_schema nesting too deep skips enrichment for just "
          "that action, other actions unaffected (#2437-class)",
          "[discovery][plugins][depth][pg]") {
    DiscoverHarness h(/*wire_rbac=*/true, /*wire_instr=*/true, /*wire_registry=*/true,
                      /*grant_instr_read=*/true);
    // Object-shaped (see the comment on the sibling test above) - an
    // array-shaped payload would already fail this function's own
    // is_object() filter and never reach schema_by_action either way,
    // proving nothing about the depth guard.
    const std::string deep = R"({"a":)" + std::string(35, '[') + std::string(35, ']') + "}";
    // Matches make_def's default plugin/action (system_info/query).
    auto poisoned_id = h.instr->create_definition(make_def("Poisoned Query", /*enabled=*/true, deep));
    REQUIRE(poisoned_id.has_value());
    auto healthy_def =
        make_def("Healthy List", /*enabled=*/true, R"({"type":"object"})");
    healthy_def.plugin = "processes";
    healthy_def.action = "list";
    REQUIRE(h.instr->create_definition(healthy_def).has_value());

    auto info = make_agent_info("agent-1", "windows", "WIN-TESTBOX");
    auto* p1 = info.add_plugins();
    p1->set_name("system_info");
    p1->add_capabilities("query");
    auto* p2 = info.add_plugins();
    p2->set_name("processes");
    p2->add_capabilities("list");
    (void)h.registry.register_agent(info);

    auto res = h.sink.Get("/api/v1/discover/plugins");
    REQUIRE(res); // no crash
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    CHECK(j["actions_enriched_with_schema"].get<int>() == 1); // only the healthy action
    bool checked_system_info = false, checked_processes = false;
    for (const auto& pl : j["plugins"]) {
        if (pl["name"] == "system_info") {
            for (const auto& a : pl["actions"]) {
                if (a["name"] == "query") {
                    checked_system_info = true;
                    CHECK_FALSE(a.contains("parameter_schema")); // excluded, never dumped
                }
            }
        }
        if (pl["name"] == "processes") {
            for (const auto& a : pl["actions"]) {
                if (a["name"] == "list") {
                    checked_processes = true;
                    REQUIRE(a.contains("parameter_schema"));
                    CHECK(a["parameter_schema"]["type"] == "object");
                }
            }
        }
    }
    CHECK(checked_system_info);
    CHECK(checked_processes);
}

TEST_CASE("discover.instructions: null InstructionStore -> 503",
          "[discovery][instructions][pg]") {
    DiscoverHarness h(/*wire_rbac=*/true, /*wire_instr=*/false);
    auto res = h.sink.Get("/api/v1/discover/instructions");
    REQUIRE(res);
    CHECK(res->status == 503);
}

// ── /discover/routes ─────────────────────────────────────────────────────────

TEST_CASE("discover.routes: subsets the OpenAPI document, honesty fields present",
          "[discovery][routes][pg]") {
    DiscoverHarness h;
    auto res = h.sink.Get("/api/v1/discover/routes");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(res->get_header_value("ETag").empty());

    auto j = nlohmann::json::parse(res->body);
    CHECK(j.value("source", "") == "openapi");
    REQUIRE(j.contains("caveat"));
    CHECK_FALSE(j["caveat"].get<std::string>().empty());
    REQUIRE(j.contains("routes"));
    CHECK(j["routes"].is_array());
    CHECK_FALSE(j["routes"].empty());

    // Dogfood: the catalog must include its OWN five sibling routes (added to
    // openapi_spec() alongside this route) — proves the openapi_spec_json()
    // wiring reaches the SAME document GET /api/v1/openapi.json serves.
    bool saw_self = false;
    for (const auto& r : j["routes"]) {
        REQUIRE(r.contains("method"));
        REQUIRE(r.contains("path"));
        REQUIRE(r.contains("summary"));
        REQUIRE(r.contains("tags"));
        if (r["path"] == "/api/v1/discover/routes" && r["method"] == "GET")
            saw_self = true;
    }
    CHECK(saw_self);

    CHECK(h.last_securable_type == "Infrastructure");
}

// ── /discover/scope-kinds ────────────────────────────────────────────────────

TEST_CASE("discover.scope-kinds: static catalog shape", "[discovery][scope_kinds][pg]") {
    DiscoverHarness h;
    auto res = h.sink.Get("/api/v1/discover/scope-kinds");
    REQUIRE(res);
    CHECK(res->status == 200);
    const std::string etag = res->get_header_value("ETag");
    CHECK_FALSE(etag.empty());

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("ground_kinds"));
    REQUIRE(j.contains("attribute_kinds"));
    REQUIRE(j.contains("operators"));
    REQUIRE(j.contains("extended_forms"));
    REQUIRE(j.contains("combinators"));

    std::vector<std::string> ground_kinds;
    for (const auto& k : j["ground_kinds"])
        ground_kinds.push_back(k["kind"].get<std::string>());
    CHECK(std::find(ground_kinds.begin(), ground_kinds.end(), "__all__") != ground_kinds.end());
    CHECK(std::find(ground_kinds.begin(), ground_kinds.end(), "group:<name>") !=
          ground_kinds.end());

    // attribute_kinds mirrors scope_kind_catalog() 1:1.
    CHECK(j["attribute_kinds"].size() == yuzu::server::detail::scope_kind_catalog().size());

    // Every CompOp value published, each carrying a non-empty token.
    CHECK(j["operators"].size() == yuzu::scope::kCompOpCount);
    for (const auto& op : j["operators"])
        CHECK_FALSE(op["token"].get<std::string>().empty());

    CHECK(j["combinators"] == nlohmann::json::array({"AND", "OR", "NOT"}));

    // No store dependency — answers 200 even with everything unwired.
    DiscoverHarness bare(/*wire_rbac=*/false, /*wire_instr=*/false, /*wire_registry=*/false);
    auto bare_res = bare.sink.Get("/api/v1/discover/scope-kinds");
    REQUIRE(bare_res);
    CHECK(bare_res->status == 200);

    auto cached = h.sink.Get("/api/v1/discover/scope-kinds", {{"If-None-Match", etag}});
    REQUIRE(cached);
    CHECK(cached->status == 304);
}

// CROSS-CHECK #1: every entry in scope_kind_catalog() (agent_registry.hpp,
// colocated with the evaluate_scope resolver it documents) is honored by the
// resolver — proves the enumerator is a SUBSET of what the resolver actually
// answers. This does NOT prove the converse (a resolver branch added without a
// matching catalog entry stays invisible to this test) — see the DRIFT
// CONTRACT comment on the resolver lambda in agent_registry.cpp, which is the
// human-inspection half of this guarantee.
TEST_CASE("CROSS-CHECK: scope_kind_catalog entries are honored by evaluate_scope resolver",
          "[discovery][scope_kinds][crosscheck]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    auto info = make_agent_info("agent-1", "windows", "WIN-TESTBOX");
    (*info.mutable_scopable_tags())["department"] = "finance";
    (void)registry.register_agent(info);

    // tag:department and props.owner need their respective stores; both are
    // optional (nullptr) parameters to evaluate_scope, so kinds backed solely
    // by a store (props.<key>) are only reachable via in-memory scopable_tags
    // for tag:<key> here — props.<key> without a store always resolves empty,
    // which this loop treats as "no match" and skips (documented below).
    for (const auto& k : yuzu::server::detail::scope_kind_catalog()) {
        if (k.kind == "props.<key>")
            continue; // needs a live CustomPropertiesStore — covered by
                      // dedicated props tests elsewhere, not this catalog check.

        std::string expr;
        if (k.kind == "from_result_set:<id>") {
            // Bare atom, no operator/value (scope_engine.cpp parse_expression:
            // `from_result_set:<id>` short-circuits to an implicit EXISTS
            // condition — `from_result_set:<id> == <value>` is a parse error).
            // No ResultSetStore wired here (authz semantics belong to
            // test_scope_walking_authz.cpp) — assert the kind is RECOGNISED by
            // the resolver rather than throwing/crashing the parser.
            expr = "from_result_set:rs_nonexistent";
            auto parsed = yuzu::scope::parse(expr);
            REQUIRE(parsed.has_value());
            // H1 (governance 2026-07-29): with no store to owner-resolve
            // against, the resolver ABORTS (nullopt) — it never reports "no
            // match". Reporting "no match" is the fail-open shape H1 closed: a
            // `NOT from_result_set:<id>` atom would invert it into a
            // fleet-wide match. See the `evaluate_scope` contract in
            // agent_registry.hpp (abort case 3).
            //
            // This is a STRONGER cross-check than the unknown-kind arm below:
            // a kind the resolver did NOT recognise falls through to the
            // generic attribute path and yields a populated-but-empty vector,
            // so only a recognised from_result_set: atom can produce nullopt.
            auto matched = registry.evaluate_scope(*parsed, nullptr);
            CHECK_FALSE(matched.has_value());
            continue;
        }
        if (k.kind == "ostype")
            expr = R"(ostype == "windows")";
        else if (k.kind == "hostname")
            expr = R"(hostname == "WIN-TESTBOX")";
        else if (k.kind == "arch")
            expr = R"(arch == "x86_64")";
        else if (k.kind == "agent_version")
            expr = R"(agent_version == "0.13.0")";
        else if (k.kind == "tag:<key>")
            expr = R"(tag:department == "finance")";
        else
            FAIL(std::string("scope_kind_catalog entry '") + k.kind +
                 "' has no cross-check case — add one above alongside the new resolver branch");

        auto parsed = yuzu::scope::parse(expr);
        REQUIRE(parsed.has_value());
        auto matched = registry.evaluate_scope(*parsed, nullptr);
        REQUIRE(matched.has_value());
        CHECK(std::find(matched->begin(), matched->end(), "agent-1") != matched->end());
    }

    // A made-up kind the resolver has never heard of must resolve to no match
    // (proves the resolver doesn't silently accept everything as a wildcard).
    auto bogus = yuzu::scope::parse(R"(totally_bogus_kind == "x")");
    REQUIRE(bogus.has_value());
    auto bogus_matched = registry.evaluate_scope(*bogus, nullptr);
    REQUIRE(bogus_matched.has_value());
    CHECK(bogus_matched->empty());
}

// CROSS-CHECK #2: yuzu::scope::operator_token's switch (scope_engine.cpp) has
// NO default case — adding a CompOp value without a case there is a build-log
// -Wswitch signal. This test is the runtime half: it asserts comp_op_catalog()
// (discover_routes.hpp, the array the /discover/scope-kinds "operators" array
// is built from) covers exactly the 11 currently-declared CompOp values and
// that operator_token() answers every one of them. Bump the literal 11 (here
// AND in discover_routes.hpp's std::array<CompOpEntry, 11>) when CompOp grows.
TEST_CASE("CROSS-CHECK: comp_op_catalog covers every CompOp value (G9-style drift guard)",
          "[discovery][scope_kinds][crosscheck]") {
    const auto& catalog = yuzu::server::comp_op_catalog();
    // Bound to the enum's single-source count, not a hardcoded literal — the
    // catalog array is sized by kCompOpCount, so this also proves the two agree
    // (governance arch-SHOULD-4 / cpp-expert: the -Wswitch signal is not portable).
    CHECK(catalog.size() == yuzu::scope::kCompOpCount);
    std::vector<std::string> tokens;
    for (const auto& e : catalog) {
        auto tok = yuzu::scope::operator_token(e.op);
        CHECK_FALSE(tok.empty());
        tokens.emplace_back(tok);
    }
    // Every token distinct (Eq/Neq/Like/... map to unique wire tokens).
    std::sort(tokens.begin(), tokens.end());
    CHECK(std::adjacent_find(tokens.begin(), tokens.end()) == tokens.end());
}

// ── /discover/plugins ────────────────────────────────────────────────────────

TEST_CASE("discover.plugins: wraps AgentRegistry::help_json with a limitation note",
          "[discovery][plugins][pg]") {
    DiscoverHarness h;
    auto info = make_agent_info("agent-1", "windows", "WIN-TESTBOX");
    auto* p = info.add_plugins();
    p->set_name("processes");
    p->set_version("1.0");
    p->set_description("Process enumeration");
    p->add_capabilities("list");
    p->add_capabilities("query");
    (void)h.registry.register_agent(info);

    auto res = h.sink.Get("/api/v1/discover/plugins");
    REQUIRE(res);
    CHECK(res->status == 200);
    const std::string etag = res->get_header_value("ETag");
    CHECK_FALSE(etag.empty());

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("limitation"));
    CHECK_FALSE(j["limitation"].get<std::string>().empty());
    REQUIRE(j.contains("plugins"));
    bool saw_processes = false;
    for (const auto& pl : j["plugins"]) {
        if (pl["name"] == "processes") {
            saw_processes = true;
            REQUIRE(pl.contains("actions"));
            std::vector<std::string> action_names;
            for (const auto& a : pl["actions"])
                action_names.push_back(a["name"].get<std::string>());
            CHECK(std::find(action_names.begin(), action_names.end(), "list") !=
                  action_names.end());
            CHECK(std::find(action_names.begin(), action_names.end(), "query") !=
                  action_names.end());
        }
    }
    CHECK(saw_processes);

    CHECK(h.last_securable_type == "Infrastructure");

    auto cached = h.sink.Get("/api/v1/discover/plugins", {{"If-None-Match", etag}});
    REQUIRE(cached);
    CHECK(cached->status == 304);
}

// A published InstructionDefinition for the reported plugin/action + the caller
// holding InstructionDefinition:Read -> the action carries its parameter_schema
// inline and actions_enriched_with_schema counts it (the self-orientation win).
TEST_CASE("discover.plugins: parameter_schema enriched when caller holds InstructionDefinition:Read",
          "[discovery][plugins][enrich][pg]") {
    DiscoverHarness h(/*wire_rbac=*/true, /*wire_instr=*/true, /*wire_registry=*/true,
                      /*grant_instr_read=*/true);
    h.instr->create_definition(make_def(
        "Query System", /*enabled=*/true,
        R"({"type":"object","properties":{"depth":{"type":"integer"}}})")); // system_info/query
    auto info = make_agent_info("agent-1", "windows", "WIN-TESTBOX");
    auto* p = info.add_plugins();
    p->set_name("system_info");
    p->add_capabilities("query");
    (void)h.registry.register_agent(info);

    auto res = h.sink.Get("/api/v1/discover/plugins");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["version"] == 3); // 2 -> 3: the per-plugin `docs` summary join
    REQUIRE(j.contains("actions_enriched_with_schema"));
    CHECK(j["actions_enriched_with_schema"].get<int>() >= 1);
    bool found_schema = false;
    for (const auto& pl : j["plugins"]) {
        if (pl["name"] != "system_info")
            continue;
        for (const auto& a : pl["actions"]) {
            if (a["name"] == "query" && a.contains("parameter_schema")) {
                found_schema = true;
                CHECK(a["parameter_schema"]["type"] == "object");
            }
        }
    }
    CHECK(found_schema);
}

// Least-privilege gate (security-guardian MEDIUM / UP-7): the SAME setup, but the
// caller has Infrastructure:Read (mock perm_fn) WITHOUT InstructionDefinition:Read
// -> enrichment is withheld; the catalog is name+description only. This proves the
// InstructionDefinition:Read content is not leaked through the Infrastructure gate.
TEST_CASE("discover.plugins: enrichment withheld when caller lacks InstructionDefinition:Read",
          "[discovery][plugins][enrich][pg]") {
    DiscoverHarness h(/*wire_rbac=*/true, /*wire_instr=*/true, /*wire_registry=*/true,
                      /*grant_instr_read=*/false);
    h.instr->create_definition(make_def(
        "Query System", /*enabled=*/true,
        R"({"type":"object","properties":{"depth":{"type":"integer"}}})"));
    auto info = make_agent_info("agent-1", "windows", "WIN-TESTBOX");
    auto* p = info.add_plugins();
    p->set_name("system_info");
    p->add_capabilities("query");
    (void)h.registry.register_agent(info);

    auto res = h.sink.Get("/api/v1/discover/plugins");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["actions_enriched_with_schema"].get<int>() == 0);
    for (const auto& pl : j["plugins"]) {
        if (pl["name"] != "system_info")
            continue;
        for (const auto& a : pl["actions"])
            CHECK_FALSE(a.contains("parameter_schema"));
    }
}

TEST_CASE("discover.plugins: null AgentRegistry -> 503", "[discovery][plugins][pg]") {
    DiscoverHarness h(/*wire_rbac=*/true, /*wire_instr=*/true, /*wire_registry=*/false);
    auto res = h.sink.Get("/api/v1/discover/plugins");
    REQUIRE(res);
    CHECK(res->status == 503);
}

// ── /discover/plugin-docs (docs/plugin-readme-standard.md rule 10) ──────────
//
// The build-embedded per-plugin documentation manifests. Static like
// scope-kinds: no store dependency, answers during warmup, publicly cacheable.
// The manifests themselves are content (content/plugin-docs/*.json, generated
// by tools/plugin-doc-gen and byte-gated by tests/test_plugin_readmes.py);
// these cases pin the ENVELOPE, the join into /discover/plugins, and the gate.

TEST_CASE("discover.plugin-docs: static manifest catalog shape + ETag revalidation",
          "[discovery][plugin_docs][pg]") {
    DiscoverHarness h;
    auto res = h.sink.Get("/api/v1/discover/plugin-docs");
    REQUIRE(res);
    CHECK(res->status == 200);
    const std::string etag = res->get_header_value("ETag");
    CHECK_FALSE(etag.empty());
    CHECK(h.last_securable_type == "Infrastructure");
    CHECK(h.last_operation == "Read");

    auto j = nlohmann::json::parse(res->body);
    CHECK(j["catalog"] == "plugin-docs");
    CHECK(j["version"] == 1);
    CHECK(j["source"] == "build-embedded");
    REQUIRE(j.contains("plugins"));
    REQUIRE(j["plugins"].is_array());
    CHECK(j["plugin_count"].get<std::size_t>() == j["plugins"].size());
    CHECK(j["skipped_invalid"] == 0);
    // The two pilots ship with this tree; an empty table would make the loop
    // below vacuous, so the count is asserted, not just the shape.
    CHECK(j["plugin_count"].get<std::size_t>() >= 2);
    for (const auto& m : j["plugins"]) {
        CHECK(m["manifest_version"].is_number_integer());
        CHECK(m["name"].is_string());
        CHECK(m["description"].is_string());
        CHECK(m["actions"].is_array());
        CHECK(m["platforms"].is_object());
        CHECK(m["readme"].is_string());
    }

    // Byte-identical to the shared builder the MCP resource serves.
    CHECK(res->body == yuzu::server::plugin_docs_catalog().json);

    // No store dependency — answers 200 even with everything unwired.
    DiscoverHarness bare(/*wire_rbac=*/false, /*wire_instr=*/false, /*wire_registry=*/false);
    auto bare_res = bare.sink.Get("/api/v1/discover/plugin-docs");
    REQUIRE(bare_res);
    CHECK(bare_res->status == 200);

    auto cached = h.sink.Get("/api/v1/discover/plugin-docs", {{"If-None-Match", etag}});
    REQUIRE(cached);
    CHECK(cached->status == 304);
}

TEST_CASE("discover.plugin-docs: permission denied -> 403, no body leak",
          "[discovery][plugin_docs][pg]") {
    DiscoverHarness h;
    h.grant_perms = false;
    auto res = h.sink.Get("/api/v1/discover/plugin-docs");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("\"plugins\"") == std::string::npos);
}

TEST_CASE("discover.plugin-docs/{name}: single manifest shape + ETag + 404 (#4108)",
          "[discovery][plugin_docs][pg]") {
    DiscoverHarness h;
    const auto catalog = nlohmann::json::parse(yuzu::server::plugin_docs_catalog().json);
    REQUIRE(catalog["plugins"].is_array());
    REQUIRE_FALSE(catalog["plugins"].empty());
    const std::string name = catalog["plugins"][0]["name"].get<std::string>();

    auto res = h.sink.Get("/api/v1/discover/plugin-docs/" + name);
    REQUIRE(res);
    CHECK(res->status == 200);
    const std::string etag = res->get_header_value("ETag");
    CHECK_FALSE(etag.empty());
    // Same revalidation contract as the whole-catalog route (#4108 review):
    // publicly cacheable, five-minute floor, not just "some ETag exists".
    CHECK(res->get_header_value("Cache-Control") == "public, max-age=300");
    CHECK(h.last_securable_type == "Infrastructure");
    CHECK(h.last_operation == "Read");

    auto j = nlohmann::json::parse(res->body);
    CHECK(j == catalog["plugins"][0]);
    // Same builder as the MCP resource template — byte-identical.
    const auto* manifest = yuzu::server::plugin_docs_manifest(name);
    REQUIRE(manifest != nullptr);
    CHECK(res->body == manifest->json);

    // No store dependency — answers 200 even with everything unwired, like
    // the whole-catalog route.
    DiscoverHarness bare(/*wire_rbac=*/false, /*wire_instr=*/false, /*wire_registry=*/false);
    auto bare_res = bare.sink.Get("/api/v1/discover/plugin-docs/" + name);
    REQUIRE(bare_res);
    CHECK(bare_res->status == 200);

    auto cached = h.sink.Get("/api/v1/discover/plugin-docs/" + name, {{"If-None-Match", etag}});
    REQUIRE(cached);
    CHECK(cached->status == 304);

    // Unknown name: 404, A4 envelope, no leak of a real manifest's shape.
    auto missing = h.sink.Get("/api/v1/discover/plugin-docs/no_such_plugin_for_docs");
    REQUIRE(missing);
    CHECK(missing->status == 404);
    auto mj = nlohmann::json::parse(missing->body);
    REQUIRE(mj.contains("error"));
    CHECK(mj["error"]["code"] == 404);
    CHECK(mj["error"]["correlation_id"].is_string());
    CHECK_FALSE(mj["error"]["correlation_id"].get<std::string>().empty());
    CHECK(missing->body.find("\"actions\"") == std::string::npos);
}

TEST_CASE("discover.plugin-docs/{name}: every documented plugin resolves, not just the first "
          "(#4108)",
          "[discovery][plugin_docs][pg]") {
    // #4108 review: the single-name cases above always pick plugins[0], which
    // cannot detect an index-construction regression that only populates the
    // first entry. Loop the whole catalog.
    DiscoverHarness h;
    const auto catalog = nlohmann::json::parse(yuzu::server::plugin_docs_catalog().json);
    REQUIRE(catalog["plugins"].is_array());
    REQUIRE_FALSE(catalog["plugins"].empty());
    for (const auto& expected : catalog["plugins"]) {
        const std::string name = expected["name"].get<std::string>();
        const auto* manifest = yuzu::server::plugin_docs_manifest(name);
        REQUIRE(manifest != nullptr);
        CHECK(nlohmann::json::parse(manifest->json) == expected);

        auto res = h.sink.Get("/api/v1/discover/plugin-docs/" + name);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body == manifest->json);
    }
}

TEST_CASE("discover.plugin-docs/{name}: permission denied -> 403 before the name lookup, "
          "even for an unknown name",
          "[discovery][plugin_docs][pg]") {
    DiscoverHarness h;
    h.grant_perms = false;
    auto res = h.sink.Get("/api/v1/discover/plugin-docs/no_such_plugin_for_docs");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("\"actions\"") == std::string::npos);
}

TEST_CASE("discover.plugins: docs summary joined by plugin name, null when undocumented",
          "[discovery][plugins][plugin_docs][pg]") {
    DiscoverHarness h;
    auto info = make_agent_info("agent-1", "windows", "WIN-TESTBOX");
    // A plugin whose README has adopted the standard — whichever manifest the
    // embedded catalog lists first, so the case does not depend on which
    // pilots ship — and one that has not.
    const auto catalog = nlohmann::json::parse(yuzu::server::plugin_docs_catalog().json);
    REQUIRE(catalog["plugins"].is_array());
    REQUIRE_FALSE(catalog["plugins"].empty());
    const std::string documented_name = catalog["plugins"][0]["name"].get<std::string>();
    auto* documented = info.add_plugins();
    documented->set_name(documented_name);
    documented->set_version("1.0.0");
    documented->set_description("drive health");
    documented->add_capabilities("smart");
    auto* undocumented = info.add_plugins();
    undocumented->set_name("no_such_plugin_for_docs");
    undocumented->set_version("0.0.1");
    undocumented->set_description("never documented");
    undocumented->add_capabilities("noop");
    (void)h.registry.register_agent(info);

    // The join reads the same index the catalog serves — a manifest present
    // there MUST surface as a summary here, and vice versa.
    REQUIRE(yuzu::server::plugin_docs_summary(documented_name) != nullptr);
    CHECK(yuzu::server::plugin_docs_summary("no_such_plugin_for_docs") == nullptr);

    // Same shape for the #4108 per-plugin manifest accessor: present for a
    // documented name, null for an undocumented one, and byte-identical to
    // that plugin's own element in the whole catalog.
    const auto* manifest = yuzu::server::plugin_docs_manifest(documented_name);
    REQUIRE(manifest != nullptr);
    CHECK(nlohmann::json::parse(manifest->json) == catalog["plugins"][0]);
    CHECK(yuzu::server::plugin_docs_manifest("no_such_plugin_for_docs") == nullptr);

    auto res = h.sink.Get("/api/v1/discover/plugins");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["version"] == 3);
    bool saw_documented = false, saw_undocumented = false;
    for (const auto& pl : j["plugins"]) {
        REQUIRE(pl.contains("docs")); // always present: object or explicit null
        if (pl["name"] == documented_name) {
            saw_documented = true;
            REQUIRE(pl["docs"].is_object());
            CHECK(pl["docs"]["summary"].is_string());
            CHECK_FALSE(pl["docs"]["summary"].get<std::string>().empty());
            CHECK(pl["docs"]["platforms"].is_object());
            REQUIRE(pl["docs"]["kind"].is_object());
            CHECK(pl["docs"]["kind"]["collector"].is_boolean());
            CHECK(pl["docs"]["kind"]["mutating"].is_boolean());
            CHECK(pl["docs"]["kind"]["gathered"].is_boolean());
            CHECK(pl["docs"]["readme"] == "agents/plugins/" + documented_name + "/README.md");
            CHECK(pl["docs"]["resource"] == "yuzu://plugin-docs/" + documented_name);
        } else if (pl["name"] == "no_such_plugin_for_docs") {
            saw_undocumented = true;
            CHECK(pl["docs"].is_null());
        }
    }
    CHECK(saw_documented);
    CHECK(saw_undocumented);
}
