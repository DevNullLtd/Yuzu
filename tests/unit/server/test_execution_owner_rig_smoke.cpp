/**
 * test_execution_owner_rig_smoke.cpp -- #5557: proves the shared real-gate rig
 * (test_execution_owner_scope_rig.hpp) works.
 *
 * The rig is what it claims: one real AuthRoutes feeds authentication, permission and
 * fleet-read, the credentials resolve to the sessions and scopes the fixture documents, and the
 * seeded fixture holds exactly the ids it should. It asserts no per-surface behaviour: the
 * surface cases live in test_execution_owner_legacy.cpp, test_execution_owner_rest_v1.cpp and
 * test_execution_owner_dashboard.cpp (and test_mcp_server.cpp for MCP).
 *
 * This file does not use, and does not depend on, any fleet-read or list-read gate refusal.
 */

#include "test_execution_owner_scope_rig.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::test::ExecutionOwnerRig;

TEST_CASE("owner rig: one real session feeds authentication, permission and fleet-read",
          "[pg][execution][owner_rig][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    const auto& c = r.creds;
    using Agents = std::vector<std::string>;

    // Authentication: a service-scoped token is its MINTER's session with a service scope and no
    // tier; the MCP twin adds the explicit tier. A cookie session carries neither.
    auto sa = r.session_of_token(c.svc_a);
    REQUIRE(sa);
    CHECK(sa->username == "mina");
    CHECK(sa->token_scope_service == "A");
    CHECK(sa->mcp_tier.empty());
    auto ma = r.session_of_token(c.mcp_svc_a);
    REQUIRE(ma);
    CHECK(ma->username == "mina");
    CHECK(ma->token_scope_service == "A");
    CHECK(ma->mcp_tier == "readonly");
    auto cookie = r.session_of(ExecutionOwnerRig::cookie(r.cookie_session("mina")));
    REQUIRE(cookie);
    CHECK(cookie->username == "mina");
    CHECK(cookie->token_scope_service.empty());
    CHECK(cookie->mcp_tier.empty());

    // Fleet-read: the exact agent scope each credential resolves to, tierless and tiered alike.
    for (const auto& token : {c.svc_a, c.mcp_svc_a}) {
        auto s = r.fleet_scope(ExecutionOwnerRig::bearer(token));
        CHECK(s.admitted);
        CHECK(s.agents == std::optional<Agents>(Agents{"a1", "a2"}));
    }
    CHECK(r.fleet_scope(ExecutionOwnerRig::bearer(c.svc_b)).agents ==
          std::optional<Agents>(Agents{"b1"}));
    // meet(group {a1}, service {a1,a2}) = {a1}
    CHECK(r.fleet_scope(ExecutionOwnerRig::bearer(c.svc_bob_a)).agents ==
          std::optional<Agents>(Agents{"a1"}));
    CHECK(r.fleet_scope(ExecutionOwnerRig::bearer(c.bob)).agents ==
          std::optional<Agents>(Agents{"a1"}));
    // service C tags no agent: ADMITTED with an empty scope (not a refusal).
    {
        auto s = r.fleet_scope(ExecutionOwnerRig::bearer(c.svc_none));
        CHECK(s.admitted);
        CHECK(s.agents == std::optional<Agents>(Agents{}));
    }
    // mina holds a GLOBAL grant: admitted unfiltered (nullopt, not an empty list).
    {
        auto s = r.fleet_scope(ExecutionOwnerRig::bearer(c.mina));
        CHECK(s.admitted);
        CHECK_FALSE(s.agents.has_value());
    }
    // dan is authenticated with no Execution:Read: refused (403), distinct from the admitted-empty
    // service C case above.
    {
        auto s = r.fleet_scope(ExecutionOwnerRig::bearer(c.dan));
        CHECK_FALSE(s.admitted);
        CHECK(s.status == 403);
    }

    // Permission: the SAME AuthRoutes' require_permission. A global grant passes; no grant is
    // refused; a service-scoped token is default-denied by the plain gate (which is why a
    // service-scoped credential cannot reach MCP execute_instruction today).
    auto perm = [&](const std::string& token) {
        httplib::Request req;
        req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        return r.perm_fn()(req, res, "Execution", "Read");
    };
    CHECK(perm(c.mina));
    CHECK_FALSE(perm(c.dan));
    CHECK_FALSE(perm(c.svc_a));
}

TEST_CASE("owner rig: the seeded fixture holds exactly the documented executions",
          "[pg][execution][owner_rig][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};

    // Unconfined view (nullopt scope = unrestricted): every always-seeded id and nothing else.
    auto all = r.tracker.query_executions_checked(ExecutionQuery{.limit = 500}, std::nullopt);
    REQUIRE(all.has_value());
    std::vector<std::string> got;
    for (const auto& e : *all)
        got.push_back(e.id);
    CHECK(ExecutionOwnerRig::sorted(got) == r.all_seeded_ids());

    // The a2-only execution and the running row are what make the exact sets discriminating.
    auto a2 = r.tracker.get_agent_statuses_checked(r.ids.a2, std::nullopt);
    REQUIRE(a2.has_value());
    REQUIRE(a2->size() == 1);
    CHECK((*a2)[0].agent_id == "a2");
    auto run = r.tracker.get_agent_statuses_checked(r.ids.run, std::nullopt);
    REQUIRE(run.has_value());
    int running = 0;
    for (const auto& s : *run)
        running += (s.status == "running") ? 1 : 0;
    CHECK(running == 2);
}

TEST_CASE("owner rig: child, starvation and cap fixtures seed on demand",
          "[pg][execution][owner_rig][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};

    const auto kids = r.seed_children();
    auto set1 = r.tracker.get_children_checked(kids.parent_in, std::nullopt);
    REQUIRE(set1.has_value());
    std::vector<std::string> got;
    for (const auto& e : set1->children)
        got.push_back(e.id);
    CHECK(ExecutionOwnerRig::sorted(got) ==
          ExecutionOwnerRig::sorted(
              {kids.c_in, kids.c_minter_out, kids.c_minter_pending, kids.c_b}));
    CHECK_FALSE(set1->truncated);

    // The cap fixture must really exceed the tracker's cap, or it proves nothing later.
    const auto cap = r.seed_children_cap();
    auto capped = r.tracker.get_children_checked(cap.parent_cap, std::nullopt);
    REQUIRE(capped.has_value());
    CHECK(capped->truncated);

    CHECK(r.seed_starvation(60).size() == 60);
}
