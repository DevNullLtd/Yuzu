/**
 * test_engine_aware_visibility.cpp -- #6204: the username-keyed visibility and dispatch-permission
 * resolvers (engine_aware_visibility.hpp, bound into the route seams by ServerImpl) honour the
 * engine rule against REAL RbacStore + ManagementGroupStore instances.
 *
 * THE RULE: an engine principal (`engine:<slug>`) has RBAC-only authority, so the legacy-open
 * fallback that admits every human when RBAC is off never applies to it. These are the behavioural
 * tests for the five resolvers that were previously pinned only by a source-presence scan, because
 * they were private ServerImpl members. Each case compares an engine with a human under identical
 * facts, so the engine arm is the only variable.
 */

#include "engine_aware_visibility.hpp"

#include "../test_helpers.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_rbac_store_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <set>
#include <string>

using namespace yuzu::server;
namespace vis = yuzu::server::visibility;

namespace {

constexpr const char* kEngine = "engine:vuln";

/// RBAC + management-group stores, three enrolled agents (two in one group), and the roles the
/// cases need. Enforcement starts ON; cases that need legacy-open turn it off.
struct VisRig {
    yuzu::test::RbacStorePg rbac_bundle;
    RbacStore& rbac = *rbac_bundle;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    ManagementGroupStore& mgmt = *mgmt_bundle;
    std::string group;

    VisRig() {
        rbac.set_rbac_enabled(true);
        REQUIRE(rbac.create_role({"InfraReader6204", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"InfraReader6204", "Infrastructure", "Read", "allow"})
                    .has_value());
        REQUIRE(rbac.create_role({"RespReader6204", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"RespReader6204", "Response", "Read", "allow"}).has_value());
        REQUIRE(rbac.create_role({"ExecRunner6204", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"ExecRunner6204", "Execution", "Execute", "allow"})
                    .has_value());
        ManagementGroup g;
        g.name = "G6204";
        g.membership_type = "static";
        auto id = mgmt.create_group(g);
        REQUIRE(id.has_value());
        group = *id;
        REQUIRE(mgmt.add_member(group, "agent-1").has_value());
        REQUIRE(mgmt.add_member(group, "agent-2").has_value());
        REQUIRE(mgmt.add_member(mgmt_other_group(), "agent-3").has_value());
    }

    std::string mgmt_other_group() {
        ManagementGroup g;
        g.name = "Other6204";
        g.membership_type = "static";
        auto id = mgmt.create_group(g);
        REQUIRE(id.has_value());
        return *id;
    }

    void rbac_off() {
        rbac.set_rbac_enabled(false);
        REQUIRE_FALSE(rbac.is_rbac_enabled());
    }
    void grant_engine(const std::string& role) {
        REQUIRE(rbac.assign_role({"engine", kEngine, role}).has_value());
    }
    void grant_user(const std::string& user, const std::string& role) {
        REQUIRE(rbac.assign_role({"user", user, role}).has_value());
    }
};

nlohmann::json fleet() {
    return nlohmann::json::array({{{"agent_id", "agent-1"}},
                                  {{"agent_id", "agent-2"}},
                                  {{"agent_id", "agent-3"}}});
}

std::set<std::string> ids(const nlohmann::json& arr) {
    std::set<std::string> out;
    for (const auto& a : arr)
        out.insert(a["agent_id"].get<std::string>());
    return out;
}

} // namespace

TEST_CASE("dispatch_permission: RBAC off admits a human and refuses an engine (#6204)",
          "[pg][6204][engine][visibility]") {
    VisRig r;
    SECTION("RBAC off") {
        r.rbac_off();
        CHECK(vis::dispatch_permission(&r.rbac, "alice", "Execution", authz::Operation::Execute));
        CHECK_FALSE(
            vis::dispatch_permission(&r.rbac, kEngine, "Execution", authz::Operation::Execute));
    }
    SECTION("RBAC on: a grant decides, for the engine too") {
        CHECK_FALSE(
            vis::dispatch_permission(&r.rbac, kEngine, "Execution", authz::Operation::Execute));
        r.grant_engine("ExecRunner6204");
        CHECK(vis::dispatch_permission(&r.rbac, kEngine, "Execution", authz::Operation::Execute));
        CHECK_FALSE(vis::dispatch_permission(&r.rbac, "alice", "Execution",
                                             authz::Operation::Execute));
    }
    SECTION("an unavailable store refuses everyone (fail closed)") {
        CHECK_FALSE(vis::dispatch_permission(nullptr, "alice", "Execution",
                                             authz::Operation::Execute));
        CHECK_FALSE(
            vis::dispatch_permission(nullptr, kEngine, "Execution", authz::Operation::Execute));
    }
}

TEST_CASE("response_agent_in_scope: RBAC off admits a human and refuses an engine (#6204)",
          "[pg][6204][engine][visibility]") {
    VisRig r;
    SECTION("RBAC off") {
        r.rbac_off();
        CHECK(vis::response_agent_in_scope(&r.rbac, &r.mgmt, "alice", "agent-1"));
        CHECK_FALSE(vis::response_agent_in_scope(&r.rbac, &r.mgmt, kEngine, "agent-1"));
    }
    SECTION("RBAC on: an engine with a global grant is in scope, without one is not") {
        CHECK_FALSE(vis::response_agent_in_scope(&r.rbac, &r.mgmt, kEngine, "agent-1"));
        r.grant_engine("RespReader6204");
        CHECK(vis::response_agent_in_scope(&r.rbac, &r.mgmt, kEngine, "agent-1"));
    }
    SECTION("a null store fails closed") {
        CHECK_FALSE(vis::response_agent_in_scope(nullptr, &r.mgmt, "alice", "agent-1"));
    }
}

TEST_CASE("visible_agents_json: an engine sees no agents when RBAC is off (#6204)",
          "[pg][6204][engine][visibility]") {
    VisRig r;
    SECTION("RBAC off: human sees the fleet, engine sees nothing") {
        r.rbac_off();
        CHECK(ids(vis::visible_agents_json(fleet(), &r.rbac, &r.mgmt, "alice")).size() == 3);
        auto engine = vis::visible_agents_json(fleet(), &r.rbac, &r.mgmt, kEngine);
        REQUIRE(engine.is_array());
        CHECK(engine.empty());
    }
    SECTION("RBAC on: a global Infrastructure:Read grant sees the fleet, for the engine too") {
        CHECK(vis::visible_agents_json(fleet(), &r.rbac, &r.mgmt, kEngine).empty());
        r.grant_engine("InfraReader6204");
        CHECK(ids(vis::visible_agents_json(fleet(), &r.rbac, &r.mgmt, kEngine)).size() == 3);
    }
    SECTION("RBAC on: a group-confined human sees only their group") {
        r.grant_user("bob", "InfraReader6204"); // global
        CHECK(ids(vis::visible_agents_json(fleet(), &r.rbac, &r.mgmt, "bob")).size() == 3);
        REQUIRE(r.mgmt.assign_role({r.group, "user", "carol", "ExecRunner6204"}).has_value());
        CHECK(ids(vis::visible_agents_json(fleet(), &r.rbac, &r.mgmt, "carol")) ==
              std::set<std::string>{"agent-1", "agent-2"});
    }
}

TEST_CASE("infrastructure_visible_set: nullopt means the whole fleet and an engine never gets it "
          "when RBAC is off (#6204)",
          "[pg][6204][engine][visibility]") {
    VisRig r;
    SECTION("RBAC off") {
        r.rbac_off();
        CHECK_FALSE(vis::infrastructure_visible_set(&r.rbac, &r.mgmt, "alice").has_value());
        auto engine = vis::infrastructure_visible_set(&r.rbac, &r.mgmt, kEngine);
        REQUIRE(engine.has_value()); // present-EMPTY, never nullopt
        CHECK(engine->empty());
    }
    SECTION("RBAC on") {
        auto none = vis::infrastructure_visible_set(&r.rbac, &r.mgmt, kEngine);
        REQUIRE(none.has_value());
        CHECK(none->empty());
        r.grant_engine("InfraReader6204");
        CHECK_FALSE(vis::infrastructure_visible_set(&r.rbac, &r.mgmt, kEngine).has_value());
    }
}

TEST_CASE("response_visible_set: nullopt means the whole fleet and an engine never gets it when "
          "RBAC is off (#6204)",
          "[pg][6204][engine][visibility]") {
    VisRig r;
    SECTION("RBAC off") {
        r.rbac_off();
        CHECK_FALSE(vis::response_visible_set(&r.rbac, &r.mgmt, "alice").has_value());
        auto engine = vis::response_visible_set(&r.rbac, &r.mgmt, kEngine);
        REQUIRE(engine.has_value());
        CHECK(engine->empty());
    }
    SECTION("RBAC on: grant decides; a degraded/absent store is empty, never nullopt") {
        auto none = vis::response_visible_set(&r.rbac, &r.mgmt, kEngine);
        REQUIRE(none.has_value());
        CHECK(none->empty());
        r.grant_engine("RespReader6204");
        CHECK_FALSE(vis::response_visible_set(&r.rbac, &r.mgmt, kEngine).has_value());
        auto no_store = vis::response_visible_set(&r.rbac, nullptr, "dave");
        REQUIRE(no_store.has_value());
        CHECK(no_store->empty());
    }
}

// ── Degraded stores ─────────────────────────────────────────────────────────────────────────────
// An absent RBAC store counts as enforcement in effect (fail closed), so no resolver may return the
// fleet: every one narrows to deny or empty, for a human and an engine alike, never to nullopt.
TEST_CASE("every resolver narrows to deny or empty on an absent RBAC store (#6204)",
          "[pg][6204][engine][visibility][degraded]") {
    VisRig r;
    for (const char* who : {"alice", kEngine}) {
        INFO("principal: " << who);
        CHECK_FALSE(vis::dispatch_permission(nullptr, who, "Execution", authz::Operation::Execute));
        CHECK_FALSE(vis::response_agent_in_scope(nullptr, &r.mgmt, who, "agent-1"));
        CHECK(vis::visible_agents_json(fleet(), nullptr, &r.mgmt, who).empty());
        auto infra = vis::infrastructure_visible_set(nullptr, &r.mgmt, who);
        REQUIRE(infra.has_value());
        CHECK(infra->empty());
        auto resp = vis::response_visible_set(nullptr, &r.mgmt, who);
        REQUIRE(resp.has_value());
        CHECK(resp->empty());
    }
}

// The engine rule leans on the stores refusing what would give an engine a confined view: scoped
// engine role assignments and engine group members. The resolvers have no engine arm for a confined
// engine, so if either refusal is ever relaxed this case must fail and point here.
TEST_CASE("an engine cannot be given a confined view: scoped assignment and group membership are "
          "refused (#6204)",
          "[pg][6204][engine][visibility]") {
    VisRig r;
    auto scoped = r.mgmt.assign_role({r.group, "engine", kEngine, "ExecRunner6204"});
    REQUIRE_FALSE(scoped.has_value());
    CHECK(scoped.error().find("engine") != std::string::npos);

    REQUIRE(r.rbac.create_group({"G6204rbac", "", "local", "", 0}).has_value());
    auto member = r.rbac.add_group_member("G6204rbac", kEngine);
    REQUIRE_FALSE(member.has_value());
    CHECK(member.error().find("engine:") != std::string::npos);
}

// An absent management-group store with enforcement on: nothing to resolve a confined view against,
// so a caller without a global grant gets deny or empty, never the fleet. A global grant still wins.
TEST_CASE("an absent management-group store narrows to empty unless the caller has a global grant "
          "(#6204)",
          "[pg][6204][engine][visibility][degraded]") {
    VisRig r;
    for (const char* who : {"alice", kEngine}) {
        INFO("principal: " << who);
        CHECK(vis::visible_agents_json(fleet(), &r.rbac, nullptr, who).empty());
        auto infra = vis::infrastructure_visible_set(&r.rbac, nullptr, who);
        REQUIRE(infra.has_value());
        CHECK(infra->empty());
        auto resp = vis::response_visible_set(&r.rbac, nullptr, who);
        REQUIRE(resp.has_value());
        CHECK(resp->empty());
        CHECK_FALSE(vis::response_agent_in_scope(&r.rbac, nullptr, who, "agent-1"));
    }
    SECTION("a global Infrastructure:Read grant still sees the fleet") {
        r.grant_engine("InfraReader6204");
        CHECK(ids(vis::visible_agents_json(fleet(), &r.rbac, nullptr, kEngine)).size() == 3);
        CHECK_FALSE(vis::infrastructure_visible_set(&r.rbac, nullptr, kEngine).has_value());
    }
}
