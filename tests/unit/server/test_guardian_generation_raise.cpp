/**
 * test_guardian_generation_raise.cpp - the supported "raise the Guardian policy generation to
 * N" operation: the pure request parser and result shaping (guardian_generation_raise.hpp), the
 * REST route `POST /api/v1/guaranteed-state/policy-generation/raise`, and its MCP twin
 * `raise_guardian_policy_generation`.
 *
 * The route and the tool are driven through RbacRoleHarness
 * (test_rbac_admin_surface_harness.hpp) with its optional Guardian stores, so both transports
 * run off the SAME RbacStore / AuthDB / ApprovalManager / GuaranteedStateStore / BaselineStore.
 * Store-level coverage of the raise itself (monotonicity, the ceiling, concurrency, the
 * mutation hook) lives in test_guaranteed_state_store.cpp.
 *
 * The parser tests need no database. Every route and tool test is PG-gated: it skips when
 * YUZU_TEST_POSTGRES_DSN is unset and fails when set but broken.
 */

#include "guardian_generation_raise.hpp"
#include "mcp_jsonrpc.hpp"
#include "pg/pg_exec.hpp"

#include "test_rbac_admin_surface_harness.hpp" // AuditRecord, RbacRoleHarness, GuardianStores

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <vector>

using namespace yuzu::server;
using nlohmann::json;
namespace guardian = yuzu::server::guardian;

namespace {

constexpr std::int64_t kCeiling = guardian::kMaxPolicyGenerationTarget;
constexpr const char* kRoute = "/api/v1/guaranteed-state/policy-generation/raise";
constexpr const char* kTool = "raise_guardian_policy_generation";
constexpr const char* kCounter = "yuzu_server_guardian_policy_generation_raise_total";

json valid_body(std::int64_t target = 5) {
    return {{"target_generation", target}, {"acknowledge_rule_set_replaced", true}};
}

std::uint64_t counter_value(RbacRoleHarness& h, const char* transport, const char* result) {
    return static_cast<std::uint64_t>(
        h.metrics.counter(kCounter, {{"transport", transport}, {"result", result}}).value());
}

std::vector<AuditRecord> rows_for_raise(const RbacRoleHarness& h) {
    std::vector<AuditRecord> out;
    for (const auto& a : h.audit_log)
        if (a.action == guardian::kRaiseAuditAction)
            out.push_back(a);
    return out;
}

bool has_row(const RbacRoleHarness& h, const std::string& result) {
    for (const auto& a : rows_for_raise(h))
        if (a.result == result)
            return true;
    return false;
}

std::uint64_t generation(RbacRoleHarness& h) {
    const auto g = h.guardian_store->current_policy_generation();
    REQUIRE(g.has_value());
    return *g;
}

// Run one statement on the harness's shared database, outside the stores under test.
void run_sql(RbacRoleHarness& h, const char* sql) {
    auto lease = h.auth_db.pool().acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), sql, std::vector<std::string>{});
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

auto raise_rest(RbacRoleHarness& h, const json& body) { return h.sink.Post(kRoute, body.dump()); }

// A durable administrator for the harness's default session user, RBAC off.
void admin_caller(RbacRoleHarness& h) { h.make_caller_admin(/*rbac_on=*/false); }

} // namespace

// -- parse_raise_request ------------------------------------------------------------------

TEST_CASE("parse_raise_request accepts an integer target in 1..ceiling with the acknowledgement",
          "[guardian][raise][parse]") {
    for (const std::int64_t target : {std::int64_t{1}, std::int64_t{2}, std::int64_t{1000},
                                      kCeiling - 1, kCeiling}) {
        INFO("target=" << target);
        const auto r = guardian::parse_raise_request(valid_body(target));
        REQUIRE(r.has_value());
        CHECK(*r == target);
    }
    // An unsigned JSON integer within range parses the same way.
    const auto u = guardian::parse_raise_request(
        json::parse(R"({"target_generation":9007199254740991,"acknowledge_rule_set_replaced":true})"));
    REQUIRE(u.has_value());
    CHECK(*u == kCeiling);
    // Fields this operation does not define are ignored.
    auto extra = valid_body(9);
    extra["approval_id"] = "x";
    extra["note"] = "free text";
    const auto e = guardian::parse_raise_request(extra);
    REQUIRE(e.has_value());
    CHECK(*e == 9);
}

TEST_CASE("parse_raise_request rejects a target that is not an integer in 1..ceiling",
          "[guardian][raise][parse]") {
    const struct {
        const char* label;
        const char* body;
    } cases[] = {
        {"float", R"({"target_generation":5.5,"acknowledge_rule_set_replaced":true})"},
        {"whole float", R"({"target_generation":5.0,"acknowledge_rule_set_replaced":true})"},
        {"string", R"({"target_generation":"5","acknowledge_rule_set_replaced":true})"},
        {"bool", R"({"target_generation":true,"acknowledge_rule_set_replaced":true})"},
        {"null", R"({"target_generation":null,"acknowledge_rule_set_replaced":true})"},
        {"array", R"({"target_generation":[5],"acknowledge_rule_set_replaced":true})"},
        {"negative", R"({"target_generation":-1,"acknowledge_rule_set_replaced":true})"},
        {"zero", R"({"target_generation":0,"acknowledge_rule_set_replaced":true})"},
        {"ceiling plus one",
         R"({"target_generation":9007199254740992,"acknowledge_rule_set_replaced":true})"},
        {"int64 max",
         R"({"target_generation":9223372036854775807,"acknowledge_rule_set_replaced":true})"},
        {"uint64 max",
         R"({"target_generation":18446744073709551615,"acknowledge_rule_set_replaced":true})"},
        {"int64 min",
         R"({"target_generation":-9223372036854775808,"acknowledge_rule_set_replaced":true})"},
        {"missing target", R"({"acknowledge_rule_set_replaced":true})"},
    };
    for (const auto& c : cases) {
        INFO("case=" << c.label);
        const auto r = guardian::parse_raise_request(json::parse(c.body));
        REQUIRE_FALSE(r.has_value());
        CHECK_FALSE(r.error().empty());
    }
}

TEST_CASE("parse_raise_request requires the acknowledgement to be the JSON boolean true",
          "[guardian][raise][parse]") {
    const char* bodies[] = {
        R"({"target_generation":5})",
        R"({"target_generation":5,"acknowledge_rule_set_replaced":false})",
        R"({"target_generation":5,"acknowledge_rule_set_replaced":"true"})",
        R"({"target_generation":5,"acknowledge_rule_set_replaced":1})",
        R"({"target_generation":5,"acknowledge_rule_set_replaced":null})",
    };
    for (const char* b : bodies) {
        INFO("body=" << b);
        const auto r = guardian::parse_raise_request(json::parse(b));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("acknowledge_rule_set_replaced") != std::string::npos);
    }
}

TEST_CASE("parse_raise_request rejects a body that is not an object",
          "[guardian][raise][parse]") {
    for (const char* b : {"[]", "5", "\"x\"", "null", "true"}) {
        INFO("body=" << b);
        const auto r = guardian::parse_raise_request(json::parse(b));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("JSON object") != std::string::npos);
    }
}

TEST_CASE("parse_raise_request error text never echoes a request value and has no control bytes",
          "[guardian][raise][parse]") {
    const json hostile = {{"target_generation", "evil\r\nINJECT"},
                          {"acknowledge_rule_set_replaced", "evil\nINJECT"}};
    const auto r = guardian::parse_raise_request(hostile);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("INJECT") == std::string::npos);
    for (const char c : r.error())
        CHECK(static_cast<unsigned char>(c) >= 0x20);

    const auto ack = guardian::parse_raise_request(
        json{{"target_generation", 5}, {"acknowledge_rule_set_replaced", "evil\nINJECT"}});
    REQUIRE_FALSE(ack.has_value());
    CHECK(ack.error().find("INJECT") == std::string::npos);
}

TEST_CASE("raise_audit_detail and raise_result_json shape the shared text and body",
          "[guardian][raise][parse]") {
    CHECK(guardian::raise_audit_detail(10, 3, 10, true, 4, 2) ==
          "target=10; previous=3; resulting=10; raised=true; rules=4; deployed_baselines=2");
    CHECK(guardian::raise_audit_detail(2, 9, 9, false, 0, 0) ==
          "target=2; previous=9; resulting=9; raised=false; rules=0; deployed_baselines=0");
    const auto j = guardian::raise_result_json(3, 10, true, 4, 2);
    CHECK(j["previous_generation"] == 3);
    CHECK(j["generation"] == 10);
    CHECK(j["raised"] == true);
    CHECK(j["rules"] == 4);
    CHECK(j["deployed_baselines"] == 2);
    CHECK(j["ceiling"] == kCeiling);
    CHECK(j.size() == 6);
}

// -- REST: happy paths ---------------------------------------------------------------------

TEST_CASE("REST POST policy-generation/raise: an administrator raises the generation; response, "
          "store, audit rows and counter agree",
          "[pg][rest][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    int hook_fired = 0;
    h.guardian_store->set_on_rule_mutation([&] { ++hook_fired; });

    auto res = raise_rest(h, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto body = json::parse(res->body);
    CHECK(body["data"]["previous_generation"] == 0);
    CHECK(body["data"]["generation"] == 42);
    CHECK(body["data"]["raised"] == true);
    CHECK(body["data"]["rules"] == 0);
    CHECK(body["data"]["deployed_baselines"] == 0);
    CHECK(body["data"]["ceiling"] == kCeiling);

    CHECK(generation(h) == 42);
    CHECK(hook_fired == 1); // this replica's reconcile caches are dropped

    // The attempted row comes first, then the outcome row with the shared detail text.
    const auto rows = rows_for_raise(h);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[0].target_id == "policy_generation");
    CHECK(rows[0].detail.find("target=42") != std::string::npos);
    CHECK(rows[1].result == "success");
    CHECK(rows[1].target_id == "policy_generation");
    CHECK(rows[1].detail ==
          "target=42; previous=0; resulting=42; raised=true; rules=0; deployed_baselines=0");

    CHECK(counter_value(h, "rest", "applied") == 1);
    CHECK(counter_value(h, "rest", "unchanged") == 0);
    CHECK(counter_value(h, "rest", "refused") == 0);
    CHECK(counter_value(h, "rest", "failed") == 0);
    CHECK(h.step_up_actions.size() == 1);
    CHECK(h.step_up_actions[0] == std::string("POST ") + kRoute);
}

TEST_CASE("REST POST policy-generation/raise: the response counts the rules and the deployed "
          "Baselines it will converge agents to",
          "[pg][rest][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    GuaranteedStateRuleRow rule;
    rule.rule_id = "r1";
    rule.name = "guard-one";
    rule.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: GuaranteedStateRule\n";
    rule.version = 1;
    rule.enabled = true;
    rule.enforcement_mode = "enforce";
    rule.severity = "high";
    rule.os_target = "windows";
    rule.scope_expr = "tag:workstations";
    rule.created_at = "2026-04-19T12:00:00Z";
    rule.updated_at = "2026-04-19T12:00:00Z";
    rule.created_by = "alice";
    rule.updated_by = "alice";
    REQUIRE(h.guardian_store->create_rule(rule));
    const auto before = generation(h); // the create bumped it

    auto res = raise_rest(h, valid_body(static_cast<std::int64_t>(before) + 10));
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto body = json::parse(res->body);
    CHECK(body["data"]["rules"] == 1);
    CHECK(body["data"]["previous_generation"] == before);
    CHECK(body["data"]["generation"] == before + 10);
    const auto rows = rows_for_raise(h);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].detail.find("rules=1") != std::string::npos);
}

TEST_CASE("REST POST policy-generation/raise: a target at or below the current generation is "
          "200 raised=false, changes nothing, fires no hook, counts unchanged",
          "[pg][rest][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    REQUIRE(h.guardian_store->raise_policy_generation(100).has_value());
    int hook_fired = 0;
    h.guardian_store->set_on_rule_mutation([&] { ++hook_fired; });

    for (const std::int64_t target : {std::int64_t{100}, std::int64_t{7}}) {
        INFO("target=" << target);
        auto res = raise_rest(h, valid_body(target));
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto body = json::parse(res->body);
        CHECK(body["data"]["raised"] == false);
        CHECK(body["data"]["previous_generation"] == 100);
        CHECK(body["data"]["generation"] == 100);
    }
    CHECK(generation(h) == 100);
    CHECK(hook_fired == 0);
    CHECK(counter_value(h, "rest", "unchanged") == 2);
    CHECK(counter_value(h, "rest", "applied") == 0);
    bool saw_no_op_row = false;
    for (const auto& a : rows_for_raise(h))
        if (a.result == "success" && a.detail.find("raised=false") != std::string::npos)
            saw_no_op_row = true;
    CHECK(saw_no_op_row);
}

TEST_CASE("REST POST policy-generation/raise: the ceiling itself is accepted",
          "[pg][rest][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    auto res = raise_rest(h, valid_body(kCeiling));
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(json::parse(res->body)["data"]["generation"] == kCeiling);
    CHECK(generation(h) == static_cast<std::uint64_t>(kCeiling));
}

// -- REST: gates ---------------------------------------------------------------------------

TEST_CASE("REST POST policy-generation/raise: a non-administrator is denied 403 before the body "
          "is read; nothing changes, a denied row is written, the counter is untouched",
          "[pg][rest][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    REQUIRE(h.auth_db->upsert_user("plainuser", "hash", "salt", auth::Role::user).has_value());
    h.session_user = "plainuser";

    // A body that would otherwise be a 400: the gate answers first.
    auto res = h.sink.Post(kRoute, "not json");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(generation(h) == 0);
    CHECK(h.step_up_actions.empty());
    const auto rows = rows_for_raise(h);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].result == "denied");
    CHECK_FALSE(has_row(h, "attempted"));
    for (const char* r : {"applied", "unchanged", "refused", "failed"})
        CHECK(counter_value(h, "rest", r) == 0);

    // The gate is the administrator check, not a Guardian permission: with RBAC on, an
    // Operator is denied too.
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", "plainuser", "Operator"}).has_value());
    auto res2 = raise_rest(h, valid_body(9));
    REQUIRE(res2);
    CHECK(res2->status == 403);
    CHECK(generation(h) == 0);
}

TEST_CASE("REST POST policy-generation/raise: a service-scoped token, an engine session and an "
          "MCP-tier bearer token are each denied 403 with no mutation",
          "[pg][rest][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);

    SECTION("service-scoped token") {
        h.session_token_scope_service = "some-service";
        auto res = raise_rest(h, valid_body(9));
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_FALSE(json::parse(res->body)["error"].contains("permission"));
    }
    SECTION("engine session") {
        h.session_principal_kind = "engine";
        auto res = raise_rest(h, valid_body(9));
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    SECTION("MCP-tier bearer token") {
        h.rest_session_mcp_tier = "supervised";
        auto res = raise_rest(h, valid_body(9));
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(json::parse(res->body)["error"]["message"].get<std::string>().find(kTool) !=
              std::string::npos);
    }
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "attempted"));
    CHECK_FALSE(has_row(h, "success"));
    for (const char* r : {"applied", "unchanged", "refused", "failed"})
        CHECK(counter_value(h, "rest", r) == 0);
}

TEST_CASE("REST POST policy-generation/raise: a missing or failed MFA step-up is refused before "
          "anything is read or changed",
          "[pg][rest][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    h.step_up = [](const httplib::Request&, httplib::Response& res, const auth::Session&,
                   const std::string&) {
        res.status = 401;
        res.set_content(R"({"error":{"message":"step-up required"}})", "application/json");
        return false;
    };
    auto res = raise_rest(h, valid_body(9));
    REQUIRE(res);
    CHECK(res->status == 401);
    REQUIRE(h.step_up_actions.size() == 1);
    CHECK(h.step_up_actions[0] == std::string("POST ") + kRoute);
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "attempted"));
    CHECK_FALSE(has_row(h, "success"));
    for (const char* r : {"applied", "unchanged", "refused", "failed"})
        CHECK(counter_value(h, "rest", r) == 0);
}

// -- REST: request validation --------------------------------------------------------------

TEST_CASE("REST POST policy-generation/raise: a malformed body, a missing or false "
          "acknowledgement and an out-of-range target are 400 with no mutation",
          "[pg][rest][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);

    const std::vector<std::string> bodies = {
        "not json",
        "[]",
        R"({"target_generation":5})",
        R"({"target_generation":5,"acknowledge_rule_set_replaced":false})",
        R"({"target_generation":5,"acknowledge_rule_set_replaced":"true"})",
        R"({"target_generation":0,"acknowledge_rule_set_replaced":true})",
        R"({"target_generation":-3,"acknowledge_rule_set_replaced":true})",
        R"({"target_generation":9007199254740992,"acknowledge_rule_set_replaced":true})",
        R"({"target_generation":"7","acknowledge_rule_set_replaced":true})",
        R"({"target_generation":7.5,"acknowledge_rule_set_replaced":true})",
        R"({"acknowledge_rule_set_replaced":true})",
    };
    for (const auto& b : bodies) {
        INFO("body=" << b);
        auto res = h.sink.Post(kRoute, b);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(json::parse(res->body).contains("error"));
    }
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "attempted"));
    CHECK_FALSE(has_row(h, "success"));
    CHECK(counter_value(h, "rest", "refused") == bodies.size());
    CHECK(counter_value(h, "rest", "applied") == 0);
    CHECK(counter_value(h, "rest", "failed") == 0);
    for (const auto& a : rows_for_raise(h))
        CHECK(a.result == "denied");
}

// -- REST: audit fail-closed ---------------------------------------------------------------

TEST_CASE("REST POST policy-generation/raise: when the attempted audit row cannot be stored the "
          "request is 503 with Sec-Audit-Failed and NOTHING is changed",
          "[pg][rest][guardian][raise][audit_failclose]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    int hook_fired = 0;
    h.guardian_store->set_on_rule_mutation([&] { ++hook_fired; });
    h.audit_fail_result = "attempted";

    auto res = raise_rest(h, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(generation(h) == 0); // no audit row, no mutation
    CHECK(hook_fired == 0);
    CHECK_FALSE(has_row(h, "success"));
    CHECK(counter_value(h, "rest", "failed") == 1);
    CHECK(counter_value(h, "rest", "applied") == 0);
}

TEST_CASE("REST POST policy-generation/raise: when only the outcome audit row cannot be stored "
          "the response is 503 and says the raise took effect",
          "[pg][rest][guardian][raise][audit_failclose]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    h.audit_fail_result = "success";

    auto res = raise_rest(h, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(json::parse(res->body)["error"]["message"].get<std::string>().find("raised") !=
          std::string::npos);
    CHECK(generation(h) == 42); // the change committed; the response must not claim otherwise
    CHECK(has_row(h, "attempted"));
}

// -- REST: store degradation and wiring ----------------------------------------------------

TEST_CASE("REST POST policy-generation/raise: a degraded rule-count read is 503 with no attempted "
          "row and no mutation",
          "[pg][rest][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    run_sql(h, "ALTER TABLE guaranteed_state_store.guaranteed_state_rules "
               "RENAME TO guaranteed_state_rules_off");

    auto res = raise_rest(h, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK_FALSE(has_row(h, "attempted"));
    CHECK(has_row(h, "denied"));
    CHECK(counter_value(h, "rest", "failed") == 1);

    run_sql(h, "ALTER TABLE guaranteed_state_store.guaranteed_state_rules_off "
               "RENAME TO guaranteed_state_rules");
    CHECK(generation(h) == 0);
}

TEST_CASE("REST POST policy-generation/raise: a store that cannot write the counter is 503 with "
          "a failure row and no change",
          "[pg][rest][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    int hook_fired = 0;
    h.guardian_store->set_on_rule_mutation([&] { ++hook_fired; });
    run_sql(h, "ALTER TABLE guaranteed_state_store.guardian_meta RENAME TO guardian_meta_off");

    auto res = raise_rest(h, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(has_row(h, "attempted"));
    CHECK(has_row(h, "failure"));
    CHECK_FALSE(has_row(h, "success"));
    CHECK(hook_fired == 0);
    CHECK(counter_value(h, "rest", "failed") == 1);

    run_sql(h, "ALTER TABLE guaranteed_state_store.guardian_meta_off RENAME TO guardian_meta");
    CHECK(generation(h) == 0);
}

TEST_CASE("REST POST policy-generation/raise: a missing Baseline store is 503 with no mutation",
          "[pg][rest][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kGuardianOnly);
    admin_caller(h);
    auto res = raise_rest(h, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "attempted"));
    CHECK(counter_value(h, "rest", "failed") == 1);
}

// -- MCP twin ------------------------------------------------------------------------------

TEST_CASE("MCP raise_guardian_policy_generation: an administrator with an approved ticket raises "
          "the generation; structuredContent, store, audit rows and counter agree",
          "[pg][mcp][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    int hook_fired = 0;
    h.guardian_store->set_on_rule_mutation([&] { ++hook_fired; });

    auto res = h.mcp_call_tool_approved(kTool, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto body = json::parse(res->body);
    REQUIRE_FALSE(body.contains("error"));
    const auto sc = body["result"]["structuredContent"];
    CHECK(sc["previous_generation"] == 0);
    CHECK(sc["generation"] == 42);
    CHECK(sc["raised"] == true);
    CHECK(sc["rules"] == 0);
    CHECK(sc["deployed_baselines"] == 0);
    CHECK(sc["ceiling"] == kCeiling);

    CHECK(generation(h) == 42);
    CHECK(hook_fired == 1);
    const auto rows = rows_for_raise(h);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[1].result == "success");
    CHECK(rows[1].detail ==
          "target=42; previous=0; resulting=42; raised=true; rules=0; deployed_baselines=0");
    CHECK(counter_value(h, "mcp", "applied") == 1);
    CHECK(counter_value(h, "rest", "applied") == 0);
}

TEST_CASE("MCP raise_guardian_policy_generation: the first call mints an approval ticket and "
          "changes nothing",
          "[pg][mcp][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    auto res = h.mcp_call_tool(kTool, valid_body(42));
    REQUIRE(res);
    const auto body = json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == mcp::kApprovalRequired);
    CHECK(generation(h) == 0);
    CHECK(h.appr->pending_count() == 1);
    CHECK_FALSE(has_row(h, "attempted"));
}

TEST_CASE("MCP raise_guardian_policy_generation: a target at or below the current generation is "
          "a success with raised=false and fires no hook",
          "[pg][mcp][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    REQUIRE(h.guardian_store->raise_policy_generation(100).has_value());
    int hook_fired = 0;
    h.guardian_store->set_on_rule_mutation([&] { ++hook_fired; });

    auto res = h.mcp_call_tool_approved(kTool, valid_body(50));
    REQUIRE(res);
    const auto body = json::parse(res->body);
    REQUIRE_FALSE(body.contains("error"));
    CHECK(body["result"]["structuredContent"]["raised"] == false);
    CHECK(body["result"]["structuredContent"]["generation"] == 100);
    CHECK(generation(h) == 100);
    CHECK(hook_fired == 0);
    CHECK(counter_value(h, "mcp", "unchanged") == 1);
}

TEST_CASE("MCP raise_guardian_policy_generation: a non-administrator, a service-scoped token and "
          "an empty-tier caller are each denied with no mutation",
          "[pg][mcp][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);

    SECTION("non-administrator") {
        REQUIRE(h.auth_db->upsert_user("plainuser", "hash", "salt", auth::Role::user).has_value());
        h.session_user = "plainuser";
        auto res = h.mcp_call_tool_approved(kTool, valid_body(42));
        REQUIRE(res);
        CHECK(json::parse(res->body).contains("error"));
        CHECK(has_row(h, "denied"));
    }
    SECTION("service-scoped token") {
        admin_caller(h);
        h.session_token_scope_service = "some-service";
        // Denied by the service-scope default before any approval ticket is minted.
        auto res = h.mcp_call_tool(kTool, valid_body(42));
        REQUIRE(res);
        CHECK(json::parse(res->body).contains("error"));
        CHECK(h.appr->pending_count() == 0);
    }
    SECTION("empty mcp_tier is denied outright, with an audit row") {
        admin_caller(h);
        h.session_mcp_tier = "";
        auto res = h.mcp_call_tool(kTool, valid_body(42));
        REQUIRE(res);
        CHECK(json::parse(res->body).contains("error"));
        CHECK(res->body.find("requires an MCP-tier bearer token") != std::string::npos);
        bool found = false;
        for (const auto& a : rows_for_raise(h))
            if (a.result == "denied" && a.detail.find("empty mcp_tier") != std::string::npos)
                found = true;
        CHECK(found);
    }
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "attempted"));
    CHECK_FALSE(has_row(h, "success"));
    for (const char* r : {"applied", "unchanged", "refused", "failed"})
        CHECK(counter_value(h, "mcp", r) == 0);
}

TEST_CASE("MCP raise_guardian_policy_generation: a missing acknowledgement or an out-of-range "
          "target is rejected with no ticket, no mutation and no success row",
          "[pg][mcp][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    const std::vector<json> bad = {
        json{{"target_generation", 5}},
        json{{"target_generation", 5}, {"acknowledge_rule_set_replaced", false}},
        json{{"target_generation", 0}, {"acknowledge_rule_set_replaced", true}},
        json{{"target_generation", kCeiling + 1}, {"acknowledge_rule_set_replaced", true}},
        json{{"target_generation", "5"}, {"acknowledge_rule_set_replaced", true}},
        json{{"acknowledge_rule_set_replaced", true}},
    };
    for (const auto& args : bad) {
        INFO("args=" << args.dump());
        auto res = h.mcp_call_tool(kTool, args);
        REQUIRE(res);
        CHECK(json::parse(res->body).contains("error"));
    }
    CHECK(h.appr->pending_count() == 0);
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "success"));
}

TEST_CASE("MCP raise_guardian_policy_generation: when the attempted audit row cannot be stored "
          "the call fails with audit_persisted=false and NOTHING is changed",
          "[pg][mcp][guardian][raise][audit_failclose]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    const std::string approval_id = h.mcp_mint_and_approve(kTool, valid_body(42));
    h.audit_fail_result = "attempted";
    json args = valid_body(42);
    args["approval_id"] = approval_id;

    auto res = h.mcp_call_tool(kTool, args);
    REQUIRE(res);
    const auto body = json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["data"]["audit_persisted"] == false);
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "success"));
    CHECK(counter_value(h, "mcp", "failed") == 1);
}

TEST_CASE("MCP raise_guardian_policy_generation: when only the outcome audit row cannot be "
          "stored the call is a 503 shape saying the change took effect",
          "[pg][mcp][guardian][raise][audit_failclose]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    admin_caller(h);
    const std::string approval_id = h.mcp_mint_and_approve(kTool, valid_body(42));
    h.audit_fail_result = "success";
    json args = valid_body(42);
    args["approval_id"] = approval_id;

    auto res = h.mcp_call_tool(kTool, args);
    REQUIRE(res);
    const auto body = json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == 503);
    CHECK(body["error"]["data"]["audit_persisted"] == false);
    CHECK(body["error"]["message"].get<std::string>().find("took effect") != std::string::npos);
    CHECK(generation(h) == 42);
}

TEST_CASE("MCP raise_guardian_policy_generation: a store that cannot write the counter, and a "
          "missing Baseline store, each fail with no mutation",
          "[pg][mcp][guardian][raise]") {
    SECTION("counter table unreadable") {
        RbacRoleHarness h(GuardianStores::kBoth);
        admin_caller(h);
        run_sql(h, "ALTER TABLE guaranteed_state_store.guardian_meta RENAME TO guardian_meta_off");
        auto res = h.mcp_call_tool_approved(kTool, valid_body(42));
        REQUIRE(res);
        CHECK(json::parse(res->body).contains("error"));
        CHECK(has_row(h, "failure"));
        CHECK_FALSE(has_row(h, "success"));
        CHECK(counter_value(h, "mcp", "failed") == 1);
        run_sql(h, "ALTER TABLE guaranteed_state_store.guardian_meta_off RENAME TO guardian_meta");
        CHECK(generation(h) == 0);
    }
    SECTION("rule count unreadable") {
        RbacRoleHarness h(GuardianStores::kBoth);
        admin_caller(h);
        run_sql(h, "ALTER TABLE guaranteed_state_store.guaranteed_state_rules "
                   "RENAME TO guaranteed_state_rules_off");
        auto res = h.mcp_call_tool_approved(kTool, valid_body(42));
        REQUIRE(res);
        CHECK(json::parse(res->body).contains("error"));
        CHECK_FALSE(has_row(h, "attempted"));
        run_sql(h, "ALTER TABLE guaranteed_state_store.guaranteed_state_rules_off "
                   "RENAME TO guaranteed_state_rules");
        CHECK(generation(h) == 0);
    }
    SECTION("no Baseline store") {
        RbacRoleHarness h(GuardianStores::kGuardianOnly);
        admin_caller(h);
        auto res = h.mcp_call_tool_approved(kTool, valid_body(42));
        REQUIRE(res);
        CHECK(json::parse(res->body).contains("error"));
        CHECK(generation(h) == 0);
        CHECK_FALSE(has_row(h, "attempted"));
        CHECK(counter_value(h, "mcp", "failed") == 1);
    }
}

TEST_CASE("MCP raise_guardian_policy_generation: advertised in tools/list as a destructive, "
          "idempotent write with a bounded input schema",
          "[pg][mcp][guardian][raise]") {
    RbacRoleHarness h(GuardianStores::kBoth);
    auto res = h.mcp_call(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const auto body = json::parse(res->body);
    bool found = false;
    for (const auto& t : body["result"]["tools"]) {
        if (t["name"] != kTool)
            continue;
        found = true;
        CHECK(t["annotations"]["destructiveHint"] == true);
        CHECK(t["annotations"]["idempotentHint"] == true);
        CHECK(t["annotations"]["readOnlyHint"] == false);
        CHECK(t["annotations"]["openWorldHint"] == false);
        const auto& props = t["inputSchema"]["properties"];
        CHECK(props["target_generation"]["minimum"] == 1);
        CHECK(props["target_generation"]["maximum"] == kCeiling);
        CHECK(props["acknowledge_rule_set_replaced"]["enum"][0] == true);
        const auto req = t["inputSchema"]["required"];
        CHECK(req.size() == 2);
    }
    CHECK(found);
}
