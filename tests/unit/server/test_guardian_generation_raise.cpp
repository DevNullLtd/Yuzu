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
#include "openapi_spec_access.hpp"
#include "pg/pg_exec.hpp"
#include "rbac_admin_predicate.hpp" // kRbacAdminGate*AuditReason, kRbacRegimeAuthority*
#include "web_utils.hpp"            // normalise_trusted_origins

#include "test_rbac_admin_surface_harness.hpp" // AuditRecord, RbacRoleHarness, GuardianStores

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;
using nlohmann::json;
namespace guardian = yuzu::server::guardian;

namespace {

constexpr std::int64_t kCeiling = guardian::kMaxPolicyGenerationTarget;
constexpr const char* kRoute = "/api/v1/guaranteed-state/policy-generation/raise";
constexpr const char* kTool = "raise_guardian_policy_generation";
constexpr const char* kCounter = "yuzu_server_guardian_policy_generation_raise_total";

// RbacRoleHarness already sends a same-site Host and Origin with every REST request; a test
// overrides `sink.default_headers` to vary that.
using RaiseHarness = RbacRoleHarness;

// Indexing a const json with a missing key is undefined behaviour, so each step is checked
// before it is taken and a miss fails the test cleanly.
const json& json_step(const json& node, const char* key) {
    INFO("key=" << key);
    REQUIRE(node.is_object());
    REQUIRE(node.contains(key));
    return node.at(key);
}

// The request a caller sends to a server that holds nothing deployed: both acknowledgements.
json valid_body(std::int64_t target = 5) {
    return {{"target_generation", target},
            {"acknowledge_rule_set_replaced", true},
            {"acknowledge_empty_rule_set", true}};
}

// The request a caller sends to a server that holds a deployed rule set: only the first
// acknowledgement.
json populated_body(std::int64_t target = 5) {
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

GuaranteedStateRuleRow make_rule(const std::string& id) {
    GuaranteedStateRuleRow rule;
    rule.rule_id = id;
    rule.name = "guard-" + id;
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
    return rule;
}

constexpr std::int64_t kSeededRules = 3; // two enabled and one disabled

// Three rules (the third disabled), one deployed Baseline and one draft Baseline. The rule
// figure counts every row, so the disabled rule is part of the total. Returns the generation
// after the seeding, which the rule creates bumped.
std::uint64_t seed_rules_and_baselines(RbacRoleHarness& h) {
    REQUIRE(h.guardian_store->create_rule(make_rule("r1")));
    REQUIRE(h.guardian_store->create_rule(make_rule("r2")));
    auto disabled = make_rule("r3");
    disabled.enabled = false;
    REQUIRE(h.guardian_store->create_rule(disabled));
    Baseline draft;
    draft.name = "draft-only";
    draft.created_by = "alice";
    draft.updated_by = "alice";
    Baseline live = draft;
    live.name = "will-deploy";
    const auto draft_id = h.baseline_store->create_baseline(draft);
    const auto live_id = h.baseline_store->create_baseline(live);
    REQUIRE(draft_id.has_value());
    REQUIRE(live_id.has_value());
    // The deploy handler's effect: snapshot the member set and flip the lifecycle.
    auto members = h.baseline_store->get_members_checked(*live_id);
    REQUIRE(members.has_value());
    auto b = h.baseline_store->get_baseline(*live_id);
    REQUIRE(b.has_value());
    b->lifecycle = kBaselineDeployed;
    b->deployed_snapshot = json(*members).dump();
    b->deployed_by = "bob";
    REQUIRE(h.baseline_store->update_baseline(*b).has_value());
    return generation(h);
}

// One rule row and no Baseline: the server holds a rule but nothing deployed.
std::uint64_t seed_rule_without_deployed_baseline(RbacRoleHarness& h) {
    REQUIRE(h.guardian_store->create_rule(make_rule("r1")));
    return generation(h);
}

// One deployed Baseline with no member and no rule row at all.
std::uint64_t seed_deployed_baseline_without_rules(RbacRoleHarness& h) {
    Baseline live;
    live.name = "empty-deployed";
    live.created_by = "alice";
    live.updated_by = "alice";
    const auto live_id = h.baseline_store->create_baseline(live);
    REQUIRE(live_id.has_value());
    auto b = h.baseline_store->get_baseline(*live_id);
    REQUIRE(b.has_value());
    b->lifecycle = kBaselineDeployed;
    b->deployed_snapshot = "[]";
    b->deployed_by = "bob";
    REQUIRE(h.baseline_store->update_baseline(*b).has_value());
    return generation(h);
}

bool has_row_with_detail(const RbacRoleHarness& h, const std::string& result,
                         const std::string& detail_prefix) {
    for (const auto& a : rows_for_raise(h))
        if (a.result == result && a.detail.rfind(detail_prefix, 0) == 0)
            return true;
    return false;
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
        const auto r = guardian::parse_raise_request(populated_body(target));
        REQUIRE(r.has_value());
        CHECK(r->target == target);
        CHECK_FALSE(r->acknowledge_empty);
    }
    // An unsigned JSON integer within range parses the same way.
    const auto u = guardian::parse_raise_request(
        json::parse(R"({"target_generation":9007199254740991,"acknowledge_rule_set_replaced":true})"));
    REQUIRE(u.has_value());
    CHECK(u->target == kCeiling);
    // Fields this operation does not define are ignored.
    auto extra = populated_body(9);
    extra["approval_id"] = "x";
    extra["note"] = "free text";
    const auto e = guardian::parse_raise_request(extra);
    REQUIRE(e.has_value());
    CHECK(e->target == 9);
}

TEST_CASE("parse_raise_request reads the optional empty-rule-set acknowledgement; absent is false "
          "and a non-boolean is rejected",
          "[guardian][raise][parse]") {
    const auto absent = guardian::parse_raise_request(populated_body(5));
    REQUIRE(absent.has_value());
    CHECK_FALSE(absent->acknowledge_empty);

    auto yes = populated_body(5);
    yes["acknowledge_empty_rule_set"] = true;
    const auto t = guardian::parse_raise_request(yes);
    REQUIRE(t.has_value());
    CHECK(t->acknowledge_empty);
    CHECK(t->target == 5);

    auto no = populated_body(5);
    no["acknowledge_empty_rule_set"] = false;
    const auto f = guardian::parse_raise_request(no);
    REQUIRE(f.has_value());
    CHECK_FALSE(f->acknowledge_empty);

    for (const char* bad : {R"("true")", "1", "0", "null", "[]", "{}"}) {
        INFO("acknowledge_empty_rule_set=" << bad);
        auto body = populated_body(5);
        body["acknowledge_empty_rule_set"] = json::parse(bad);
        const auto r = guardian::parse_raise_request(body);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("acknowledge_empty_rule_set") != std::string::npos);
    }

    // The empty-set acknowledgement never substitutes for the replacement one.
    const auto only_empty = guardian::parse_raise_request(
        json{{"target_generation", 5}, {"acknowledge_empty_rule_set", true}});
    REQUIRE_FALSE(only_empty.has_value());
    CHECK(only_empty.error().find("acknowledge_rule_set_replaced") != std::string::npos);
}

TEST_CASE("raise_target_set_is_empty is true when either count is zero",
          "[guardian][raise][parse]") {
    CHECK(guardian::raise_target_set_is_empty(0, 0));
    CHECK(guardian::raise_target_set_is_empty(3, 0)); // rules exist, none deployed
    CHECK(guardian::raise_target_set_is_empty(0, 2));
    CHECK_FALSE(guardian::raise_target_set_is_empty(3, 1));
    CHECK(guardian::empty_rule_set_denied_detail(7, 3, 0) ==
          "empty rule set not acknowledged; rules=3; deployed_baselines=0; target=7");
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

    const auto empty = guardian::parse_raise_request(
        json{{"target_generation", 5},
             {"acknowledge_rule_set_replaced", true},
             {"acknowledge_empty_rule_set", "evil\nINJECT"}});
    REQUIRE_FALSE(empty.has_value());
    CHECK(empty.error().find("INJECT") == std::string::npos);
    for (const char c : empty.error())
        CHECK(static_cast<unsigned char>(c) >= 0x20);
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
    RaiseHarness h(GuardianStores::kBoth);
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

TEST_CASE("REST POST policy-generation/raise: the response counts every rule row and only the "
          "deployed Baselines",
          "[pg][rest][guardian][raise]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    const auto before = seed_rules_and_baselines(h);

    auto res = raise_rest(h, populated_body(static_cast<std::int64_t>(before) + 10));
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto body = json::parse(res->body);
    CHECK(body["data"]["rules"] == kSeededRules); // the disabled rule is counted
    CHECK(body["data"]["deployed_baselines"] == 1); // the draft Baseline is not counted
    CHECK(body["data"]["previous_generation"] == before);
    CHECK(body["data"]["generation"] == before + 10);
    const auto rows = rows_for_raise(h);
    REQUIRE(rows.size() == 2);
    const std::string rules_text = "rules=" + std::to_string(kSeededRules);
    CHECK(rows[0].detail.find(rules_text) != std::string::npos);
    CHECK(rows[0].detail.find("deployed_baselines=1") != std::string::npos);
    CHECK(rows[1].detail.find(rules_text + "; deployed_baselines=1") != std::string::npos);
}

TEST_CASE("REST POST policy-generation/raise: a stored value below zero is reported as previous 0",
          "[pg][rest][guardian][raise]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    run_sql(h, "UPDATE guaranteed_state_store.guardian_meta SET value = -5 "
               "WHERE key = 'policy_generation'");

    auto res = raise_rest(h, valid_body(10));
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto body = json::parse(res->body);
    CHECK(body["data"]["previous_generation"] == 0);
    CHECK(body["data"]["generation"] == 10);
    CHECK(body["data"]["raised"] == true);
}

TEST_CASE("REST POST policy-generation/raise: a target at or below the current generation is "
          "200 raised=false, changes nothing, fires no hook, counts unchanged",
          "[pg][rest][guardian][raise]") {
    RaiseHarness h(GuardianStores::kBoth);
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
    RaiseHarness h(GuardianStores::kBoth);
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
    RaiseHarness h(GuardianStores::kBoth);
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
          "MCP-tier bearer token are each denied 403 by their own gate, with no mutation",
          "[pg][rest][guardian][raise]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);

    // The administrator predicate also refuses each of these callers with a 403, so the audit
    // row's reason is what shows WHICH gate answered: deleting the dedicated gate would leave
    // the status unchanged and change only this text.
    SECTION("service-scoped token") {
        h.session_token_scope_service = "some-service";
        auto res = raise_rest(h, valid_body(9));
        REQUIRE(res);
        CHECK(res->status == 403);
        const auto body = json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK_FALSE(body["error"].contains("permission"));
        CHECK(has_row_with_detail(h, "denied",
                                  "service-scoped token blocked from Guardian policy generation "
                                  "raise"));
    }
    SECTION("engine session") {
        h.session_principal_kind = "engine";
        auto res = raise_rest(h, valid_body(9));
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(has_row_with_detail(h, "denied", "engine_session_denied"));
        // The denial names the resource it refused, like every other row of this action.
        for (const auto& a : rows_for_raise(h))
            CHECK(a.target_id == "policy_generation");
    }
    SECTION("MCP-tier bearer token") {
        h.rest_session_mcp_tier = "supervised";
        auto res = raise_rest(h, valid_body(9));
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(json::parse(res->body)["error"]["message"].get<std::string>().find(kTool) !=
              std::string::npos);
        CHECK(has_row_with_detail(h, "denied", "MCP token blocked from admin route"));
        for (const auto& a : rows_for_raise(h))
            CHECK(a.target_id == "policy_generation");
    }
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "attempted"));
    CHECK_FALSE(has_row(h, "success"));
    for (const char* r : {"applied", "unchanged", "refused", "failed"})
        CHECK(counter_value(h, "rest", r) == 0);
}

// -- REST: same-site gate for cookie sessions -----------------------------------------------

namespace {
bool has_csrf_denied_row(const RbacRoleHarness& h) {
    for (const auto& a : h.audit_log)
        if (a.action == "csrf.denied" && a.result == "denied")
            return true;
    return false;
}
} // namespace

TEST_CASE("REST POST policy-generation/raise: a cookie session with a cross-site Origin is "
          "refused 403 with a csrf.denied row and no mutation",
          "[pg][rest][guardian][raise][csrf]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://evil.example"}};

    auto res = raise_rest(h, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(json::parse(res->body)["error"]["message"] == "cross-site request refused");
    CHECK(has_csrf_denied_row(h));
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "attempted"));
    CHECK_FALSE(has_row(h, "success"));
    // The gate runs after the step-up and before anything is read or counted.
    CHECK(h.step_up_actions.size() == 1);
    for (const char* r : {"applied", "unchanged", "refused", "failed"})
        CHECK(counter_value(h, "rest", r) == 0);
}

TEST_CASE("REST POST policy-generation/raise: a cookie session with no Origin and no Referer is "
          "refused, a same-site Referer alone is accepted",
          "[pg][rest][guardian][raise][csrf]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);

    SECTION("neither header") {
        h.sink.default_headers = {{"Host", "yuzu.test"}};
        auto res = raise_rest(h, valid_body(42));
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(has_csrf_denied_row(h));
        CHECK(generation(h) == 0);
    }
    SECTION("same-site Referer only") {
        h.sink.default_headers = {{"Host", "yuzu.test"}, {"Referer", "https://yuzu.test/guardian"}};
        auto res = raise_rest(h, valid_body(42));
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_FALSE(has_csrf_denied_row(h));
        CHECK(generation(h) == 42);
    }
}

TEST_CASE("REST POST policy-generation/raise: an api_token session is exempt from the same-site "
          "gate even with a foreign Origin",
          "[pg][rest][guardian][raise][csrf]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    h.session_auth_source = "api_token";
    h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://evil.example"}};

    auto res = raise_rest(h, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(has_csrf_denied_row(h));
    CHECK(generation(h) == 42);
}

TEST_CASE("REST POST policy-generation/raise: the same-site gate runs before the body is read, so a "
          "cross-site request with a malformed body is 403, not 400",
          "[pg][rest][guardian][raise][csrf]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://evil.example"}};

    const std::vector<std::string> bodies = {
        "not json",
        "[]",
        R"({"target_generation":5})",
        R"({"target_generation":"7","acknowledge_rule_set_replaced":true})",
        R"({"acknowledge_rule_set_replaced":true})",
    };
    for (const auto& b : bodies) {
        INFO("body=" << b);
        auto res = h.sink.Post(kRoute, b);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(json::parse(res->body)["error"]["message"] == "cross-site request refused");
    }
    std::size_t csrf_rows = 0;
    for (const auto& a : h.audit_log)
        if (a.action == "csrf.denied" && a.result == "denied")
            ++csrf_rows;
    CHECK(csrf_rows == bodies.size());
    // Nothing downstream of the gate ran: no raise audit row of any kind, no counter movement
    // (a body refusal would have counted as refused), no mutation.
    CHECK(rows_for_raise(h).empty());
    CHECK_FALSE(has_row(h, "attempted"));
    for (const char* r : {"applied", "unchanged", "refused", "failed"})
        CHECK(counter_value(h, "rest", r) == 0);
    CHECK(generation(h) == 0);
}

TEST_CASE("REST POST policy-generation/raise: a foreign Origin proceeds only when it is a configured "
          "trusted origin",
          "[pg][rest][guardian][raise][csrf]") {
    const std::vector<std::string> configured =
        normalise_trusted_origins(std::vector<std::string>{"https://proxy.example"});

    SECTION("a configured trusted origin behind a Host-rewriting proxy proceeds") {
        RaiseHarness h(GuardianStores::kBoth, configured);
        admin_caller(h);
        h.sink.default_headers = {{"Host", "internal.test:8080"},
                                  {"Origin", "https://proxy.example"}};
        auto res = raise_rest(h, valid_body(42));
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_FALSE(has_csrf_denied_row(h));
        CHECK(generation(h) == 42);
    }
    SECTION("an untrusted foreign origin is still refused when others are configured") {
        RaiseHarness h(GuardianStores::kBoth, configured);
        admin_caller(h);
        h.sink.default_headers = {{"Host", "internal.test:8080"},
                                  {"Origin", "https://other.example"}};
        auto res = raise_rest(h, valid_body(42));
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(has_csrf_denied_row(h));
        CHECK(generation(h) == 0);
    }
    SECTION("the same origin is refused when no trusted origin is configured") {
        RaiseHarness h(GuardianStores::kBoth);
        admin_caller(h);
        h.sink.default_headers = {{"Host", "internal.test:8080"},
                                  {"Origin", "https://proxy.example"}};
        auto res = raise_rest(h, valid_body(42));
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(has_csrf_denied_row(h));
        CHECK(generation(h) == 0);
    }
}

TEST_CASE("REST POST policy-generation/raise: an api_token session with no Origin and no Referer "
          "proceeds",
          "[pg][rest][guardian][raise][csrf]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    h.session_auth_source = "api_token";
    h.sink.default_headers = {{"Host", "yuzu.test"}};

    auto res = raise_rest(h, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(has_csrf_denied_row(h));
    CHECK(generation(h) == 42);
}

TEST_CASE("REST POST policy-generation/raise: a non-administrator with a cross-site Origin learns "
          "only the administrator denial",
          "[pg][rest][guardian][raise][csrf]") {
    RaiseHarness h(GuardianStores::kBoth);
    REQUIRE(h.auth_db->upsert_user("plainuser", "hash", "salt", auth::Role::user).has_value());
    h.session_user = "plainuser";
    h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://evil.example"}};

    auto res = raise_rest(h, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(json::parse(res->body)["error"]["message"] != "cross-site request refused");
    CHECK_FALSE(has_csrf_denied_row(h));
    CHECK(has_row_with_detail(h, "denied", std::string(kRbacAdminGateDeniedAuditReason)));
}

// -- REST and MCP: the fresh regime re-check and gate degradation -----------------------------

TEST_CASE("REST POST policy-generation/raise: a caller whose Administrator grant belongs to a "
          "deactivated account is refused by the fresh regime check",
          "[pg][rest][guardian][raise][a2]") {
    RaiseHarness h(GuardianStores::kBoth);
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.auth_db->upsert_user(h.session_user, "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE(h.auth_db->remove_user(h.session_user).has_value()); // deactivate

    auto res = raise_rest(h, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(has_row_with_detail(h, "denied", "caller does not hold authority under the regime"));
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "attempted"));
    CHECK(h.step_up_actions.empty());
}

TEST_CASE("REST POST policy-generation/raise: an RBAC-on Administrator with an active account "
          "passes both administrator checks",
          "[pg][rest][guardian][raise][a2]") {
    RaiseHarness h(GuardianStores::kBoth);
    h.make_caller_admin(/*rbac_on=*/true);

    auto res = raise_rest(h, valid_body(42));
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(generation(h) == 42);
}

TEST_CASE("REST POST policy-generation/raise: an administrator gate that cannot confirm is 503 "
          "with an audited denial, the same for the fresh regime read",
          "[pg][rest][guardian][raise][a2]") {
    RaiseHarness h(GuardianStores::kBoth);
    h.make_caller_admin(/*rbac_on=*/true);

    SECTION("is_rbac_administrator cannot read the grants") {
        run_sql(h, "DROP TABLE rbac_store.principal_roles CASCADE");
        auto res = raise_rest(h, valid_body(42));
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(has_row_with_detail(h, "denied", std::string(kRbacAdminGateUnavailableAuditReason)));
    }
    SECTION("the fresh regime read cannot join auth.users") {
        run_sql(h, "DROP TABLE auth.users CASCADE");
        auto res = raise_rest(h, valid_body(42));
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(has_row_with_detail(
            h, "denied", std::string(kRbacRegimeAuthorityUnavailableAuditReason)));
    }
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "attempted"));
    CHECK(h.step_up_actions.empty());
}

TEST_CASE("REST POST policy-generation/raise: a missing or failed MFA step-up is refused before "
          "anything is read or changed",
          "[pg][rest][guardian][raise]") {
    RaiseHarness h(GuardianStores::kBoth);
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
          "acknowledgement, a non-boolean empty-set acknowledgement and an out-of-range target "
          "are 400 with no mutation",
          "[pg][rest][guardian][raise]") {
    RaiseHarness h(GuardianStores::kBoth);
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
        R"({"target_generation":5,"acknowledge_rule_set_replaced":true,"acknowledge_empty_rule_set":"true"})",
        R"({"target_generation":5,"acknowledge_rule_set_replaced":true,"acknowledge_empty_rule_set":1})",
        R"({"target_generation":5,"acknowledge_rule_set_replaced":true,"acknowledge_empty_rule_set":null})",
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

// -- REST: the second acknowledgement for an empty rule set ---------------------------------

TEST_CASE("REST POST policy-generation/raise: a server holding no rules refuses a raise without "
          "acknowledge_empty_rule_set; 400, a denied row, no attempted row, nothing changes",
          "[pg][rest][guardian][raise][empty]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    int hook_fired = 0;
    h.guardian_store->set_on_rule_mutation([&] { ++hook_fired; });

    for (const char* shape : {"absent", "false"}) {
        INFO("acknowledge_empty_rule_set=" << shape);
        auto body = populated_body(42);
        if (std::string(shape) == "false")
            body["acknowledge_empty_rule_set"] = false;
        auto res = raise_rest(h, body);
        REQUIRE(res);
        CHECK(res->status == 400);
        const auto envelope = json::parse(res->body);
        const std::string message = json_step(json_step(envelope, "error"), "message");
        CHECK(message.find("no deployed rules") != std::string::npos);
        CHECK(message.find("zero guards") != std::string::npos);
        CHECK(message.find("acknowledge_empty_rule_set: true") != std::string::npos);
    }
    CHECK(generation(h) == 0);
    CHECK(hook_fired == 0);
    CHECK_FALSE(has_row(h, "attempted"));
    CHECK_FALSE(has_row(h, "success"));
    const auto rows = rows_for_raise(h);
    REQUIRE(rows.size() == 2);
    for (const auto& r : rows) {
        CHECK(r.result == "denied");
        CHECK(r.detail ==
              "empty rule set not acknowledged; rules=0; deployed_baselines=0; target=42");
    }
    CHECK(counter_value(h, "rest", "refused") == 2);
    CHECK(counter_value(h, "rest", "applied") == 0);
    CHECK(counter_value(h, "rest", "failed") == 0);

    // The same request carrying the acknowledgement proceeds.
    auto ok = raise_rest(h, valid_body(42));
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(json::parse(ok->body)["data"]["raised"] == true);
    CHECK(generation(h) == 42);
    CHECK(has_row(h, "attempted"));
    CHECK(counter_value(h, "rest", "applied") == 1);
}

TEST_CASE("REST POST policy-generation/raise: rules with no deployed Baseline are refused too, "
          "and so are a deployed Baseline with no rules",
          "[pg][rest][guardian][raise][empty]") {
    SECTION("rules exist, none deployed") {
        RaiseHarness h(GuardianStores::kBoth);
        admin_caller(h);
        const auto before = seed_rule_without_deployed_baseline(h);
        auto res = raise_rest(h, populated_body(static_cast<std::int64_t>(before) + 10));
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(generation(h) == before);
        CHECK_FALSE(has_row(h, "attempted"));
        CHECK(has_row_with_detail(h, "denied",
                                  "empty rule set not acknowledged; rules=1; deployed_baselines=0"));
        CHECK(counter_value(h, "rest", "refused") == 1);

        auto ok = raise_rest(h, valid_body(static_cast<std::int64_t>(before) + 10));
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK(generation(h) == before + 10);
    }
    SECTION("a deployed Baseline exists, no rule row does") {
        RaiseHarness h(GuardianStores::kBoth);
        admin_caller(h);
        const auto before = seed_deployed_baseline_without_rules(h);
        auto res = raise_rest(h, populated_body(static_cast<std::int64_t>(before) + 10));
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(generation(h) == before);
        CHECK_FALSE(has_row(h, "attempted"));
        CHECK(has_row_with_detail(h, "denied",
                                  "empty rule set not acknowledged; rules=0; deployed_baselines=1"));
        CHECK(counter_value(h, "rest", "refused") == 1);
    }
}

TEST_CASE("REST POST policy-generation/raise: a server holding a deployed rule set raises "
          "without acknowledge_empty_rule_set, and the flag changes nothing there",
          "[pg][rest][guardian][raise][empty]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    const auto before = seed_rules_and_baselines(h);
    auto res = raise_rest(h, populated_body(static_cast<std::int64_t>(before) + 10));
    REQUIRE(res);
    CHECK(res->status == 200);
    auto flagged = raise_rest(h, valid_body(static_cast<std::int64_t>(before) + 20));
    REQUIRE(flagged);
    CHECK(flagged->status == 200);
    CHECK(generation(h) == before + 20);
    CHECK(counter_value(h, "rest", "refused") == 0);
    for (const auto& r : rows_for_raise(h))
        CHECK(r.result != "denied");
}

// -- REST: audit fail-closed ---------------------------------------------------------------

TEST_CASE("REST POST policy-generation/raise: when the attempted audit row cannot be stored the "
          "request is 503 with Sec-Audit-Failed and NOTHING is changed",
          "[pg][rest][guardian][raise][audit_failclose]") {
    RaiseHarness h(GuardianStores::kBoth);
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
    RaiseHarness h(GuardianStores::kBoth);
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
    RaiseHarness h(GuardianStores::kBoth);
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
    RaiseHarness h(GuardianStores::kBoth);
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
    // A lost commit acknowledgement can hide a committed change, so the response claims
    // neither outcome and says a repeat is safe.
    const auto message = json::parse(res->body)["error"]["message"].get<std::string>();
    CHECK(message.find("unconfirmed") != std::string::npos);
    CHECK(message.find("idempotent") != std::string::npos);
    CHECK(message.find("was not changed") == std::string::npos);
    CHECK(has_row_with_detail(h, "failure", "policy generation store unavailable; target=42"));
    CHECK(rows_for_raise(h).back().detail.find("unconfirmed") != std::string::npos);

    run_sql(h, "ALTER TABLE guaranteed_state_store.guardian_meta_off RENAME TO guardian_meta");
    CHECK(generation(h) == 0);
}

TEST_CASE("REST POST policy-generation/raise: a missing Baseline store is 503 with no mutation",
          "[pg][rest][guardian][raise]") {
    RaiseHarness h(GuardianStores::kGuardianOnly);
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
    RaiseHarness h(GuardianStores::kBoth);
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
    RaiseHarness h(GuardianStores::kBoth);
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
    RaiseHarness h(GuardianStores::kBoth);
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
    RaiseHarness h(GuardianStores::kBoth);

    SECTION("non-administrator") {
        REQUIRE(h.auth_db->upsert_user("plainuser", "hash", "salt", auth::Role::user).has_value());
        h.session_user = "plainuser";
        auto res = h.mcp_call_tool_approved(kTool, valid_body(42));
        REQUIRE(res);
        const auto body = json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == mcp::kPermissionDenied);
        CHECK(has_row_with_detail(h, "denied", std::string(kRbacAdminGateDeniedAuditReason)));
    }
    SECTION("engine session") {
        admin_caller(h);
        h.session_principal_kind = "engine";
        auto res = h.mcp_call_tool_approved(kTool, valid_body(42));
        REQUIRE(res);
        const auto body = json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == mcp::kPermissionDenied);
        CHECK(has_row_with_detail(h, "denied", std::string(kRbacAdminGateDeniedAuditReason)));
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

TEST_CASE("MCP raise_guardian_policy_generation: a missing acknowledgement, a non-boolean "
          "empty-set acknowledgement or an out-of-range target is rejected with no ticket, no "
          "mutation and no success row",
          "[pg][mcp][guardian][raise]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    const std::vector<json> bad = {
        json{{"target_generation", 5}},
        json{{"target_generation", 5}, {"acknowledge_rule_set_replaced", false}},
        json{{"target_generation", 0}, {"acknowledge_rule_set_replaced", true}},
        json{{"target_generation", kCeiling + 1}, {"acknowledge_rule_set_replaced", true}},
        json{{"target_generation", "5"}, {"acknowledge_rule_set_replaced", true}},
        json{{"acknowledge_rule_set_replaced", true}},
        json{{"target_generation", 5},
             {"acknowledge_rule_set_replaced", true},
             {"acknowledge_empty_rule_set", "yes"}},
        json{{"target_generation", 5},
             {"acknowledge_rule_set_replaced", true},
             {"acknowledge_empty_rule_set", 1}},
    };
    for (const auto& args : bad) {
        INFO("args=" << args.dump());
        auto res = h.mcp_call_tool(kTool, args);
        REQUIRE(res);
        const auto body = json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == mcp::kInvalidParams);
    }
    CHECK(h.appr->pending_count() == 0);
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "success"));
}

TEST_CASE("MCP raise_guardian_policy_generation: a server holding no rules refuses a raise "
          "without acknowledge_empty_rule_set with -32602 AFTER the approval ticket is consumed; "
          "nothing is mutated",
          "[pg][mcp][guardian][raise][empty]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    int hook_fired = 0;
    h.guardian_store->set_on_rule_mutation([&] { ++hook_fired; });

    const auto args = populated_body(42);
    const std::string approval_id = h.mcp_mint_and_approve(kTool, args);
    {
        const auto ticket = h.appr->get(approval_id);
        REQUIRE(ticket.has_value());
        CHECK(ticket->consumed_at == 0); // minted and approved, not yet spent
    }
    json recall = args;
    recall["approval_id"] = approval_id;
    auto res = h.mcp_call_tool(kTool, recall);
    REQUIRE(res);
    const auto body = json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == mcp::kInvalidParams);
    const std::string message = body["error"]["message"];
    CHECK(message.find("no deployed rules") != std::string::npos);
    CHECK(message.find("zero guards") != std::string::npos);
    CHECK(message.find("acknowledge_empty_rule_set: true") != std::string::npos);

    // The C8 gate spends the one-time ticket before the handler runs.
    const auto spent = h.appr->get(approval_id);
    REQUIRE(spent.has_value());
    CHECK(spent->consumed_at != 0);

    CHECK(generation(h) == 0);
    CHECK(hook_fired == 0);
    CHECK_FALSE(has_row(h, "attempted"));
    CHECK_FALSE(has_row(h, "success"));
    CHECK(has_row_with_detail(
        h, "denied", "empty rule set not acknowledged; rules=0; deployed_baselines=0; target=42"));
    CHECK(counter_value(h, "mcp", "refused") == 1);
    CHECK(counter_value(h, "mcp", "applied") == 0);
    CHECK(counter_value(h, "mcp", "failed") == 0);

    // With the acknowledgement (a fresh ticket) the same raise proceeds.
    auto ok = h.mcp_call_tool_approved(kTool, valid_body(42));
    REQUIRE(ok);
    REQUIRE_FALSE(json::parse(ok->body).contains("error"));
    CHECK(generation(h) == 42);
    CHECK(counter_value(h, "mcp", "applied") == 1);
}

TEST_CASE("MCP raise_guardian_policy_generation: rules with no deployed Baseline are refused "
          "too; a deployed rule set raises without the flag",
          "[pg][mcp][guardian][raise][empty]") {
    SECTION("rules exist, none deployed") {
        RaiseHarness h(GuardianStores::kBoth);
        admin_caller(h);
        const auto before = seed_rule_without_deployed_baseline(h);
        auto res = h.mcp_call_tool_approved(
            kTool, populated_body(static_cast<std::int64_t>(before) + 10));
        REQUIRE(res);
        const auto body = json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == mcp::kInvalidParams);
        CHECK(generation(h) == before);
        CHECK_FALSE(has_row(h, "attempted"));
        CHECK(has_row_with_detail(h, "denied",
                                  "empty rule set not acknowledged; rules=1; deployed_baselines=0"));
        CHECK(counter_value(h, "mcp", "refused") == 1);
    }
    SECTION("a deployed rule set raises without the flag") {
        RaiseHarness h(GuardianStores::kBoth);
        admin_caller(h);
        const auto before = seed_rules_and_baselines(h);
        auto res = h.mcp_call_tool_approved(
            kTool, populated_body(static_cast<std::int64_t>(before) + 10));
        REQUIRE(res);
        REQUIRE_FALSE(json::parse(res->body).contains("error"));
        CHECK(generation(h) == before + 10);
        CHECK(counter_value(h, "mcp", "refused") == 0);
    }
}

TEST_CASE("MCP raise_guardian_policy_generation: when the attempted audit row cannot be stored "
          "the call fails with audit_persisted=false and NOTHING is changed",
          "[pg][mcp][guardian][raise][audit_failclose]") {
    RaiseHarness h(GuardianStores::kBoth);
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
    RaiseHarness h(GuardianStores::kBoth);
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
    const auto message = body["error"]["message"].get<std::string>();
    CHECK(message.find("took effect") != std::string::npos);
    // No read exists to reconcile through: the instruction is to repeat the idempotent request.
    CHECK(message.find("repeat the same request") != std::string::npos);
    CHECK(message.find("a read") == std::string::npos);
    const std::string remediation = body["error"]["data"]["remediation"].get<std::string>();
    CHECK(remediation.find("repeat the same request") != std::string::npos);
    CHECK(remediation.find("do not retry") == std::string::npos);
    CHECK(generation(h) == 42);
}

TEST_CASE("MCP raise_guardian_policy_generation: a store that cannot write the counter, and a "
          "missing Baseline store, each fail with no mutation",
          "[pg][mcp][guardian][raise]") {
    SECTION("counter table unreadable") {
        RaiseHarness h(GuardianStores::kBoth);
        admin_caller(h);
        run_sql(h, "ALTER TABLE guaranteed_state_store.guardian_meta RENAME TO guardian_meta_off");
        auto res = h.mcp_call_tool_approved(kTool, valid_body(42));
        REQUIRE(res);
        CHECK(json::parse(res->body).contains("error"));
        CHECK(has_row(h, "failure"));
        CHECK_FALSE(has_row(h, "success"));
        CHECK(counter_value(h, "mcp", "failed") == 1);
        const auto message =
            json::parse(res->body)["error"]["message"].get<std::string>();
        CHECK(message.find("unconfirmed") != std::string::npos);
        CHECK(message.find("idempotent") != std::string::npos);
        run_sql(h, "ALTER TABLE guaranteed_state_store.guardian_meta_off RENAME TO guardian_meta");
        CHECK(generation(h) == 0);
    }
    SECTION("rule count unreadable") {
        RaiseHarness h(GuardianStores::kBoth);
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
        RaiseHarness h(GuardianStores::kGuardianOnly);
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
    RaiseHarness h(GuardianStores::kBoth);
    auto res = h.mcp_call(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const auto body = json::parse(res->body, nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(body.is_discarded());
    const json& tools = json_step(json_step(body, "result"), "tools");
    REQUIRE(tools.is_array());
    const json* tool = nullptr;
    for (const auto& t : tools) {
        if (t.is_object() && t.contains("name") && t.at("name") == kTool)
            tool = &t;
    }
    REQUIRE(tool != nullptr);
    const json& t = *tool;
    const json& annotations = json_step(t, "annotations");
    CHECK(json_step(annotations, "destructiveHint") == true);
    CHECK(json_step(annotations, "idempotentHint") == true);
    CHECK(json_step(annotations, "readOnlyHint") == false);
    CHECK(json_step(annotations, "openWorldHint") == false);
    const json& schema = json_step(t, "inputSchema");
    const json& props = json_step(schema, "properties");
    CHECK(json_step(json_step(props, "target_generation"), "minimum") == 1);
    CHECK(json_step(json_step(props, "target_generation"), "maximum") == kCeiling);
    const json& ack_enum = json_step(json_step(props, "acknowledge_rule_set_replaced"), "enum");
    REQUIRE(ack_enum.is_array());
    REQUIRE(ack_enum.size() == 1);
    CHECK(ack_enum.at(0) == true);
    // The empty-set acknowledgement is optional: declared as a boolean, not required.
    CHECK(json_step(json_step(props, "acknowledge_empty_rule_set"), "type") == "boolean");
    // The prose names the same ceiling as the schema.
    const json& description = json_step(t, "description");
    REQUIRE(description.is_string());
    CHECK(description.get<std::string>().find(std::to_string(kCeiling)) != std::string::npos);
    // The rules figure counts every rule row; only enabled members of deployed Baselines
    // reach agents, and the schema says so.
    const json& rules_desc = json_step(
        json_step(json_step(json_step(t, "outputSchema"), "properties"), "rules"), "description");
    REQUIRE(rules_desc.is_string());
    CHECK(rules_desc.get<std::string>().find("enabled") != std::string::npos);
    const json& required = json_step(schema, "required");
    REQUIRE(required.is_array());
    CHECK(required.size() == 2);
}

TEST_CASE("MCP raise_guardian_policy_generation: the result counts every rule row and only the "
          "deployed Baselines",
          "[pg][mcp][guardian][raise]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    const auto before = seed_rules_and_baselines(h);

    auto res =
        h.mcp_call_tool_approved(kTool, populated_body(static_cast<std::int64_t>(before) + 10));
    REQUIRE(res);
    const auto body = json::parse(res->body);
    REQUIRE_FALSE(body.contains("error"));
    const auto sc = body["result"]["structuredContent"];
    CHECK(sc["rules"] == kSeededRules); // the disabled rule is counted
    CHECK(sc["deployed_baselines"] == 1); // the draft Baseline is not counted
    CHECK(sc["previous_generation"] == before);
    CHECK(has_row_with_detail(h, "success", "target="));
    CHECK(rows_for_raise(h)[0].detail.find("rules=" + std::to_string(kSeededRules) +
                                           "; deployed_baselines=1") != std::string::npos);
}

TEST_CASE("MCP raise_guardian_policy_generation: a caller whose Administrator grant belongs to a "
          "deactivated account is refused by the fresh regime check",
          "[pg][mcp][guardian][raise][a2]") {
    RaiseHarness h(GuardianStores::kBoth);
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.auth_db->upsert_user(h.session_user, "hash", "salt", auth::Role::user).has_value());
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE(h.auth_db->remove_user(h.session_user).has_value()); // deactivate

    auto res = h.mcp_call_tool_approved(kTool, valid_body(42));
    REQUIRE(res);
    const auto body = json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == mcp::kPermissionDenied);
    CHECK(has_row_with_detail(h, "denied", "caller does not hold authority under the regime"));
    CHECK(generation(h) == 0);
    CHECK_FALSE(has_row(h, "attempted"));
}

TEST_CASE("MCP raise_guardian_policy_generation: an administrator gate that cannot confirm is an "
          "internal error with an audited denial, the same for the fresh regime read",
          "[pg][mcp][guardian][raise][a2]") {
    RaiseHarness h(GuardianStores::kBoth);
    h.make_caller_admin(/*rbac_on=*/true);

    SECTION("is_rbac_administrator cannot read the grants") {
        run_sql(h, "DROP TABLE rbac_store.principal_roles CASCADE");
        auto res = h.mcp_call_tool_approved(kTool, valid_body(42));
        REQUIRE(res);
        const auto body = json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == mcp::kInternalError);
        CHECK(has_row_with_detail(h, "denied", std::string(kRbacAdminGateUnavailableAuditReason)));
    }
    SECTION("the fresh regime read cannot join auth.users") {
        run_sql(h, "DROP TABLE auth.users CASCADE");
        auto res = h.mcp_call_tool_approved(kTool, valid_body(42));
        REQUIRE(res);
        const auto body = json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == mcp::kInternalError);
        CHECK(has_row_with_detail(
            h, "denied", std::string(kRbacRegimeAuthorityUnavailableAuditReason)));
    }
    CHECK_FALSE(has_row(h, "attempted"));
}

// -- the harness audit seam the audit_failclose tests above depend on -----------------------

TEST_CASE("RbacRoleHarness audit seam: a row is dropped only by audit_allow or an equal "
          "audit_fail_result, never because its own result is empty",
          "[pg][guardian][raise][harness]") {
    RaiseHarness h(GuardianStores::kBoth);
    CHECK(h.audit_persists(""));
    CHECK(h.audit_persists("attempted"));

    h.audit_fail_result = "attempted";
    CHECK_FALSE(h.audit_persists("attempted"));
    CHECK(h.audit_persists("success"));
    CHECK(h.audit_persists(""));

    h.audit_fail_result.clear();
    h.audit_allow = false;
    CHECK_FALSE(h.audit_persists(""));
    CHECK_FALSE(h.audit_persists("success"));
}

// -- OpenAPI and MCP prose name the same ceiling as the code --------------------------------

TEST_CASE("the OpenAPI entry for the raise route bounds target_generation at the code's ceiling",
          "[guardian][raise][openapi]") {
    const json spec = json::parse(openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    const auto step = json_step;
    const json& paths = step(spec, "paths");
    const json& route = step(paths, "/guaranteed-state/policy-generation/raise");
    const json& entry = step(route, "post");
    REQUIRE(entry.is_object());
    const json& body_content = step(step(entry, "requestBody"), "content");
    const json& schema = step(step(body_content, "application/json"), "schema");
    const json& target = step(step(schema, "properties"), "target_generation");
    CHECK(step(target, "maximum") == kCeiling);
    CHECK(step(target, "minimum") == 1);
    // The prose names the same number, formatted from the constant.
    REQUIRE(step(entry, "description").is_string());
    CHECK(entry.at("description").get<std::string>().find(std::to_string(kCeiling)) !=
          std::string::npos);
}

// -- The read-only twin: GET policy-generation and MCP get_guardian_policy_generation ---------

namespace {

constexpr const char* kReadRoute = "/api/v1/guaranteed-state/policy-generation";
constexpr const char* kReadTool = "get_guardian_policy_generation";

auto read_rest(RbacRoleHarness& h) { return h.sink.Get(kReadRoute); }

auto read_mcp(RbacRoleHarness& h) { return h.mcp_call_tool(kReadTool, json::object()); }

// The generation the REST read reports, after checking the response is a 200.
std::uint64_t rest_read_value(RbacRoleHarness& h) {
    auto res = read_rest(h);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    const auto body = json::parse(res->body);
    return json_step(json_step(body, "data"), "generation").get<std::uint64_t>();
}

// The generation the MCP read reports, after checking the call succeeded.
std::uint64_t mcp_read_value(RbacRoleHarness& h) {
    auto res = read_mcp(h);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    const auto body = json::parse(res->body);
    REQUIRE_FALSE(body.contains("error"));
    return json_step(json_step(json_step(body, "result"), "structuredContent"), "generation")
        .get<std::uint64_t>();
}

} // namespace

TEST_CASE("generation_read_json shapes the shared body and maps a value above INT64_MAX to 0",
          "[guardian][raise][parse][read]") {
    const auto j = guardian::generation_read_json(7);
    CHECK(j["generation"] == 7);
    CHECK(j["ceiling"] == kCeiling);
    CHECK(j.size() == 2);
    CHECK(guardian::generation_read_json(0)["generation"] == 0);
    CHECK(guardian::generation_read_json(static_cast<std::uint64_t>(kCeiling))["generation"] ==
          kCeiling);
    // The pure guard: the unsigned form of a negative is never echoed as a generation. The
    // store never produces one (it reports a negative stored value as a degraded read), so
    // this pins the function, not a reachable read.
    CHECK(guardian::generation_read_json(static_cast<std::uint64_t>(std::int64_t{-5}))
              ["generation"] == 0);
    CHECK(guardian::generation_read_json(
              static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))["generation"] ==
          std::numeric_limits<std::int64_t>::max());
}

TEST_CASE("REST GET policy-generation: a fresh store reports 0 with the ceiling, writes no audit "
          "row and asks for no step-up",
          "[pg][rest][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    std::vector<std::pair<std::string, std::string>> gates;
    h.perm_override = [&](const std::string& type, const std::string& op) {
        gates.emplace_back(type, op);
        return true;
    };
    auto res = read_rest(h);
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto body = json::parse(res->body);
    CHECK(json_step(json_step(body, "data"), "generation") == 0);
    CHECK(json_step(json_step(body, "data"), "ceiling") == kCeiling);
    CHECK(json_step(body, "data").size() == 2);
    CHECK(h.audit_log.empty());
    CHECK(h.step_up_actions.empty());
    // The gate asked is GuaranteedState:Read, the neighbour catalogue reads' pair.
    REQUIRE(gates.size() == 1);
    CHECK(gates[0] == std::make_pair(std::string("GuaranteedState"), std::string("Read")));
}

TEST_CASE("REST GET policy-generation: the value follows rule bumps and a raise exactly",
          "[pg][rest][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    const auto after_seed = seed_rules_and_baselines(h);
    CHECK(after_seed > 0);
    CHECK(rest_read_value(h) == after_seed);

    auto raised = raise_rest(h, populated_body(static_cast<std::int64_t>(after_seed) + 10));
    REQUIRE(raised);
    REQUIRE(raised->status == 200);
    CHECK(rest_read_value(h) == after_seed + 10);

    // A rule write after the raise bumps by one, and the read sees it.
    REQUIRE(h.guardian_store->create_rule(make_rule("r-after")));
    CHECK(rest_read_value(h) == after_seed + 11);
    CHECK(rest_read_value(h) == generation(h));
}

TEST_CASE("REST GET policy-generation: a stored value below zero is a retryable 503, never a "
          "number, and a raise repairs it",
          "[pg][rest][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    run_sql(h, "UPDATE guaranteed_state_store.guardian_meta SET value = -5 "
               "WHERE key = 'policy_generation'");

    auto res = read_rest(h);
    REQUIRE(res);
    CHECK(res->status == 503);
    const auto body = json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK_FALSE(body.contains("data"));
    CHECK(json_step(json_step(body, "error"), "retry_after_ms") == mcp::kMcpStoreFaultRetryMs);
    CHECK_FALSE(h.guardian_store->current_policy_generation().has_value());

    // The raise is the repair: it reports previous 0 and lands on the target.
    auto raised = raise_rest(h, valid_body(10));
    REQUIRE(raised);
    CHECK(raised->status == 200);
    CHECK(json::parse(raised->body)["data"]["previous_generation"] == 0);
    CHECK(rest_read_value(h) == 10);
}

TEST_CASE("REST GET policy-generation: a caller without GuaranteedState:Read is denied 403 and "
          "learns no value",
          "[pg][rest][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    REQUIRE(raise_rest(h, valid_body(4321))->status == 200);
    h.perm_override = [](const std::string& type, const std::string& op) {
        return !(type == "GuaranteedState" && op == "Read");
    };
    auto res = read_rest(h);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("4321") == std::string::npos);
    CHECK(res->body.find("generation") == std::string::npos);
}

TEST_CASE("REST GET policy-generation: a service-scoped token is denied 403 with an audit row and "
          "learns no value",
          "[pg][rest][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    REQUIRE(raise_rest(h, valid_body(4321))->status == 200);
    h.audit_log.clear();
    h.session_token_scope_service = "some-service";
    auto res = read_rest(h);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("4321") == std::string::npos);
    bool denied_row = false;
    for (const auto& a : h.audit_log)
        if (a.action == "guaranteed_state.policy_generation.read" && a.result == "denied" &&
            a.target_id == "policy_generation")
            denied_row = true;
    CHECK(denied_row);
}

TEST_CASE("REST GET policy-generation: an unauthenticated request learns no value",
          "[pg][rest][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    REQUIRE(raise_rest(h, valid_body(4321))->status == 200);
    h.auth_enabled = false;
    auto res = read_rest(h);
    REQUIRE(res);
    CHECK(res->body.find("4321") == std::string::npos);
    CHECK(res->body.find("generation") == std::string::npos);
}

TEST_CASE("REST GET policy-generation: a degraded store is 503 with retry_after_ms, never 0",
          "[pg][rest][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    run_sql(h, "ALTER TABLE guaranteed_state_store.guardian_meta RENAME TO guardian_meta_off");
    auto res = read_rest(h);
    REQUIRE(res);
    CHECK(res->status == 503);
    const auto body = json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK_FALSE(body.contains("data"));
    CHECK(json_step(json_step(body, "error"), "retry_after_ms") == mcp::kMcpStoreFaultRetryMs);
    CHECK(h.audit_log.empty());
    run_sql(h, "ALTER TABLE guaranteed_state_store.guardian_meta_off RENAME TO guardian_meta");
    CHECK(rest_read_value(h) == 0);
}

TEST_CASE("REST GET policy-generation: a route with no Guardian store is 503 with no value",
          "[pg][rest][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kNone);
    auto res = read_rest(h);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("\"data\"") == std::string::npos);
}

TEST_CASE("MCP get_guardian_policy_generation: needs no approval ticket and reports the value; "
          "REST and MCP agree after a bump and a raise",
          "[pg][mcp][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    auto first = read_mcp(h);
    REQUIRE(first);
    const auto fresh = json::parse(first->body);
    REQUIRE_FALSE(fresh.contains("error"));
    const auto sc = json_step(json_step(fresh, "result"), "structuredContent");
    CHECK(json_step(sc, "generation") == 0);
    CHECK(json_step(sc, "ceiling") == kCeiling);
    CHECK(sc.size() == 2);
    CHECK(h.appr->pending_count() == 0);

    const auto after_seed = seed_rules_and_baselines(h);
    CHECK(mcp_read_value(h) == after_seed);
    CHECK(mcp_read_value(h) == rest_read_value(h));
    REQUIRE(h.mcp_call_tool_approved(kTool,
                                     populated_body(static_cast<std::int64_t>(after_seed) + 7))
                ->status == 200);
    CHECK(mcp_read_value(h) == after_seed + 7);
    CHECK(mcp_read_value(h) == rest_read_value(h));
    CHECK(mcp_read_value(h) == generation(h));
}

TEST_CASE("MCP get_guardian_policy_generation: a caller without GuaranteedState:Read, an unknown "
          "tier and a service-scoped token are each denied and learn no value",
          "[pg][mcp][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    REQUIRE(h.mcp_call_tool_approved(kTool, valid_body(4321))->status == 200);
    SECTION("no permission") {
        h.perm_override = [](const std::string& type, const std::string& op) {
            return !(type == "GuaranteedState" && op == "Read");
        };
        auto res = read_mcp(h);
        REQUIRE(res);
        CHECK(res->body.find("4321") == std::string::npos);
        CHECK(res->body.find("structuredContent") == std::string::npos);
    }
    SECTION("unknown tier") {
        h.session_mcp_tier = "bogus";
        auto res = read_mcp(h);
        REQUIRE(res);
        const auto body = json::parse(res->body);
        REQUIRE(body.contains("error"));
        CHECK(body["error"]["code"] == mcp::kTierDenied);
        CHECK(res->body.find("4321") == std::string::npos);
    }
    SECTION("service-scoped token") {
        h.audit_log.clear();
        h.session_token_scope_service = "some-service";
        auto res = read_mcp(h);
        REQUIRE(res);
        CHECK(json::parse(res->body).contains("error"));
        CHECK(res->body.find("4321") == std::string::npos);
        CHECK(res->body.find("structuredContent") == std::string::npos);
        // The refusal is the central default-deny one: its audit row is the generic MCP
        // verb for this tool with result "denied", and the tool's own read-audit verb
        // (the REST twin's) is never written because the handler did not run.
        bool central_denied_row = false;
        bool handler_row = false;
        for (const auto& a : h.audit_log) {
            if (a.action == std::string("mcp.") + kReadTool && a.result == "denied" &&
                a.target_id == kReadTool)
                central_denied_row = true;
            if (a.action == "guaranteed_state.policy_generation.read")
                handler_row = true;
        }
        CHECK(central_denied_row);
        CHECK_FALSE(handler_row);
    }
}

TEST_CASE("MCP get_guardian_policy_generation: a degraded store is a retryable error, never 0",
          "[pg][mcp][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    run_sql(h, "ALTER TABLE guaranteed_state_store.guardian_meta RENAME TO guardian_meta_off");
    auto res = read_mcp(h);
    REQUIRE(res);
    const auto body = json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == mcp::kInternalError);
    CHECK_FALSE(body.contains("result"));
    REQUIRE(body["error"]["data"].contains("retry_after_ms"));
    CHECK(body["error"]["data"]["retry_after_ms"].get<int>() == mcp::kMcpStoreFaultRetryMs);
    run_sql(h, "ALTER TABLE guaranteed_state_store.guardian_meta_off RENAME TO guardian_meta");
    CHECK(mcp_read_value(h) == 0);
}

TEST_CASE("MCP get_guardian_policy_generation: a stored value below zero is a retryable error, "
          "never a number, and a raise repairs it",
          "[pg][mcp][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    admin_caller(h);
    run_sql(h, "UPDATE guaranteed_state_store.guardian_meta SET value = -5 "
               "WHERE key = 'policy_generation'");
    auto res = read_mcp(h);
    REQUIRE(res);
    const auto body = json::parse(res->body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == mcp::kInternalError);
    CHECK_FALSE(body.contains("result"));
    REQUIRE(body["error"]["data"].contains("retry_after_ms"));
    CHECK(body["error"]["data"]["retry_after_ms"].get<int>() == mcp::kMcpStoreFaultRetryMs);

    auto raised = h.mcp_call_tool_approved(kTool, valid_body(10));
    REQUIRE(raised);
    const auto raised_body = json::parse(raised->body);
    REQUIRE_FALSE(raised_body.contains("error"));
    CHECK(raised_body["result"]["structuredContent"]["previous_generation"] == 0);
    CHECK(mcp_read_value(h) == 10);
}

TEST_CASE("MCP get_guardian_policy_generation: advertised in tools/list as a read-only, idempotent "
          "read with an empty bounded input and a typed output schema",
          "[pg][mcp][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    auto res = h.mcp_call(R"({"jsonrpc":"2.0","method":"tools/list","id":1})");
    REQUIRE(res);
    const auto body = json::parse(res->body, nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(body.is_discarded());
    const json& tools = json_step(json_step(body, "result"), "tools");
    REQUIRE(tools.is_array());
    const json* tool = nullptr;
    for (const auto& t : tools)
        if (t.is_object() && t.contains("name") && t.at("name") == kReadTool)
            tool = &t;
    REQUIRE(tool != nullptr);
    const json& t = *tool;
    const json& annotations = json_step(t, "annotations");
    CHECK(json_step(annotations, "readOnlyHint") == true);
    CHECK(json_step(annotations, "destructiveHint") == false);
    CHECK(json_step(annotations, "idempotentHint") == true);
    CHECK(json_step(annotations, "openWorldHint") == false);
    CHECK(json_step(json_step(t, "inputSchema"), "properties").empty());
    const json& out = json_step(t, "outputSchema");
    const json& out_props = json_step(out, "properties");
    CHECK(json_step(json_step(out_props, "generation"), "type") == "integer");
    CHECK(json_step(json_step(out_props, "ceiling"), "type") == "integer");
    const json& required = json_step(out, "required");
    REQUIRE(required.is_array());
    CHECK(required.size() == 2);
}

TEST_CASE("the OpenAPI entry for the read route documents the generation and ceiling fields",
          "[guardian][raise][openapi][read]") {
    const json spec = json::parse(openapi_spec_json(), nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(spec.is_discarded());
    const json& route =
        json_step(json_step(spec, "paths"), "/guaranteed-state/policy-generation");
    const json& entry = json_step(route, "get");
    REQUIRE(entry.is_object());
    const json& data = json_step(
        json_step(json_step(json_step(json_step(json_step(json_step(entry, "responses"), "200"),
                                                "content"),
                                      "application/json"),
                            "schema"),
                  "properties"),
        "data");
    const json& props = json_step(data, "properties");
    CHECK(props.contains("generation"));
    CHECK(props.contains("ceiling"));
    CHECK(json_step(data, "required").size() == 2);
    CHECK(json_step(entry, "responses").contains("503"));
    // The audit posture is stated truthfully: a refusal of a service-scoped token is audited.
    const std::string description = json_step(entry, "description").get<std::string>();
    CHECK(description.find("A successful read is not audited; a refusal of a service-scoped "
                           "token is audited as guaranteed_state.policy_generation.read.") !=
          std::string::npos);
}

TEST_CASE("MCP get_guardian_policy_generation: the readonly and operator tiers may read it",
          "[pg][mcp][guardian][raise][read]") {
    RaiseHarness h(GuardianStores::kBoth);
    REQUIRE(h.guardian_store->create_rule(make_rule("r1")));
    const auto stored = generation(h);
    for (const char* tier : {"readonly", "operator", "supervised"}) {
        INFO("tier = " << tier);
        h.session_mcp_tier = tier;
        CHECK(mcp_read_value(h) == stored);
    }
}
