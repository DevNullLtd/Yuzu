/**
 * test_policy_admin_routes.cpp — coverage for PolicyAdminRoutes, split out
 * of compliance_routes.cpp by ADR-0031 WS-A4 Task B (policy/fragment
 * mutator routes: no public REST v1/MCP twin — see policy_admin_routes.hpp's
 * file banner for why this deliberately stays outside the compliance
 * family's seam-closure enforcement).
 *
 * ComplianceRoutes had no route-level mutator test coverage before this
 * split (test_compliance_routes.cpp only ever called PolicyStore mutators
 * directly as fixture setup, never through the routes) — this file is NEW
 * coverage, not a move of pre-existing tests.
 */

#include "test_policy_fragment_helper.hpp"
#include "agent_registry.hpp"
#include "offline_endpoint_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "policy_admin_routes.hpp"
#include "policy_evaluator.hpp"
#include "policy_store.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};

struct PolicyAdminHarness {
    // Declaration order matters (CLAUDE.md TestRouteSink convention): `sink`
    // captures `routes`'s `this` in its registered handlers, so `routes`
    // must outlive `sink` — declare it FIRST so it destructs LAST.
    PolicyAdminRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    std::vector<AuditCall> audit_calls;
    std::vector<std::string> emitted_events;
    // WP06 F4: the fake for the instruction-authority closure. Default = admitted, unrestricted.
    std::vector<std::string> authorized_instructions;
    PolicyAdminRoutes::InstructionAuthority authority{.ok = true, .status = 200, .message = {},
                                                      .plugin_action = "plug.act",
                                                      .visible = std::nullopt};

    explicit PolicyAdminHarness(PolicyStore* policy_store = nullptr) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };
        auto emit_fn = [this](const std::string& event_type, const httplib::Request&,
                              const nlohmann::json&, const nlohmann::json&) {
            emitted_events.push_back(event_type);
        };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, emit_fn, policy_store,
                               /*policy_evaluator=*/nullptr, /*metrics=*/nullptr);
        routes.set_authorize_instruction_fn(
            [this](const httplib::Request&, const std::string& instruction_id) {
                authorized_instructions.push_back(instruction_id);
                return authority;
            });
    }
};

// Same template KEY as test_compliance_routes.cpp / test_policy_store.cpp —
// PgTestTemplate explicitly supports sharing a name across files needing the
// exact same store set, so this reuses the already-built template instead of
// paying a second migration pass.
yuzu::test::PgTestTemplate policy_admin_store_tpl{
    "policystore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        PolicyStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("policy_store template: failed to migrate");
    }};

// Used by the degraded-presence 503/error test below — file-scope like
// policy_admin_store_tpl above, not function-local, per this file's own
// convention for PgTestTemplate instances.
yuzu::test::PgTestTemplate presence_tpl{"policyadminpresence", [](const std::string& dsn) {
                                             yuzu::server::pg::PgPool p{{.conninfo = dsn, .size = 1}};
                                             OfflineEndpointStore s{p};
                                             if (!s.is_open())
                                                 throw std::runtime_error(
                                                     "presence template: failed to migrate");
                                         }};

const std::string kFragmentYaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
displayName: Admin Route Fragment
description: Verify a Windows service is running
spec:
  check:
    instruction: get_service_status
    compliance: "result.status == 'running'"
)";

} // namespace

TEST_CASE("POST /api/policies: null store -> 503", "[compliance][admin]") {
    PolicyAdminHarness h;
    auto res = h.sink.Post("/api/policies", R"({"yaml_source":"x"})");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("POST /api/policy-fragments: null store -> 503", "[compliance][admin]") {
    PolicyAdminHarness h;
    auto res = h.sink.Post("/api/policy-fragments", kFragmentYaml, "text/plain");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("POST /api/policy-fragments: creates a fragment, audits, and emits",
          "[compliance][admin]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
    PolicyAdminHarness h{&store};

    auto res = h.sink.Post("/api/policy-fragments", kFragmentYaml, "text/plain");
    REQUIRE(res);
    CHECK(res->status == 201);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["status"] == "created");
    REQUIRE(!h.audit_calls.empty());
    CHECK(h.audit_calls.back().action == "policy_fragment.create");
    CHECK(h.audit_calls.back().result == "success");
    REQUIRE(!h.emitted_events.empty());
    CHECK(h.emitted_events.back() == "policy_fragment.created");

    // The fragment is really there — visible through the store directly.
    auto frags = store.query_fragments();
    REQUIRE(frags);
    CHECK(frags->size() == 1);
}

TEST_CASE("DELETE /api/policy-fragments/:id: deletes a real fragment", "[compliance][admin]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
    auto created = yuzu::test::create_fragment_for_test(store, kFragmentYaml);
    REQUIRE(created);

    PolicyAdminHarness h{&store};
    auto res = h.sink.Delete("/api/policy-fragments/" + *created);
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["deleted"] == true);
    REQUIRE(!h.audit_calls.empty());
    CHECK(h.audit_calls.back().action == "policy_fragment.delete");
}

TEST_CASE("POST /api/policies/:id/enable + /disable: round-trips a real policy",
          "[compliance][admin]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
    auto frag = yuzu::test::create_fragment_for_test(store, kFragmentYaml);
    REQUIRE(frag);
    auto policy = store.create_policy(R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Admin Route Policy
description: A test policy
fragment: )" + *frag + R"(
scope: "tags.env == 'production'"
)");
    REQUIRE(policy);

    PolicyAdminHarness h{&store};

    auto disable_res = h.sink.Post("/api/policies/" + *policy + "/disable", "");
    REQUIRE(disable_res);
    CHECK(disable_res->status == 200);

    auto enable_res = h.sink.Post("/api/policies/" + *policy + "/enable", "");
    REQUIRE(enable_res);
    CHECK(enable_res->status == 200);

    REQUIRE(h.audit_calls.size() >= 2);
    CHECK(h.audit_calls[0].action == "policy.disable");
    CHECK(h.audit_calls[1].action == "policy.enable");
}

// #4981 PR-1 adversarial-review MEDIUM fix (independently found by both Kimi
// and Codex): a scope-evaluation abort (e.g. a presence-store outage) was
// being collapsed by PolicyEvaluator::resolve_targets into an ordinary empty
// target list, so these two ROUTES answered as if nothing had gone wrong —
// /evaluate as a clean 409 "matches no agents", /remediate as a 400 audited
// "denied" (a false claim that the OPERATOR was refused, when the real cause
// is an infrastructure degradation). Both must now answer 503, audited
// "error" — the same posture every OTHER degraded read on these two routes
// already has (see the precedent this fix follows in policy_evaluator.cpp).
// This is the route-level proof; test_policy_evaluator.cpp's own presence-
// degraded test proves the same fix at the PolicyEvaluator unit level.
TEST_CASE("POST /api/policies/:id/evaluate and /remediate: a degraded scope "
          "evaluation is reported as 503/error, never 409/denied",
          "[pg][policy][admin][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore ps{pool};
    REQUIRE(ps.is_open());

    // Degraded presence store — same double-PG-template fault-injection
    // recipe as test_policy_evaluator.cpp's "reports presence_degraded
    // rather than silently proceeding as empty-scope" test: a second,
    // independent Postgres database whose endpoints table is held under an
    // ACCESS EXCLUSIVE lock by a second connection, with a short
    // lock_timeout so AgentRegistry::evaluate_scope's presence read fails
    // deterministically rather than racing a real timeout.
    YUZU_REQUIRE_PG_DB_TPL(presence_db, presence_tpl);
    yuzu::server::pg::PgPool short_lock_pool{
        {.conninfo = presence_db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(short_lock_pool.valid());
    OfflineEndpointStore degraded_store{short_lock_pool};
    REQUIRE(degraded_store.is_open());

    yuzu::server::detail::EventBus bus;
    yuzu::MetricsRegistry metrics;
    yuzu::server::detail::AgentRegistry registry(bus, metrics);
    registry.configure_presence(&degraded_store, std::chrono::hours(1));

    yuzu::server::pg::PgConn locker{PQconnectdb(presence_db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(
                locker.get(), "LOCK TABLE endpoint_state.endpoints IN ACCESS EXCLUSIVE MODE",
                std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    // A scope-expression policy (no management groups) with BOTH a check and
    // a fix instruction — resolve_targets aborts before dispatch_instruction
    // is ever reached on either path, so neither instruction needs a real
    // InstructionStore entry to exercise this specific abort.
    auto fid = yuzu::test::create_fragment_for_test(ps, 
        "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\ndisplayName: Degraded Route "
        "Fragment\ndescription: check+fix\nspec:\n  check:\n    instruction: test.check\n"
        "    compliance: \"result.hostname != ''\"\n  fix:\n    instruction: test.fix\n");
    REQUIRE(fid.has_value());
    auto pid = ps.create_policy("apiVersion: yuzu.io/v1alpha1\nkind: Policy\ndisplayName: "
                                "Degraded Route Policy\ndescription: policy\nfragment: " +
                                *fid + "\nscope: \"ostype == 'linux'\"\n");
    REQUIRE(pid.has_value());

    PolicyEvaluator::Deps d;
    d.policy_store = &ps;
    d.registry = &registry;
    d.metrics = &metrics;
    PolicyEvaluator evaluator(d);

    std::vector<AuditCall> audit_calls;
    auto auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "tester";
        s.role = auth::Role::admin;
        return s;
    };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) -> bool { return true; };
    auto audit_fn = [&audit_calls](const httplib::Request&, const std::string& action,
                                   const std::string& result, const std::string& target_type,
                                   const std::string& target_id, const std::string& detail) -> bool {
        audit_calls.push_back({action, result, target_type, target_id, detail});
        return true;
    };
    auto emit_fn = [](const std::string&, const httplib::Request&, const nlohmann::json&,
                      const nlohmann::json&) {};

    PolicyAdminRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, auth_fn, perm_fn, audit_fn, emit_fn, &ps, &evaluator, &metrics);
    routes.set_authorize_instruction_fn(
        [](const httplib::Request&, const std::string&) -> PolicyAdminRoutes::InstructionAuthority {
            return {.ok = true, .status = 200, .message = {}, .plugin_action = "test.pair",
                    .visible = std::nullopt};
        });

    auto eval_res = sink.Post("/api/policies/" + *pid + "/evaluate", "");
    REQUIRE(eval_res);
    CHECK(eval_res->status == 503);
    REQUIRE(!audit_calls.empty());
    CHECK(audit_calls.back().action == "policy.evaluate");
    CHECK(audit_calls.back().result == "error");

    auto remediate_res =
        sink.Post("/api/policies/" + *pid + "/remediate", R"({"agent_ids":["some-agent"]})");
    REQUIRE(remediate_res);
    CHECK(remediate_res->status == 503);
    REQUIRE(!audit_calls.empty());
    CHECK(audit_calls.back().action == "policy.remediate");
    CHECK(audit_calls.back().result == "error");

    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
}

TEST_CASE("POST /api/policies/:id/remediate: a fix pair that differs from the stored snapshot "
          "answers 409 and audits denied (WP06 F4)",
          "[pg][policy][admin][f4]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore ps{pool};
    REQUIRE(ps.is_open());
    yuzu::MetricsRegistry metrics;
    PolicyEvaluator::Deps d;
    d.policy_store = &ps;
    d.metrics = &metrics;
    PolicyEvaluator evaluator(d);

    // The snapshot (test.pair, from the helper) is what the author was authorized for.
    auto fid = yuzu::test::create_fragment_for_test(
        ps, "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\ndisplayName: Pair Fragment\n"
            "spec:\n  check:\n    instruction: test.check\n    compliance: \"result.x == 1\"\n"
            "  fix:\n    instruction: test.fix\n");
    REQUIRE(fid.has_value());
    auto pid = ps.create_policy("apiVersion: yuzu.io/v1alpha1\nkind: Policy\ndisplayName: "
                                "Pair Policy\nfragment: " + *fid + "\nscope: \"ostype == 'linux'\"\n");
    REQUIRE(pid.has_value());

    std::vector<AuditCall> audit_calls;
    auto auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "tester";
        s.role = auth::Role::admin;
        return s;
    };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) -> bool { return true; };
    auto audit_fn = [&audit_calls](const httplib::Request&, const std::string& action,
                                   const std::string& result, const std::string& target_type,
                                   const std::string& target_id, const std::string& detail) -> bool {
        audit_calls.push_back({action, result, target_type, target_id, detail});
        return true;
    };
    auto emit_fn = [](const std::string&, const httplib::Request&, const nlohmann::json&,
                      const nlohmann::json&) {};
    PolicyAdminRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, auth_fn, perm_fn, audit_fn, emit_fn, &ps, &evaluator, &metrics);
    routes.set_authorize_instruction_fn(
        [](const httplib::Request&, const std::string&) -> PolicyAdminRoutes::InstructionAuthority {
            // The definition now resolves to a DIFFERENT pair than the one snapshotted.
            return {.ok = true, .status = 200, .message = {}, .plugin_action = "other.pair",
                    .visible = std::nullopt};
        });
    auto r = sink.Post("/api/policies/" + *pid + "/remediate", "");
    REQUIRE(r);
    CHECK(r->status == 409);
    CHECK(r->body.find("instruction_pair_mismatch") != std::string::npos);
    REQUIRE_FALSE(audit_calls.empty());
    CHECK(audit_calls.back().action == "policy.remediate");
    CHECK(audit_calls.back().result == "denied");
    CHECK(audit_calls.back().detail.find("fix_instruction_pair_mismatch") != std::string::npos);
}

TEST_CASE("POST /api/policies: the policy.create audit row records the stored targeting (#2123)",
          "[compliance][admin]") {
    // Governance G6-CO-1 (CC6.1/CC6.3): the audit row carried an empty detail, so
    // what a policy actually targeted could not be reconstructed after the fact —
    // the reason #2123's silently-broadened scopes left no trace.
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
    auto frag = yuzu::test::create_fragment_for_test(store, kFragmentYaml);
    REQUIRE(frag.has_value());
    PolicyAdminHarness h{&store};

    const std::string yaml = "apiVersion: yuzu.io/v1alpha1\r\n"
                             "kind: Policy\r\n"
                             "displayName: Audited Policy\r\n"
                             "fragment: " +
                             *frag +
                             "\r\n"
                             "scope:\r\n"
                             "  selector:\r\n"
                             "    platform: Windows\r\n"
                             "\r\n"
                             "    tags: [prod]\r\n"
                             "managementGroups:\r\n"
                             "  - abc123def456\r\n";
    auto res = h.sink.Post("/api/policies", yaml, "text/plain");
    REQUIRE(res);
    REQUIRE(res->status == 201);
    REQUIRE(!h.audit_calls.empty());
    const auto& a = h.audit_calls.back();
    CHECK(a.action == "policy.create");
    INFO("detail = " << a.detail);
    CHECK(a.detail.find("scope=") != std::string::npos);
    CHECK(a.detail.find("tag:prod") != std::string::npos);
    CHECK(a.detail.find("windows") != std::string::npos);
    CHECK(a.detail.find("groups=1") != std::string::npos);
    CHECK(a.detail.find("abc123def456") != std::string::npos);
    CHECK(a.detail.find('\n') == std::string::npos);
    CHECK(a.detail.find('\r') == std::string::npos);
}

TEST_CASE("POST /api/policies: policy.create audit records an empty group list as groups=0 (#2123)",
          "[compliance][admin]") {
    // A value only the stored policy can supply (the request carries no groups
    // and a mixed-case platform), so an echo of the request cannot satisfy it
    // (governance Gate 8 quality-engineer F2).
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
    auto frag = yuzu::test::create_fragment_for_test(store, kFragmentYaml);
    REQUIRE(frag.has_value());
    PolicyAdminHarness h{&store};
    const std::string yaml =
        "apiVersion: yuzu.io/v1alpha1\nkind: Policy\ndisplayName: Selector Only\n"
        "fragment: " +
        *frag + "\nscope:\n  selector:\n    platform: LiNuX\n";
    auto res = h.sink.Post("/api/policies", yaml, "text/plain");
    REQUIRE(res);
    REQUIRE(res->status == 201);
    REQUIRE(!h.audit_calls.empty());
    const auto& a = h.audit_calls.back();
    INFO("detail = " << a.detail);
    CHECK(a.detail == "scope=ostype____\"linux\" groups=0");
}

// ── Identifier handling: an invalid id is refused ─────────────────────────────────────────────
//
// The id in these routes is a path capture. An id that is not valid is refused as a whole:
// no policy is deleted, enabled or disabled, and no success audit row is written.

namespace {

std::string make_policy(PolicyStore& store) {
    auto frag = yuzu::test::create_fragment_for_test(store, kFragmentYaml);
    REQUIRE(frag);
    auto policy = store.create_policy(R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Id Handling Policy
description: A test policy
fragment: )" + *frag + R"(
scope: "tags.env == 'production'"
)");
    REQUIRE(policy);
    return *policy;
}

} // namespace

TEST_CASE("DELETE /api/policies/:id: an invalid id deletes nothing and audits no success",
          "[pg][compliance][admin][validation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
    const std::string pid = make_policy(store);

    PolicyAdminHarness h{&store};
    auto res = h.sink.Delete("/api/policies/" + pid + std::string("\0junk", 5));
    REQUIRE(res);
    // Nothing matched, so the route answers a plain "not deleted": status 200, deleted=false.
    CHECK(res->status == 200);
    const auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("deleted"));
    CHECK(body["deleted"] == false);
    {
        auto still = store.get_policy(pid);
        REQUIRE(still.has_value());
        CHECK(still->has_value());
    }
    CHECK(h.audit_calls.empty());
    CHECK(h.emitted_events.empty());
}

TEST_CASE("POST /api/policies/:id/disable|enable: an invalid id changes nothing",
          "[pg][compliance][admin][validation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
    const std::string pid = make_policy(store);
    const auto before = store.get_policy(pid);
    REQUIRE(before.has_value());
    REQUIRE(before->has_value());

    PolicyAdminHarness h{&store};
    const std::string bad = pid + std::string("\0junk", 5);
    auto dis = h.sink.Post("/api/policies/" + bad + "/disable", "");
    REQUIRE(dis);
    // The store refuses the value, which the route reports as a store fault (503) with the
    // store's fixed message, never as success.
    CHECK(dis->status == 503);
    {
        const auto body = nlohmann::json::parse(dis->body);
        CHECK(body["error"]["code"] == 503);
        CHECK(body["error"]["message"] == "failed to disable policy");
    }
    auto ena = h.sink.Post("/api/policies/" + bad + "/enable", "");
    REQUIRE(ena);
    CHECK(ena->status == 503);
    {
        const auto body = nlohmann::json::parse(ena->body);
        CHECK(body["error"]["code"] == 503);
        CHECK(body["error"]["message"] == "failed to enable policy");
    }

    const auto after = store.get_policy(pid);
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->enabled == (*before)->enabled);
    CHECK(h.audit_calls.empty());
    CHECK(h.emitted_events.empty());
}

TEST_CASE("POST /api/policies/:id/disable|enable: an unknown clean id answers 400 policy not found",
          "[pg][compliance][admin][validation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());

    PolicyAdminHarness h{&store};
    for (const char* verb : {"disable", "enable"}) {
        INFO("verb=" << verb);
        auto res = h.sink.Post(std::string("/api/policies/yuzu_test_no_such_policy/") + verb, "");
        REQUIRE(res);
        CHECK(res->status == 400);
        const auto body = nlohmann::json::parse(res->body);
        CHECK(body["error"] == "policy not found");
    }
    CHECK(h.audit_calls.empty());
    CHECK(h.emitted_events.empty());
}

// ── WP06 F4 (interim): authoring-time authorization of a fragment's instructions ─────────────

TEST_CASE("POST /api/policy-fragments: every instruction the fragment names is authorized for "
          "the author, and a refusal writes nothing (WP06 F4)",
          "[compliance][admin][f4]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
    PolicyAdminHarness h{&store};

    const std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
displayName: F4 Fragment
spec:
  check:
    instruction: chk.instr
    compliance: "result.status == 'running'"
  postCheck:
    instruction: post.instr
    compliance: "result.status == 'running'"
  fix:
    instruction: fix.instr
)";
    // Refused (the author may not dispatch the fix pair): 403, nothing created, denied audit.
    h.authority.ok = false;
    h.authority.status = 403;
    h.authority.message = "permission denied: Execution:Execute";
    auto denied = h.sink.Post("/api/policy-fragments", yaml, "text/plain");
    REQUIRE(denied);
    CHECK(denied->status == 403);
    CHECK(denied->body.find("Execution:Execute") != std::string::npos);
    auto listed = store.query_fragments();
    REQUIRE(listed.has_value());
    CHECK(listed->empty());
    REQUIRE_FALSE(h.audit_calls.empty());
    CHECK(h.audit_calls.back().result == "denied");
    CHECK(h.audit_calls.back().detail.find("instruction_not_authorized") != std::string::npos);

    // Admitted: all three instruction ids were checked, in check / postCheck / fix order.
    h.authority.ok = true;
    h.authority.plugin_action = "plug.act";
    h.authorized_instructions.clear();
    auto ok = h.sink.Post("/api/policy-fragments", yaml, "text/plain");
    REQUIRE(ok);
    CHECK(ok->status == 201);
    REQUIRE(h.authorized_instructions.size() == 3);
    // The authorized plugin.action of each instruction is snapshotted on the stored fragment.
    auto stored = store.query_fragments();
    REQUIRE(stored.has_value());
    REQUIRE(stored->size() == 1);
    auto pairs = nlohmann::json::parse((*stored)[0].instruction_pairs);
    CHECK(pairs["fix.instr"] == "plug.act");
    CHECK(h.authorized_instructions[0] == "chk.instr");
    CHECK(h.authorized_instructions[1] == "post.instr");
    CHECK(h.authorized_instructions[2] == "fix.instr");
}

TEST_CASE("POST /api/policy-fragments: an unwired authorization closure refuses (fail closed)",
          "[compliance][admin][f4]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
    PolicyAdminHarness h{&store};
    h.routes.set_authorize_instruction_fn(nullptr);

    auto res = h.sink.Post("/api/policy-fragments", kFragmentYaml, "text/plain");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("PolicyStore::peek_fragment_instructions reads the same three sections create stores",
          "[compliance][admin][f4]") {
    const auto none = PolicyStore::peek_fragment_instructions(
        "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\nspec:\n  check:\n    compliance: x\n");
    CHECK(none.empty());
    const auto some = PolicyStore::peek_fragment_instructions(kFragmentYaml);
    REQUIRE(some.size() == 1);
    CHECK(some[0].first == "check");
    CHECK(some[0].second == "get_service_status");
}
