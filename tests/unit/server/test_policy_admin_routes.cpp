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
    auto created = store.create_fragment(kFragmentYaml);
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
    auto frag = store.create_fragment(kFragmentYaml);
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
    static yuzu::test::PgTestTemplate presence_tpl{
        "policyadminpresence", [](const std::string& dsn) {
            yuzu::server::pg::PgPool p{{.conninfo = dsn, .size = 1}};
            OfflineEndpointStore s{p};
            if (!s.is_open())
                throw std::runtime_error("presence template: failed to migrate");
        }};
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
    auto fid = ps.create_fragment(
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
