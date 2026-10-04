/**
 * test_workflow_executions_list_authz.cpp -- GET /fragments/executions drives the REAL
 * AuthRoutes::require_fleet_read (no fake gate) over a real Postgres RbacStore,
 * ManagementGroupStore, ApiTokenStore, TagStore and ExecutionTracker.
 *
 * The route's sole gate is require_fleet_read (ADR-0017). Each case asserts the EXACT set of
 * execution ids served, not just that a VisibleSet was handed over: a confinement test that
 * only observes the scope stays green while the intersection is deleted
 * (docs/authz-model.md, dispatch visibility row 5). The unit-level projection/limit/degrade
 * cases against a fake gate live in test_workflow_routes.cpp.
 *
 * Admission note (a capability change, not a leak fix): before this route moved onto
 * require_fleet_read it gated on the plain require_permission, which only a principal holding a
 * GLOBAL grant passes, and such a principal is unfiltered anyway. A group-scoped-only operator
 * and a service-scoped token therefore got 403 and now get the same confined view the v1 twin
 * GET /api/v1/executions already served.
 */

#include "execution_tracker.hpp"
#include "tag_store.hpp"
#include "test_response_execution_authz_pg_helper.hpp"
#include "test_route_sink.hpp"
#include "workflow_routes.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

struct ListRig {
    yuzu::test::ResponseExecutionAuthzPgRig rig;
    ExecutionTracker tracker;
    TagStore tags;
    std::unique_ptr<AuthRoutes> svc_auth; // same stores + a TagStore: service-scoped tokens resolve
    std::string x_bob, x_mixed, x_alice, x_bob_own;

    explicit ListRig(const std::string& dsn)
        : rig{dsn}, tracker{rig.pool}, tags{rig.pool} {
        REQUIRE(tracker.is_open());
        REQUIRE(tags.is_open());
        // gary: GLOBAL Execution:Read. dave: no Execution grant at all.
        REQUIRE(rig.rbac.assign_role({"user", "gary", "ExecutionReader1634"}).has_value());
        REQUIRE(rig.auth_mgr.upsert_user("gary", "correct-horse-battery-staple",
                                         auth::Role::user));
        REQUIRE(rig.auth_mgr.upsert_user("dave", "correct-horse-battery-staple",
                                         auth::Role::user));
        REQUIRE(tags.set_tag("bob-agent", "service", "printers").has_value());
        REQUIRE(tags.set_tag("alice-agent", "service", "scanners").has_value());
        svc_auth = std::make_unique<AuthRoutes>(rig.cfg, rig.auth_mgr, &rig.rbac,
                                                rig.api_tokens.get(), /*audit_store=*/nullptr,
                                                &rig.mgmt, &tags, /*analytics_store=*/nullptr,
                                                rig.oidc_mu, rig.oidc_provider);
        seed();
    }

    std::string make(const std::string& dispatched_by, int64_t at, int targeted) {
        Execution e;
        e.definition_id = "def-list-authz";
        e.dispatched_by = dispatched_by;
        e.status = "completed";
        e.dispatched_at = at;
        e.agents_targeted = targeted;
        auto id = tracker.create_execution(e);
        REQUIRE(id.has_value());
        return *id;
    }
    void status(const std::string& exec, const std::string& agent, const std::string& st,
                const std::string& err = {}, int64_t done = 1735689660) {
        AgentExecStatus a;
        a.agent_id = agent;
        a.status = st;
        a.completed_at = done;
        a.error_detail = err;
        tracker.update_agent_status(exec, a);
    }
    void seed() {
        x_bob = make("carol", 1735689600, 1); // bob-agent only
        status(x_bob, "bob-agent", "success");
        x_mixed = make("carol", 1735689601, 2); // both
        status(x_mixed, "bob-agent", "success");
        status(x_mixed, "alice-agent", "failure", "SECRET-ALICE-ERR-MIXED", 1735689690);
        x_alice = make("carol", 1735689602, 1); // alice-agent only
        status(x_alice, "alice-agent", "failure", "SECRET-ALICE-ERR-ONLY", 1735689691);
        x_bob_own = make("bob", 1735689603, 1); // bob dispatched; alice-agent only
        status(x_bob_own, "alice-agent", "failure", "SECRET-ALICE-ERR-OWN", 1735689692);
    }

    std::string mint(const std::string& user, const std::string& service = {}) {
        const auto expires = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count() +
                             3600;
        auto t = rig.api_tokens->create_token("list-authz", user, expires, service);
        REQUIRE(t.has_value());
        return *t;
    }

    struct Resp {
        int status{0};
        std::string body;
        std::vector<std::string> ids;
    };
    // `use_tag_aware_auth`: route the gate through the AuthRoutes that has a TagStore, which
    // is what resolves a service-scoped token (production wires one AuthRoutes with both).
    Resp get(const std::string& token, bool use_tag_aware_auth = false) {
        AuthRoutes& ar = use_tag_aware_auth ? *svc_auth : *rig.auth_routes;
        yuzu::server::test::TestRouteSink sink;
        WorkflowRoutes routes;
        WorkflowRoutes::Deps d;
        d.auth_fn = [&ar](const httplib::Request& req,
                          httplib::Response& res) -> std::optional<auth::Session> {
            return ar.require_auth(req, res);
        };
        d.perm_fn = [&ar](const httplib::Request& req, httplib::Response& res,
                          const std::string& t, const std::string& o) -> bool {
            return ar.require_permission(req, res, t, o);
        };
        d.fleet_read_fn = [&ar](const httplib::Request& req, httplib::Response& res,
                                const std::string& t,
                                const std::string& o) -> authz::FleetReadGate {
            auto result = ar.require_fleet_read(req, res, t, o);
            if (!result)
                return {};
            return {true, result->visible_for_query()};
        };
        d.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                        const std::string&, const std::string&, const std::string&) {};
        d.execution_tracker = &tracker;
        routes.register_routes(sink, std::move(d));
        std::unordered_map<std::string, std::string> hdrs;
        if (!token.empty())
            hdrs = {{"Authorization", "Bearer " + token}};
        auto res = sink.dispatch("GET", "/fragments/executions", {}, "application/json", hdrs);
        REQUIRE(res);
        Resp r{res->status, res->body, {}};
        const std::string needle = "data-execution-id=\"";
        for (auto at = r.body.find(needle); at != std::string::npos; at = r.body.find(needle, at)) {
            at += needle.size();
            r.ids.push_back(r.body.substr(at, r.body.find('"', at) - at));
        }
        std::sort(r.ids.begin(), r.ids.end());
        return r;
    }
    static std::vector<std::string> sorted(std::vector<std::string> v) {
        std::sort(v.begin(), v.end());
        return v;
    }
};

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("fragments/executions real gate: group-scoped-only operator gets the confined set",
          "[pg][workflow][executions][list][confinement][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ListRig r{db.dsn()};
    const auto token = r.mint("bob");

    // Control: the PLAIN gate refuses bob (it never joins management-group assignments);
    // the route no longer uses it, so bob is admitted with the confined view instead of 403.
    {
        httplib::Request req;
        req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        CHECK_FALSE(r.rig.auth_routes->require_permission(req, res, "Execution", "Read"));
    }

    auto got = r.get(token);
    CHECK(got.status == 200);
    // bob-agent rows plus the row bob dispatched himself; alice-agent-only rows excluded.
    CHECK(got.ids == ListRig::sorted({r.x_bob, r.x_mixed, r.x_bob_own}));
    CHECK_FALSE(has(got.body, "SECRET-ALICE"));
}

TEST_CASE("fragments/executions real gate: global principal is unfiltered by design",
          "[pg][workflow][executions][list][confinement][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ListRig r{db.dsn()};
    auto got = r.get(r.mint("gary"));
    CHECK(got.status == 200);
    CHECK(got.ids == ListRig::sorted({r.x_bob, r.x_mixed, r.x_alice, r.x_bob_own}));
    // The control that makes the leak assertions above meaningful: the secret IS in the data.
    CHECK(has(got.body, "SECRET-ALICE"));
}

TEST_CASE("fragments/executions real gate: service-scoped token gets a narrowed view",
          "[pg][workflow][executions][list][confinement][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ListRig r{db.dsn()};

    // A GLOBAL principal's token narrowed to service "printers" (= {bob-agent}): previously
    // 403 on the plain gate, now the tag-scoped set. gary dispatched none of these rows.
    auto g = r.get(r.mint("gary", "printers"), /*use_tag_aware_auth=*/true);
    CHECK(g.status == 200);
    CHECK(g.ids == ListRig::sorted({r.x_bob, r.x_mixed}));
    CHECK_FALSE(has(g.body, "SECRET-ALICE"));

    // bob's group scope {bob-agent} intersected with service "scanners" (= {alice-agent}) is
    // empty: nothing visible but bob's own dispatch.
    auto b = r.get(r.mint("bob", "scanners"), /*use_tag_aware_auth=*/true);
    CHECK(b.status == 200);
    CHECK(b.ids == ListRig::sorted({r.x_bob_own}));
    CHECK_FALSE(has(b.body, "SECRET-ALICE-ERR-ONLY"));
    CHECK_FALSE(has(b.body, "SECRET-ALICE-ERR-MIXED"));
}

TEST_CASE("fragments/executions real gate: a principal with no Execution:Read is refused",
          "[pg][workflow][executions][list][confinement][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ListRig r{db.dsn()};
    auto dave = r.get(r.mint("dave"));
    CHECK(dave.status == 403);
    CHECK(dave.ids.empty());
    auto anon = r.get("");
    CHECK(anon.status == 401);
    CHECK(anon.ids.empty());
}
