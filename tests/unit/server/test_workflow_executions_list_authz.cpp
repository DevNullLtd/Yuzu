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

#include "audit_store.hpp"
#include "execution_tracker.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "tag_store.hpp"
#include "test_response_execution_authz_pg_helper.hpp"
#include "test_route_sink.hpp"
#include "workflow_routes.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;

namespace {

struct ListRig {
    yuzu::test::ResponseExecutionAuthzPgRig rig;
    ExecutionTracker tracker;
    TagStore tags;
    // A real AuditStore on a second pool over the same database (its own schema), wired into
    // svc_auth only: the gate's refusal is rewritten to a 200 note by the route, so the audit
    // row is the one durable proof the gate still recorded the denial.
    pg::PgPool audit_pool;
    AuditStore audit_store;
    std::unique_ptr<AuthRoutes> svc_auth; // same stores + a TagStore: service-scoped tokens resolve
    std::string x_bob, x_mixed, x_alice, x_bob_own;

    explicit ListRig(const std::string& dsn)
        : rig{dsn}, tracker{rig.pool}, tags{rig.pool},
          audit_pool{{.conninfo = dsn, .size = 2}}, audit_store{audit_pool} {
        REQUIRE(tracker.is_open());
        REQUIRE(tags.is_open());
        REQUIRE(audit_store.is_open());
        // gary: GLOBAL Execution:Read. dave: no Execution grant at all.
        REQUIRE(rig.rbac.assign_role({"user", "gary", "ExecutionReader1634"}).has_value());
        REQUIRE(rig.auth_mgr.upsert_user("gary", "correct-horse-battery-staple",
                                         auth::Role::user));
        REQUIRE(rig.auth_mgr.upsert_user("dave", "correct-horse-battery-staple",
                                         auth::Role::user));
        REQUIRE(tags.set_tag("bob-agent", "service", "printers").has_value());
        REQUIRE(tags.set_tag("alice-agent", "service", "scanners").has_value());
        svc_auth = std::make_unique<AuthRoutes>(rig.cfg, rig.auth_mgr, &rig.rbac,
                                                rig.api_tokens.get(), &audit_store,
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
    // The audit rows (via svc_auth) with this action, as "result|detail".
    std::vector<std::string> audit(const std::string& action) {
        std::vector<std::string> out;
        auto rows = audit_store.query({});
        REQUIRE(rows.has_value());
        for (const auto& row : *rows)
            if (row.action == action)
                out.push_back(row.result + "|" + row.detail);
        return out;
    }
    static std::vector<std::string> sorted(std::vector<std::string> v) {
        std::sort(v.begin(), v.end());
        return v;
    }
};

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

// The gate's refusal is rewritten by the route to a 200 text/html note. Assert the note, that no
// row is served, and that nothing of the gate's A4 JSON body survived.
void check_denied_note(const ListRig::Resp& r) {
    CHECK(r.status == 200);
    CHECK(has(r.body, "data-denied=\"true\""));
    CHECK(has(r.body, "You do not have permission to view executions."));
    CHECK(r.ids.empty());
    CHECK_FALSE(has(r.body, "data-execution-id"));
    CHECK_FALSE(has(r.body, "data-degraded"));
    CHECK_FALSE(has(r.body, "\"error\""));
    CHECK_FALSE(has(r.body, "retry_after_ms"));
    CHECK_FALSE(has(r.body, "does not grant"));
    CHECK_FALSE(has(r.body, "\"permission\""));
    CHECK_FALSE(has(r.body, "ITServiceOwner"));
    CHECK_FALSE(has(r.body, "SECRET-ALICE"));
}
void check_degraded_note(const ListRig::Resp& r) {
    CHECK(r.status == 200);
    CHECK(has(r.body, "data-degraded=\"gate\""));
    CHECK(has(r.body, "Retry shortly."));
    CHECK(r.ids.empty());
    CHECK_FALSE(has(r.body, "data-execution-id"));
    CHECK_FALSE(has(r.body, "data-denied"));
    CHECK_FALSE(has(r.body, "\"error\""));
    CHECK_FALSE(has(r.body, "retry_after_ms"));
    CHECK_FALSE(has(r.body, "does not grant"));
    CHECK_FALSE(has(r.body, "\"permission\""));
    CHECK_FALSE(has(r.body, "SECRET-ALICE"));
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
    // empty: nothing visible. bob's own dispatch (x_bob_own) is NOT served either: a service
    // token's session username is its minter, and the owner disjunct is suppressed for it.
    auto b = r.get(r.mint("bob", "scanners"), /*use_tag_aware_auth=*/true);
    CHECK(b.status == 200);
    CHECK(b.ids.empty());
    CHECK(has(b.body, "No executions visible in your scope."));
    CHECK_FALSE(has(b.body, "SECRET-ALICE-ERR-ONLY"));
    CHECK_FALSE(has(b.body, "SECRET-ALICE-ERR-MIXED"));
    CHECK_FALSE(has(b.body, "SECRET-ALICE-ERR-OWN"));
}

TEST_CASE("fragments/executions real gate: a principal with no Execution:Read is refused",
          "[pg][workflow][executions][list][confinement][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ListRig r{db.dsn()};
    // Via svc_auth so the gate's audit row is observable (the plain rig has no AuditStore).
    auto dave = r.get(r.mint("dave"), /*use_tag_aware_auth=*/true);
    check_denied_note(dave);
    // The rewrite happens AFTER the gate: its denied audit row is still written.
    const auto rows = r.audit("auth.fleet_read_required");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].rfind("denied|", 0) == 0);
    // Unauthenticated is NOT rewritten: still the gate's 401.
    auto anon = r.get("");
    CHECK(anon.status == 401);
    CHECK(anon.ids.empty());
    CHECK_FALSE(has(anon.body, "data-denied"));
}

// ITServiceOwner AUTHORITY CEILING through the real fragment: the route's only gate is
// require_fleet_read, whose service axis now applies the same ceiling as require_permission.
// With the seeded defaults (ITServiceOwner holds Execution CRUD) nothing changes, which the
// service-token case above pins; once an operator revokes Execution:Read from ITServiceOwner
// a service token is refused even though its minter holds the grant, while a non-service
// principal (global or group-scoped) is unaffected.
TEST_CASE("fragments/executions real gate: revoking Execution:Read from ITServiceOwner refuses "
          "service tokens only",
          "[pg][workflow][executions][list][confinement][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ListRig r{db.dsn()};
    const auto svc_gary = r.mint("gary", "printers");
    const auto svc_bob = r.mint("bob", "scanners");

    // Control (seeded defaults): admitted.
    CHECK(r.get(svc_gary, /*use_tag_aware_auth=*/true).status == 200);

    REQUIRE(r.rig.rbac.remove_permission("ITServiceOwner", "Execution", "Read").has_value());

    auto g = r.get(svc_gary, /*use_tag_aware_auth=*/true);
    check_denied_note(g); // the gate's "service-scoped token does not grant" text is not echoed
    // The gate's own audit row (written before the rewrite) still carries the reason.
    auto rows = r.audit("auth.fleet_read_required");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].rfind("denied|", 0) == 0);
    CHECK(has(rows[0], "lacks ITServiceOwner permission Execution:Read"));
    auto b = r.get(svc_bob, /*use_tag_aware_auth=*/true);
    check_denied_note(b);
    CHECK(r.audit("auth.fleet_read_required").size() == 2);

    // Non-service principals are unaffected: global gary unfiltered, group-scoped bob confined.
    auto gary = r.get(r.mint("gary"), /*use_tag_aware_auth=*/true);
    CHECK(gary.status == 200);
    CHECK(gary.ids == ListRig::sorted({r.x_bob, r.x_mixed, r.x_alice, r.x_bob_own}));
    auto bob = r.get(r.mint("bob"), /*use_tag_aware_auth=*/true);
    CHECK(bob.status == 200);
    CHECK(bob.ids == ListRig::sorted({r.x_bob, r.x_mixed, r.x_bob_own}));
}

// A FAILED ITServiceOwner ceiling read is an infrastructure fault, not a deny: the fragment
// is rewritten from the gate's own retryable 503 to a 200 degrade note and serves no row, while the
// siblings that keep the 403 mapping (require_permission) are pinned in test_authz_gates.cpp.
TEST_CASE("fragments/executions real gate: a degraded ITServiceOwner ceiling read is a 503 for "
          "a service token and serves no rows",
          "[pg][workflow][executions][list][confinement][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ListRig r{db.dsn()};
    const auto svc_gary = r.mint("gary", "printers");
    CHECK(r.get(svc_gary, /*use_tag_aware_auth=*/true).status == 200); // control

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE rbac_store.role_permissions CASCADE")};
        REQUIRE(d.ok());
    }
    auto g = r.get(svc_gary, /*use_tag_aware_auth=*/true);
    check_degraded_note(g);
    // The gate's degraded-ceiling audit row (written before the rewrite) is still there.
    const auto rows = r.audit("auth.fleet_read_required");
    REQUIRE(rows.size() == 1);
    CHECK(has(rows[0], "RBAC read degraded resolving the ITServiceOwner ceiling"));
}

// UP-2 (ADR-1006 ceiling): a service-scoped token's session username is its MINTER's identity, so
// the owner disjunct (dispatched_by == username) would list every execution the minter
// dispatched, outside the token's service tag scope. The fragment suppresses the owner disjunct
// for a service-scoped session, in SQL and in the per-row check: the token sees only executions
// that touched an in-scope agent. Ordinary (non-service) callers keep the owner disjunct.
TEST_CASE("fragments/executions real gate: a service-scoped token never sees its minter's "
          "out-of-scope dispatches",
          "[pg][workflow][executions][list][confinement][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ListRig r{db.dsn()};
    // bob also dispatched a just-submitted execution no agent has answered yet: invisible to a
    // service token (no in-scope status row), owner-visible to bob himself.
    const auto x_bob_pending = r.make("bob", 1735689604, 1);

    // bob's group {bob-agent} intersected with service "printers" (= {bob-agent}) = {bob-agent}.
    const auto token = r.mint("bob", "printers");
    auto svc = r.get(token, /*use_tag_aware_auth=*/true);
    CHECK(svc.status == 200);
    // (b) in-scope executions are served; (a) the minter's alice-agent-only dispatch and the
    // pending one are not.
    CHECK(svc.ids == ListRig::sorted({r.x_bob, r.x_mixed}));
    CHECK(std::find(svc.ids.begin(), svc.ids.end(), r.x_bob_own) == svc.ids.end());
    CHECK(std::find(svc.ids.begin(), svc.ids.end(), x_bob_pending) == svc.ids.end());
    CHECK_FALSE(has(svc.body, "SECRET-ALICE"));

    // (e) Control: the SAME principal without the service narrowing keeps the owner disjunct.
    auto plain = r.get(r.mint("bob"), /*use_tag_aware_auth=*/true);
    CHECK(plain.status == 200);
    CHECK(plain.ids == ListRig::sorted({r.x_bob, r.x_mixed, r.x_bob_own, x_bob_pending}));

    // (c) Revoking Execution:Read from ITServiceOwner mid-test refuses the token outright; no
    // row (owner-keyed or otherwise) is ever served through it.
    REQUIRE(r.rig.rbac.remove_permission("ITServiceOwner", "Execution", "Read").has_value());
    auto revoked = r.get(token, /*use_tag_aware_auth=*/true);
    check_denied_note(revoked);
    // The ordinary owner is unaffected.
    CHECK(r.get(r.mint("bob"), /*use_tag_aware_auth=*/true).ids ==
          ListRig::sorted({r.x_bob, r.x_mixed, r.x_bob_own, x_bob_pending}));
}

// UP-2 at the SQL layer: the owner clear must reach the scope clause that runs BEFORE the page
// LIMIT (50). If the owner stayed in SQL (only the per-row check cleared), a service-scoped
// token whose minter dispatched more than a page of out-of-scope executions would have the whole
// page consumed by those rows, the per-row check would then drop them all, and the older
// in-scope executions would never be served. The minter's 55 newer rows touch only alice-agent
// (out of the "printers" scope); the seeded in-scope rows (x_bob, x_mixed) are older.
TEST_CASE("fragments/executions real gate: a service-scoped token is not starved by a minter's "
          "page of newer out-of-scope dispatches",
          "[pg][workflow][executions][list][confinement][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ListRig r{db.dsn()};
    constexpr int kMinterRows = 55; // > the fragment's 50-row page limit
    std::vector<std::string> minter_ids;
    for (int i = 0; i < kMinterRows; ++i) {
        auto id = r.make("bob", 1735700000 + i, 1); // all newer than the seeded rows
        r.status(id, "alice-agent", "failure", "SECRET-ALICE-ERR-FLOOD");
        minter_ids.push_back(id);
    }

    auto svc = r.get(r.mint("bob", "printers"), /*use_tag_aware_auth=*/true);
    CHECK(svc.status == 200);
    CHECK(svc.ids == ListRig::sorted({r.x_bob, r.x_mixed}));
    for (const auto& id : minter_ids)
        CHECK(std::find(svc.ids.begin(), svc.ids.end(), id) == svc.ids.end());
    CHECK_FALSE(has(svc.body, "SECRET-ALICE"));
}

// Default posture: RBAC ships OFF. With enforcement off every authenticated non-service caller
// is admitted UNCONFINED (no management-group narrowing, no grant required) and sees the whole
// fleet's executions; a service-scoped token is refused (it requires RBAC to be enabled). This
// pins the documented default so a change to it is a loud, deliberate test edit.
TEST_CASE("fragments/executions real gate: with RBAC off (the default) every authenticated "
          "caller sees the full fleet and a service token is refused",
          "[pg][workflow][executions][list][confinement][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ListRig r{db.dsn()};
    const auto bob_token = r.mint("bob");
    const auto dave_token = r.mint("dave");
    const auto gary_token = r.mint("gary");
    const auto svc_token = r.mint("gary", "printers");
    // Control (RBAC on, as the rig seeds it): bob is confined, dave refused.
    CHECK(r.get(bob_token, true).ids == ListRig::sorted({r.x_bob, r.x_mixed, r.x_bob_own}));
    check_denied_note(r.get(dave_token, true));

    r.rig.rbac.set_rbac_enabled(false);
    const auto everything = ListRig::sorted({r.x_bob, r.x_mixed, r.x_alice, r.x_bob_own});
    for (const auto& token : {bob_token, dave_token, gary_token}) {
        auto got = r.get(token, /*use_tag_aware_auth=*/true);
        CHECK(got.status == 200);
        CHECK(got.ids == everything);
    }
    auto svc = r.get(svc_token, /*use_tag_aware_auth=*/true);
    check_denied_note(svc);
    // The refused service token left a denied gate row (dave's control denial is the other).
    CHECK_FALSE(r.audit("auth.fleet_read_required").empty());
}

// The service axis needs a tag read to resolve the token's scope; when the tag store is
// unreachable the gate answers its own retryable 503 (rewritten by the route to a 200 degrade note) and
// serves no row, while a non-service caller (who needs no tag read) is unaffected.
TEST_CASE("fragments/executions real gate: an unreachable tag store is a 503 for a service "
          "token and serves no rows while an ordinary caller still gets 200",
          "[pg][workflow][executions][list][confinement][authz][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ListRig r{db.dsn()};
    const auto svc_token = r.mint("gary", "printers");
    CHECK(r.get(svc_token, /*use_tag_aware_auth=*/true).status == 200); // control

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{PQexec(conn.get(), "DROP TABLE tag_store.tags CASCADE")};
        REQUIRE(d.ok());
    }
    auto svc = r.get(svc_token, /*use_tag_aware_auth=*/true);
    check_degraded_note(svc);
    CHECK_FALSE(r.audit("auth.fleet_read_required").empty());

    auto gary = r.get(r.mint("gary"), /*use_tag_aware_auth=*/true);
    CHECK(gary.status == 200);
    CHECK(gary.ids == ListRig::sorted({r.x_bob, r.x_mixed, r.x_alice, r.x_bob_own}));
}
