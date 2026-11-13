/**
 * test_execution_owner_legacy.cpp -- #5557: the legacy /api/executions* surface under
 * service-scoped credentials, through the shared REAL-GATE rig
 * (test_execution_owner_scope_rig.hpp).
 *
 * The service-scoped session carries its MINTER's username. Before the owner-key conversion every
 * route here admitted any execution whose `dispatched_by` equalled that username in addition to
 * executions that touched an in-scope agent. These cases assert the EXACT ids, projected counts
 * and agent rows each credential sees, that the same human's non-service sessions are unchanged,
 * and that a hidden id and a never-existing id answer identically within the surface.
 *
 * Mutation routes (rerun/cancel) are not driven here: they are the mutation-key conversion's
 * surface, not this one.
 */

#include "execution_routes.hpp"
#include "test_execution_owner_scope_rig.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <functional>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::test::ExecutionOwnerRig;
using Ids = std::vector<std::string>;
using Hdrs = ExecutionOwnerRig::Headers;

namespace {

struct Call {
    int status{0};
    nlohmann::json body;
};

struct AuditCall {
    std::string action, result, target_id, detail;
};

// The legacy routes wired the way server.cpp wires them: real gate, real session resolver, real
// tracker. The audit sink is a capture (the gate's own denial rows are asserted through the rig).
struct Legacy {
    ExecutionOwnerRig& r;
    yuzu::server::test::TestRouteSink sink;
    std::vector<AuditCall> audits;

    explicit Legacy(ExecutionOwnerRig& rig) : r(rig) {
        execution::Deps d;
        d.perm_fn = r.perm_fn();
        d.fleet_read_fn = r.fleet_read_fn();
        d.resolve_session_fn = r.resolve_session_fn();
        d.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& res,
                            const std::string&, const std::string& target,
                            const std::string& detail) {
            audits.push_back({a, res, target, detail});
            return true;
        };
        d.emit_event_fn = [](const std::string&, const httplib::Request&, const nlohmann::json&,
                             const nlohmann::json&) {};
        d.execution_tracker = &r.tracker;
        execution::register_execution_routes(sink, std::move(d));
    }

    Call get(const std::string& path, const Hdrs& headers) {
        auto res = sink.dispatch("GET", path, {}, "application/json", headers);
        REQUIRE(res);
        Call c{res->status, {}};
        c.body = nlohmann::json::parse(res->body, nullptr, false);
        return c;
    }
    Ids list_ids(const Hdrs& headers, const std::string& query = "?limit=50") {
        auto c = get("/api/executions" + query, headers);
        REQUIRE(c.status == 200);
        Ids ids;
        for (const auto& e : c.body["executions"])
            ids.push_back(e["id"].get<std::string>());
        std::sort(ids.begin(), ids.end());
        return ids;
    }
    nlohmann::json list_row(const Hdrs& headers, const std::string& id) {
        auto c = get("/api/executions?limit=50", headers);
        REQUIRE(c.status == 200);
        for (const auto& e : c.body["executions"])
            if (e["id"] == id)
                return e;
        FAIL("row not listed: " << id);
        return {};
    }
};

// A not-found body with the per-request correlation id removed, so a hidden id and a
// never-existing id can be compared for equality WITHIN this surface.
std::string normalized(nlohmann::json body) {
    std::function<void(nlohmann::json&)> strip = [&](nlohmann::json& j) {
        if (j.is_object()) {
            j.erase("correlation_id");
            for (auto& [k, v] : j.items())
                strip(v);
        } else if (j.is_array()) {
            for (auto& v : j)
                strip(v);
        }
    };
    strip(body);
    return body.dump();
}

constexpr const char* kNoSuchId = "00000000-0000-0000-0000-00000000dead";

} // namespace

TEST_CASE("owner legacy: GET /api/executions lists exactly the service-scope executions",
          "[pg][execution][owner_rig][owner_legacy][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    Legacy L{r};
    const auto& c = r.creds;
    const auto& id = r.ids;

    // Service A: the agent-evidence rows only. Neither of the minter's out-of-scope or pending
    // dispatches is listed (the #5557 leak).
    CHECK(L.list_ids(ExecutionOwnerRig::bearer(c.svc_a)) == r.service_a_ids());
    // Service B: only b1 touches. E_mixed and E_run each hold a b1 row.
    CHECK(L.list_ids(ExecutionOwnerRig::bearer(c.svc_b)) ==
          ExecutionOwnerRig::sorted({id.mixed, id.run}));
    // bob-minted service-A token: meet({a1}, {a1,a2}) = {a1}. NOT E_a2, and none of bob's own
    // dispatches (E_bob_out on z1, E_bob_pending with no rows).
    CHECK(L.list_ids(ExecutionOwnerRig::bearer(c.svc_bob_a)) ==
          ExecutionOwnerRig::sorted({id.in_a, id.mixed, id.run, id.minter_in_a}));
    // Service C tags no agent: ADMITTED with an empty scope, so 200 and an empty list (never the
    // unfiltered list, and never the minter's rows).
    CHECK(L.list_ids(ExecutionOwnerRig::bearer(c.svc_none)).empty());

    // The same humans WITHOUT a service scope are unchanged.
    CHECK(L.list_ids(ExecutionOwnerRig::bearer(c.bob)) ==
          ExecutionOwnerRig::sorted({id.in_a, id.mixed, id.run, id.minter_in_a, id.bob_out,
                                     id.bob_pending}));
    CHECK(L.list_ids(ExecutionOwnerRig::bearer(c.mina)) == r.all_seeded_ids());
    // A cookie session of the same human is not service-scoped either.
    CHECK(L.list_ids(ExecutionOwnerRig::cookie(r.cookie_session("mina"))) ==
          r.all_seeded_ids());

    // dan holds no Execution:Read: refused at the gate, distinct from service C's admitted-empty.
    auto dan = L.get("/api/executions", ExecutionOwnerRig::bearer(c.dan));
    CHECK(dan.status == 403);
    // Deny-all of the credential itself: no token at all is a 401 and no row.
    CHECK(L.get("/api/executions", {}).status == 401);
}

TEST_CASE("owner legacy: the list projects only in-scope agent rows and counts",
          "[pg][execution][owner_rig][owner_legacy][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    Legacy L{r};
    const auto& id = r.ids;
    const auto a = ExecutionOwnerRig::bearer(r.creds.svc_a);

    // E_mixed has a1 success and b1 failure: service A sees targeted 1, responded 1, success 1,
    // failure 0 (the b1 failure is out of scope).
    auto mixed = L.list_row(a, id.mixed);
    CHECK(mixed["agents_targeted"] == 1);
    CHECK(mixed["agents_responded"] == 1);
    CHECK(mixed["agents_success"] == 1);
    CHECK(mixed["agents_failure"] == 0);
    // E_run: a1 running, a2 success, b1 running. Running is targeted, NOT responded.
    auto run = L.list_row(a, id.run);
    CHECK(run["agents_targeted"] == 2);
    CHECK(run["agents_responded"] == 1);
    CHECK(run["agents_success"] == 1);
    CHECK(run["agents_failure"] == 0);
    // The out-of-scope error text never reaches service A, in the list or the per-agent rows.
    auto listed = L.get("/api/executions?limit=50", a);
    CHECK(listed.body.dump().find("SECRET-B-ERR") == std::string::npos);

    // Service B sees the SAME execution through ITS scope: the failure and its own counts.
    const auto b = ExecutionOwnerRig::bearer(r.creds.svc_b);
    auto mixed_b = L.list_row(b, id.mixed);
    CHECK(mixed_b["agents_targeted"] == 1);
    CHECK(mixed_b["agents_responded"] == 1);
    CHECK(mixed_b["agents_success"] == 0);
    CHECK(mixed_b["agents_failure"] == 1);
    auto run_b = L.list_row(b, id.run);
    CHECK(run_b["agents_targeted"] == 1);
    CHECK(run_b["agents_responded"] == 0);

    // The non-service group-scoped bob keeps his own-dispatch disjunct, with projected counts.
    auto bob_run = L.list_row(ExecutionOwnerRig::bearer(r.creds.bob), id.run);
    CHECK(bob_run["agents_targeted"] == 1);
    CHECK(bob_run["agents_responded"] == 0);
}

TEST_CASE("owner legacy: 60 newer minter rows cannot starve a service-scoped list page",
          "[pg][execution][owner_rig][owner_legacy][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    const auto starving = r.seed_starvation(60);
    Legacy L{r};

    // The owner key is dropped in SQL BEFORE the page LIMIT: with limit=50 the page is the five
    // in-scope rows, not a page of the minter's newer z1 rows.
    auto ids = L.list_ids(ExecutionOwnerRig::bearer(r.creds.svc_a), "?limit=50");
    CHECK(ids == r.service_a_ids());
    for (const auto& s : starving)
        CHECK(std::find(ids.begin(), ids.end(), s) == ids.end());
    // The non-service same human is unconfined and DOES page through them.
    CHECK(L.list_ids(ExecutionOwnerRig::bearer(r.creds.mina), "?limit=50").size() == 50);
}

TEST_CASE("owner legacy: the detail family serves the in-scope ids and hides the minter's",
          "[pg][execution][owner_rig][owner_legacy][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    Legacy L{r};
    const auto& id = r.ids;
    const auto a = ExecutionOwnerRig::bearer(r.creds.svc_a);

    // Visible: the five agent-evidence ids answer 200 on /{id}, /summary and /agents.
    for (const auto& vis : r.service_a_ids()) {
        INFO("visible id " << vis);
        CHECK(L.get("/api/executions/" + vis, a).status == 200);
        CHECK(L.get("/api/executions/" + vis + "/summary", a).status == 200);
        CHECK(L.get("/api/executions/" + vis + "/agents", a).status == 200);
    }
    // Per-agent arrays hold only in-scope agents.
    auto mixed_agents = L.get("/api/executions/" + id.mixed + "/agents", a);
    REQUIRE(mixed_agents.body["agents"].size() == 1);
    CHECK(mixed_agents.body["agents"][0]["agent_id"] == "a1");
    auto run_agents = L.get("/api/executions/" + id.run + "/agents", a);
    Ids run_ids;
    for (const auto& x : run_agents.body["agents"])
        run_ids.push_back(x["agent_id"].get<std::string>());
    std::sort(run_ids.begin(), run_ids.end());
    CHECK(run_ids == Ids{"a1", "a2"});
    // The detail's projected counts (E_run: targeted 2, responded 1).
    auto run_detail = L.get("/api/executions/" + id.run, a);
    CHECK(run_detail.body["agents_targeted"] == 2);
    CHECK(run_detail.body["agents_responded"] == 1);

    // Hidden: the minter's out-of-scope and pending rows, plus a foreign one and the a2-only row
    // for the bob-minted token. Each answers exactly like a never-existing id on every route,
    // and records one `denied` audit row with the non-distinguishing detail.
    for (const char* suffix : {"", "/summary", "/agents"}) {
        const auto absent = L.get(std::string("/api/executions/") + kNoSuchId + suffix, a);
        CHECK(absent.status == 404);
        for (const auto& hidden : {id.minter_out, id.minter_pending, id.foreign}) {
            INFO("hidden id " << hidden << " suffix " << suffix);
            L.audits.clear();
            auto got = L.get("/api/executions/" + hidden + suffix, a);
            CHECK(got.status == 404);
            CHECK(normalized(got.body) == normalized(absent.body));
            REQUIRE(L.audits.size() == 1);
            CHECK(L.audits[0].action == "execution.read");
            CHECK(L.audits[0].result == "denied");
            CHECK(L.audits[0].target_id == hidden);
            CHECK(L.audits[0].detail.find("not found or outside caller's fleet-read scope") !=
                  std::string::npos);
        }
    }
    const auto bob_a = ExecutionOwnerRig::bearer(r.creds.svc_bob_a);
    CHECK(L.get("/api/executions/" + id.a2, bob_a).status == 404);
    CHECK(L.get("/api/executions/" + id.bob_pending, bob_a).status == 404);
    CHECK(L.get("/api/executions/" + id.bob_out, bob_a).status == 404);

    // The non-service sessions of the same humans: mina (global) sees the hidden rows, and the
    // group-scoped bob still reaches his own pending dispatch through the owner disjunct.
    const auto mina = ExecutionOwnerRig::bearer(r.creds.mina);
    CHECK(L.get("/api/executions/" + id.minter_pending, mina).status == 200);
    const auto bob = ExecutionOwnerRig::bearer(r.creds.bob);
    CHECK(L.get("/api/executions/" + id.bob_pending, bob).status == 200);
    CHECK(L.get("/api/executions/" + id.bob_pending + "/summary", bob).status == 200);
    CHECK(L.get("/api/executions/" + id.bob_pending + "/agents", bob).status == 200);

    // Service C (admitted, empty scope): every detail is not-found.
    const auto none = ExecutionOwnerRig::bearer(r.creds.svc_none);
    for (const auto& any : r.all_seeded_ids())
        CHECK(L.get("/api/executions/" + any, none).status == 404);
    // dan (no grant): 403 at the gate, not a 404.
    CHECK(L.get("/api/executions/" + id.in_a, ExecutionOwnerRig::bearer(r.creds.dan)).status ==
          403);
}

TEST_CASE("owner legacy: children are filtered per child and survive the child cap",
          "[pg][execution][owner_rig][owner_legacy][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    const auto kids = r.seed_children();
    const auto cap = r.seed_children_cap();
    Legacy L{r};
    const auto a = ExecutionOwnerRig::bearer(r.creds.svc_a);

    auto child_ids = [&](const std::string& parent, const Hdrs& h) {
        auto c = L.get("/api/executions/" + parent + "/children", h);
        REQUIRE(c.status == 200);
        Ids out;
        for (const auto& e : c.body["children"])
            out.push_back(e["id"].get<std::string>());
        std::sort(out.begin(), out.end());
        return out;
    };

    // P_in has four children; service A sees only the a1 one, never the minter's z1 or pending
    // children and never the b1 one.
    CHECK(child_ids(kids.parent_in, a) == Ids{kids.c_in});
    // The cap fixture: 105 NEWER minter children on z1 and ONE older visible child. The scope
    // clause precedes the capped window, so the older visible child still comes back.
    CHECK(child_ids(cap.parent_cap, a) == Ids{cap.c_old_in});
    // A hidden parent (minter, z1) is not-found, although it has a visible child.
    const auto absent = L.get(std::string("/api/executions/") + kNoSuchId + "/children", a);
    CHECK(absent.status == 404);
    auto hidden = L.get("/api/executions/" + kids.parent_minter_out + "/children", a);
    CHECK(hidden.status == 404);
    CHECK(normalized(hidden.body) == normalized(absent.body));

    // Non-service mina is unconfined and sees all four.
    CHECK(child_ids(kids.parent_in, ExecutionOwnerRig::bearer(r.creds.mina)) ==
          ExecutionOwnerRig::sorted(
              {kids.c_in, kids.c_minter_out, kids.c_minter_pending, kids.c_b}));
}

TEST_CASE("owner legacy: RBAC off refuses a service-scoped token and leaves others alone",
          "[pg][execution][owner_rig][owner_legacy][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    Legacy L{r};
    r.rbac.set_rbac_enabled(false);

    // A service-scoped token needs RBAC: refused, no rows, on the list and a detail.
    auto svc = L.get("/api/executions", ExecutionOwnerRig::bearer(r.creds.svc_a));
    CHECK(svc.status == 403);
    CHECK(svc.body.dump().find(r.ids.minter_out) == std::string::npos);
    CHECK(L.get("/api/executions/" + r.ids.minter_out, ExecutionOwnerRig::bearer(r.creds.svc_a))
              .status == 403);
    // A non-service session of the same human is the legacy unconfined behaviour.
    CHECK(L.list_ids(ExecutionOwnerRig::bearer(r.creds.mina)) == r.all_seeded_ids());
}

TEST_CASE("owner legacy: a degraded tracker is a 503 for a service-scoped list, never an empty 200",
          "[pg][execution][owner_rig][owner_legacy][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    Legacy L{r};
    r.exec_sql("ALTER TABLE execution_tracker.executions RENAME TO executions_hidden_5557");
    auto c = L.get("/api/executions", ExecutionOwnerRig::bearer(r.creds.svc_a));
    CHECK(c.status == 503);
    CHECK(c.body["error"]["retry_after_ms"] == 5000);
    CHECK(L.audits.empty()); // a degrade is never recorded as a confinement denial
    r.exec_sql("ALTER TABLE execution_tracker.executions_hidden_5557 RENAME TO executions");
}
