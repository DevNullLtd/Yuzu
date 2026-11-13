/**
 * test_execution_owner_dashboard.cpp -- #5557: the dashboard execution fragments and the
 * /sse/executions/{id} stream under service-scoped credentials, through the shared REAL-GATE rig
 * (test_execution_owner_scope_rig.hpp).
 *
 * Surfaces: GET /fragments/executions (the list, as the regression control for the fix that
 * already covered it), GET /fragments/executions/{id}/detail and GET /sse/executions/{id}
 * (attach, buffered replay and live events). The service-scoped session carries its MINTER's
 * username; every case asserts the exact ids, agent cells and SSE frames a credential sees, that
 * the same human's non-service and cookie sessions are unchanged, and that a hidden id and a
 * never-existing id answer identically within this surface.
 */

#include "execution_event_bus.hpp"
#include "test_execution_owner_scope_rig.hpp"
#include "test_route_sink.hpp"
#include "workflow_routes.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::test::ExecutionOwnerRig;
using Ids = std::vector<std::string>;
using Hdrs = ExecutionOwnerRig::Headers;

namespace {

struct AuditCall {
    std::string action, result, target_id, detail;
};

struct Frame {
    std::string event;
    nlohmann::json data;
};

struct Resp {
    int status{0};
    std::string body;
};

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

// Every distinct value of `attr="..."` in an HTML body, sorted (a detail drawer renders each
// agent in more than one element).
Ids attr_values(const std::string& body, const std::string& attr) {
    Ids out;
    const std::string needle = attr + "=\"";
    for (auto at = body.find(needle); at != std::string::npos; at = body.find(needle, at)) {
        at += needle.size();
        out.push_back(body.substr(at, body.find('"', at) - at));
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::vector<Frame> frames_of(const std::string& wire) {
    std::vector<Frame> out;
    std::size_t at = 0;
    while (at < wire.size()) {
        auto end = wire.find("\n\n", at);
        if (end == std::string::npos)
            end = wire.size();
        const std::string block = wire.substr(at, end - at);
        at = end + 2;
        Frame f;
        std::size_t line = 0;
        while (line < block.size()) {
            auto nl = block.find('\n', line);
            if (nl == std::string::npos)
                nl = block.size();
            const std::string l = block.substr(line, nl - line);
            line = nl + 1;
            if (l.rfind("event: ", 0) == 0)
                f.event = l.substr(7);
            else if (l.rfind("data: ", 0) == 0)
                f.data = nlohmann::json::parse(l.substr(6), nullptr, false);
        }
        if (!f.event.empty() && f.event != "heartbeat")
            out.push_back(std::move(f));
    }
    return out;
}

std::vector<std::string> agents_of(const std::vector<Frame>& fs) {
    std::vector<std::string> out;
    for (const auto& f : fs)
        if (f.event == "agent-transition")
            out.push_back(f.data.value("agent_id", std::string{"?"}));
    return out;
}

// The dashboard routes wired the way server.cpp wires them: the rig's ONE real AuthRoutes feeds
// authentication, permission and fleet-read; a real tracker publishes onto a real event bus.
struct Dash {
    ExecutionOwnerRig& r;
    ExecutionEventBus& bus;
    yuzu::server::test::TestRouteSink sink;
    WorkflowRoutes routes;
    std::vector<AuditCall> audits;

    Dash(ExecutionOwnerRig& rig, ExecutionEventBus& b) : r(rig), bus(b) {
        r.tracker.set_event_bus(&bus);
        WorkflowRoutes::Deps d;
        d.auth_fn = r.auth_fn();
        d.perm_fn = r.perm_fn();
        d.fleet_read_fn = r.fleet_read_fn();
        d.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& res,
                            const std::string&, const std::string& target,
                            const std::string& detail) {
            audits.push_back({a, res, target, detail});
        };
        d.probe_perm_fn = [this](const httplib::Request& req, const std::string& t,
                                 const std::string& o) -> bool {
            httplib::Response scratch;
            return r.auth->require_permission(req, scratch, t, o);
        };
        d.execution_tracker = &r.tracker;
        d.execution_event_bus = &bus;
        routes.register_routes(sink, std::move(d));
    }

    Resp get(const std::string& path, const Hdrs& headers) {
        auto res = sink.dispatch("GET", path, {}, "application/json", headers);
        REQUIRE(res);
        return {res->status, res->body};
    }
    Ids list_ids(const Hdrs& headers) {
        auto got = get("/fragments/executions", headers);
        REQUIRE(got.status == 200);
        return attr_values(got.body, "data-execution-id");
    }
    Resp detail(const std::string& id, const Hdrs& headers) {
        return get("/fragments/executions/" + id + "/detail", headers);
    }
};

constexpr const char* kNoSuchId = "no-such-execution-5557";

} // namespace

TEST_CASE("owner dashboard: GET /fragments/executions lists exactly the service-scope executions",
          "[pg][execution][owner_rig][owner_dashboard][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionEventBus bus;
    ExecutionOwnerRig r{db.dsn()};
    const auto starving = r.seed_starvation(60);
    Dash D{r, bus};
    const auto& c = r.creds;
    const auto& id = r.ids;

    // Regression control: this list was already fixed; the shared owner key must keep it exact,
    // including past 60 newer minter rows (the page holds 50).
    auto a = D.list_ids(ExecutionOwnerRig::bearer(c.svc_a));
    CHECK(a == r.service_a_ids());
    for (const auto& s : starving)
        CHECK(std::find(a.begin(), a.end(), s) == a.end());
    CHECK(D.list_ids(ExecutionOwnerRig::bearer(c.svc_b)) ==
          ExecutionOwnerRig::sorted({id.mixed, id.run}));
    CHECK(D.list_ids(ExecutionOwnerRig::bearer(c.svc_bob_a)) ==
          ExecutionOwnerRig::sorted({id.in_a, id.mixed, id.run, id.minter_in_a}));
    CHECK(D.list_ids(ExecutionOwnerRig::bearer(c.svc_none)).empty());
    // The same humans without a service scope keep their own-dispatch rows (non-service bob).
    auto bob = D.list_ids(ExecutionOwnerRig::bearer(c.bob));
    for (const auto& want : {id.in_a, id.mixed, id.run, id.minter_in_a, id.bob_out, id.bob_pending})
        CHECK(std::find(bob.begin(), bob.end(), want) != bob.end());
    CHECK(std::find(bob.begin(), bob.end(), id.a2) == bob.end());
    CHECK(D.list_ids(ExecutionOwnerRig::cookie(r.cookie_session("mina"))).size() == 50);
}

TEST_CASE("owner dashboard: the detail fragment serves the in-scope ids and hides the minter's",
          "[pg][execution][owner_rig][owner_dashboard][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionEventBus bus;
    ExecutionOwnerRig r{db.dsn()};
    Dash D{r, bus};
    const auto& id = r.ids;
    const auto a = ExecutionOwnerRig::bearer(r.creds.svc_a);

    // Visible: the five agent-evidence ids; the agent cells hold only in-scope agents and no
    // out-of-scope error text reaches the page.
    for (const auto& vis : r.service_a_ids()) {
        INFO("visible id " << vis);
        CHECK(D.detail(vis, a).status == 200);
    }
    CHECK(attr_values(D.detail(id.run, a).body, "data-agent-id") == Ids{"a1", "a2"});
    CHECK(attr_values(D.detail(id.mixed, a).body, "data-agent-id") == Ids{"a1"});
    CHECK_FALSE(has(D.detail(id.mixed, a).body, "SECRET-B-ERR"));
    // The selected-execution panel of the executions page projects the same counts.
    CHECK(D.detail(id.run, a).body.find("b1") == std::string::npos);

    // Hidden: the minter's rows and a foreign one answer like a never-existing id, with one
    // `denied` audit row carrying the non-distinguishing detail.
    for (const std::string suffix : {"", "?view=page"}) {
        const auto absent = D.get(std::string("/fragments/executions/") + kNoSuchId + "/detail" +
                                      suffix, a);
        CHECK(absent.status == 404);
        for (const auto& hidden : {id.minter_out, id.minter_pending, id.foreign}) {
            INFO("hidden id " << hidden << " suffix " << suffix);
            D.audits.clear();
            auto got = D.get("/fragments/executions/" + hidden + "/detail" + suffix, a);
            CHECK(got.status == 404);
            CHECK(got.body == absent.body);
            REQUIRE(D.audits.size() == 1);
            CHECK(D.audits[0].action == "execution.detail.view");
            CHECK(D.audits[0].result == "denied");
            CHECK(D.audits[0].target_id == hidden);
            CHECK(has(D.audits[0].detail, "not found or outside caller's fleet-read scope"));
        }
    }
    const auto bob_a = ExecutionOwnerRig::bearer(r.creds.svc_bob_a);
    CHECK(D.detail(id.a2, bob_a).status == 404);
    CHECK(D.detail(id.bob_pending, bob_a).status == 404);
    CHECK(D.detail(id.bob_out, bob_a).status == 404);

    // Non-service sessions of the same humans: mina (global, and by cookie) sees the minter's
    // rows; the group-scoped bob reaches his own pending dispatch through the owner disjunct.
    CHECK(D.detail(id.minter_pending, ExecutionOwnerRig::bearer(r.creds.mina)).status == 200);
    CHECK(D.detail(id.minter_pending, ExecutionOwnerRig::cookie(r.cookie_session("mina")))
              .status == 200);
    CHECK(D.detail(id.bob_pending, ExecutionOwnerRig::bearer(r.creds.bob)).status == 200);

    // Service C (admitted, empty scope): every detail is not-found. dan (no grant) is refused at
    // the gate, which is not a 404.
    for (const auto& any : r.all_seeded_ids())
        CHECK(D.detail(any, ExecutionOwnerRig::bearer(r.creds.svc_none)).status == 404);
    CHECK(D.detail(id.in_a, ExecutionOwnerRig::bearer(r.creds.dan)).status != 200);
}

TEST_CASE("owner dashboard: RBAC off refuses a service-scoped token; a degraded tracker is a 503",
          "[pg][execution][owner_rig][owner_dashboard][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionEventBus bus;
    ExecutionOwnerRig r{db.dsn()};
    Dash D{r, bus};

    r.exec_sql("ALTER TABLE execution_tracker.executions RENAME TO executions_hidden_5557");
    auto degraded = D.detail(r.ids.in_a, ExecutionOwnerRig::bearer(r.creds.svc_a));
    CHECK(degraded.status == 503);
    CHECK(has(degraded.body, "Execution tracker degraded"));
    CHECK(D.audits.empty()); // a degrade is never recorded as a confinement denial
    r.exec_sql("ALTER TABLE execution_tracker.executions_hidden_5557 RENAME TO executions");

    r.rbac.set_rbac_enabled(false);
    // The fragment answers a gate refusal with its denied note (no row, no id).
    auto svc = D.get("/fragments/executions", ExecutionOwnerRig::bearer(r.creds.svc_a));
    CHECK(svc.status == 200);
    CHECK(has(svc.body, "data-denied=\"true\""));
    CHECK(attr_values(svc.body, "data-execution-id").empty());
    CHECK(D.detail(r.ids.minter_out, ExecutionOwnerRig::bearer(r.creds.svc_a)).status != 200);
    // A non-service session of the same human is unconfined, as before.
    CHECK(D.detail(r.ids.minter_out, ExecutionOwnerRig::bearer(r.creds.mina)).status == 200);
}

TEST_CASE("owner dashboard: /sse/executions/{id} attach, replay and live events for a service scope",
          "[pg][execution][owner_rig][owner_dashboard][events][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionEventBus bus;
    ExecutionOwnerRig r{db.dsn()};
    Dash D{r, bus};
    const auto& id = r.ids;
    const auto a = ExecutionOwnerRig::bearer(r.creds.svc_a);
    auto attach = [&](const std::string& exec, const Hdrs& h) {
        return D.sink.dispatch("GET", "/sse/executions/" + exec, {}, "application/json", h);
    };

    // Attach: the minter's pending execution is not-found for service A, exactly like a
    // never-existing id; a foreign execution likewise.
    const auto absent = attach(kNoSuchId, a);
    REQUIRE(absent);
    CHECK(absent->status == 404);
    for (const auto& hidden : {id.minter_pending, id.foreign}) {
        D.audits.clear();
        auto res = attach(hidden, a);
        REQUIRE(res);
        CHECK(res->status == 404);
        CHECK(res->body == absent->body);
        REQUIRE(D.audits.size() == 1);
        CHECK(D.audits[0].action == "execution.live_subscribe");
        CHECK(D.audits[0].result == "denied");
    }
    // Non-service sessions of the same humans keep their own-dispatch attach; bob-minted service
    // A is refused his own pending dispatch.
    CHECK(attach(id.minter_pending, ExecutionOwnerRig::bearer(r.creds.mina))->status == 200);
    CHECK(attach(id.bob_pending, ExecutionOwnerRig::bearer(r.creds.bob))->status == 200);
    CHECK(attach(id.bob_pending, ExecutionOwnerRig::bearer(r.creds.svc_bob_a))->status == 404);
    CHECK(attach(id.run, ExecutionOwnerRig::bearer(r.creds.svc_none))->status == 404);
    CHECK(attach(id.run, ExecutionOwnerRig::bearer(r.creds.dan))->status != 200);

    // Buffered replay: three transitions and a progress event are published BEFORE the attach.
    bus.publish(id.run, "agent-transition", R"({"agent_id":"a1","status":"running"})", false);
    bus.publish(id.run, "agent-transition", R"({"agent_id":"z1","status":"running"})", false);
    bus.publish(id.run, "agent-transition", R"({"agent_id":"b1","status":"running"})", false);
    bus.publish(id.run, "execution-progress", R"({"agents_responded":2})", false);
    auto res = attach(id.run, a);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto replayed = frames_of(yuzu::server::test::drain_chunked_provider_once(*res));
    CHECK(agents_of(replayed) == std::vector<std::string>{"a1"});
    CHECK(replayed.size() == 1);

    // Live events after the attach: a2 passes, z1 drops, and the completed event is sanitized to
    // exactly the real terminal status with no fleet counts.
    bus.publish(id.run, "agent-transition", R"({"agent_id":"a2","status":"success"})", false);
    bus.publish(id.run, "agent-transition", R"({"agent_id":"z1","status":"success"})", false);
    bus.publish(id.run, "execution-completed",
                R"({"status":"cancelled","agents_targeted":3,"agents_success":1,"agents_failure":2})",
                true);
    auto live = frames_of(yuzu::server::test::drain_chunked_provider_once(*res));
    CHECK(agents_of(live) == std::vector<std::string>{"a2"});
    const auto done = std::find_if(live.begin(), live.end(), [](const Frame& f) {
        return f.event == "execution-completed";
    });
    REQUIRE(done != live.end());
    CHECK(done->data == nlohmann::json({{"status", "cancelled"}}));
    CHECK(live.size() == 2);

    // Control: the non-service global mina is unfiltered on the same channel.
    auto mina = attach(id.run, ExecutionOwnerRig::bearer(r.creds.mina));
    REQUIRE(mina);
    auto all = agents_of(frames_of(yuzu::server::test::drain_chunked_provider_once(*mina)));
    std::sort(all.begin(), all.end());
    CHECK(all == std::vector<std::string>{"a1", "a2", "b1", "z1", "z1"});
}
