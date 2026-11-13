/**
 * test_execution_owner_rest_v1.cpp -- #5557: the REST v1 execution reads and the events stream
 * under service-scoped credentials, through the shared REAL-GATE rig
 * (test_execution_owner_scope_rig.hpp).
 *
 * Surfaces: GET /api/v1/executions, GET /api/v1/executions/{id} (with and without
 * include=agents), GET /api/v1/executions/{id}/children and GET /api/v1/events (attach,
 * buffered replay and live events). The service-scoped session carries its MINTER's username;
 * every case asserts the exact ids, projected counts, agent rows and SSE frames a credential
 * sees, that the same human's non-service sessions are unchanged, and that a hidden id and a
 * never-existing id answer identically within this surface.
 *
 * The mutation routes (cancel/rerun) are the mutation-key conversion's surface, not this one.
 */

#include "execution_event_bus.hpp"
#include "rest_api_v1.hpp"
#include "test_execution_owner_scope_rig.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

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

struct Frame {
    std::string event;
    nlohmann::json data;
};

// The REST v1 routes wired the way server.cpp wires them: the rig's ONE real AuthRoutes feeds
// authentication, permission and fleet-read; a real tracker publishes onto a real event bus.
struct RestV1 {
    ExecutionOwnerRig& r;
    ExecutionEventBus& bus;
    yuzu::MetricsRegistry metrics;
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;
    std::vector<AuditCall> audits;

    RestV1(ExecutionOwnerRig& rig, ExecutionEventBus& b) : r(rig), bus(b) {
        r.tracker.set_event_bus(&bus);
        auto audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& res,
                               const std::string&, const std::string& target,
                               const std::string& detail) -> bool {
            audits.push_back({a, res, target, detail});
            return true;
        };
        api.register_routes(sink, r.auth_fn(), r.perm_fn(), audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr, &r.tracker,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{}, &bus,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr, /*auth_db=*/nullptr,
                            /*directory_sync=*/nullptr, /*stream_budget=*/nullptr,
                            /*exec_visible_fn=*/{}, /*list_read_fn=*/{}, r.fleet_read_fn());
    }

    Call get(const std::string& path, const Hdrs& headers) {
        auto res = sink.dispatch("GET", path, {}, "application/json", headers);
        REQUIRE(res);
        Call c{res->status, {}};
        c.body = nlohmann::json::parse(res->body, nullptr, false);
        return c;
    }
    Ids list_ids(const Hdrs& headers, const std::string& query = "?limit=50") {
        auto c = get("/api/v1/executions" + query, headers);
        REQUIRE(c.status == 200);
        Ids ids;
        for (const auto& e : c.body["data"])
            ids.push_back(e["id"].get<std::string>());
        std::sort(ids.begin(), ids.end());
        return ids;
    }
    nlohmann::json list_row(const Hdrs& headers, const std::string& id) {
        auto c = get("/api/v1/executions?limit=50", headers);
        REQUIRE(c.status == 200);
        for (const auto& e : c.body["data"])
            if (e["id"] == id)
                return e;
        FAIL("row not listed: " << id);
        return {};
    }
    Ids child_ids(const std::string& parent, const Hdrs& headers, bool* truncated = nullptr) {
        auto c = get("/api/v1/executions/" + parent + "/children", headers);
        REQUIRE(c.status == 200);
        Ids out;
        for (const auto& e : c.body["data"]["children"])
            out.push_back(e["id"].get<std::string>());
        std::sort(out.begin(), out.end());
        if (truncated)
            *truncated = c.body["data"].contains("result_truncated_by_cap");
        return out;
    }
};

// A body with the per-request correlation id removed, so a hidden id and a never-existing id can
// be compared for equality WITHIN this surface.
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

// One drained provider invocation as frames, heartbeats removed. Each wire block is
// `id: N\nevent: T\ndata: <envelope>\n\n`.
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

std::vector<std::string> agents_of(const std::vector<Frame>& fs, const std::string& type) {
    std::vector<std::string> out;
    for (const auto& f : fs)
        if (f.event == type)
            out.push_back(f.data["payload"].value("agent_id", std::string{"?"}));
    return out;
}

constexpr const char* kNoSuchId = "no-such-execution-5557";

} // namespace

TEST_CASE("owner rest v1: GET /api/v1/executions lists exactly the service-scope executions",
          "[pg][execution][owner_rig][owner_rest][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionEventBus bus;
    ExecutionOwnerRig r{db.dsn()};
    RestV1 V{r, bus};
    const auto& c = r.creds;
    const auto& id = r.ids;

    CHECK(V.list_ids(ExecutionOwnerRig::bearer(c.svc_a)) == r.service_a_ids());
    CHECK(V.list_ids(ExecutionOwnerRig::bearer(c.svc_b)) ==
          ExecutionOwnerRig::sorted({id.mixed, id.run}));
    CHECK(V.list_ids(ExecutionOwnerRig::bearer(c.svc_bob_a)) ==
          ExecutionOwnerRig::sorted({id.in_a, id.mixed, id.run, id.minter_in_a}));
    CHECK(V.list_ids(ExecutionOwnerRig::bearer(c.svc_none)).empty());

    // The same humans without a service scope are unchanged.
    CHECK(V.list_ids(ExecutionOwnerRig::bearer(c.bob)) ==
          ExecutionOwnerRig::sorted({id.in_a, id.mixed, id.run, id.minter_in_a, id.bob_out,
                                     id.bob_pending}));
    CHECK(V.list_ids(ExecutionOwnerRig::bearer(c.mina)) == r.all_seeded_ids());
    CHECK(V.list_ids(ExecutionOwnerRig::cookie(r.cookie_session("mina"))) ==
          r.all_seeded_ids());

    // No Execution:Read: refused at the gate.
    CHECK(V.get("/api/v1/executions", ExecutionOwnerRig::bearer(c.dan)).status == 403);
}

TEST_CASE("owner rest v1: the list projects only in-scope agent rows and counts",
          "[pg][execution][owner_rig][owner_rest][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionEventBus bus;
    ExecutionOwnerRig r{db.dsn()};
    RestV1 V{r, bus};
    const auto& id = r.ids;
    const auto a = ExecutionOwnerRig::bearer(r.creds.svc_a);
    const auto b = ExecutionOwnerRig::bearer(r.creds.svc_b);

    auto mixed = V.list_row(a, id.mixed);
    CHECK(mixed["agents_targeted"] == 1);
    CHECK(mixed["agents_responded"] == 1);
    CHECK(mixed["agents_success"] == 1);
    CHECK(mixed["agents_failure"] == 0);
    auto run = V.list_row(a, id.run);
    CHECK(run["agents_targeted"] == 2);
    CHECK(run["agents_responded"] == 1); // running is targeted, not responded
    CHECK(run["agents_success"] == 1);
    CHECK(run["agents_failure"] == 0);
    CHECK(V.get("/api/v1/executions?limit=50", a).body.dump().find("SECRET-B-ERR") ==
          std::string::npos);

    auto mixed_b = V.list_row(b, id.mixed);
    CHECK(mixed_b["agents_targeted"] == 1);
    CHECK(mixed_b["agents_failure"] == 1);
    CHECK(mixed_b["error_preview"] == "SECRET-B-ERR"); // service B's own agent's error text
    auto run_b = V.list_row(b, id.run);
    CHECK(run_b["agents_targeted"] == 1);
    CHECK(run_b["agents_responded"] == 0);
}

TEST_CASE("owner rest v1: 60 newer minter rows cannot starve a service-scoped list page",
          "[pg][execution][owner_rig][owner_rest][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionEventBus bus;
    ExecutionOwnerRig r{db.dsn()};
    const auto starving = r.seed_starvation(60);
    RestV1 V{r, bus};

    auto ids = V.list_ids(ExecutionOwnerRig::bearer(r.creds.svc_a), "?limit=50");
    CHECK(ids == r.service_a_ids());
    for (const auto& s : starving)
        CHECK(std::find(ids.begin(), ids.end(), s) == ids.end());
    CHECK(V.list_ids(ExecutionOwnerRig::bearer(r.creds.mina), "?limit=50").size() == 50);
}

TEST_CASE("owner rest v1: detail, include=agents and children for a service-scoped credential",
          "[pg][execution][owner_rig][owner_rest][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionEventBus bus;
    ExecutionOwnerRig r{db.dsn()};
    const auto kids = r.seed_children();
    const auto cap = r.seed_children_cap();
    RestV1 V{r, bus};
    const auto& id = r.ids;
    const auto a = ExecutionOwnerRig::bearer(r.creds.svc_a);

    // Visible, with and without the per-agent expansion; agent rows hold only a1/a2.
    for (const auto& vis : r.service_a_ids()) {
        INFO("visible id " << vis);
        CHECK(V.get("/api/v1/executions/" + vis, a).status == 200);
        CHECK(V.get("/api/v1/executions/" + vis + "?include=agents", a).status == 200);
    }
    auto run = V.get("/api/v1/executions/" + id.run + "?include=agents", a);
    CHECK(run.body["data"]["agents_targeted"] == 2);
    CHECK(run.body["data"]["agents_responded"] == 1);
    Ids run_agents;
    for (const auto& x : run.body["data"]["agents"])
        run_agents.push_back(x["agent_id"].get<std::string>());
    std::sort(run_agents.begin(), run_agents.end());
    CHECK(run_agents == Ids{"a1", "a2"});
    auto mixed = V.get("/api/v1/executions/" + id.mixed + "?include=agents", a);
    REQUIRE(mixed.body["data"]["agents"].size() == 1);
    CHECK(mixed.body["data"]["agents"][0]["agent_id"] == "a1");
    CHECK(mixed.body.dump().find("SECRET-B-ERR") == std::string::npos);

    // Hidden: the minter's rows and a foreign one answer like a never-existing id, with one
    // `denied` audit row carrying the non-distinguishing detail.
    for (const std::string suffix : {"", "?include=agents"}) {
        const auto absent = V.get(std::string("/api/v1/executions/") + kNoSuchId + suffix, a);
        CHECK(absent.status == 404);
        for (const auto& hidden : {id.minter_out, id.minter_pending, id.foreign}) {
            INFO("hidden id " << hidden << " suffix " << suffix);
            V.audits.clear();
            auto got = V.get("/api/v1/executions/" + hidden + suffix, a);
            CHECK(got.status == 404);
            CHECK(normalized(got.body) == normalized(absent.body));
            REQUIRE(V.audits.size() == 1);
            CHECK(V.audits[0].action == "execution.detail.fetch");
            CHECK(V.audits[0].result == "denied");
            CHECK(V.audits[0].target_id == hidden);
            CHECK(V.audits[0].detail.find("not found or outside caller's fleet-read scope") !=
                  std::string::npos);
        }
    }
    const auto bob_a = ExecutionOwnerRig::bearer(r.creds.svc_bob_a);
    CHECK(V.get("/api/v1/executions/" + id.a2, bob_a).status == 404);
    CHECK(V.get("/api/v1/executions/" + id.bob_pending, bob_a).status == 404);

    // Non-service sessions of the same humans: mina sees the minter's rows; the group-scoped
    // bob reaches his own pending dispatch through the owner disjunct.
    CHECK(V.get("/api/v1/executions/" + id.minter_pending,
                ExecutionOwnerRig::bearer(r.creds.mina)).status == 200);
    CHECK(V.get("/api/v1/executions/" + id.bob_pending,
                ExecutionOwnerRig::bearer(r.creds.bob)).status == 200);

    // Service C (admitted, empty scope): every detail is not-found; dan is a 403 at the gate.
    for (const auto& any : r.all_seeded_ids())
        CHECK(V.get("/api/v1/executions/" + any, ExecutionOwnerRig::bearer(r.creds.svc_none))
                  .status == 404);
    CHECK(V.get("/api/v1/executions/" + id.in_a, ExecutionOwnerRig::bearer(r.creds.dan)).status ==
          403);

    // Children: only the visible child of P_in, the older visible child past the cap, and a
    // hidden parent is not-found although it has a visible child.
    CHECK(V.child_ids(kids.parent_in, a) == Ids{kids.c_in});
    bool truncated = true;
    CHECK(V.child_ids(cap.parent_cap, a, &truncated) == Ids{cap.c_old_in});
    CHECK_FALSE(truncated); // the marker reflects only the VISIBLE rows
    const auto absent_children =
        V.get(std::string("/api/v1/executions/") + kNoSuchId + "/children", a);
    CHECK(absent_children.status == 404);
    auto hidden_children = V.get("/api/v1/executions/" + kids.parent_minter_out + "/children", a);
    CHECK(hidden_children.status == 404);
    CHECK(normalized(hidden_children.body) == normalized(absent_children.body));
    // Non-service mina is unconfined: all four, and the cap truncation is reported.
    CHECK(V.child_ids(kids.parent_in, ExecutionOwnerRig::bearer(r.creds.mina)) ==
          ExecutionOwnerRig::sorted(
              {kids.c_in, kids.c_minter_out, kids.c_minter_pending, kids.c_b}));
    V.child_ids(cap.parent_cap, ExecutionOwnerRig::bearer(r.creds.mina), &truncated);
    CHECK(truncated);
}

TEST_CASE("owner rest v1: RBAC off refuses a service-scoped token; a degraded tracker is a 503",
          "[pg][execution][owner_rig][owner_rest][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionEventBus bus;
    ExecutionOwnerRig r{db.dsn()};
    RestV1 V{r, bus};

    // Degraded read first (RBAC on): 503 with a retry hint, no rows, no `denied` audit row.
    r.exec_sql("ALTER TABLE execution_tracker.executions RENAME TO executions_hidden_5557");
    auto degraded = V.get("/api/v1/executions", ExecutionOwnerRig::bearer(r.creds.svc_a));
    CHECK(degraded.status == 503);
    CHECK(degraded.body["error"]["retry_after_ms"] == 5000);
    CHECK(V.audits.empty());
    r.exec_sql("ALTER TABLE execution_tracker.executions_hidden_5557 RENAME TO executions");

    r.rbac.set_rbac_enabled(false);
    auto svc = V.get("/api/v1/executions", ExecutionOwnerRig::bearer(r.creds.svc_a));
    CHECK(svc.status == 403);
    CHECK(svc.body.dump().find(r.ids.minter_out) == std::string::npos);
    CHECK(V.get("/api/v1/executions/" + r.ids.minter_out,
                ExecutionOwnerRig::bearer(r.creds.svc_a)).status == 403);
    CHECK(V.list_ids(ExecutionOwnerRig::bearer(r.creds.mina)) == r.all_seeded_ids());
}

TEST_CASE("owner rest v1: GET /api/v1/events attach, replay and live events for a service scope",
          "[pg][execution][owner_rig][owner_rest][events][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionEventBus bus;
    ExecutionOwnerRig r{db.dsn()};
    RestV1 V{r, bus};
    const auto& id = r.ids;
    const auto a = ExecutionOwnerRig::bearer(r.creds.svc_a);
    auto events = [&](const std::string& exec, const Hdrs& h) {
        return V.sink.dispatch("GET", "/api/v1/events?since=0&execution_id=" + exec, {},
                               "application/json", h);
    };

    // Attach: the minter's pending execution (running) is not-found for service A, exactly like a
    // never-existing id; E_run (a1/a2 evidence) is admitted. A foreign execution is not-found.
    const auto absent = events(kNoSuchId, a);
    REQUIRE(absent);
    CHECK(absent->status == 404);
    for (const auto& hidden : {id.minter_pending, id.foreign}) {
        V.audits.clear();
        auto res = events(hidden, a);
        REQUIRE(res);
        CHECK(res->status == 404);
        CHECK(normalized(nlohmann::json::parse(res->body)) ==
              normalized(nlohmann::json::parse(absent->body)));
        REQUIRE(V.audits.size() == 1);
        CHECK(V.audits[0].action == "api.v1.events.subscribe");
        CHECK(V.audits[0].result == "denied");
    }
    // The non-service sessions of the same humans keep their own-dispatch attach.
    {
        auto res = events(id.minter_pending, ExecutionOwnerRig::bearer(r.creds.mina));
        REQUIRE(res);
        CHECK(res->status == 200);
        auto bob = events(id.bob_pending, ExecutionOwnerRig::bearer(r.creds.bob));
        REQUIRE(bob);
        CHECK(bob->status == 200);
        CHECK(events(id.bob_pending, ExecutionOwnerRig::bearer(r.creds.svc_bob_a))->status == 404);
    }
    // Service C (admitted, empty scope) and dan (no grant).
    CHECK(events(id.run, ExecutionOwnerRig::bearer(r.creds.svc_none))->status == 404);
    CHECK(events(id.run, ExecutionOwnerRig::bearer(r.creds.dan))->status == 403);

    // Buffered replay: three transitions and a progress event were published BEFORE the attach.
    bus.publish(id.run, "agent-transition", R"({"agent_id":"a1","status":"running"})", false);
    bus.publish(id.run, "agent-transition", R"({"agent_id":"z1","status":"running"})", false);
    bus.publish(id.run, "agent-transition", R"({"agent_id":"b1","status":"running"})", false);
    bus.publish(id.run, "execution-progress", R"({"agents_responded":2})", false);
    auto res = events(id.run, a);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto replayed = frames_of(yuzu::server::test::drain_chunked_provider_once(*res));
    CHECK(agents_of(replayed, "agent-transition") == std::vector<std::string>{"a1"});
    CHECK(agents_of(replayed, "execution-progress").empty());
    CHECK(replayed.size() == 1);

    // Live events after the attach: a2 passes, z1 drops, and the completed event is sanitized to
    // exactly the real terminal status with no fleet counts.
    bus.publish(id.run, "agent-transition", R"({"agent_id":"a2","status":"success"})", false);
    bus.publish(id.run, "agent-transition", R"({"agent_id":"z1","status":"success"})", false);
    bus.publish(id.run, "execution-completed",
                R"({"status":"cancelled","agents_targeted":3,"agents_success":1,"agents_failure":2})",
                true);
    auto live = frames_of(yuzu::server::test::drain_chunked_provider_once(*res));
    CHECK(agents_of(live, "agent-transition") == std::vector<std::string>{"a2"});
    const auto done = std::find_if(live.begin(), live.end(), [](const Frame& f) {
        return f.event == "execution-completed";
    });
    REQUIRE(done != live.end());
    CHECK(done->data["payload"] == nlohmann::json({{"status", "cancelled"}}));
    CHECK(live.size() == 2);

    // Control: the non-service global mina is unfiltered on the same channel (replay holds all
    // seven published events' agent transitions).
    auto mina = events(id.run, ExecutionOwnerRig::bearer(r.creds.mina));
    REQUIRE(mina);
    auto all = frames_of(yuzu::server::test::drain_chunked_provider_once(*mina));
    auto transitions = agents_of(all, "agent-transition");
    std::sort(transitions.begin(), transitions.end());
    CHECK(transitions == std::vector<std::string>{"a1", "a2", "b1", "z1", "z1"});
}
