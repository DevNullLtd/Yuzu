/// @file test_hardware_sync_routes.cpp
/// Route matrix for `POST /api/v1/hardware/sync` — the Software page's "Sync now" for a
/// device / scope expression or group / whole fleet. Driven in-process through
/// TestRouteSink; the harness copies test_hardware_routes.cpp's HwHarness shape (every
/// provider a lambda over `this`) but is its own file so the sync matrix and the
/// Hardware record tests do not share one fixture. The pure rules (grammar, partition,
/// cap, cooldown, wording) have their own fixture vectors in test_software_sync_decision.cpp;
/// what is pinned HERE is the sequencing: gate -> parse -> guard -> resolve -> decide ->
/// audit -> dispatch, and that nothing is sent on any refusal.

#include "hardware_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
namespace ss = yuzu::server::software_sync;

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

struct SyncHarness {
    HardwareRoutes routes;
    yuzu::server::test::TestRouteSink sink; // declared after `routes`: its handlers capture it

    bool allow_execute = true;
    std::string username = "alice";
    bool audit_should_fail = false;

    // The resolver's answer. `ids` is what the caller can SEE (already confined).
    ss::Resolved resolved;
    std::unordered_map<std::string, std::optional<std::string>> version_by_id;
    std::optional<std::string> default_version{std::string("0.13.1")};
    // Dispatch: how many sessions accept the frame (nullopt = all of them).
    std::optional<std::size_t> accept;

    // Observations, in call order, so a test can pin audit-BEFORE-dispatch.
    std::vector<std::string> events;
    std::vector<std::string> audit_rows;    // "action|result|target_type|target_id"
    std::vector<std::string> audit_details;
    std::vector<std::string> dispatched;
    int dispatch_calls = 0;
    int resolve_calls = 0;
    ss::Selector last_selector;
    std::string last_username;
    // Runs inside the dispatch call, to re-enter the route while a run is in flight.
    std::function<void()> during_dispatch;

    explicit SyncHarness(bool wire_dispatch = true, bool wire_resolver = true) {
        resolved.status = ss::Resolved::Status::Ok;
        resolved.caller_unfiltered = true;

        HardwareRoutes::Deps deps;
        deps.auth_fn = [this](const httplib::Request&, httplib::Response&) {
            auth::Session s;
            s.username = username;
            return std::optional<auth::Session>(s);
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& tid, const std::string& d) {
            events.push_back("audit:" + r);
            audit_rows.push_back(a + "|" + r + "|" + tt + "|" + tid);
            audit_details.push_back(d);
            return !audit_should_fail;
        };
        deps.sync_perm_fn = [this](const httplib::Request&, httplib::Response& res,
                                   const std::string& type, const std::string& op) {
            if (type != "Execution" || op != "Execute")
                return false;
            if (!allow_execute)
                res.status = 403;
            return allow_execute;
        };
        deps.scoped_perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                                 const std::string&, const std::string&) { return true; };
        deps.agent_version_fn = [this](const std::string& id) -> std::optional<std::string> {
            const auto it = version_by_id.find(id);
            return it != version_by_id.end() ? it->second : default_version;
        };
        if (wire_resolver)
            deps.sync_resolve_fn = [this](const auth::Session& s, const ss::Selector& sel) {
                ++resolve_calls;
                last_selector = sel;
                last_username = s.username;
                return resolved;
            };
        if (wire_dispatch)
            deps.sync_dispatch_many_fn = [this](const std::vector<std::string>& ids) {
                ++dispatch_calls;
                events.push_back("dispatch");
                dispatched.insert(dispatched.end(), ids.begin(), ids.end());
                if (during_dispatch)
                    during_dispatch();
                return ss::DispatchResult{accept.value_or(ids.size()), "__sync__-fleet-test"};
            };
        routes.register_routes(sink, deps);
    }

    void live(std::size_t n, const std::string& prefix = "d") {
        resolved.ids.clear();
        for (std::size_t i = 0; i < n; ++i)
            resolved.ids.push_back(prefix + std::to_string(i));
    }

    std::unique_ptr<httplib::Response> post(const std::string& body) {
        return sink.Post("/api/v1/hardware/sync", body);
    }

    bool audited(const std::string& result) const {
        return std::any_of(audit_rows.begin(), audit_rows.end(), [&](const std::string& r) {
            return r.starts_with("inventory.sync.request|" + result + "|");
        });
    }
};

nlohmann::json parse(const std::string& s) { return nlohmann::json::parse(s, nullptr, false); }

} // namespace

// ── happy path ────────────────────────────────────────────────────────────────────

TEST_CASE("sync route: a fleet run is 202 with counts only, audited before anything is sent",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(4);
    h.version_by_id["d1"] = std::nullopt;                    // offline
    h.version_by_id["d2"] = std::string("0.12.9");            // below the floor
    auto res = h.post(R"({"scope":"__all__","source":"installed_software"})");
    REQUIRE(res);
    REQUIRE(res->status == 202);
    const auto body = parse(res->body);
    REQUIRE_FALSE(body.is_discarded());
    const auto& d = body["data"];
    CHECK(d["requested"] == 4);
    CHECK(d["reached"] == 2);
    CHECK(d["skipped_offline"] == 1);
    CHECK(d["skipped_version"] == 1);
    CHECK(d["command_id"] == "__sync__-fleet-test");
    CHECK(d["source"] == "installed_software");
    CHECK(d.contains("requested_at"));
    CHECK(body["meta"]["api_version"] == "v1");
    // Counts only: no device id appears anywhere in the body.
    for (const auto& id : h.resolved.ids)
        CHECK_FALSE(contains(res->body, id));
    // Only the live, new-enough devices were sent, in one dispatch call.
    CHECK(h.dispatch_calls == 1);
    CHECK(h.dispatched == std::vector<std::string>{"d0", "d3"});
    // Audit BEFORE dispatch, once, carrying scope, arm and every count.
    REQUIRE(h.events == std::vector<std::string>{"audit:requested", "dispatch"});
    REQUIRE(h.audit_rows.size() == 1);
    CHECK(h.audit_rows[0] == "inventory.sync.request|requested|Scope|__all__");
    CHECK(h.audit_details[0] ==
          "scope=__all__ arm=broadcast requested=4 reached=2 skipped_offline=1 skipped_version=1");
}

TEST_CASE("sync route: the resolver sees the parsed selector and the caller's session",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.username = "bob";
    h.live(1);
    REQUIRE(h.post(R"({"scope":"group:finance"})")->status == 202);
    CHECK(h.last_selector.arm == DispatchArm::Group);
    CHECK(h.last_selector.expr == "group:finance");
    CHECK(h.last_username == "bob");
    REQUIRE(h.post(R"({"scope_expression":"ostype == \"windows\""})")->status == 429); // bob just ran
    h.username = "carol";
    REQUIRE(h.post(R"({"scope_expression":"ostype == \"windows\""})")->status == 202);
    CHECK(h.last_selector.arm == DispatchArm::Scope);
    CHECK(h.last_selector.expr == R"(ostype == "windows")");
    CHECK(h.audit_rows.back() == "inventory.sync.request|requested|Scope|expression");
}

TEST_CASE("sync route: a single named device is allowed and needs no cooldown",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.resolved.ids = {"host-01"};
    for (int i = 0; i < 3; ++i) {
        auto res = h.post(R"({"scope":"host-01"})");
        REQUIRE(res);
        CHECK(res->status == 202);
    }
    CHECK(h.dispatch_calls == 3);
    CHECK(h.audit_rows.back() == "inventory.sync.request|requested|Agent|host-01");
}

TEST_CASE("sync route: nothing live to reach is 202 with reached 0, audited no_agents, nothing sent",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(3);
    h.default_version = std::nullopt; // everyone offline
    auto res = h.post(R"({"scope":"group:g"})");
    REQUIRE(res);
    REQUIRE(res->status == 202);
    const auto d = parse(res->body)["data"];
    CHECK(d["requested"] == 3);
    CHECK(d["reached"] == 0);
    CHECK(d["skipped_offline"] == 3);
    CHECK(h.dispatch_calls == 0);
    CHECK(h.audited("no_agents"));
    // Nothing happened, so the operator's cooldown is not spent.
    CHECK(h.post(R"({"scope":"group:g"})")->status == 202);
}

// ── refusals: nothing is ever sent ────────────────────────────────────────────────

TEST_CASE("sync route: a caller without Execution:Execute is refused before anything runs",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.allow_execute = false;
    h.live(2);
    auto res = h.post(R"({"scope":"__all__"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.resolve_calls == 0);
    CHECK(h.dispatch_calls == 0);
}

TEST_CASE("sync route: whole-fleet sync needs an unfiltered Execution:Execute", "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(3);
    h.resolved.caller_unfiltered = false; // a management-group-confined operator
    auto res = h.post(R"({"scope":"__all__"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(contains(res->body, "fleet-wide Execution:Execute"));
    CHECK(h.dispatch_calls == 0);
    CHECK(h.audited("denied"));
    CHECK(contains(h.audit_details.back(), "fleet_wide_required"));
    // The same operator may still sync a group or an expression within their own set.
    CHECK(h.post(R"({"scope":"group:mine"})")->status == 202);
    CHECK(h.dispatch_calls == 1);
}

TEST_CASE("sync route: malformed requests are 400, audited denied, and never reach the resolver",
          "[hardware][sync_fanout][route]") {
    const char* bad[] = {
        "",                                                   // no body
        "{not json",
        "[]",
        R"({})",                                              // names no target
        R"({"scope":"__all__","scope_expression":"__all__"})",
        R"({"scope":42})",
        R"({"scope":"__all__","source":"all"})",
        R"({"scope":"group:"})",
    };
    for (const char* b : bad) {
        INFO(b);
        SyncHarness h;
        auto res = h.post(b);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(h.resolve_calls == 0);
        CHECK(h.dispatch_calls == 0);
        CHECK(h.audited("denied"));
    }
}

TEST_CASE("sync route: an unparseable scope expression is 400 and sends nothing", "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.resolved.status = ss::Resolved::Status::InvalidScope;
    h.resolved.detail = "unexpected token";
    auto res = h.post(R"({"scope_expression":"ostype =="})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(contains(res->body, "invalid scope: unexpected token"));
    CHECK(h.dispatch_calls == 0);
    CHECK(h.audited("denied"));
}

TEST_CASE("sync route: a scope that could not be evaluated is 503, never 'no matches'",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.resolved.status = ss::Resolved::Status::Aborted;
    h.resolved.detail = "owner_check_failed";
    auto res = h.post(R"({"scope_expression":"from_result_set:abc"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK_FALSE(contains(res->body, "owner_check_failed")); // not an oracle for result-set ownership
    CHECK(h.dispatch_calls == 0);
    CHECK(h.audited("failure"));
    CHECK(contains(h.audit_details.back(), "owner_check_failed"));
}

// ── bounds ────────────────────────────────────────────────────────────────────────

TEST_CASE("sync route: 501 reachable devices is 413 with the count, 500 is allowed",
          "[hardware][sync_fanout][route][security]") {
    {
        SyncHarness h;
        h.live(501);
        auto res = h.post(R"({"scope":"__all__"})");
        REQUIRE(res);
        CHECK(res->status == 413);
        CHECK(contains(res->body, "501"));
        CHECK(contains(res->body, "500"));
        CHECK(h.dispatch_calls == 0);
        CHECK(h.audited("denied"));
        CHECK(contains(h.audit_details.back(), "over_cap"));
        // A refusal for size does not start the operator's cooldown.
        h.live(2);
        CHECK(h.post(R"({"scope":"__all__"})")->status == 202);
    }
    {
        SyncHarness h;
        h.live(500);
        auto res = h.post(R"({"scope":"__all__"})");
        REQUIRE(res);
        CHECK(res->status == 202);
        CHECK(parse(res->body)["data"]["reached"] == 500);
        CHECK(h.dispatched.size() == 500);
    }
}

TEST_CASE("sync route: the cap counts devices that will be sent to, not devices merely named",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(700);
    for (std::size_t i = 0; i < 300; ++i)
        h.version_by_id["d" + std::to_string(i)] = std::nullopt; // 300 offline -> 400 live
    auto res = h.post(R"({"scope":"__all__"})");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto d = parse(res->body)["data"];
    CHECK(d["requested"] == 700);
    CHECK(d["reached"] == 400);
    CHECK(d["skipped_offline"] == 300);
}

TEST_CASE("sync route: a second run by the same operator inside 60 s is 429 with Retry-After",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(2);
    REQUIRE(h.post(R"({"scope":"__all__"})")->status == 202);
    auto again = h.post(R"({"scope":"group:g"})");
    REQUIRE(again);
    CHECK(again->status == 429);
    const int retry = std::stoi(again->get_header_value("Retry-After"));
    CHECK(retry >= 1);
    CHECK(retry <= 60);
    CHECK(h.dispatch_calls == 1); // the second run sent nothing
    CHECK(h.resolve_calls == 1);  // and was refused before resolving
    CHECK(h.audited("denied"));
    CHECK(contains(h.audit_details.back(), "rate_limited"));
    // Another operator is not held back by this one's run.
    h.username = "bob";
    CHECK(h.post(R"({"scope":"group:g"})")->status == 202);
}

TEST_CASE("sync route: a run already in flight makes a second one 409 and sends nothing",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(2);
    int inner_status = 0;
    int inner_dispatches_before = -1;
    h.during_dispatch = [&] {
        inner_dispatches_before = h.dispatch_calls;
        h.username = "bob"; // a different operator, so only the in-flight guard can refuse
        auto r = h.post(R"({"scope":"__all__"})");
        inner_status = r ? r->status : -1;
        h.username = "alice";
    };
    REQUIRE(h.post(R"({"scope":"__all__"})")->status == 202);
    CHECK(inner_status == 409);
    CHECK(h.dispatch_calls == 1);
    CHECK(inner_dispatches_before == 1);
    // The flag is released afterwards: bob can run now.
    h.during_dispatch = nullptr;
    h.username = "bob";
    CHECK(h.post(R"({"scope":"__all__"})")->status == 202);
}

TEST_CASE("sync route: a single-device sync is not held by a multi-device run in flight",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(2);
    int inner_status = 0;
    bool inside = false; // the inner request dispatches too; do not re-enter from it
    h.during_dispatch = [&] {
        if (inside)
            return;
        inside = true;
        h.resolved.ids = {"host-01"};
        auto r = h.post(R"({"scope":"host-01"})");
        inner_status = r ? r->status : -1;
    };
    REQUIRE(h.post(R"({"scope":"__all__"})")->status == 202);
    CHECK(inner_status == 202);
}

// ── audit and dispatch failure ────────────────────────────────────────────────────

TEST_CASE("sync route: an audit-store degrade fails CLOSED with zero dispatches",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(3);
    h.audit_should_fail = true;
    auto res = h.post(R"({"scope":"__all__"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.dispatch_calls == 0);
    // A refused-for-audit run did not spend the cooldown either.
    h.audit_should_fail = false;
    CHECK(h.post(R"({"scope":"__all__"})")->status == 202);
}

TEST_CASE("sync route: every send refused is 503 and leaves the cooldown unspent",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(3);
    h.accept = 0;
    auto res = h.post(R"({"scope":"__all__"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.audited("requested")); // the pre-dispatch row is the durable evidence of the ask
    h.accept = std::nullopt;
    CHECK(h.post(R"({"scope":"__all__"})")->status == 202);
}

TEST_CASE("sync route: a partly refused send reports only what was accepted", "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(5);
    h.accept = 3;
    auto res = h.post(R"({"scope":"__all__"})");
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto d = parse(res->body)["data"];
    CHECK(d["requested"] == 5);
    CHECK(d["reached"] == 3);
    CHECK(d["skipped_offline"] == 2);
}

TEST_CASE("sync route: unwired dependencies fail closed", "[hardware][sync_fanout][route]") {
    {
        SyncHarness h(/*wire_dispatch=*/false);
        h.live(1);
        auto res = h.post(R"({"scope":"__all__"})");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(h.resolve_calls == 0);
    }
    {
        SyncHarness h(/*wire_dispatch=*/true, /*wire_resolver=*/false);
        auto res = h.post(R"({"scope":"__all__"})");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(h.dispatch_calls == 0);
    }
}

TEST_CASE("sync route: the per-device sync route is still its own route", "[hardware][sync_fanout][route]") {
    // `/api/v1/hardware/sync` must not be swallowed by `/api/v1/hardware/{id}/sync` (or the
    // reverse): the collection route has no id segment, the device route has one.
    SyncHarness h;
    h.live(1);
    CHECK(h.post(R"({"scope":"__all__"})")->status == 202);
    auto device = h.sink.Post("/api/v1/hardware/agent-1/sync", "");
    REQUIRE(device); // registered, and it is the per-device handler (unwired -> 503, not our 202)
    CHECK(device->status == 503);
}
