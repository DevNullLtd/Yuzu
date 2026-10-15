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

// Which dependencies are wired. Every one defaults to wired; a test turns one off. Declared
// outside the harness: a nested type with default member initializers cannot be used in the
// enclosing class's own default argument.
struct SyncWiring {
    bool perm = true, auth = true, resolver = true, dispatch = true, precheck = true, version = true,
         audit = true, clock = true;
};

struct SyncHarness {
    HardwareRoutes routes;
    yuzu::server::test::TestRouteSink sink; // declared after `routes`: its handlers capture it

    bool allow_execute = true;
    std::string username = "alice";
    std::string auth_source;       // "api_token" etc.: what the same-site gate sees
    bool audit_should_fail = false;
    std::int64_t clock = 1'700'000'000; // the route's injected "now" (seconds)

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
    int precheck_calls = 0;
    // The cheap "is this caller unfiltered" pre-check. Unset: it agrees with the resolver's answer.
    std::optional<bool> precheck_override;
    ss::Selector last_selector;
    std::string last_username;
    // Runs inside the dispatch call, to re-enter the route while a run is in flight.
    std::function<void()> during_dispatch;
    // Runs inside every audit write, to prove what the route holds while it writes.
    std::function<void()> on_audit;
    // Runs on every read of the injected clock (before it returns), to interleave a competing
    // request at an exact point of the route.
    std::function<void()> on_clock;

    explicit SyncHarness(SyncWiring w = {}) {
        resolved.status = ss::Resolved::Status::Ok;
        resolved.caller_unfiltered = true;

        HardwareRoutes::Deps deps;
        if (w.auth)
            deps.auth_fn = [this](const httplib::Request&, httplib::Response&) {
                auth::Session s;
                s.username = username;
                return std::optional<auth::Session>(s);
            };
        if (w.audit)
            deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                                   const std::string& tt, const std::string& tid, const std::string& d) {
                events.push_back("audit:" + r);
                audit_rows.push_back(a + "|" + r + "|" + tt + "|" + tid);
                audit_details.push_back(d);
                if (on_audit)
                    on_audit();
                return !audit_should_fail;
            };
        if (w.perm)
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
        if (w.version)
            deps.agent_version_fn = [this](const std::string& id) -> std::optional<std::string> {
                const auto it = version_by_id.find(id);
                return it != version_by_id.end() ? it->second : default_version;
            };
        // The fleet run exists only when every closure it needs is wired: a missing one leaves
        // the route's runner empty, which is the audited 500 the unwired tests pin.
        if (w.resolver && w.dispatch && w.precheck && w.version) {
            ss::Env env;
            env.resolve = [this](const auth::Session& s, const ss::Selector& sel) {
                ++resolve_calls;
                last_selector = sel;
                last_username = s.username;
                return resolved;
            };
            env.dispatch = [this](const auth::Session&, const std::vector<std::string>& ids) {
                ++dispatch_calls;
                events.push_back("dispatch");
                dispatched.insert(dispatched.end(), ids.begin(), ids.end());
                if (during_dispatch)
                    during_dispatch();
                return ss::DispatchResult{accept.value_or(ids.size()), "__sync__-fleet-test"};
            };
            env.caller_unfiltered = [this](const auth::Session&) {
                ++precheck_calls;
                return precheck_override.value_or(resolved.caller_unfiltered);
            };
            env.agent_version = deps.agent_version_fn;
            if (w.clock)
                env.now = [this] {
                    if (on_clock)
                        on_clock();
                    return clock;
                };
            deps.sync_runner = std::make_shared<ss::Runner>(std::move(env));
        }
        deps.write_gate.resolve_session = [this](const httplib::Request&) {
            auth::Session s;
            s.username = username;
            s.auth_source = auth_source;
            return std::optional<auth::Session>(s);
        };
        // A browser sends these on every same-origin write; the same-site tests override them.
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
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


// Bodies with escaped quotes are spelled as ordinary literals held in constants, not as raw
// strings inside REQUIRE(...): MSVC's preprocessor mis-lexes a raw string with embedded quotes
// inside a macro argument ("invalid literal suffix", C2014-class errors) and the Windows leg
// fails to compile.
const std::string kBodyWindows = "{\"scope_expression\":\"ostype == \\\"windows\\\"\"}";
const std::string kBodyLinux = "{\"scope_expression\":\"ostype == \\\"linux\\\"\"}";

} // namespace

// ── happy path ────────────────────────────────────────────────────────────────────

TEST_CASE("sync route: a fleet run is 202 with counts only; audited before anything is sent",
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
    CHECK(d["agents_reached"] == 2);
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

TEST_CASE("sync route: a device with no session on this server is skipped_offline; whatever its reason",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(4);
    // d1 is disconnected; d2 is attached to another replica. This route sees the same thing for
    // both (no session on this process), counts both in skipped_offline and never sends to them.
    h.version_by_id["d1"] = std::nullopt;
    h.version_by_id["d2"] = std::nullopt;
    auto res = h.post(R"({"scope":"group:g"})");
    REQUIRE(res);
    REQUIRE(res->status == 202);
    const auto d = parse(res->body)["data"];
    CHECK(d["requested"] == 4);
    CHECK(d["agents_reached"] == 2);
    CHECK(d["skipped_offline"] == 2);
    CHECK_FALSE(d.contains("skipped_other_replica"));
    CHECK(h.dispatched == std::vector<std::string>{"d0", "d3"});
    REQUIRE(h.audit_details.size() == 1);
    CHECK(h.audit_details[0] ==
          "scope=group:g arm=group requested=4 reached=2 skipped_offline=2 skipped_version=0");
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
    REQUIRE(h.post(kBodyWindows)->status == 429); // bob just ran
    h.username = "carol";
    REQUIRE(h.post(kBodyWindows)->status == 202);
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

TEST_CASE("sync route: nothing live to reach is 202 with reached 0; audited no_agents; nothing sent",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(3);
    h.default_version = std::nullopt; // everyone offline
    auto res = h.post(R"({"scope":"group:g"})");
    REQUIRE(res);
    REQUIRE(res->status == 202);
    const auto d = parse(res->body)["data"];
    CHECK(d["requested"] == 3);
    CHECK(d["agents_reached"] == 0);
    CHECK(d["skipped_offline"] == 3);
    CHECK(h.dispatch_calls == 0);
    CHECK(h.audited("no_agents"));
    // The resolve and the lookups were paid for, so the operator's cooldown is spent.
    CHECK(h.post(R"({"scope":"group:g"})")->status == 429);
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
    CHECK(h.resolve_calls == 0); // refused before the fleet is read
    CHECK(h.audited("denied"));
    CHECK(contains(h.audit_details.back(), "fleet_wide_required"));
    // The same operator may still sync a group or an expression within their own set.
    CHECK(h.post(R"({"scope":"group:mine"})")->status == 202);
    CHECK(h.dispatch_calls == 1);
}

TEST_CASE("sync route: a confined caller's __all__ is refused before the run guard and the fleet read",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(3);
    h.resolved.caller_unfiltered = false;
    auto res = h.post(R"({"scope":"__all__"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.precheck_calls == 1);
    CHECK(h.resolve_calls == 0); // the resolver is what reads the fleet
    CHECK(h.dispatch_calls == 0);
    CHECK(h.audit_rows.back() == "inventory.sync.request|denied|Scope|__all__");
    CHECK(contains(h.audit_details.back(), "fleet_wide_required"));
    // The refusal took no slot and no cooldown: a legitimate run goes straight through.
    CHECK(h.post(R"({"scope":"group:g"})")->status == 202);
    CHECK(h.dispatch_calls == 1);
}

TEST_CASE("sync route: a refused __all__ does not occupy the in-flight slot of a run in progress",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(2);
    int inner_status = 0;
    int resolves_before = 0;
    h.during_dispatch = [&] {
        resolves_before = h.resolve_calls;
        h.username = "mallory";
        h.resolved.caller_unfiltered = false; // a confined operator asks for the fleet mid-run
        auto r = h.post(R"({"scope":"__all__"})");
        inner_status = r ? r->status : -1;
        h.resolved.caller_unfiltered = true;
        h.username = "alice";
    };
    REQUIRE(h.post(R"({"scope":"group:g"})")->status == 202);
    // 403, not 409: it was refused on who it was, before the guard was even consulted.
    CHECK(inner_status == 403);
    CHECK(h.resolve_calls == resolves_before); // and it read nothing
    CHECK(h.dispatch_calls == 1);
}

TEST_CASE("sync route: if the pre-check and the resolver disagree the stricter answer wins",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(3);
    h.precheck_override = true;           // the pre-check admits...
    h.resolved.caller_unfiltered = false; // ...but the resolver says the caller is confined
    auto res = h.post(R"({"scope":"__all__"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.resolve_calls == 1);
    CHECK(h.dispatch_calls == 0);
    CHECK(contains(h.audit_details.back(), "fleet_wide_required"));
}

TEST_CASE("sync route: only a fleet request asks the pre-check", "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(2);
    REQUIRE(h.post(R"({"scope":"group:g"})")->status == 202);
    h.username = "bob";
    REQUIRE(h.post(kBodyLinux)->status == 202);
    h.resolved.ids = {"host-01"};
    REQUIRE(h.post(R"({"scope":"host-01"})")->status == 202);
    CHECK(h.precheck_calls == 0);
    h.live(2);
    h.username = "carol";
    REQUIRE(h.post(R"({"scope":"__all__"})")->status == 202);
    CHECK(h.precheck_calls == 1);
}

TEST_CASE("sync route: malformed requests are 400; audited denied; and never reach the resolver",
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

TEST_CASE("sync route: a scope that could not be evaluated is 503; never 'no matches'",
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

// ── same-site write gate ──────────────────────────────────────────────────────────

TEST_CASE("sync route: a cross-site, foreign-origin or header-less cookie write is 403 and sends nothing",
          "[hardware][sync_fanout][route][security]") {
    const std::vector<std::unordered_map<std::string, std::string>> bad = {
        {{"Host", "yuzu.test"}, {"Origin", "https://evil.example"}}, // foreign Origin
        {{"Host", "yuzu.test"}, {"Referer", "https://evil.example/x"}}, // foreign Referer
        {{"Host", "yuzu.test"}},                                       // neither header
    };
    for (const auto& headers : bad) {
        SyncHarness h;
        h.live(3);
        h.sink.default_headers = headers;
        auto res = h.post(R"({"scope":"__all__"})");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.resolve_calls == 0);
        CHECK(h.dispatch_calls == 0);
        CHECK(h.audited("requested") == false);
        REQUIRE_FALSE(h.audit_rows.empty());
        CHECK(h.audit_rows.back().starts_with("csrf.denied|denied|"));
    }
}

TEST_CASE("sync route: the same-site gate runs after the permission gate and exempts token callers",
          "[hardware][sync_fanout][route][security]") {
    {
        // An unauthorised cross-site caller keeps the plain 403 and leaves no csrf row.
        SyncHarness h;
        h.allow_execute = false;
        h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://evil.example"}};
        auto res = h.post(R"({"scope":"__all__"})");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.audit_rows.empty());
    }
    for (const char* source : {"api_token", "mcp_token"}) {
        SyncHarness h;
        h.live(2);
        h.auth_source = source;
        h.sink.default_headers = {{"Host", "yuzu.test"}}; // automation sends no Origin
        auto res = h.post(R"({"scope":"__all__"})");
        REQUIRE(res);
        CHECK(res->status == 202);
        CHECK(h.dispatch_calls == 1);
    }
}

// ── bounds ────────────────────────────────────────────────────────────────────────

TEST_CASE("sync route: 501 reachable devices is 413; 500 is allowed",
          "[hardware][sync_fanout][route][security]") {
    {
        SyncHarness h;
        h.live(501);
        auto res = h.post(R"({"scope":"__all__"})");
        REQUIRE(res);
        CHECK(res->status == 413);
        // The partition stops at the first target past the cap, so the exact total is not known.
        CHECK(contains(res->body, "500"));
        CHECK(h.dispatch_calls == 0);
        CHECK(h.audited("denied"));
        CHECK(contains(h.audit_details.back(), "over_cap"));
        // A refusal for size cost a fleet-sized walk, so it spends the operator's cooldown.
        h.live(2);
        CHECK(h.post(R"({"scope":"__all__"})")->status == 429);
    }
    {
        SyncHarness h;
        h.live(500);
        auto res = h.post(R"({"scope":"__all__"})");
        REQUIRE(res);
        CHECK(res->status == 202);
        CHECK(parse(res->body)["data"]["agents_reached"] == 500);
        CHECK(h.dispatched.size() == 500);
    }
}

TEST_CASE("sync route: the cap counts devices that will be sent to; not devices merely named",
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
    CHECK(d["agents_reached"] == 400);
    CHECK(d["skipped_offline"] == 300);
}

TEST_CASE("sync route: the cooldown is exactly 60 s per operator; on the injected clock",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(2);
    const std::int64_t t0 = h.clock;
    auto first = h.post(R"({"scope":"__all__"})");
    REQUIRE(first);
    REQUIRE(first->status == 202);
    CHECK(parse(first->body)["data"]["requested_at"] == t0); // stamped from the injected clock

    // Inside the window: 429 with the exact seconds left, in the header and in the body.
    const auto attempt = [&](std::int64_t dt) {
        h.clock = t0 + dt;
        return h.post(R"({"scope":"group:g"})");
    };
    struct Window {
        std::int64_t dt;
        int left;
    };
    for (const Window w : {Window{0, 60}, Window{1, 59}, Window{30, 30}, Window{59, 1}}) {
        INFO("t+" << w.dt);
        auto r = attempt(w.dt);
        REQUIRE(r);
        CHECK(r->status == 429);
        CHECK(r->get_header_value("Retry-After") == std::to_string(w.left));
        CHECK(parse(r->body)["error"]["retry_after_ms"] == w.left * 1000);
    }
    CHECK(h.dispatch_calls == 1); // none of those sent anything
    CHECK(h.resolve_calls == 1);  // and each was refused before resolving
    CHECK(h.audited("denied"));
    CHECK(contains(h.audit_details.back(), "rate_limited cooldown=1s"));

    // At exactly t+60 the window is over, and the new run restarts it.
    auto again = attempt(60);
    REQUIRE(again);
    CHECK(again->status == 202);
    CHECK(h.dispatch_calls == 2);
    auto restarted = attempt(61);
    REQUIRE(restarted);
    CHECK(restarted->status == 429);
    CHECK(restarted->get_header_value("Retry-After") == "59");

    // A clock that stepped back (stamp at t+60, now t+30) is not a lock-out: the stamp from the
    // future is stale, the run goes through, and its own stamp replaces it.
    const int runs_before = h.dispatch_calls;
    auto back = attempt(30);
    REQUIRE(back);
    CHECK(back->status == 202);
    CHECK(h.dispatch_calls == runs_before + 1);
    auto after_back = attempt(31); // the window now counts from t+30
    REQUIRE(after_back);
    CHECK(after_back->status == 429);
    CHECK(after_back->get_header_value("Retry-After") == "59");

    // Neither another operator nor a single named device is held by this operator's window.
    h.clock = t0 + 31;
    h.username = "bob";
    CHECK(h.post(R"({"scope":"group:g"})")->status == 202);
    h.username = "alice";
    h.resolved.ids = {"host-01"};
    CHECK(h.post(R"({"scope":"host-01"})")->status == 202);
    CHECK(h.post(R"({"scope":"host-01"})")->status == 202);
}

TEST_CASE("sync route: a run already in flight makes a second one 409 and sends nothing",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(2);
    int inner_status = 0;
    int inner_dispatches_before = -1;
    bool inside = false; // never re-enter from the inner request, whatever it does
    h.during_dispatch = [&] {
        if (inside)
            return;
        inside = true;
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
    // The refusal is on the audit record, as the last row after the first run's own.
    CHECK(h.audited("denied"));
    CHECK(contains(h.audit_details.back(), "run_in_flight"));
    // The flag is released afterwards: bob can run now.
    h.during_dispatch = nullptr;
    h.username = "bob";
    CHECK(h.post(R"({"scope":"__all__"})")->status == 202);
}

TEST_CASE("sync route: the same operator overlapping a run gets 409 from the slot; not a second run",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(2);
    int inner_status = 0;
    bool inside = false;
    h.during_dispatch = [&] {
        if (inside)
            return;
        inside = true;
        auto r = h.post(R"({"scope":"group:g"})"); // alice again, her first run not yet stamped
        inner_status = r ? r->status : -1;
    };
    REQUIRE(h.post(R"({"scope":"__all__"})")->status == 202);
    CHECK(inner_status == 409);
    CHECK(h.dispatch_calls == 1);
    CHECK(h.audited("denied"));
    CHECK(contains(h.audit_details.back(), "run_in_flight"));
    // Once the first run has stamped, the cooldown (not the slot) is what refuses her.
    h.during_dispatch = nullptr;
    CHECK(h.post(R"({"scope":"group:g"})")->status == 429);
}

TEST_CASE("sync route: the cooldown 429 outranks the in-flight 409",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(2);
    REQUIRE(h.post(R"({"scope":"__all__"})")->status == 202); // alice stamps at t0
    h.clock += 1;
    // bob starts a run; from inside it alice asks for one. Both limits apply to her (bob holds the
    // slot, and she is inside her own window); the cooldown is checked first, so she is told 429.
    int inner_status = 0;
    bool inside = false;
    h.during_dispatch = [&] {
        if (inside)
            return;
        inside = true;
        h.username = "alice";
        auto r = h.post(R"({"scope":"group:g"})");
        inner_status = r ? r->status : -1;
        h.username = "bob";
    };
    h.username = "bob";
    REQUIRE(h.post(R"({"scope":"__all__"})")->status == 202);
    CHECK(inner_status == 429);
    CHECK(contains(h.audit_details.back(), "rate_limited"));
    CHECK_FALSE(contains(h.audit_details.back(), "run_in_flight"));
    CHECK(h.dispatch_calls == 2); // alice's t0 run and bob's; the refused one sent nothing
}

TEST_CASE("sync route: an early cooldown 429 does not hold the slot while its audit row is written",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(2);
    REQUIRE(h.post(R"({"scope":"__all__"})")->status == 202); // alice stamps
    // From inside alice's refused attempt's audit write, another operator asks for a run. The
    // slot is free (a 429 never took it), so bob is not answered 409.
    int inner_status = 0;
    bool fired = false;
    h.on_audit = [&] {
        if (fired)
            return;
        fired = true;
        h.username = "bob";
        auto r = h.post(R"({"scope":"group:g"})");
        inner_status = r ? r->status : -1;
        h.username = "alice";
    };
    CHECK(h.post(R"({"scope":"group:g"})")->status == 429);
    CHECK(fired);
    CHECK(inner_status == 202);
}

TEST_CASE("sync route: a run that stamped between the cooldown check and the slot is still refused",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(2);
    const std::int64_t t0 = h.clock;
    // alice's request R2 reads her (empty) cooldown, then reads the clock. On that first clock read
    // a COMPETING run by the same operator completes (taking and releasing the slot, stamping at
    // T). R2 then takes the now-free slot with a stale view; only the re-read after the slot stops
    // it. Everything R2 does next is observed.
    bool competing_done = false;
    bool audit_armed = false;
    bool audit_fired = false;
    int competing_status = 0;
    int bob_status = 0;
    h.on_clock = [&] {
        if (competing_done)
            return;
        competing_done = true;
        h.clock = t0 + 5; // the competing run stamps at t0 + 5
        auto r = h.post(R"({"scope":"group:g"})");
        competing_status = r ? r->status : -1;
        h.clock = t0 + 12; // time passes before R2's own re-read
        audit_armed = true;
    };
    // From inside R2's refusal audit write a different operator asks for a run: the slot must be
    // free (R2 released it before writing), so bob is not answered 409.
    h.on_audit = [&] {
        if (!audit_armed || audit_fired)
            return;
        audit_fired = true;
        h.username = "bob";
        auto r = h.post(R"({"scope":"group:g"})");
        bob_status = r ? r->status : -1;
        h.username = "alice";
    };
    auto r2 = h.post(R"({"scope":"group:g"})");
    REQUIRE(r2);
    CHECK(competing_status == 202);
    CHECK(r2->status == 429);
    CHECK(r2->get_header_value("Retry-After") == "53"); // 60 s from the competing stamp at t0+5, read at t0+12
    // R2's refusal row is on the audit record (bob's run wrote its own rows after it).
    CHECK(std::any_of(h.audit_details.begin(), h.audit_details.end(), [](const std::string& d) {
        return contains(d, "rate_limited cooldown=53s");
    }));
    CHECK(h.dispatch_calls == 2); // the competing run and bob's; R2 itself sent nothing
    CHECK(audit_fired);
    CHECK(bob_status == 202); // the slot was free while R2's refusal was audited
    // R2's refusal did not overwrite the competing run's stamp: still counted from t0 + 5.
    h.on_clock = nullptr;
    h.on_audit = nullptr;
    h.clock = t0 + 35;
    auto later = h.post(R"({"scope":"group:g"})");
    REQUIRE(later);
    CHECK(later->status == 429);
    CHECK(later->get_header_value("Retry-After") == "30");
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
    CHECK(d["agents_reached"] == 3);
    CHECK(d["skipped_offline"] == 2);
}

TEST_CASE("sync route: a missing dependency is an AUDITED 500 and nothing runs",
          "[hardware][sync_fanout][route][security]") {
    struct Case {
        const char* name;
        SyncWiring wiring;
    };
    SyncWiring no_perm, no_auth, no_resolver, no_dispatch, no_precheck, no_version;
    no_perm.perm = false;
    no_auth.auth = false;
    no_resolver.resolver = false;
    no_dispatch.dispatch = false;
    no_precheck.precheck = false;
    no_version.version = false;
    for (const Case& c : {Case{"sync_perm_fn", no_perm}, Case{"auth_fn", no_auth},
                          Case{"sync_resolve_fn", no_resolver}, Case{"sync_dispatch_many_fn", no_dispatch},
                          Case{"sync_caller_unfiltered_fn", no_precheck},
                          Case{"agent_version_fn", no_version}}) {
        INFO(c.name);
        SyncHarness h(c.wiring);
        h.live(1);
        auto res = h.post(R"({"scope":"__all__"})");
        REQUIRE(res);
        CHECK(res->status == 500); // a misconfiguration, not a retryable outage
        CHECK(contains(res->body, "not configured"));
        CHECK(h.resolve_calls == 0);
        CHECK(h.dispatch_calls == 0);
        // The refusal is on the audit record (the sink is independent of the missing dependency).
        REQUIRE(h.audit_rows.size() == 1);
        CHECK(h.audit_rows[0] == "inventory.sync.request|failure|Scope|");
        CHECK(h.audit_details[0] == "sync fan-out unwired");
    }
}

TEST_CASE("sync route: with no audit sink the unwired refusal is still a 500; and audit-off still serves",
          "[hardware][sync_fanout][route]") {
    {
        SyncWiring w;
        w.audit = false;
        w.resolver = false; // something else is missing too
        SyncHarness h(w);
        auto res = h.post(R"({"scope":"__all__"})");
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(h.audit_rows.empty());
    }
    {
        // Audit-off is a legal deployment (try_persist_audit treats it as persisted): it serves.
        SyncWiring w;
        w.audit = false;
        SyncHarness h(w);
        h.live(2);
        auto res = h.post(R"({"scope":"group:g"})");
        REQUIRE(res);
        CHECK(res->status == 202);
        CHECK(h.dispatch_calls == 1);
    }
}

TEST_CASE("sync route: with no injected clock the system clock is used", "[hardware][sync_fanout][route]") {
    SyncWiring w;
    w.clock = false;
    SyncHarness h(w);
    h.live(1);
    auto res = h.post(R"({"scope":"group:g"})");
    REQUIRE(res);
    CHECK(res->status == 202);
    // A real epoch second, not the fake clock's constant.
    CHECK(parse(res->body)["data"]["requested_at"].get<std::int64_t>() > h.clock);
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
