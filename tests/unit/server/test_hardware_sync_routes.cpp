/// @file test_hardware_sync_routes.cpp
/// Route matrix for `POST /api/v1/hardware/sync` and `GET /api/v1/hardware/sync/{execution_id}` —
/// the Software page's "Sync now" for a device / scope expression or group / whole fleet, and how a
/// run is going. Driven in-process through TestRouteSink; the harness copies
/// test_hardware_routes.cpp's HwHarness shape (every provider a lambda over `this`) but is its own
/// file so the sync matrix and the Hardware record tests do not share one fixture. The pure rules
/// (grammar, partition, run key, join, cooldown, pacing, wording) have their own fixture vectors in
/// test_software_sync_decision.cpp / _pacing.cpp / _runner.cpp; what is pinned HERE is the
/// sequencing and the HTTP mapping: gate -> parse -> confirm -> guard -> resolve -> admit -> audit ->
/// dispatch, that nothing is sent on any refusal, and who may read a run's status.

#include "execution_scope_rules.hpp" // execution_owner_key (what each surface passes as `owned`)
#include "hardware_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
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
         audit = true, clock = true, status = true;
};

struct SyncHarness {
    HardwareRoutes routes;
    yuzu::server::test::TestRouteSink sink; // declared after `routes`: its handlers capture it

    bool allow_execute = true;
    std::string username = "alice";
    std::string auth_source;       // "api_token" etc.: what the same-site gate sees
    bool audit_should_fail = false;
    std::int64_t clock = 1'700'000'000; // the route's injected "now" (seconds)
    bool admin = true;                  // the fleet-administrator seam

    // The resolver's answer. `ids` is what the caller can SEE (already confined). Its
    // `caller_unfiltered` follows `confined_users` per request.
    ss::Resolved resolved;
    std::unordered_set<std::string> confined_users;
    std::unordered_map<std::string, std::optional<std::string>> version_by_id;
    std::optional<std::string> default_version{std::string("0.13.1")};
    // Dispatch: how many sessions accept the frame (nullopt = all of them).
    std::optional<std::size_t> accept;
    // last_synced_before: the store read.
    std::unordered_map<std::string, std::int64_t> last_seen_by_id;
    bool last_seen_ok = true;

    // The tracker: rows the run creates, and what the status route reads.
    std::vector<Execution> executions;
    bool tracker_degraded = false;
    bool status_unfiltered = false;
    int unfiltered_calls = 0;

    // Observations, in call order, so a test can pin audit-BEFORE-dispatch.
    std::vector<std::string> events;
    std::vector<std::string> audit_rows;    // "action|result|target_type|target_id"
    std::vector<std::string> audit_details;
    std::vector<std::string> dispatched;
    std::int64_t last_delay = -1;
    std::string last_execution_id;
    int dispatch_calls = 0;
    int resolve_calls = 0;
    int precheck_calls = 0;
    // The cheap "is this caller unfiltered" pre-check. Unset: it agrees with `confined_users`.
    std::optional<bool> precheck_override;
    ss::Selector last_selector;
    std::string last_username;
    // Runs inside the dispatch call, to re-enter the route while a run is in flight.
    std::function<void()> during_dispatch;
    // Runs inside every audit write, to prove what the route holds while it writes.
    std::function<void()> on_audit;

    explicit SyncHarness(SyncWiring w = {}) {
        resolved.status = ss::Resolved::Status::Ok;

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
        // The run exists only when every closure it needs is wired: a missing one leaves the
        // route's runner empty, which is the audited 500 the unwired tests pin.
        if (w.resolver && w.dispatch && w.precheck && w.version) {
            ss::Env env;
            env.resolve = [this](const auth::Session& s, const ss::Selector& sel) {
                ++resolve_calls;
                last_selector = sel;
                last_username = s.username;
                auto r = resolved;
                r.caller_unfiltered = !confined_users.contains(s.username);
                return r;
            };
            env.dispatch = [this](const auth::Session&, const std::vector<std::string>& ids,
                                  std::int64_t delay_max_s, const std::string& execution_id) {
                ++dispatch_calls;
                events.push_back("dispatch");
                dispatched.insert(dispatched.end(), ids.begin(), ids.end());
                last_delay = delay_max_s;
                last_execution_id = execution_id;
                if (during_dispatch)
                    during_dispatch();
                return ss::DispatchResult{accept.value_or(ids.size()), "__sync__-fleet-test"};
            };
            env.caller_unfiltered = [this](const auth::Session& s) {
                ++precheck_calls;
                return precheck_override.value_or(!confined_users.contains(s.username));
            };
            env.fleet_admin = [this](const auth::Session&) { return admin; };
            env.agent_version = deps.agent_version_fn;
            env.last_seen = [this](const std::vector<std::string>& ids)
                -> std::optional<std::unordered_map<std::string, std::int64_t>> {
                if (!last_seen_ok)
                    return std::nullopt;
                std::unordered_map<std::string, std::int64_t> out;
                for (const auto& id : ids)
                    if (const auto it = last_seen_by_id.find(id); it != last_seen_by_id.end())
                        out[id] = it->second;
                return out;
            };
            env.track.create = [this](const auth::Session& s, const ss::Selector& sel, std::int64_t delay) {
                events.push_back("track.create");
                Execution e;
                e.id = "exec-" + std::to_string(executions.size() + 1);
                e.definition_id = std::string(ss::kSyncDefinitionId);
                e.status = "running";
                e.scope_expression = sel.expr;
                e.dispatched_by = s.username;
                e.dispatched_at = clock;
                nlohmann::json p = {{"source", "installed_software"}};
                if (delay > 0)
                    p["delay_max_s"] = delay;
                e.parameter_values = p.dump();
                executions.push_back(e);
                return e.id;
            };
            env.track.set_targeted = [this](const std::string& id, std::size_t n) {
                for (auto& e : executions)
                    if (e.id == id)
                        e.agents_targeted = static_cast<int>(n);
                return true;
            };
            env.track.cancel = [this](const std::string& id, const auth::Session&) {
                for (auto& e : executions)
                    if (e.id == id)
                        e.status = "cancelled";
            };
            if (w.clock)
                env.now = [this] { return clock; };
            deps.sync_runner = std::make_shared<ss::Runner>(std::move(env));
        }
        if (w.status) {
            deps.sync_status_fn = [this](const std::string& id)
                -> std::expected<std::optional<Execution>, std::string> {
                if (tracker_degraded)
                    return std::unexpected(std::string("pool exhausted"));
                for (const auto& e : executions)
                    if (e.id == id)
                        return std::optional<Execution>(e);
                return std::optional<Execution>{};
            };
            deps.sync_unfiltered_fn = [this](const auth::Session&) {
                ++unfiltered_calls;
                return status_unfiltered;
            };
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
    std::unique_ptr<httplib::Response> status_of(const std::string& execution_id) {
        return sink.Get("/api/v1/hardware/sync/" + execution_id);
    }

    bool audited(const std::string& result) const {
        return std::any_of(audit_rows.begin(), audit_rows.end(), [&](const std::string& r) {
            return r.find("|" + result + "|") != std::string::npos;
        });
    }
};

nlohmann::json parse(const std::string& s) { return nlohmann::json::parse(s, nullptr, false); }

// A run of a group the way the page sends it, and the fleet the way an administrator does.
std::string group_body(const std::string& g, bool confirm = true) {
    return "{\"scope\":\"group:" + g + "\"" + (confirm ? ",\"confirm\":true" : "") + "}";
}
const std::string kFleetBody = "{\"scope\":\"__all__\",\"confirm\":true}";

// Bodies with escaped quotes are spelled as ordinary literals held in constants, not as raw
// strings inside REQUIRE(...): MSVC's preprocessor mis-lexes a raw string with embedded quotes
// inside a macro argument ("invalid literal suffix", C2014-class errors) and the Windows leg
// fails to compile.
const std::string kBodyWindows = "{\"scope_expression\":\"ostype == \\\"windows\\\"\"}";
const std::string kBodyLinux = "{\"scope_expression\":\"ostype == \\\"linux\\\"\"}";

} // namespace

// ── happy path ────────────────────────────────────────────────────────────────────

TEST_CASE("sync route: a group run is 202 with counts only; audited before anything is sent",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(4);
    h.version_by_id["d1"] = std::nullopt;                    // offline
    h.version_by_id["d2"] = std::string("0.12.9");            // below the floor
    auto res = h.post("{\"scope\":\"group:g\",\"confirm\":true,\"source\":\"installed_software\"}");
    REQUIRE(res);
    REQUIRE(res->status == 202);
    const auto body = parse(res->body);
    REQUIRE_FALSE(body.is_discarded());
    const auto& d = body["data"];
    CHECK(d["requested"] == 4);
    CHECK(d["agents_reached"] == 2);
    CHECK(d["skipped_offline"] == 1);
    CHECK(d["skipped_version"] == 1);
    CHECK(d["skipped_fresh"] == 0);
    CHECK(d["command_id"] == "__sync__-fleet-test");
    CHECK(d["source"] == "installed_software");
    CHECK(d["requested_at"] == h.clock);
    CHECK(d["execution_id"] == "exec-1");
    CHECK(d["delay_max_s"] == 0);
    CHECK(d["estimated_completion_at"] == h.clock);
    CHECK(d["joined"] == false);
    CHECK(body["meta"]["api_version"] == "v1");
    // Counts only: no device id appears anywhere in the body.
    for (const auto& id : h.resolved.ids)
        CHECK_FALSE(contains(res->body, id));
    // Only the live, new-enough devices were sent, in one dispatch call, against the run's record.
    CHECK(h.dispatch_calls == 1);
    CHECK(h.dispatched == std::vector<std::string>{"d0", "d3"});
    CHECK(h.last_execution_id == "exec-1");
    // Audit BEFORE the record and the send, once, carrying scope, arm, every count and the spread.
    REQUIRE(h.events == std::vector<std::string>{"audit:requested", "track.create", "dispatch"});
    REQUIRE(h.audit_rows.size() == 1);
    CHECK(h.audit_rows[0] == "inventory.sync.request|requested|Scope|group:g");
    CHECK(h.audit_details[0] ==
          "scope=group:g arm=group requested=4 reached=2 skipped_offline=1 skipped_version=1 "
          "skipped_fresh=0 delay_max_s=0");
}

TEST_CASE("sync route: a large run is paced; the 202 carries the spread and an estimated completion",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(100); // 100 devices at 25 per second
    auto res = h.post(group_body("g"));
    REQUIRE(res);
    REQUIRE(res->status == 202);
    const auto d = parse(res->body)["data"];
    CHECK(d["delay_max_s"] == 4);
    CHECK(d["estimated_completion_at"] == h.clock + 4);
    CHECK(h.last_delay == 4); // the same number rode out on the command
    CHECK(contains(h.audit_details[0], "delay_max_s=4"));
}

TEST_CASE("sync route: the fleet is audited under its own verb; every other arm under the sync verb",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(4);
    auto fleet = h.post(kFleetBody);
    REQUIRE(fleet);
    REQUIRE(fleet->status == 202);
    REQUIRE(h.audit_rows.size() == 1);
    CHECK(h.audit_rows[0] == "software_estate.sync.fleet_wide|requested|Scope|__all__");
    CHECK(h.audit_details[0] ==
          "scope=__all__ arm=broadcast requested=4 reached=4 skipped_offline=0 skipped_version=0 "
          "skipped_fresh=0 delay_max_s=0");
    CHECK_FALSE(h.audited("inventory.sync.request"));

    h.clock += 1;
    REQUIRE(h.post(group_body("g"))->status == 202);
    REQUIRE(h.post(kBodyLinux)->status == 202);
    h.resolved.ids = {"host-01"};
    REQUIRE(h.post("{\"scope\":\"host-01\"}")->status == 202);
    CHECK(h.audit_rows[1] == "inventory.sync.request|requested|Scope|group:g");
    CHECK(h.audit_rows[2] == "inventory.sync.request|requested|Scope|expression");
    CHECK(h.audit_rows[3] == "inventory.sync.request|requested|Agent|host-01");
    // A fleet run whose row cannot be stored fails closed like any other.
    h.live(2);
    h.audit_should_fail = true;
    h.clock += 1000;
    const auto before = h.dispatch_calls;
    auto refused = h.post(kFleetBody);
    REQUIRE(refused);
    CHECK(refused->status == 503);
    CHECK(refused->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.dispatch_calls == before);
}

TEST_CASE("sync route: a device with no session on this server is skipped_offline; whatever its reason",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(4);
    // d1 is disconnected; d2 is attached to another replica. This route sees the same thing for
    // both (no session on this process), counts both in skipped_offline and never sends to them.
    h.version_by_id["d1"] = std::nullopt;
    h.version_by_id["d2"] = std::nullopt;
    auto res = h.post(group_body("g"));
    REQUIRE(res);
    REQUIRE(res->status == 202);
    const auto d = parse(res->body)["data"];
    CHECK(d["requested"] == 4);
    CHECK(d["agents_reached"] == 2);
    CHECK(d["skipped_offline"] == 2);
    CHECK_FALSE(d.contains("skipped_other_replica"));
    CHECK(h.dispatched == std::vector<std::string>{"d0", "d3"});
}

TEST_CASE("sync route: the resolver sees the parsed selector and the caller's session",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.username = "bob";
    h.live(1);
    REQUIRE(h.post(group_body("finance"))->status == 202);
    CHECK(h.last_selector.arm == DispatchArm::Group);
    CHECK(h.last_selector.expr == "group:finance");
    CHECK(h.last_selector.confirm);
    CHECK(h.last_username == "bob");
    REQUIRE(h.post(kBodyWindows)->status == 202); // a different key: bob's expression
    CHECK(h.last_selector.arm == DispatchArm::Scope);
    CHECK(h.last_selector.expr == R"(ostype == "windows")");
    CHECK(h.audit_rows.back() == "inventory.sync.request|requested|Scope|expression");
}

TEST_CASE("sync route: a single named device is allowed, needs no confirmation and no cooldown",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.resolved.ids = {"host-01"};
    for (int i = 0; i < 3; ++i) {
        auto res = h.post("{\"scope\":\"host-01\"}");
        REQUIRE(res);
        CHECK(res->status == 202);
    }
    CHECK(h.dispatch_calls == 3);
    CHECK(h.last_delay == 0);
    CHECK(h.audit_rows.back() == "inventory.sync.request|requested|Agent|host-01");
}

TEST_CASE("sync route: nothing live to reach is 202 with reached 0; audited no_agents; nothing sent",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(3);
    h.default_version = std::nullopt; // everyone offline
    auto res = h.post(group_body("g"));
    REQUIRE(res);
    REQUIRE(res->status == 202);
    const auto d = parse(res->body)["data"];
    CHECK(d["requested"] == 3);
    CHECK(d["agents_reached"] == 0);
    CHECK(d["skipped_offline"] == 3);
    CHECK(d["execution_id"].is_null());
    CHECK(h.dispatch_calls == 0);
    CHECK(h.executions.empty()); // no record for a run that sent nothing
    CHECK(h.audited("no_agents"));
    // The resolve and the lookups were paid for, so the group's cooldown is spent.
    CHECK(h.post(group_body("g"))->status == 429);
}

// ── who may ask, and what must be confirmed ────────────────────────────────────────

TEST_CASE("sync route: a caller without Execution:Execute is refused before anything runs",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.allow_execute = false;
    h.live(2);
    auto res = h.post(kFleetBody);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.resolve_calls == 0);
    CHECK(h.dispatch_calls == 0);
}

TEST_CASE("sync route: a whole group or the whole fleet without confirm is 400; a device or expression is not",
          "[hardware][sync_fanout][route]") {
    for (const char* body : {"{\"scope\":\"group:g\"}", "{\"scope\":\"__all__\"}",
                             "{\"scope\":\"group:g\",\"confirm\":false}",
                             "{\"scope_expression\":\"group:g\"}", "{\"scope_expression\":\"__all__\"}"}) {
        INFO(body);
        SyncHarness h;
        h.live(3);
        auto res = h.post(body);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(contains(res->body, "confirm"));
        CHECK(h.resolve_calls == 0);
        CHECK(h.dispatch_calls == 0);
        CHECK(h.audited("denied"));
        CHECK(contains(h.audit_details.back(), "confirmation_required"));
    }
    SyncHarness h;
    h.live(3);
    CHECK(h.post("{\"scope\":\"host-01\"}")->status == 202);
    CHECK(h.post(kBodyLinux)->status == 202);
}

TEST_CASE("sync route: the fleet needs a fleet administrator; that refusal outranks the confirmation",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(3);
    h.admin = false; // unfiltered Execution:Execute but no global ManagementGroup:Write
    // Without confirm AND without the grant, the caller is told 403, not asked to confirm.
    auto res = h.post("{\"scope\":\"__all__\"}");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(contains(res->body, "ManagementGroup:Write"));
    CHECK(h.resolve_calls == 0); // refused before the fleet is read
    CHECK(h.dispatch_calls == 0);
    CHECK(h.audited("denied"));
    CHECK(contains(h.audit_details.back(), "fleet_wide_required"));
    CHECK(h.post(kFleetBody)->status == 403);
    // The same caller may still sync a group or an expression within their own set.
    CHECK(h.post(group_body("mine"))->status == 202);
    CHECK(h.dispatch_calls == 1);
}

TEST_CASE("sync route: a confined caller's __all__ is refused before the run guard and the fleet read",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(3);
    h.confined_users.insert("alice"); // a management-group-confined operator
    auto res = h.post(kFleetBody);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.precheck_calls == 1);
    CHECK(h.resolve_calls == 0); // the resolver is what reads the fleet
    CHECK(h.dispatch_calls == 0);
    CHECK(h.audit_rows.back() == "inventory.sync.request|denied|Scope|__all__");
    CHECK(contains(h.audit_details.back(), "fleet_wide_required"));
    // The refusal took no key and no cooldown: a legitimate run goes straight through.
    CHECK(h.post(group_body("g"))->status == 202);
    CHECK(h.dispatch_calls == 1);
}

TEST_CASE("sync route: if the pre-check and the resolver disagree the run is 503; nothing is sent",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(3);
    h.confined_users.insert("alice"); // the resolver says confined...
    h.precheck_override = true;       // ...but the cheap check said unfiltered when the key was built
    auto res = h.post(group_body("g"));
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.resolve_calls == 1);
    CHECK(h.dispatch_calls == 0);
    CHECK(contains(h.audit_details.back(), "caller_class_changed"));
}

TEST_CASE("sync route: malformed requests are 400; audited denied; and never reach the resolver",
          "[hardware][sync_fanout][route]") {
    const char* bad[] = {
        "",                                                   // no body
        "{not json",
        "[]",
        R"({})",                                              // names no target
        R"({"confirm":true})",                                // an empty scope is never the fleet
        R"({"scope":"__all__","scope_expression":"__all__"})",
        R"({"scope":42})",
        R"({"scope":"__all__","source":"all"})",
        R"({"scope":"group:"})",
        R"({"scope":"group:g","confirm":"true"})",            // confirm is a boolean, never coerced
        R"({"scope":"group:g","confirm":1})",
        R"({"scope":"group:g","confirm":true,"last_synced_before":-1})",
        R"({"scope":"group:g","confirm":true,"last_synced_before":"1700000000"})",
        R"({"scope":"group:g","confirm":true,"last_synced_before":1.5})",
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
        // Refused before the body is parsed: not even the missing-confirmation 400 is reached.
        for (const auto& body : {kFleetBody, std::string("{\"scope\":\"__all__\"}"), std::string("not json")}) {
            auto res = h.post(body);
            REQUIRE(res);
            CHECK(res->status == 403);
        }
        CHECK(h.resolve_calls == 0);
        CHECK(h.dispatch_calls == 0);
        CHECK(h.audited("requested") == false);
        REQUIRE_FALSE(h.audit_rows.empty());
        CHECK(h.audit_rows.back() == "csrf.denied|denied|Endpoint|hardware.sync");
    }
}

TEST_CASE("sync route: the same-site gate runs after the permission gate and exempts token callers",
          "[hardware][sync_fanout][route][security]") {
    {
        // An unauthorised cross-site caller keeps the plain 403 and leaves no csrf row.
        SyncHarness h;
        h.allow_execute = false;
        h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://evil.example"}};
        auto res = h.post(kFleetBody);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.audit_rows.empty());
    }
    for (const char* source : {"api_token", "mcp_token"}) {
        SyncHarness h;
        h.live(2);
        h.auth_source = source;
        h.sink.default_headers = {{"Host", "yuzu.test"}}; // automation sends no Origin
        auto res = h.post(kFleetBody);
        REQUIRE(res);
        CHECK(res->status == 202);
        CHECK(h.dispatch_calls == 1);
    }
}

// ── pacing, join, cooldown ────────────────────────────────────────────────────────

TEST_CASE("sync route: there is no device ceiling; ten thousand devices are one paced run",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(10'000);
    auto res = h.post(kFleetBody);
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto d = parse(res->body)["data"];
    CHECK(d["agents_reached"] == 10'000);
    CHECK(d["delay_max_s"] == 400); // 10,000 at 25 per second
    CHECK(h.dispatched.size() == 10'000);
}

TEST_CASE("sync route: the free pacing budget is shared; a run that cannot start is 429 with Retry-After",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(1000);
    // Five runs leave under the minimum run rate free.
    for (int i = 0; i < 5; ++i)
        REQUIRE(h.post(group_body("g" + std::to_string(i)))->status == 202);
    const int sent = h.dispatch_calls;
    auto res = h.post(group_body("g5"));
    REQUIRE(res);
    CHECK(res->status == 429);
    CHECK(res->get_header_value("Retry-After") == "40"); // the first run's spread ends in 40 s
    CHECK(parse(res->body)["error"]["retry_after_ms"] == 40'000);
    CHECK(h.dispatch_calls == sent);
    CHECK(h.audited("denied"));
    CHECK(contains(h.audit_details.back(), "budget_busy"));
    // When that run has ended its rate is back.
    h.clock += 40;
    CHECK(h.post(group_body("g5"))->status == 202);
}

TEST_CASE("sync route: a run that cannot be spread inside 86,400 s is 413 and sends nothing",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(1000);
    for (int i = 0; i < 4; ++i)
        REQUIRE(h.post(group_body("h" + std::to_string(i)))->status == 202);
    const int sent = h.dispatch_calls;
    h.live(135'001); // the free share is 1.5625 per second
    auto res = h.post(group_body("huge"));
    REQUIRE(res);
    CHECK(res->status == 413);
    CHECK(contains(res->body, "86400"));
    CHECK(res->get_header_value("Retry-After").empty());
    CHECK(h.dispatch_calls == sent);
    CHECK(contains(h.audit_details.back(), "unspreadable"));
}

TEST_CASE("sync route: a repeat of a running request joins it: 202, joined true, nothing sent",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(100);
    auto first = h.post(group_body("g"));
    REQUIRE(first);
    REQUIRE(first->status == 202);
    h.clock += 1;
    h.username = "bob"; // another operator who sees the same devices
    auto again = h.post(group_body("g"));
    REQUIRE(again);
    CHECK(again->status == 202);
    const auto d = parse(again->body)["data"];
    CHECK(d["joined"] == true);
    CHECK(d["execution_id"] == parse(first->body)["data"]["execution_id"]);
    CHECK(d["command_id"] == parse(first->body)["data"]["command_id"]);
    CHECK(d["agents_reached"] == 100);
    CHECK(h.dispatch_calls == 1);
    CHECK(h.executions.size() == 1);
    CHECK(h.audit_rows.back() == "inventory.sync.request|joined|Scope|group:g");
}

TEST_CASE("sync route: a confined caller posting a group an unfiltered caller is running gets a run of their own",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(100);
    auto admin_run = h.post(group_body("g"));
    REQUIRE(admin_run);
    REQUIRE(admin_run->status == 202);
    // carol may see only 60 of the group's devices.
    h.username = "carol";
    h.confined_users.insert("carol");
    h.live(60);
    h.clock += 1;
    auto own = h.post(group_body("g"));
    REQUIRE(own);
    REQUIRE(own->status == 202);
    const auto d = parse(own->body)["data"];
    CHECK(d["joined"] == false);              // never joined with the other caller's run
    CHECK(d["agents_reached"] == 60);         // and never handed its counts
    CHECK(d["execution_id"] != parse(admin_run->body)["data"]["execution_id"]);
    CHECK(h.dispatch_calls == 2);
    // Her own repeat joins her own run.
    h.clock += 1;
    auto repeat = h.post(group_body("g"));
    REQUIRE(repeat);
    CHECK(parse(repeat->body)["data"]["joined"] == true);
    CHECK(parse(repeat->body)["data"]["execution_id"] == d["execution_id"]);
    CHECK(parse(repeat->body)["data"]["agents_reached"] == 60);
    CHECK(h.dispatch_calls == 2);
}

TEST_CASE("sync route: the cooldown is per group, 600 s by default, on the injected clock",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(100);
    const std::int64_t t0 = h.clock;
    auto first = h.post(group_body("g"));
    REQUIRE(first);
    REQUIRE(first->status == 202);
    CHECK(parse(first->body)["data"]["requested_at"] == t0); // stamped from the injected clock

    // Once the 4 s spread is over the run is only cooling down: 429 with the exact seconds left,
    // in the header and in the body.
    struct Window {
        std::int64_t dt;
        int left;
    };
    for (const Window w : {Window{10, 590}, Window{300, 300}, Window{599, 1}}) {
        INFO("t+" << w.dt);
        h.clock = t0 + w.dt;
        auto r = h.post(group_body("g"));
        REQUIRE(r);
        CHECK(r->status == 429);
        CHECK(r->get_header_value("Retry-After") == std::to_string(w.left));
        CHECK(parse(r->body)["error"]["retry_after_ms"] == w.left * 1000);
    }
    CHECK(h.dispatch_calls == 1); // none of those sent anything
    CHECK(h.resolve_calls == 1);  // and each was refused before resolving
    CHECK(contains(h.audit_details.back(), "rate_limited cooldown=1s"));
    // Another group is not held by this group's window.
    h.clock = t0 + 10;
    CHECK(h.post(group_body("other"))->status == 202);
    // At exactly t+600 the window is over.
    h.clock = t0 + 600;
    CHECK(h.post(group_body("g"))->status == 202);
}

TEST_CASE("sync route: a same-key request while the first is still being started is 409 with a 1 s hint",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(2);
    int inner_status = 0;
    int inner_retry_ms = 0;
    bool fired = false;
    h.on_audit = [&] {
        if (fired)
            return;
        fired = true;
        h.username = "bob";
        auto r = h.post(group_body("g"));
        inner_status = r ? r->status : -1;
        if (r)
            inner_retry_ms = parse(r->body)["error"]["retry_after_ms"].get<int>();
        h.username = "alice";
    };
    REQUIRE(h.post(group_body("g"))->status == 202);
    CHECK(inner_status == 409);
    CHECK(inner_retry_ms == 1000);
    CHECK(h.dispatch_calls == 1);
    CHECK(contains(h.audit_details.back(), "run_in_flight"));
}

TEST_CASE("sync route: a fourth concurrent send is 409; a single-device sync is not counted",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(2);
    int depth = 0;
    int refused_status = 0;
    int device_status = 0;
    h.during_dispatch = [&] {
        if (depth >= 3)
            return;
        ++depth;
        if (depth == 3) {
            const auto saved = h.resolved.ids;
            auto r = h.post(group_body("n3")); // the fourth send loop
            refused_status = r ? r->status : -1;
            h.resolved.ids = {"host-01"};
            auto d = h.post("{\"scope\":\"host-01\"}");
            device_status = d ? d->status : -1;
            h.resolved.ids = saved;
        } else {
            (void)h.post(group_body("n" + std::to_string(depth)));
        }
    };
    REQUIRE(h.post(group_body("n0"))->status == 202);
    CHECK(refused_status == 409);
    CHECK(device_status == 202);
}

// ── last_synced_before ────────────────────────────────────────────────────────────

TEST_CASE("sync route: last_synced_before asks only devices not synced since; the rest are skipped_fresh",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(4);
    h.last_seen_by_id = {{"d0", 5000}, {"d1", 999}, {"d2", 1000}};
    auto res = h.post("{\"scope\":\"group:g\",\"confirm\":true,\"last_synced_before\":1000}");
    REQUIRE(res);
    REQUIRE(res->status == 202);
    const auto d = parse(res->body)["data"];
    CHECK(d["requested"] == 4);
    CHECK(d["skipped_fresh"] == 2);
    CHECK(d["agents_reached"] == 2);
    CHECK(h.dispatched == std::vector<std::string>{"d1", "d3"}); // d3 never reported: it is asked
    CHECK(contains(h.audit_details[0], "skipped_fresh=2"));
}

TEST_CASE("sync route: a degraded last_synced_before read is 503 and sends nothing",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(4);
    h.last_seen_ok = false;
    auto res = h.post("{\"scope\":\"group:g\",\"confirm\":true,\"last_synced_before\":1000}");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.dispatch_calls == 0);
    CHECK(h.executions.empty());
}

// ── audit and dispatch failure ────────────────────────────────────────────────────

TEST_CASE("sync route: an audit-store degrade fails CLOSED with zero dispatches and keeps nothing",
          "[hardware][sync_fanout][route][security]") {
    SyncHarness h;
    h.live(3);
    h.audit_should_fail = true;
    auto res = h.post(group_body("g"));
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.dispatch_calls == 0);
    CHECK(h.executions.empty()); // no record for a run that was never admitted
    // A refused-for-audit run did not spend the cooldown or hold the key either.
    h.audit_should_fail = false;
    CHECK(h.post(group_body("g"))->status == 202);
}

TEST_CASE("sync route: every send refused is 503, closes the record and leaves the cooldown unspent",
          "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(3);
    h.accept = 0;
    auto res = h.post(group_body("g"));
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.audited("requested")); // the pre-dispatch row is the durable evidence of the ask
    REQUIRE(h.executions.size() == 1);
    CHECK(h.executions[0].status == "cancelled");
    h.accept = std::nullopt;
    CHECK(h.post(group_body("g"))->status == 202);
}

TEST_CASE("sync route: a partly refused send reports only what was accepted", "[hardware][sync_fanout][route]") {
    SyncHarness h;
    h.live(5);
    h.accept = 3;
    auto res = h.post(group_body("g"));
    REQUIRE(res);
    CHECK(res->status == 202);
    const auto d = parse(res->body)["data"];
    CHECK(d["requested"] == 5);
    CHECK(d["agents_reached"] == 3);
    CHECK(d["skipped_offline"] == 2);
    REQUIRE(h.executions.size() == 1);
    CHECK(h.executions[0].agents_targeted == 3); // the record carries the frames accepted
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
                          Case{"sync_resolve_fn", no_resolver}, Case{"sync_dispatch_fn", no_dispatch},
                          Case{"sync_caller_unfiltered_fn", no_precheck},
                          Case{"agent_version_fn", no_version}}) {
        INFO(c.name);
        SyncHarness h(c.wiring);
        h.live(1);
        auto res = h.post(kFleetBody);
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
        auto res = h.post(kFleetBody);
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
        auto res = h.post(group_body("g"));
        REQUIRE(res);
        CHECK(res->status == 202);
        CHECK(h.dispatch_calls == 1);
    }
}

// ── GET /api/v1/hardware/sync/{execution_id} ──────────────────────────────────────

TEST_CASE("sync status: the caller who started a run reads it; counts, state and the spread",
          "[hardware][sync_fanout][route][status]") {
    SyncHarness h;
    h.live(100);
    auto run = h.post(group_body("g"));
    REQUIRE(run);
    REQUIRE(run->status == 202);
    const auto id = parse(run->body)["data"]["execution_id"].get<std::string>();
    // The tracker counts the replies as they arrive.
    h.executions.at(0).agents_success = 90;
    h.executions.at(0).agents_failure = 2;
    auto res = h.status_of(id);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    const auto body = parse(res->body);
    const auto& d = body["data"];
    CHECK(d["execution_id"] == id);
    CHECK(d["state"] == "running");
    CHECK(d["targeted"] == 100);
    CHECK(d["acknowledged"] == 90);
    CHECK(d["failed"] == 2);
    CHECK(d["dispatched_at"] == h.clock);
    CHECK(d["delay_max_s"] == 4);
    CHECK(d["estimated_completion_at"] == h.clock + 4);
    CHECK(body["meta"]["api_version"] == "v1");
    CHECK_FALSE(d.contains("scope")); // nothing about who or what was asked beyond the counts
    CHECK_FALSE(contains(res->body, "d0"));
}

TEST_CASE("sync status: another operator, a non-sync execution and an unknown id are the same 404",
          "[hardware][sync_fanout][route][status][security]") {
    SyncHarness h;
    h.live(3);
    REQUIRE(h.post(group_body("g"))->status == 202);
    // A workflow execution alice started: not a sync run, so it is not served here even to her.
    Execution other;
    other.id = "wf-1";
    other.definition_id = "some.definition";
    other.status = "running";
    other.dispatched_by = "alice";
    h.executions.push_back(other);

    h.username = "mallory";
    const auto not_mine = h.status_of("exec-1");
    h.username = "alice";
    const auto not_sync = h.status_of("wf-1");
    const auto unknown = h.status_of("exec-404");
    REQUIRE(not_mine);
    REQUIRE(not_sync);
    REQUIRE(unknown);
    for (const auto* r : {&not_mine, &not_sync, &unknown}) {
        CHECK((*r)->status == 404);
        CHECK(parse((*r)->body)["error"]["message"] == parse(unknown->body)["error"]["message"]);
    }
    CHECK(h.status_of("exec-1")->status == 200); // alice still reads her own
}

TEST_CASE("sync status: a caller whose Execution:Execute is unfiltered reads any sync run",
          "[hardware][sync_fanout][route][status]") {
    SyncHarness h;
    h.live(3);
    REQUIRE(h.post(group_body("g"))->status == 202);
    h.username = "bob";
    CHECK(h.status_of("exec-1")->status == 404);
    h.status_unfiltered = true;
    auto res = h.status_of("exec-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    // ...but an unfiltered caller still gets no non-sync execution.
    Execution other;
    other.id = "wf-1";
    other.definition_id = "some.definition";
    other.dispatched_by = "alice";
    h.executions.push_back(other);
    CHECK(h.status_of("wf-1")->status == 404);
}

TEST_CASE("sync status: a caller without Execution:Execute is refused; an unwired tracker is 503, never an empty 200",
          "[hardware][sync_fanout][route][status][security]") {
    {
        SyncHarness h;
        h.live(3);
        REQUIRE(h.post(group_body("g"))->status == 202);
        h.allow_execute = false;
        auto res = h.status_of("exec-1");
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    {
        SyncWiring w;
        w.status = false;
        SyncHarness h(w);
        auto res = h.status_of("exec-1");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(parse(res->body)["error"]["retry_after_ms"].get<int>() > 0);
        CHECK_FALSE(contains(res->body, "\"data\""));
    }
    {
        // A tracker read that fails is a retryable outage, not a not-found and not an empty body.
        SyncHarness h;
        h.live(3);
        REQUIRE(h.post(group_body("g"))->status == 202);
        h.tracker_degraded = true;
        auto res = h.status_of("exec-1");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(parse(res->body)["error"]["retry_after_ms"].get<int>() > 0);
        CHECK(h.unfiltered_calls == 0); // the 503 is decided by the read; no RBAC work is spent on it
    }
    {
        // An unknown id still evaluates the unfiltered callback once, so it costs the same as
        // another caller's run and the not-found answers stay indistinguishable.
        SyncHarness h;
        auto res = h.status_of("exec-404");
        REQUIRE(res);
        CHECK(h.unfiltered_calls == 1);
    }
    {
        SyncWiring w;
        w.perm = false;
        SyncHarness h(w);
        auto res = h.status_of("exec-1");
        REQUIRE(res);
        CHECK(res->status == 500);
    }
}

TEST_CASE("sync status: a run with no spread reports delay 0 and its dispatch time as the estimate",
          "[hardware][sync_fanout][route][status]") {
    SyncHarness h;
    h.live(3);
    REQUIRE(h.post(group_body("g"))->status == 202);
    // A row whose parameters are not the JSON the run wrote is still served, with no spread.
    h.executions.at(0).parameter_values = "not json";
    auto res = h.status_of("exec-1");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    const auto d = parse(res->body)["data"];
    CHECK(d["delay_max_s"] == 0);
    CHECK(d["estimated_completion_at"] == d["dispatched_at"]);
}

// ── clock and neighbours ──────────────────────────────────────────────────────────

TEST_CASE("sync route: with no injected clock the system clock is used", "[hardware][sync_fanout][route]") {
    SyncWiring w;
    w.clock = false;
    SyncHarness h(w);
    h.live(1);
    auto res = h.post(group_body("g"));
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
    CHECK(h.post(kFleetBody)->status == 202);
    auto device = h.sink.Post("/api/v1/hardware/agent-1/sync", "");
    REQUIRE(device); // registered, and it is the per-device handler (unwired -> 503, not our 202)
    CHECK(device->status == 503);
    // And the status route is not the record route: `sync/<id>` is two segments after hardware.
    auto status = h.status_of("exec-1");
    REQUIRE(status);
    CHECK(status->status == 200);
}

// ── software_sync::sync_status: the one function the REST route and the MCP tool both call ──

namespace {

Execution sync_run(const std::string& id, const std::string& owner, const std::string& params_json) {
    Execution e;
    e.id = id;
    e.definition_id = std::string(ss::kSyncDefinitionId);
    e.status = "running";
    e.dispatched_by = owner;
    e.dispatched_at = 1'700'000'000;
    e.agents_targeted = 5;
    e.agents_success = 3;
    e.agents_failure = 1;
    e.parameter_values = params_json;
    return e;
}

std::expected<std::optional<Execution>, std::string> found(const Execution& e) {
    return std::optional<Execution>(e);
}

// What each surface passes as `owned`: the caller's execution owner key owns the row.
bool owned_by(const std::string& username, const Execution& e, const std::string& service = {}) {
    auth::Session s;
    s.username = username;
    s.token_scope_service = service;
    return execution_owner_key(s).owns(e);
}

} // namespace

TEST_CASE("sync_status: an owned run is served with its counts and the spread",
          "[hardware][sync_fanout][status]") {
    const auto run = sync_run("exec-1", "alice", R"({"delay_max_s":120})");
    const auto r = ss::sync_status(found(run), owned_by("alice", run), false);
    REQUIRE(r);
    CHECK(*r == nlohmann::json{{"execution_id", "exec-1"},
                               {"state", "running"},
                               {"targeted", 5},
                               {"acknowledged", 3},
                               {"failed", 1},
                               {"dispatched_at", 1'700'000'000},
                               {"delay_max_s", 120},
                               {"estimated_completion_at", 1'700'000'120}});
}

TEST_CASE("sync_status: delay_max_s is read only from a positive integer; the estimate is dispatch plus spread",
          "[hardware][sync_fanout][status]") {
    for (const char* params : {"", "not json", "[]", R"({})", R"({"delay_max_s":0})",
                               R"({"delay_max_s":-5})", R"({"delay_max_s":"60"})",
                               R"({"delay_max_s":2.5})"}) {
        INFO(params);
        const auto run = sync_run("exec-1", "alice", params);
        const auto r = ss::sync_status(found(run), owned_by("alice", run), false);
        REQUIRE(r);
        CHECK((*r)["delay_max_s"] == 0);
        CHECK((*r)["estimated_completion_at"] == (*r)["dispatched_at"]);
    }
    const auto run = sync_run("exec-1", "alice", R"({"delay_max_s":7})");
    const auto spread = ss::sync_status(found(run), owned_by("alice", run), false);
    REQUIRE(spread);
    CHECK((*spread)["delay_max_s"] == 7);
    CHECK((*spread)["estimated_completion_at"] == 1'700'000'007);
}

TEST_CASE("sync_status: a read error is Unavailable, never an empty answer",
          "[hardware][sync_fanout][status]") {
    const std::expected<std::optional<Execution>, std::string> degraded =
        std::unexpected(std::string("pool exhausted"));
    const auto r = ss::sync_status(degraded, false, true);
    REQUIRE_FALSE(r);
    CHECK(r.error() == ss::SyncStatusFault::kUnavailable);
}

TEST_CASE("sync_status: no such run, a non-sync execution and another caller's run are the same NotFound",
          "[hardware][sync_fanout][status][security]") {
    const std::expected<std::optional<Execution>, std::string> none = std::optional<Execution>{};
    auto other_def = sync_run("wf-1", "alice", "{}");
    other_def.definition_id = "some.workflow";
    const auto mine = sync_run("exec-1", "alice", "{}");

    const auto unknown = ss::sync_status(none, false, true);
    const auto not_sync = ss::sync_status(found(other_def), owned_by("alice", other_def), true);
    const auto not_mine = ss::sync_status(found(mine), owned_by("bob", mine), false);
    for (const auto& r : {unknown, not_sync, not_mine}) {
        REQUIRE_FALSE(r);
        CHECK(r.error() == ss::SyncStatusFault::kNotFound);
    }
    // An unfiltered Execution:Execute reads any SYNC run, but still not another kind of execution.
    CHECK(ss::sync_status(found(mine), owned_by("bob", mine), true));
    CHECK_FALSE(ss::sync_status(found(other_def), owned_by("bob", other_def), true));
    // A service-scoped session owns nothing (its key is empty), so it reads only through an
    // unfiltered grant.
    CHECK_FALSE(owned_by("alice", mine, "printers"));
    CHECK_FALSE(ss::sync_status(found(mine), owned_by("alice", mine, "printers"), false));
}
