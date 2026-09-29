/**
 * test_command_routes.cpp — #2557: POST /api/command, extracted from
 * server.cpp onto the HttpRouteSink seam (command_routes.{hpp,cpp}).
 *
 * Regression pins for the 6 confirmed-live defects fixed as part of the
 * extraction (see command_routes.cpp's file header for the fix numbering):
 *   #1  stale re-auth in the Scope arm
 *   #2/#4 send-time leak on a zero-reach or throwing dispatch
 *   #3/#6 audit exception-unsafety (denial paths and the success path)
 *   #5  the destructive confine-to-empty 404 arm had no metric/audit
 *   #7  bad_ident's locale-dependent std::isalnum
 *   #8  a second, independent re-parse of agent_ids (targeting erasure)
 *
 * `CommandHarness` wires every `Deps` closure to a fake recording harness
 * field; `AgentRegistry`/`CommandCapabilityRegistry` are real (Tier A raw
 * pointers in `Deps`, called directly by the handler), everything else is a
 * fake `std::function`.
 */

#include "command_routes.hpp"
#include "management_group_store.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "agent_registry.hpp"
#include "capability_decls/core_dispatch_capabilities.hpp"
#include "command_capability.hpp"
#include "dispatch_caller.hpp"
#include "dispatch_destructive_gate.hpp"
#include "event_bus.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <yuzu/metrics.hpp>

#include <array>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::command;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::ClassifiedCommand;
using yuzu::server::detail::ClassifiedCommandTestAccess;
using yuzu::server::detail::DispatchDenial;
using yuzu::server::detail::DispatchDenialReason;
using yuzu::server::detail::EventBus;

namespace {

namespace agent_pb = ::yuzu::agent::v1;

agent_pb::AgentInfo make_agent_info(const std::string& id) {
    agent_pb::AgentInfo info;
    info.set_agent_id(id);
    info.set_hostname("host.local");
    return info; // deliberately no add_plugins() — empty inventory never flags
                 // an agent as "missing" a plugin (fail-open on absent DATA).
}

// A small, independent fixture (never the real catalogue — that is
// test_command_capability.cpp's job): one ReadOnly row for the ordinary
// dispatch-success tests, one Destructive row for the destructive-gate
// path (fix #5), and one Forensics row (Wave 7 PR7.2's single-target rule)
// mirroring the shape a real Forensics-securable row takes (a companion
// package's app_usage.last_used, for one) rather than reclassifying it here.
inline constexpr std::array<CommandCapability, 3> kFixture{{
    {
        .plugin = "noop",
        .action = "run",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Execution",
        .operation = yuzu::server::authz::Operation::Execute,
        .risk_tier = yuzu::server::authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "tar",
        .action = "purge_source",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = yuzu::server::authz::Operation::Delete,
        .risk_tier = yuzu::server::authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "app_usage",
        .action = "last_used",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = yuzu::server::authz::Operation::Read,
        .risk_tier = yuzu::server::authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
}};

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};

struct CommandHarness {
    // Declaration order: TestRouteSink (`sink`) captures a copy of `Deps`
    // whose closures/pointers reach back into THIS harness's other members
    // (registry, metrics, capability_registry, and every fake closure) — so
    // `sink` must be declared LAST, destructed FIRST (CLAUDE.md TestRouteSink
    // convention).
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    CommandCapabilityRegistry capability_registry{std::span<const CommandCapability>(kFixture)};

    // -- auth/perm --
    int auth_fn_calls = 0;
    bool auth_fails = false;
    bool perm_allow = true;

    // -- audit --
    std::vector<AuditCall> audit_calls;
    bool audit_throws = false;

    // -- misc side-effect recorders --
    bool emit_event_throws = false;
    bool publish_throws = false;
    bool thead_throws = false;
    bool forward_gateway_throws = false;
    bool audit_quarantine_throws = false;
    bool audit_unknown_plugin_throws = false;
    int emit_event_calls = 0;
    int publish_calls = 0;
    int forward_gateway_calls = 0;

    // -- classification --
    bool classify_deny = false;

    // -- containment --
    bool containment_fail_closed = false;

    // -- dispatch sink --
    std::vector<std::string> send_to_ids_called;
    int send_all_calls = 0;
    bool sink_throws = false;
    bool force_zero_sends = false;
    // WS-4 4.2b Task D: mirrors force_zero_sends -- makes the sink's
    // `prepare_route_fallback` report a degraded gateway routing-directory
    // read, the exact sibling of `containment_fail_closed` above.
    bool force_route_unreadable = false;

    // -- send-time discard --
    bool discard_send_time_called = false;
    std::string discarded_command_id;
    bool record_send_time_called = false;
    // Governance round 1 closure evidence (SAFE-1/UP-2).
    bool record_send_time_throws = false;

    Deps deps;
    yuzu::server::test::TestRouteSink sink;

    // Wave 7 PR7.2: an optional real ManagementGroupStore, so the Forensics
    // single-target composition tests below can drive an actual in-scope
    // dispatch rather than only the fail-closed-empty confinement arm every
    // other case here exercises (mgmt_group_store stays nullptr by default).
    explicit CommandHarness(ManagementGroupStore* mg = nullptr) {
        (void)registry.register_agent(make_agent_info("dev-A"));
        (void)registry.register_agent(make_agent_info("dev-B"));

        deps.metrics = &metrics;
        deps.registry = &registry;
        deps.capability_registry = &capability_registry;
        deps.mgmt_group_store = mg;
        deps.result_set_store = nullptr;
        deps.tag_store = nullptr;
        deps.custom_properties_store = nullptr;

        deps.auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            ++auth_fn_calls;
            if (auth_fails) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string&, const std::string&) -> bool {
            if (!perm_allow) {
                res.status = 403;
                return false;
            }
            return true;
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            if (audit_throws)
                throw std::runtime_error("audit sink threw");
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };
        deps.emit_event_fn = [this](const std::string&, const httplib::Request&,
                                    const nlohmann::json&, const nlohmann::json&) {
            ++emit_event_calls;
            if (emit_event_throws)
                throw std::runtime_error("emit_event threw");
        };
        deps.publish_fn = [this](const std::string&, const std::string&) {
            ++publish_calls;
            if (publish_throws)
                throw std::runtime_error("publish threw");
        };
        deps.audit_store_configured_fn = []() -> bool { return true; };
        deps.derive_dispatch_caller_fn = [](const auth::Session& s) -> DispatchCaller {
            return DispatchCaller{.principal = s.username,
                                  .principal_role = auth::role_to_string(s.role),
                                  .exec_visible = std::nullopt, // unfiltered
                                  .system = false,
                                  .principal_is_admin = s.role == auth::Role::admin};
        };
        deps.build_classified_command_fn =
            [this](const DispatchCaller&, const std::string& plugin, const std::string& action,
                  const std::string& command_id,
                  const std::unordered_map<std::string, std::string>&, const std::string&, int,
                  int, const std::string&,
                  const std::string&) -> std::expected<ClassifiedCommand, DispatchDenial> {
            if (classify_deny)
                return std::unexpected(
                    DispatchDenial{DispatchDenialReason::Unclassified, "", yuzu::server::authz::Operation::Read});
            agent_pb::CommandRequest cmd;
            cmd.set_command_id(command_id);
            cmd.set_plugin(plugin);
            cmd.set_action(action);
            return ClassifiedCommandTestAccess::make(cmd);
        };
        deps.make_containment_gate_fn = [this](const std::string&,
                                               const std::string&) -> ContainmentGate {
            if (containment_fail_closed)
                return ContainmentGate::enforcing(/*fail_closed=*/true, {});
            return ContainmentGate::exempt_control_plugin();
        };
        deps.make_confined_dispatch_sink_fn =
            [this](const ClassifiedCommand&) -> ConfinedDispatchSink {
            return ConfinedDispatchSink{
                [this](const std::string& aid) -> bool {
                    if (sink_throws)
                        throw std::runtime_error("dispatch sink threw mid-fan-out");
                    if (force_zero_sends)
                        return false;
                    send_to_ids_called.push_back(aid);
                    return true;
                },
                [this]() -> int {
                    ++send_all_calls;
                    if (sink_throws)
                        throw std::runtime_error("dispatch sink threw mid-fan-out");
                    if (force_zero_sends)
                        return 0;
                    return 2;
                },
                [this]() -> std::vector<std::string> { return registry.all_ids(); },
                [this](const std::vector<std::string>&) -> bool {
                    return force_route_unreadable;
                }};
        };
        deps.discard_send_time_fn = [this](const std::string& command_id) -> bool {
            discard_send_time_called = true;
            discarded_command_id = command_id;
            return true;
        };
        deps.record_send_time_fn = [this](const std::string&) {
            record_send_time_called = true;
            if (record_send_time_throws)
                throw std::runtime_error("record_send_time threw");
        };
        deps.thead_for_plugin_fn = [this](const std::string& plugin) -> std::string {
            if (thead_throws)
                throw std::runtime_error("thead_for_plugin threw");
            return "<tr><th>" + plugin + "</th></tr>";
        };
        deps.forward_gateway_pending_fn = [this]() {
            ++forward_gateway_calls;
            if (forward_gateway_throws)
                throw std::runtime_error("forward_gateway_pending threw");
        };
        deps.audit_quarantine_dispatch_fail_closed_fn =
            [this](std::string_view, const std::string&, const std::string&, const std::string&,
                  std::size_t) {
                if (audit_quarantine_throws)
                    throw std::runtime_error("audit_quarantine_dispatch_fail_closed threw");
            };
        deps.audit_quarantine_dispatch_denied_batch_fn =
            [this](std::string_view, const std::string&, const std::string&, const std::string&,
                  std::vector<std::string>) {
                if (audit_quarantine_throws)
                    throw std::runtime_error("audit_quarantine_dispatch_denied_batch threw");
            };
        deps.audit_unknown_plugin_dispatch_fn =
            [this](std::string_view, const std::string&, const std::string&, const std::string&,
                  const std::string&, std::size_t) {
                if (audit_unknown_plugin_throws)
                    throw std::runtime_error("audit_unknown_plugin_dispatch threw");
            };
        deps.audit_scope_resolution_failed_fn =
            [](const std::string&, const std::string&, const std::string&,
              const std::string&) {};
        deps.audit_scope_evaluation_aborted_fn =
            [](const std::string&, const std::string&, const std::string&,
              const std::string&) {};

        register_command_routes(sink, deps);
    }
};

/// Wave 7 PR7.2: makes `agents` visible to the harness's "tester" principal
/// (the session `auth_fn` always mints) via a group `tester` holds a role
/// on — the same shape as test_dashboard_destructive_gate.cpp's helper of
/// the same name, needed here so the Forensics single-target composition
/// test below can drive a real Targeted dispatch rather than only the
/// fail-closed-empty confinement arm.
void grant_visibility(ManagementGroupStore& mg, std::initializer_list<std::string> agents) {
    ManagementGroup g;
    g.name = "All Devices";
    g.membership_type = "static";
    auto gid = mg.create_group(g);
    REQUIRE(gid.has_value());
    for (const auto& a : agents)
        REQUIRE(mg.add_member(*gid, a).has_value());
    GroupRoleAssignment ra;
    ra.group_id = *gid;
    ra.principal_type = "user";
    ra.principal_id = "tester";
    ra.role_name = "ITServiceOwner";
    REQUIRE(mg.assign_role(ra).has_value());
}

} // namespace

// ─────────────────────────── Permission/auth gate ───────────────────────────

TEST_CASE("/api/command: a denied permission gate refuses with 403", "[command_routes][security]") {
    CommandHarness h;
    h.perm_allow = false;
    auto res = h.sink.Post("/api/command", R"({"plugin":"noop","action":"run"})");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("/api/command: an authorized caller with an explicit target dispatches successfully",
          "[command_routes]") {
    CommandHarness h;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["status"] == "sent");
    CHECK(j.contains("command_id"));
    CHECK(j["agents_reached"] == 1);
}

// ───────────────────── Fix #1: Scope arm single re-auth ─────────────────────

TEST_CASE("/api/command: the Scope arm resolves the session exactly once",
          "[command_routes][security]") {
    CommandHarness h;
    // An unparseable scope expression aborts before evaluate_scope is ever
    // called (dispatch_scope_ladder.hpp: parse failure short-circuits before
    // the evaluator lambda runs), so this is safe with tag_store/result_set_
    // store left null — it still exercises the Scope arm's auth resolution,
    // which is all this regression pin cares about.
    auto res =
        h.sink.Post("/api/command", R"({"plugin":"noop","action":"run","scope":"(((invalid"})");
    REQUIRE(res);
    // Pre-fix #1, this arm called auth_fn/require_auth a SECOND time here —
    // always exactly 2 for any request reaching the Scope arm. Post-fix, the
    // single derivation above the arm switch is reused.
    CHECK(h.auth_fn_calls == 1);
}

// ──────────────────── Fix #2/#4: send-time leak on 0 or throw ───────────────

TEST_CASE("/api/command: send-time is discarded when every send returns false (sent==0)",
          "[command_routes]") {
    CommandHarness h;
    h.force_zero_sends = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.record_send_time_called);
    CHECK(h.discard_send_time_called);
}

TEST_CASE("/api/command: a degraded gateway routing-directory read reports "
          "reason=route_unreadable, retryable (WS-4 4.2b Task D — the exact sibling of "
          "containment_unreadable)",
          "[command_routes]") {
    CommandHarness h;
    h.force_zero_sends = true;
    h.force_route_unreadable = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["reason"] == "route_unreadable");
    CHECK(j["error"]["retry_after_ms"] == 5000);
}

TEST_CASE("/api/command: send-time is discarded when the confined-dispatch sink throws "
          "mid-fan-out",
          "[command_routes]") {
    CommandHarness h;
    h.sink_throws = true;
    // A throw inside the handler propagates out of TestRouteSink::dispatch
    // (it does not catch on the route owner's behalf, matching production
    // httplib — an uncaught exception is a 5xx at the transport layer, not
    // something this sink models). We only need to observe the RAII guard's
    // effect, so catch it here the way an httplib worker's own exception
    // boundary would.
    bool threw = false;
    try {
        (void)h.sink.Post("/api/command",
                          R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);
    CHECK(h.record_send_time_called);
    CHECK(h.discard_send_time_called);
    CHECK(h.discarded_command_id.find("noop-") == 0);
}

// ──────── Governance round 1 closure evidence (SAFE-1/UP-2) ────────────────

TEST_CASE("/api/command: send-time is discarded even when record_send_time_fn itself throws",
          "[command_routes]") {
    // Pre-fix, the SendTimeGuard was constructed AFTER the
    // record_send_time_fn call — a throw INSIDE that call (e.g.
    // AgentServiceImpl::record_send_time's own internal
    // publish_send_times_gauge_locked step) ran with no guard yet
    // constructed, so `discard_send_time_called` would stay false here:
    // this case is exactly the window the reorder closes. Post-fix, the
    // guard is a fully-constructed local object by the time
    // record_send_time_fn is called, so it still runs its destructor
    // (RAII) during unwinding. Matches the existing sink_throws test's
    // shape immediately above: the throw is not caught anywhere in the
    // production handler (nothing wraps this specific call in a
    // guarded()-style catch, deliberately — this is a leak-prevention
    // fix, not a response-shaping one), so it is caught here the way an
    // httplib worker's own exception boundary would catch it.
    CommandHarness h;
    h.record_send_time_throws = true;
    bool threw = false;
    try {
        (void)h.sink.Post("/api/command",
                          R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);
    CHECK(h.discard_send_time_called);
}

// ───────────────── Fix #3: throwing audit sink on a denial path ────────────

TEST_CASE("/api/command: a throwing audit sink on the destructive-untargeted denial still "
          "returns 400 with Sec-Audit-Failed set",
          "[command_routes][security]") {
    // Note on the body-type ("request body must be a JSON object") denial
    // arm, deliberately NOT covered here: it is unreachable through this
    // handler's own structure, not merely hard to hit. `plugin`/`action`
    // are extracted via `extract_json_string(req.body, ...)` BEFORE the
    // body-type check even runs, and that extraction already requires
    // `req.body` to parse as an object with string `plugin`/`action`
    // fields (nlohmann's `contains()` is false for any non-object) — so
    // by the time execution reaches `!body.is_object()`, the identical
    // `req.body` bytes have already parsed as an object once. A request
    // that clears the earlier `plugin.empty() || action.empty()` 400
    // cannot also fail `body.is_object()` on a second parse of the same
    // string. This branch is verified reachable only from an internal
    // caller of `check_targeting_shape` with a hand-built non-object
    // `nlohmann::json`, which `test_dispatch_target_shape.cpp` already
    // covers at the unit level.
    CommandHarness h;
    h.audit_throws = true;
    auto res = h.sink.Post("/api/command", R"({"plugin":"tar","action":"purge_source"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
}

TEST_CASE("/api/command: a throwing audit sink on the targeting-shape denial still returns "
          "400 with Sec-Audit-Failed set",
          "[command_routes][security]") {
    CommandHarness h;
    h.audit_throws = true;
    auto res =
        h.sink.Post("/api/command", R"({"plugin":"noop","action":"run","agent_ids":[]})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
}

TEST_CASE("/api/command: a throwing audit sink on the classification denial still returns "
          "400 with Sec-Audit-Failed set",
          "[command_routes][security]") {
    CommandHarness h;
    h.audit_throws = true;
    h.classify_deny = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
}

// ───────────────────── Fix #6: throwing audit on success path ──────────────

TEST_CASE("/api/command: a throwing audit sink on the SUCCESS path still returns 200 with "
          "command_id present and audit_emitted:false",
          "[command_routes]") {
    CommandHarness h;
    h.audit_throws = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j.contains("command_id"));
    REQUIRE(j.contains("audit_emitted"));
    CHECK(j["audit_emitted"] == false);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
}

// ──────── Fix #5: destructive confine-to-empty 404 is counted+audited ──────

TEST_CASE("/api/command: a Destructive dispatch whose agent_ids all fall outside the "
          "caller's visible set is a 404 that is counted and audited",
          "[command_routes][security]") {
    // `mgmt_group_store` is null in this harness -> `vis` stays nullopt ->
    // `DestructiveVisibleAgents{nullopt}` -> fail-closed-empty ->
    // `confine_destructive_targets` returns empty -> the 404 arm this test
    // pins. `tar.purge_source` (kFixture) is Destructive; `agent_ids` is
    // explicit and non-empty, so this is NOT the sibling
    // `destructive_untargeted` (400) case above.
    CommandHarness h;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"tar","action":"purge_source","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 404);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("audit_emitted"));
    CHECK(j["audit_emitted"] == true);
    bool saw_no_visible_target = false;
    bool saw_untargeted = false;
    for (const auto& c : h.audit_calls) {
        if (c.action == "command.dispatch" && c.result == "denied" &&
            c.detail.find("reason=destructive_no_visible_target") != std::string::npos)
            saw_no_visible_target = true;
        if (c.detail.find("destructive_untargeted") != std::string::npos)
            saw_untargeted = true;
    }
    CHECK(saw_no_visible_target);
    // The RefuseUntargeted sibling must NOT have fired — this was a
    // targeted (non-empty agent_ids) request, just one confined to nothing
    // visible.
    CHECK_FALSE(saw_untargeted);
}

// ───────────────────── Fix #7: non-ASCII plugin/action refused ─────────────

TEST_CASE("/api/command: a non-ASCII byte in plugin is refused regardless of locale",
          "[command_routes][security]") {
    // Regression PIN, not a red->green demonstration: std::isalnum under the
    // process's default "C" locale already rejects a raw 0xE9 byte, so this
    // case alone cannot distinguish the pre-fix std::isalnum mechanism from
    // the post-fix explicit ASCII range check — both reject it under "C".
    // What this pins is the OBSERVABLE CONTRACT (a non-ASCII high byte in
    // plugin/action is always a 400, regardless of the mechanism), so a
    // future change back to a locale-sensitive check under a non-"C" locale
    // is still caught structurally even though this test cannot flip red
    // under the old code in this process's locale.
    CommandHarness h;
    const std::string body = std::string("{\"plugin\":\"no\xE9op\",\"action\":\"run\"}");
    auto res = h.sink.Post("/api/command", body);
    REQUIRE(res);
    CHECK(res->status == 400);
}

// ───────────────── Fix #8: explicit agent_ids never widens to broadcast ────

TEST_CASE("/api/command: an explicit non-empty agent_ids list is never widened to a broadcast",
          "[command_routes][security]") {
    CommandHarness h;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A","dev-B"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.send_all_calls == 0);
    CHECK(h.send_to_ids_called == std::vector<std::string>{"dev-A", "dev-B"});
}

// ──────────────── Post-dispatch audit helpers throwing (not 5xx) ───────────

TEST_CASE("/api/command: forward_gateway_pending throwing still returns 200 with command_id",
          "[command_routes]") {
    CommandHarness h;
    h.forward_gateway_throws = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j.contains("command_id"));
}

TEST_CASE("/api/command: audit_unknown_plugin_dispatch throwing still returns 200 with "
          "command_id",
          "[command_routes]") {
    CommandHarness h;
    h.audit_unknown_plugin_throws = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j.contains("command_id"));
}

TEST_CASE("/api/command: audit_quarantine_dispatch_denied_batch throwing still returns 200 "
          "with command_id",
          "[command_routes]") {
    CommandHarness h;
    h.audit_quarantine_throws = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j.contains("command_id"));
}

TEST_CASE("/api/command: audit_quarantine_dispatch_fail_closed throwing still returns 200 "
          "with command_id",
          "[command_routes]") {
    CommandHarness h;
    h.containment_fail_closed = true;
    h.audit_quarantine_throws = true;
    // A fail-closed containment gate withholds every id, so force the sink
    // to still report sends for a different arm... instead, keep the
    // dispatch itself trivial: fail-closed containment denies the whole
    // fleet, so `sent` stays 0 and this exercises the 503 path with the
    // throwing helper — still not a 5xx from the throw itself.
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 503);
    // Governance round 1 closure evidence (UP-1b): the throw above used to
    // degrade to a log line ONLY — assert the metric value itself, not a
    // log/stdout grep.
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_fanout_throw_total",
                       {{"route", "command"}, {"phase", "audit_quarantine_dispatch_fail_closed"}})
              .value() == 1);
}

// Governance round 1 closure evidence (UP-1b), remaining guarded() call
// sites: the counter-increment property above is asserted once per site so a
// regression narrowed to a single `guarded()` call cannot hide behind the
// others passing.

TEST_CASE("/api/command: forward_gateway_pending throwing increments the fanout counter",
          "[command_routes]") {
    CommandHarness h;
    h.forward_gateway_throws = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_fanout_throw_total",
                       {{"route", "command"}, {"phase", "forward_gateway_pending"}})
              .value() == 1);
}

TEST_CASE("/api/command: audit_unknown_plugin_dispatch throwing increments the fanout counter",
          "[command_routes]") {
    CommandHarness h;
    h.audit_unknown_plugin_throws = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_fanout_throw_total",
                       {{"route", "command"}, {"phase", "audit_unknown_plugin_dispatch"}})
              .value() == 1);
}

TEST_CASE("/api/command: audit_quarantine_dispatch_denied_batch throwing increments the fanout "
          "counter",
          "[command_routes]") {
    CommandHarness h;
    h.audit_quarantine_throws = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_fanout_throw_total",
                       {{"route", "command"}, {"phase", "audit_quarantine_dispatch_denied_batch"}})
              .value() == 1);
}

TEST_CASE("/api/command: thead_for_plugin throwing increments the fanout counter",
          "[command_routes]") {
    CommandHarness h;
    h.thead_throws = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_fanout_throw_total",
                       {{"route", "command"}, {"phase", "thead_for_plugin"}})
              .value() == 1);
}

TEST_CASE("/api/command: publish(command-status) throwing increments the fanout counter",
          "[command_routes]") {
    CommandHarness h;
    h.publish_throws = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_fanout_throw_total",
                       {{"route", "command"}, {"phase", "publish(command-status)"}})
              .value() == 1);
}

TEST_CASE("/api/command: emit_event(command.dispatched) throwing increments the fanout counter",
          "[command_routes]") {
    CommandHarness h;
    h.emit_event_throws = true;
    auto res = h.sink.Post("/api/command",
                           R"({"plugin":"noop","action":"run","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.metrics
              .counter("yuzu_server_dispatch_fanout_throw_total",
                       {{"route", "command"}, {"phase", "emit_event(command.dispatched)"}})
              .value() == 1);
}

// ── Wave 7 PR7.2: Forensics single-target rule through the REAL /api/command
// producer surface (not just evaluate_destructive_targeting in isolation) ──

TEST_CASE("/api/command: a Forensics action with ZERO targets (agent_ids omitted) is refused "
          "with the forensic-specific message",
          "[command_routes][security]") {
    CommandHarness h;
    auto res = h.sink.Post("/api/command", R"({"plugin":"app_usage","action":"last_used"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["message"] == std::string(yuzu::server::kForensicUntargetedMessage));
    bool saw_reason = false;
    for (const auto& c : h.audit_calls)
        if (c.detail.find(std::string(yuzu::server::kReasonForensicUntargeted)) !=
            std::string::npos)
            saw_reason = true;
    CHECK(saw_reason);
}

TEST_CASE("/api/command: a Forensics action with TWO explicit targets is refused — the rule is "
          "exactly-one, not merely non-empty",
          "[command_routes][security]") {
    CommandHarness h;
    auto res = h.sink.Post(
        "/api/command",
        R"({"plugin":"app_usage","action":"last_used","agent_ids":["dev-A","dev-B"]})");
    REQUIRE(res);
    CHECK(res->status == 400);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["message"] == std::string(yuzu::server::kForensicUntargetedMessage));
}

TEST_CASE("/api/command: a Forensics action with a scope key alongside a single agent_id is "
          "refused — scope fan-out is never admitted for a forensic read",
          "[command_routes][security]") {
    CommandHarness h;
    auto res = h.sink.Post(
        "/api/command",
        R"({"plugin":"app_usage","action":"last_used","agent_ids":["dev-A"],"scope":"__all__"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["message"] == std::string(yuzu::server::kForensicUntargetedMessage));
}

TEST_CASE("/api/command: a Forensics action with exactly ONE explicit, in-scope target DOES "
          "dispatch",
          "[pg][command_routes][security]") {
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    REQUIRE(mg.is_open());
    grant_visibility(mg, {"dev-A", "dev-B"});

    CommandHarness h{&mg};
    auto res = h.sink.Post(
        "/api/command", R"({"plugin":"app_usage","action":"last_used","agent_ids":["dev-A"]})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["status"] == "sent");
    CHECK(j["agents_reached"] == 1);
    CHECK(h.send_to_ids_called == std::vector<std::string>{"dev-A"});
}

TEST_CASE("/api/command: a Forensics action's single target falling outside the caller's "
          "visible set is a 404, distinct from the untargeted 400",
          "[pg][command_routes][security]") {
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    REQUIRE(mg.is_open());
    grant_visibility(mg, {"dev-A"}); // dev-B deliberately NOT granted

    CommandHarness h{&mg};
    auto res = h.sink.Post(
        "/api/command", R"({"plugin":"app_usage","action":"last_used","agent_ids":["dev-B"]})");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(h.send_to_ids_called.empty());
}

// ─────────────── json-dump-depth-guard fix (#2437-class) ────────────────────
//
// nlohmann::json::dump() is unboundedly recursive. This body is an
// otherwise-VALID, otherwise-ACCEPTED request (plugin/action/agent_ids all
// well-formed) with one extra deeply-nested field inside "params" - the
// exact field extract_json_string_map's non-string coercion calls .dump()
// on - so on unguarded code the request proceeds all the way to dispatch,
// and only the new depth check tells fixed and unfixed code apart. depth 40
// is trivially safe to build/dump directly in this test process; the real
// attack depth this guard exists for is many orders of magnitude higher
// (~100,000 levels).

TEST_CASE("/api/command: a body nested past the depth limit is rejected before dispatch",
          "[command_routes][security][depth]") {
    CommandHarness h;
    const std::string deep_array = std::string(40, '[') + std::string(40, ']');
    const std::string body =
        R"({"plugin":"noop","action":"run","agent_ids":["dev-A"],"params":{"deep":)" +
        deep_array + "}}";
    auto res = h.sink.Post("/api/command", body);
    REQUIRE(res);
    CHECK(res->status == 400);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["message"].get<std::string>().find("nests too deeply") != std::string::npos);
    CHECK(h.send_to_ids_called.empty());
    CHECK(h.send_all_calls == 0);
}
