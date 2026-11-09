/**
 * test_command_v1_routes.cpp -- POST /api/v1/commands (#2146), the REST v1 twin of POST
 * /api/command and of MCP execute_instruction.
 *
 * WHY THIS FILE COMPOSES THE PRODUCTION PIECES. An injected dispatch stub proves wiring, not
 * confinement (test_dispatch_confined_arms.cpp documents the false green that shipped once).
 * So the dispatch closure here is the real chokepoint (classify_and_authorize_dispatch ->
 * finalize_classified_command) feeding the real wire_and_dispatch_confined
 * (-> dispatch_confined_arms) over a REAL AgentRegistry, and every send-set test asserts the
 * EXACT recipients through AgentRegistry::drain_gateway_pending (the K-1 technique), with a
 * decoy agent registered so a send to the wrong agent is observable.
 *
 * Stand-ins, named as such:
 *   - `perm_fn` is a fake that applies the REAL service-scope rule
 *     (`authz::service_scope_global_safe`) and an engine default-deny; the real
 *     `AuthRoutes::require_permission` needs an RbacStore (Postgres) and is pinned by
 *     test_auth_routes.cpp.
 *   - `derive_caller_fn` re-spells `ServerImpl::derive_dispatch_caller` (a private member) but
 *     decides `exec_visible` with the REAL `authz::compose_exec_visible`, the function that
 *     owns the service-scoped / engine / global precedence.
 *   - The execution tracker is a PG store: it is replaced by recording `ExecutionOps`, so the
 *     execution-row minting against a real table is NOT covered here.
 *   - The audit writer records rows; it does not persist them.
 */

#include "agent_registry.hpp"
#include "authz_model.hpp"
#include "body_cap_policy.hpp"
#include "capability_fragments.hpp"
#include "command_capability.hpp"
#include "command_v1_routes.hpp"
#include "dispatch_denial_text.hpp"
#include "dispatch_destructive_gate.hpp"
#include "dispatch_scope_ladder.hpp"
#include "mcp_input_bounds.hpp"
#include "service_scope_policy.hpp"
#include "test_partial_send_dispatch.hpp"

#include "../test_helpers.hpp"
#include "test_route_sink.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <expected>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
namespace cv1 = yuzu::server::command_v1;
using nlohmann::json;

namespace {

constexpr const char* kA = "agent-a";
constexpr const char* kB = "agent-b";
constexpr const char* kC = "agent-c";
constexpr const char* kDecoy = "agent-decoy"; // registered, never named by any request

struct AuditRow {
    std::string actor;
    std::string role;
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

struct RigOpts {
    bool session_writer = true;
    bool dispatch = true;
    bool visible_fn = true;
    bool emit = true; // wire Deps::emit_event_fn
};

struct Rig {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry;
    CommandCapabilityRegistry caps{YUZU_ALL_CAPABILITY_FRAGMENTS};

    // ---- the caller of the route ----
    auth::Session session;
    std::set<std::string> perm_denied; // "Securable:Operation" the fake perm_fn refuses
    std::vector<std::string> perm_calls;
    bool engine_has_grant = false;
    bool principal_flips = false; // the second auth_fn call names a different user
    int auth_calls = 0;

    // ---- exec_visible facts (decided by the real compose_exec_visible) ----
    authz::ExecVisibleFacts facts{.legacy_open = true};
    std::optional<std::vector<std::string>> visible_agents; // Destructive confinement read

    // ---- the seam ----
    ContainmentGate gate = ContainmentGate::exempt_control_plugin();
    std::optional<ConfinedDispatchOutcome> canned; // overrides the real seam for one outcome
    bool dispatch_throws = false;
    bool dispatch_throws_nonstd = false;
    /// >0: the dispatch runs the REAL arms and the REAL instrumented sink, and send number N
    /// throws (test_partial_send_dispatch.hpp).
    int throw_on_nth_send = 0;
    bool set_targeted_ok = true;
    bool set_targeted_throws = false; ///< the count write THROWS (the success path's bookkeeping)
    bool create_throws = false;
    bool create_throws_nonstd = false;
    bool create_fails = false; ///< the tracker answers an error: the dispatch runs with execution_id ""
    int dispatch_calls = 0;
    DispatchCaller last_caller;
    std::string last_execution_id;
    std::vector<std::string> dispatched_ids;
    std::string dispatched_scope;

    // ---- observation ----
    std::vector<AuditRow> audits;
    bool requested_row_persists = true;
    bool outcome_row_persists = true;
    int exec_created = 0;
    std::vector<std::string> exec_params;
    std::vector<std::string> cancelled;
    std::vector<std::pair<std::string, int>> targeted;
    bool admit_service_scoped = false; // simulate a (hypothetical) allow-list entry at the gate
    struct Emitted {
        std::string type;
        json attrs, payload;
    };
    std::vector<Emitted> emitted;
    /// Audit rows and emitted events in the order they happened (one vector, so order is real).
    std::vector<std::string> trace;
    bool emit_throws = false;
    /// Runs inside the `requested` audit write: the window in which production lets a grant, an
    /// elevation or a visible set move (#7110).
    std::function<void()> on_requested_row;

    yuzu::server::test::TestRouteSink sink;

    explicit Rig(RigOpts opts = {}) : registry(bus, metrics) {
        session.username = "alice";
        session.role = auth::Role::user;
        for (const auto* id : {kA, kB, kC, kDecoy}) {
            ::yuzu::agent::v1::AgentInfo info;
            info.set_agent_id(id);
            info.set_hostname(std::string(id) + ".local");
            info.mutable_platform()->set_os(std::string(id) == kC ? "windows" : "linux");
            (void)registry.register_agent(info);
            REQUIRE(registry.set_gateway_route(
                id, /*session_id=*/{}, "test-gateway",
                {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));
        }
        cv1::Deps d;
        d.auth_fn = [this](const httplib::Request&,
                           httplib::Response&) -> std::optional<auth::Session> {
            ++auth_calls;
            auto s = session;
            if (principal_flips && auth_calls >= 2)
                s.username = "mallory";
            return s;
        };
        d.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& sec,
                           const std::string& op) -> bool {
            perm_calls.push_back(sec + ":" + op);
            // The REAL service-scope rule: kServiceScopeGlobalSafe is empty, so a service-scoped
            // token clears no pair.
            if (!admit_service_scoped && !session.token_scope_service.empty() &&
                !authz::service_scope_global_safe(sec, op)) {
                res.status = 403;
                return false;
            }
            // Engine principals are default-deny: an explicit grant or nothing.
            if (session.is_engine() && !engine_has_grant) {
                res.status = 403;
                return false;
            }
            if (perm_denied.contains(sec + ":" + op)) {
                res.status = 403;
                return false;
            }
            return true;
        };
        d.audit_fn = [this](const httplib::Request&, const std::string& action,
                            const std::string& result, const std::string&, const std::string& tid,
                            const std::string& detail) {
            trace.push_back("audit:" + result);
            audits.push_back({"<re-resolving>", "", action, result, tid, detail});
            if (result == "requested" && on_requested_row)
                on_requested_row();
            return true;
        };
        if (opts.session_writer)
            d.audit_as_session = [this](const httplib::Request&, const auth::Session& s,
                                        const std::string& role, const std::string& action,
                                        const std::string& result, const std::string&,
                                        const std::string& tid, const std::string& detail) {
                trace.push_back("audit:" + result);
                audits.push_back({s.username, role, action, result, tid, detail});
                if (result == "requested" && on_requested_row)
                    on_requested_row();
                return result == "requested" ? requested_row_persists : outcome_row_persists;
            };
        d.classify_fn = [this](std::string_view p, std::string_view a) {
            return caps.classify(p, a);
        };
        d.authorize_dispatch_fn = [this](const DispatchCaller& caller, std::string_view plugin,
                                         std::string_view action) {
            return detail::classify_and_authorize_dispatch(
                caps, caller, plugin, action,
                [](std::string_view, std::string_view, authz::Operation) { return true; });
        };
        if (opts.dispatch)
            d.dispatch_fn = [this](const std::string& plugin, const std::string& action,
                                   const std::vector<std::string>& ids, const std::string& scope,
                                   const std::unordered_map<std::string, std::string>& params,
                                   const std::string& exec_id, const DispatchCaller& caller) {
                return real_dispatch(plugin, action, ids, scope, params, exec_id, caller);
            };
        d.derive_caller_fn = [this](const auth::Session& s) {
            authz::ExecVisibleFacts f = facts;
            f.service_scoped = !s.token_scope_service.empty();
            f.principal_is_engine = s.is_engine();
            return DispatchCaller{.principal = s.username,
                                  .principal_role = auth::role_to_string(s.role),
                                  .exec_visible = authz::compose_exec_visible(f),
                                  .system = false,
                                  .principal_is_admin = auth::effective_role(s) == auth::Role::admin};
        };
        if (opts.visible_fn)
            d.visible_agents_fn = [this](const std::string&) { return visible_agents; };
        d.execution.create = [this](const std::string&, const std::string&,
                                    const std::string& params_json)
            -> std::expected<std::string, std::string> {
            exec_params.push_back(params_json);
            if (create_throws)
                throw std::runtime_error("create boom");
            if (create_throws_nonstd)
                throw 42; // NOLINT(hicpp-exception-baseclass): a non-std throw is the point
            if (create_fails)
                return std::unexpected(std::string("no execution tracker"));
            return "exec-" + std::to_string(++exec_created);
        };
        d.execution.mark_cancelled = [this](const std::string& id, const std::string&) {
            cancelled.push_back(id);
            return true;
        };
        d.execution.set_targeted = [this](const std::string& id, int n) {
            targeted.emplace_back(id, n);
            if (set_targeted_throws)
                throw std::runtime_error("count write boom");
            return set_targeted_ok;
        };
        d.metrics = &metrics;
        if (opts.emit)
            d.emit_event_fn = [this](const std::string& type, const httplib::Request&,
                                     const json& attrs, const json& payload) {
                trace.push_back("emit:" + type);
                emitted.push_back({type, attrs, payload});
                if (emit_throws)
                    throw std::runtime_error("analytics sink blew up");
            };
        cv1::register_command_v1_routes(sink, std::move(d));
    }

    ConfinedDispatchOutcome real_dispatch(const std::string& plugin, const std::string& action,
                                          const std::vector<std::string>& ids,
                                          const std::string& scope,
                                          const std::unordered_map<std::string, std::string>& params,
                                          const std::string& exec_id, const DispatchCaller& caller) {
        ++dispatch_calls;
        last_caller = caller;
        last_execution_id = exec_id;
        dispatched_ids = ids;
        dispatched_scope = scope;
        if (dispatch_throws)
            throw std::runtime_error("boom");
        if (dispatch_throws_nonstd)
            throw 42; // NOLINT(hicpp-exception-baseclass): a non-std throw is the point
        if (throw_on_nth_send > 0)
            return yuzu::test::dispatch_throwing_on_nth_send(ids, throw_on_nth_send);
        const std::string command_id = plugin + "-cmd-" + std::to_string(dispatch_calls);
        if (canned) {
            auto out = *canned;
            out.command_id = command_id;
            return out;
        }
        auto decision = detail::classify_and_authorize_dispatch(
            caps, caller, plugin, action,
            [](std::string_view, std::string_view, authz::Operation) { return true; });
        if (!decision)
            return ConfinedDispatchOutcome{.command_id = command_id, .denied = decision.error()};
        const auto arm = classify_dispatch_arm(!ids.empty(), scope);
        auto classified = detail::finalize_classified_command(
            *decision, detail::KillSwitchFn{}, plugin, action, command_id, params, /*payload=*/{}, 0,
            0, std::string(dispatch_arm_label(arm)), exec_id);
        if (!classified)
            return ConfinedDispatchOutcome{.command_id = command_id, .denied = classified.error()};
        auto noop = [](const std::string&, const std::string&, const std::string&,
                       const std::string&) {};
        return wire_and_dispatch_confined(registry, nullptr, nullptr, nullptr, nullptr, nullptr, noop,
                                          noop, command_id, exec_id, caller.principal_role, ids, scope,
                                          caller.exec_visible, /*broadcast_on_none=*/false, gate,
                                          *classified);
    }

    std::unique_ptr<httplib::Response> post(const json& body) {
        return sink.Post("/api/v1/commands", body.dump());
    }
    std::unique_ptr<httplib::Response> post_raw(const std::string& body) {
        return sink.Post("/api/v1/commands", body);
    }

    // The exact set of agents the dispatch queued a command for (sorted), draining the queue.
    std::vector<std::string> sent() {
        std::vector<std::string> out;
        for (const auto& p : registry.drain_gateway_pending())
            out.push_back(p.agent_id);
        std::sort(out.begin(), out.end());
        return out;
    }

    bool has_audit(const std::string& result, const std::string& detail_part = {}) const {
        return std::any_of(audits.begin(), audits.end(), [&](const AuditRow& r) {
            return r.action == "command.dispatch" && r.result == result &&
                   r.detail.find(detail_part) != std::string::npos;
        });
    }
};

json body_of(const std::unique_ptr<httplib::Response>& r) {
    REQUIRE(r != nullptr);
    return json::parse(r->body);
}
std::string reason_of(const std::unique_ptr<httplib::Response>& r) {
    const auto j = body_of(r);
    return j.contains("error") ? j["error"].value("reason", "") : std::string{};
}

using Ids = std::vector<std::string>;

// A read-only, non-destructive pair from the production catalogue.
const json kRead = {{"plugin", "os_info"}, {"action", "os_version"}};

} // namespace

// ───────────────────────────── send sets: unconfined and confined ─────────────────────────────

TEST_CASE("command_v1: an omitted target is the fleet; the unconfined caller reaches exactly "
          "every registered agent",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.facts = {.legacy_open = true}; // unfiltered authority (nullopt exec_visible)
    const auto res = rig.post(kRead);
    REQUIRE(res->status == 202);
    CHECK(rig.sent() == Ids{kA, kB, kC, kDecoy});
    const auto data = body_of(res)["data"];
    CHECK(data["agents_reached"] == 4);
    CHECK(data["plugin"] == "os_info");
    CHECK(data["execution_id"] == "exec-1");
    CHECK(rig.dispatched_scope == "__all__"); // the omitted target became the broadcast scope
    CHECK(rig.targeted == std::vector<std::pair<std::string, int>>{{"exec-1", 4}});
}

TEST_CASE("command_v1: a CONFINED caller's send set is the intersection, on every targeting arm",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    // global_grant=false, legacy_open=false: only the scoped set {agent-a, agent-c} is visible.
    rig.facts = {};
    rig.facts.scoped_visible = std::unordered_set<std::string>{kA, kC};

    SECTION("agent_ids arm: names a, b, c -- b is dropped by the seam, the decoy is untouched") {
        const auto res = rig.post({{"plugin", "os_info"},
                                   {"action", "os_version"},
                                   {"agent_ids", Ids{kA, kB, kC}}});
        REQUIRE(res->status == 202);
        CHECK(rig.sent() == Ids{kA, kC});
        CHECK(body_of(res)["data"]["agents_reached"] == 2);
    }
    SECTION("broadcast arm (omitted target): only the visible set is reached") {
        const auto res = rig.post(kRead);
        REQUIRE(res->status == 202);
        CHECK(rig.sent() == Ids{kA, kC});
    }
    SECTION("scope arm: a scope matching a, b and the decoy reaches only the visible subset") {
        const auto res = rig.post({{"plugin", "os_info"},
                                   {"action", "os_version"},
                                   {"scope", "ostype == \"linux\""}});
        REQUIRE(res->status == 202);
        // linux agents are a, b, decoy; visible are a, c -> exactly a.
        CHECK(rig.sent() == Ids{kA});
    }
}

TEST_CASE("command_v1: an empty exec_visible (a store fault or an unwired derivation) reaches "
          "nobody, it never reads as the fleet",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.facts = {}; // not legacy-open, no grant, no scoped set: compose_exec_visible => present-empty
    const auto res = rig.post(kRead);
    CHECK(res->status == 503);
    CHECK(reason_of(res) == "no_agents_reached");
    CHECK(rig.sent().empty());
}

TEST_CASE("command_v1: the caller handed to the seam is the derived one, never a rebuilt one",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.session.username = "carol";
    rig.session.role = auth::Role::admin;
    rig.facts = {.legacy_open = true};
    REQUIRE(rig.post(kRead)->status == 202);
    CHECK(rig.last_caller.principal == "carol");
    CHECK(rig.last_caller.principal_is_admin); // the CALLER's real admin bit
    CHECK(rig.last_caller.approval_provenance == ApprovalProvenance::None); // REST stamps none
    CHECK_FALSE(rig.last_caller.system);
}

// ───────────────────────────── service-scoped and engine principals ─────────────────────────────

TEST_CASE("command_v1: a service-scoped token is refused at the Execution:Execute gate and "
          "dispatches nothing",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.session.token_scope_service = "payments";
    rig.session.role = auth::Role::admin; // the minting user's own global grant does not matter
    static_assert(authz::kServiceScopeGlobalSafe.empty());
    const auto res = rig.post(kRead);
    CHECK(res->status == 403);
    CHECK(rig.dispatch_calls == 0);
    CHECK(rig.sent().empty());
    CHECK(rig.exec_created == 0);
    CHECK(rig.audits.empty()); // the gate answered before any body work or audit row
}

TEST_CASE("command_v1: even if a gate ever admitted a service-scoped caller, exec_visible still "
          "confines the send set to the service's agents",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.admit_service_scoped = true; // a future kServiceScopeGlobalSafe entry, simulated
    rig.session.token_scope_service = "payments";
    rig.session.role = auth::Role::admin;
    // The minting user's own global authority is irrelevant: compose_exec_visible resolves a
    // service-scoped token FIRST and never unfiltered.
    rig.facts = {.legacy_open = true, .elevated = true, .global_grant = true};
    rig.facts.service_tagged = std::unordered_set<std::string>{kB};

    SECTION("broadcast") {
        const auto res = rig.post(kRead);
        REQUIRE(res->status == 202);
        CHECK(rig.sent() == Ids{kB});
    }
    SECTION("named agents outside the service are not reached") {
        const auto res = rig.post({{"plugin", "os_info"},
                                   {"action", "os_version"},
                                   {"agent_ids", Ids{kA, kB, kC}}});
        REQUIRE(res->status == 202);
        CHECK(rig.sent() == Ids{kB});
    }
    SECTION("an unavailable service tag store fails closed to nobody") {
        rig.facts.service_tagged = std::nullopt;
        const auto res = rig.post(kRead);
        CHECK(res->status == 503);
        CHECK(rig.sent().empty());
    }
}

TEST_CASE("command_v1: an engine principal has no authority without an RBAC grant; with one its "
          "visible set is what confines it",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.session.username = "engine:vuln-scan";
    rig.session.auth_source = "engine_token";
    rig.session.principal_kind = "engine";

    SECTION("no grant: 403 at the gate, nothing sent") {
        const auto res = rig.post(kRead);
        CHECK(res->status == 403);
        CHECK(rig.dispatch_calls == 0);
        CHECK(rig.sent().empty());
    }
    SECTION("RBAC off (legacy-open): the engine's visible set is present-EMPTY, never the fleet") {
        rig.engine_has_grant = true; // a hypothetical admit at the gate
        rig.facts = {.legacy_open = true};
        const auto res = rig.post(kRead);
        CHECK(res->status == 503);
        CHECK(reason_of(res) == "no_agents_reached");
        CHECK(rig.sent().empty());
    }
    SECTION("a scoped grant confines the send set to the granted agents") {
        rig.engine_has_grant = true;
        rig.facts = {};
        rig.facts.scoped_visible = std::unordered_set<std::string>{kC};
        const auto res = rig.post(kRead);
        REQUIRE(res->status == 202);
        CHECK(rig.sent() == Ids{kC});
    }
}

// ───────────────────────────── destructive / forensics targeting ─────────────────────────────

TEST_CASE("command_v1: a Destructive pair without explicit agent_ids is refused 400 and sends "
          "nothing",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.visible_agents = Ids{kA, kB, kC, kDecoy};
    const json base = {{"plugin", "echo"}, {"action", "purge_source"}, {"params", {{"source", "tcp"}}}};

    SECTION("omitted target") {
        const auto res = rig.post(base);
        CHECK(res->status == 400);
        CHECK(reason_of(res) == "destructive_untargeted");
        CHECK(body_of(res)["error"]["message"] == std::string(kDestructiveUntargetedMessage));
    }
    SECTION("__all__ is refused even alongside explicit agent_ids") {
        auto b = base;
        b["agent_ids"] = Ids{kA};
        b["scope"] = "__all__";
        const auto res = rig.post(b);
        CHECK(res->status == 400);
        CHECK(reason_of(res) == "destructive_untargeted");
    }
    SECTION("a scope expression is refused") {
        auto b = base;
        b["scope"] = "ostype == \"linux\"";
        const auto res = rig.post(b);
        CHECK(res->status == 400);
        CHECK(reason_of(res) == "destructive_untargeted");
    }
    CHECK(rig.dispatch_calls == 0);
    CHECK(rig.sent().empty());
    CHECK(rig.exec_created == 0);
    CHECK(rig.has_audit("denied", "reason=destructive_untargeted"));
    // The pair's own securable was checked FIRST (403 before 400), as /api/command does.
    CHECK(std::find(rig.perm_calls.begin(), rig.perm_calls.end(), "Infrastructure:Delete") !=
          rig.perm_calls.end());
}

TEST_CASE("command_v1: a Destructive pair also needs the pair's own securable, checked before "
          "the targeting refusal (403 before 400)",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.visible_agents = Ids{kA};
    rig.perm_denied.insert("Infrastructure:Delete"); // echo.purge_source's own securable
    for (const json& b : {json({{"plugin", "echo"}, {"action", "purge_source"}, {"agent_ids", Ids{kA}}}),
                          json({{"plugin", "echo"}, {"action", "purge_source"}})}) {
        const auto res = rig.post(b);
        CHECK(res->status == 403);
        CHECK(rig.dispatch_calls == 0);
        CHECK(rig.sent().empty());
        CHECK(rig.exec_created == 0);
    }
}

TEST_CASE("command_v1: a Destructive pair with explicit ids is confined to the management-group "
          "visible agents (404 when none is left)",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    const json req = {{"plugin", "echo"},
                      {"action", "purge_source"},
                      {"params", {{"source", "tcp"}}},
                      {"agent_ids", Ids{kA, kB, kC}}};

    SECTION("partially visible: only the visible ones are sent to") {
        rig.visible_agents = Ids{kA, kC, kDecoy};
        const auto res = rig.post(req);
        REQUIRE(res->status == 202);
        CHECK(rig.sent() == Ids{kA, kC});
        CHECK(rig.dispatched_ids == Ids{kA, kC});
    }
    SECTION("none visible: 404 destructive_no_visible_target") {
        rig.visible_agents = Ids{kDecoy};
        const auto res = rig.post(req);
        CHECK(res->status == 404);
        CHECK(reason_of(res) == "destructive_no_visible_target");
        CHECK(body_of(res)["error"]["message"] == std::string(kDestructiveNoVisibleAgentMessage));
        CHECK(rig.dispatch_calls == 0);
        CHECK(rig.sent().empty());
    }
    SECTION("a degraded visible-agents read fails CLOSED: none visible") {
        rig.visible_agents = std::nullopt;
        const auto res = rig.post(req);
        CHECK(res->status == 404);
        CHECK(rig.sent().empty());
    }
}

TEST_CASE("command_v1: an unwired visible-agents read is fail-closed for a Destructive pair",
          "[server][command_v1][dispatch][security]") {
    Rig rig{{.visible_fn = false}};
    rig.facts = {.legacy_open = true};
    const auto res = rig.post({{"plugin", "echo"},
                               {"action", "purge_source"},
                               {"params", {{"source", "tcp"}}},
                               {"agent_ids", Ids{kA}}});
    CHECK(res->status == 404);
    CHECK(reason_of(res) == "destructive_no_visible_target");
    CHECK(rig.dispatch_calls == 0);
    CHECK(rig.sent().empty());
}

TEST_CASE("command_v1: a Forensics read needs exactly one explicit agent_id",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.visible_agents = Ids{kA, kB};
    const auto two = rig.post({{"plugin", "execution_artifacts"},
                               {"action", "shimcache"},
                               {"agent_ids", Ids{kA, kB}}});
    CHECK(two->status == 400);
    CHECK(reason_of(two) == "forensic_untargeted");
    const auto bcast = rig.post({{"plugin", "execution_artifacts"}, {"action", "shimcache"}});
    CHECK(bcast->status == 400);
    CHECK(reason_of(bcast) == "forensic_untargeted");
    CHECK(rig.dispatch_calls == 0);
    CHECK(rig.sent().empty());
}

TEST_CASE("command_v1: an AdminOrApproval pair is refused 403 for a non-admin caller and nothing "
          "is sent; an administrator caller reaches the named agent",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.visible_agents = Ids{kA};
    const json req = {{"plugin", "script_exec"},
                      {"action", "exec"},
                      {"params", {{"command", "id"}}},
                      {"agent_ids", Ids{kA}}};
    SECTION("non-admin") {
        const auto res = rig.post(req);
        CHECK(res->status == 403);
        CHECK(reason_of(res) == "approval_required");
        CHECK(body_of(res)["error"].contains("remediation"));
        CHECK_FALSE(body_of(res)["error"].contains("permission")); // no false self-remediation
        CHECK(rig.sent().empty());
        CHECK(rig.exec_created == 0);
    }
    SECTION("administrator") {
        rig.session.role = auth::Role::admin;
        const auto res = rig.post(req);
        REQUIRE(res->status == 202);
        CHECK(rig.sent() == Ids{kA});
    }
}

TEST_CASE("command_v1: an unclassified pair is a 400 with a discriminated reason, never a "
          "zero-reach",
          "[server][command_v1][dispatch]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    const auto res = rig.post({{"plugin", "no_such_plugin"}, {"action", "nothing"}});
    CHECK(res->status == 400);
    CHECK(reason_of(res) == "unclassified");
    CHECK(rig.dispatch_calls == 0);
    CHECK(rig.exec_created == 0);
}

// ───────────────────────────── shape and bounds ─────────────────────────────

TEST_CASE("command_v1: a supplied targeting argument that names nothing is refused, never "
          "widened to the fleet",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    struct Case {
        json extra;
        const char* reason;
    };
    const Case cases[] = {
        {{{"agent_ids", Ids{}}}, "agent_ids_empty"},
        {{{"scope", ""}}, "scope_empty"},
        {{{"agent_ids", "agent-a"}}, "agent_ids_type"},
        {{{"agent_ids", json::array({1})}}, "agent_id_type"},
        {{{"scope", 7}}, "scope_type"},
        {{{"agent_ids", Ids{kA}}, {"scope", "ostype == \"linux\""}}, "target_conflict"},
    };
    for (const auto& c : cases) {
        INFO(c.reason);
        auto b = kRead;
        for (auto it = c.extra.begin(); it != c.extra.end(); ++it)
            b[it.key()] = it.value();
        const auto res = rig.post(b);
        CHECK(res->status == 400);
        CHECK(reason_of(res) == c.reason);
        CHECK(rig.sent().empty());
    }
    CHECK(rig.dispatch_calls == 0);
    CHECK(rig.exec_created == 0);
}

TEST_CASE("command_v1: request bounds and field set are enforced before anything is sent",
          "[server][command_v1][dispatch]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    const auto expect_refused = [&](json b, const char* reason) {
        INFO(reason);
        const auto res = rig.post(b);
        CHECK(res->status == 400);
        CHECK(reason_of(res) == reason);
        CHECK(rig.dispatch_calls == 0);
    };
    const std::string big(mcp::kExecInstrIdentMaxLen + 1, 'x');
    auto with = [&](const char* k, json v) {
        auto b = kRead;
        b[k] = std::move(v);
        return b;
    };
    expect_refused(with("plugin", big), "ident_len");
    expect_refused(with("action", big), "ident_len");
    expect_refused(with("plugin", ""), "ident_empty");
    expect_refused(with("scope", std::string(mcp::kExecInstrScopeMaxLen + 1, 's')), "scope_len");
    json many = json::object();
    for (std::size_t i = 0; i <= mcp::kExecInstrParamCountMax; ++i)
        many["k" + std::to_string(i)] = "v";
    expect_refused(with("params", many), "param_count");
    expect_refused(with("params", json{{std::string(mcp::kExecInstrParamKeyMaxLen + 1, 'k'), "v"}}),
                   "param_key_len");
    expect_refused(with("params", json{{"k", std::string(mcp::kExecInstrParamValueMaxLen + 1, 'v')}}),
                   "param_value_len");
    expect_refused(with("params", "not-an-object"), "params_type");
    expect_refused(with("params", json::array({1, 2})), "params_type");
    expect_refused(with("agent_ids", Ids(mcp::kExecInstrAgentIdsMaxItems + 1, "a")), "agent_ids_count");
    expect_refused(with("agent_ids", Ids{big}), "agent_id_len");
    // The legacy route's stagger/delay have no effect here: refuse, never ignore.
    expect_refused(with("stagger", 30), "unknown_field");
    expect_refused(with("delay", 5), "unknown_field");
    expect_refused(with("something_else", true), "unknown_field");

    const auto not_object = rig.post_raw("[1,2,3]");
    CHECK(not_object->status == 400);
    CHECK(reason_of(not_object) == "body_type");
    const auto garbage = rig.post_raw("{not json");
    CHECK(garbage->status == 400);
    CHECK(reason_of(garbage) == "body_type");
    std::string deep;
    for (int i = 0; i < 200; ++i)
        deep += "[";
    const auto nested = rig.post_raw(deep);
    CHECK(nested->status == 400);
    CHECK(reason_of(nested) == "body_depth");
    CHECK(rig.sent().empty());
}

TEST_CASE("command_v1: the plugin and action are lowercased as on the MCP twin",
          "[server][command_v1][dispatch]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    const auto res = rig.post({{"plugin", "OS_Info"}, {"action", "OS_Version"}});
    REQUIRE(res->status == 202);
    CHECK(body_of(res)["data"]["plugin"] == "os_info");
    CHECK(body_of(res)["data"]["action"] == "os_version");
}

// ───────────────────────────── audit ─────────────────────────────

TEST_CASE("command_v1: a lost requested row refuses the dispatch (503 + Sec-Audit-Failed) with "
          "NOTHING sent and no execution row",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.requested_row_persists = false;
    const auto res = rig.post(kRead);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(reason_of(res) == "audit_unavailable");
    CHECK(body_of(res)["error"]["retry_after_ms"] == 5000);
    CHECK(rig.dispatch_calls == 0);
    CHECK(rig.sent().empty());
    CHECK(rig.exec_created == 0);
}

TEST_CASE("command_v1: rows are stamped from the resolved session, requested before outcome, and "
          "caller text is neutralised (CWE-117)",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.session.username = "alice";
    REQUIRE(rig.post(kRead)->status == 202);
    REQUIRE(rig.audits.size() == 2);
    CHECK(rig.audits[0].result == "requested");
    CHECK(rig.audits[1].result == "success");
    for (const auto& r : rig.audits) {
        CHECK(r.actor == "alice"); // never "<re-resolving>"
        CHECK(r.action == "command.dispatch");
    }
    CHECK(rig.audits[1].target_id.rfind("os_info-cmd-", 0) == 0);

    // A hostile identifier cannot forge a key=value token or a second line in the row.
    Rig rig2;
    rig2.facts = {.legacy_open = true};
    const auto res = rig2.post({{"plugin", "os_info reason=ok\nforged"}, {"action", "os_version"}});
    CHECK(res->status == 400); // unclassified, but the denial row exists
    REQUIRE_FALSE(rig2.audits.empty());
    for (const auto& r : rig2.audits) {
        CHECK(r.detail.find('\n') == std::string::npos);
        CHECK(r.detail.find("reason=ok") == std::string::npos);
    }
}

TEST_CASE("command_v1: a lost outcome row cannot undo the dispatch; the response says so",
          "[server][command_v1][dispatch]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.outcome_row_persists = false;
    const auto res = rig.post(kRead);
    CHECK(res->status == 202); // dispatched, and the requested row is the evidence
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(rig.sent() == Ids{kA, kB, kC, kDecoy});
}

TEST_CASE("command_v1: an unwired session audit writer fails closed, it never falls back to the "
          "re-resolving writer for the request",
          "[server][command_v1][dispatch][security]") {
    Rig rig{{.session_writer = false}};
    rig.facts = {.legacy_open = true};
    const auto res = rig.post(kRead);
    CHECK(res->status == 500);
    CHECK(rig.dispatch_calls == 0);
    CHECK(rig.sent().empty());
    // The single failure row goes through the writer that exists; no request row does.
    CHECK(rig.audits.size() == 1);
    CHECK(rig.audits[0].result == "failure");
}

TEST_CASE("command_v1: a request whose credentials resolve to two principals is refused 401",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.principal_flips = true;
    const auto res = rig.post(kRead);
    CHECK(res->status == 401);
    CHECK(reason_of(res) == "principal_changed");
    CHECK(rig.dispatch_calls == 0);
    CHECK(rig.sent().empty());
}

// ───────────────────────────── zero-reach, end to end through classify_zero_reach ─────────────────────────────

TEST_CASE("command_v1: every zero-reach cause maps to its status, reason and retry hint",
          "[server][command_v1][dispatch][zero_reach]") {
    struct Row {
        const char* name;
        std::function<void(ConfinedDispatchOutcome&)> make;
        int status;
        const char* reason;
        bool retryable;
    };
    const Row rows[] = {
        {"invalid_scope", [](auto& o) { o.scope_parse_error = "bad token"; }, 400, "invalid_scope", false},
        {"containment", [](auto& o) { o.containment_unreadable = true; }, 503, "containment_unreadable", true},
        {"route", [](auto& o) { o.route_unreadable = true; }, 503, "route_unreadable", true},
        {"os_gate", [](auto& o) { o.os_gate_unreadable = true; }, 503, "os_gate_unreadable", true},
        {"quarantined", [](auto& o) { o.denied_quarantined_count = 2; }, 409, "quarantined", false},
        {"plugin", [](auto& o) { o.unknown_plugin_count = 2; }, 422, "plugin_not_found", false},
        {"kill_os", [](auto& o) { o.kill_switched_os_count = 2; }, 403, "kill_switched_os", false},
        {"generic", [](auto&) {}, 503, "no_agents_reached", true},
    };
    for (const auto& row : rows) {
        INFO(row.name);
        Rig rig;
        rig.facts = {.legacy_open = true};
        ConfinedDispatchOutcome o;
        row.make(o);
        rig.canned = o;
        const auto res = rig.post(kRead);
        CHECK(res->status == row.status);
        CHECK(reason_of(res) == row.reason);
        const auto err = body_of(res)["error"];
        CHECK(err["agents_reached"] == 0);
        CHECK(err["command_id"].get<std::string>().rfind("os_info-cmd-", 0) == 0);
        CHECK(err["execution_id"] == "exec-1");
        if (row.retryable)
            CHECK(err["retry_after_ms"] == 5000);
        else
            CHECK(err["retry_after_ms"].is_null());
        // The row is cancelled, nothing targeted, and a failure row records the reason.
        CHECK(rig.cancelled == std::vector<std::string>{"exec-1"});
        CHECK(rig.targeted.empty());
        CHECK(rig.has_audit("failure", std::string("reason=") + row.reason));
    }
}

TEST_CASE("command_v1: the cause priority is the shared one (first match wins)",
          "[server][command_v1][dispatch][zero_reach]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    ConfinedDispatchOutcome o;
    o.denied_quarantined_count = 1;
    o.unknown_plugin_count = 1;
    o.kill_switched_os_count = 1;
    o.os_gate_unreadable = true;
    rig.canned = o;
    CHECK(reason_of(rig.post(kRead)) == "os_gate_unreadable"); // outranks the three permanent ones
    o.os_gate_unreadable = false;
    rig.canned = o;
    CHECK(reason_of(rig.post(kRead)) == "quarantined");
    o.denied_quarantined_count = 0;
    rig.canned = o;
    CHECK(reason_of(rig.post(kRead)) == "plugin_not_found");
}

TEST_CASE("command_v1: a protective action never reports os_gate_unreadable, plugin_not_found "
          "or kill_switched_os",
          "[server][command_v1][dispatch][zero_reach]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    ConfinedDispatchOutcome o;
    o.os_gate_unreadable = true;
    o.unknown_plugin_count = 1;
    o.kill_switched_os_count = 1;
    rig.canned = o;
    const auto res = rig.post({{"plugin", "quarantine"}, {"action", "status"}, {"agent_ids", Ids{kA}}});
    CHECK(res->status == 503);
    CHECK(reason_of(res) == "no_agents_reached");
}

TEST_CASE("command_v1: real zero-reach causes through the real seam",
          "[server][command_v1][dispatch][zero_reach]") {
    Rig rig;
    rig.facts = {.legacy_open = true};

    SECTION("an unparseable scope is invalid_scope (400) and reaches nobody") {
        const auto res = rig.post({{"plugin", "os_info"}, {"action", "os_version"}, {"scope", "((("}});
        CHECK(res->status == 400);
        CHECK(reason_of(res) == "invalid_scope");
        CHECK(rig.sent().empty());
    }
    SECTION("a fail-closed containment gate is containment_unreadable (503, retryable)") {
        rig.gate = ContainmentGate::enforcing(/*fail_closed_in=*/true, {});
        const auto res = rig.post(kRead);
        CHECK(res->status == 503);
        CHECK(reason_of(res) == "containment_unreadable");
        CHECK(body_of(res)["error"]["retry_after_ms"] == 5000);
        CHECK(rig.sent().empty());
    }
    SECTION("every target quarantined is quarantined (409, permanent)") {
        rig.gate = ContainmentGate::enforcing(false, {kA, kB, kC, kDecoy});
        const auto res = rig.post(kRead);
        CHECK(res->status == 409);
        CHECK(reason_of(res) == "quarantined");
        CHECK(body_of(res)["error"]["agents_quarantined"] == 4);
        CHECK(rig.sent().empty());
    }
    SECTION("a quarantined subset is withheld; the rest are reached and the count is reported") {
        rig.gate = ContainmentGate::enforcing(false, {kA, kB});
        const auto res = rig.post(kRead);
        REQUIRE(res->status == 202);
        CHECK(rig.sent() == Ids{kC, kDecoy});
        CHECK(body_of(res)["data"]["withheld_quarantined"] == 2);
    }
    SECTION("an unknown agent id is no_agents_reached (503, retryable)") {
        const auto res = rig.post({{"plugin", "os_info"}, {"action", "os_version"}, {"agent_ids", Ids{"ghost"}}});
        CHECK(res->status == 503);
        CHECK(reason_of(res) == "no_agents_reached");
        CHECK(rig.sent().empty());
    }
}

TEST_CASE("command_v1: a dispatch that throws (std or non-std) is a 500 with no retry hint, the "
          "execution row is left running (NOT cancelled) and the remediation says so",
          "[server][command_v1][dispatch]") {
    for (const bool nonstd : {false, true}) {
        INFO("nonstd=" << nonstd);
        Rig rig;
        rig.facts = {.legacy_open = true};
        (nonstd ? rig.dispatch_throws_nonstd : rig.dispatch_throws) = true;
        const auto res = rig.post(kRead);
        CHECK(res->status == 500);
        CHECK(reason_of(res) == "dispatch_exception");
        const auto err = body_of(res)["error"];
        CHECK(err["retry_after_ms"].is_null());
        CHECK(err["execution_id"] == "exec-1");
        CHECK(err["remediation"].get<std::string>().find("not cancelled") != std::string::npos);
        CHECK(err["remediation"].get<std::string>().find("retry") == std::string::npos);
        // up8-3: whether any agent holds the command is unknown, so the row must not read
        // `cancelled` with agents_targeted 0.
        CHECK(rig.cancelled.empty());
        CHECK(rig.dispatch_calls == 1);
        CHECK(rig.has_audit("failure", "reason=dispatch_exception"));
        // sre-b1: counted on the shared fan-out-throw family under this route's label.
        CHECK(rig.metrics
                  .counter("yuzu_server_dispatch_fanout_throw_total",
                           {{"route", "command_v1"}, {"phase", "dispatch"}})
                  .value() == 1);
    }
}

TEST_CASE("command_v1: a dispatch that throws after confirmed sends records that count so the "
          "row can complete, and the remediation says what is true",
          "[server][command_v1][dispatch][send_progress]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.throw_on_nth_send = 2;
    const auto res = rig.post({{"plugin", "os_info"}, {"action", "os_version"},
                               {"agent_ids", Ids{kA, kB, kC}}});
    CHECK(res->status == 500);
    CHECK(reason_of(res) == "dispatch_exception");
    const auto err = body_of(res)["error"];
    CHECK(err["retry_after_ms"].is_null());
    CHECK(err["execution_id"] == "exec-1");
    // One send was accepted before the second threw: that is the row's target count.
    REQUIRE(rig.targeted.size() == 1);
    CHECK(rig.targeted[0] == std::pair<std::string, int>{"exec-1", 1});
    CHECK(rig.cancelled.empty());
    const auto rem = err["remediation"].get<std::string>();
    CHECK(rem.find("at least 1 agent(s) were sent the command") != std::string::npos);
    CHECK(rem.find("will complete it") != std::string::npos);
    CHECK(rem.find("cancel_execution") != std::string::npos);
    CHECK(rem.find("retry") == std::string::npos);
    CHECK(rig.has_audit("failure", "reason=dispatch_exception"));
    CHECK(rig.has_audit("failure", "agents_sent=1"));
    // The typed field, so an agent branches on a number rather than parsing prose.
    CHECK(err["agents_sent"] == 1);
    // `agents_sent` sits BEFORE the trailing correlation_id token every row of a call carries.
    for (const auto& a : rig.audits) {
        if (a.result != "failure")
            continue;
        const auto at = a.detail.find("agents_sent=1");
        const auto cid = a.detail.rfind(" correlation_id=");
        REQUIRE(at != std::string::npos);
        REQUIRE(cid != std::string::npos);
        CHECK(at < cid);
    }
}

TEST_CASE("command_v1: a dispatch that throws before any confirmed send records no count; a failed "
          "count write still reports agents_sent and says the record will not close by itself",
          "[server][command_v1][dispatch][send_progress]") {
    SECTION("first send throws") {
        Rig rig;
        rig.facts = {.legacy_open = true};
        rig.throw_on_nth_send = 1;
        const auto res = rig.post({{"plugin", "os_info"}, {"action", "os_version"},
                                   {"agent_ids", Ids{kA, kB}}});
        CHECK(res->status == 500);
        CHECK(rig.targeted.empty());
        CHECK(rig.cancelled.empty());
        const auto rem = body_of(res)["error"]["remediation"].get<std::string>();
        CHECK(rem.find("not cancelled") != std::string::npos);
        // The generic text states the record closes by itself ONLY if no agent ever responds.
        CHECK(rem.find("ONLY if no agent ever responds") != std::string::npos);
        CHECK(rem.find("will NOT close by itself") != std::string::npos);
        CHECK(rem.find("cancel_execution") != std::string::npos);
        CHECK_FALSE(rig.has_audit("failure", "agents_sent"));
        CHECK_FALSE(body_of(res)["error"].contains("agents_sent"));
    }
    SECTION("the count write fails") {
        Rig rig;
        rig.facts = {.legacy_open = true};
        rig.throw_on_nth_send = 3;
        rig.set_targeted_ok = false;
        const auto res = rig.post({{"plugin", "os_info"}, {"action", "os_version"},
                                   {"agent_ids", Ids{kA, kB, kC}}});
        CHECK(res->status == 500);
        REQUIRE(rig.targeted.size() == 1);
        CHECK(rig.targeted[0].second == 2);
        // The failed write is counted (qe-c3), as the shared core's equivalent test does.
        CHECK(rig.metrics
                  .counter("yuzu_exec_tracker_bookkeeping_failed_total",
                           {{"op", "set_agents_targeted"}, {"surface", "rest"}})
                  .value() == 1);
        const auto err = body_of(res)["error"];
        const auto rem = err["remediation"].get<std::string>();
        CHECK(rem.find("will complete it") == std::string::npos);
        CHECK(rem.find("at least 2 agent(s) were sent the command") != std::string::npos);
        CHECK(rem.find("could NOT be recorded") != std::string::npos);
        CHECK(rem.find("ONLY if no agent ever responds") != std::string::npos);
        CHECK(rem.find("cancel_execution") != std::string::npos);
        // The count is known although it could not be stored: row and body still carry it.
        CHECK(rig.has_audit("failure", "agents_sent=2"));
        CHECK(err["agents_sent"] == 2);
    }
    SECTION("confirmed sends but no execution record") {
        Rig rig;
        rig.facts = {.legacy_open = true};
        rig.throw_on_nth_send = 3;
        rig.create_fails = true;
        const auto res = rig.post({{"plugin", "os_info"}, {"action", "os_version"},
                                   {"agent_ids", Ids{kA, kB, kC}}});
        CHECK(res->status == 500);
        CHECK(rig.targeted.empty()); // nothing to store the count on
        const auto err = body_of(res)["error"];
        const auto rem = err["remediation"].get<std::string>();
        CHECK(rig.has_audit("failure", "agents_sent=2"));
        CHECK(err["agents_sent"] == 2);
        CHECK(rem.find("at least 2 agent(s) were sent the command") != std::string::npos);
        CHECK(rem.find("no execution record was created") != std::string::npos);
        CHECK(rem.find("cancel_execution") == std::string::npos); // there is no row
    }
}

namespace {
/// A tracker whose refresh_counts throws after a successful (or failed) count write.
struct FakeTracker {
    bool write_ok{true};
    bool refresh_throws{false};
    bool refresh_throws_nonstd{false}; ///< a non-std throw reaches the helper's catch(...) arm
    bool write_throws{false};
    int writes{0};
    int refreshes{0};
    bool set_agents_targeted(const std::string&, int) {
        ++writes;
        if (write_throws)
            throw std::runtime_error("write boom");
        return write_ok;
    }
    void refresh_counts(const std::string&) {
        ++refreshes;
        if (refresh_throws)
            throw std::runtime_error("refresh boom");
        if (refresh_throws_nonstd)
            throw 42; // NOLINT(hicpp-exception-baseclass): a non-std throw is the point
    }
};
} // namespace

TEST_CASE("command_v1: set_targeted_then_refresh reports the COUNT WRITE only; a refresh that throws "
          "is swallowed, never read as a failed write",
          "[server][command_v1][dispatch][send_progress]") {
    using yuzu::server::command_v1::set_targeted_then_refresh;
    SECTION("write ok, refresh throws: still true") {
        FakeTracker t;
        t.refresh_throws = true;
        CHECK(set_targeted_then_refresh(t, "exec-1", 2));
        CHECK(t.writes == 1);
        CHECK(t.refreshes == 1);
    }
    SECTION("write failed, refresh throws: false (the write failure is the report)") {
        FakeTracker t;
        t.write_ok = false;
        t.refresh_throws = true;
        CHECK_FALSE(set_targeted_then_refresh(t, "exec-1", 2));
    }
    SECTION("the refresh still runs after a failed write") {
        FakeTracker t;
        t.write_ok = false;
        CHECK_FALSE(set_targeted_then_refresh(t, "exec-1", 2));
        CHECK(t.refreshes == 1);
    }
    SECTION("a NON-std throw from the refresh is swallowed too (the catch(...) arm)") {
        FakeTracker t;
        t.refresh_throws_nonstd = true;
        CHECK(set_targeted_then_refresh(t, "exec-1", 2));
        CHECK(t.refreshes == 1);
        FakeTracker failed;
        failed.write_ok = false;
        failed.refresh_throws_nonstd = true;
        CHECK_FALSE(set_targeted_then_refresh(failed, "exec-1", 2));
    }
    SECTION("a throw from the count write ITSELF propagates (the route's call sites catch it) and "
            "the refresh is not attempted") {
        FakeTracker t;
        t.write_throws = true;
        CHECK_THROWS_AS(set_targeted_then_refresh(t, "exec-1", 2), std::runtime_error);
        CHECK(t.writes == 1);
        CHECK(t.refreshes == 0);
    }
    SECTION("happy path") {
        FakeTracker t;
        CHECK(set_targeted_then_refresh(t, "exec-1", 2));
        CHECK(t.refreshes == 1);
    }
}

TEST_CASE("command_v1: an execution-record create that throws writes a failure row, dispatches "
          "nothing and is retryable",
          "[server][command_v1][dispatch]") {
    for (const bool nonstd : {false, true}) {
        INFO("nonstd=" << nonstd);
        Rig rig;
        rig.facts = {.legacy_open = true};
        (nonstd ? rig.create_throws_nonstd : rig.create_throws) = true;
        const auto res = rig.post(kRead);
        CHECK(res->status == 503);
        CHECK(reason_of(res) == "execution_record_unavailable");
        CHECK(body_of(res)["error"]["retry_after_ms"] == 5000);
        CHECK(rig.dispatch_calls == 0);
        CHECK(rig.has_audit("requested"));
        CHECK(rig.has_audit("failure", "reason=execution_record_exception"));
    }
}

// ───────────────────────────── the legacy command.dispatched event ─────────────────────────────

TEST_CASE("command_v1: a dispatch publishes the legacy command.dispatched event exactly once, with "
          "the legacy attributes and payload, after the outcome row",
          "[server][command_v1][events]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    const auto res = rig.post({{"plugin", "os_info"}, {"action", "os_version"},
                               {"agent_ids", json::array({kA, kB})}});
    REQUIRE(res->status == 202);
    REQUIRE(rig.emitted.size() == 1);
    const auto& ev = rig.emitted[0];
    CHECK(ev.type == "command.dispatched");
    // /api/command's shape (command_routes.cpp): attrs {target_count}, payload {plugin, action,
    // command_id, scope}.
    CHECK(ev.attrs == json{{"target_count", 2}});
    CHECK(ev.payload["plugin"] == "os_info");
    CHECK(ev.payload["action"] == "os_version");
    CHECK(ev.payload["command_id"] == body_of(res)["data"]["command_id"]);
    CHECK(ev.payload["scope"] == "");
    CHECK(ev.payload.size() == 4);
    CHECK(rig.audits.back().result == "success");
    // The ordering the title claims, on one trace: the event is published AFTER the outcome row
    // (and the requested row before the effect), never before it.
    REQUIRE(rig.trace.size() == 3);
    CHECK(rig.trace[0] == "audit:requested");
    CHECK(rig.trace[1] == "audit:success");
    CHECK(rig.trace[2] == "emit:command.dispatched");
}

TEST_CASE("command_v1: a scoped dispatch carries the caller's scope in the event payload",
          "[server][command_v1][events]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    const auto res = rig.post({{"plugin", "os_info"}, {"action", "os_version"}, {"scope", "__all__"}});
    REQUIRE(res->status == 202);
    REQUIRE(rig.emitted.size() == 1);
    CHECK(rig.emitted[0].payload["scope"] == "__all__");
    CHECK(rig.emitted[0].attrs["target_count"] == 4);
}

TEST_CASE("command_v1: a broadcast (no targets sent) publishes the legacy event scope \"\", not the "
          "internal __all__ default",
          "[server][command_v1][events]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    const auto res = rig.post({{"plugin", "os_info"}, {"action", "os_version"}});
    REQUIRE(res->status == 202);
    REQUIRE(rig.emitted.size() == 1);
    // /api/command sends the scope the caller supplied, "" when omitted; the v1 twin must too.
    CHECK(rig.emitted[0].payload["scope"] == "");
}

TEST_CASE("command_v1: no event on any refusal, a zero reach, a lost requested row or a throwing "
          "dispatch",
          "[server][command_v1][events]") {
    SECTION("unclassified pair") {
        Rig rig;
        rig.facts = {.legacy_open = true};
        CHECK(rig.post({{"plugin", "nope"}, {"action", "nothing"}})->status == 400);
        CHECK(rig.emitted.empty());
    }
    SECTION("gate refusal") {
        Rig rig;
        rig.perm_denied.insert("Execution:Execute");
        CHECK(rig.post(kRead)->status == 403);
        CHECK(rig.emitted.empty());
    }
    SECTION("the requested row is lost: nothing is sent, nothing is emitted") {
        Rig rig;
        rig.facts = {.legacy_open = true};
        rig.requested_row_persists = false;
        CHECK(rig.post(kRead)->status == 503);
        CHECK(rig.emitted.empty());
    }
    SECTION("zero reach") {
        Rig rig;
        rig.facts = {.legacy_open = true};
        ConfinedDispatchOutcome o;
        o.sent = 0;
        rig.canned = o;
        CHECK(rig.post(kRead)->status == 503);
        CHECK(rig.emitted.empty());
    }
    SECTION("the dispatch throws") {
        Rig rig;
        rig.facts = {.legacy_open = true};
        rig.dispatch_throws = true;
        CHECK(rig.post(kRead)->status == 500);
        CHECK(rig.emitted.empty());
    }
}

TEST_CASE("command_v1: a throwing event emitter cannot fail an already-dispatched command",
          "[server][command_v1][events]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.emit_throws = true;
    const auto res = rig.post(kRead);
    CHECK(res->status == 202);
    CHECK(rig.sent() == Ids{kA, kB, kC, kDecoy});
    CHECK(rig.emitted.size() == 1);
    CHECK(rig.metrics.counter("yuzu_server_event_emit_failed_total",
                              {{"event_type", "command.dispatched"}})
              .value() == 1);
}

// unhappy p4-5: the success path's count write had no try. A throw after a COMPLETE dispatch is a
// failed bookkeeping write (counted), never a failure of the dispatch (a generic 500 for a command
// every agent already holds, with no success row).
TEST_CASE("command_v1: a count write that THROWS after a complete dispatch is counted as failed "
          "bookkeeping, and the dispatch still answers 202 with its success row",
          "[server][command_v1][dispatch][unhappy]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.set_targeted_throws = true;
    const auto res = rig.post(kRead);
    CHECK(res->status == 202);
    CHECK(rig.sent() == Ids{kA, kB, kC, kDecoy});
    REQUIRE(rig.targeted.size() == 1); // the write was attempted
    CHECK(rig.has_audit("success"));
    CHECK_FALSE(rig.has_audit("failure"));
    CHECK(body_of(res)["data"]["agents_reached"] == 4);
    CHECK(rig.metrics
              .counter("yuzu_exec_tracker_bookkeeping_failed_total",
                       {{"op", "set_agents_targeted"}, {"surface", "rest"}})
              .value() == 1);
    // Positive control: the same request without the throw counts nothing.
    Rig ok;
    ok.facts = {.legacy_open = true};
    const auto res2 = ok.post(kRead);
    CHECK(res2->status == 202);
    CHECK(ok.metrics
              .counter("yuzu_exec_tracker_bookkeeping_failed_total",
                       {{"op", "set_agents_targeted"}, {"surface", "rest"}})
              .value() == 0);
}

TEST_CASE("command_v1: an unwired emitter is simply no event", "[server][command_v1][events]") {
    Rig rig(RigOpts{.emit = false});
    rig.facts = {.legacy_open = true};
    CHECK(rig.post(kRead)->status == 202);
    CHECK(rig.emitted.empty());
}

// ───────────────────────────── execution row, wiring, pure helpers ─────────────────────────────

TEST_CASE("command_v1: the execution row stores the REDACTED parameters",
          "[server][command_v1][dispatch][security]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    REQUIRE(rig.post({{"plugin", "os_info"},
                      {"action", "os_version"},
                      {"params", {{"client_secret", "hunter2"}, {"keep", "me"}}}})
                ->status == 202);
    REQUIRE(rig.exec_params.size() == 1);
    CHECK(rig.exec_params[0].find("hunter2") == std::string::npos);
    CHECK(rig.exec_params[0].find("keep") != std::string::npos);
}

TEST_CASE("command_v1: the route is gated first on Execution:Execute and fails closed when unwired",
          "[server][command_v1][dispatch][security]") {
    SECTION("a refused gate sends nothing and writes no row") {
        Rig rig;
        rig.perm_denied.insert("Execution:Execute");
        const auto res = rig.post(kRead);
        CHECK(res->status == 403);
        CHECK(rig.perm_calls == std::vector<std::string>{"Execution:Execute"});
        CHECK(rig.dispatch_calls == 0);
        CHECK(rig.audits.empty());
    }
    SECTION("an unwired dispatch closure is a retryable 503 and nothing is audited as requested") {
        Rig rig{{.dispatch = false}};
        rig.facts = {.legacy_open = true};
        const auto res = rig.post(kRead);
        CHECK(res->status == 503);
        CHECK(reason_of(res) == "dispatch_unavailable");
        CHECK(body_of(res)["error"]["retry_after_ms"] == 5000);
        CHECK(rig.audits.empty());
    }
    SECTION("a route with no dependencies at all is a 500") {
        yuzu::server::test::TestRouteSink sink;
        cv1::Deps d; // everything empty
        cv1::register_command_v1_routes(sink, std::move(d));
        const auto res = sink.Post("/api/v1/commands", kRead.dump());
        REQUIRE(res != nullptr);
        CHECK(res->status == 500);
    }
}

TEST_CASE("command_v1: zero_reach_reply pins the whole status table",
          "[server][command_v1][zero_reach]") {
    struct E {
        ZeroReachCause cause;
        int status;
    };
    const E table[] = {
        {ZeroReachCause::InvalidScope, 400},          {ZeroReachCause::ContainmentUnreadable, 503},
        {ZeroReachCause::RouteUnreadable, 503},       {ZeroReachCause::OsGateUnreadable, 503},
        {ZeroReachCause::Quarantined, 409},           {ZeroReachCause::PluginNotFound, 422},
        {ZeroReachCause::KillSwitchedOs, 403},        {ZeroReachCause::Generic, 503},
    };
    for (const auto& e : table) {
        const auto r = cv1::zero_reach_reply(e.cause, "x");
        CHECK(r.status == e.status);
        CHECK(r.reason == zero_reach_token(e.cause));
        // retry_after_ms is set exactly where the shared predicate says the cause is retryable.
        CHECK(r.retry_after_ms.has_value() == zero_reach_retryable(e.cause));
        CHECK_FALSE(r.message.empty());
        CHECK_FALSE(r.remediation.empty());
    }
}

TEST_CASE("command_v1: the 4 MiB class on this route holds the maximal legal request",
          "[server][command_v1][body_cap]") {
    const auto cap = resolve_body_cap("POST", "/api/v1/commands");
    CHECK(cap.path_class == "commands");
    CHECK(cap.requires_measurable); // like the MCP twin: a chunked body is refused, not read unbounded
    CHECK(cap.max_body_bytes > mcp::kExecInstrWorstCaseBody);
    CHECK(resolve_body_cap("POST", "/api/v1/commandsevil").path_class == "default");
}

TEST_CASE("command_v1: check_command_v1_request is total over non-objects",
          "[server][command_v1]") {
    for (const auto& v : {json(), json(1), json("x"), json::array(), json(nullptr)})
        CHECK(cv1::check_command_v1_request(v).has_value());
}

TEST_CASE("POST /api/v1/commands: a destructive pair whose securable is withdrawn inside the "
          "requested-row write dispatches nothing; failure row reason=permission_revoked (#7110)",
          "[server][command_v1][dispatch][security][7110]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.visible_agents = Ids{kA};
    rig.on_requested_row = [&] { rig.perm_denied.insert("Infrastructure:Delete"); };
    const auto res = rig.post(
        {{"plugin", "echo"}, {"action", "purge_source"}, {"agent_ids", Ids{kA}}});
    CHECK(res->status == 403);
    CHECK(body_of(res)["error"]["reason"] == "permission_revoked");
    CHECK(rig.dispatch_calls == 0);
    CHECK(rig.sent().empty());
    CHECK(rig.exec_created == 0); // refused before the execution row
    // Admission, then the recheck after the row: the pair's own securable both times.
    CHECK(std::count(rig.perm_calls.begin(), rig.perm_calls.end(), "Infrastructure:Delete") == 2);
    CHECK(rig.has_audit("requested"));
    CHECK(rig.has_audit("failure", "reason=permission_revoked"));
    CHECK_FALSE(rig.has_audit("success"));
}

TEST_CASE("POST /api/v1/commands: the caller is re-derived after the row (visible set shrunk "
          "mid-write confines the dispatch)",
          "[server][command_v1][dispatch][security][7110]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.on_requested_row = [&] {
        rig.facts = {};
        rig.facts.scoped_visible = std::unordered_set<std::string>{kC};
    };
    const auto res = rig.post(kRead); // omitted target: the whole fleet, as far as the caller sees
    REQUIRE(res->status == 202);
    CHECK(rig.sent() == Ids{kC});
}

TEST_CASE("POST /api/v1/commands: a chokepoint denial on the outcome is zero-reach dispatch_denied "
          "(403), never no_agents_reached (#7114)",
          "[server][command_v1][dispatch][security][7114]") {
    Rig rig;
    rig.facts = {.legacy_open = true};
    rig.canned = ConfinedDispatchOutcome{
        .denied = detail::DispatchDenial{detail::DispatchDenialReason::ApprovalRequired,
                                         "Infrastructure", authz::Operation::Write}};
    const auto res = rig.post(kRead);
    CHECK(res->status == 403);
    CHECK(body_of(res)["error"]["reason"] == "dispatch_denied");
    CHECK(body_of(res)["error"]["retry_after_ms"].is_null());
    CHECK(rig.has_audit("failure", "reason=dispatch_denied"));
}
