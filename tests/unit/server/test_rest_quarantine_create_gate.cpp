/**
 * test_rest_quarantine_create_gate.cpp -- #6065 PR-Q: POST /api/v1/quarantine
 * runs the shared dispatch chokepoint for ("quarantine","quarantine"), and a
 * denied caller reaches NO agent, end to end; DELETE (release) runs it for
 * ("quarantine","unquarantine") and a denied release leaves the record active (case j).
 *
 * WHY THIS FILE EXISTS. test_rest_quarantine_routes.cpp pins the route WIRING
 * with an injected authorizer; an injected admission proves wiring, not
 * confinement (test_dispatch_confined_arms.cpp:1-24 documents the false green
 * that shipped once already). This file composes the PRODUCTION pieces and
 * asserts the exact recipients and the exact stored whitelist:
 *
 *   - the real REST route lambda, registered on a TestRouteSink;
 *   - a real QuarantineStore, ResponseStore, RbacStore and ManagementGroupStore
 *     on one Postgres database;
 *   - the real classify_and_authorize_dispatch over a real
 *     CommandCapabilityRegistry carrying the PRODUCTION catalogue
 *     (YUZU_ALL_CAPABILITY_FRAGMENTS), with the dispatch_has_permission shape
 *     over the real RbacStore (RBAC on AND off);
 *   - the real QuarantineContainmentReconciler, whose dispatch_fn is the real
 *     chokepoint (system caller) feeding the real wire_and_dispatch_confined
 *     (-> dispatch_confined_arms) over a REAL AgentRegistry;
 *   - a real LeaderElector gating the tick exactly as server.cpp does.
 *
 * Only the transport is not real: the agents are registered on the gateway
 * route and a dispatch is observed through AgentRegistry::drain_gateway_pending
 * (the K-1 technique in test_dispatch_confined_arms.cpp), which records the
 * exact agent id and the exact CommandRequest (plugin, action, parameters)
 * with no gRPC stream. That is stricter than the file's RecordingSink: it is the
 * production send_to, not a mock of it. The sink was NOT hoisted into a shared
 * header, so test_dispatch_confined_arms.cpp is untouched.
 *
 * Four things are stand-ins and are named as such:
 *   - The scoped gate (ScopedPermFn) is `scoped_gate_stub`: RBAC enforced ->
 *     RbacStore::check_scoped_permission (what require_scoped_permission's RBAC
 *     branch calls); RBAC off -> ADMIT. The real RBAC-off branch of
 *     require_scoped_permission refuses a non-admin Execute ("admin role
 *     required") BEFORE this route reaches the chokepoint, so under RBAC off the
 *     chokepoint's own ApprovalRequired decision (case b) is only observable
 *     with a scoped gate that admits. The gate is not the unit under test here.
 *   - dispatch_has_permission is a private ServerImpl member, so `has_permission`
 *     below reproduces its three lines (not-enforced -> true, else
 *     RbacStore::check_permission) rather than calling it.
 *   - `Rig::authorize_dispatch` and `Rig::caller_for` re-spell the closure server.cpp
 *     defines and the caller MCP builds. Case (e) therefore proves the DECISION is a
 *     pure function of the caller, NOT that server.cpp hands REST and MCP the same
 *     closure: that wiring is pinned lexically by tests/test_tier_policy_wiring_lexical.py
 *     (clause 4: one definition, two uses) and by a static_assert in server.cpp.
 *   - The agents are registered on the gateway route (no gRPC stream). A second,
 *     never-targeted agent is registered as a decoy so that "exactly agent-1" and
 *     "nobody else" can actually observe a send to the wrong agent.
 */

#include "agent_registry.hpp"
#include "background_jobs.hpp"
#include "capability_fragments.hpp"
#include "command_capability.hpp"
#include "dispatch_caller.hpp"
#include "dispatch_denial_text.hpp"
#include "dispatch_scope_ladder.hpp"
#include "dispatch_target_shape.hpp"
#include "leader_elector.hpp"
#include "leader_gate.hpp"
#include "management_group_store.hpp"
#include "quarantine_containment_reconciler.hpp"
#include "quarantine_store.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "rest_api_v1.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"
#include "test_route_sink.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>
#include <yuzu/protective_actions.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cctype>
#include <chrono>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using yuzu::server::pg::PgPool;

namespace {

// One database carries every store this file composes. A unique template key: the registry
// replay-verifies that every registration of ONE key builds the identical structure, and no
// other file composes this set.
yuzu::test::PgTestTemplate create_gate_tpl{"restquarantinecreategate", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    QuarantineStore quarantine{pool};
    ResponseStore responses{pool};
    RbacStore rbac{pool};
    ManagementGroupStore mgmt{pool};
    if (!quarantine.is_open() || !responses.is_open() || !rbac.is_open() || !mgmt.is_open())
        throw std::runtime_error("restquarantinecreategate template: a store failed to migrate");
}};

constexpr const char* kAgent = "agent-1";
constexpr const char* kDecoy = "agent-2"; // registered, never named by a record
constexpr const char* kWhitelist = "10.0.0.1,10.0.0.2";

// What the dispatch observed: the exact agent and the exact wire command.
struct Sent {
    std::string agent_id;
    std::string plugin;
    std::string action;
    std::unordered_map<std::string, std::string> params;
};

struct Rig {
    // ---- stores and the chokepoint inputs (declaration order = construction order) ----
    PgPool pool;
    QuarantineStore quarantine;
    ResponseStore responses;
    RbacStore rbac;
    ManagementGroupStore mgmt;
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry;
    CommandCapabilityRegistry caps{YUZU_ALL_CAPABILITY_FRAGMENTS};
    LeaderElector elector;

    // ---- the caller of the REST route ----
    std::string session_user;
    auth::Role session_role{auth::Role::user};
    bool session_elevated{false}; // a live JIT elevation on the session (effective role admin)
    std::vector<std::pair<std::string, std::string>> audits; // "action/result" + detail
    // The actor each row in `audits` names, index for index. The re-resolving writer
    // (`audit_fn`) names `audit_resolves_to` when set (a credential that lapsed, or a second
    // one, between the route's own resolution and the write); the session writer names the
    // session the route handed it.
    std::vector<std::string> audit_actors;
    std::vector<std::string> audit_roles; // the role each row carries, aligned with `audits`
    std::string audit_resolves_to;
    // When non-empty, each auth_fn call takes its user from the front (then drops it): the
    // first call is the route's entry, the second its re-resolution. `auth_elevated_queue`
    // does the same for a live JIT elevation on that call's session.
    std::deque<std::string> auth_user_queue;
    std::deque<bool> auth_elevated_queue;
    bool wire_audit_as_session{true};

    std::int64_t command_seq{0};
    std::string last_command_id;
    std::vector<Sent> sent_log;

    RestApiV1::AuthorizeDispatchFn authorize_dispatch;
    detail::KillSwitchFn kill_switch; // empty = unwired (legacy-open), as server.cpp without a store
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;
    std::unique_ptr<QuarantineContainmentReconciler> reconciler;

    static LeaderElector::Config elector_cfg(const std::string& dsn, std::string holder) {
        return LeaderElector::Config{.dsn = dsn, .holder_id = std::move(holder)};
    }

    explicit Rig(const std::string& dsn, bool wire_session_writer = true)
        : pool{{.conninfo = dsn, .size = 8}}, quarantine(pool), responses(pool), rbac(pool),
          mgmt(pool), registry(bus, metrics), elector(elector_cfg(dsn, "holder-a")) {
        REQUIRE(quarantine.is_open());
        REQUIRE(responses.is_open());
        REQUIRE(rbac.is_open());
        REQUIRE(mgmt.is_open());
        REQUIRE(elector.is_open());
        wire_audit_as_session = wire_session_writer;

        // The agent is reachable on the gateway route: send_to queues onto
        // drain_gateway_pending() with NO gRPC stream, and the queue carries the full
        // CommandRequest. The dispatch-tag capability is advertised as a real gateway's
        // CONNECTED notification would (send_to refuses a tagged command otherwise).
        ::yuzu::agent::v1::AgentInfo info;
        info.set_agent_id(kAgent);
        info.set_hostname("host.local");
        (void)registry.register_agent(info);
        REQUIRE(registry.set_gateway_route(
            kAgent, /*session_id=*/{}, "test-gateway",
            {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));
        ::yuzu::agent::v1::AgentInfo decoy;
        decoy.set_agent_id(kDecoy);
        decoy.set_hostname("decoy.local");
        (void)registry.register_agent(decoy);
        REQUIRE(registry.set_gateway_route(
            kDecoy, /*session_id=*/{}, "test-gateway",
            {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));

        // A copy of the one closure server.cpp binds for REST and MCP: classify +
        // authorize through the real chokepoint, then the kill-switch half (no
        // plugin_config_store here: legacy-open, the server.cpp unwired contract).
        authorize_dispatch = [this](const DispatchCaller& caller, std::string_view plugin,
                                    std::string_view action)
            -> std::expected<CommandCapability, detail::DispatchDenial> {
            auto decision = detail::classify_and_authorize_dispatch(
                caps, caller, plugin, action,
                [this](std::string_view principal, std::string_view securable, authz::Operation op) {
                    return has_permission(principal, securable, op);
                });
            if (!decision)
                return decision;
            if (auto os_set = detail::kill_switch_denial(*decision, kill_switch); !os_set)
                return std::unexpected(os_set.error());
            return decision;
        };

        register_routes();
        build_reconciler();
    }

    // The three lines of ServerImpl::dispatch_has_permission (private member).
    bool has_permission(std::string_view principal, std::string_view securable,
                        authz::Operation op) const {
        if (!rbac_enforcement_in_effect(&rbac))
            return true;
        return rbac.check_permission(std::string(principal), std::string(securable),
                                     std::string(authz::to_string(op)));
    }

    void set_rbac(bool on) {
        REQUIRE(rbac.set_rbac_enabled(on).has_value());
        REQUIRE(rbac_enforcement_in_effect(&rbac) == on);
    }

    void as_admin(const std::string& user) {
        session_user = user;
        session_role = auth::Role::admin;
        session_elevated = false;
    }
    void as_user(const std::string& user) {
        session_user = user;
        session_role = auth::Role::user;
        session_elevated = false;
    }
    void as_jit_elevated_user(const std::string& user) {
        as_user(user);
        session_elevated = true;
    }

    // THE session the route's auth_fn returns, and the one the tests assert on: a single
    // builder, so a test can prove the fixture really is (or is not) an effective admin.
    auth::Session make_session(const std::string& user, bool elevated) const {
        auth::Session s;
        s.username = user;
        s.role = session_role;
        if (elevated) {
            s.elevated_until = std::chrono::system_clock::now() + std::chrono::hours(1);
            s.steady_elevated_until = std::chrono::steady_clock::now() + std::chrono::hours(1);
        }
        return s;
    }
    auth::Session make_session() const { return make_session(session_user, session_elevated); }

    void register_routes() {
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (session_user.empty()) {
                res.status = 401;
                return std::nullopt;
            }
            if (!auth_user_queue.empty()) {
                const std::string user = auth_user_queue.front();
                auth_user_queue.pop_front();
                bool elevated = session_elevated;
                if (!auth_elevated_queue.empty()) {
                    elevated = auth_elevated_queue.front();
                    auth_elevated_queue.pop_front();
                }
                return make_session(user, elevated);
            }
            return make_session();
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&, const std::string&,
                               const std::string& detail) -> bool {
            // The quarantine routes write through the session writer below; the one row that
            // may reach this re-resolving writer is the unwired-writer failure row, which has
            // no session writer to use. Any other row here is the defect this file pins.
            if (action.rfind("quarantine.", 0) == 0 &&
                detail != "audit identity writer not configured")
                FAIL_CHECK("a quarantine row went through the re-resolving audit_fn: "
                           << action << "/" << result);
            audits.emplace_back(action + "/" + result, detail);
            audit_actors.push_back(audit_resolves_to.empty() ? session_user : audit_resolves_to);
            audit_roles.push_back({});
            return true;
        };
        // The session writer server.cpp binds: the row names the session it is handed.
        if (wire_audit_as_session)
            api.set_audit_as_session_fn(
                [this](const httplib::Request&, const auth::Session& session,
                       const std::string& principal_role, const std::string& action,
                       const std::string& result, const std::string&, const std::string&,
                       const std::string& detail) -> bool {
                    audits.emplace_back(action + "/" + result, detail);
                    audit_actors.push_back(session.username);
                    audit_roles.push_back(principal_role);
                    return true;
                });
        // Stand-in, named in the file header.
        RestApiV1::ScopedPermFn scoped_gate_stub =
            [this](const httplib::Request&, httplib::Response& res, const std::string& securable,
                   const std::string& operation, const std::string& agent_id) -> bool {
            if (!rbac_enforcement_in_effect(&rbac))
                return true;
            if (rbac.check_scoped_permission(session_user, securable, operation, agent_id, &mgmt))
                return true;
            res.status = 403;
            return false;
        };
        RestApiV1::ExecVisibleFn exec_visible = [](const auth::Session&) { return authz::deny_all(); };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/&rbac, /*mgmt_store=*/&mgmt,
                            /*token_store=*/nullptr, &quarantine,
                            /*response_store=*/&responses, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr, /*service_group_fn=*/{},
                            /*tag_push_fn=*/{}, /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr, /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr, /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr, /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{}, /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr, /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{}, /*guardian_push_fn=*/{}, /*dex_perf_fn=*/{},
                            /*network_api=*/{}, /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr, scoped_gate_stub,
                            /*software_inventory_store=*/nullptr, /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr, exec_visible,
                            /*list_read_fn=*/{}, /*fleet_read_fn=*/{},
                            /*agents_fn=*/{}, /*response_visible_set_fn=*/{},
                            /*verify_api=*/nullptr, /*device_api=*/nullptr,
                            /*dex_api=*/nullptr, /*dex_perf_api=*/nullptr,
                            /*guardian_api=*/nullptr, /*tier_policy_fn=*/{}, authorize_dispatch);
    }

    // The reconciler's dispatch_fn: the real chokepoint for a SYSTEM caller composed with the
    // real wire_and_dispatch_confined, the slice of ServerImpl::dispatch_confined that decides
    // who is reached (build_classified_command -> make_containment_gate ->
    // wire_and_dispatch_confined). The kill switch store is unwired (legacy-open), as in
    // server.cpp when plugin_config_store_ is null.
    ConfinedDispatchOutcome system_dispatch(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id) {
        auto norm_action = action;
        for (auto& c : norm_action)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        const std::string command_id = plugin + "-cmd-" + std::to_string(++command_seq);
        last_command_id = command_id;

        const DispatchCaller system_caller{.system = true};
        auto decision = detail::classify_and_authorize_dispatch(
            caps, system_caller, plugin, norm_action,
            [this](std::string_view principal, std::string_view securable, authz::Operation op) {
                return has_permission(principal, securable, op);
            });
        if (!decision)
            return ConfinedDispatchOutcome{.command_id = command_id};
        const auto arm = classify_dispatch_arm(!agent_ids.empty(), scope_expr);
        auto classified = detail::finalize_classified_command(
            *decision, detail::KillSwitchFn{}, plugin, norm_action, command_id, parameters,
            /*payload=*/{}, /*stagger_seconds=*/0, /*delay_seconds=*/0,
            std::string(dispatch_arm_label(arm)), execution_id);
        if (!classified)
            return ConfinedDispatchOutcome{.command_id = command_id};
        // make_containment_gate: the quarantine plugin's own control channel is exempt.
        const auto gate = yuzu::protective::is_quarantine_control_plugin(plugin, norm_action)
                              ? ContainmentGate::exempt_control_plugin()
                              : ContainmentGate::enforcing(/*fail_closed_in=*/false, {});
        auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                             const std::string&) {};
        return wire_and_dispatch_confined(
            registry, /*mgmt_group_store=*/nullptr, /*result_set_store=*/nullptr,
            /*tag_store=*/nullptr, /*custom_properties_store=*/nullptr,
            /*execution_tracker=*/nullptr, noop_audit, noop_audit, command_id, execution_id,
            /*principal_role=*/"", agent_ids, scope_expr, system_caller.exec_visible,
            /*broadcast_on_none=*/false, gate, *classified);
    }

    void build_reconciler() {
        reconciler = std::make_unique<QuarantineContainmentReconciler>(
            QuarantineContainmentReconciler::Deps{
                .quarantine_store = &quarantine,
                .response_store = &responses,
                .registry = &registry,
                .metrics = &metrics,
                .audit_store = nullptr,
                .dispatch_fn = [this](const std::string& plugin, const std::string& action,
                                      const std::vector<std::string>& ids, const std::string& scope,
                                      const std::unordered_map<std::string, std::string>& params,
                                      const std::string& exec) {
                    return system_dispatch(plugin, action, ids, scope, params, exec);
                },
                .now_fn = {},
                // Test knobs: drive the apply -> poll -> status state machine in
                // milliseconds, not the production minutes.
                .min_reapply_interval_override = std::chrono::milliseconds(10),
                .response_wait_override = std::chrono::milliseconds(2000),
                .verify_grace_override = std::chrono::milliseconds(10),
            });
    }

    // server.cpp's tick site: the FencedLeaderOnly gate, then tick().
    bool leader_tick() {
        if (!leader_gate_permits<background_job_class("quarantine_reconciler.tick")>(&elector))
            return false;
        reconciler->tick();
        return true;
    }

    // Everything the transport received since the last call: the exact agent and command.
    std::vector<Sent> drain() {
        std::vector<Sent> out;
        for (auto& p : registry.drain_gateway_pending()) {
            Sent s{p.agent_id, p.cmd.plugin(), p.cmd.action(), {}};
            for (const auto& [k, v] : p.cmd.parameters())
                s.params[k] = v;
            out.push_back(std::move(s));
            sent_log.push_back(out.back());
        }
        return out;
    }

    void store_response(const std::string& command_id, const std::string& output) {
        StoredResponse sr;
        sr.instruction_id = command_id;
        sr.agent_id = kAgent;
        sr.status = 1; // SUCCESS
        sr.output = output;
        sr.plugin = "quarantine";
        responses.store(sr);
    }

    auto post(const std::string& whitelist = kWhitelist) {
        const std::string body = std::string(R"({"agent_id":")") + kAgent +
                                 R"(","reason":"6065","whitelist":")" + whitelist + R"("})";
        return sink.Post("/api/v1/quarantine", body, "application/json");
    }

    auto del() { return sink.Delete(std::string("/api/v1/quarantine/") + kAgent); }

    std::size_t quarantined_count() {
        auto list = quarantine.list_quarantined();
        REQUIRE(list.has_value());
        return list->size();
    }

    void clear_audits() {
        audits.clear();
        audit_actors.clear();
        audit_roles.clear();
    }
    // Every row carries `role` (the role the request was authorized as).
    bool every_audit_has_role(const std::string& role) const {
        if (audits.empty() || audits.size() != audit_roles.size())
            return false;
        for (const auto& r : audit_roles)
            if (r != role)
                return false;
        return true;
    }
    // Every row written, and the actor each names; `audits` and `audit_actors` stay index-aligned.
    bool every_audit_names(const std::string& user) const {
        if (audits.empty() || audits.size() != audit_actors.size())
            return false;
        for (const auto& a : audit_actors)
            if (a != user)
                return false;
        return true;
    }

    bool has_audit(const std::string& key) const {
        for (const auto& [k, d] : audits)
            if (k == key)
                return true;
        return false;
    }
    std::string audit_detail(const std::string& key) const {
        for (const auto& [k, d] : audits)
            if (k == key)
                return d;
        return {};
    }

    // A caller as the MCP surface derives it from the same session (principal, role,
    // effective-admin, deny-all exec_visible).
    DispatchCaller caller_for(const std::string& user, auth::Role role) const {
        auth::Session s;
        s.username = user;
        s.role = role;
        DispatchCaller c;
        c.principal = user;
        c.principal_role = auth::role_to_string(role);
        c.principal_is_admin = auth::effective_role(s) == auth::Role::admin;
        c.exec_visible = authz::deny_all();
        return c;
    }

    // Grants `user` Security:Execute through a management group ONLY: a custom role carrying
    // the permission, assigned to the user on a group containing kAgent, never globally.
    void grant_group_only_security_execute(const std::string& user) {
        REQUIRE(rbac.create_role({"SecurityExecutor6065", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"SecurityExecutor6065", "Security", "Execute", "allow"})
                    .has_value());
        ManagementGroup g;
        g.name = "Secops 6065";
        g.membership_type = "static";
        auto gid = mgmt.create_group(g);
        REQUIRE(gid.has_value());
        REQUIRE(mgmt.add_member(*gid, kAgent).has_value());
        REQUIRE(mgmt.assign_role({*gid, "user", user, "SecurityExecutor6065"}).has_value());
    }

    // Grants `user` Security:Execute GLOBALLY through a custom role (the account role stays
    // `user`: an RBAC grant is not the account role the dispatch gate's admin test reads).
    void grant_global_security_execute(const std::string& user) {
        REQUIRE(rbac.create_role({"SecurityExecutorGlobal6065", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"SecurityExecutorGlobal6065", "Security", "Execute", "allow"})
                    .has_value());
        REQUIRE(rbac.assign_role({"user", user, "SecurityExecutorGlobal6065"}).has_value());
    }
};

nlohmann::json err_of(const std::string& body) {
    auto j = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(j.is_discarded());
    return j.contains("error") && j["error"].is_object() ? j["error"] : j;
}

void settle() {
    // The reconciler's gates are steady_clock deadlines (10 ms test knobs above).
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
}

} // namespace

TEST_CASE("quarantine create gate (a): an admin cookie under RBAC off creates the record and the "
          "reconciler reaches exactly agent-1 with the stored whitelist, then one status",
          "[rest][quarantine][authz][dispatch][integration][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, create_gate_tpl);
    Rig rig(db.dsn());
    REQUIRE(rig.elector.try_acquire());
    rig.set_rbac(false);
    rig.as_admin("alice");

    auto res = rig.post();
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(rig.quarantined_count() == 1);
    CHECK(rig.has_audit("quarantine.enable/attempt"));
    CHECK(rig.has_audit("quarantine.enable/success"));
    CHECK_FALSE(rig.has_audit("quarantine.enable/denied"));

    // Tick 1: exactly one quarantine.quarantine, to agent-1 only, with the STORED whitelist.
    REQUIRE(rig.leader_tick());
    auto first = rig.drain();
    REQUIRE(first.size() == 1);
    CHECK(first[0].agent_id == kAgent);
    CHECK(first[0].plugin == "quarantine");
    CHECK(first[0].action == "quarantine");
    REQUIRE(first[0].params.size() == 1);
    CHECK(first[0].params.at("whitelist_ips") == kWhitelist);

    // The agent answers the apply; the next tick schedules the verify, the one after sends
    // exactly one quarantine.status.
    rig.store_response(rig.last_command_id, "status|quarantined|rules_applied|1");
    settle();
    REQUIRE(rig.leader_tick());
    CHECK(rig.drain().empty()); // polled the apply response; no dispatch yet
    settle();
    REQUIRE(rig.leader_tick());
    auto second = rig.drain();
    REQUIRE(second.size() == 1);
    CHECK(second[0].agent_id == kAgent);
    CHECK(second[0].plugin == "quarantine");
    CHECK(second[0].action == "status");

    // Across the whole scenario: exactly those two commands, nothing else, nobody else.
    REQUIRE(rig.sent_log.size() == 2);
    CHECK(rig.sent_log[0].action == "quarantine");
    CHECK(rig.sent_log[1].action == "status");
    for (const auto& s : rig.sent_log)
        CHECK(s.agent_id == kAgent);
}

TEST_CASE("quarantine create gate (b): a non-admin under RBAC off is refused approval_required, "
          "no record, and the reconciler reaches nobody",
          "[rest][quarantine][authz][dispatch][integration][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, create_gate_tpl);
    Rig rig(db.dsn());
    REQUIRE(rig.elector.try_acquire());
    rig.set_rbac(false);
    rig.as_user("bob");
    auto& denied = rig.metrics.counter("yuzu_server_dispatch_denied_total",
                                       {{"reason", "approval_required"}});
    const auto before = denied.value();

    auto res = rig.post();
    REQUIRE(res);
    CHECK(res->status == 403);
    const auto err = err_of(res->body);
    CHECK(err.value("message", std::string()).find("approval required for quarantine.quarantine") !=
          std::string::npos);
    CHECK_FALSE(err.contains("permission"));
    CHECK(err.contains("remediation"));
    CHECK(rig.audit_detail("quarantine.enable/denied") ==
          "reason=approval_required securable=Security");
    CHECK_FALSE(rig.has_audit("quarantine.enable/attempt"));
    CHECK(denied.value() == before + 1);

    CHECK(rig.quarantined_count() == 0);
    REQUIRE(rig.leader_tick());
    CHECK(rig.drain().empty());
    CHECK(rig.sent_log.empty());
}

TEST_CASE("quarantine create gate (c): RBAC on, a non-admin holding Security:Execute through a "
          "management group only is refused forbidden by the global binder, no record, no send",
          "[rest][quarantine][authz][dispatch][integration][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, create_gate_tpl);
    Rig rig(db.dsn());
    REQUIRE(rig.elector.try_acquire());
    rig.grant_group_only_security_execute("carol");
    rig.set_rbac(true);
    rig.as_user("carol");

    // Preconditions that make this case mean what it says: the scoped dimension ADMITS carol
    // for the device, the global dimension does not.
    REQUIRE(rig.rbac.check_scoped_permission("carol", "Security", "Execute", kAgent, &rig.mgmt));
    REQUIRE_FALSE(rig.rbac.check_permission("carol", "Security", "Execute"));

    auto res = rig.post();
    REQUIRE(res);
    CHECK(res->status == 403);
    const auto err = err_of(res->body);
    CHECK(err.value("message", std::string()) == "permission denied: Security:Execute");
    CHECK_FALSE(err.contains("permission"));
    CHECK(rig.audit_detail("quarantine.enable/denied") == "reason=forbidden securable=Security");
    CHECK_FALSE(rig.has_audit("quarantine.enable/attempt"));
    CHECK(rig.metrics.counter("yuzu_server_dispatch_denied_total", {{"reason", "forbidden"}})
              .value() == 1);

    CHECK(rig.quarantined_count() == 0);
    REQUIRE(rig.leader_tick());
    CHECK(rig.drain().empty());
}

TEST_CASE("quarantine create gate (d): RBAC on, an Administrator creates the record and the "
          "reconciler reaches exactly agent-1 with the stored whitelist",
          "[rest][quarantine][authz][dispatch][integration][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, create_gate_tpl);
    Rig rig(db.dsn());
    REQUIRE(rig.elector.try_acquire());
    REQUIRE(rig.rbac.assign_role({"user", "alice", "Administrator"}).has_value());
    rig.set_rbac(true);
    rig.as_admin("alice");

    auto res = rig.post();
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(rig.quarantined_count() == 1);

    REQUIRE(rig.leader_tick());
    auto sent = rig.drain();
    REQUIRE(sent.size() == 1);
    CHECK(sent[0].agent_id == kAgent);
    CHECK(sent[0].plugin == "quarantine");
    CHECK(sent[0].action == "quarantine");
    REQUIRE(sent[0].params.size() == 1);
    CHECK(sent[0].params.at("whitelist_ips") == kWhitelist);
}

TEST_CASE("quarantine create gate (e): REST and the closure MCP receives return the SAME "
          "DispatchDenial for the same caller shape",
          "[rest][quarantine][authz][dispatch][integration][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, create_gate_tpl);
    Rig rig(db.dsn());
    rig.grant_group_only_security_execute("carol");

    struct Shape {
        const char* label;
        bool rbac_on;
        std::string user;
        auth::Role role;
        const char* reason;
    };
    const std::vector<Shape> shapes = {
        {"non-admin, RBAC off", false, "bob", auth::Role::user, "approval_required"},
        {"group-only grant, RBAC on", true, "carol", auth::Role::user, "forbidden"},
    };
    for (const auto& shape : shapes) {
        CAPTURE(shape.label);
        rig.clear_audits();
        rig.set_rbac(shape.rbac_on);
        rig.as_user(shape.user);

        // A copy of the closure server.cpp binds to BOTH surfaces, called as MCP calls it.
        const auto mcp_view = rig.authorize_dispatch(rig.caller_for(shape.user, shape.role),
                                                     "quarantine", "quarantine");
        REQUIRE_FALSE(mcp_view.has_value());
        const auto& denial = mcp_view.error();
        CHECK(std::string(detail::to_string(denial.reason)) == shape.reason);

        // What the REST route reported for the same caller shape.
        auto res = rig.post();
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(rig.audit_detail("quarantine.enable/denied") ==
              "reason=" + std::string(detail::to_string(denial.reason)) +
                  " securable=" + denial.securable);
        CHECK(denial.securable == "Security");
        CHECK(denial.operation == authz::Operation::Execute);

        // And the shared text helper renders the two surfaces identically for it.
        const auto rest_text = describe_dispatch_denial(denial.reason, "quarantine", "quarantine",
                                                        denial, DenialSurface::kRest);
        const auto mcp_text = describe_dispatch_denial(denial.reason, "quarantine", "quarantine",
                                                       denial, DenialSurface::kMcp);
        CHECK(rest_text.message == mcp_text.message);
        CHECK(err_of(res->body).value("message", std::string()) == rest_text.message);
        CHECK(rig.quarantined_count() == 0);
    }
}

TEST_CASE("quarantine create gate (f): a non-leader replica ticks nothing even with a record "
          "present (the FencedLeaderOnly gate server.cpp applies)",
          "[rest][quarantine][authz][dispatch][integration][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, create_gate_tpl);
    Rig rig(db.dsn());
    rig.set_rbac(false);
    rig.as_admin("alice");
    {
        auto created = rig.post();
        REQUIRE(created);
        REQUIRE(created->status == 201);
    }
    REQUIRE(rig.quarantined_count() == 1);

    // `rig.elector` has not acquired; a second elector holds the lease.
    LeaderElector other(Rig::elector_cfg(db.dsn(), "holder-b"));
    REQUIRE(other.is_open());
    REQUIRE(other.try_acquire());
    REQUIRE_FALSE(rig.elector.try_acquire());

    CHECK_FALSE(rig.leader_tick());
    CHECK(rig.drain().empty());

    // Handover: once the other replica resigns, this one leads and the record is applied.
    other.resign();
    REQUIRE(rig.elector.try_acquire());
    REQUIRE(rig.leader_tick());
    auto sent = rig.drain();
    REQUIRE(sent.size() == 1);
    CHECK(sent[0].agent_id == kAgent);
    CHECK(sent[0].action == "quarantine");
}

TEST_CASE("quarantine create gate (g): RBAC on, a JIT-elevated administrator with no global "
          "Security:Execute grant of their own is refused forbidden, no record, no send",
          "[rest][quarantine][authz][dispatch][integration][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, create_gate_tpl);
    Rig rig(db.dsn());
    REQUIRE(rig.elector.try_acquire());
    rig.grant_group_only_security_execute("erin");
    rig.set_rbac(true);
    rig.as_jit_elevated_user("erin");

    // The fixture really is an effective administrator whose own grants are not global; the
    // scoped dimension still admits her for the device.
    REQUIRE(auth::effective_role(rig.make_session()) == auth::Role::admin);
    REQUIRE(rig.rbac.check_scoped_permission("erin", "Security", "Execute", kAgent, &rig.mgmt));
    REQUIRE_FALSE(rig.rbac.check_permission("erin", "Security", "Execute"));

    auto res = rig.post();
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(err_of(res->body).value("message", std::string()) == "permission denied: Security:Execute");
    CHECK(rig.audit_detail("quarantine.enable/denied") == "reason=forbidden securable=Security");
    CHECK_FALSE(rig.has_audit("quarantine.enable/attempt"));
    CHECK(rig.quarantined_count() == 0);
    REQUIRE(rig.leader_tick());
    CHECK(rig.drain().empty());
}

TEST_CASE("quarantine create gate (h): the admin test reads the ACCOUNT role, and JIT elevation "
          "counts as that role; an RBAC grant alone does not",
          "[rest][quarantine][authz][dispatch][integration][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, create_gate_tpl);
    Rig rig(db.dsn());
    REQUIRE(rig.elector.try_acquire());

    SECTION("RBAC on, global Security:Execute grant, account role user, not elevated: refused "
            "approval_required (an RBAC grant is not the account role)") {
        rig.grant_global_security_execute("frank");
        rig.set_rbac(true);
        rig.as_user("frank");
        REQUIRE(rig.rbac.check_permission("frank", "Security", "Execute"));
        REQUIRE(auth::effective_role(rig.make_session()) == auth::Role::user);

        auto res = rig.post();
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(rig.audit_detail("quarantine.enable/denied") ==
              "reason=approval_required securable=Security");
        CHECK_FALSE(rig.has_audit("quarantine.enable/attempt"));
        CHECK(rig.quarantined_count() == 0);
        REQUIRE(rig.leader_tick());
        CHECK(rig.drain().empty());
    }

    SECTION("RBAC on, the same global grant plus a live JIT elevation: admitted, and the "
            "reconciler reaches exactly agent-1 (principal_is_admin reads the EFFECTIVE role)") {
        rig.grant_global_security_execute("frank");
        rig.set_rbac(true);
        rig.as_jit_elevated_user("frank");
        REQUIRE(auth::effective_role(rig.make_session()) == auth::Role::admin);

        auto res = rig.post();
        REQUIRE(res);
        CHECK(res->status == 201);
        CHECK(rig.quarantined_count() == 1);
        REQUIRE(rig.leader_tick());
        auto sent = rig.drain();
        REQUIRE(sent.size() == 1);
        CHECK(sent[0].agent_id == kAgent);
    }

    SECTION("RBAC off (the default), a live JIT elevation, no grants of any kind: admitted "
            "(the binder is legacy-open and the elevated session is an effective admin)") {
        rig.set_rbac(false);
        rig.as_jit_elevated_user("frank");
        REQUIRE(auth::effective_role(rig.make_session()) == auth::Role::admin);

        auto res = rig.post();
        REQUIRE(res);
        CHECK(res->status == 201);
        CHECK(rig.quarantined_count() == 1);
    }
}

TEST_CASE("quarantine create gate (i): a degraded kill-switch read never refuses the protective "
          "quarantine pair, end to end through the route",
          "[rest][quarantine][authz][dispatch][integration][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, create_gate_tpl);
    Rig rig(db.dsn());
    REQUIRE(rig.elector.try_acquire());
    // nullopt = "killed for every OS OR the store is degraded" (the fail-closed collapse). For a
    // non-protective pair that is a KillSwitched refusal; quarantine.quarantine is protective, so
    // the callback must not even be consulted.
    int consulted = 0;
    rig.kill_switch = [&consulted](std::string_view, std::string_view)
        -> std::optional<std::unordered_set<std::string>> {
        ++consulted;
        return std::nullopt;
    };
    rig.set_rbac(false);
    rig.as_admin("alice");

    auto res = rig.post();
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(consulted == 0);
    CHECK_FALSE(rig.has_audit("quarantine.enable/denied"));
    CHECK(rig.quarantined_count() == 1);
    REQUIRE(rig.leader_tick());
    auto sent = rig.drain();
    REQUIRE(sent.size() == 1);
    CHECK(sent[0].agent_id == kAgent);
}

TEST_CASE("quarantine release gate (j): DELETE runs the same chokepoint for quarantine.unquarantine, "
          "so a caller who cannot create a record cannot end one",
          "[rest][quarantine][authz][dispatch][integration][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, create_gate_tpl);
    Rig rig(db.dsn());
    REQUIRE(rig.elector.try_acquire());
    rig.grant_global_security_execute("frank");
    // The administrator holds the same global grant (RBAC on needs an admin account role AND
    // the caller's own global Security:Execute grant).
    REQUIRE(rig.rbac.assign_role({"user", "alice", "SecurityExecutorGlobal6065"}).has_value());

    // An administrator creates the record; every section starts from one active record.
    rig.set_rbac(true);
    rig.as_admin("alice");
    {
        auto created = rig.post();
        REQUIRE(created);
        REQUIRE(created->status == 201);
        REQUIRE(rig.quarantined_count() == 1);
    }
    rig.clear_audits();

    SECTION("RBAC on, a non-administrator holding Security:Execute globally: refused "
            "approval_required, the record stays active, no attempt row") {
        rig.as_user("frank");
        auto& denied = rig.metrics.counter("yuzu_server_dispatch_denied_total",
                                           {{"reason", "approval_required"}});
        const auto before = denied.value();

        auto res = rig.del();
        REQUIRE(res);
        CHECK(res->status == 403);
        const auto err = err_of(res->body);
        CHECK(err.value("message", std::string()).find("approval required for quarantine.unquarantine") !=
              std::string::npos);
        CHECK_FALSE(err.contains("permission"));
        CHECK(err.contains("remediation"));
        CHECK(rig.audit_detail("quarantine.disable/denied") ==
              "reason=approval_required securable=Security");
        CHECK_FALSE(rig.has_audit("quarantine.disable/attempt"));
        CHECK_FALSE(rig.has_audit("quarantine.disable/success"));
        CHECK(denied.value() == before + 1);
        CHECK(rig.quarantined_count() == 1); // still contained
    }

    SECTION("RBAC on, a caller who holds Security:Execute only through a management group: "
            "passes the scoped gate, refused forbidden here, the record stays active") {
        rig.grant_group_only_security_execute("grace");
        rig.as_user("grace");
        auto res = rig.del();
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(rig.audit_detail("quarantine.disable/denied") ==
              "reason=forbidden securable=Security");
        CHECK(rig.quarantined_count() == 1);
        CHECK(rig.metrics.counter("yuzu_server_dispatch_denied_total", {{"reason", "forbidden"}})
                  .value() == 1);
    }

    SECTION("an administrator releases the record: attempt then success, no denied row") {
        rig.as_admin("alice");
        auto res = rig.del();
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(rig.has_audit("quarantine.disable/attempt"));
        CHECK(rig.has_audit("quarantine.disable/success"));
        CHECK_FALSE(rig.has_audit("quarantine.disable/denied"));
        CHECK(rig.quarantined_count() == 0);
    }

    SECTION("a degraded kill-switch read never refuses the release: quarantine.unquarantine is "
            "protective, so the callback is not even consulted (the emergency path)") {
        int consulted = 0;
        rig.kill_switch = [&consulted](std::string_view, std::string_view)
            -> std::optional<std::unordered_set<std::string>> {
            ++consulted;
            return std::nullopt;
        };
        rig.as_admin("alice");
        auto res = rig.del();
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(consulted == 0);
        CHECK_FALSE(rig.has_audit("quarantine.disable/denied"));
        CHECK(rig.quarantined_count() == 0);
    }

    SECTION("a JIT-elevated administrator who holds the global grant releases the record") {
        rig.as_jit_elevated_user("frank");
        REQUIRE(auth::effective_role(rig.make_session()) == auth::Role::admin);
        auto res = rig.del();
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(rig.quarantined_count() == 0);
    }
}

TEST_CASE("quarantine audit identity (k): every row the quarantine routes write names the session "
          "the route resolved, never a second resolution of the request",
          "[rest][quarantine][audit][integration][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, create_gate_tpl);
    Rig rig(db.dsn());
    REQUIRE(rig.elector.try_acquire());
    rig.set_rbac(false);
    rig.as_admin("alice");

    SECTION("POST: the audit write would re-resolve to another principal (a lapsed cookie falling "
            "through to a bearer token); attempt and success still name the session that created "
            "the record") {
        rig.audit_resolves_to = "bob";
        auto res = rig.post();
        REQUIRE(res);
        CHECK(res->status == 201);
        REQUIRE(rig.has_audit("quarantine.enable/attempt"));
        REQUIRE(rig.has_audit("quarantine.enable/success"));
        CHECK(rig.every_audit_names("alice"));
        auto list = rig.quarantine.list_quarantined();
        REQUIRE(list.has_value());
        REQUIRE(list->size() == 1);
        CHECK((*list)[0].quarantined_by == "alice"); // the record and its evidence agree
    }

    SECTION("DELETE: the same, for the release rows") {
        {
            auto created = rig.post();
            REQUIRE(created);
            REQUIRE(created->status == 201);
        }
        rig.clear_audits();
        rig.audit_resolves_to = "bob";
        auto res = rig.del();
        REQUIRE(res);
        CHECK(res->status == 200);
        REQUIRE(rig.has_audit("quarantine.disable/attempt"));
        REQUIRE(rig.has_audit("quarantine.disable/success"));
        CHECK(rig.every_audit_names("alice"));
    }

    SECTION("a refusal row names the session too (the chokepoint denial)") {
        rig.as_user("frank");
        rig.audit_resolves_to = "bob";
        auto res = rig.post();
        REQUIRE(res);
        CHECK(res->status == 403);
        REQUIRE(rig.has_audit("quarantine.enable/denied"));
        CHECK(rig.every_audit_names("frank"));
        CHECK(rig.quarantined_count() == 0);
    }

    SECTION("a row written before the second resolution (a bad whitelist) names the session too") {
        rig.audit_resolves_to = "bob";
        auto res = rig.post("not-an-address!");
        REQUIRE(res);
        CHECK(res->status == 400);
        REQUIRE(rig.has_audit("quarantine.enable/failure"));
        CHECK(rig.every_audit_names("alice"));
        CHECK(rig.quarantined_count() == 0);
    }

    SECTION("the rows carry the role of the SECOND resolution, the one the request was "
            "authorized as: the same user, JIT-elevated between the two look-ups") {
        rig.as_user("frank");
        rig.auth_user_queue = {"frank", "frank"};
        rig.auth_elevated_queue = {false, true};
        auto res = rig.post();
        REQUIRE(res);
        CHECK(res->status == 201); // authorized as an effective administrator
        REQUIRE(rig.has_audit("quarantine.enable/attempt"));
        REQUIRE(rig.has_audit("quarantine.enable/success"));
        CHECK(rig.every_audit_names("frank"));
        CHECK(rig.every_audit_has_role("admin"));
    }

    SECTION("POST: a second resolution that names a different principal ends the request at 401 "
            "before any record, attempt row or dispatch; the refusal row names the first principal") {
        rig.auth_user_queue = {"alice", "bob"};
        auto res = rig.post();
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK(rig.quarantined_count() == 0);
        CHECK_FALSE(rig.has_audit("quarantine.enable/attempt"));
        CHECK_FALSE(rig.has_audit("quarantine.enable/success"));
        CHECK(rig.audit_detail("quarantine.enable/denied") ==
              "authenticated principal changed during the request now=bob");
        CHECK(rig.every_audit_names("alice"));
        REQUIRE(rig.leader_tick());
        CHECK(rig.drain().empty());
    }

    SECTION("DELETE: the same, and the record stays active") {
        {
            auto created = rig.post();
            REQUIRE(created);
            REQUIRE(created->status == 201);
        }
        rig.clear_audits();
        rig.auth_user_queue = {"alice", "bob"};
        auto res = rig.del();
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK(rig.quarantined_count() == 1);
        CHECK_FALSE(rig.has_audit("quarantine.disable/attempt"));
        CHECK_FALSE(rig.has_audit("quarantine.disable/success"));
        CHECK(rig.audit_detail("quarantine.disable/denied") ==
              "authenticated principal changed during the request now=bob");
        CHECK(rig.every_audit_names("alice"));
    }
}

TEST_CASE("quarantine audit identity (l): an unwired session audit writer answers 500 on both "
          "routes, never falling back to the re-resolving writer, and changes nothing",
          "[rest][quarantine][audit][integration][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, create_gate_tpl);
    Rig rig(db.dsn(), /*wire_session_writer=*/false);
    rig.set_rbac(false);
    rig.as_admin("alice");

    auto created = rig.post();
    REQUIRE(created);
    CHECK(created->status == 500);
    CHECK(rig.quarantined_count() == 0);
    CHECK(rig.audit_detail("quarantine.enable/failure") == "audit identity writer not configured");
    CHECK_FALSE(rig.has_audit("quarantine.enable/attempt"));

    // Seed a record directly so DELETE has something to (not) release.
    REQUIRE(rig.quarantine.quarantine_device(kAgent, "alice", "seed", kWhitelist).has_value());
    auto released = rig.del();
    REQUIRE(released);
    CHECK(released->status == 500);
    CHECK(rig.quarantined_count() == 1);
    CHECK(rig.audit_detail("quarantine.disable/failure") == "audit identity writer not configured");
    CHECK_FALSE(rig.has_audit("quarantine.disable/attempt"));
}
