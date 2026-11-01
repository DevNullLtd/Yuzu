#include "command_v1_routes.hpp"

#include "authz_model.hpp"               // authz::to_string(Operation)
#include "dispatch_denial_text.hpp"      // describe_dispatch_denial
#include "dispatch_destructive_gate.hpp" // evaluate_destructive_targeting / confine_destructive_targets
#include "http_route_sink.hpp"
#include "mcp_input_bounds.hpp"     // kExecInstr* bounds + check_exec_instruction_shape
#include "mcp_jsonrpc.hpp"          // mcp::json_exceeds_depth / kMcpMaxJsonDepth (#2437 depth guard)
#include "rest_a4_envelope_http.hpp" // detail::a4_denial / ensure_correlation_id
#include "rest_audit.hpp"           // detail::emit_behavioral_audit
#include "sensitive_instruction_params.hpp" // redact_sensitive_instruction_params
#include "web_utils.hpp"            // audit_token (CWE-117)

#include <yuzu/protective_actions.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <exception>
#include <string>
#include <utility>

namespace yuzu::server::command_v1 {

namespace {

constexpr std::int64_t kRetryAfterMs = 5000;

[[nodiscard]] std::string lowered(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

[[nodiscard]] bool is_targeting_reason(std::string_view reason) {
    for (const auto r : kTargetingShapeReasons)
        if (r == reason)
            return true;
    return false;
}

void count_target_rejected(yuzu::MetricsRegistry* metrics, std::string_view reason) {
    if (metrics == nullptr)
        return;
    try {
        metrics
            ->counter("yuzu_server_dispatch_target_rejected_total",
                      {{"route", "command_v1"}, {"reason", std::string(reason)}})
            .increment();
    } catch (const std::exception& e) {
        spdlog::error("dispatch_target_rejected_total counter threw (reason={}): {}", reason,
                      e.what());
    } catch (...) {
        spdlog::error("dispatch_target_rejected_total counter threw (reason={})", reason);
    }
}

void count_bookkeeping_failed(yuzu::MetricsRegistry* metrics, const char* op) {
    if (metrics == nullptr)
        return;
    try {
        metrics
            ->counter("yuzu_exec_tracker_bookkeeping_failed_total",
                      {{"op", op}, {"surface", "rest"}})
            .increment();
    } catch (...) { // NOLINT(bugprone-empty-catch)
        // observability must never fail the request
    }
}

/// The A4 envelope plus the machine-readable `reason` (and any extra string/int fields) inside
/// the `error` object. One builder, so every refusal of this route has the one shape.
[[nodiscard]] std::string error_body(httplib::Response& res, int status, std::string_view message,
                                     std::string_view reason,
                                     const detail::A4ErrorOpts& opts = {},
                                     const nlohmann::json& extra = nlohmann::json::object()) {
    auto j = nlohmann::json::parse(detail::a4_denial(res, status, message, opts), nullptr, false);
    if (j.is_discarded() || !j.contains("error") || !j["error"].is_object())
        return detail::a4_denial(res, status, message, opts); // never reached: the builder is ours
    if (!reason.empty())
        j["error"]["reason"] = std::string(reason);
    for (const auto& [k, v] : extra.items())
        j["error"][k] = v;
    return j.dump();
}

[[nodiscard]] Deps::AuditFn bind_audit(const Deps& d, const auth::Session& session) {
    // The effective role is read once per binding, as AuthRoutes' own binder does.
    std::string role = auth::role_to_string(auth::effective_role(session));
    return [writer = d.audit_as_session, session, role = std::move(role)](
               const httplib::Request& req, const std::string& action, const std::string& result,
               const std::string& target_type, const std::string& target_id,
               const std::string& detail) {
        return writer(req, session, role, action, result, target_type, target_id, detail);
    };
}

/// Everything after the gate. `first` is the session the route authenticated at entry.
void handle_post(const Deps& d, const auth::Session& first, const httplib::Request& req,
                 httplib::Response& res) {
    const std::string cid = detail::ensure_correlation_id(res);

    // The second resolution must name the SAME principal as the first: a request whose credentials
    // resolve to two principals was gated as one and would be attributed to, and dispatched as, the
    // other.
    auto resolved = d.auth_fn(req, res);
    if (!resolved)
        return;
    const auth::Session& session = *resolved;
    if (session.username != first.username) {
        res.status = 401;
        res.set_content(error_body(res, 401, "the authenticated principal changed during the request",
                                   "principal_changed", {.remediation = "retry the request"}),
                        "application/json");
        const auto audit_first = bind_audit(d, first);
        (void)detail::emit_behavioral_audit(
            audit_first, req, res, "command.dispatch", "denied", "command", "",
            "reason=principal_changed now=" + audit_token(session.username) +
                " correlation_id=" + cid);
        return;
    }
    const Deps::AuditFn audit = bind_audit(d, session);

    // What was being attempted, once known, for every row after the body parses.
    std::string what;
    const auto detail_of = [&](std::string_view reason) {
        std::string out = "reason=" + std::string(reason);
        if (!what.empty())
            out += " " + what;
        return out + " correlation_id=" + cid;
    };
    // A refusal: the A4 body with `reason`, a `denied` row, and (for the closed targeting set) the
    // counter. The row's persist outcome does not change the refusal's status (a correct 400 must
    // not become an outage); emit_behavioral_audit sets Sec-Audit-Failed when it fails.
    const auto refuse = [&](int status, std::string_view reason, std::string_view message,
                            std::string_view remediation = {}) {
        if (is_targeting_reason(reason) || reason == kReasonDestructiveUntargeted ||
            reason == kReasonForensicUntargeted || reason == kReasonDestructiveNoVisibleTarget ||
            reason == kReasonBodyType)
            count_target_rejected(d.metrics, reason);
        (void)detail::emit_behavioral_audit(audit, req, res, "command.dispatch", "denied",
                                            "command", "", detail_of(reason));
        res.status = status;
        res.set_content(error_body(res, status, message, reason, {.remediation = remediation}),
                        "application/json");
    };

    // #2437-class guard: the raw-text depth check BEFORE any parse of this body.
    if (mcp::json_exceeds_depth(req.body, mcp::kMcpMaxJsonDepth)) {
        refuse(400, "body_depth", "request body nests too deeply",
               "flatten the request body and re-send");
        return;
    }
    // Parsed with allow_exceptions=false: a parse failure (or std::bad_alloc) is a refusal here,
    // never a body that continues as "named no target" and broadcasts.
    const auto body = nlohmann::json::parse(req.body, nullptr, /*allow_exceptions=*/false);
    if (!body.is_object()) {
        refuse(400, kReasonBodyType, "request body must be a JSON object");
        return;
    }
    if (auto bv = check_command_v1_request(body)) {
        refuse(400, bv->reason, bv->message, "correct the request to the documented shape and re-send");
        return;
    }

    // Agent plugins register actions in lowercase and match case-sensitively; normalise as MCP does.
    const std::string plugin = lowered(body["plugin"].get<std::string>());
    const std::string action = lowered(body["action"].get<std::string>());
    what = audit_token(plugin) + ":" + audit_token(action);

    std::unordered_map<std::string, std::string> params;
    if (body.contains("params"))
        for (const auto& [k, v] : body["params"].items())
            params[k] = v.is_string() ? v.get<std::string>() : v.dump();

    std::vector<std::string> agent_ids;
    if (body.contains("agent_ids"))
        for (const auto& v : body["agent_ids"])
            agent_ids.push_back(v.get<std::string>());
    std::string scope = body.contains("scope") ? body["scope"].get<std::string>() : std::string{};

    // An omitted target is the fleet; a SUPPLIED one that resolved to nothing is never widened.
    // check_command_v1_request already refuses those shapes, so this is the second line of defence
    // at the one place a bypass would turn a specific-looking target list into the whole fleet.
    if (scope.empty() && agent_ids.empty()) {
        if (targeting_supplied(body)) {
            refuse(400, body.contains("agent_ids") ? kReasonAgentIdsEmpty : kReasonScopeEmpty,
                   "a targeting argument was supplied but resolved to no target; omit it entirely "
                   "to target all agents");
            return;
        }
        scope = std::string(kBroadcastScope);
    }

    // Destructive / Forensics targeting (#3685): ONE decision, shared with /api/command and MCP.
    // No `default:`: a new verdict is a build failure here, not a silent fall-through.
    const auto gate = evaluate_destructive_targeting(d.classify_fn(plugin, action),
                                                     /*valid_nonempty_agent_ids=*/!agent_ids.empty(),
                                                     /*scope_key_present=*/!scope.empty(),
                                                     /*agent_id_count=*/agent_ids.size());
    switch (gate.verdict) {
    case DestructiveTargetingVerdict::NotDestructive:
        break;
    case DestructiveTargetingVerdict::ClassifyMiss:
        // The dispatch-chokepoint dry run below denies a miss locally, with the discriminated
        // reason; nothing of its own to do here (MCP's Policy B).
        break;
    case DestructiveTargetingVerdict::Targeted:
    case DestructiveTargetingVerdict::RefuseUntargeted: {
        const auto& cap = *gate.capability;
        // The pair's own securable FIRST (403 before 400), as /api/command does: for the rows whose
        // securable is not Execution this is real elevation.
        if (!d.perm_fn(req, res, std::string(cap.securable),
                       std::string(authz::to_string(cap.operation))))
            return;
        if (gate.verdict == DestructiveTargetingVerdict::RefuseUntargeted) {
            refuse(400, gate.refusal_reason, gate.refusal_message,
                   remediation_for_refusal_reason(gate.refusal_reason));
            return;
        }
        // Confine to the caller's visible agents. FAIL CLOSED: an unwired or degraded read is
        // "none visible", the opposite of authz::VisibleSet's nullopt. An id outside the set is
        // dropped silently (it must not disclose that the device exists).
        std::optional<std::vector<std::string>> visible;
        if (d.visible_agents_fn)
            visible = d.visible_agents_fn(session.username);
        agent_ids = confine_destructive_targets(agent_ids, DestructiveVisibleAgents{std::move(visible)});
        if (agent_ids.empty()) {
            refuse(404, kReasonDestructiveNoVisibleTarget, kDestructiveNoVisibleAgentMessage);
            return;
        }
        break;
    }
    }

    // The caller: identity AND the real principal_is_admin / exec_visible (service-scoped and
    // engine principals included). approval_provenance stays None: REST has no ticket flow.
    const DispatchCaller caller = d.derive_caller_fn(session);

    // The dispatch chokepoint's dry run (classify + authorize + kill switch), so a denial is a
    // discriminated refusal rather than an ambiguous zero-reach.
    if (const auto decision = d.authorize_dispatch_fn(caller, plugin, action); !decision) {
        const auto& denial = decision.error();
        const std::string_view reason = detail::to_string(denial.reason);
        auto text = describe_dispatch_denial(denial.reason, plugin, action, denial,
                                             DenialSurface::kRest);
        int status = 500;
        switch (text.cls) {
        case DispatchDenialClass::kInvalidParams:
            status = 400;
            break;
        case DispatchDenialClass::kPermissionDenied:
            status = 403;
            break;
        case DispatchDenialClass::kInternal:
            status = 500;
            break;
        }
        if (denial.reason == detail::DispatchDenialReason::ApprovalRequired)
            text.remediation = "dispatch as an administrator, or run this action through "
                               "POST /api/instructions/{id}/execute, which supports the approval "
                               "workflow";
        spdlog::warn("dispatch denied: {} reason={} securable={} caller={}", what, reason,
                     audit_token(denial.securable), audit_token(session.username));
        if (d.metrics != nullptr) {
            try {
                d.metrics
                    ->counter("yuzu_server_dispatch_denied_total", {{"reason", std::string(reason)}})
                    .increment();
            } catch (...) { // NOLINT(bugprone-empty-catch)
            }
        }
        // No `.permission`: a chokepoint denial (approval, identity, kill switch) is not cured by
        // granting one securable, so the field would claim a false self-remediation.
        refuse(status, reason, text.message, text.remediation);
        return;
    }

    // Fail-closed `requested` row BEFORE the dispatch (ADR-0033 section 9): no durable evidence,
    // no effect.
    {
        const auto arm = classify_dispatch_arm(!agent_ids.empty(), scope);
        const std::string requested = what + " arm=" + std::string(dispatch_arm_label(arm)) +
                                      " ids=" + std::to_string(agent_ids.size()) +
                                      " correlation_id=" + cid;
        if (!detail::emit_behavioral_audit(audit, req, res, "command.dispatch", "requested",
                                           "command", "", requested)) {
            res.status = 503;
            res.set_content(error_body(res, 503,
                                       "audit subsystem unavailable; refusing to dispatch without "
                                       "durable evidence",
                                       "audit_unavailable",
                                       {.retry_after_ms = kRetryAfterMs,
                                        .remediation = "retry the request"}),
                            "application/json");
            return;
        }
    }

    std::string execution_id;
    if (d.execution.create) {
        // The port may throw (a pool or driver fault). The `requested` row is already written
        // and nothing has been dispatched, so a throw answers 503 after a `failure` row rather
        // than unwinding with no outcome row.
        std::expected<std::string, std::string> created;
        bool create_threw = false;
        try {
            created = d.execution.create(
                session.username, scope,
                nlohmann::json(redact_sensitive_instruction_params(params)).dump());
        } catch (const std::exception& e) {
            spdlog::error("POST /api/v1/commands: create_execution threw: {}", e.what());
            create_threw = true;
        } catch (...) {
            spdlog::error("POST /api/v1/commands: create_execution threw an unknown exception");
            create_threw = true;
        }
        if (create_threw) {
            (void)detail::emit_behavioral_audit(audit, req, res, "command.dispatch", "failure",
                                                "command", "",
                                                "reason=execution_record_exception " + what +
                                                    " correlation_id=" + cid);
            res.status = 503;
            res.set_content(error_body(res, 503,
                                       "execution history unavailable: nothing was dispatched",
                                       "execution_record_unavailable",
                                       {.retry_after_ms = kRetryAfterMs,
                                        .remediation = "retry the request"}),
                            "application/json");
            return;
        }
        if (created.has_value()) {
            execution_id = *created;
        } else {
            spdlog::warn("POST /api/v1/commands: create_execution failed ({}); dispatching with "
                         "an empty execution_id principal={} command={}",
                         created.error(), audit_token(session.username), what);
        }
    }
    const auto cancel_execution = [&] {
        if (execution_id.empty() || !d.execution.mark_cancelled)
            return;
        if (!d.execution.mark_cancelled(execution_id, session.username)) {
            spdlog::error("POST /api/v1/commands: mark_cancelled failed for execution_id={}",
                          execution_id);
            count_bookkeeping_failed(d.metrics, "mark_cancelled");
        }
    };

    ConfinedDispatchOutcome outcome;
    bool threw = false;
    try {
        outcome = d.dispatch_fn(plugin, action, agent_ids, scope, params, execution_id, caller);
    } catch (const std::exception& e) {
        spdlog::error("POST /api/v1/commands: dispatch failed: {}", e.what());
        threw = true;
    } catch (...) {
        spdlog::error("POST /api/v1/commands: dispatch failed: unknown exception");
        threw = true;
    }
    if (threw) {
        // The execution row is deliberately NOT cancelled (up8-3 / sg-5): whether any agent
        // already received the command is unknown, and a `cancelled` row with agents_targeted 0
        // would tell every reader that nothing was sent. Left `running`, a response from any agent
        // that did receive it is still recorded, and the stuck-execution reaper closes the row
        // only when no agent ever answered. The tracker has no `failed` execution status.
        (void)detail::emit_behavioral_audit(audit, req, res, "command.dispatch", "failure",
                                            "command", "",
                                            "reason=dispatch_exception " + what +
                                                " execution_id=" + audit_token(execution_id) +
                                                " correlation_id=" + cid);
        // No retry hint: whether any agent received the command is unknown, and a blind retry
        // could dispatch it twice.
        res.status = 500;
        res.set_content(
            error_body(res, 500, "dispatch failed", "dispatch_exception",
                       {.remediation =
                            execution_id.empty()
                                ? "the dispatch failed part-way and some agents may already have "
                                  "received the command; no execution record was created, so "
                                  "confirm on the devices before sending it again"
                                : "the dispatch failed part-way and some agents may already have "
                                  "received the command; the execution was left running, not "
                                  "cancelled, so results from any agent that did receive it are "
                                  "still recorded against it: check its per-agent results before "
                                  "sending it again"},
                       nlohmann::json{{"execution_id", execution_id}}),
            "application/json");
        return;
    }

    if (outcome.sent == 0) {
        cancel_execution();
        const auto cause = classify_zero_reach(outcome, yuzu::protective::is_protective_action(plugin, action));
        const auto reply = zero_reach_reply(cause, outcome.scope_parse_error.value_or(std::string{}));
        (void)detail::emit_behavioral_audit(
            audit, req, res, "command.dispatch", "failure", "command", outcome.command_id,
            detail_of(reply.reason) + " execution_id=" + audit_token(execution_id));
        detail::A4ErrorOpts opts;
        opts.retry_after_ms = reply.retry_after_ms;
        opts.remediation = reply.remediation;
        nlohmann::json extra{{"command_id", outcome.command_id},
                             {"execution_id", execution_id},
                             {"agents_reached", 0},
                             {"agents_quarantined", outcome.denied_quarantined_count},
                             {"agents_unknown_plugin", outcome.unknown_plugin_count},
                             {"agents_kill_switched_os", outcome.kill_switched_os_count}};
        res.status = reply.status;
        res.set_content(error_body(res, reply.status, reply.message, reply.reason, opts, extra),
                        "application/json");
        return;
    }

    if (!execution_id.empty() && d.execution.set_targeted &&
        !d.execution.set_targeted(execution_id, outcome.sent)) {
        spdlog::error("POST /api/v1/commands: set_agents_targeted failed for execution_id={}",
                      execution_id);
        count_bookkeeping_failed(d.metrics, "set_agents_targeted");
    }
    // The `requested` row is the fail-closed evidence; this outcome row is best effort (the
    // dispatch cannot be undone), and the helper sets Sec-Audit-Failed if it is lost.
    (void)detail::emit_behavioral_audit(
        audit, req, res, "command.dispatch", "success", "command", outcome.command_id,
        what + " -> " + std::to_string(outcome.sent) + " agent(s) execution_id=" +
            audit_token(execution_id) + " correlation_id=" + cid);
    // The legacy `POST /api/command` event, same attributes and payload (command_routes.cpp).
    // Best effort, after the effect and its evidence row: it can never change the answer.
    emit_event_guarded(bind_event_emit(d.emit_event_fn, req, d.metrics), "command.dispatched",
                       nlohmann::json{{"target_count", outcome.sent}},
                       nlohmann::json{{"plugin", plugin},
                                      {"action", action},
                                      {"command_id", outcome.command_id},
                                      {"scope", scope}});

    nlohmann::json data{{"command_id", outcome.command_id},
                        {"execution_id", execution_id},
                        {"agents_reached", outcome.sent},
                        {"plugin", plugin},
                        {"action", action},
                        {"withheld_quarantined", outcome.denied_quarantined_count},
                        {"withheld_unknown_plugin", outcome.unknown_plugin_count},
                        {"withheld_kill_switched_os", outcome.kill_switched_os_count}};
    res.status = 202; // accepted: collect via the execution (GET /api/v1/executions/{id})
    res.set_content(nlohmann::json({{"data", std::move(data)}, {"meta", {{"api_version", "v1"}}}}).dump(),
                    "application/json");
}

[[nodiscard]] bool fully_wired(const Deps& d) {
    return d.auth_fn && d.perm_fn && d.audit_as_session && d.classify_fn &&
           d.authorize_dispatch_fn && d.derive_caller_fn;
}

} // namespace

std::optional<BoundViolation> check_command_v1_request(const nlohmann::json& body) {
    if (!body.is_object())
        return BoundViolation{kReasonBodyType.data(), "request body must be a JSON object"};
    // A field this route does not take is refused, never ignored: `stagger` and `delay` of the
    // legacy route have no effect here, and a caller must not believe a command was held.
    for (const auto& [key, value] : body.items()) {
        (void)value;
        bool known = false;
        for (const auto allowed : kAllowedFields)
            known = known || allowed == key;
        if (!known)
            return BoundViolation{kReasonUnknownField.data(),
                                  "the request carries a field this route does not accept; the "
                                  "accepted fields are plugin, action, params, agent_ids, scope"};
    }
    // `params` is an object or absent. MCP ignores a non-object silently; a REST caller who sent a
    // string or an array would dispatch without the parameters they believed they set.
    if (body.contains("params") && !body["params"].is_object())
        return BoundViolation{kReasonParamsType.data(), "params must be a JSON object"};

    if (auto v = mcp::check_exec_instruction_shape(body))
        return v; // ident_empty, param_count, param_key_len, then the shared targeting shape

    constexpr auto ident_max = mcp::kExecInstrIdentMaxLen;
    if (body["plugin"].get_ref<const std::string&>().size() > ident_max ||
        body["action"].get_ref<const std::string&>().size() > ident_max)
        return BoundViolation{"ident_len", "plugin and action must each be at most " +
                                               std::to_string(ident_max) + " bytes"};
    if (body.contains("scope") && body["scope"].get_ref<const std::string&>().size() >
                                      mcp::kExecInstrScopeMaxLen)
        return BoundViolation{"scope_len", "scope must be at most " +
                                               std::to_string(mcp::kExecInstrScopeMaxLen) + " bytes"};
    if (body.contains("params")) {
        for (const auto& [k, v] : body["params"].items()) {
            (void)k;
            // Measure what the handler stores: a non-string value is dumped to text, and the dump
            // is what reaches the agent.
            const std::size_t vlen =
                v.is_string() ? v.get_ref<const std::string&>().size() : v.dump().size();
            if (vlen > mcp::kExecInstrParamValueMaxLen)
                return BoundViolation{"param_value_len",
                                      "a params value exceeds " +
                                          std::to_string(mcp::kExecInstrParamValueMaxLen) + " bytes"};
        }
    }
    if (body.contains("agent_ids")) {
        const auto& ids = body["agent_ids"];
        if (ids.size() > mcp::kExecInstrAgentIdsMaxItems)
            return BoundViolation{"agent_ids_count", "agent_ids must have at most " +
                                                         std::to_string(mcp::kExecInstrAgentIdsMaxItems) +
                                                         " entries"};
        for (const auto& id : ids)
            if (id.get_ref<const std::string&>().size() > ident_max)
                return BoundViolation{"agent_id_len", "an agent_ids entry exceeds " +
                                                          std::to_string(ident_max) + " bytes"};
    }
    return std::nullopt;
}

ZeroReachReply zero_reach_reply(ZeroReachCause cause, std::string_view scope_error) {
    const std::string token(zero_reach_token(cause));
    ZeroReachReply r{503, zero_reach_token(cause), std::nullopt, {}, {}};
    if (zero_reach_retryable(cause))
        r.retry_after_ms = kRetryAfterMs;
    switch (cause) {
    case ZeroReachCause::InvalidScope:
        r.status = 400;
        r.message = "No agents reached: the scope expression could not be parsed (" +
                    std::string(scope_error) +
                    "). This is a caller error, not a fleet-state fact.";
        r.remediation = "fix the scope expression and resubmit; retrying the same scope will not help";
        break;
    case ZeroReachCause::ContainmentUnreadable:
        r.status = 503;
        r.message = "No agents reached: the quarantine containment gate's state is unreadable, so "
                    "dispatch is failing closed rather than guessing who is quarantined.";
        r.remediation = "retry after the retry_after_ms interval; the gate recovers once the "
                        "containment store is reachable again";
        break;
    case ZeroReachCause::RouteUnreadable:
        r.status = 503;
        r.message = "No agents reached: the gateway routing directory could not be read for one or "
                    "more targets, so dispatch to them was withheld rather than guessing where to "
                    "route.";
        r.remediation = "retry after the retry_after_ms interval";
        break;
    case ZeroReachCause::OsGateUnreadable:
        r.status = 503;
        r.message = "No agents reached: agent presence could not be read while a per-OS kill "
                    "switch is set, so dispatch is failing closed.";
        r.remediation = "retry after the retry_after_ms interval";
        break;
    case ZeroReachCause::Quarantined:
        r.status = 409;
        r.message = "No agents reached: every target was withheld by the quarantine containment "
                    "gate. This is a policy denial, not unreachability.";
        r.remediation = "release the device (DELETE /api/v1/quarantine) or check its quarantine "
                        "status before retrying; retrying alone will not help";
        break;
    case ZeroReachCause::PluginNotFound:
        r.status = 422;
        r.message = "No agents reached: the dispatched plugin is not in any target agent's reported "
                    "inventory, so the command was withheld before dispatch.";
        r.remediation = "check the plugin name, or confirm the plugin is installed on the targets; "
                        "retrying alone will not help";
        break;
    case ZeroReachCause::KillSwitchedOs:
        r.status = 403;
        r.message = "No agents reached: every target runs an OS for which this plugin action is "
                    "switched off by a per-OS kill switch, so the command was withheld before "
                    "dispatch.";
        r.remediation = "an operator must re-enable the action for that OS before it can dispatch; "
                        "retrying alone will not help";
        break;
    case ZeroReachCause::Generic:
        r.status = 503;
        r.message = "No agents reached: every target was unreachable, or the dispatch was refused "
                    "at the final approval check.";
        r.remediation = "an offline device may reconnect: retry after the retry_after_ms interval. "
                        "An approval refusal is permanent and retrying will not help";
        break;
    }
    return r;
}

void register_command_v1_routes(HttpRouteSink& sink, Deps deps) {
    sink.Post("/api/v1/commands", [deps = std::move(deps)](const httplib::Request& req,
                                                           httplib::Response& res) {
        // An unwired dependency is a misconfiguration and FAILS CLOSED (500): never a gate-less
        // dispatch. The session writer is checked here with the rest, so no row is ever written
        // through the re-resolving writer for a request this route accepts.
        if (!fully_wired(deps)) {
            res.status = 500;
            res.set_content(error_body(res, 500, "command dispatch is not configured",
                                       "not_configured"),
                            "application/json");
            if (deps.audit_fn)
                (void)deps.audit_fn(req, "command.dispatch", "failure", "command", "",
                                    "command dispatch is not configured");
            return;
        }
        // Authenticate first (401 before any body work), then the gate. This is the first gate.
        const auto first = deps.auth_fn(req, res);
        if (!first)
            return;
        if (!deps.perm_fn(req, res, "Execution", "Execute"))
            return;
        if (!deps.dispatch_fn) {
            res.status = 503;
            res.set_content(error_body(res, 503, "command dispatch unavailable", "dispatch_unavailable",
                                       {.retry_after_ms = kRetryAfterMs}),
                            "application/json");
            return;
        }
        handle_post(deps, *first, req, res);
    });
}

} // namespace yuzu::server::command_v1
