#include "instruction_execute.hpp"

#include "dispatch_denial_text.hpp"
#include "dispatch_destructive_gate.hpp"
#include "dispatch_send_progress.hpp"
#include "dispatch_target_shape.hpp"
#include "rest_a4_envelope.hpp" // detail::make_correlation_id
#include "sensitive_instruction_params.hpp"

#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>
#include <yuzu/protective_actions.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <format>

namespace yuzu::server::instruction_execute {

namespace {

constexpr int kRetryAfterMs = 5000;

/// A kMisconfigured, kClassifierUnavailable or kApprovalUnavailable refusal is a SERVER defect (a
/// required port was never wired at boot): it does not clear by itself, so it carries NO retry
/// hint (`retry_after_ms` stays null) and says so.
constexpr std::string_view kMisconfiguredRemediation =
    "this is a server configuration defect and retrying will not help; report it to the server "
    "operator";

/// An audit hook that throws (bad_alloc class) must not turn a refusal into a 500 or, worse,
/// skip the fail-closed gate: a throw reads as "did not persist".
bool safe_audit(const AuditHook& hook, std::string_view result, const std::string& detail) noexcept {
    if (!hook)
        return true; // audit-off mode (unit harness); production always wires it
    try {
        return hook(result, detail);
    } catch (...) {
        // Silent here would hide the one signal that an audit row was lost to a throw (the
        // caller sees only "did not persist"). Mirrors rest_audit.hpp's try_persist_audit.
        try {
            spdlog::error("instruction.execute audit hook threw (result '{}'); the row is treated "
                          "as not persisted",
                          ::yuzu::log_token(std::string(result)));
        } catch (...) { // NOLINT(bugprone-empty-catch)
        }
        return false;
    }
}

/// Observability must never fail a request. The label vector is built INSIDE the try (the labels
/// arrive as string_views, and no call site builds a std::string just to pass one: a reason that
/// is already a string_view or a literal is passed as is, the route through route_label), so a
/// bad_alloc building them is swallowed here instead of unwinding out of a caller that is
/// deliberately mid-recovery. The one allocation left at a call site is a reason that was already
/// a std::string before the call (the chokepoint denial's), which is only viewed, not copied.
using LabelViews = std::initializer_list<std::pair<std::string_view, std::string_view>>;
void bump(const Ports& ports, const char* family, LabelViews labels) noexcept {
    if (!ports.metrics)
        return;
    try {
        yuzu::Labels built;
        built.reserve(labels.size());
        for (const auto& [k, v] : labels)
            built.emplace_back(std::string(k), std::string(v));
        ports.metrics->counter(family, std::move(built)).increment();
    } catch (...) { // NOLINT(bugprone-empty-catch)
    }
}

/// The trailing token every row of one call carries (command_v1_routes.cpp's spelling and
/// position), on a `log_token`-cleaned value.
std::string cid_suffix(std::string_view cid) {
    return " correlation_id=" + ::yuzu::log_token(std::string(cid));
}

struct Ctx {
    const Request& rq;
    const Ports& ports;
    const AuditHook& hook;
    const EventEmitHook& emit;
    std::string cid; ///< the call's ONE correlation id; never empty (the entry points mint it)
    bool audit_dropped{false};

    /// A best-effort row; a lost one is reported through `audit_dropped`.
    /// The row text is built here, inside a try: a bad_alloc concatenating it reads as "did not
    /// persist" (the same as a hook that throws) instead of unwinding past a caller that is
    /// mid-recovery, where skipping the next step (the targeted count) would be worse than a
    /// lost row.
    void audit(std::string_view result, const std::string& detail) {
        try {
            if (safe_audit(hook, result, detail + cid_suffix(cid)))
                return;
        } catch (...) { // NOLINT(bugprone-empty-catch): falls through to the dropped flag
        }
        audit_dropped = true;
    }
    /// The fail-closed row: the caller decides what a lost row means.
    bool audit_required(std::string_view result, const std::string& detail) {
        try {
            return safe_audit(hook, result, detail + cid_suffix(cid));
        } catch (...) {
            return false; // could not even build the row: the fail-closed gate reads "not persisted"
        }
    }
};

Refusal make_refusal(RefusalKind kind, std::string reason, std::string message,
                     std::string remediation = {}, std::optional<int> retry = std::nullopt) {
    Refusal r;
    r.kind = kind;
    r.reason = std::move(reason);
    r.message = std::move(message);
    r.remediation = std::move(remediation);
    r.retry_after_ms = retry;
    return r;
}

PrepareOutcome refuse(Ctx& c, Refusal r) {
    return PrepareOutcome{std::move(r), c.audit_dropped, {}};
}

std::string ident_pair(const InstructionDefinition& d) {
    return ::yuzu::log_token(d.plugin) + ":" + ::yuzu::log_token(d.action);
}

std::string resolve_cid(const Request& rq) {
    return rq.correlation_id.empty() ? ::yuzu::server::detail::make_correlation_id()
                                     : rq.correlation_id;
}

/// The ONE dispatch-denied refusal, for both authorize runs (the pre-row dry run and the post-write
/// re-run): counts the denial and carries the denial, plugin and action the renderers dereference
/// unconditionally for kDispatchDenied. The audit row stays at each site (its result word
/// differs: `denied` before the `requested` row, `failure` after it) and reads `reason` from here.
Refusal dispatch_denied_refusal(const Ports& ports, const InstructionDefinition& def,
                                const detail::DispatchDenial& denial) {
    std::string reason(detail::to_string(denial.reason));
    bump(ports, "yuzu_server_dispatch_denied_total", {{"reason", reason}});
    Refusal r = make_refusal(RefusalKind::kDispatchDenied, std::move(reason), {});
    r.denial = denial;
    r.plugin = def.plugin;
    r.action = def.action;
    return r;
}

} // namespace

std::string effect_binding(std::string_view plugin, std::string_view action,
                           std::string_view approval_mode, std::string_view concurrency_mode) {
    // `replace`, not the strict default: a stored value that is not valid UTF-8 must not throw
    // out of the MCP handler. Two values differing only in invalid bytes bind identically, which
    // is irrelevant here (the authorizer rejects an unknown pair either way).
    const nlohmann::json effect = nlohmann::json::array(
        {std::string(plugin), std::string(action), std::string(approval_mode),
         std::string(concurrency_mode)});
    return "effect=" +
           effect.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace) + "\n";
}

std::string bounded_definition_id(std::string_view id) {
    if (id.size() <= kAuditDefinitionIdMax)
        return std::string(id);
    // id[cut] is the first byte EXCLUDED from the head. A continuation byte there means the head
    // ends mid-sequence: step back (at most 3 bytes, the longest sequence minus its lead) onto the
    // lead byte, which is then excluded too. Garbage input just stops the walk after 3 steps.
    std::size_t cut = kAuditDefinitionIdMax;
    for (int back = 0; back < 3 && cut > 0 && (static_cast<unsigned char>(id[cut]) & 0xC0) == 0x80;
         ++back)
        --cut;
    std::string out(id.substr(0, cut));
    out += "...";
    return out;
}

bool audit_pre_core_denial(const AuditHook& audit, std::string_view correlation_id,
                           std::string_view reason, std::string_view definition_id) {
    return safe_audit(audit, "denied",
                      "reason=" + ::yuzu::log_token(std::string(reason)) +
                          " definition=" + ::yuzu::log_token(bounded_definition_id(definition_id)) +
                          cid_suffix(correlation_id));
}

bool definition_needs_approval(std::string_view approval_mode, bool caller_is_admin) noexcept {
    if (approval_mode == "auto")
        return false;
    if (approval_mode == "always")
        return true;
    if (approval_mode == "role-gated")
        return !caller_is_admin;
    // Unknown (or empty) mode: fail closed. A typo must not silently open the gate.
    return true;
}

namespace {

PrepareOutcome prepare_impl(Ctx& c) {
    const Request& rq = c.rq;
    const Ports& ports = c.ports;

    // 0. A control byte (NUL included) or a byte sequence that is not well-formed UTF-8 in the id
    //    is refused before ANY store read. NUL: the Postgres binding passes the id as a C string,
    //    so "foo\0xyz" would resolve `foo` while the audit row and the log record a different
    //    string. Invalid UTF-8 (httplib percent-decodes the path, so %C0%80 / %FF arrive raw):
    //    Postgres raises 22021, which would answer a retryable 503 for an input that can never
    //    succeed. The `detail` text and the log are cleaned (log_token) and bounded; the REST
    //    route cleans the `target_id` column the same way for such an id.
    if (definition_id_is_malformed(rq.definition_id)) {
        c.audit("denied", "reason=invalid_definition_id definition=" +
                              ::yuzu::log_token(bounded_definition_id(rq.definition_id)));
        return refuse(c, make_refusal(RefusalKind::kBadRequest, "invalid_definition_id",
                                      "definition id must be valid UTF-8 and hold no control "
                                      "byte (below 0x20 or 0x7F)",
                                      "re-call with the definition id exactly as the list "
                                      "endpoint returns it"));
    }

    // 1. Definition lookup. A store fault is not "no such definition".
    if (!ports.lookup_definition) {
        // NEVER wired: a server defect that does not clear by itself, so no retry hint and a
        // defect remediation (the same class as the kMisconfigured arms). The kind stays
        // kStoreUnavailable (a 503-class answer). A wired port that FAILS, below, is a fault a
        // retry can clear and keeps its hint.
        return refuse(c, make_refusal(RefusalKind::kStoreUnavailable, "store_unavailable",
                                      "instruction store not available",
                                      std::string(kMisconfiguredRemediation)));
    }
    auto looked_up = ports.lookup_definition(rq.definition_id);
    if (!looked_up) {
        spdlog::warn("instruction execute: definition lookup failed for '{}': {}",
                     ::yuzu::log_token(bounded_definition_id(rq.definition_id)),
                     looked_up.error());
        return refuse(c, make_refusal(RefusalKind::kStoreUnavailable, "store_unavailable",
                                      "instruction store not available",
                                      "retry shortly; the definition store is unavailable",
                                      kRetryAfterMs));
    }
    if (!*looked_up) {
        // A `denied` row (command_v1 writes one for its unknown-definition class too). The audit
        // log is operator-only evidence, not a caller-visible existence oracle: the 404 itself
        // already tells the caller the id is unknown.
        c.audit("denied", "reason=not_found definition=" +
                             ::yuzu::log_token(bounded_definition_id(rq.definition_id)));
        return refuse(c, make_refusal(RefusalKind::kNotFound, "not_found",
                                      "instruction definition not found",
                                      "list definitions and re-call with a valid definition id"));
    }
    InstructionDefinition def = std::move(**looked_up);
    const std::string def_token = ::yuzu::log_token(bounded_definition_id(rq.definition_id));

    // 1b. The effect a supervised-tier ticket was minted over (L1). Held BEFORE the authorizer,
    //     any row or any dispatch: this lookup is a second, fresh read of a definition an editor
    //     may have repointed since the recall's pre-consume probe saw it, and the ticket has
    //     already been spent by now, so the only safe answer to a change is to run nothing.
    if (rq.expected_effect &&
        *rq.expected_effect !=
            effect_binding(def.plugin, def.action, def.approval_mode, def.concurrency_mode)) {
        c.audit("denied", "reason=definition_changed definition=" + def_token);
        return refuse(c, make_refusal(RefusalKind::kBadRequest, "definition_changed",
                                      "the definition changed after this call's approval ticket "
                                      "was checked; nothing was dispatched",
                                      "the approval ticket is spent; re-request approval for the "
                                      "definition as it is now and re-call"));
    }

    // 2. The shared chokepoint's dry run for the definition's own (plugin, action), BEFORE any
    //    body work: a caller who may not run this pair learns nothing about its parameters, and
    //    the 403-before-400 order of POST /api/command is preserved for destructive pairs.
    if (!ports.authorize) {
        return refuse(c, make_refusal(RefusalKind::kMisconfigured, "authorizer_unconfigured",
                                      "dispatch authorizer not configured",
                                      std::string(kMisconfiguredRemediation)));
    }
    if (auto decision = ports.authorize(rq.caller, def.plugin, def.action); !decision) {
        const auto& denial = decision.error();
        Refusal r = dispatch_denied_refusal(ports, def, denial);
        spdlog::warn("dispatch denied: {} reason={} securable={} caller={}", ident_pair(def),
                     r.reason, denial.securable.empty() ? "(none)" : denial.securable,
                     rq.caller.principal.empty() ? "(anonymous)"
                                                 : ::yuzu::log_token(rq.caller.principal));
        c.audit("denied", "reason=" + r.reason + " definition=" + def_token);
        return refuse(c, std::move(r));
    }

    // 3. Body shape. `check_targeting_shape` requires an OBJECT: nlohmann's contains() is false
    //    for an array or scalar, so an array body would otherwise read as "named no target" and
    //    broadcast to the whole fleet.
    if (!rq.body.is_object()) {
        bump(ports, "yuzu_server_dispatch_target_rejected_total",
             {{"route", route_label(rq.surface)}, {"reason", kReasonBodyType}});
        c.audit("denied", "reason=" + std::string(kReasonBodyType) + " definition=" + def_token);
        return refuse(c, make_refusal(RefusalKind::kBadRequest, std::string(kReasonBodyType),
                                      "request body must be a JSON object"));
    }
    if (auto bv = check_targeting_shape(rq.body)) {
        bump(ports, "yuzu_server_dispatch_target_rejected_total",
             {{"route", route_label(rq.surface)}, {"reason", bv->reason}});
        c.audit("denied", std::string("reason=") + bv->reason + " definition=" + def_token);
        return refuse(c, make_refusal(RefusalKind::kBadRequest, bv->reason, bv->message,
                                      "correct the targeting arguments and re-call; nothing was "
                                      "dispatched and no approval ticket was created"));
    }

    Plan plan;
    plan.def = def;
    for (const auto& a : rq.body.value("agent_ids", nlohmann::json::array()))
        plan.agent_ids.push_back(a.get<std::string>()); // shape-checked above: strings only
    if (rq.body.contains("scope") && rq.body["scope"].is_string())
        plan.scope = rq.body["scope"].get<std::string>();
    if (rq.body.contains("params") && rq.body["params"].is_object()) {
        for (auto& [k, v] : rq.body["params"].items())
            plan.params[k] = v.is_string() ? v.get<std::string>() : v.dump();
    }

    // 4. Stored parameter_schema, strict. BEFORE the approval step so a refused call never queues
    //    an approval (a ticket does not bind the params), creates an execution row or dispatches.
    {
        const std::string_view pr = route_label(rq.surface);
        const auto count_reject = [&](const char* reason) {
            bump(ports, "yuzu_server_instruction_param_rejected_total",
                 {{"route", pr}, {"reason", reason}});
        };
        if (!ports.validators) {
            return refuse(c, make_refusal(RefusalKind::kMisconfigured, "validators_unconfigured",
                                          "parameter validators not configured",
                                          std::string(kMisconfiguredRemediation)));
        }
        auto validator = ports.validators->get(def.id, def.parameter_schema);
        if (!validator) {
            // A stored schema that cannot be prepared: FAIL CLOSED, never "no validation".
            spdlog::warn("instruction '{}' has an invalid stored parameter_schema; execute refused "
                         "until it is replaced: {}",
                         def_token,
                         validator.error().empty() ? std::string("(no detail)")
                                                   : validator.error().front());
            count_reject("schema_invalid");
            c.audit("failure", "reason=param_schema_invalid definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kSchemaInvalid, "param_schema_invalid",
                                          "stored parameter schema for this instruction is invalid",
                                          "An administrator must export the definition, delete it "
                                          "and import it again with a corrected parameter_schema "
                                          "(signed, unless the server allows unsigned "
                                          "definitions)."));
        }
        if (!(*validator)->absent()) {
            // `params` omitted and `params: null` both mean no params.
            static const nlohmann::json kNoParams = nullptr;
            const nlohmann::json& raw = rq.body.contains("params") ? rq.body["params"] : kNoParams;
            if (auto violation = (*validator)->check(raw)) {
                const bool root = violation->path.empty();
                count_reject(!raw.is_null() && !raw.is_object() ? "shape" : "violation");
                c.audit("denied", "reason=param_schema path=" +
                                      (root ? std::string("(root)")
                                            : ::yuzu::log_token(violation->path)) +
                                      " definition=" + def_token);
                return refuse(c, make_refusal(RefusalKind::kBadRequest, "param_schema",
                                              "invalid params: " +
                                                  (root ? std::string("(root)") : violation->path) +
                                                  ": " + violation->reason,
                                              "Correct params to match the instruction's "
                                              "parameter schema and re-call; nothing was "
                                              "dispatched and no approval ticket was created."));
            }
        } else if (rq.body.contains("params") && !rq.body["params"].is_null() &&
                   !rq.body["params"].is_object()) {
            // No stored schema to hold `params` to a shape, but a supplied value that is not an
            // object (stringified JSON is the likely mistake) would otherwise be dropped and the
            // action run with its defaults. Refuse it rather than ignore it.
            count_reject("shape");
            c.audit("denied", "reason=params_type definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kBadRequest, "params_type",
                                          "params must be a JSON object",
                                          "send params as an object of named values and re-call; "
                                          "nothing was dispatched and no approval ticket was "
                                          "created"));
        }
    }

    // 5. Destructive / Forensics targeting. Same chokepoint functions as /api/command and MCP
    //    execute_instruction; both refusal strings come from dispatch_destructive_gate.hpp.
    if (!ports.classify) {
        return refuse(c, make_refusal(RefusalKind::kClassifierUnavailable, "classifier_unavailable",
                                      "capability registry not available",
                                      std::string(kMisconfiguredRemediation)));
    }
    {
        const auto gate = evaluate_destructive_targeting(
            ports.classify(def.plugin, def.action),
            /*valid_nonempty_agent_ids=*/!plan.agent_ids.empty(),
            /*scope_key_present=*/!plan.scope.empty(),
            /*agent_id_count=*/plan.agent_ids.size());
        switch (gate.verdict) {
        case DestructiveTargetingVerdict::NotDestructive:
            break;
        case DestructiveTargetingVerdict::ClassifyMiss:
            // Policy B, as at the other callers: the dry run above already denies a miss
            // (Unclassified / Ambiguous) before we get here, so this is unreachable with a
            // wired authorizer; falling through lets the dispatch chokepoint deny it too.
            break;
        case DestructiveTargetingVerdict::Targeted: {
            // Confine to the operator's visible agents. absent or degraded -> empty -> 404.
            std::optional<std::vector<std::string>> vis;
            if (ports.visible_agents)
                vis = ports.visible_agents(rq.caller.principal);
            plan.agent_ids =
                confine_destructive_targets(plan.agent_ids, DestructiveVisibleAgents{std::move(vis)});
            if (plan.agent_ids.empty()) {
                bump(ports, "yuzu_server_dispatch_target_rejected_total",
                     {{"route", route_label(rq.surface)},
                      {"reason", kReasonDestructiveNoVisibleTarget}});
                c.audit("denied", "reason=" + std::string(kReasonDestructiveNoVisibleTarget) +
                                      " definition=" + def_token);
                return refuse(c, make_refusal(RefusalKind::kNoVisibleTarget,
                                              std::string(kReasonDestructiveNoVisibleTarget),
                                              std::string(kDestructiveNoVisibleAgentMessage)));
            }
            break;
        }
        case DestructiveTargetingVerdict::RefuseUntargeted: {
            bump(ports, "yuzu_server_dispatch_target_rejected_total",
                 {{"route", route_label(rq.surface)}, {"reason", gate.refusal_reason}});
            c.audit("denied", "reason=" + std::string(gate.refusal_reason) +
                                  " definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kBadRequest, std::string(gate.refusal_reason),
                                          std::string(gate.refusal_message),
                                          std::string(remediation_for_refusal_reason(
                                              gate.refusal_reason)) +
                                              "; nothing was dispatched and no approval ticket "
                                              "was created"));
        }
        }
    }

    // 6. The definition's OWN approval_mode. Nothing about the caller's MCP tier is read here.
    if (definition_needs_approval(def.approval_mode, rq.caller.principal_is_admin)) {
        if (!ports.submit_approval) {
            spdlog::error("instruction '{}' requires approval (mode={}) but no approval manager is "
                          "available: rejecting execution",
                          def_token, ::yuzu::log_token(def.approval_mode));
            bump(ports, kApprovalRefusedMetric,
                 {{"reason", kReasonApprovalUnavailable}});
            c.audit("failure", "reason=approval_unavailable mode=" +
                                   ::yuzu::log_token(def.approval_mode) + " definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kApprovalUnavailable, kReasonApprovalUnavailable,
                                          "approval system unavailable: cannot execute an "
                                          "approval-gated instruction",
                                          std::string(kMisconfiguredRemediation)));
        }
        // A cap was requested but its counter is unwired: refuse, never silently run uncapped
        // (the same fail-closed stance as an unwired approval manager above).
        if (rq.submitter_pending_cap > 0 && !ports.pending_count_for) {
            spdlog::error("instruction '{}' requires approval but the pending-approval counter is "
                          "unwired: rejecting rather than running without the per-principal cap",
                          def_token);
            bump(ports, kApprovalRefusedMetric, {{"reason", kReasonApprovalUnavailable}});
            c.audit("failure", "reason=approval_unavailable mode=" +
                                   ::yuzu::log_token(def.approval_mode) + " definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kApprovalUnavailable, kReasonApprovalUnavailable,
                                          "approval system unavailable: cannot execute an "
                                          "approval-gated instruction",
                                          std::string(kMisconfiguredRemediation)));
        }
        std::optional<int> pending_now;
        if (rq.submitter_pending_cap > 0) {
            // up8-1 / sre-2: an unreadable count must refuse, not read as zero. The cap exists to
            // bound one principal's share of the global pending queue, and a store that cannot
            // be counted is exactly when every principal would otherwise be admitted.
            try {
                pending_now = ports.pending_count_for(rq.caller.principal);
            } catch (...) {
                pending_now = std::nullopt;
            }
            if (!pending_now) {
                spdlog::error("instruction '{}': the pending-approval count could not be read; "
                              "refusing rather than running without the per-principal cap",
                              def_token);
                bump(ports, kApprovalRefusedMetric, {{"reason", kReasonApprovalUnavailable}});
                c.audit("failure", "reason=approval_unavailable cause=pending_count_unreadable "
                                   "definition=" + def_token);
                // A store fault (pool timeout or query failure), not a wiring defect: unlike the
                // unwired-port refusals above, a retry can succeed.
                return refuse(c, make_refusal(RefusalKind::kApprovalUnavailable,
                                              kReasonApprovalUnavailable,
                                              "approval system unavailable: the pending-approval "
                                              "count could not be read",
                                              "retry shortly; the approval store could not be read",
                                              kRetryAfterMs));
            }
        }
        if (rq.submitter_pending_cap > 0 && *pending_now >= rq.submitter_pending_cap) {
            bump(ports, kApprovalRefusedMetric,
                 {{"reason", kReasonApprovalCapReached}});
            c.audit("denied", "reason=approval_cap_reached definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kApprovalCapReached, kReasonApprovalCapReached,
                                          "too many pending approvals for this principal; approve "
                                          "or let existing requests expire before creating more",
                                          "wait for your pending approvals to be reviewed"));
        }
        auto submitted = ports.submit_approval(rq.definition_id, rq.caller.principal, plan.scope,
                                               def.plugin, def.action);
        if (!submitted) {
            spdlog::error("approval submit failed for '{}': {}", def_token, submitted.error().message);
            if (submitted.error().queue_full) {
                // The GLOBAL queue is full: only a human reviewer deciding a pending approval, or
                // the 7-day expiry, frees a slot. Not a store fault, so no retry hint (a retry
                // loop cannot succeed) and its own reason (ca8-9 / sre-1 / up8-8).
                bump(ports, kApprovalRefusedMetric, {{"reason", kReasonApprovalQueueFull}});
                c.audit("denied", "reason=approval_queue_full definition=" + def_token);
                return refuse(c, make_refusal(RefusalKind::kApprovalQueueFull,
                                              kReasonApprovalQueueFull,
                                              "the approval queue is full: no approval request "
                                              "can be created right now",
                                              "a human reviewer must decide pending approvals "
                                              "(or the oldest expire) before a new approval "
                                              "request can be created; retrying will not help"));
            }
            bump(ports, kApprovalRefusedMetric,
                 {{"reason", kReasonApprovalSubmitFailed}});
            c.audit("failure", "reason=approval_submit_failed definition=" + def_token);
            return refuse(c, make_refusal(RefusalKind::kApprovalSubmitFailed,
                                          kReasonApprovalSubmitFailed,
                                          "failed to create approval request", "retry later",
                                          kRetryAfterMs));
        }
        c.audit("pending", "approval_id=" + ::yuzu::log_token(*submitted) +
                               " mode=" + ::yuzu::log_token(def.approval_mode) +
                               " definition=" + def_token);
        emit_event_guarded(c.emit, "approval.created"); // the legacy route's event
        return PrepareOutcome{PendingApproval{*submitted, def.approval_mode, rq.definition_id},
                              c.audit_dropped, {}};
    }

    return PrepareOutcome{std::move(plan), c.audit_dropped, {}};
}

} // namespace

PrepareOutcome prepare(const Request& rq, const Ports& ports, const AuditHook& audit,
                       const EventEmitHook& emit) {
    Ctx c{rq, ports, audit, emit, resolve_cid(rq)};
    PrepareOutcome out = prepare_impl(c);
    out.correlation_id = c.cid;
    return out;
}

namespace {

std::string zero_reach_text(ZeroReachCause cause, const ConfinedDispatchOutcome& o) {
    switch (cause) {
    case ZeroReachCause::Denied:
        return std::format("the dispatch chokepoint refused this command ({}): dispatch was withheld, "
                           "not attempted, and no agent was reached",
                           o.denied ? detail::to_string(o.denied->reason) : std::string_view{"unknown"});
    case ZeroReachCause::InvalidScope:
        return "invalid scope: " + o.scope_parse_error.value_or("(unparsed)");
    case ZeroReachCause::ContainmentUnreadable:
        return "containment state is unreadable: dispatch is failing closed and reaching no agent; "
               "check the quarantine store";
    case ZeroReachCause::RouteUnreadable:
        return "the gateway routing directory could not be read for one or more targets: dispatch "
               "is failing closed rather than guessing where to route";
    case ZeroReachCause::OsGateUnreadable:
        return "agent presence could not be read while a per-OS kill switch is set: dispatch is "
               "failing closed and reaching no agent";
    case ZeroReachCause::Quarantined:
        return std::format("{} target(s) are quarantined: dispatch to them was withheld, not "
                           "attempted, and no agent was reached",
                           o.denied_quarantined_count);
    case ZeroReachCause::PluginNotFound:
        return std::format("the dispatched plugin is not in the reported inventory of {} target(s): "
                           "dispatch was withheld, not attempted, and no agent was reached",
                           o.unknown_plugin_count);
    case ZeroReachCause::KillSwitchedOs:
        return std::format("{} target(s) run an OS for which this plugin action is switched off: "
                           "dispatch was withheld, not attempted, and no agent was reached",
                           o.kill_switched_os_count);
    case ZeroReachCause::Generic:
        return "no agents reached: every target was unreachable or excluded by an in-flight "
               "per-device concurrency claim (check yuzu_server_dispatch_concurrency_skipped_total "
               "before treating this as an agent-connectivity fault)";
    }
    return "no agents reached";
}

void cancel_row(Ctx& c, const std::string& execution_id) {
    const Ports& p = c.ports;
    if (!p.mark_cancelled || execution_id.empty())
        return;
    bool ok = false;
    try {
        ok = p.mark_cancelled(execution_id, c.rq.caller.principal);
    } catch (...) {
        ok = false;
    }
    if (!ok) {
        spdlog::error("instruction execute: mark_cancelled failed for execution_id={}", execution_id);
        bump(p, "yuzu_exec_tracker_bookkeeping_failed_total",
             {{"op", "mark_cancelled"}, {"surface", bookkeeping_label(c.rq.surface)}});
    }
}

/// Records how many agents hold the command and re-evaluates the row's counters (responses that
/// arrived BEFORE the count was set could not move it to terminal). Returns whether the count was
/// stored; a failure is logged and counted, never thrown. Shared by the success path and the
/// throwing-dispatch arm, which stores the partial count of sends accepted by the send path.
bool record_targeted(Ctx& c, const std::string& execution_id, int agents) {
    const Ports& p = c.ports;
    if (!p.set_agents_targeted || execution_id.empty())
        return false;
    bool ok = false;
    try {
        ok = p.set_agents_targeted(execution_id, agents);
    } catch (...) {
        ok = false;
    }
    if (!ok) {
        spdlog::error("instruction execute: set_agents_targeted failed for execution_id={}",
                      execution_id);
        bump(p, "yuzu_exec_tracker_bookkeeping_failed_total",
             {{"op", "set_agents_targeted"}, {"surface", bookkeeping_label(c.rq.surface)}});
    }
    if (p.refresh_counts) {
        try {
            p.refresh_counts(execution_id);
        } catch (const std::exception& e) {
            spdlog::warn("instruction execute: refresh_counts threw for execution_id={}: {}",
                         execution_id, e.what());
        } catch (...) {
            spdlog::warn("instruction execute: refresh_counts threw a non-standard exception "
                         "for execution_id={}",
                         execution_id);
        }
    }
    return ok;
}

Outcome dispatch_stage(Ctx& c, Plan plan) {
    const Ports& p = c.ports;
    const Request& rq = c.rq;
    const InstructionDefinition& def = plan.def;
    const std::string def_token = ::yuzu::log_token(bounded_definition_id(rq.definition_id));

    if (!p.dispatch) {
        return Outcome{make_refusal(RefusalKind::kMisconfigured, "dispatch_unconfigured",
                                    "command dispatch unavailable",
                                    std::string(kMisconfiguredRemediation)),
                       c.audit_dropped};
    }

    if (!p.readmit) { // before the row: an unwired recheck is a defect, never "no gate"
        return Outcome{make_refusal(RefusalKind::kMisconfigured, "readmit_unconfigured",
                                    "dispatch re-admission not configured",
                                    std::string(kMisconfiguredRemediation)),
                       c.audit_dropped};
    }

    // 7. Audit BEFORE the side effect, fail closed (house v1 dispatch pattern).
    if (!c.audit_required(
            "requested",
            "definition=" + def_token + " " + ident_pair(def) + " targets=" +
                (plan.agent_ids.empty() ? std::string(plan.scope.empty() ? "all" : "scope")
                                        : std::to_string(plan.agent_ids.size())))) {
        return Outcome{make_refusal(RefusalKind::kAuditUnavailable, "audit_unavailable",
                                    "audit subsystem unavailable: refusing to dispatch without "
                                    "durable evidence",
                                    "retry the request", kRetryAfterMs),
                       c.audit_dropped};
    }

    // 8. The execution row BEFORE dispatch, so its id is known when the dispatch registers the
    //    command_id -> execution_id mapping (closes the fast-agent race, UP2-4).
    std::string execution_id;
    if (p.create_execution) {
        ExecutionRow row;
        row.definition_id = rq.definition_id;
        row.scope_expression = plan.scope;
        // A REDACTED copy is persisted; the live dispatch below still uses the raw map.
        row.parameter_values =
            nlohmann::json(redact_sensitive_instruction_params(plan.params)).dump();
        row.dispatched_by = rq.caller.principal;
        // up8-3: the port may throw (a pool or driver fault). The `requested` row is already
        // written, so an unwound exception would leave it with no outcome row. Nothing has been
        // dispatched yet, so this refuses (retryable) after writing the `failure` row.
        bool create_threw = false;
        std::optional<std::string> created;
        try {
            created = p.create_execution(row);
        } catch (const std::exception& e) {
            spdlog::error("instruction execute: create_execution failed for '{}': {}", def_token,
                          e.what());
            create_threw = true;
        } catch (...) {
            spdlog::error("instruction execute: create_execution failed for '{}': unknown exception",
                          def_token);
            create_threw = true;
        }
        if (create_threw) {
            c.audit("failure", "reason=execution_record_exception definition=" + def_token);
            return Outcome{make_refusal(RefusalKind::kStoreUnavailable, "execution_record_unavailable",
                                        "execution history unavailable: nothing was dispatched",
                                        "retry the request", kRetryAfterMs),
                           c.audit_dropped};
        }
        if (created.has_value())
            execution_id = *created;
        else
            spdlog::warn("instruction execute: execution row not created for '{}'; dispatching "
                         "with an empty execution_id",
                         def_token);
    }

    // 8b. #7110: the surface's own writes are done (the requested row and the execution row); a
    //     grant, a JIT elevation or a visible set can move while either is written, so decide
    //     again here. Not re-decided: the chokepoint's own provenance-record write, see
    //     docs/user-manual/rest-api.md 'Refused after the audit row'.
    std::optional<DispatchCaller> readmitted;
    std::optional<detail::DispatchDenial> denial;
    try {
        readmitted = p.readmit();
        if (readmitted)
            if (auto decision = p.authorize(*readmitted, def.plugin, def.action); !decision)
                denial = decision.error();
    } catch (...) { // fail closed: a throwing recheck (or authorizer) is a withdrawn permission
        readmitted = std::nullopt;
        denial.reset();
    }
    // Both refusals close the rows alike: a `failure` outcome, the execution cancelled.
    const auto refuse_after_rows = [&](Refusal r, const std::string& detail) {
        c.audit("failure", detail + " execution_id=" + execution_id);
        cancel_row(c, execution_id);
        return Outcome{std::move(r), c.audit_dropped};
    };
    if (!readmitted)
        return refuse_after_rows(
            make_refusal(RefusalKind::kPermissionRevoked, "permission_revoked",
                         "permission revoked after the request was recorded",
                         "this request was not dispatched; the permission it needs was withdrawn "
                         "while it was being recorded, and retrying will not help until it is "
                         "granted again"),
            "reason=permission_revoked definition=" + def_token);
    const DispatchCaller& caller = *readmitted; // the fresh caller is the one dispatched
    if (denial) {
        Refusal r = dispatch_denied_refusal(p, def, *denial);
        const std::string detail = "reason=" + r.reason + " definition=" + def_token;
        return refuse_after_rows(std::move(r), detail);
    }

    // OMITTED agent_ids + OMITTED scope is a deliberate broadcast and is NAMED, never inferred
    // from "both happen to be empty" (the shape check guarantees that arriving here empty means
    // the caller omitted both).
    const std::string dispatch_scope = (plan.agent_ids.empty() && plan.scope.empty())
                                           ? std::string(kBroadcastScope)
                                           : plan.scope;
    // The throw arm's strings are built BEFORE the dispatch (execution_mutation.cpp's
    // `threw_detail` pattern): a second bad_alloc while building them after the throw must not
    // escape without a `failure` row. The arm may upgrade them once it knows the partial count,
    // and falls back to these when that upgrade cannot allocate.
    std::string threw_detail =
        "reason=dispatch_exception definition=" + def_token + " execution_id=" + execution_id;
    // NO retry hint, on the wire or in prose: whether any agent already received the command is
    // unknown once the dispatch has thrown, so a blind retry could dispatch it twice.
    // (command_v1_routes.cpp's dispatch_exception arm drops it for the same reason.)
    std::string threw_remediation =
        "the dispatch failed part-way and some agents may already have received the command; ";
    if (execution_id.empty()) {
        threw_remediation += "no execution record was created, so there is no execution record to "
                             "attach per-agent results to; confirm on the devices before "
                             "running it again";
    } else {
        threw_remediation +=
            "execution " + execution_id +
            " was left running, not cancelled, so results from any agent that did receive the "
            "command are still recorded against it; check that execution's per-agent results "
            "before running the definition again; the server closes the record by itself ONLY if no "
            "agent ever responds, a record an agent has answered will NOT close by itself, and "
            "cancel_execution (POST /api/v1/executions/{id}/cancel on REST) closes it";
    }
    // The refusal itself is built here too, so the throw arm below only MOVES into it (a string
    // move-assign and an int store): no allocation is left between the bookkeeping and the return.
    Refusal threw_refusal = make_refusal(RefusalKind::kDispatchFailed, "dispatch_exception",
                                         "dispatch failed", std::move(threw_remediation));
    threw_refusal.execution_id = execution_id;

    ConfinedDispatchOutcome o;
    SendProgress progress; // sends accepted by the send path before a throw (dispatch_send_progress.hpp)
    bool threw = false;
    try {
        const SendProgressScope send_scope(progress);
        o = p.dispatch(def.plugin, def.action, plan.agent_ids, dispatch_scope, plan.params,
                       execution_id, caller, def.id, def.concurrency_mode);
    } catch (const std::exception& e) {
        spdlog::error("instruction execute: dispatch failed for '{}': {}", def_token, e.what());
        threw = true;
    } catch (...) {
        spdlog::error("instruction execute: dispatch failed for '{}': unknown exception",
                      def_token);
        threw = true;
    }
    if (threw) {
        // ORDER matters, and each step is isolated from the others' allocation failures (a second
        // bad_alloc here must never skip the failure row nor the targeted count):
        //   1. the `failure` row, first, with strings that were pre-built before the dispatch;
        //   2. the partial count of accepted sends (record_targeted never throws);
        //   3. the upgraded remediation text (best effort: the pre-built text is the fallback);
        //   4. the metric, last, with its labels built inside bump's own try.
        //
        // The execution row is deliberately NOT cancelled (up8-3 / sg-5): a row marked
        // `cancelled` with agents_targeted 0 would tell every reader nothing was sent, and some
        // agents may hold the command. It stays `running` (the tracker has no `failed` status).
        //
        // When the send path accepted sends before the throw, that count is stored as the row's
        // `agents_targeted` and the counters refreshed, so the results of those agents complete
        // the row through the ordinary refresh_counts path. Without it the row could never close:
        // refresh_counts promotes only when agents_targeted > 0, and the stuck-execution reaper
        // excludes any row an agent has answered. With NO accepted send the row stays at 0 and
        // the reaper cancels it if no agent ever answers. The count is a lower bound (see
        // dispatch_send_progress.hpp).
        const bool any_sent = progress.sent > 0;
        if (any_sent) {
            // `agents_sent` is on the row whenever it is known, whether or not the count could
            // be stored: it is the evidence of how far the fan-out got.
            try {
                threw_detail += " agents_sent=" + std::to_string(progress.sent);
            } catch (...) { // NOLINT(bugprone-empty-catch): the pre-built row text stands
            }
        }
        c.audit("failure", threw_detail);
        const bool recorded = any_sent && record_targeted(c, execution_id, progress.sent);
        if (any_sent) {
            try {
                std::string remediation =
                    "the dispatch failed part-way: at least " + std::to_string(progress.sent) +
                    " agent(s) were sent the command before the failure, and others may also have "
                    "received it; ";
                if (execution_id.empty()) {
                    remediation += "no execution record was created, so there is no execution "
                                   "record to attach per-agent results to; confirm on the "
                                   "devices before running the definition again";
                } else if (recorded) {
                    remediation +=
                        "execution " + execution_id + " was left running (not cancelled) with " +
                        std::to_string(progress.sent) +
                        " agent(s) targeted, so results from those agents are still recorded "
                        "against it and will complete it; check that execution's per-agent "
                        "results before running the definition again, and close it with "
                        "cancel_execution (POST /api/v1/executions/{id}/cancel on REST) if it "
                        "should not wait";
                } else {
                    remediation +=
                        "execution " + execution_id +
                        " was left running (not cancelled) but its targeted count could NOT be "
                        "recorded; the server closes the record by itself ONLY if no agent ever "
                        "responds, and a record an agent has answered will NOT close by itself; "
                        "check that execution's per-agent results before running the definition "
                        "again, and close it with cancel_execution (POST "
                        "/api/v1/executions/{id}/cancel on REST)";
                }
                threw_refusal.remediation = std::move(remediation); // noexcept move-assign
            } catch (...) { // NOLINT(bugprone-empty-catch): keep the pre-built generic strings
            }
        }
        bump(p, "yuzu_server_dispatch_fanout_throw_total",
             {{"route", route_label(rq.surface)}, {"phase", "dispatch"}});
        threw_refusal.agents_sent = any_sent ? progress.sent : 0;
        return Outcome{std::move(threw_refusal), c.audit_dropped};
    }

    if (o.sent == 0) {
        cancel_row(c, execution_id);
        const bool protective = yuzu::protective::is_protective_action(def.plugin, def.action);
        const ZeroReachCause cause = classify_zero_reach(o, protective);
        ZeroReach z;
        z.cause = cause;
        z.command_id = o.command_id;
        z.execution_id = execution_id;
        z.message = zero_reach_text(cause, o);
        z.definition_id = rq.definition_id;
        z.plugin = def.plugin;
        z.action = def.action;
        z.agents_quarantined = o.denied_quarantined_count;
        z.agents_unknown_plugin = o.unknown_plugin_count;
        z.agents_kill_switched_os = o.kill_switched_os_count;
        c.audit("failure", "reason=" + std::string(zero_reach_token(cause)) +
                               " definition=" + def_token + " execution_id=" + execution_id);
        return Outcome{std::move(z), c.audit_dropped, {}};
    }

    // 9. Success. Record the targeted count, then re-evaluate counters: responses that arrived
    //    BEFORE the count was set could not move the row to terminal.
    (void)record_targeted(c, execution_id, o.sent);
    c.audit("success", "command_id=" + ::yuzu::log_token(o.command_id) +
                           " execution_id=" + execution_id + " agents=" + std::to_string(o.sent) +
                           " definition=" + def_token);
    emit_event_guarded(c.emit, "instruction.executed"); // the legacy route's event
    Dispatched d;
    d.command_id = o.command_id;
    d.execution_id = execution_id;
    d.agents_reached = o.sent;
    d.definition_id = rq.definition_id;
    d.plugin = def.plugin;
    d.action = def.action;
    return Outcome{std::move(d), c.audit_dropped, {}};
}

} // namespace

Outcome run(const Request& rq, const Ports& ports, const AuditHook& audit,
            const EventEmitHook& emit) {
    // ONE id for the whole call: resolved once here, stamped by both stages through one Ctx.
    Ctx c{rq, ports, audit, emit, resolve_cid(rq)};
    PrepareOutcome prep = prepare_impl(c);
    Outcome out;
    if (auto* plan = std::get_if<Plan>(&prep.result)) {
        out = dispatch_stage(c, std::move(*plan));
    } else if (auto* pending = std::get_if<PendingApproval>(&prep.result)) {
        out = Outcome{std::move(*pending), c.audit_dropped, {}};
    } else {
        out = Outcome{std::move(std::get<Refusal>(prep.result)), c.audit_dropped, {}};
    }
    out.correlation_id = c.cid;
    return out;
}

} // namespace yuzu::server::instruction_execute
