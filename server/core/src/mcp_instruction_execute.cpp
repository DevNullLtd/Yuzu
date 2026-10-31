#include "mcp_instruction_execute.hpp"

#include "dispatch_denial_text.hpp"
#include "dispatch_target_shape.hpp"
#include "mcp_jsonrpc.hpp" // kInvalidParams / kInternalError / kPermissionDenied / kTierDenied

#include <format>

namespace yuzu::server::mcp::instruction_definition {

using instruction_execute::Dispatched;
using instruction_execute::Outcome;
using instruction_execute::PendingApproval;
using instruction_execute::Refusal;
using instruction_execute::RefusalKind;
using instruction_execute::ZeroReach;

std::optional<BoundViolation> check_args(const nlohmann::json& args) {
    // definition_id: required, a non-empty bounded string. Absent, non-string and empty are all
    // `ident_empty` (the schema marks it required, but its served literal puts no floor on it).
    if (!args.contains("definition_id") || !args["definition_id"].is_string() ||
        args["definition_id"].get_ref<const std::string&>().empty())
        return BoundViolation{"ident_empty",
                              "definition_id is required and must be a non-empty string"};
    if (args["definition_id"].get_ref<const std::string&>().size() > kDefinitionIdMaxLen)
        return BoundViolation{"ident_len", std::format("definition_id must be at most {} bytes",
                                                       kDefinitionIdMaxLen)};

    if (args.contains("params") && args["params"].is_object()) {
        const auto& p = args["params"];
        if (p.size() > kExecInstrParamCountMax)
            return BoundViolation{"param_count", std::format("params must have at most {} keys",
                                                             kExecInstrParamCountMax)};
        for (const auto& [k, v] : p.items()) {
            if (k.size() > kExecInstrParamKeyMaxLen)
                return BoundViolation{"param_key_len", std::format("a params key exceeds {} bytes",
                                                                   kExecInstrParamKeyMaxLen)};
            // What the dispatch will actually carry: a non-string value is dumped to text.
            const std::size_t vlen =
                v.is_string() ? v.get_ref<const std::string&>().size() : v.dump().size();
            if (vlen > kExecInstrParamValueMaxLen)
                return BoundViolation{"param_value_len",
                                      std::format("a params value exceeds {} bytes",
                                                  kExecInstrParamValueMaxLen)};
        }
    }
    if (args.contains("scope") && args["scope"].is_string() &&
        args["scope"].get_ref<const std::string&>().size() > kExecInstrScopeMaxLen)
        return BoundViolation{"scope_len", std::format("scope must be at most {} bytes",
                                                       kExecInstrScopeMaxLen)};
    if (args.contains("agent_ids") && args["agent_ids"].is_array()) {
        const auto& a = args["agent_ids"];
        if (a.size() > kExecInstrAgentIdsMaxItems)
            return BoundViolation{"agent_ids_count",
                                  std::format("agent_ids must have at most {} entries",
                                              kExecInstrAgentIdsMaxItems)};
        for (const auto& v : a) {
            if (v.is_string() && v.get_ref<const std::string&>().size() > kExecInstrIdentMaxLen)
                return BoundViolation{"agent_id_len",
                                      std::format("an agent_ids entry exceeds {} bytes",
                                                  kExecInstrIdentMaxLen)};
        }
    }
    // Targeting type / supplied-but-empty / agent_ids+scope conflict: the one shared function.
    return yuzu::server::check_targeting_shape(args);
}

nlohmann::json core_body(const nlohmann::json& args) {
    nlohmann::json body = nlohmann::json::object();
    for (const char* key : {"agent_ids", "scope", "params"}) {
        if (args.contains(key))
            body[key] = args[key];
    }
    return body;
}

namespace {

std::string error_data(const std::string& cid, const std::optional<int>& retry,
                       const std::string& reason, const std::string& remediation, bool audit_dropped) {
    nlohmann::json d{{"correlation_id", cid},
                     {"retry_after_ms", retry ? nlohmann::json(*retry) : nlohmann::json(nullptr)},
                     {"remediation", remediation.empty() ? nlohmann::json(nullptr)
                                                         : nlohmann::json(remediation)}};
    if (!reason.empty())
        d["reason"] = reason;
    if (audit_dropped)
        d["audit_persisted"] = false;
    return d.dump();
}

} // namespace

Rendered render_refusal(const Refusal& r, bool audit_dropped, const std::string& cid) {
    Rendered out;
    out.is_error = true;
    std::string message = r.message;
    std::string remediation = r.remediation;
    switch (r.kind) {
    case RefusalKind::kNotFound:
    case RefusalKind::kBadRequest:
    case RefusalKind::kNoVisibleTarget:
        out.code = kInvalidParams;
        break;
    case RefusalKind::kApprovalCapReached:
        out.code = kTierDenied;
        break;
    case RefusalKind::kDispatchDenied: {
        const auto& d = *r.denial;
        const auto text = describe_dispatch_denial(d.reason, "", "", d, DenialSurface::kMcp);
        message = text.message;
        remediation = text.remediation;
        switch (text.cls) {
        case DispatchDenialClass::kInvalidParams:
            out.code = kInvalidParams;
            break;
        case DispatchDenialClass::kPermissionDenied:
            out.code = kPermissionDenied;
            break;
        case DispatchDenialClass::kInternal:
            out.code = kInternalError;
            break;
        }
        break;
    }
    case RefusalKind::kStoreUnavailable:
    case RefusalKind::kSchemaInvalid:
    case RefusalKind::kApprovalUnavailable:
    case RefusalKind::kApprovalSubmitFailed:
    case RefusalKind::kClassifierUnavailable:
    case RefusalKind::kMisconfigured:
    case RefusalKind::kAuditUnavailable:
    case RefusalKind::kDispatchFailed:
        out.code = kInternalError;
        break;
    }
    out.message = message;
    out.data_json = error_data(cid, r.retry_after_ms, r.reason, remediation, audit_dropped);
    return out;
}

Rendered render_pending(const PendingApproval& p, bool audit_dropped) {
    Rendered out;
    nlohmann::json j{{"status", "pending_approval"},
                     {"approval_id", p.approval_id},
                     {"approval_mode", p.approval_mode},
                     {"definition_id", p.definition_id}};
    if (audit_dropped)
        j["audit_persisted"] = false;
    out.payload_json = j.dump();
    return out;
}

Rendered render_outcome(const Outcome& o, const std::string& cid) {
    if (const auto* r = std::get_if<Refusal>(&o.result))
        return render_refusal(*r, o.audit_dropped, cid);
    if (const auto* p = std::get_if<PendingApproval>(&o.result))
        return render_pending(*p, o.audit_dropped);
    Rendered out;
    if (const auto* z = std::get_if<ZeroReach>(&o.result)) {
        nlohmann::json j{{"status", std::string(zero_reach_token(z->cause))},
                         {"command_id", z->command_id},
                         {"execution_id", z->execution_id},
                         {"agents_reached", 0},
                         {"definition_id", z->definition_id},
                         {"plugin", z->plugin},
                         {"action", z->action},
                         {"message", z->message},
                         {"retry_after_ms", zero_reach_retryable(z->cause) ? nlohmann::json(5000)
                                                                           : nlohmann::json(nullptr)},
                         {"agents_quarantined", z->agents_quarantined},
                         {"agents_unknown_plugin", z->agents_unknown_plugin},
                         {"agents_kill_switched_os", z->agents_kill_switched_os}};
        if (o.audit_dropped)
            j["audit_persisted"] = false;
        out.payload_json = j.dump();
        return out;
    }
    const auto& d = std::get<Dispatched>(o.result);
    nlohmann::json j{{"command_id", d.command_id},
                     {"execution_id", d.execution_id},
                     {"agents_reached", d.agents_reached},
                     {"definition_id", d.definition_id},
                     {"plugin", d.plugin},
                     {"action", d.action}};
    if (o.audit_dropped)
        j["audit_persisted"] = false;
    out.payload_json = j.dump();
    return out;
}

std::optional<Rendered> render_unless_plan(const instruction_execute::PrepareOutcome& p,
                                           const std::string& cid) {
    if (const auto* r = std::get_if<Refusal>(&p.result))
        return render_refusal(*r, p.audit_dropped, cid);
    if (const auto* pa = std::get_if<PendingApproval>(&p.result))
        return render_pending(*pa, p.audit_dropped);
    return std::nullopt;
}

} // namespace yuzu::server::mcp::instruction_definition
