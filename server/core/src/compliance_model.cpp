/// @file compliance_model.cpp
/// Implementations for compliance_model.hpp (api-parity #4034). Every
/// function here is pure: no I/O, no store access, no httplib. Field names
/// and order mirror the legacy `/api/compliance*` / `/api/polic*` handlers'
/// existing hand-rolled `nlohmann::json` bodies exactly (`compliance_routes.cpp`)
/// so REST v1 / the fragment renderers / MCP all serve byte-identical shapes.

#include "compliance_model.hpp"

namespace yuzu::server {

nlohmann::json fleet_compliance_json(const FleetCompliance& fc) {
    return nlohmann::json{{"compliance_pct", fc.compliance_pct},
                          {"total_checks", fc.total_checks},
                          {"compliant", fc.compliant},
                          {"non_compliant", fc.non_compliant},
                          {"unknown", fc.unknown},
                          {"fixing", fc.fixing},
                          {"error", fc.error}};
}

nlohmann::json compliance_summary_json(const ComplianceSummary& cs) {
    return nlohmann::json{{"compliant", cs.compliant},
                          {"non_compliant", cs.non_compliant},
                          {"unknown", cs.unknown},
                          {"fixing", cs.fixing},
                          {"error", cs.error},
                          {"total", cs.total}};
}

nlohmann::json policy_agent_status_json(const PolicyAgentStatus& s) {
    return nlohmann::json{{"agent_id", s.agent_id},
                          {"status", s.status},
                          {"last_check_at", s.last_check_at},
                          {"last_fix_at", s.last_fix_at},
                          {"check_result", s.check_result}};
}

nlohmann::json policy_list_row_json(const Policy& p) {
    nlohmann::json inputs_obj = nlohmann::json::object();
    for (const auto& inp : p.inputs)
        inputs_obj[inp.key] = inp.value;

    nlohmann::json triggers_arr = nlohmann::json::array();
    for (const auto& t : p.triggers) {
        triggers_arr.push_back({{"id", t.id},
                                {"type", t.trigger_type},
                                {"config", nlohmann::json::parse(t.config_json, nullptr, false)}});
    }

    return nlohmann::json{{"id", p.id},
                          {"name", p.name},
                          {"description", p.description},
                          {"fragment_id", p.fragment_id},
                          {"scope_expression", p.scope_expression},
                          {"enabled", p.enabled},
                          {"inputs", inputs_obj},
                          {"triggers", triggers_arr},
                          {"management_groups", p.management_groups},
                          {"created_at", p.created_at},
                          {"updated_at", p.updated_at}};
}

nlohmann::json policy_fragment_list_row_json(const PolicyFragment& f) {
    return nlohmann::json{{"id", f.id},
                          {"name", f.name},
                          {"description", f.description},
                          {"check_instruction", f.check_instruction},
                          {"check_compliance", f.check_compliance},
                          {"fix_instruction", f.fix_instruction},
                          {"post_check_instruction", f.post_check_instruction},
                          {"created_at", f.created_at},
                          {"updated_at", f.updated_at}};
}

nlohmann::json single_policy_detail_json(const Policy& p, const ComplianceSummary& cs,
                                         bool remediation_available) {
    nlohmann::json obj = policy_list_row_json(p);
    obj["yaml_source"] = p.yaml_source;
    obj["remediation_available"] = remediation_available;
    obj["compliance"] = compliance_summary_json(cs);
    return obj;
}

ConfinedPolicyCompliance confined_policy_compliance(const std::vector<PolicyAgentStatus>& statuses,
                                                     const authz::VisibleSet& scope,
                                                     const std::string& policy_id) {
    ConfinedPolicyCompliance out;
    out.summary.policy_id = policy_id;
    out.visible.reserve(statuses.size());
    for (const auto& s : statuses) {
        if (!authz::in_scope(scope, s.agent_id))
            continue;
        out.visible.push_back(s);
        ++out.summary.total;
        if (s.status == "compliant")
            ++out.summary.compliant;
        else if (s.status == "non_compliant")
            ++out.summary.non_compliant;
        else if (s.status == "unknown")
            ++out.summary.unknown;
        else if (s.status == "fixing")
            ++out.summary.fixing;
        else if (s.status == "error")
            ++out.summary.error;
    }
    return out;
}

} // namespace yuzu::server
