#include "guardian_model.hpp"

#include "baseline_store.hpp"
#include "guaranteed_state_store.hpp"

#include <unordered_map>

namespace yuzu::server {

std::optional<GuardianStatusRollup>
guardian_status_rollup(GuaranteedStateStore& store,
                       const std::optional<std::vector<std::string>>& agent_scope) {
    // ADR-0038 catastrophic-read set: a degraded read must never render as a
    // silent 0 that would misreport the fleet as compliant (mirrors the
    // pre-existing inline logic this replaces in rest_api_v1.cpp verbatim).
    auto rule_names_result = store.rule_names();
    auto errored_result = store.errored_rule_count(agent_scope);
    if (!rule_names_result || !errored_result)
        return std::nullopt;
    GuardianStatusRollup out;
    out.total_rules = static_cast<std::int64_t>(rule_names_result->size());
    out.compliant_rules = 0;
    out.drifted_rules = 0;
    out.errored_rules = static_cast<std::int64_t>(*errored_result);
    return out;
}

std::optional<GuardianAgentStatusRollup>
guardian_agent_status_rollup(GuaranteedStateStore& store, const std::string& agent_id) {
    // Mirrors the pre-existing inline logic in rest_api_v1.cpp's
    // GET /guaranteed-state/status/{agent_id} handler verbatim (#2146 Batch B1
    // extraction, same precedent as guardian_status_rollup's own #4037 header
    // comment) — REST and MCP cannot drift on this derivation by construction.
    auto statuses_result = store.agent_rule_statuses_for_agent(agent_id);
    if (!statuses_result)
        return std::nullopt;
    std::vector<std::string> rule_ids;
    rule_ids.reserve(statuses_result->size());
    for (const auto& st : *statuses_result)
        rule_ids.push_back(st.rule_id);
    auto rule_names_result = store.rule_names_for(rule_ids);
    if (!rule_names_result)
        return std::nullopt;
    const auto& rule_names = *rule_names_result;
    GuardianAgentStatusRollup out;
    for (const auto& st : *statuses_result) {
        if (!rule_names.count(st.rule_id))
            continue; // orphan census row for a since-deleted rule
        ++out.total_rules;
        if (st.state == "errored")
            ++out.errored_rules;
    }
    return out;
}

std::optional<std::vector<GuardianRuleAgentStatusRow>>
guardian_rule_agent_status_rows(GuaranteedStateStore& store, const std::string& rule_id) {
    auto statuses = store.agent_rule_statuses(rule_id);
    if (!statuses)
        return std::nullopt;
    std::vector<GuardianRuleAgentStatusRow> out;
    out.reserve(statuses->size());
    for (const auto& s : *statuses) {
        GuardianRuleAgentStatusRow row;
        row.agent_id = s.agent_id;
        row.state = s.state;
        row.updated_at = s.updated_at;
        out.push_back(std::move(row));
    }
    return out;
}

std::optional<std::vector<GuardianDeviceGuardRow>>
guardian_device_all_guards(GuaranteedStateStore& store, const std::string& agent_id) {
    auto statuses = store.agent_rule_statuses_for_agent(agent_id);
    if (!statuses)
        return std::nullopt;
    std::vector<std::string> rule_ids;
    rule_ids.reserve(statuses->size());
    for (const auto& s : *statuses)
        rule_ids.push_back(s.rule_id);
    auto names = store.rule_names_for(rule_ids);
    if (!names)
        return std::nullopt;
    std::vector<GuardianDeviceGuardRow> out;
    out.reserve(statuses->size());
    for (const auto& s : *statuses) {
        GuardianDeviceGuardRow row;
        row.rule_id = s.rule_id;
        const auto it = names->find(s.rule_id);
        row.name = (it != names->end() && !it->second.empty()) ? it->second : s.rule_id;
        row.state = s.state;
        row.updated_at = s.updated_at;
        out.push_back(std::move(row));
    }
    return out;
}

std::optional<GuardianDeviceComplianceRollup>
guardian_device_compliance_rollup(BaselineStore& baseline_store, GuaranteedStateStore& store,
                                  const std::string& baseline_name, const std::string& agent_id,
                                  bool* store_degraded, bool* pii_access_began) {
    *store_degraded = false;
    *pii_access_began = false;
    bool baseline_store_ok = true;
    const auto baseline = baseline_store.get_baseline_by_name(baseline_name, &baseline_store_ok);
    if (!baseline_store_ok) {
        // Pre-PII fault: no per-agent data has been touched yet, same
        // "no PII was looked up yet" posture this route has always had -
        // pii_access_began stays false, caller owes no audit row.
        *store_degraded = true;
        return std::nullopt;
    }
    if (!baseline)
        return std::nullopt; // genuinely no such baseline, not a fault

    // ADR-0055 catastrophic-read set: a degraded deployed_member_rule_ids
    // read must never render as an empty guard_ids that flows through as a
    // false-clean "0 guards, fully compliant" report for this baseline.
    // The baseline itself was found, so this and every read below counts as
    // having begun accessing this agent's per-baseline standing.
    *pii_access_began = true;
    auto guard_ids_result = baseline_store.deployed_member_rule_ids(baseline->baseline_id);
    if (!guard_ids_result) {
        *store_degraded = true;
        return std::nullopt;
    }
    const auto& guard_ids = *guard_ids_result;

    // ADR-0038 catastrophic-read set: this route's compliance counts are an
    // enforce-gate/census consumer - a degrade must never render as a silent
    // "0 guards reported" that would misreport the device as compliant.
    // agent_rule_statuses_for_agent is the behavioral-PII read proper - by
    // the time either of these two calls happens, the PII access has
    // already executed regardless of whether it degraded, so a failure
    // here MUST still be audited (pii_access_began is already true above).
    auto rule_names_result = store.rule_names_for(guard_ids);
    auto statuses_result = store.agent_rule_statuses_for_agent(agent_id);
    if (!rule_names_result || !statuses_result) {
        *store_degraded = true;
        return std::nullopt;
    }
    const auto& rule_names = *rule_names_result;

    std::unordered_map<std::string, GuardianAgentRuleStatus> dev;
    for (auto& st : *statuses_result)
        dev[st.rule_id] = std::move(st);

    GuardianDeviceComplianceRollup out;
    out.baseline_id = baseline->baseline_id;
    out.baseline_name = baseline->name;
    out.baseline_lifecycle = baseline->lifecycle;
    out.deployed = (baseline->lifecycle == kBaselineDeployed);
    out.snapshot_total = static_cast<std::int64_t>(guard_ids.size());

    // Report-driven device-applicable subset: emit ONLY the deployed-snapshot
    // members this device has actually reported a verdict for (guard_ids
    // order, so the emitted subset keeps a stable order).
    for (const auto& rid : guard_ids) {
        const auto it = dev.find(rid);
        if (it == dev.end())
            continue; // not applicable to this device
        ++out.total_guards;
        std::string status = "pending";
        const std::string& s = it->second.state;
        if (s == "compliant") { status = s; ++out.compliant; }
        else if (s == "drifted") { status = s; ++out.drifted; }
        else if (s == "errored") { status = s; ++out.errored; }
        const std::string& updated_at = it->second.updated_at;
        if (!updated_at.empty() && updated_at > out.last_updated)
            out.last_updated = updated_at;
        const auto nit = rule_names.find(rid);
        GuardianDeviceComplianceGuardRow row;
        row.rule_id = rid;
        row.name = (nit != rule_names.end() && !nit->second.empty()) ? nit->second : rid;
        row.status = status;
        row.updated_at = updated_at;
        out.guards.push_back(std::move(row));
    }
    out.pending = out.total_guards - (out.compliant + out.drifted + out.errored);
    return out;
}

} // namespace yuzu::server
