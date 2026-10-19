#pragma once

#include "step_up_policy.hpp"

#include <array>
#include <cstddef>
#include <iterator>
#include <string_view>
#include <vector>

/// @file step_up_mcp_policy.hpp
/// The MCP half of the MFA step-up policy: one row per MCP tool whose
/// `kToolSecurityRows` operation is not `Read` (mcp_server.cpp), keyed by tool name.
/// It is DATA ONLY at this stage: no MCP code path consults `kMcpStepUpPolicy`, and nothing
/// here changes what any tool call does. The REST table it is seeded from, the class and
/// reason vocabulary, and the pending-row discipline are `step_up_policy.hpp`'s; this file
/// reuses them and adds nothing that a second table would need to keep in step.
///
/// EXTEND this table, never fork it. A new non-Read tool needs a row here in the same change
/// (`test_mcp_step_up_policy.cpp` fails by tool name otherwise); a row for a tool that is
/// gone, or is now Read, is stale and fails the same test.
///
/// CLASSES in use: kExempt (reviewed, `reason` is one of `kMcpExemptReasons`) and
/// kPendingRuling (the one neutral literal, count pinned by `kMcpPendingRulingMax`, which may
/// only go DOWN). kRequired is accepted by the self-check but no row carries it yet.
///
/// TWIN: `rest_method`/`rest_pattern` name the REST route the tool mirrors, byte-for-byte as
/// registered, so the self-check can prove the twin exists in `kStepUpPolicy` and that the
/// tool is never classified weaker than its twin: a tool whose twin is kRequired or
/// kPendingRuling is itself kRequired or kPendingRuling, never kExempt. Both are empty for a
/// tool with no single REST route.
///
/// Self-checks (`consteval`, so a bad edit is a BUILD FAILURE): no duplicate tool name, every
/// kExempt reason from the named list, the pending literal on every kPendingRuling row, every
/// twin present in the REST table and not weaker than it, and the pending ceiling.

namespace yuzu::server {

struct McpStepUpPolicyEntry {
    std::string_view tool;
    StepUpClass cls;
    std::string_view reason;       // kExempt: one of kMcpExemptReasons; kPendingRuling: the pending literal
    std::string_view rest_method;  // "" when the tool has no single REST twin
    std::string_view rest_pattern; // EXACT registered pattern text of the twin
};

namespace step_up_mcp_detail {

/// An MCP-specific exempt class. The REST classes are reused as-is from `step_up_detail`.
inline constexpr std::string_view kReadOnlyOperation =
    "read-only operation: performs no mutation; classified as a write only by its gate";

/// The closed list of reasons a kExempt MCP row may carry. A new reason is a new constant in
/// `step_up_policy.hpp` (or above) AND an entry here: the class name is the review record.
inline constexpr std::array<std::string_view, 6> kMcpExemptReasons = {
    step_up_detail::kExecutionDispatch, step_up_detail::kOperationalData,
    step_up_detail::kSyncTrigger,       step_up_detail::kEvidenceCapture,
    step_up_detail::kStopsEffect,       kReadOnlyOperation,
};

[[nodiscard]] constexpr McpStepUpPolicyEntry exempt(std::string_view tool, std::string_view reason,
                                                    std::string_view rest_method = {},
                                                    std::string_view rest_pattern = {}) {
    return {tool, StepUpClass::kExempt, reason, rest_method, rest_pattern};
}

[[nodiscard]] constexpr McpStepUpPolicyEntry pending(std::string_view tool,
                                                     std::string_view rest_method,
                                                     std::string_view rest_pattern) {
    return {tool, StepUpClass::kPendingRuling, step_up_detail::kPendingReason, rest_method,
            rest_pattern};
}
} // namespace step_up_mcp_detail

// clang-format off
inline constexpr McpStepUpPolicyEntry kMcpStepUpPolicy[] = {
    // AccessReview:Attest
    step_up_mcp_detail::exempt ("open_access_review",                   step_up_detail::kEvidenceCapture,   "POST",   R"(/api/v1/access-reviews)"),
    step_up_mcp_detail::exempt ("record_attestation",                   step_up_detail::kEvidenceCapture,   "POST",   R"(/api/v1/access-reviews/([^/]+)/attestations)"),
    step_up_mcp_detail::exempt ("close_access_review",                  step_up_detail::kEvidenceCapture,   "POST",   R"(/api/v1/access-reviews/([^/]+)/close)"),
    // ApiToken:Delete / Rotate / Write
    step_up_mcp_detail::pending("revoke_api_token",                     "DELETE", R"(/api/v1/tokens/(.+))"),
    step_up_mcp_detail::pending("confirm_api_token_rotation",           "POST",   R"(/api/v1/tokens/([^/]+)/confirm)"),
    step_up_mcp_detail::pending("rotate_api_token",                     "POST",   R"(/api/v1/tokens/([^/]+)/rotate)"),
    step_up_mcp_detail::pending("create_api_token",                     "POST",   R"(/api/v1/tokens)"),
    // Approval:Write
    step_up_mcp_detail::pending("approve_request",                      "POST",   R"(/api/approvals/([^/]+)/approve)"),
    step_up_mcp_detail::pending("reject_request",                       "POST",   R"(/api/approvals/([^/]+)/reject)"),
    // Execution:Execute
    step_up_mcp_detail::exempt ("create_result_set_from_tar_query",     step_up_detail::kOperationalData,   "POST",   R"(/api/v1/result-sets/from-tar-query)"),
    step_up_mcp_detail::exempt ("create_result_set_from_instruction_result", step_up_detail::kOperationalData, "POST", R"(/api/v1/result-sets/from-instruction-result)"),
    step_up_mcp_detail::exempt ("execute_bundle",                       step_up_detail::kExecutionDispatch, "POST",   R"(/api/v1/bundles)"),
    step_up_mcp_detail::exempt ("execute_instruction",                  step_up_detail::kExecutionDispatch),
    step_up_mcp_detail::exempt ("reevaluate_result_set",                step_up_detail::kOperationalData,   "POST",   R"(/api/v1/result-sets/(rs_[0-9a-f]+)/re-eval)"),
    step_up_mcp_detail::exempt ("sync_hardware_software",               step_up_detail::kSyncTrigger,       "POST",   R"(/api/v1/hardware/sync)"),
    // GuaranteedState:Delete / Push / Write
    step_up_mcp_detail::pending("delete_guardian_rule",                 "DELETE", R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))"),
    step_up_mcp_detail::pending("push_guardian_rules",                  "POST",   R"(/api/v1/guaranteed-state/push)"),
    step_up_mcp_detail::pending("create_guardian_rule",                 "POST",   R"(/api/v1/guaranteed-state/rules)"),
    step_up_mcp_detail::pending("update_guardian_rule",                 "PUT",    R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))"),
    // Infrastructure:Delete / Write
    step_up_mcp_detail::exempt ("delete_result_set",                    step_up_detail::kOperationalData,   "DELETE", R"(/api/v1/result-sets/(rs_[0-9a-f]+))"),
    step_up_mcp_detail::pending("create_offload_target",                "POST",   R"(/api/v1/offload-targets)"),
    step_up_mcp_detail::exempt ("create_result_set",                    step_up_detail::kOperationalData,   "POST",   R"(/api/v1/result-sets)"),
    step_up_mcp_detail::pending("delete_offload_target",                "DELETE", R"(/api/v1/offload-targets/(\d+))"),
    step_up_mcp_detail::exempt ("pin_result_set",                       step_up_detail::kOperationalData,   "POST",   R"(/api/v1/result-sets/(rs_[0-9a-f]+)/pin)"),
    step_up_mcp_detail::exempt ("unpin_result_set",                     step_up_detail::kOperationalData,   "POST",   R"(/api/v1/result-sets/(rs_[0-9a-f]+)/unpin)"),
    // Inventory:Write
    step_up_mcp_detail::exempt ("create_result_set_from_inventory_query", step_up_detail::kOperationalData, "POST",   R"(/api/v1/result-sets/from-inventory-query)"),
    // License:Write
    step_up_mcp_detail::pending("activate_platform_license",            "POST",   R"(/api/v1/license)"),
    // ManagementGroup:Write
    step_up_mcp_detail::pending("add_management_group_member",          "POST",   R"(/api/v1/management-groups/([a-f0-9]+)/members)"),
    step_up_mcp_detail::pending("assign_management_group_role",         "POST",   R"(/api/v1/management-groups/([a-f0-9]+)/roles)"),
    step_up_mcp_detail::pending("create_management_group",              "POST",   R"(/api/v1/management-groups)"),
    step_up_mcp_detail::exempt ("preview_management_group_agent_count", step_up_mcp_detail::kReadOnlyOperation),
    step_up_mcp_detail::pending("update_management_group",              "PUT",    R"(/api/v1/management-groups/([a-f0-9]+))"),
    // PluginConfig:Delete / Write
    step_up_mcp_detail::pending("delete_plugin_config",                 "DELETE", R"(/api/v1/plugin-config/([^/]+)/([^/]+))"),
    step_up_mcp_detail::pending("set_plugin_config",                    "PUT",    R"(/api/v1/plugin-config/([^/]+)/([^/]+))"),
    step_up_mcp_detail::pending("set_plugin_kill_switch",               "PUT",    R"(/api/v1/plugin-config/([^/]+)/kill-switch)"),
    // PluginSecret:Delete / Write
    step_up_mcp_detail::pending("delete_plugin_secret",                 "DELETE", R"(/api/v1/plugin-config/([^/]+)/([^/]+)/secret)"),
    step_up_mcp_detail::pending("set_plugin_secret",                    "PUT",    R"(/api/v1/plugin-config/([^/]+)/([^/]+)/secret)"),
    // Security:Delete / Execute / Write
    step_up_mcp_detail::pending("revoke_certificate",                   "POST",   R"(/api/v1/ca/revoke)"),
    step_up_mcp_detail::pending("quarantine_device",                    "POST",   R"(/api/v1/quarantine)"),
    step_up_mcp_detail::pending("assign_engine_role",                   "POST",   R"(/api/v1/engine-principals/([a-z0-9._-]+)/roles)"),
    step_up_mcp_detail::pending("assign_rbac_role",                     "POST",   R"(/api/v1/rbac/roles/([A-Za-z0-9._-]+)/assignments)"),
    step_up_mcp_detail::pending("confirm_engine_rotation",              "POST",   R"(/api/v1/engine-principals/([^/]+)/credentials/confirm)"),
    step_up_mcp_detail::pending("create_engine_principal",              "POST",   R"(/api/v1/engine-principals)"),
    step_up_mcp_detail::pending("import_ca_chain",                      "POST",   R"(/api/v1/ca/import-chain)"),
    step_up_mcp_detail::pending("issue_code_signing_cert",              "POST",   R"(/api/v1/ca/issue-code-signing)"),
    step_up_mcp_detail::pending("mint_engine_credential",               "POST",   R"(/api/v1/engine-principals/([^/]+)/credentials)"),
    step_up_mcp_detail::pending("revoke_engine_principal",              "DELETE", R"(/api/v1/engine-principals/([^/]+))"),
    step_up_mcp_detail::pending("rewrap_secrets",                       "POST",   R"(/api/v1/secrets/kek/rewrap)"),
    step_up_mcp_detail::pending("rotate_engine_credential",             "POST",   R"(/api/v1/engine-principals/([^/]+)/credentials/rotate)"),
    step_up_mcp_detail::pending("rotate_kek",                           "POST",   R"(/api/v1/secrets/kek/rotate)"),
    step_up_mcp_detail::pending("set_rbac_enforcement",                 "PUT",    R"(/api/v1/rbac/enforcement)"),
    step_up_mcp_detail::pending("transfer_engine_principal_owner",      "POST",   R"(/api/v1/engine-principals/([^/]+)/transfer-owner)"),
    step_up_mcp_detail::pending("unassign_engine_role",                 "DELETE", R"(/api/v1/engine-principals/([a-z0-9._-]+)/roles/([^/]+))"),
    step_up_mcp_detail::pending("unassign_rbac_role",                   "DELETE", R"(/api/v1/rbac/roles/([A-Za-z0-9._-]+)/assignments/([A-Za-z0-9._-]+))"),
    // SoftwareDeployment:Execute
    step_up_mcp_detail::exempt ("cancel_software_deployment",           step_up_detail::kStopsEffect,       "POST",   R"(/api/v1/software-deployments/([a-f0-9]+)/cancel)"),
    step_up_mcp_detail::pending("create_software_deployment",           "POST",   R"(/api/v1/software-deployments)"),
    step_up_mcp_detail::pending("rollback_software_deployment",         "POST",   R"(/api/v1/software-deployments/([a-f0-9]+)/rollback)"),
    // Tag:Delete / Write
    step_up_mcp_detail::exempt ("delete_tag",                           step_up_detail::kOperationalData,   "DELETE", R"(/api/v1/tags/([^/]+)/([^/]+))"),
    step_up_mcp_detail::exempt ("set_tag",                              step_up_detail::kOperationalData,   "PUT",    R"(/api/v1/tags)"),
    // UploadGrant:Delete / Write
    step_up_mcp_detail::pending("revoke_upload_grant",                  "DELETE", R"(/api/v1/upload-grants/([a-f0-9]+))"),
    step_up_mcp_detail::pending("mint_upload_grant",                    "POST",   R"(/api/v1/upload-grants)"),
    // UserManagement:Write
    step_up_mcp_detail::pending("unlock_account",                       "POST",   R"(/api/v1/users/([^/]+)/unlock)"),
};
// clang-format on

/// Ceiling on the number of kPendingRuling MCP rows. May only be LOWERED: a new tool cannot be
/// parked as pending, it needs a real class.
inline constexpr std::size_t kMcpPendingRulingMax = 44;

inline constexpr std::size_t kMcpStepUpPolicyCount = std::size(kMcpStepUpPolicy);

/// Exact tool-name lookup. Returns nullptr when `tool_name` has no row.
[[nodiscard]] constexpr const McpStepUpPolicyEntry* mcp_step_up_policy_for(std::string_view tool_name) {
    for (const auto& e : kMcpStepUpPolicy) {
        if (e.tool == tool_name)
            return &e;
    }
    return nullptr;
}

/// Of `non_read_tools` (every tool whose security-row operation is not `Read`), the ones with
/// no row in the table. Pure. A future boot-time validation consumes this same function.
[[nodiscard]] inline std::vector<std::string_view>
mcp_step_up_unclassified_tools(const std::vector<std::string_view>& non_read_tools) {
    std::vector<std::string_view> missing;
    for (const auto tool : non_read_tools) {
        if (mcp_step_up_policy_for(tool) == nullptr)
            missing.push_back(tool);
    }
    return missing;
}

/// The table's rows whose tool is not in `non_read_tools`: a tool that was removed or became
/// Read leaves a stale row. Pure.
[[nodiscard]] inline std::vector<std::string_view>
mcp_step_up_stale_rows(const std::vector<std::string_view>& non_read_tools) {
    std::vector<std::string_view> stale;
    for (const auto& e : kMcpStepUpPolicy) {
        bool found = false;
        for (const auto tool : non_read_tools) {
            if (tool == e.tool) {
                found = true;
                break;
            }
        }
        if (!found)
            stale.push_back(e.tool);
    }
    return stale;
}

namespace step_up_mcp_detail {

[[nodiscard]] constexpr bool is_listed_exempt_reason(std::string_view reason) {
    for (const auto r : kMcpExemptReasons) {
        if (r == reason)
            return true;
    }
    return false;
}

[[nodiscard]] consteval bool table_is_well_formed() {
    std::size_t pending_rows = 0;
    for (std::size_t i = 0; i < kMcpStepUpPolicyCount; ++i) {
        const auto& a = kMcpStepUpPolicy[i];
        if (a.tool.empty())
            return false;
        if (a.cls != StepUpClass::kRequired && a.cls != StepUpClass::kExempt &&
            a.cls != StepUpClass::kPendingRuling)
            return false;
        if (a.cls == StepUpClass::kExempt && !is_listed_exempt_reason(a.reason))
            return false;
        if (a.cls == StepUpClass::kPendingRuling) {
            ++pending_rows;
            if (a.reason != step_up_detail::kPendingReason)
                return false;
        }
        // The twin is both-or-neither, must exist in the REST table, and the tool is never
        // weaker than it.
        if (a.rest_method.empty() != a.rest_pattern.empty())
            return false;
        if (!a.rest_method.empty()) {
            const auto* twin = step_up_policy_for(a.rest_method, a.rest_pattern);
            if (twin == nullptr)
                return false;
            const bool twin_gates_or_pending = twin->cls == StepUpClass::kRequired ||
                                               twin->cls == StepUpClass::kPendingRuling;
            if (twin_gates_or_pending && a.cls == StepUpClass::kExempt)
                return false;
        }
        for (std::size_t j = i + 1; j < kMcpStepUpPolicyCount; ++j) {
            if (a.tool == kMcpStepUpPolicy[j].tool)
                return false; // duplicate tool
        }
    }
    return pending_rows <= kMcpPendingRulingMax;
}

[[nodiscard]] consteval std::size_t count_class(StepUpClass c) {
    std::size_t n = 0;
    for (const auto& e : kMcpStepUpPolicy)
        n += (e.cls == c) ? 1 : 0;
    return n;
}

} // namespace step_up_mcp_detail

static_assert(step_up_mcp_detail::table_is_well_formed(),
              "step_up_mcp_policy.hpp: duplicate tool, unlisted exempt reason, wrong pending "
              "literal, a twin missing from the REST table or exempt where its twin is not, or "
              "more kPendingRuling rows than kMcpPendingRulingMax");
static_assert(step_up_mcp_detail::count_class(StepUpClass::kRequired) == 0,
              "no MCP consumer evaluates kRequired rows yet");

} // namespace yuzu::server
