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
/// kPendingRuling (the one neutral literal). The pending rows are two sets:
///   - the BASELINE: the frozen set of pending tools, i.e. every pending row that is not on the
///     second list. Its count is pinned by `kMcpPendingBaselineMax`, which only goes down; the
///     test file pins its identity too.
///   - the SECOND LIST, `kMcpPendingBecauseRestTwinRequired`: tools added AFTER the baseline was
///     frozen. It is legal only for a tool whose REST twin is kRequired (a `consteval` check
///     below proves the twin in the REST table), so a new tool cannot be parked as pending unless
///     it is forced to be; anything else must be classified kExempt.
/// Every pending tool whose REST twin is kRequired (on either set) is pending because no MCP
/// consumer enforces kRequired yet; its MCP class needs a maintainer ruling once one exists.
/// kRequired is accepted by the self-check but no row carries it.
///
/// TWIN: `rest_method`/`rest_pattern` name the REST route the tool mirrors, byte-for-byte as
/// registered, so the self-check can prove the twin exists in `kStepUpPolicy` and that the
/// tool is never classified weaker than its twin: a tool whose twin is kRequired or
/// kPendingRuling is itself kRequired or kPendingRuling, never kExempt. Both are empty for a
/// tool with no single REST route.
///
/// Self-checks (`consteval`, so a bad edit is a BUILD FAILURE): no duplicate tool name, every
/// kExempt reason from the named list, the pending literal on every kPendingRuling row, every
/// twin present in the REST table and not weaker than it, the baseline ceiling, and the
/// second list (every entry a pending row whose REST twin is kRequired, none repeated).

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
    step_up_mcp_detail::exempt ("set_crypto_dashboard_layout",          step_up_detail::kOperationalData,   "PUT",    R"(/api/v1/crypto/dashboard/layout)"),
    // On kMcpPendingBecauseRestTwinRequired: the twin is kRequired (an administrator can write the plugin-signing and audit-retention keys through it).
    step_up_mcp_detail::pending("set_runtime_config",                   "PUT",    R"(/api/v1/config/([a-z_]+))"),
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
    // On kMcpPendingBecauseRestTwinRequired: added after the baseline was frozen; the twin is kRequired.
    step_up_mcp_detail::pending("raise_guardian_policy_generation",     "POST",   R"(/api/v1/guaranteed-state/policy-generation/raise)"),
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

/// Ceiling on the BASELINE pending rows: the frozen set of kPendingRuling rows that are not on
/// `kMcpPendingBecauseRestTwinRequired`. It only goes down: a new tool cannot be parked as
/// pending, it needs a real class.
inline constexpr std::size_t kMcpPendingBaselineMax = 44;

/// Tools added AFTER the baseline was frozen that are kPendingRuling because their REST twin is
/// kRequired and no MCP consumer enforces kRequired yet. Each entry must be a pending row whose
/// twin resolves to a kRequired REST row (`second_list_is_valid`), so a tool whose twin is not
/// kRequired cannot be listed here and must be kExempt. Many baseline tools also have a kRequired
/// twin; this list is not the only such group. The class of these entries needs a maintainer
/// ruling once an MCP step-up consumer exists. Sorted, unique.
inline constexpr std::array<std::string_view, 2> kMcpPendingBecauseRestTwinRequired = {
    "raise_guardian_policy_generation",
    "set_runtime_config",
};

/// True when `tool` is on `kMcpPendingBecauseRestTwinRequired`.
[[nodiscard]] constexpr bool mcp_pending_because_rest_twin_required(std::string_view tool) {
    for (const auto t : kMcpPendingBecauseRestTwinRequired) {
        if (t == tool)
            return true;
    }
    return false;
}

inline constexpr std::size_t kMcpStepUpPolicyCount = std::size(kMcpStepUpPolicy);

namespace step_up_mcp_detail {
/// Slots of the tool-name index a check builds locally; kept at least 3x the row count.
inline constexpr std::size_t kMcpKeySlots = 256;
} // namespace step_up_mcp_detail
static_assert(kMcpStepUpPolicyCount * 3 <= step_up_mcp_detail::kMcpKeySlots,
              "step_up_mcp_policy.hpp: the table outgrew its tool-name index; raise kMcpKeySlots "
              "(a power of two) and re-measure the checks with -fconstexpr-ops-limit");

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

/// What one row must satisfy on its own (its twin, if any, is checked by `twins_are_valid`).
[[nodiscard]] constexpr bool row_is_well_formed(const McpStepUpPolicyEntry& a) {
    if (a.tool.empty())
        return false;
    if (a.cls != StepUpClass::kRequired && a.cls != StepUpClass::kExempt &&
        a.cls != StepUpClass::kPendingRuling)
        return false;
    if (a.cls == StepUpClass::kExempt && !is_listed_exempt_reason(a.reason))
        return false;
    if (a.cls == StepUpClass::kPendingRuling && a.reason != step_up_detail::kPendingReason)
        return false;
    // The twin is both-or-neither.
    return a.rest_method.empty() == a.rest_pattern.empty();
}

// COMPILE-TIME COST: see the same heading in step_up_policy.hpp. The checks below avoid its
// quadratic shape the same way: one local open-addressing index per check (reusing
// `step_up_detail::sample_hash` / `key_hash`), never a scan of the REST table per row.

[[nodiscard]] consteval bool rows_are_well_formed() {
    for (std::size_t i = 0; i < kMcpStepUpPolicyCount; ++i) {
        if (!row_is_well_formed(kMcpStepUpPolicy[i]))
            return false;
    }
    return true;
}

[[nodiscard]] consteval bool tool_names_are_unique() {
    unsigned short slot[kMcpKeySlots] = {};
    for (std::size_t i = 0; i < kMcpStepUpPolicyCount; ++i) {
        const auto& e = kMcpStepUpPolicy[i];
        std::size_t h = step_up_detail::sample_hash(e.tool) & (kMcpKeySlots - 1);
        while (slot[h] != 0) {
            if (kMcpStepUpPolicy[slot[h] - 1].tool == e.tool)
                return false; // duplicate tool
            h = (h + 1) & (kMcpKeySlots - 1);
        }
        slot[h] = static_cast<unsigned short>(i + 1);
    }
    return true;
}

/// For rows [Begin, End): the twin exists in the REST table, and the tool is never weaker than it.
/// Building the REST index dominates the cost, so the rows are split across evaluations that each
/// rebuild it (see the heading above).
template <std::size_t Begin, std::size_t End>
[[nodiscard]] consteval bool twins_are_valid() {
    unsigned short slot[step_up_detail::kKeySlots] = {};
    constexpr std::size_t kMask = step_up_detail::kKeySlots - 1;
    for (std::size_t i = 0; i < kStepUpPolicyCount; ++i) {
        const auto& e = kStepUpPolicy[i];
        std::size_t h = step_up_detail::key_hash(e.method, e.pattern) & kMask;
        while (slot[h] != 0)
            h = (h + 1) & kMask;
        slot[h] = static_cast<unsigned short>(i + 1);
    }
    for (std::size_t i = Begin; i < End && i < kMcpStepUpPolicyCount; ++i) {
        const auto& a = kMcpStepUpPolicy[i];
        if (a.rest_method.empty())
            continue;
        // The matched REST row is tracked by INDEX, never by a pointer compared with nullptr: under
        // `-fsanitize=null` (GCC) a null check on a pointer into the constexpr table is not a
        // constant expression, which fails the `static_assert`s below on the sanitizer legs.
        int found = -1;
        std::size_t h = step_up_detail::key_hash(a.rest_method, a.rest_pattern) & kMask;
        while (slot[h] != 0 && found < 0) {
            const std::size_t idx = slot[h] - 1;
            const auto& e = kStepUpPolicy[idx];
            if (e.method == a.rest_method && e.pattern == a.rest_pattern)
                found = static_cast<int>(idx);
            h = (h + 1) & kMask;
        }
        if (found < 0)
            return false;
        const StepUpPolicyEntry& twin = kStepUpPolicy[static_cast<std::size_t>(found)];
        const bool twin_gates_or_pending =
            twin.cls == StepUpClass::kRequired || twin.cls == StepUpClass::kPendingRuling;
        if (twin_gates_or_pending && a.cls == StepUpClass::kExempt)
            return false;
    }
    return true;
}

/// The baseline pending rows (pending and not on the second list) are within the ceiling.
[[nodiscard]] consteval bool baseline_pending_rows_within_ceiling() {
    std::size_t baseline_rows = 0;
    for (const auto& e : kMcpStepUpPolicy) {
        if (e.cls == StepUpClass::kPendingRuling && !mcp_pending_because_rest_twin_required(e.tool))
            ++baseline_rows;
    }
    return baseline_rows <= kMcpPendingBaselineMax;
}

/// Every second-list entry is a kPendingRuling row whose REST twin resolves to a kRequired row,
/// and none is listed twice. A twin missing from the REST table, or classed anything but
/// kRequired, fails here, so the list cannot become a general parking lot.
[[nodiscard]] consteval bool second_list_is_valid() {
    for (std::size_t i = 0; i < kMcpPendingBecauseRestTwinRequired.size(); ++i) {
        const auto tool = kMcpPendingBecauseRestTwinRequired[i];
        for (std::size_t j = 0; j < i; ++j) {
            if (kMcpPendingBecauseRestTwinRequired[j] == tool)
                return false; // duplicate entry
        }
        // Rows are found by INDEX, never by a pointer compared with nullptr (see `twins_are_valid`).
        int row = -1;
        for (std::size_t k = 0; k < kMcpStepUpPolicyCount && row < 0; ++k) {
            if (kMcpStepUpPolicy[k].tool == tool)
                row = static_cast<int>(k);
        }
        if (row < 0)
            return false;
        const auto& r = kMcpStepUpPolicy[static_cast<std::size_t>(row)];
        if (r.cls != StepUpClass::kPendingRuling || r.rest_method.empty())
            return false;
        int twin = -1;
        for (std::size_t k = 0; k < kStepUpPolicyCount && twin < 0; ++k) {
            if (kStepUpPolicy[k].method == r.rest_method && kStepUpPolicy[k].pattern == r.rest_pattern)
                twin = static_cast<int>(k);
        }
        if (twin < 0 || kStepUpPolicy[static_cast<std::size_t>(twin)].cls != StepUpClass::kRequired)
            return false;
    }
    return true;
}

[[nodiscard]] consteval std::size_t count_class(StepUpClass c) {
    std::size_t n = 0;
    for (const auto& e : kMcpStepUpPolicy)
        n += (e.cls == c) ? 1 : 0;
    return n;
}

} // namespace step_up_mcp_detail

static_assert(step_up_mcp_detail::rows_are_well_formed(),
              "step_up_mcp_policy.hpp: an empty tool name, an unlisted exempt reason, a wrong pending "
              "literal, or a twin with only one of method/pattern");
static_assert(step_up_mcp_detail::tool_names_are_unique(),
              "step_up_mcp_policy.hpp: duplicate tool name");
static_assert(step_up_mcp_detail::twins_are_valid<0, 21>(),
              "step_up_mcp_policy.hpp: a twin (rows 0-20) missing from the REST table, or a tool "
              "exempt where its twin is not");
static_assert(step_up_mcp_detail::twins_are_valid<21, 42>(),
              "step_up_mcp_policy.hpp: a twin (rows 21-41) missing from the REST table, or a tool "
              "exempt where its twin is not");
static_assert(step_up_mcp_detail::twins_are_valid<42, step_up_mcp_detail::kMcpKeySlots / 3>(),
              "step_up_mcp_policy.hpp: a twin (rows 42-end) missing from the REST table, or a tool "
              "exempt where its twin is not");
static_assert(step_up_mcp_detail::baseline_pending_rows_within_ceiling(),
              "step_up_mcp_policy.hpp: more baseline kPendingRuling rows than kMcpPendingBaselineMax "
              "(a pending row that is not on kMcpPendingBecauseRestTwinRequired)");
static_assert(step_up_mcp_detail::second_list_is_valid(),
              "step_up_mcp_policy.hpp: a kMcpPendingBecauseRestTwinRequired entry that is repeated, is "
              "not a kPendingRuling row, or whose REST twin is missing or not kRequired");
static_assert(step_up_mcp_detail::count_class(StepUpClass::kRequired) == 0,
              "no MCP consumer evaluates kRequired rows yet");

} // namespace yuzu::server
