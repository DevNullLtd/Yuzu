// Shared MCP/REST twin table: the (tool, securable, operation, is_read) row each served MCP
// twin must carry, pinned against its REST counterpart's gate.
//
// Consumers: test_operator_surface_twins.cpp binds every row to the served security map, the
// write-tool set and the A5 contract; test_twin_completeness.cpp requires every registry tool to
// have a row, so a new registry tool cannot ship without one (docs/api-twin-recipe.md).
#pragma once

#include <string_view>

namespace yuzu::server::twin_table {

struct TwinRow {
    std::string_view tool;
    std::string_view securable;
    std::string_view operation;
    bool is_read;
};

// Pinned against plugin_config_routes.hpp's / file_retrieval_routes.hpp's
// documented REST route tables - the SAME (securable, operation) each REST
// handler gates on (see those headers' file-header route tables).
inline constexpr TwinRow kExpectedTwins[] = {
    {"get_plugin_config", "PluginConfig", "Read", true},
    {"list_plugin_config", "PluginConfig", "Read", true},
    {"set_plugin_config", "PluginConfig", "Write", false},
    {"delete_plugin_config", "PluginConfig", "Delete", false},
    {"set_plugin_secret", "PluginSecret", "Write", false},
    {"delete_plugin_secret", "PluginSecret", "Delete", false},
    {"get_plugin_kill_switch", "PluginConfig", "Read", true},
    {"set_plugin_kill_switch", "PluginConfig", "Write", false},
    {"mint_upload_grant", "UploadGrant", "Write", false},
    {"list_upload_grants", "UploadGrant", "Read", true},
    {"revoke_upload_grant", "UploadGrant", "Delete", false},
    // #4036 (api-parity Batch A) - pinned against preflight_routes.cpp's /
    // deployment_routes.cpp's new GET /api/v1/preflight/runs / GET
    // /api/v1/deployments/preview handlers (same (securable, operation) each
    // REST twin gates on).
    {"list_preflight_runs", "Infrastructure", "Read", true},
    {"get_deployment_preview", "SoftwareDeployment", "Read", true},
    {"list_deployments", "SoftwareDeployment", "Read", true},
    {"get_deployment", "SoftwareDeployment", "Read", true},
    // Estate E-2: the discovered-devices read twin, pinned against the REST
    // GET /api/v1/network/discovered-devices gate in network_routes.cpp.
    {"list_discovered_devices", "Infrastructure", "Read", true},
    // The MCP twin of POST /api/v1/hardware/sync (same Execution:Execute gate).
    {"sync_hardware_software", "Execution", "Execute", false},
    // #4030: executions/workflows/schedules read-twin programme.
    {"list_workflows", "Workflow", "Read", true},
    {"get_workflow", "Workflow", "Read", true},
    {"get_workflow_execution", "Workflow", "Read", true},
    {"list_workflow_executions", "Workflow", "Read", true},
    // #2146 A2-R1 - pinned against the new GET /api/v1/executions/{id}/children
    // (rest_api_v1.cpp) and legacy GET /api/executions/{id}/children
    // (execution_routes.cpp) handlers' shared (securable, operation) gate.
    {"get_execution_children", "Execution", "Read", true},
    // #4029 (api-parity Batch A content/catalog half): instruction-definition
    // read twins, pinned against instruction_definition_model.hpp / the new
    // GET /api/v1/instructions* routes (rest_api_v1.cpp).
    {"list_definitions", "InstructionDefinition", "Read", true},
    {"get_definition", "InstructionDefinition", "Read", true},
    {"export_definition", "InstructionDefinition", "Read", true},
    // #4029: product-pack read twins, pinned against product_pack_model.hpp /
    // the new GET /api/v1/product-packs* routes.
    {"list_product_packs", "ProductPack", "Read", true},
    {"get_product_pack", "ProductPack", "Read", true},
    // #4027 - Echo process-tree/capture-sources/retention-paused read twins.
    // Same Infrastructure:Read gate as GET /fragments/echo/process-tree,
    // .../capture-sources, .../retention-paused (echo_tree_routes.cpp /
    // dashboard_routes.cpp).
    {"list_echo_process_tree_devices", "Infrastructure", "Read", true},
    {"list_echo_capture_sources_devices", "Infrastructure", "Read", true},
    {"list_echo_retention_paused", "Infrastructure", "Read", true},
    // #4031: directory-sync (AD/Entra) read twin - parity with GET
    // /api/v1/directory/users. The OIDC-config, auto-approve-rules, and
    // pending-agents read twins are REST-only per #520 (see
    // docs/mcp-server.md) and so carry no MCP tool, no row here.
    //
    // get_directory_status (the /directory/status twin) is deliberately NOT
    // listed here even though it shares Directory:Read: it takes no input
    // parameters, so its schema is the honest, bounded
    // {"type":"object","properties":{}} shape - same precedent as
    // get_guardian_schemas above, also absent from this array for the same
    // reason (the A5 sweep below asserts every LISTED tool's schema differs
    // from that literal, which is correct for this curated list but not a
    // universal rule; validate_tool_security_registration's boot-time check
    // is what proves get_directory_status's own table entries are
    // consistent, and test_mcp_server.cpp exercises its dispatch directly).
    {"list_directory_users", "Directory", "Read", true},
    // #4033 (#2146 Batch A) - pinned against
    // /fragments/create-group-form's own ManagementGroup:Write gate
    // (dashboard_routes.cpp) and its REST twin GET /api/v1/management-groups/
    // agent-count-preview (rest_api_v1.cpp).
    {"preview_management_group_agent_count", "ManagementGroup", "Write", false},
    // #4034 - compliance/policy REST v1 read twins.
    {"get_policy", "Policy", "Read", true},
    {"list_policy_fragments", "Policy", "Read", true},
    {"get_policy_agent_statuses", "Policy", "Read", true},
    // #4035 (api-parity #2146 Batch A): MCP-only gaps closing the REST-only
    // twins for /fragments/device/dex and /fragments/dex/device/app-perf -
    // see docs/api-twin-recipe.md §6/§7/§8, which directs a twin PR to extend
    // this array (not only the plugin-config/upload-grant families the
    // header comment above was originally pinned against).
    {"get_dex_device_score", "GuaranteedState", "Read", true},
    {"get_dex_device_app_perf", "GuaranteedState", "Read", true},
    // #4035: the 8 genuinely-new REST+MCP twins from the same issue.
    {"get_dex_app", "GuaranteedState", "Read", true},
    {"list_dex_apps", "GuaranteedState", "Read", true},
    // ADR-0031 WS-A4 PR-1: the Catalogue View 1 REST+MCP
    // twin, pinned against GET /api/v1/dex/catalogue (rest_api_v1.cpp).
    {"get_dex_catalogue", "GuaranteedState", "Read", true},
    {"get_dex_catalogue_group", "GuaranteedState", "Read", true},
    {"get_dex_device_history", "GuaranteedState", "Read", true},
    {"get_dex_observation", "GuaranteedState", "Read", true},
    {"get_dex_health", "GuaranteedState", "Read", true},
    {"get_dex_trends", "GuaranteedState", "Read", true},
    {"get_dex_overview", "GuaranteedState", "Read", true},
    // #4037 - Guardian read twins (api-parity #2146 Batch A). Pinned against
    // rest_api_v1.cpp's /api/v1/guaranteed-state/{status,rules,events,
    // rules/{id}/status,agents/{id}/rules} routes.
    {"get_guardian_status", "GuaranteedState", "Read", true},
    {"list_guardian_rules", "GuaranteedState", "Read", true},
    {"list_guardian_events", "GuaranteedState", "Read", true},
    {"get_guardian_rule_status", "GuaranteedState", "Read", true},
    {"get_guardian_device_guards", "GuaranteedState", "Read", true},
    // The read-only twin of raise_guardian_policy_generation, pinned against GET
    // /api/v1/guaranteed-state/policy-generation (the same GuaranteedState:Read gate).
    {"get_guardian_policy_generation", "GuaranteedState", "Read", true},
    // #2146 Batch B2 - result-set MCP twins, pinned against rest_api_v1.cpp's
    // 12-operation REST v1 result-set API (docs/scope-walking-design.md).
    // The three async dispatch producers + reevaluate share
    // execute_instruction's own Execution:Execute pair; the rest are owner-
    // scoped, no RBAC gate in the handler (Infrastructure:Read/Write/Delete
    // drive MCP tier classification only, matching validate_scope's own
    // precedent of a registered pair with no backing perm_fn call).
    //
    // create_result_set_from_inventory_query is DELIBERATELY NOT listed here:
    // its real RBAC gate is a genuine perm_fn(Inventory, Read) call (matching
    // the REST twin exactly - see that tool's own permission-denied test),
    // but its kToolSecurityRows/kWriteTools registration is Inventory:WRITE,
    // because the tool genuinely creates a new result set (a write) and
    // readOnlyHint/kWriteTools classification must stay truthful regardless
    // of which permission happens to gate the read half of the work. This
    // array's contract ("REST and MCP gate on the SAME securable/operation")
    // does not hold for this one tool by design, so pinning it here would
    // assert something false in one direction or fail in the other.
    {"list_result_sets", "Infrastructure", "Read", true},
    {"create_result_set", "Infrastructure", "Write", false},
    {"create_result_set_from_echo_query", "Execution", "Execute", false},
    {"create_result_set_from_instruction_result", "Execution", "Execute", false},
    {"reevaluate_result_set", "Execution", "Execute", false},
    {"get_result_set", "Infrastructure", "Read", true},
    {"get_result_set_members", "Infrastructure", "Read", true},
    {"get_result_set_lineage", "Infrastructure", "Read", true},
    {"pin_result_set", "Infrastructure", "Write", false},
    {"unpin_result_set", "Infrastructure", "Write", false},
    {"delete_result_set", "Infrastructure", "Delete", false},
    // #2146 Batch B3 (api-parity programme) - execution/fleet statistics +
    // fleet visualization read twins. Pinned against rest_api_v1.cpp's
    // GET /api/v1/execution-statistics{,/agents,/definitions} + GET
    // /api/v1/statistics, and viz_routes.cpp's GET /api/v1/viz/fleet/topology
    // + GET /api/v1/viz/host/{id}/topology - the SAME (securable, operation)
    // each REST twin gates on.
    {"get_execution_statistics", "Execution", "Read", true},
    {"get_execution_statistics_by_agent", "Execution", "Read", true},
    {"get_execution_statistics_by_definition", "Execution", "Read", true},
    {"get_fleet_statistics", "Infrastructure", "Read", true},
    {"get_fleet_topology", "Response", "Read", true},
    {"get_host_topology", "Response", "Read", true},
    // #2146 Batch B5 - offload targets, CA root-CSR export/subordinate-chain
    // import, platform license, and software deployments. Pinned against
    // offload_routes.cpp / ca_routes.cpp / rest_api_v1.cpp's own gates.
    {"list_offload_targets", "Infrastructure", "Read", true},
    {"create_offload_target", "Infrastructure", "Write", false},
    {"get_offload_target", "Infrastructure", "Read", true},
    {"delete_offload_target", "Infrastructure", "Write", false},
    {"list_offload_target_deliveries", "Infrastructure", "Read", true},
    {"export_ca_root_csr", "Security", "Read", true},
    {"import_ca_chain", "Security", "Write", false},
    {"get_platform_license", "License", "Read", true},
    {"activate_platform_license", "License", "Write", false},
    {"list_license_alerts", "License", "Read", true},
    {"list_software_deployments", "SoftwareDeployment", "Read", true},
    {"create_software_deployment", "SoftwareDeployment", "Execute", false},
    {"rollback_software_deployment", "SoftwareDeployment", "Execute", false},
    {"cancel_software_deployment", "SoftwareDeployment", "Execute", false},
    // Wave 7 PR7.2 - app-usage read surface. Pinned against
    // app_usage_routes.cpp's own gate (GET /api/v1/forensics/agents/{id}/
    // app-usage), same (securable, operation) the MCP twin enforces.
    {"get_agent_app_usage", "Forensics", "Read", true},
    // #2146 A2-R4 (review finding, PR #4656) - approval-review read twins.
    // Pinned against rest_api_v1.cpp's GET /api/v1/approvals and GET
    // /api/v1/approvals/pending/count, same Approval:Read gate the MCP
    // twins' tier_allows/perm_fn calls enforce.
    {"list_pending_approvals", "Approval", "Read", true},
    {"get_pending_approval_count", "Approval", "Read", true},
    // M.9 software catalogue twins, pinned against
    // GET /api/v1/inventory/software/catalogue{,/versions} (rest_api_v1.cpp): the same
    // Inventory:Read gate the REST routes take through require_fleet_read.
    {"query_software_catalogue", "Inventory", "Read", true},
    {"get_software_versions", "Inventory", "Read", true},
    // /crypto slice 1 twins, pinned against GET /api/v1/crypto/libraries{,/devices}
    // (crypto_routes.cpp): the same Inventory:Read gate through fleet_read_fn.
    {"get_crypto_libraries", "Inventory", "Read", true},
    {"list_crypto_library_devices", "Inventory", "Read", true},
    {"export_crypto_cbom", "Inventory", "Read", true},
    // The hardware CI twins, pinned against GET /api/v1/hardware{,/{id}} (hardware_routes.cpp): the
    // same Inventory:Read gate through fleet_read_fn.
    {"list_hardware_ci", "Inventory", "Read", true},
    {"get_hardware_ci", "Inventory", "Read", true},
    // Seam PR2: list_quarantined_devices, pinned against GET /api/v1/quarantine
    // (rest_api_v1.cpp): the same Security:Read gate through require_fleet_read.
    {"list_quarantined_devices", "Security", "Read", true},
    // /crypto dashboard widget twins (ADR-0070 D13, R2). The Yuzu-issued counts are pinned
    // against GET /api/v1/crypto/ca/stats (crypto_routes.cpp), which gates on fleet_read_fn
    // Inventory:Read and withholds a confined caller; the rows behind them are list_issued_certs'
    // filtered form (Security:Read, the CA family's row). The catalogue and the caller's OWN
    // layout follow the owner-scoped result-set rows above: Infrastructure Read/Write is the MCP
    // tier class, and both transports key the layout by the session user with no RBAC securable
    // (the REST layout routes apply the same tier belt and refuse a service-scoped token).
    {"list_crypto_widgets", "Infrastructure", "Read", true},
    {"get_crypto_dashboard_layout", "Infrastructure", "Read", true},
    {"set_crypto_dashboard_layout", "Infrastructure", "Write", false},
    {"get_crypto_ca_stats", "Inventory", "Read", true},
    // Runtime configuration: GET/PUT /api/v1/config gate on Infrastructure Read/Write, as the legacy
    // /api/config routes do. The per-key administrator-only refusal is config::write_refusal's.
    {"get_runtime_config", "Infrastructure", "Read", true},
    {"set_runtime_config", "Infrastructure", "Write", false},
    // get_me, the twin of GET /api/v1/me (ledger row get.api-me). The REST route has no
    // permission gate (auth_fn only), so this row pins the MCP side alone:
    // Infrastructure:Read drives MCP tier classification only, with no RBAC check behind it
    // (the check_permission pattern), and a service-scoped token is refused at the generic
    // MCP gate. No arguments, so it is a kNoArgTools entry in test_operator_surface_twins.cpp.
    {"get_me", "Infrastructure", "Read", true},
};

} // namespace yuzu::server::twin_table
