#include "mcp_orientation.hpp"

#include <array>

namespace yuzu::server::mcp {

// ── Static orientation text ──────────────────────────────────────────────────
//
// Moved verbatim from the former inline literals in the mcp_server.cpp
// resources/read arms so the resource bytes are unchanged. Product copy; do not
// rewrite here to satisfy a style preference (the em-dash below is pre-existing
// primer text, kept byte-identical for the single-source guarantee).

std::string_view about_text() {
    return "# Yuzu\n\n"
           "Yuzu is an agentic enterprise endpoint management control plane for "
           "Windows, Linux, and macOS fleets. Through MCP, an LLM can inspect fleet "
           "state, inventory, compliance, command responses, audit evidence, DEX "
           "signals, and network posture.\n\n"
           "Safe operating rules: classify the question first; read existing facts "
           "before dispatch; narrow scope before action; use dry-run/read-only probes "
           "where possible; request explicit approval before remediation; label "
           "connector gaps honestly.\n\n"
           "Engine-principal management (create/list/get/revoke/mint/rotate/transfer-"
           "owner engine principals, plus a no-admin audit) is a supervised-tier, "
           "human-admin-only surface for provisioning the durable identities behind "
           "autonomous use-case-engine modules — engine-classed sessions are structurally "
           "barred from calling it, and every mutation is approval-gated.";
}

std::string_view operating_model_text() {
    return "Recommended MCP workflow: classify the question, identify connector gaps, "
           "read high-level posture, narrow scope by cohort/site/OS/management group, "
           "prefer existing responses and inventory, use live dispatch only for "
           "read-only probes, request approval for mutation, execute with the smallest "
           "safe scope, then monitor responses/audit/events.";
}

// ── Tool-family enumeration ──────────────────────────────────────────────────
//
// The union of every family's `tools` list is exactly the kTools[] set. This is
// asserted mechanically by the family-tether test against the live tools/list
// output, so a new tool with no family assignment (or a family dropped from the
// blob) is a test FAILURE, not a review miss. Keep names in kTools[] order.

namespace {

constexpr std::string_view kFleet[] = {"list_agents", "get_agent_details"};
constexpr std::string_view kTags[] = {"get_tags", "search_agents_by_tag", "set_tag", "delete_tag"};
// #4029: export_definition joins the family — same domain, same securable.
constexpr std::string_view kDefinitions[] = {"list_definitions", "get_definition",
                                             "export_definition", "list_schedules"};
// #4029: product packs are a distinct catalog domain (installed bundles of
// InstructionDefinition/PolicyFragment/Policy/Workflow documents), own
// securable (ProductPack), own family.
constexpr std::string_view kProductPacks[] = {"list_product_packs", "get_product_pack"};
constexpr std::string_view kResponses[] = {"query_responses", "aggregate_responses"};
// #2146 A2-R1: get_execution_children joins the family - same securable
// (Execution:Read), same domain as get_execution_status/list_executions.
constexpr std::string_view kExecutionsAudit[] = {"get_execution_status", "get_execution_children",
                                                 "list_executions", "query_audit_log"};
constexpr std::string_view kInventory[] = {"query_inventory", "list_inventory_tables",
                                           "get_agent_inventory", "query_installed_software",
                                           "query_software_licenses", "get_agent_app_usage"};
constexpr std::string_view kCompliance[] = {
    "list_policies",    "get_compliance_summary",       "get_fleet_compliance",
    "get_guardian_schemas", "get_policy", "list_policy_fragments",
    "get_policy_agent_statuses"}; // #4034
constexpr std::string_view kScope[] = {"validate_scope", "preview_scope_targets"};
// B4 (#2146 API-parity) adds Create/Read/Update/membership/role management-
// group tools to this family (create/get/update/add_member/list_roles/
// assign_role) — same domain, same securable, no reason for a separate family.
// Delete-class management-group operations (delete group, remove member,
// unassign role) have no MCP twin yet.
constexpr std::string_view kMgmtGroups[] = {"list_management_groups",
                                            "preview_management_group_agent_count",
                                            "create_management_group",
                                            "get_management_group",
                                            "update_management_group",
                                            "add_management_group_member",
                                            "list_management_group_roles",
                                            "assign_management_group_role"};
constexpr std::string_view kApprovals[] = {"list_pending_approvals",
                                           "get_pending_approval_count", // #2146 A2-R4
                                           "approve_request", "reject_request"};
constexpr std::string_view kDexSignals[] = {
    "list_dex_signals",       "get_dex_signal_scope",     "get_dex_signal_detail",
    "get_dex_device_score",   "get_dex_app",              "list_dex_apps",
    "get_dex_catalogue_group", "get_dex_device_history",  "get_dex_observation",
    "get_dex_health",         "get_dex_trends",           "get_dex_overview"};
constexpr std::string_view kDexPerf[] = {"get_dex_perf_fleet",   "get_dex_perf_cohorts",
                                         "get_dex_perf_cohort_diff", "list_dex_perf_devices",
                                         "list_dex_perf_apps",   "get_dex_app_perf",
                                         "list_dex_app_perf_devices",
                                         "get_dex_group_app_perf",   "get_dex_tag_app_perf",
                                         "compare_app_perf_versions",
                                         "get_dex_device_app_perf"};
constexpr std::string_view kNetwork[] = {"get_network_fleet", "list_network_devices"};
constexpr std::string_view kExecution[] = {"execute_instruction", "execute_bundle",
                                           "get_bundle_result"};
constexpr std::string_view kRemediation[] = {"quarantine_device"};
// gap-matrix #10 (ADR-1005 A5 parity): issue_code_signing_cert joins the
// family — same Security securable domain, same "Certificates" mental model.
// B5 (api-parity #2146): export_ca_root_csr joins too — same PKI/CA domain,
// same Security securable, distinct from the "Offload targets" family below
// despite both being new in this same PR.
constexpr std::string_view kCerts[] = {"list_issued_certs", "revoke_certificate",
                                       "issue_code_signing_cert", "export_ca_root_csr",
                                       "import_ca_chain"};
// KEK rotation (#2395 track C) is its own family, distinct from Certificates:
// a KEK is the server's own secrets-at-rest encryption key, not a PKI
// certificate, and it gates on a different lifecycle (rotate/rewrap/status,
// no issue/revoke) even though both share the Security securable.
constexpr std::string_view kKekRotation[] = {"rotate_kek", "rewrap_secrets", "get_kek_status"};
// PR1.5c/PR1.6c. Plugin configuration and the per-action kill switch share one
// family: the kill switch IS a config row, and an operator reaching for one
// almost always wants the other. Secrets are write-only here by construction —
// there is deliberately no get_plugin_secret.
constexpr std::string_view kPluginConfig[] = {
    "get_plugin_config",    "list_plugin_config",      "set_plugin_config",
    "delete_plugin_config", "set_plugin_secret",       "delete_plugin_secret",
    "get_plugin_kill_switch", "set_plugin_kill_switch"};
// Upload grants are separate from plugin config: they are a short-lived
// CREDENTIAL surface, not configuration, and the agent-side session endpoints
// they authorize deliberately have no MCP twin at all.
constexpr std::string_view kUploadGrants[] = {"mint_upload_grant", "list_upload_grants",
                                              "revoke_upload_grant"};
constexpr std::string_view kEnginePrincipals[] = {
    "create_engine_principal",        "list_engine_principals",
    "get_engine_principal",           "revoke_engine_principal",
    "mint_engine_credential",         "rotate_engine_credential",
    "confirm_engine_rotation",        "transfer_engine_principal_owner",
    "audit_engine_no_admin",          "assign_engine_role",
    "unassign_engine_role",           "list_engine_roles"};
constexpr std::string_view kAccessReviews[] = {"export_access_review", "open_access_review",
                                               "record_attestation", "get_access_review",
                                               "list_access_reviews", "close_access_review"};
// Human API-token lifecycle (P2 #11, SOC 2 CC6.3 rotation; B4 #2146 API-parity
// adds list/create/revoke) — own family distinct from Engine principals. List/
// create/rotate/confirm are self-service ONLY (mint/list/rotate always act on
// the calling principal's own tokens, never an admin-for-another-user path);
// revoke ADDITIONALLY allows an elevated/admin session to act on another
// user's token (the one asymmetry in this family — see revoke_api_token's own
// tool description for the exact posture).
constexpr std::string_view kApiTokens[] = {"rotate_api_token", "confirm_api_token_rotation",
                                           "list_api_tokens", "create_api_token",
                                           "revoke_api_token"};
constexpr std::string_view kAgenticHelpers[] = {"get_fleet_posture_fast",
                                                "classify_operational_question",
                                                "get_incident_playbook", "summarize_working_set"};
constexpr std::string_view kDiscovery[] = {"discover_permissions", "discover_instructions",
                                           "discover_routes", "discover_scope_kinds",
                                           "discover_plugins"};
// #4037: live Guardian rule/event/device state — distinct from
// "Policy & compliance"'s get_guardian_schemas, which is the static rule
// SCHEMA catalog, not live enforcement state. get_guardian_status is the
// fleet rollup; list_guardian_rules/get_guardian_rule_status are per-rule
// views; list_guardian_events is the __observation__/enforcement event feed
// (confined, not denied — see its kToolSecurityRows comment);
// get_guardian_device_guards is the per-device all-guards census.
// #2146 Batch B1 extends this family with the rule CRUD/push mutations
// (create/get/update/delete_guardian_rule, push_guardian_rules) and the two
// per-agent reads #4037 deliberately deferred (get_guardian_agent_status,
// get_guardian_device_compliance) — same live-enforcement-state family, not
// a new one; the schema-catalog/live-state distinction this family's
// description draws still holds.
constexpr std::string_view kGuardian[] = {
    "get_guardian_status",         "list_guardian_rules",
    "get_guardian_rule_status",    "list_guardian_events",
    "get_guardian_device_guards",  "create_guardian_rule",
    "get_guardian_rule",           "update_guardian_rule",
    "delete_guardian_rule",        "push_guardian_rules",
    "get_guardian_agent_status",   "get_guardian_device_compliance"};
// #4036 (api-parity Batch A) — the /auto pre-flight ASSESS + deploy ACT
// stages' read twins. Own family, distinct from Fleet & agents / Live
// execution: these are owner-scoped readiness/preview reads over the
// operator's OWN saved runs, not fleet-wide agent data or dispatch.
constexpr std::string_view kPreflightDeploy[] = {"list_preflight_runs", "get_deployment_preview"};
// #4030: WorkflowEngine's multi-step orchestration — its own family, distinct
// from both "Instructions & schedules" (single InstructionDefinitions) and
// "Executions & audit" (ExecutionTracker's single-instruction fan-out): a
// Workflow composes multiple steps, and its execution record is a different
// data model from an Execution (see get_workflow_execution's tool doc).
constexpr std::string_view kWorkflows[] = {"list_workflows", "get_workflow",
                                           "get_workflow_execution"};
// #4027 — TAR (Timeline / Activity Recorder) had zero MCP presence before this
// read-twin batch; its own family rather than folding into an unrelated one.
constexpr std::string_view kTar[] = {"list_tar_process_tree_devices",
                                     "list_tar_capture_sources_devices",
                                     "list_tar_retention_paused"};
// #4031: AD/Entra directory-sync user listing + directory-sync status (last
// sync time/health, NOT OIDC SSO config — that lives at REST-only
// GET /api/v1/settings/oidc, deliberately with no MCP twin per #520) — both
// Directory:Read, deliberately their own family rather than folded into
// Fleet & agents (directory users are IdP-sourced identity records, not
// managed endpoints) or Engine principals (unrelated identity axis).
constexpr std::string_view kDirectory[] = {"list_directory_users", "get_directory_status"};
// #2146 Batch B2 — scope-walking result sets (docs/scope-walking-design.md):
// the named, TTL-bounded, lineage-tracked device sets produced by a query,
// dispatch, or manual curation. Own family, distinct from "Scope targeting"
// (a stateless expression check/preview, not a persisted, owner-scoped
// artifact) and from "Live execution" (the three dispatch producers here
// create/materialise a result set as their side effect; they do not exist to
// collect a plugin/action response the way execute_instruction does).
constexpr std::string_view kResultSets[] = {"list_result_sets",
                                            "create_result_set",
                                            "create_result_set_from_inventory_query",
                                            "create_result_set_from_tar_query",
                                            "create_result_set_from_instruction_result",
                                            "reevaluate_result_set",
                                            "get_result_set",
                                            "get_result_set_members",
                                            "get_result_set_lineage",
                                            "pin_result_set",
                                            "unpin_result_set",
                                            "delete_result_set"};
// #2146 Batch B3 (api-parity programme) — fleet execution/dashboard rollups,
// distinct from "Executions & audit" (single-execution records/status) and
// "DEX performance" (per-device/app reliability signals): these are
// ExecutionTracker-wide success/failure aggregates, not per-execution detail.
constexpr std::string_view kExecutionStatistics[] = {"get_execution_statistics",
                                                     "get_execution_statistics_by_agent",
                                                     "get_execution_statistics_by_definition",
                                                     "get_fleet_statistics"};
// #2146 Batch B3 — the 3D fleet visualizer's REST surface had zero MCP
// presence before this read-twin pair; its own family, distinct from "Fleet &
// agents" (a machine/process/socket topology snapshot is a different data
// model from an agent roster row).
constexpr std::string_view kFleetVisualization[] = {"get_fleet_topology", "get_host_topology"};
// B4 (#2146 API-parity) — no existing family covers a self-check "can I do X"
// RBAC read; own family, distinct from Discovery's discover_permissions (the
// whole catalog + role grid) and from Engine principals' assign/unassign/
// list_engine_roles (grant AUTHORING, not a self-check).
constexpr std::string_view kRbacCheck[] = {"check_permission"};
// B4 — no existing family covers local-account lockout lifecycle; own family,
// distinct from Directory & identity (AD/Entra sync, a different identity
// axis) and from Engine principals (a different principal class entirely).
constexpr std::string_view kAccountLockout[] = {"unlock_account"};
// B5 (api-parity #2146) — response-offload targets (event-forwarding
// webhooks). Own family: distinct securable (Infrastructure, same as several
// others, but a distinct operator mental model) and no prior MCP presence.
// export_ca_root_csr joins Certificates (same PKI domain as
// list_issued_certs/revoke_certificate/issue_code_signing_cert), not this
// family, despite both being CA-adjacent — see kCerts below.
constexpr std::string_view kOffloadTargets[] = {
    "list_offload_targets", "create_offload_target", "get_offload_target",
    "delete_offload_target", "list_offload_target_deliveries"};
// B5 — platform license lifecycle. LicenseStore is dormant on `dev`
// (ADR-0048) — see mcp_server.hpp's forward-declaration comment — so this
// family answers "unavailable" in production today, same posture as its
// REST siblings.
constexpr std::string_view kLicense[] = {"get_platform_license", "activate_platform_license",
                                         "list_license_alerts"};
// B5 — software-package fleet deployments. SoftwareDeploymentStore is
// dormant on `dev` (ADR-0051) — same posture note as kLicense above. No
// start_software_deployment tool (MFA step-up, non-interactive MCP tokens
// cannot satisfy it) — see the tool family's own per-tool doc comments.
constexpr std::string_view kSoftwareDeployments[] = {
    "list_software_deployments", "create_software_deployment",
    "rollback_software_deployment", "cancel_software_deployment"};

constexpr std::array<ToolFamily, 38> kFamilies{{
    {"Fleet & agents", "connected agents, their OS/arch/version, and details", kFleet},
    {"Tags", "read and write agent tags, and find agents by tag", kTags},
    {"Instructions & schedules", "instruction definitions, their full export, and recurring "
                                 "schedules",
     kDefinitions},
    {"Product packs", "installed bundles of instruction/policy/workflow content", kProductPacks},
    {"Command responses", "query and aggregate stored command/instruction responses", kResponses},
    {"Executions & audit", "execution status/history and the who-did-what audit log",
     kExecutionsAudit},
    {"Inventory & software", "collected inventory tables, installed software, and licenses",
     kInventory},
    {"Policy & compliance", "policies, per-device and fleet compliance, Guardian schemas",
     kCompliance},
    {"Scope targeting", "validate a scope expression and preview the devices it selects", kScope},
    {"Result sets", "create, inspect, pin, and re-evaluate named scope-walking device sets "
                    "(from a pre-computed list, an inventory query, a TAR SQL dispatch, or an "
                    "instruction-result dispatch); walk their lineage",
     kResultSets},
    {"Management groups",
     "the hierarchical device grouping used for access scoping — list/create/get/update groups, "
     "manage static membership, and delegate group-scoped Operator/Viewer roles",
     kMgmtGroups},
    {"Approvals", "list pending approvals and approve/reject maker-checker tickets", kApprovals},
    {"DEX signals", "digital-employee-experience reliability signals and their scope/detail",
     kDexSignals},
    {"DEX performance", "fleet, cohort, device, and per-app performance over time", kDexPerf},
    {"Network quality", "fleet and per-device network-quality posture", kNetwork},
    {"Live execution", "dispatch plugin actions or bundles to endpoints and collect results",
     kExecution},
    {"Device remediation", "quarantine a device (destructive, approval-gated)", kRemediation},
    {"Certificates",
     "list issued agent certificates, revoke one, and issue a code-signing certificate via "
     "CSR custody",
     kCerts},
    {"KEK rotation", "rotate the server's secrets-at-rest encryption key, resume an "
                     "interrupted re-wrap, and check rotation status",
     kKekRotation},
    {"Plugin configuration", "per-plugin config keys, write-only secrets, and the per-action "
                             "kill switch",
     kPluginConfig},
    {"Upload grants", "mint, list and revoke the one-time grants that authorize an agent to "
                      "upload a file northbound",
     kUploadGrants},
    {"Engine principals", "provision and manage the durable identities behind use-case engines",
     kEnginePrincipals},
    {"Access reviews", "open, attest, close, and export SOC 2 access-certification reviews",
     kAccessReviews},
    {"API tokens", "list/create/revoke/rotate your own API tokens (self-service; revoke "
                   "additionally allows an elevated admin session to act on another user's "
                   "token)",
     kApiTokens},
    {"Agentic helpers", "high-level workflow helpers: fast posture, classification, playbooks",
     kAgenticHelpers},
    {"Discovery", "enumerate permissions, instructions, routes, scope kinds, and plugins",
     kDiscovery},
    {"Guardian", "live Guardian rule/event state and per-device guard status (not the schema "
                "catalog -- see Policy & compliance for that)",
     kGuardian},
    {"Pre-flight & deploy", "owner-scoped saved pre-flight runs and the deploy-config go/warn "
                            "preview for one of them",
     kPreflightDeploy},
    {"Workflows", "multi-step workflow definitions and their per-step execution records",
     kWorkflows},
    {"TAR process-tree & retention", "operator-scoped device pickers for the TAR process-tree "
                                     "and capture-sources frames, and the caller's own "
                                     "retention-paused source scan",
     kTar},
    {"Directory & identity", "AD/Entra directory-synced users and directory-sync status",
     kDirectory},
    {"Execution statistics", "fleet-wide, per-agent, and per-definition execution "
                             "success/failure rollups",
     kExecutionStatistics},
    {"Fleet visualization", "3D fleet topology snapshot -- per-machine processes, "
                            "connections, and listening sockets, fleet-wide or per-host",
     kFleetVisualization},
    {"RBAC self-check", "check whether the calling principal itself holds a specific RBAC "
                        "permission",
     kRbacCheck},
    {"Account lockout", "clear a local account's failed-login lockout counter (SOC 2 CC6.3)",
     kAccountLockout},
    {"Offload targets", "configure event-forwarding webhook targets and inspect their delivery "
                        "history",
     kOffloadTargets},
    {"Platform license", "the active platform license, activation, and lifecycle alerts",
     kLicense},
    {"Software deployments", "software-package fleet deployment lifecycle (list, create, "
                             "rollback, cancel)",
     kSoftwareDeployments},
}};

}  // namespace

std::span<const ToolFamily> tool_families() { return kFamilies; }

// ── initialize.instructions blob ─────────────────────────────────────────────

const std::string& initialize_instructions() {
    static const std::string blob = [] {
        std::string s;
        s += about_text();
        s += "\n\n## Operating model\n\n";
        s += operating_model_text();
        s += "\n\n## Tool families\n\n";
        s += "The MCP tool surface groups into these capability areas; call "
             "tools/list for the full input/output schema of any tool.\n\n";
        for (const auto& f : tool_families()) {
            s += "- ";
            s += f.name;
            s += ": ";
            s += f.blurb;
            s += " (";
            bool first = true;
            for (const auto& t : f.tools) {
                if (!first)
                    s += ", ";
                s += t;
                first = false;
            }
            s += ")\n";
        }
        s += "\n## Where to start\n\n";
        s += "Enumerate the live surface before acting: the discovery tools "
             "(discover_routes, discover_permissions, discover_instructions, "
             "discover_scope_kinds, discover_plugins) and resources/list "
             "(yuzu://about, yuzu://operating-model, yuzu://capabilities) describe "
             "exactly what this deployment exposes to your principal.";
        return s;
    }();
    return blob;
}

}  // namespace yuzu::server::mcp
