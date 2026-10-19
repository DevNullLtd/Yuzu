#pragma once

#include <array>
#include <cstddef>
#include <iterator>
#include <string_view>
#include <utility>
#include <vector>

/// @file step_up_policy.hpp
/// The ONE table classifying every mutating HTTP route by its MFA step-up
/// requirement. `step_up_gate.cpp`'s chokepoint looks a request up here by the
/// exact `(method, registered pattern)` pair httplib matched; the in-handler
/// `StepUpFn` calls that predate the table are kept in step with it.
///
/// EXTEND this table, never fork it. A second list of step-up routes is the
/// same drift `body_cap_policy.hpp` and `authz_topology_floor.hpp` exist to
/// prevent for their own chokepoints.
///
/// KEYS: `pattern` is the registered route string byte-for-byte, as passed to
/// `HttpRouteSink::Post/Put/Delete/Patch` (a raw-string pattern is written as
/// the same raw string here). It is compared for equality with httplib's
/// `Request::matched_route`, which is `matcher->pattern()` verbatim, so there is
/// no prefix matching, no wildcard and no segment-boundary rule to get wrong:
/// a prefix exemption would silently cover a future route registered under it.
/// GET and OPTIONS never appear.
///
/// CLASSES (`StepUpClass`):
///   kRequired       - the chokepoint evaluates `decide_step_up` before the
///                     handler runs; a stale or absent proof is refused.
///   kStrong         - reserved for a stricter assurance level; no row carries
///                     it yet and the chokepoint fails CLOSED on one rather than
///                     treating it as kRequired.
///   kOwnGate        - the handler owns a stricter, order-sensitive gate; the
///                     chokepoint skips it. Closed to the three elevation routes.
///   kExempt         - reviewed and deliberately not gated; `reason` names why.
///   kPendingRuling  - not yet classified; treated as kExempt by the chokepoint,
///                     but the row count is pinned by `kPendingRulingMax` below,
///                     which may only go DOWN, so "pending" is not a free pass.
///
/// `action_label` is the audit `target_id` of the `mfa.step_up.required` row and
/// is kept identical to the label the in-handler call has always used, so
/// evidence queries keyed on it keep working.
///
/// Self-checks (`consteval`, so a bad edit is a BUILD FAILURE): no duplicate
/// `(method, pattern)` key, a non-empty `reason` on every kExempt / kOwnGate row,
/// a non-empty `action_label` on every kRequired row, and the kPendingRuling
/// ceiling.

namespace yuzu::server {

enum class StepUpClass : unsigned char {
    kRequired,
    kStrong,
    kOwnGate,
    kExempt,
    kPendingRuling,
};

struct StepUpPolicyEntry {
    std::string_view method;  // "POST" | "PUT" | "DELETE" | "PATCH"
    std::string_view pattern; // EXACT registered pattern text
    StepUpClass cls;
    std::string_view reason;       // mandatory for kExempt / kOwnGate: the review record
    std::string_view action_label; // audit target_id; the label the in-handler call used
};

namespace step_up_detail {
inline constexpr std::string_view kElevationReason =
    "handler owns a stricter elevation gate with a minimum window";
inline constexpr std::string_view kNoReason = "";
inline constexpr std::string_view kNoLabel = "";

// The exempt classes. A new kExempt row names one of these, or adds a class here with its
// own reason: the class name is the review record.
inline constexpr std::string_view kPreSession =
    "unauthenticated by design: pre-session authentication flow";
inline constexpr std::string_view kStepUpProofEndpoint =
    "the step-up proof endpoint itself";
inline constexpr std::string_view kSelfSignOut = "self-service sign-out; reduces access";
inline constexpr std::string_view kSelfPrivilegeReduction =
    "self-service privilege reduction: revokes the caller's own elevation";
inline constexpr std::string_view kExecutionDispatch =
    "execution dispatch: governed by the execute gate and approval";
inline constexpr std::string_view kApprovalGatedElsewhere =
    "deployment pipeline: approval-gated elsewhere";
inline constexpr std::string_view kOperationalData =
    "operational data: not credentials, identity or authority";
inline constexpr std::string_view kReadShaped = "read-only request carried by POST";
inline constexpr std::string_view kSyncTrigger =
    "triggers a synchronisation read; changes no authority or configuration";
inline constexpr std::string_view kAgentUploadProtocol =
    "agent upload protocol: grant-bearing, no interactive session";
inline constexpr std::string_view kScimBearer = "SCIM bearer endpoint: no interactive session";
inline constexpr std::string_view kMcpTransport =
    "MCP transport endpoint: tool calls are governed by the MCP tier and approval ladder";
inline constexpr std::string_view kContentAuthoring =
    "content authoring: running the content is gated separately";
inline constexpr std::string_view kPolicyLifecycle =
    "policy lifecycle: governed by the Policy securable and approval";
inline constexpr std::string_view kEvidenceCapture = "evidence capture under its own securable";
inline constexpr std::string_view kStopsEffect = "stops an in-flight effect; reduces risk";
inline constexpr std::string_view kAlertingConfig = "alerting and notification configuration";
inline constexpr std::string_view kMfaEnrolment =
    "MFA enrolment flow: cannot replace or remove an enabled factor";
inline constexpr std::string_view kSchedulingGatedWork = "schedule of work that is gated separately";
inline constexpr std::string_view kSelfNotificationState = "the caller's own notification state";

/// The ONE reason a kPendingRuling row carries.
inline constexpr std::string_view kPendingReason = "classification pending";

[[nodiscard]] constexpr StepUpPolicyEntry exempt(std::string_view method, std::string_view pattern,
                                                 std::string_view reason) {
    return {method, pattern, StepUpClass::kExempt, reason, kNoLabel};
}

[[nodiscard]] constexpr StepUpPolicyEntry pending(std::string_view method,
                                                  std::string_view pattern) {
    return {method, pattern, StepUpClass::kPendingRuling, kPendingReason, kNoLabel};
}
} // namespace step_up_detail

// clang-format off
inline constexpr StepUpPolicyEntry kStepUpPolicy[] = {
    // -- kRequired: routes that already carry an in-handler step-up call ----------------------
    // REST (rest_api_v1.cpp)
    {"POST",   R"(/api/v1/users/me/password)",                                  StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/users/me/password"},
    {"POST",   R"(/api/v1/users/([^/]+)/password)",                             StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/users/{name}/password"},
    {"POST",   R"(/api/v1/engine-principals/([a-z0-9._-]+)/roles)",             StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/engine-principals/{id}/roles"},
    {"DELETE", R"(/api/v1/engine-principals/([a-z0-9._-]+)/roles/([^/]+))",     StepUpClass::kRequired, step_up_detail::kNoReason, "DELETE /api/v1/engine-principals/{id}/roles/{role}"},
    {"POST",   R"(/api/v1/tokens)",                                             StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/tokens"},
    {"DELETE", R"(/api/v1/tokens/(.+))",                                        StepUpClass::kRequired, step_up_detail::kNoReason, "DELETE /api/v1/tokens/{id}"},
    {"POST",   R"(/api/v1/tokens/([^/]+)/rotate)",                              StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/tokens/{id}/rotate"},
    {"POST",   R"(/api/v1/tokens/([^/]+)/confirm)",                             StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/tokens/{id}/confirm"},
    {"POST",   R"(/api/v1/engine-principals)",                                  StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/engine-principals"},
    {"DELETE", R"(/api/v1/engine-principals/([^/]+))",                          StepUpClass::kRequired, step_up_detail::kNoReason, "DELETE /api/v1/engine-principals/{id}"},
    {"POST",   R"(/api/v1/engine-principals/([^/]+)/credentials)",              StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/engine-principals/{id}/credentials"},
    {"POST",   R"(/api/v1/engine-principals/([^/]+)/credentials/rotate)",       StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/engine-principals/{id}/credentials/rotate"},
    {"POST",   R"(/api/v1/engine-principals/([^/]+)/credentials/confirm)",      StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/engine-principals/{id}/credentials/confirm"},
    {"POST",   R"(/api/v1/engine-principals/([^/]+)/transfer-owner)",           StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/engine-principals/{id}/transfer-owner"},
    {"DELETE", R"(/api/v1/sessions)",                                           StepUpClass::kRequired, step_up_detail::kNoReason, "DELETE /api/v1/sessions"},
    {"POST",   R"(/api/v1/users/([^/]+)/unlock)",                               StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/users/{name}/unlock"},
    {"POST",   R"(/api/v1/rbac/roles/([A-Za-z0-9._-]+)/assignments)",           StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/rbac/roles/{name}/assignments"},
    {"DELETE", R"(/api/v1/rbac/roles/([A-Za-z0-9._-]+)/assignments/([A-Za-z0-9._-]+))", StepUpClass::kRequired, step_up_detail::kNoReason, "DELETE /api/v1/rbac/roles/{name}/assignments/{principal_id}"},
    {"PUT",    R"(/api/v1/rbac/enforcement)",                                   StepUpClass::kRequired, step_up_detail::kNoReason, "PUT /api/v1/rbac/enforcement"},
    {"POST",   R"(/api/v1/software-packages)",                                  StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/software-packages"},
    {"POST",   R"(/api/v1/software-deployments/([a-f0-9]+)/start)",             StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/software-deployments/{id}/start"},
    {"POST",   R"(/api/v1/guaranteed-state/rules)",                             StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/guaranteed-state/rules"},
    {"PUT",    R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))",          StepUpClass::kRequired, step_up_detail::kNoReason, "PUT /api/v1/guaranteed-state/rules/{id}"},
    {"DELETE", R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))",          StepUpClass::kRequired, step_up_detail::kNoReason, "DELETE /api/v1/guaranteed-state/rules/{id}"},
    {"POST",   R"(/api/v1/guaranteed-state/push)",                              StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/v1/guaranteed-state/push"},
    // Dashboard (guardian_routes.cpp)
    {"POST",   R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/update)",        StepUpClass::kRequired, step_up_detail::kNoReason, "POST /fragments/guardian/guard/{id}/update"},
    {"POST",   R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/delete)",        StepUpClass::kRequired, step_up_detail::kNoReason, "POST /fragments/guardian/guard/{id}/delete"},
    // Dashboard (settings_routes.cpp)
    {"DELETE", R"(/api/settings/users/(.+))",                                   StepUpClass::kRequired, step_up_detail::kNoReason, "DELETE /api/settings/users/{username}"},
    {"POST",   R"(/api/settings/users/(.+)/role)",                              StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/settings/users/{username}/role"},
    {"POST",   R"(/api/settings/api-tokens)",                                   StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/settings/api-tokens"},
    {"DELETE", R"(/api/settings/api-tokens/(.+))",                              StepUpClass::kRequired, step_up_detail::kNoReason, "DELETE /api/settings/api-tokens/{id}"},
    {"POST",   R"(/api/settings/mfa/recovery-codes)",                           StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/settings/mfa/recovery-codes"},
    {"POST",   R"(/api/settings/mfa/disable)",                                  StepUpClass::kRequired, step_up_detail::kNoReason, "POST /api/settings/mfa/disable"},

    // -- kOwnGate: the handler's own elevation gate is stricter and order-sensitive -----------
    // (auth_routes.cpp `elevation_step_up`; the chokepoint skips these.)
    {"POST",   R"(/api/v1/users/([^/]+)/elevation-eligibility)",                StepUpClass::kOwnGate,  step_up_detail::kElevationReason, "POST /api/v1/users/{name}/elevation-eligibility"},
    {"POST",   R"(/api/v1/users/elevation-eligibility)",                        StepUpClass::kOwnGate,  step_up_detail::kElevationReason, "POST /api/v1/users/{name}/elevation-eligibility"},
    {"POST",   R"(/api/v1/elevate)",                                            StepUpClass::kOwnGate,  step_up_detail::kElevationReason, "POST /api/v1/elevate"},

    // -- APPEND-ONLY REGION ------------------------------------------------------------------
    // Every other mutating route: kExempt with a named class reason, or kPendingRuling with the
    // literal "classification pending". Keep `kPendingRulingMax` equal to the count of
    // kPendingRuling rows. Rows are grouped by owning file, in registration-scan order.
    // approval_routes.cpp
    step_up_detail::pending("POST",  R"(/api/approvals/([^/]+)/approve)"),
    step_up_detail::pending("POST",  R"(/api/approvals/([^/]+)/reject)"),
    // auth_routes.cpp
    step_up_detail::exempt("POST",  R"(/login)",                                                                  step_up_detail::kPreSession),
    step_up_detail::exempt("POST",  R"(/login/mfa)",                                                              step_up_detail::kPreSession),
    step_up_detail::exempt("POST",  R"(/login/mfa/enroll)",                                                       step_up_detail::kPreSession),
    step_up_detail::exempt("POST",  R"(/login/mfa/stepup)",                                                       step_up_detail::kStepUpProofEndpoint),
    step_up_detail::exempt("POST",  R"(/logout)",                                                                 step_up_detail::kSelfSignOut),
    step_up_detail::exempt("POST",  R"(/saml/acs)",                                                               step_up_detail::kPreSession),
    step_up_detail::exempt("POST",  R"(/api/v1/elevate/revoke)",                                                  step_up_detail::kSelfPrivilegeReduction),
    // ca_routes.cpp
    step_up_detail::pending("POST",  R"(/api/v1/ca/revoke)"),
    step_up_detail::pending("POST",  R"(/api/v1/ca/issue-code-signing)"),
    step_up_detail::pending("POST",  R"(/api/v1/ca/import-chain)"),
    step_up_detail::pending("POST",  R"(/api/settings/ca/revoke)"),
    step_up_detail::pending("POST",  R"(/api/settings/ca/import-chain)"),
    // command_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/command)",                                                            step_up_detail::kExecutionDispatch),
    // config_routes.cpp
    step_up_detail::pending("PUT",   R"(/api/config/([a-z_]+))"),
    // custom_properties_routes.cpp
    step_up_detail::exempt("PUT",   R"(/api/agents/([^/]+)/properties/([a-zA-Z0-9_.:-]+))",                       step_up_detail::kOperationalData),
    step_up_detail::exempt("DELETE",R"(/api/agents/([^/]+)/properties/([a-zA-Z0-9_.:-]+))",                       step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/api/property-schemas)",                                                   step_up_detail::kOperationalData),
    // dashboard_api_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/export/json-to-csv)",                                                 step_up_detail::kReadShaped),
    step_up_detail::exempt("POST",  R"(/api/scope/validate)",                                                     step_up_detail::kReadShaped),
    // dashboard_routes.cpp
    step_up_detail::pending("POST",  R"(/api/dashboard/group-from-results)"),
    step_up_detail::exempt("POST",  R"(/api/dashboard/execute)",                                                  step_up_detail::kExecutionDispatch),
    step_up_detail::exempt("POST",  R"(/api/dashboard/tar-execute)",                                              step_up_detail::kReadShaped),
    step_up_detail::exempt("POST",  R"(/fragments/tar/retention-paused/scan)",                                    step_up_detail::kReadShaped),
    step_up_detail::pending("POST",  R"(/fragments/tar/retention-paused/reenable)"),
    step_up_detail::pending("POST",  R"(/fragments/tar/retention-paused/purge)"),
    // data_inventory_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/inventory/query)",                                                    step_up_detail::kReadShaped),
    // deployment_routes.cpp
    step_up_detail::exempt("POST",  R"(/fragments/auto/deploy/run)",                                              step_up_detail::kApprovalGatedElsewhere),
    step_up_detail::exempt("POST",  R"(/fragments/auto/deploy/delete)",                                           step_up_detail::kOperationalData),
    // diagnostics_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/chargen/start)",                                                      step_up_detail::kExecutionDispatch),
    step_up_detail::exempt("POST",  R"(/api/chargen/stop)",                                                       step_up_detail::kExecutionDispatch),
    step_up_detail::exempt("POST",  R"(/api/procfetch/fetch)",                                                    step_up_detail::kExecutionDispatch),
    // discovery_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/directory/sync)",                                                     step_up_detail::kSyncTrigger),
    step_up_detail::pending("PUT",   R"(/api/directory/group-mappings)"),
    step_up_detail::exempt("POST",  R"(/api/patches/deploy)",                                                     step_up_detail::kExecutionDispatch),
    step_up_detail::exempt("POST",  R"(/api/patches/deployments/([a-f0-9]+)/cancel)",                             step_up_detail::kExecutionDispatch),
    step_up_detail::exempt("POST",  R"(/api/deployment-jobs)",                                                    step_up_detail::kExecutionDispatch),
    step_up_detail::exempt("DELETE",R"(/api/deployment-jobs/([a-f0-9]+))",                                        step_up_detail::kExecutionDispatch),
    step_up_detail::exempt("POST",  R"(/api/discovery/scan)",                                                     step_up_detail::kExecutionDispatch),
    // execution_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/executions/([^/]+)/rerun)",                                           step_up_detail::kExecutionDispatch),
    step_up_detail::exempt("POST",  R"(/api/executions/([^/]+)/cancel)",                                          step_up_detail::kExecutionDispatch),
    // file_retrieval_routes.cpp
    step_up_detail::pending("POST",  R"(/api/v1/upload-grants)"),
    step_up_detail::pending("DELETE",R"(/api/v1/upload-grants/([a-f0-9]+))"),
    step_up_detail::exempt("POST",  R"(/api/v1/uploads)",                                                         step_up_detail::kAgentUploadProtocol),
    step_up_detail::exempt("PUT",   R"(/api/v1/uploads/([a-f0-9]+)/chunk)",                                       step_up_detail::kAgentUploadProtocol),
    step_up_detail::exempt("POST",  R"(/api/v1/uploads/([a-f0-9]+)/commit)",                                      step_up_detail::kAgentUploadProtocol),
    step_up_detail::exempt("DELETE",R"(/api/v1/uploads/([a-f0-9]+))",                                             step_up_detail::kAgentUploadProtocol),
    // guardian_routes.cpp
    step_up_detail::pending("POST",  R"(/fragments/guardian/guards)"),
    step_up_detail::pending("POST",  R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/enabled)"),
    step_up_detail::pending("POST",  R"(/fragments/guardian/baselines)"),
    step_up_detail::pending("POST",  R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/deploy)"),
    step_up_detail::pending("POST",  R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/delete)"),
    step_up_detail::pending("POST",  R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+))"),
    // hardware_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/v1/hardware/([^/]+)/sync)",                                           step_up_detail::kSyncTrigger),
    step_up_detail::exempt("POST",  R"(/api/v1/hardware/sync)",                                                   step_up_detail::kSyncTrigger),
    // instruction_fragment_routes.cpp
    step_up_detail::exempt("POST",  R"(/fragments/instructions/yaml-preview)",                                    step_up_detail::kReadShaped),
    // instruction_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/instructions)",                                                       step_up_detail::kContentAuthoring),
    step_up_detail::exempt("PUT",   R"(/api/instructions/([^/]+))",                                               step_up_detail::kContentAuthoring),
    step_up_detail::exempt("DELETE",R"(/api/instructions/([^/]+))",                                               step_up_detail::kContentAuthoring),
    step_up_detail::exempt("POST",  R"(/api/instructions/import)",                                                step_up_detail::kContentAuthoring),
    step_up_detail::exempt("POST",  R"(/api/instruction-sets)",                                                   step_up_detail::kContentAuthoring),
    step_up_detail::exempt("DELETE",R"(/api/instruction-sets/([^/]+))",                                           step_up_detail::kContentAuthoring),
    step_up_detail::exempt("POST",  R"(/api/instructions/yaml)",                                                  step_up_detail::kContentAuthoring),
    step_up_detail::exempt("POST",  R"(/api/instructions/validate-yaml)",                                         step_up_detail::kContentAuthoring),
    // kek_routes.cpp
    step_up_detail::pending("POST",  R"(/api/v1/secrets/kek/rotate)"),
    step_up_detail::pending("POST",  R"(/api/v1/secrets/kek/rewrap)"),
    // mcp_disabled_routes.cpp
    step_up_detail::exempt("POST",  R"(/mcp/v1/)",                                                                step_up_detail::kMcpTransport),
    step_up_detail::exempt("DELETE",R"(/mcp/v1/)",                                                                step_up_detail::kMcpTransport),
    // notification_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/notifications/(\d+)/read)",                                           step_up_detail::kSelfNotificationState),
    step_up_detail::exempt("POST",  R"(/api/notifications/(\d+)/dismiss)",                                        step_up_detail::kSelfNotificationState),
    // nvd_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/nvd/sync)",                                                           step_up_detail::kSyncTrigger),
    step_up_detail::exempt("POST",  R"(/api/nvd/match)",                                                          step_up_detail::kReadShaped),
    // offload_routes.cpp
    step_up_detail::pending("POST",  R"(/api/v1/offload-targets)"),
    step_up_detail::pending("DELETE",R"(/api/v1/offload-targets/(\d+))"),
    // plugin_config_routes.cpp
    step_up_detail::pending("PUT",   R"(/api/v1/plugin-config/([^/]+)/kill-switch)"),
    step_up_detail::pending("PUT",   R"(/api/v1/plugin-config/([^/]+)/([^/]+)/secret)"),
    step_up_detail::pending("DELETE",R"(/api/v1/plugin-config/([^/]+)/([^/]+)/secret)"),
    step_up_detail::pending("PUT",   R"(/api/v1/plugin-config/([^/]+)/([^/]+))"),
    step_up_detail::pending("DELETE",R"(/api/v1/plugin-config/([^/]+)/([^/]+))"),
    // policy_admin_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/policy-fragments)",                                                   step_up_detail::kPolicyLifecycle),
    step_up_detail::exempt("DELETE",R"(/api/policy-fragments/([^/]+))",                                           step_up_detail::kPolicyLifecycle),
    step_up_detail::exempt("POST",  R"(/api/policies)",                                                           step_up_detail::kPolicyLifecycle),
    step_up_detail::exempt("DELETE",R"(/api/policies/([^/]+))",                                                   step_up_detail::kPolicyLifecycle),
    step_up_detail::exempt("POST",  R"(/api/policies/([^/]+)/enable)",                                            step_up_detail::kPolicyLifecycle),
    step_up_detail::exempt("POST",  R"(/api/policies/([^/]+)/disable)",                                           step_up_detail::kPolicyLifecycle),
    step_up_detail::exempt("POST",  R"(/api/policies/([^/]+)/invalidate)",                                        step_up_detail::kPolicyLifecycle),
    step_up_detail::exempt("POST",  R"(/api/policies/invalidate-all)",                                            step_up_detail::kPolicyLifecycle),
    step_up_detail::exempt("POST",  R"(/api/policies/([^/]+)/evaluate)",                                          step_up_detail::kPolicyLifecycle),
    step_up_detail::exempt("POST",  R"(/api/policies/([^/]+)/remediate)",                                         step_up_detail::kPolicyLifecycle),
    // preflight_routes.cpp
    step_up_detail::exempt("POST",  R"(/fragments/auto/delete)",                                                  step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/fragments/auto/run)",                                                     step_up_detail::kExecutionDispatch),
    // rest_api_v1.cpp
    step_up_detail::exempt("POST",  R"(/api/v1/bundles)",                                                         step_up_detail::kExecutionDispatch),
    step_up_detail::pending("POST",  R"(/api/v1/tar/retention-paused/purge)"),
    step_up_detail::pending("POST",  R"(/api/v1/management-groups)"),
    step_up_detail::pending("PUT",   R"(/api/v1/management-groups/([a-f0-9]+))"),
    step_up_detail::pending("DELETE",R"(/api/v1/management-groups/([a-f0-9]+))"),
    step_up_detail::pending("POST",  R"(/api/v1/management-groups/([a-f0-9]+)/members)"),
    step_up_detail::pending("DELETE",R"(/api/v1/management-groups/([a-f0-9]+)/members/(.+))"),
    step_up_detail::pending("POST",  R"(/api/v1/management-groups/([a-f0-9]+)/roles)"),
    step_up_detail::pending("DELETE",R"(/api/v1/management-groups/([a-f0-9]+)/roles)"),
    step_up_detail::exempt("DELETE",R"(/api/v1/sessions/me)",                                                     step_up_detail::kSelfSignOut),
    step_up_detail::pending("POST",  R"(/api/v1/quarantine)"),
    step_up_detail::pending("DELETE",R"(/api/v1/quarantine/(.+))"),
    step_up_detail::exempt("POST",  R"(/api/v1/rbac/check)",                                                      step_up_detail::kReadShaped),
    step_up_detail::exempt("PUT",   R"(/api/v1/tags)",                                                            step_up_detail::kOperationalData),
    step_up_detail::exempt("DELETE",R"(/api/v1/tags/([^/]+)/([^/]+))",                                            step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/api/v1/definitions/([A-Za-z0-9._-]+)/response-templates)",                step_up_detail::kContentAuthoring),
    step_up_detail::exempt("PUT",   R"(/api/v1/definitions/([A-Za-z0-9._-]+)/response-templates/([A-Za-z0-9_-]+))",step_up_detail::kContentAuthoring),
    step_up_detail::exempt("DELETE",R"(/api/v1/definitions/([A-Za-z0-9._-]+)/response-templates/([A-Za-z0-9_-]+))",step_up_detail::kContentAuthoring),
    step_up_detail::exempt("POST",  R"(/api/v1/access-reviews)",                                                  step_up_detail::kEvidenceCapture),
    step_up_detail::exempt("POST",  R"(/api/v1/access-reviews/([^/]+)/attestations)",                             step_up_detail::kEvidenceCapture),
    step_up_detail::exempt("POST",  R"(/api/v1/access-reviews/([^/]+)/close)",                                    step_up_detail::kEvidenceCapture),
    step_up_detail::exempt("POST",  R"(/api/v1/inventory/query)",                                                 step_up_detail::kReadShaped),
    step_up_detail::exempt("POST",  R"(/api/v1/inventory/evaluate)",                                              step_up_detail::kReadShaped),
    step_up_detail::exempt("POST",  R"(/api/v1/result-sets)",                                                     step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/api/v1/result-sets/from-inventory-query)",                                step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/api/v1/result-sets/from-tar-query)",                                      step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/api/v1/result-sets/from-instruction-result)",                             step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/api/v1/result-sets/(rs_[0-9a-f]+)/re-eval)",                              step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/api/v1/result-sets/(rs_[0-9a-f]+)/pin)",                                  step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/api/v1/result-sets/(rs_[0-9a-f]+)/unpin)",                                step_up_detail::kOperationalData),
    step_up_detail::exempt("DELETE",R"(/api/v1/result-sets/(rs_[0-9a-f]+))",                                      step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/api/v1/scope/validate)",                                                  step_up_detail::kReadShaped),
    step_up_detail::exempt("POST",  R"(/api/v1/scope/preview)",                                                   step_up_detail::kReadShaped),
    step_up_detail::pending("POST",  R"(/api/v1/device-tokens)"),
    step_up_detail::pending("DELETE",R"(/api/v1/device-tokens/([a-f0-9]+))"),
    step_up_detail::pending("POST",  R"(/api/v1/software-deployments)"),
    step_up_detail::pending("POST",  R"(/api/v1/software-deployments/([a-f0-9]+)/rollback)"),
    step_up_detail::exempt("POST",  R"(/api/v1/software-deployments/([a-f0-9]+)/cancel)",                         step_up_detail::kStopsEffect),
    step_up_detail::pending("POST",  R"(/api/v1/license)"),
    step_up_detail::pending("DELETE",R"(/api/v1/license/([a-f0-9]+))"),
    step_up_detail::exempt("POST",  R"(/api/v1/dex/devices/([^/]+)/live)",                                        step_up_detail::kReadShaped),
    // result_set_routes.cpp
    step_up_detail::exempt("POST",  R"(/fragments/result-sets/(rs_[0-9a-f]+)/pin)",                               step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/fragments/result-sets/(rs_[0-9a-f]+)/unpin)",                             step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/fragments/result-sets/(rs_[0-9a-f]+)/delete)",                            step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/fragments/result-sets/create)",                                           step_up_detail::kOperationalData),
    // schedule_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/schedules)",                                                          step_up_detail::kSchedulingGatedWork),
    step_up_detail::exempt("DELETE",R"(/api/schedules/([^/]+))",                                                  step_up_detail::kSchedulingGatedWork),
    step_up_detail::exempt("POST",  R"(/api/schedules/([^/]+)/enable)",                                           step_up_detail::kSchedulingGatedWork),
    // scim_routes.cpp
    step_up_detail::exempt("POST",  R"(/scim/v2/Users)",                                                          step_up_detail::kScimBearer),
    step_up_detail::exempt("PUT",   R"(/scim/v2/Users/([0-9a-fA-F]+))",                                           step_up_detail::kScimBearer),
    step_up_detail::exempt("PATCH", R"(/scim/v2/Users/([0-9a-fA-F]+))",                                           step_up_detail::kScimBearer),
    step_up_detail::exempt("DELETE",R"(/scim/v2/Users/([0-9a-fA-F]+))",                                           step_up_detail::kScimBearer),
    step_up_detail::exempt("POST",  R"(/scim/v2/Groups)",                                                         step_up_detail::kScimBearer),
    step_up_detail::exempt("PUT",   R"(/scim/v2/Groups/([0-9a-fA-F]+))",                                          step_up_detail::kScimBearer),
    step_up_detail::exempt("PATCH", R"(/scim/v2/Groups/([0-9a-fA-F]+))",                                          step_up_detail::kScimBearer),
    step_up_detail::exempt("DELETE",R"(/scim/v2/Groups/([0-9a-fA-F]+))",                                          step_up_detail::kScimBearer),
    // settings_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/settings/dex-alerts/routing)",                                        step_up_detail::kAlertingConfig),
    step_up_detail::exempt("POST",  R"(/api/settings/dex-alerts/blast)",                                          step_up_detail::kAlertingConfig),
    step_up_detail::exempt("POST",  R"(/api/settings/dex-alerts/cohort-export)",                                  step_up_detail::kAlertingConfig),
    step_up_detail::pending("POST",  R"(/api/settings/plugin-signing/upload)"),
    step_up_detail::pending("POST",  R"(/api/settings/plugin-signing/clear)"),
    step_up_detail::pending("POST",  R"(/api/settings/plugin-signing/require)"),
    step_up_detail::pending("POST",  R"(/api/settings/tls)"),
    step_up_detail::pending("POST",  R"(/api/settings/cert-upload)"),
    step_up_detail::pending("POST",  R"(/api/settings/cert-paste)"),
    step_up_detail::pending("POST",  R"(/api/settings/oidc)"),
    step_up_detail::exempt("POST",  R"(/api/settings/oidc/test)",                                                 step_up_detail::kReadShaped),
    step_up_detail::pending("POST",  R"(/api/settings/users)"),
    step_up_detail::pending("POST",  R"(/api/settings/enrollment-tokens)"),
    step_up_detail::pending("DELETE",R"(/api/settings/enrollment-tokens/(.+))"),
    step_up_detail::pending("POST",  R"(/api/settings/enrollment-tokens/batch)"),
    step_up_detail::pending("POST",  R"(/api/settings/pending-agents/bulk-approve)"),
    step_up_detail::pending("POST",  R"(/api/settings/pending-agents/bulk-deny)"),
    step_up_detail::pending("POST",  R"(/api/settings/pending-agents/(.+)/approve)"),
    step_up_detail::pending("POST",  R"(/api/settings/pending-agents/(.+)/deny)"),
    step_up_detail::pending("DELETE",R"(/api/settings/pending-agents/(.+))"),
    step_up_detail::pending("POST",  R"(/api/settings/auto-approve)"),
    step_up_detail::pending("POST",  R"(/api/settings/auto-approve/mode)"),
    step_up_detail::pending("POST",  R"(/api/settings/auto-approve/(\d+)/toggle)"),
    step_up_detail::pending("DELETE",R"(/api/settings/auto-approve/(\d+))"),
    step_up_detail::pending("POST",  R"(/api/settings/management-groups)"),
    step_up_detail::pending("DELETE",R"(/api/settings/management-groups/([a-f0-9]+))"),
    step_up_detail::pending("POST",  R"(/api/settings/mcp)"),
    step_up_detail::pending("POST",  R"(/api/settings/updates/upload)"),
    step_up_detail::pending("DELETE",R"(/api/settings/updates/([^/]+)/([^/]+)/([^/]+))"),
    step_up_detail::pending("POST",  R"(/api/settings/updates/([^/]+)/([^/]+)/([^/]+)/rollout)"),
    step_up_detail::exempt("POST",  R"(/api/settings/mfa/init)",                                                  step_up_detail::kMfaEnrolment),
    step_up_detail::exempt("POST",  R"(/api/settings/mfa/verify)",                                                step_up_detail::kMfaEnrolment),
    // sle_routes.cpp
    step_up_detail::pending("DELETE",R"(/api/v1/sle/agents/([^/]+))"),
    // tag_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/tags/set)",                                                           step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/api/tags/delete)",                                                        step_up_detail::kOperationalData),
    step_up_detail::exempt("POST",  R"(/api/tags/query)",                                                         step_up_detail::kReadShaped),
    // tar_tree_routes.cpp
    step_up_detail::pending("POST",  R"(/fragments/tar/capture-sources/push)"),
    // webhook_routes.cpp
    step_up_detail::pending("POST",  R"(/api/webhooks)"),
    step_up_detail::pending("DELETE",R"(/api/webhooks/(\d+))"),
    // workflow_routes.cpp
    step_up_detail::exempt("POST",  R"(/api/scope/estimate)",                                                     step_up_detail::kReadShaped),
    step_up_detail::exempt("POST",  R"(/api/workflows)",                                                          step_up_detail::kContentAuthoring),
    step_up_detail::exempt("DELETE",R"(/api/workflows/([^/]+))",                                                  step_up_detail::kContentAuthoring),
    step_up_detail::exempt("POST",  R"(/api/workflows/([^/]+)/execute)",                                          step_up_detail::kExecutionDispatch),
    step_up_detail::exempt("POST",  R"(/api/instructions/([^/]+)/execute)",                                       step_up_detail::kExecutionDispatch),
    step_up_detail::exempt("POST",  R"(/api/product-packs)",                                                      step_up_detail::kContentAuthoring),
    step_up_detail::exempt("DELETE",R"(/api/product-packs/([^/]+))",                                              step_up_detail::kContentAuthoring),
};
// clang-format on

/// Ceiling on the number of kPendingRuling rows. May only be LOWERED: a new
/// route cannot be parked as pending, it needs a real class.
inline constexpr std::size_t kPendingRulingMax = 75;

inline constexpr std::size_t kStepUpPolicyCount = std::size(kStepUpPolicy);

/// Exact-key lookup. Returns nullptr when `(method, pattern)` is unclassified.
[[nodiscard]] constexpr const StepUpPolicyEntry* step_up_policy_for(std::string_view method,
                                                                    std::string_view pattern) {
    for (const auto& e : kStepUpPolicy) {
        if (e.method == method && e.pattern == pattern)
            return &e;
    }
    return nullptr;
}

/// True when `method` is one of the verbs the table classifies.
[[nodiscard]] constexpr bool is_step_up_table_method(std::string_view method) {
    return method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH";
}

/// Which of the registered mutating routes in `routes` (method, pattern) have no row in the
/// table. Pure. `step_up_unclassified_registrations` (`step_up_gate.hpp`) feeds it the routes
/// `HttplibRouteSink` recorded, and `server.cpp` refuses to start on a non-empty result.
[[nodiscard]] inline std::vector<std::pair<std::string_view, std::string_view>>
step_up_unclassified_routes(
    const std::vector<std::pair<std::string_view, std::string_view>>& routes) {
    std::vector<std::pair<std::string_view, std::string_view>> missing;
    for (const auto& [method, pattern] : routes) {
        if (!is_step_up_table_method(method))
            continue;
        if (step_up_policy_for(method, pattern) == nullptr)
            missing.emplace_back(method, pattern);
    }
    return missing;
}

namespace step_up_detail {

[[nodiscard]] consteval bool table_is_well_formed() {
    std::size_t pending_rows = 0;
    for (std::size_t i = 0; i < kStepUpPolicyCount; ++i) {
        const auto& a = kStepUpPolicy[i];
        if (!is_step_up_table_method(a.method) || a.pattern.empty())
            return false;
        if ((a.cls == StepUpClass::kExempt || a.cls == StepUpClass::kOwnGate) && a.reason.empty())
            return false;
        if (a.cls == StepUpClass::kRequired && a.action_label.empty())
            return false;
        if (a.cls == StepUpClass::kPendingRuling)
            ++pending_rows;
        for (std::size_t j = i + 1; j < kStepUpPolicyCount; ++j) {
            const auto& b = kStepUpPolicy[j];
            if (a.method == b.method && a.pattern == b.pattern)
                return false; // duplicate key
        }
    }
    return pending_rows <= kPendingRulingMax;
}

[[nodiscard]] consteval std::size_t count_class(StepUpClass c) {
    std::size_t n = 0;
    for (const auto& e : kStepUpPolicy)
        n += (e.cls == c) ? 1 : 0;
    return n;
}

} // namespace step_up_detail

static_assert(step_up_detail::table_is_well_formed(),
              "step_up_policy.hpp: duplicate (method, pattern) key, missing reason/label, or more "
              "kPendingRuling rows than kPendingRulingMax");
static_assert(step_up_detail::count_class(StepUpClass::kStrong) == 0,
              "no consumer evaluates kStrong rows yet");
static_assert(step_up_detail::count_class(StepUpClass::kOwnGate) == 3,
              "kOwnGate is closed to the three elevation routes");

} // namespace yuzu::server
