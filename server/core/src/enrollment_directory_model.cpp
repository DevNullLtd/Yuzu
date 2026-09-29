#include "enrollment_directory_model.hpp"

#include "directory_sync.hpp"
#include <yuzu/server/server.hpp> // Config (::oidc_* fields only)

#include <chrono>

namespace yuzu::server {

namespace {

// Machine (snake_case) values, matching settings_routes.cpp's auto-approve
// POST-body parser (~line 5210) and byte-identical to auto_approve.cpp's own
// internal-linkage rule_type_to_string() (used for on-disk persistence) —
// NOT render_auto_approve_fragment()'s dashboard labels, which are Title
// Case display strings ("Trusted CA", "Hostname Glob") for a different
// audience. Three independent hand-synced copies of this mapping now exist
// (auto_approve.cpp's persistence pair, settings_routes.cpp's UI labels,
// this one); auto_approve.cpp's pair could be exported from auto_approve.hpp
// and reused here instead of a third switch — not done in this pass. A
// future new rule type must update all three.
const char* auto_approve_rule_type_str(auth::AutoApproveRuleType t) {
    switch (t) {
    case auth::AutoApproveRuleType::trusted_ca:
        return "trusted_ca";
    case auth::AutoApproveRuleType::hostname_glob:
        return "hostname_glob";
    case auth::AutoApproveRuleType::ip_subnet:
        return "ip_subnet";
    case auth::AutoApproveRuleType::cloud_provider:
        return "cloud_provider";
    }
    return "unknown";
}

} // namespace

nlohmann::json directory_user_row_json(const DirectoryUser& u) {
    nlohmann::json groups = nlohmann::json::array();
    for (const auto& g : u.groups)
        groups.push_back(g);
    return {{"id", u.id},
           {"display_name", u.display_name},
           {"email", u.email},
           {"upn", u.upn},
           {"enabled", u.enabled},
           {"groups", groups},
           {"synced_at", u.synced_at}};
}

nlohmann::json directory_status_json(const SyncStatus& status,
                                     const std::vector<DirectoryGroup>& groups,
                                     bool reveal_mapped_role) {
    nlohmann::json groups_arr = nlohmann::json::array();
    for (const auto& g : groups) {
        groups_arr.push_back({{"id", g.id},
                              {"display_name", g.display_name},
                              {"description", g.description},
                              {"mapped_role", reveal_mapped_role ? g.mapped_role : std::string{}},
                              {"synced_at", g.synced_at}});
    }
    return {{"provider", status.provider},
           {"status", status.status},
           {"last_sync_at", status.last_sync_at},
           {"user_count", status.user_count},
           {"group_count", status.group_count},
           {"last_error", status.last_error},
           {"groups", groups_arr}};
}

nlohmann::json auto_approve_rule_row_json(const auth::AutoApproveRule& rule, std::size_t index) {
    return {{"index", static_cast<int64_t>(index)},
           {"type", auto_approve_rule_type_str(rule.type)},
           {"value", rule.value},
           {"label", rule.label},
           {"enabled", rule.enabled}};
}

nlohmann::json pending_agent_row_json(const auth::PendingAgent& agent) {
    const auto requested_at_epoch = std::chrono::duration_cast<std::chrono::seconds>(
                                        agent.requested_at.time_since_epoch())
                                        .count();
    return {{"agent_id", agent.agent_id},
           {"hostname", agent.hostname},
           {"os", agent.os},
           {"arch", agent.arch},
           {"agent_version", agent.agent_version},
           {"requested_at", requested_at_epoch},
           {"status", auth::pending_status_to_string(agent.status)}};
}

nlohmann::json oidc_config_json(const Config& cfg) {
    const bool configured = !cfg.oidc_issuer.empty() && !cfg.oidc_client_id.empty();
    return {{"configured", configured},
           {"issuer", cfg.oidc_issuer},
           {"client_id", cfg.oidc_client_id},
           // Never echo the secret — same non-disclosure posture as
           // render_directory_fragment() (settings_routes.cpp), which only
           // ever renders a "********"/placeholder UI hint from this same
           // boolean fact, never the value.
           {"client_secret_configured", !cfg.oidc_client_secret.empty()},
           {"redirect_uri", cfg.oidc_redirect_uri},
           {"admin_group", cfg.oidc_admin_group},
           {"skip_tls_verify", cfg.oidc_skip_tls_verify}};
}

} // namespace yuzu::server
