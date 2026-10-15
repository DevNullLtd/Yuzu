#pragma once

#include <yuzu/server/auth.hpp>

#include <cstdint>

/// @file admin_gate.hpp
/// The ONE place the admin-route decision is made from a Session.
///
/// `AuthRoutes::require_admin` applies this verdict (and keeps the audit rows
/// and response bodies for each denial); `/api/me` and `/api/v1/me` report
/// `verdict == Admit` as `can_access_settings` so the shell's Settings link
/// can never disagree with the `/settings` page gate. Pure: no store read, no
/// audit row, no metric, so it is safe to call on every page load.
namespace yuzu::server::authz {

enum class AdminGate : std::uint8_t { Admit, ServiceScoped, McpTier, NotAdmin };

/// Order is the order `require_admin` has always applied: service-scoped
/// tokens and MCP tokens never reach admin routes whatever their creator's
/// role; otherwise the EFFECTIVE role (JIT elevation counts) must be admin.
[[nodiscard]] inline AdminGate admin_gate_verdict(const auth::Session& s) noexcept {
    if (!s.token_scope_service.empty())
        return AdminGate::ServiceScoped;
    if (!s.mcp_tier.empty())
        return AdminGate::McpTier;
    return auth::effective_role(s) == auth::Role::admin ? AdminGate::Admit : AdminGate::NotAdmin;
}

} // namespace yuzu::server::authz
