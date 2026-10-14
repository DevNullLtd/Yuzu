#pragma once

/// @file access_tokens_routes.hpp
/// Tokens and principals page (Phase 2 UI).
///
/// Routes (all GET):
///   /access/tokens                         page; 302 /login without a session
///   /fragments/access/tokens/list          API token list (?state=active|all)
///   /fragments/access/principals/list      engine principal list
///   /fragments/access/principals/detail    one principal + credentials + roles (?id=engine:<slug>)
///   /static/yuzu-tokens.js                 the page's read glue
///   /static/yuzu-tokens-actions.js         the page's write glue (dialogs, one-time reveal strip)
///
/// No mutating route is added here. Every write the page makes is a call to an existing REST v1
/// route (create, rotate, confirm, revoke, mint, transfer, roles), so each keeps its own
/// step-up, validation and audit; the dashboard twins that lack a step-up are not used.
/// The fragments only decide which controls to draw (`TokenCaps` and friends) so a caller is
/// never shown a control the server would refuse; the server stays authoritative.
///
/// The principal fragments are gated on `EnginePrincipal:Read`, the REST twin's securable
/// (floored to administrators while RBAC is off), and refuse engine and MCP-tier credentials.
/// Every gate and every capability probe is QUIET (no denial row for a cookie session: the
/// panels auto-load). The all-owner token view is a cookie-session administrator view with no
/// REST twin.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "access_tokens_render.hpp"
#include "api_token_store.hpp"
#include "engine_principal_store.hpp"
#include "rbac_store.hpp"

namespace yuzu::server {

class HttpRouteSink;

namespace access_tokens {

struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string&, const std::string&)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    template <class T>
    using Read = std::function<std::expected<T, std::string>()>;

    AuthFn auth_fn;
    /// `AuthRoutes::probe_permission`: `require_permission`'s decision, 403 already written on
    /// false, the denial row withheld for a cookie session only. Used for ApiToken:Read,
    /// EnginePrincipal:Read and (as a scratch probe) AuditLog:Read.
    PermFn perm_fn;
    AuditFn audit_fn;
    /// RBAC enforcement in effect (fail-closed view), shown to the page as a data attribute.
    std::function<bool()> rbac_enforced_fn;
    /// Epoch seconds. Injected so a golden never depends on the wall clock.
    std::function<std::int64_t()> now_fn;
    /// `ApiTokenStore::list_tokens(filter)`; an empty filter is every owner.
    std::function<std::expected<std::vector<ApiToken>, std::string>(const std::string&)> list_tokens_fn;
    Read<std::vector<EnginePrincipalRow>> list_principals_fn;
    /// `RbacStore::list_all_principal_roles_checked()` (every principal type; filtered to engine).
    Read<std::vector<PrincipalRole>> all_roles_fn;
    std::function<std::expected<std::optional<EnginePrincipalRow>, std::string>(const std::string&)>
        get_principal_fn;
    std::function<std::expected<std::vector<ApiToken>, std::string>(const std::string&)>
        active_credentials_fn;
    std::function<std::expected<std::vector<PrincipalRole>, std::string>(const std::string&)>
        principal_roles_fn;
    /// Revoked principals: the `engine_principal.revoke` audit detail ("" = none recorded).
    /// Only called when the caller holds AuditLog:Read.
    std::function<std::expected<RevokeDetail, std::string>(const std::string&)> revoke_detail_fn;
};

/// Throws `std::invalid_argument` when any `Deps` member is unbound.
void register_access_tokens_routes(HttpRouteSink& sink, Deps deps);

} // namespace access_tokens
} // namespace yuzu::server
