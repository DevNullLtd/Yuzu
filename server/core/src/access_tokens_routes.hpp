#pragma once

/// @file access_tokens_routes.hpp
/// Tokens and principals page (Phase 2 UI), read-only half.
///
/// Routes (all GET):
///   /access/tokens                         page; 302 /login without a session
///   /fragments/access/tokens/list          API token list (?state=active|all)
///   /fragments/access/principals/list      engine principal list
///   /fragments/access/principals/detail    one principal + credentials + roles (?id=engine:<slug>)
///   /static/yuzu-tokens.js                 the page's client glue
///
/// No mutating route is added and none is called from this page: creating, rotating and
/// revoking stay in Settings. The principal fragments use the Administrator account role
/// (the Settings panel's gate; RBAC grants are not consulted, so this can differ from the
/// REST twin's EnginePrincipal:Read in both directions). The all-owner token view is a
/// cookie-session administrator view with no REST twin.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "api_token_store.hpp"
#include "engine_principal_store.hpp"
#include "rbac_store.hpp"

namespace yuzu::server {

class HttpRouteSink;

namespace access_tokens {

struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    /// The LOUD admin gate (`require_admin`): on false it has already written the 403 and its
    /// audit row. Refuses MCP-tier and service-scoped tokens.
    using AdminFn = std::function<bool(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string&, const std::string&)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    template <class T>
    using Read = std::function<std::expected<T, std::string>()>;

    AuthFn auth_fn;
    AdminFn admin_fn;
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
    std::function<std::expected<std::string, std::string>(const std::string&)> revoke_detail_fn;
};

/// Throws `std::invalid_argument` when any `Deps` member is unbound.
void register_access_tokens_routes(HttpRouteSink& sink, Deps deps);

} // namespace access_tokens
} // namespace yuzu::server
