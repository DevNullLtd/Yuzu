#pragma once

/// @file access_tokens_render.hpp
/// Tokens and principals page (Phase 2 UI): pure HTML renderers. No I/O, no logging, no
/// store handle: every input is a value, so every state is reachable from a fixture.
///
/// Rules every renderer follows:
///   - every store-sourced string goes through `html_escape`; ids ride in `data-*` attributes
///     and are percent-encoded by the page script (`encodeURIComponent`), never here. A row
///     whose id is outside the charset its route accepts gets NO action control at all;
///   - a control is rendered only when the caller can use it (`TokenCaps` and friends are
///     decided by the route, never guessed here); a fixed sentence says what is missing;
///   - a read that did not answer is `Unavailable` and renders a fixed sentence. The store's
///     own error text is never rendered (#5063);
///   - a read that answered with nothing is an honest empty state, never a bare `0`.

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "engine_principal_store.hpp"
#include "rbac_store.hpp"

#include <yuzu/server/auth.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace yuzu::server::access_tokens {

/// The store did not answer. Distinct from a successful empty read.
struct Unavailable {};
/// The caller may not read the source (the audit trail, or the custom-role catalog), or the grant
/// could not be confirmed: shown as withheld, not as "none".
struct Withheld {};
/// The id is well-formed but no such principal exists.
struct NotFound {};

/// Rows rendered per panel; beyond it the panel says how many there are.
inline constexpr std::size_t kRenderCap = 500;

// Fixed sentences. The page template's `data-denied` / `data-unavailable` attributes repeat
// these byte for byte; test_access_tokens_js.cpp pins the equality so the copies cannot drift.
inline constexpr const char* kTokensDenied = "Listing API tokens needs the ApiToken:Read permission.";
inline constexpr const char* kTokensUnavailable =
    "The token store did not answer, so the list is unknown. This is not an empty list.";
inline constexpr const char* kPrincipalsDenied =
    "Engine principals need the EnginePrincipal:Read permission.";
inline constexpr const char* kPrincipalsUnavailable =
    "The principal store did not answer, so the list is unknown. This is not an empty list.";
inline constexpr const char* kDetailUnavailable = "This principal could not be read.";

/// What the caller can do to API tokens. Decided by the route (RBAC off: the account role;
/// RBAC on: one gate probe per permission), so a control is never drawn that the server
/// would refuse. The server stays authoritative either way.
struct TokenCaps {
    bool create{false};  ///< ApiToken:Write
    bool revoke{false};  ///< ApiToken:Delete (and the row is the caller's, or the caller is admin)
    bool rotate{false};  ///< ApiToken:Rotate (rotate and confirm; owner-only on the server)
};

/// Facts about the caller that the page script needs without a probe request.
struct PageFlags {
    std::int64_t now{0};          ///< server epoch seconds (`data-now`)
    bool effective_admin{false};  ///< cookie session holding the admin role (account or JIT)
    bool rbac_enforced{false};
    std::string caller;           ///< session username; rotate and confirm are owner-only
    TokenCaps caps;               ///< default: read-only
};

/// Ids that may reach a request path. Each matches (or is narrower than) the charset of the
/// route that receives it; anything else renders without action controls.
[[nodiscard]] bool safe_token_id(std::string_view id);  ///< `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`
/// The bare slug of a valid engine principal id ("" when the id is not valid).
[[nodiscard]] std::string principal_slug(std::string_view principal_id);

/// True only for a cookie session whose effective role is admin. Any bearer (API, MCP,
/// engine) or service-scoped session gets its own tokens only, as the REST twin does.
[[nodiscard]] bool sees_all_owners(const auth::Session& s);

/// `^engine:[a-z0-9._-]{1,128}$`. Checked before any store read.
[[nodiscard]] bool valid_principal_id(std::string_view id);

/// The detail of the ORIGINAL committed `engine_principal.revoke` (input is newest first).
/// A later failed or denied attempt writes the same action with a store error string as its
/// detail; that text is never shown. "" = no committed revoke recorded. The success detail is
/// `credentials_revoked=N[; superseded_by=ID]` from REST, or the operator's own typed reason
/// from MCP; it is escaped like every other store string.
[[nodiscard]] std::string committed_revoke_detail(const std::vector<AuditEvent>& newest_first);

/// Newest-first window of `engine_principal.revoke` audit events read for one principal. The
/// query asks for one row more (`kRevokeHistoryQueryLimit`) so "more exist" is observable.
inline constexpr int kRevokeHistoryWindow = 200;
inline constexpr int kRevokeHistoryQueryLimit = kRevokeHistoryWindow + 1;

/// The original revoke's detail plus whether the window was full (so an older original may
/// lie beyond it).
struct RevokeDetail {
    std::string text;
    bool truncated{false};
};

/// `committed_revoke_detail` over at most `kRevokeHistoryWindow` events, with `truncated` set
/// when the query returned the extra row (input is newest first, up to the query limit).
[[nodiscard]] RevokeDetail revoke_detail_from(std::vector<AuditEvent> newest_first);

struct TokensView {
    std::vector<ApiToken> rows;  ///< store order (newest first)
    bool all_owners{false};      ///< true when rows span every owner
    bool show_all{false};        ///< "All" toggle; false = active only
};

[[nodiscard]] std::string render_tokens_list(const std::variant<TokensView, Unavailable>& v,
                                             const PageFlags& flags);

struct PrincipalsView {
    std::vector<EnginePrincipalRow> rows;
    /// Bulk role grants (principal_type "engine"), or Unavailable -> "Not shown".
    std::variant<std::vector<PrincipalRole>, Unavailable> roles;
    /// The caller holds AuditLog:Read, which the no-administrator check (a REST call the page
    /// script makes) needs; `data-check` tells the script whether to make it.
    bool can_run_check{false};
    bool can_write{false};  ///< Security:Write: "New principal" is drawn only when true
    bool rbac_enforced{false};
};

[[nodiscard]] std::string render_principals_list(const std::variant<PrincipalsView, Unavailable>& v);

/// The names an engine principal may hold: every non-system role, in store order.
[[nodiscard]] std::vector<std::string> custom_role_names(const std::vector<RbacRole>& roles);

struct PrincipalDetail {
    EnginePrincipalRow row;
    std::variant<std::vector<ApiToken>, Unavailable> credentials;  ///< active credentials
    std::variant<std::vector<PrincipalRole>, Unavailable> roles;
    /// Revoked rows only: the audit detail string, "" = not recorded, Unavailable = the audit
    /// store did not answer, Withheld = the caller lacks AuditLog:Read.
    std::variant<std::string, Unavailable, Withheld> revoke_detail;
    /// The revoke-history window was full: the detail shown is the oldest success within it.
    bool revoke_truncated{false};
    std::int64_t now{0};
    bool can_write{false};  ///< Security:Write: every principal action is drawn only when true
    bool rbac_enforced{false};
    /// Names of the roles an engine principal may hold (non-system roles only). Empty = none
    /// exist: Assign is drawn disabled with the reason. Unavailable = the role list could not
    /// be read: Assign is disabled and the panel says so, never "no custom roles". Withheld =
    /// the caller lacks UserManagement:Read (the REST role listing's gate): no name is drawn.
    std::variant<std::vector<std::string>, Unavailable, Withheld> custom_roles;
};

[[nodiscard]] std::string render_principal_detail(
    const std::variant<PrincipalDetail, NotFound, Unavailable>& v, const std::string& id);

/// "Select a principal from the list." placeholder.
[[nodiscard]] std::string render_select_principal();

} // namespace yuzu::server::access_tokens
