#pragma once

/// @file access_render.hpp
/// Pure HTML renderers for the Access pages (Phase 2 UI). Today: the Users list and the
/// selected-account panel of `/access/users`. No I/O, no logging, no store handles: the
/// route reads the store and hands a finished value in.
///
/// Three states are kept distinct everywhere, on purpose:
///   * a populated value,
///   * `NotFound`  - the store answered and no active account has that name,
///   * `Unavailable` - the store did NOT answer. The panel says so in a red box and never
///     draws an empty table, so a degraded account store cannot read as "nobody is here".
///
/// Every user-controlled string reaches the output through `html_escape` (attributes
/// included), and every `?username=` value through `url_q`. Credential material on
/// `auth::UserEntry` (`salt_hex`, `hash_hex`) is never read.
///
/// The denied / unavailable sentences below are the single source: the page template
/// carries them as `data-denied` / `data-unavailable` attributes and `yuzu-access.js`
/// builds its client-side boxes from those attributes.

#include "rbac_store.hpp"

#include <yuzu/server/auth.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace yuzu::server::access {

/// The account store did not answer. The route logs the cause; the renderer never sees it.
struct Unavailable {};
/// Detail: the store answered and no active account has that name.
struct NotFound {};

struct UsersList {
    std::vector<auth::UserEntry> users; ///< `AuthDB::list_users()` rows (active accounts only)
    std::string self;                   ///< the caller's username; never empty (the route refuses)
};

struct UserDetail {
    auth::UserEntry user;
    bool is_self = false;
};

/// `list_users()` has no LIMIT, so the cap is applied here.
inline constexpr std::size_t kUsersRenderCap = 500;

inline constexpr std::string_view kUsersDenied =
    "Listing users needs the Administrator account role.";
inline constexpr std::string_view kUsersUnavailable =
    "The account store did not answer, so the list is unknown. This is not an empty list and "
    "nobody has been removed.";
inline constexpr std::string_view kDetailUnavailable =
    "The account store did not answer, so this account could not be read.";
inline constexpr std::string_view kSelectUser = "Select a user from the list to see the account.";

/// The whole Users panel interior (`.hd` + body). It replaces the panel's innerHTML.
std::string render_users_list(const std::variant<UsersList, Unavailable>& state);

/// The whole Account panel interior. `retry_url` (already URL-encoded, same-origin) is the
/// Retry button's `hx-get` target and is used only for `Unavailable`.
std::string render_user_detail(const std::variant<UserDetail, NotFound, Unavailable>& state,
                               const std::string& retry_url = {});

/// The Account panel before any user is selected.
std::string render_select_user();

// ---- Roles and role permissions ---------------------------------------------------------

/// `RbacStore::list_roles_checked()` rows. A store that did not answer is `Unavailable`; the
/// store seeds seven roles, so an empty answer is treated as unreadable, never as "no roles".
struct RolesList {
    std::vector<RbacRole> roles;
};

/// One role's permission rows. The store answered; `rows` may be empty ("holds no permissions").
struct RolePerms {
    std::string role;
    std::vector<Permission> rows;
};

inline constexpr std::string_view kRolesDenied =
    "The role catalogue needs UserManagement:Read (the Administrator and Viewer roles).";
inline constexpr std::string_view kRolesUnavailable =
    "The role store did not answer, so the roles are unknown. This is not an empty list.";
inline constexpr std::string_view kRolePermsUnavailable =
    "The role store did not answer, so the permissions of this role are unknown. This is not an empty list.";
inline constexpr std::string_view kSelectRole = "Select a role to see what it allows.";

/// The whole Roles panel interior.
std::string render_roles_list(const std::variant<RolesList, Unavailable>& state);

/// The whole Role permissions panel interior. `NotFound` = the catalogue answered and holds no
/// such role (distinct from a role that holds no permissions). `retry_url` is used only for
/// `Unavailable`.
std::string render_role_permissions(const std::variant<RolePerms, NotFound, Unavailable>& state,
                                    const std::string& retry_url = {});

/// The Role permissions panel before any role is selected.
std::string render_select_role();

/// True for a name that can safely be sent as ONE request segment or query value without any
/// quoting: 1-64 of `A-Za-z0-9._-`, and not made only of dots (`.` and `..` are resolved away
/// by a browser even when percent-encoded). The same charset the REST routes' own regexes use.
bool is_addressable_name(std::string_view name);

/// RFC 3986 percent-encoding of one query value: `A-Za-z0-9-._~` kept, every other byte as
/// uppercase `%XX`. (A durable SSO principal is `oidc:<iss>#<sub>`; an unencoded `#` is a
/// URL fragment separator and would silently truncate the request.)
std::string url_q(std::string_view s);

/// "local" -> "Local", "oidc" -> "OIDC", "saml" -> "SAML", "ad" -> "AD", "scim" -> "SCIM".
/// Anything else -> empty: the caller renders the escaped raw token instead of dropping it.
std::string_view source_label(std::string_view identity_source);

} // namespace yuzu::server::access
