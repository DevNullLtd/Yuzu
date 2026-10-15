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

/// RFC 3986 percent-encoding of one query value: `A-Za-z0-9-._~` kept, every other byte as
/// uppercase `%XX`. (A durable SSO principal is `oidc:<iss>#<sub>`; an unencoded `#` is a
/// URL fragment separator and would silently truncate the request.)
std::string url_q(std::string_view s);

/// "local" -> "Local", "oidc" -> "OIDC", "saml" -> "SAML", "ad" -> "AD", "scim" -> "SCIM".
/// Anything else -> empty: the caller renders the escaped raw token instead of dropping it.
std::string_view source_label(std::string_view identity_source);

} // namespace yuzu::server::access
