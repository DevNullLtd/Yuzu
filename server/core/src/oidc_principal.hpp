#pragma once

/// @file oidc_principal.hpp
///
/// ADR-2001 §5 — the single shared builder for the stable OIDC RBAC
/// principal string. Before this file existed, `"oidc:" + iss + "#" + sub`
/// was hand-built at two independent sites (`AuthManager::create_oidc_session`
/// in auth.cpp, and the `/auth/callback` handler in auth_routes.cpp) with
/// comments cross-referencing each other to stay in sync by hand. A future
/// deprovision-time revoke path (ADR-2001 §3) needs a THIRD site that
/// reconstructs the exact same string from a resolved `(iss, sub)` pair — a
/// format drift between the mint site and that resolve site would silently
/// miss every token for the affected principal ("reported success, revoked
/// nothing", the exact failure ADR-2001 exists to prevent). Routing every
/// construction site through one function makes that drift impossible by
/// construction.
///
/// Deliberately header-only / free-function / no dependency on
/// `oidc_provider.hpp` (which pulls `<openssl/evp.h>` for JWT verification) —
/// this is pure string formatting, so callers that only need the principal
/// string (e.g. a future ScimStore-driven resolver) do not have to pay for
/// or depend on the OIDC provider's JWKS/PKCE machinery. Lives beside
/// `oidc_provider.{hpp,cpp}` (lowest-coupling home: both current callers
/// already sit next to or under that pair) rather than inside it.
///
/// Do NOT change the string format here without auditing every session /
/// RBAC / audit row already keyed on the old format — see the constraint in
/// docs/adr/2001-scim-oidc-identity-linkage.md ("The `oidc:<iss>#<sub>`
/// principal is the RBAC key and cannot be re-keyed").

#include <string>
#include <string_view>

namespace yuzu::server::oidc {

/// Builds the stable OIDC RBAC/session principal string for an identity
/// asserted by issuer `iss` with stable subject `sub`. Exactly
/// `"oidc:" + iss + "#" + sub` — pinned format, see the file header.
[[nodiscard]] inline std::string oidc_principal_id(std::string_view iss, std::string_view sub) {
    std::string out;
    out.reserve(std::string_view("oidc:").size() + iss.size() + 1 + sub.size());
    out.append("oidc:");
    out.append(iss);
    out.append("#");
    out.append(sub);
    return out;
}

} // namespace yuzu::server::oidc
