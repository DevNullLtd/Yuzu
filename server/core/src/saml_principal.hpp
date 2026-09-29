#pragma once

/// @file saml_principal.hpp
///
/// ADR-2001 PR4a — the SAML analogue of `oidc_principal.hpp`'s §5 builder:
/// the single shared builder for the stable SAML RBAC/session principal
/// string. Before this file existed, SAML sessions were keyed on the raw
/// NameID alone (`AuthManager::create_saml_session`, auth.cpp — "#1837
/// fast-follow" comment), which is unsafe as a durable join key: NameID is
/// only unique *within* one IdP, and two different IdPs (or a future
/// multi-tenant deployment) could assert the identical NameID string for two
/// different humans. A deprovision-time revoke path (this same PR) needs a
/// SECOND site that reconstructs the exact same string from a resolved
/// `(entity_id, name_id)` pair — a format drift between the mint site
/// (`AuthManager::create_saml_session`) and that resolve site
/// (`deprovision_revoke.cpp`) would silently miss every SAML session for the
/// affected principal ("reported success, revoked nothing", the exact
/// failure ADR-2001 exists to prevent). Routing every construction site
/// through one function makes that drift impossible by construction — same
/// rationale as `oidc_principal_id`.
///
/// `entity_id` is the operator-configured, boot-validated IdP entityID
/// (`--saml-idp-entity-id` / `Config::saml_idp_entity_id`) — already
/// verified by `SamlProvider::validate_response` to equal the assertion's
/// signed `<saml:Issuer>` before either construction site below ever sees
/// it (single-IdP precondition: one pinned cert, one entity_id). `name_id`
/// is the assertion's verified NameID.
///
/// Deliberately header-only / free-function / no dependency on
/// `saml_provider.hpp` (which pulls xmlsec1/libxml2/zlib for XML-DSig
/// verification) — this is pure string formatting, so a caller that only
/// needs the principal string (the deprovision resolver) does not have to
/// pay for or depend on the SAML verifier's machinery. Mirrors
/// `oidc_principal.hpp`'s own rationale exactly.
///
/// Do NOT change the string format here without auditing every session/RBAC/
/// audit row already keyed on the old format.

#include <string>
#include <string_view>

namespace yuzu::server::saml {

/// Builds the stable SAML RBAC/session principal string for an identity
/// asserted by IdP `entity_id` with verified NameID `name_id`. Exactly
/// `"saml:" + entity_id + "#" + name_id` — pinned format, see the file
/// header. Mirrors `oidc_principal_id`'s `"oidc:" + iss + "#" + sub` shape
/// byte-for-byte.
[[nodiscard]] inline std::string saml_principal_id(std::string_view entity_id,
                                                    std::string_view name_id) {
    std::string out;
    out.reserve(std::string_view("saml:").size() + entity_id.size() + 1 + name_id.size());
    out.append("saml:");
    out.append(entity_id);
    out.append("#");
    out.append(name_id);
    return out;
}

/// Sanitation gate mirroring `OidcProvider::validate_claims`'s `sub`/`oid`
/// rule (oidc_provider.cpp) exactly: non-empty, <=255 bytes, no byte <0x20
/// or ==0x7F. Applied to both `name_id` and `entity_id` BEFORE either value
/// enters the stable principal string above (the session's durable RBAC/
/// audit key) or the `saml_identity_links` store (`saml_scim_link.hpp`) — a
/// malformed value must reject the LOGIN outright (fail-closed, no session
/// minted), never be sanitized-and-continued, mirroring OIDC's posture for
/// the same class of durable-join-key input (see the ACS handler,
/// auth_routes.cpp, and the file header rationale above).
[[nodiscard]] inline bool is_valid_saml_component(std::string_view v) {
    constexpr std::size_t kMaxLen = 255;
    if (v.empty() || v.size() > kMaxLen)
        return false;
    for (unsigned char c : v) {
        if (c < 0x20 || c == 0x7F)
            return false;
    }
    return true;
}

} // namespace yuzu::server::saml
