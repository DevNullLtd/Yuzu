#include "deprovision_revoke.hpp"

#include "api_token_store.hpp"
#include "oidc_principal.hpp"
#include "saml_principal.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/scim_store.hpp>

#include <algorithm>

namespace yuzu::server {

std::optional<std::vector<std::string>>
resolve_deprovision_principals(ScimStore& scim_store, const std::string& scim_id,
                               const std::string& slug_username) {
    auto links = scim_store.links_for_scim_id(scim_id);
    if (!links.has_value())
        return std::nullopt; // fail closed — the store could not answer

    // ADR-2001 PR4a — SAML second pass, mirroring the OIDC pass immediately
    // above exactly (same fail-closed contract on its own nullopt).
    auto saml_links = scim_store.saml_links_for_scim_id(scim_id);
    if (!saml_links.has_value())
        return std::nullopt; // fail closed — the store could not answer

    std::vector<std::string> principals;
    principals.reserve(1 + links->size() + saml_links->size());
    principals.push_back(slug_username);
    for (const auto& linked : *links)
        principals.push_back(oidc::oidc_principal_id(linked.iss, linked.sub));
    for (const auto& linked : *saml_links)
        principals.push_back(saml::saml_principal_id(linked.entity_id, linked.name_id));
    return principals;
}

std::optional<std::vector<std::string>>
resolve_deprovision_principals_for_username(ScimStore* scim_store, const std::string& username) {
    if (!scim_store || !scim_store->is_open()) {
        // No SCIM store wired — no scim_resources/identity_links row can
        // exist under this configuration, so there is provably nothing to
        // link. Degrade to the slug-only set rather than failing closed
        // (see the header doc — this differs deliberately from a genuine
        // link-lookup failure on a KNOWN SCIM user, below).
        return std::vector<std::string>{username};
    }
    // Governance Gate 7 BLOCKING fix (UP-7): `get_by_username` collapses a
    // genuine "no such resource" with "the store could not answer" (lease
    // timeout / query error) into the same bare `nullopt` — so under pool
    // exhaustion a KNOWN linked user's OIDC identities were silently
    // dropped from the deprovision (this degraded to the slug-only set
    // exactly as if the user had never been SCIM-provisioned). Use the
    // tri-state `get_by_username_checked` instead so the two cases are
    // told apart.
    auto checked = scim_store->get_by_username_checked(username);
    if (!checked.has_value()) {
        // OUTER nullopt: the store could not answer. FAIL CLOSED — never
        // degrade to slug-only here, that is precisely the silent-under-
        // revocation gap this function otherwise avoids for a resolution
        // failure past this point.
        return std::nullopt;
    }
    if (!checked->has_value()) {
        // INNER nullopt: the store answered and genuinely has no resource
        // for `username` — not a SCIM-provisioned user, so no possible
        // identity_links row either way.
        return std::vector<std::string>{username};
    }
    return resolve_deprovision_principals(*scim_store, (*checked)->scim_id, username);
}

std::string enumerate_principals_for_audit(const std::vector<std::string>& principals) {
    if (principals.empty())
        return {};
    const std::size_t n = std::min(principals.size(), kMaxEnumeratedPrincipals);
    std::string out = " revoked_principals=";
    for (std::size_t i = 0; i < n; ++i) {
        if (i != 0)
            out += ",";
        out += principals[i];
    }
    if (principals.size() > n)
        out += " (+" + std::to_string(principals.size() - n) + " more)";
    return out;
}

DeprovisionRevokeResult
revoke_deprovision_credentials(ApiTokenStore& token_store, auth::AuthManager& auth_mgr,
                               const std::vector<std::string>& principals) {
    DeprovisionRevokeResult result;
    for (const auto& principal : principals) {
        // Credentials FIRST — tokens before sessions, this principal fully
        // handled before the next. Never a lease from token_store held
        // while calling auth_mgr (or vice versa): each call below is
        // self-contained and returns before the next begins.
        auto revoked = token_store.revoke_for_principal(principal);
        if (!revoked.has_value()) {
            result.api_tokens_persisted = false;
        } else {
            result.api_tokens_revoked += *revoked;
        }
        auto sessions = auth_mgr.invalidate_user_sessions(principal);
        result.sessions_revoked += sessions.count;
        // Sessions are in-memory-only (AuthManager::invalidate_user_sessions
        // ' RevokeResult::db_persisted is always true today — no durable
        // session surface exists to fail to persist to) — nothing to fold
        // into api_tokens_persisted here.
    }
    return result;
}

} // namespace yuzu::server
