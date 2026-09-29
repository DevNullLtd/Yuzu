#pragma once

/// @file deprovision_revoke.hpp
///
/// ADR-2001 §§1,3 — the deprovision-time principal-set resolver and
/// credentials-FIRST revoke orchestrator, shared by every human-deprovision
/// seam: SCIM `active:false` (PATCH/PUT, via the shared `deactivate()`
/// helper), SCIM `DELETE .../Users/{id}`, SCIM create-with-`active:false`
/// (all `scim_routes.cpp`), and the dashboard `DELETE /api/settings/users/
/// {username}` (`settings_routes.cpp`).
///
/// Lives ABOVE `ScimStore`/`ApiTokenStore`/`AuthManager` (the three stores it
/// calls in sequence) — never inside any of them (INV-31-3, one owning store
/// each; this file is orchestration, not storage).
///
/// LOCK/POOL DISCIPLINE (hard invariant, ADR-2001 §3): the three stores share
/// one bounded `pg_pool_`. Every function here calls each store's public
/// method in strict SEQUENCE and never holds one store's pool lease while
/// calling another (a nested second lease from the same pool can exhaust/
/// deadlock it, `api_token_store.hpp:257`). `AuthManager::mu_` stays a leaf,
/// never held across a store/DB call — each iteration below is a bare
/// sequence of independent, self-contained calls with no lock spanning them.
///
/// Explicitly NOT `session_revoke_fn` (`server.cpp:15346`) — that helper is
/// session-FIRST and carries `caller=self|admin` metric semantics that do
/// not apply to a deprovision. This is a distinct orchestrator over the same
/// two underlying primitives (`ApiTokenStore::revoke_for_principal` +
/// `AuthManager::invalidate_user_sessions`), credentials-FIRST per ADR-2001
/// §3.

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class ScimStore;
class ApiTokenStore;

namespace auth {
class AuthManager;
}

/// ADR-2001 §1 (PR4a extends it to SAML) — the principal-set resolver. Given
/// a SCIM slug's `scim_id` and its `slug_username`, returns the SET of
/// principal strings a deprovision must revoke = `{slug_username}` UNION
/// `{oidc_principal_id(iss, sub) for each row ScimStore::links_for_scim_id
/// (scim_id) returns}` UNION `{saml_principal_id(entity_id, name_id) for
/// each row ScimStore::saml_links_for_scim_id(scim_id) returns}`. Every
/// `oidc:` string is built through `oidc::oidc_principal_id`
/// (`oidc_principal.hpp`) and every `saml:` string through
/// `saml::saml_principal_id` (`saml_principal.hpp`) — never hand-built (a
/// format drift would silently miss every session/token for that principal,
/// "reported success, revoked nothing").
///
/// FAILS CLOSED: returns `nullopt` when EITHER `links_for_scim_id` OR
/// `saml_links_for_scim_id` could not answer (a store blip/lease timeout).
/// `nullopt` is DISTINCT from "no links" (an engaged-but-empty result —
/// folded into the 1-element `{slug_username}` vector below) and the caller
/// MUST treat it as "the link population is unknown", never as "there is
/// nothing to revoke". Reporting a clean deprovision success after a
/// resolution failure is the exact silent-under-revocation gap ADR-2001
/// exists to close.
std::optional<std::vector<std::string>>
resolve_deprovision_principals(ScimStore& scim_store, const std::string& scim_id,
                               const std::string& slug_username);

/// Dashboard-delete variant: `settings_routes.cpp`'s `DELETE /api/settings/
/// users/{username}` starts from a bare username, not an already-resolved
/// `scim_id` (unlike the SCIM route handlers, which always have one from
/// `ScimStore::get_by_scim_id`/`get_by_username` already in hand). Looks the
/// user up via `ScimStore::get_by_username` first, then delegates to
/// `resolve_deprovision_principals`.
///
/// Degrades to the slug-only set `{username}` (never fails closed) when
/// `scim_store` is null/not open, OR when `username` GENUINELY does not
/// resolve to a live SCIM resource (per `ScimStore::get_by_username_checked`'s
/// tri-state contract) — BOTH cases mean "this account was never SCIM-
/// provisioned, so no `identity_links` row could possibly reference it",
/// which is a well-understood absence, not a read failure. This differs
/// deliberately from `resolve_deprovision_principals`'s `nullopt` fail-
/// closed contract, which is reserved for a genuine link-lookup failure on a
/// KNOWN SCIM user (the case this wrapper still propagates unchanged once it
/// has resolved a `scim_id`) — AND (governance Gate 7 BLOCKING fix, UP-7)
/// for a `get_by_username_checked` STORE ERROR (lease timeout / query
/// error), which this wrapper now also propagates as `nullopt` rather than
/// misreading it as "not a SCIM user" and quietly degrading to slug-only.
std::optional<std::vector<std::string>>
resolve_deprovision_principals_for_username(ScimStore* scim_store, const std::string& username);

/// Outcome of `revoke_deprovision_credentials` — everything a caller needs
/// to decide fail-open-vs-closed and to build the audit detail string
/// (mirrors `/me`'s `api_tokens_revoked=N`/`api_tokens_db_error=true`
/// pattern, `rest_api_v1.cpp:3934`).
struct DeprovisionRevokeResult {
    /// Sum of `ApiTokenStore::revoke_for_principal`'s returned counts across
    /// every principal whose revoke call persisted. Does NOT include a
    /// principal whose revoke call returned `unexpected`.
    std::size_t api_tokens_revoked{0};
    /// False iff `revoke_for_principal` returned `unexpected` for AT LEAST
    /// ONE principal in the set (lease timeout / query error — did NOT
    /// persist). The caller MUST NOT report a clean deprovision success when
    /// this is false — SCIM 500s so the IdP retries (ADR-2001 §3); the
    /// dashboard delete reports the same failure without proceeding to
    /// `remove_user`.
    bool api_tokens_persisted{true};
    /// Sum of in-memory session counts erased (`AuthManager::RevokeResult::
    /// count`) across every principal.
    std::size_t sessions_revoked{0};
};

/// ADR-2001 §3 — the credentials-FIRST orchestrator. For EACH principal in
/// `principals` (in order): revoke its API tokens, then its sessions — never
/// the reverse, and never two stores' leases held simultaneously (see the
/// lock/pool discipline note above). Continues through every principal even
/// after a non-persisted token revoke — best-effort, maximises what actually
/// gets revoked — but records the failure in the returned result so the
/// caller fails closed on the OVERALL outcome rather than reporting a clean
/// success.
DeprovisionRevokeResult
revoke_deprovision_credentials(ApiTokenStore& token_store, auth::AuthManager& auth_mgr,
                               const std::vector<std::string>& principals);

/// Governance Gate 7 SHOULD fix (UP-5, CC6.8 evidence): a shared audit-detail
/// fragment enumerating the resolved principal set — `oidc:<iss>#<sub>`
/// strings, plus the plain slug — so the deprovision's audit row is
/// self-contained CC6.8 evidence rather than a bare count. Both
/// `scim_routes.cpp`'s `revoke_linked_credentials_or_fail` and
/// `settings_routes.cpp`'s dashboard DELETE seam call this — a second
/// hand-rolled copy is the drift this shared helper exists to avoid.
///
/// Capped at the first `kMaxEnumeratedPrincipals` entries (append order,
/// i.e. slug first then every linked identity) with a "(+N more)" suffix,
/// so a slug with an unusually large number of linked identities cannot
/// blow out the audit detail string. Returns an empty string for an empty
/// `principals` (nothing to enumerate — callers append this directly onto
/// their existing detail string, so a leading space is included when
/// non-empty).
constexpr std::size_t kMaxEnumeratedPrincipals = 10;
std::string enumerate_principals_for_audit(const std::vector<std::string>& principals);

} // namespace yuzu::server
