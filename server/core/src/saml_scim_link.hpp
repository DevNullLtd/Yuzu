#pragma once

/// @file saml_scim_link.hpp
///
/// ADR-2001 PR4a — the SAML analogue of `oidc_scim_link.hpp`: the login-site
/// orchestration that forms a durable SCIM<->SAML identity link. Extracted
/// out of the `/saml/acs` handler (`auth_routes.cpp`) into a free function so
/// it is unit-testable directly against a real `ScimStore` without a live IdP
/// (mirrors `oidc_scim_link.hpp`'s own rationale — see
/// test_oidc_routes.cpp's docstring for why the full `/saml/acs` success path
/// itself is instead covered end-to-end in test_saml_routes.cpp, which DOES
/// have a signing harness, unlike the OIDC side).
///
/// Never throws: this is the fail-OPEN half of ADR-2001's login-time
/// linking contract — a link-write/lookup failure never fails the login.
/// Every `ScimStore` call failure is logged and swallowed here, mirroring
/// `link_oidc_login_to_scim` exactly.
///
/// NameID Format gate (architect BLOCK fix, ADR-2001 PR4a plan review): a
/// SAML NameID is only a safe join key when it is STABLE across logins and
/// equals the SCIM `externalId`. Transient/unspecified NameID Formats
/// silently fail or mislink if trusted the same way. This function forms a
/// link ONLY when the NameID Format is one of the STABLE formats
/// (`urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` or the SAML 1.1
/// `emailAddress` format) — a missing/empty Format is treated
/// CONSERVATIVELY as NOT linkable, never coerced/normalized into one that
/// is. A non-linkable-format NameID still mints a session (the login
/// succeeds); the identity is simply unlinkable/unrevocable-via-SCIM for
/// that login — the documented residual (see docs/adr/2001-scim-oidc-
/// identity-linkage.md).
///
/// ADR-2001 #3072 — SAML D2 observability: unlike the historical posture
/// above ("SAML has no login-observation/D2 analogue"), this function now
/// records a SAML login observation (`ScimStore::record_saml_login_observation`)
/// UNCONDITIONALLY, before the NameID-Format-linkable gate — even a
/// transient/unspecified-Format login is observed, so a later deprovision's
/// `saml_observation_matches` can still surface "a SAML login WAS attempted
/// under this externalId, but the NameID Format made it unlinkable" (SAML's
/// own D2-style tripwire, `scim_routes.cpp`'s `maybe_flag_saml_d2_unlinked`).
/// This is OBSERVE-ONLY: the observation is never normalized/promoted into a
/// link, and an unstable-format NameID is still never linked — see
/// `SamlScimLinkOutcome::not_linkable` below.

#include <optional>
#include <string>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {
class ScimStore;
}

namespace yuzu::server::saml {

/// True iff `name_id_format` is one of the SAML 2.0 NameID Format URIs this
/// codebase treats as STABLE (i.e. safe to use as a durable SCIM
/// `externalId` join key):
///  - `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
///  - `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
/// An empty (missing/unspecified) Format — and any other value, including
/// `transient` — is conservatively treated as NOT linkable.
[[nodiscard]] bool is_linkable_name_id_format(const std::string& name_id_format);

/// ADR-2001 #3072 — the typed outcome `link_saml_login_to_scim` resolves to.
/// This is an OBSERVABILITY signal only — every value below is a PROCEED
/// outcome for the login itself (login-time linking is fail-OPEN by
/// contract; see the file header). The caller uses this to decide what to
/// audit/count, never whether to deny the login.
///  - `not_linkable`: the NameID Format was not one of the STABLE formats
///    (`is_linkable_name_id_format` false) — no lookup was attempted, no
///    link formed. The observation was still recorded (unconditionally,
///    before this gate).
///  - `linked`: exactly one active SCIM resource matched `name_id` and the
///    `saml_identity_links` upsert succeeded.
///  - `no_active_match`: the NameID Format was linkable, but zero active
///    SCIM resources matched `name_id`.
///  - `ambiguous_match`: the NameID Format was linkable, but MORE THAN ONE
///    active SCIM resource matched `name_id` (ADR-2001 §2 mis-link guard —
///    an ambiguous externalId is never resolved arbitrarily).
///  - `lookup_store_error`: the NameID Format was linkable, but the
///    `ScimStore` lookup itself could not answer (closed store, lease
///    timeout, or a failed statement) — distinct from `no_active_match`
///    (a genuine zero-match answer) so the caller can tell "no match" from
///    "could not ask".
///  - `link_write_error`: exactly one active match was found, but the
///    `upsert_saml_link` write failed — the existing
///    `yuzu_scim_saml_link_write_failures_total` counter still fires for
///    this case (unchanged behaviour).
enum class SamlScimLinkOutcome {
    not_linkable,
    linked,
    no_active_match,
    ambiguous_match,
    lookup_store_error,
    link_write_error,
};

/// Resolves `name_id` (the caller MUST have already sanitised it — see
/// `saml_principal.hpp`'s `is_valid_saml_component`, applied at the ACS
/// handler before either this call or session mint) against `scim_store`'s
/// active SCIM resources, but ONLY when `name_id_format` is linkable
/// (`is_linkable_name_id_format`):
///  - Exactly one active match: upserts a `saml_identity_links` row for
///    `(entity_id, name_id)` -> that resource's `scim_id`.
///  - Zero or more-than-one match, OR a non-linkable Format: forms NO link
///    — an ambiguous `externalId` (or an unstable NameID) is never resolved
///    arbitrarily (ADR-2001 §2 mis-link guard, mirrored from the OIDC side;
///    `ScimStore::find_unique_active_by_external_id_checked` already encodes
///    the ambiguity rule, this function just consumes it).
///
/// ADR-2001 #3072: records a SAML login observation
/// (`ScimStore::record_saml_login_observation`) UNCONDITIONALLY, first —
/// before the NameID-Format-linkable gate — so even an unstable-format
/// login is observed (needed for the SAML D2 detector,
/// `scim_routes.cpp`'s `maybe_flag_saml_d2_unlinked`). The NameID itself is
/// never normalized here — only observed as-is. `name_id_format`, unlike
/// the NameID, IS bounded before it is recorded (Gate 7 fix): a value
/// exceeding 255 bytes or containing a control byte (<0x20 or ==0x7F)
/// collapses to `""` ("format unspecified") rather than being stored
/// as-is — defense-in-depth against a hostile/misconfigured pinned IdP
/// growing the observations table's index unbounded. A missing/empty
/// Format is a normal, legitimate IdP configuration and is recorded as
/// `""` either way — it is never treated as a reason to skip the
/// observation write (see `ScimStore::record_saml_login_observation`'s own
/// doc comment).
///
/// `metrics` may be null (test/CLI contexts) — bumps
/// `yuzu_scim_saml_link_write_failures_total` on an `upsert_saml_link`
/// failure; a no-op counter otherwise.
///
/// `scim_store` may be null (no PG configured, or the store failed to open
/// at boot) — a safe no-op in that case (returns `not_linkable`), same
/// fail-OPEN posture as every other failure this function absorbs. Never
/// fails/throws — the caller's login has already succeeded (or is about to)
/// by the time this runs and must not be undone by a store hiccup here.
SamlScimLinkOutcome link_saml_login_to_scim(ScimStore* scim_store, const std::string& entity_id,
                                            const std::string& name_id,
                                            const std::string& name_id_format,
                                            yuzu::MetricsRegistry* metrics = nullptr);

/// ADR-2001 §4 (PR4b) — the deny-at-login backstop's resolve-and-decide
/// result. SAML analogue of `oidc_scim_link.hpp`'s `OidcLoginDenyDecision`
/// — same shape, same field-for-field meaning: `denied` is the single
/// question the login path needs answered; `scim_id` — when the decision
/// came from an actual linked identity (deactivated or orphaned) — names
/// which SCIM resource drove a DENY, and is `nullopt` on every PROCEED
/// outcome and on the store-unavailable DENY (there is no resource to
/// name — the store could not be asked).
struct SamlLoginDenyDecision {
    bool denied{false};
    std::optional<std::string> scim_id;
};

/// ADR-2001 §4 (PR4b) — the deny-at-login backstop's resolve-and-decide
/// step, SAML analogue of `oidc_scim_link.hpp`'s
/// `oidc_login_denied_deprovisioned`. Resolves `(entity_id, name_id)` via
/// `ScimStore::saml_linked_resource_active` and collapses its state into
/// the single question the login path needs: MUST this login be denied,
/// and if so, which SCIM resource drove it? Called from `/saml/acs`
/// TWICE — once before any mint, once again immediately after (the same
/// codex-caught check-then-mint race OIDC closes) — so both call sites
/// share exactly one decision function.
///
/// Unlike the OIDC side, there is no separate `link_claim_value` parameter:
/// SAML has exactly one join key (the NameID) and no claim-selection knob
/// (see the file header), so the reprovision check below always resolves
/// against `name_id` itself — the SAME value used to resolve
/// `saml_linked_resource_active` above it.
///
/// `denied == true` iff:
///  - `scim_store` is present but could not answer
///    (`saml_linked_resource_active`'s OUTER `nullopt`) — fail-closed,
///    never treated as "no link"; `scim_id` is `nullopt` (no resource to
///    name — the caller's audit row must say "store unavailable", never
///    "resource inactive", mirroring OIDC's U6 fix);
///  - the linked resource resolved DEACTIVATED (engaged, `scim_id` set,
///    `active == false`) — `scim_id` carries the linked resource's id;
///  - the linked resource resolved ORPHANED (engaged, `scim_id` set,
///    `active == nullopt` — the `scim_resources` row was hard-deleted) AND
///    no ACTIVE resource exists for `name_id`
///    (`ScimStore::find_unique_active_by_external_id` returns `nullopt`) —
///    i.e. genuinely deprovisioned, not re-provisioned; `scim_id` carries
///    the stale (now-gone) linked resource's id.
///
/// `denied == false` (`scim_id` always `nullopt`) iff:
///  - `scim_store` is null — SCIM/ADR-2001 linkage is not configured at
///    all (mirrors `link_saml_login_to_scim`'s null-safety: no store means
///    no link could ever have formed, so there is nothing to deny against
///    — "feature off", not "store degraded");
///  - no `saml_identity_links` row exists for this identity (engaged,
///    `scim_id == nullopt`) — an unlinked SAML identity is not a
///    deprovisioned SCIM user;
///  - the linked resource resolved ACTIVE (engaged, `active == true`);
///  - the linked resource resolved ORPHANED, but an ACTIVE resource now
///    exists for `name_id` — the identity was DELETE'd then re-CREATE'd
///    under a new `scim_id` (a returning, re-provisioned user). PROCEED
///    lets the login continue; the imminent `link_saml_login_to_scim` call
///    repoints the stale `(entity_id, name_id)` link row to the new
///    `scim_id`, so the NEXT login resolves clean via the ordinary
///    active-link path.
///
/// The INACTIVE (deactivated, not orphaned) branch deliberately does NOT
/// run this reprovision check — mirrors the OIDC helper's rationale
/// exactly (see `oidc_scim_link.hpp`): reactivation is `active:true` on
/// the SAME `scim_id`, and the partial-unique index on
/// `scim_resources.external_id` prevents a second active resource sharing
/// the externalId while the inactive row still holds it.
///
/// Pure decision function: no audit, no metrics, no redirect — the caller
/// owns every side effect of a DENY (the byte-identical `/login?error=saml`
/// redirect, the `auth.saml.deprovisioned_denied` audit row carrying
/// `scim_id` when known, the `yuzu_auth_saml_deprovisioned_denied_total`
/// bump, and — on the post-mint call only — invalidating the session just
/// minted).
[[nodiscard]] SamlLoginDenyDecision
saml_login_denied_deprovisioned(ScimStore* scim_store, const std::string& entity_id,
                                const std::string& name_id);

} // namespace yuzu::server::saml
