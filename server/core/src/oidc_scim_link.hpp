#pragma once

/// @file oidc_scim_link.hpp
///
/// ADR-2001 §2/D2 — the login-site orchestration that forms a durable
/// SCIM<->OIDC identity link and records the D2 login-observation signal.
/// Extracted out of the `/auth/callback` handler (`auth_routes.cpp`) into a
/// free function so it is unit-testable directly against a real `ScimStore`
/// without a live IdP (mirrors `oidc_principal_id` in `oidc_principal.hpp` —
/// the same "pull the orchestration out of the handler" pattern Task 1
/// already established for the principal-string builder).
///
/// Deliberately `void` and never throws: this is the fail-OPEN half of
/// ADR-2001 §2 ("a failed write never fails the login"). Every ScimStore
/// call failure is logged and swallowed here so the caller never has to
/// check a return value or catch anything to keep that guarantee — a future
/// call site cannot accidentally wire this into a fail-closed path.
///
/// Governance Gate 7 BLOCKING fix (D2 tripwire, the crux): the headline D2
/// misconfiguration is an operator running `--oidc-scim-link-claim=sub`
/// while the SCIM externalId is actually the Entra `oid` — under the prior
/// "record the configured claim only" behaviour, the login observation held
/// the sub-value, never the oid-value, so a deprovision's
/// `observation_matches(external_id)` (keyed on the oid value) never
/// matched and D2 never fired for the exact case it exists to catch. This
/// function now records an observation for EACH candidate claim (`sub` AND
/// `oid`, when present and sane) regardless of which one is configured for
/// LINK FORMATION — see `oidc_scim_link.cpp`'s `is_sane_claim_value`.

#include <optional>
#include <string>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {
class ScimStore;
}

namespace yuzu::server::oidc {

/// Resolves `link_claim_value` (the validated `sub` or `oid`, per
/// `--oidc-scim-link-claim`) against `scim_store`'s active SCIM resources:
///  - Exactly one active match: upserts an `identity_links` row for
///    `(iss, sub)` -> that resource's `scim_id`.
///  - Zero or more-than-one match: forms NO link — an ambiguous
///    `external_id` is never resolved arbitrarily (ADR-2001 §2 mis-link
///    guard; `ScimStore::find_unique_active_by_external_id` already encodes
///    this, this function just consumes it).
/// LINK FORMATION uses ONLY `link_claim_value` (the configured claim) —
/// unchanged from before.
///
/// ALWAYS records a login observation for EACH of `sub` and `oid` that is
/// non-empty and passes basic claim-value sanitation (`is_sane_claim_value`
/// in the .cpp — mirrors `OidcProvider::validate_claims`'s length/control-
/// byte rule), regardless of whether a link formed and regardless of which
/// one is the configured link claim — the D2 detector's data source
/// (`ScimStore::observation_matches`). `oid` may be unsanitized/malformed
/// here: `OidcProvider::validate_claims` only validates it when it is the
/// CONFIGURED link claim (a missing/malformed `oid` must not fail a login
/// under the default `sub` link-claim configuration), so this function
/// re-applies the same sanitation rule before trusting it into a durable
/// row.
///
/// `metrics` may be null (test/CLI contexts) — bumps
/// `yuzu_scim_oidc_link_write_failures_total` on any `upsert_link`/
/// `record_login_observation` failure (UP-6); a no-op counter otherwise.
///
/// `scim_store` may be null (no PG configured, or the store failed to open
/// at boot) — a safe no-op in that case, same fail-OPEN posture as every
/// other failure this function absorbs. Never fails/throws — the caller's
/// login has already succeeded by the time this runs and must not be
/// undone by a store hiccup here.
void link_oidc_login_to_scim(ScimStore* scim_store, const std::string& iss, const std::string& sub,
                             const std::string& oid, const std::string& link_claim_value,
                             yuzu::MetricsRegistry* metrics = nullptr);

/// ADR-2001 §4 — the deny-at-login backstop's resolve-and-decide result.
/// `denied` is the single question the login path needs answered; `scim_id`
/// — when the decision came from an actual linked identity (deactivated or
/// orphaned) — names which SCIM resource drove a DENY, so the CC6.8 audit
/// row is self-contained ("denied because resource X was deprovisioned",
/// not just "denied"). `scim_id` is `nullopt` on every PROCEED outcome, and
/// also on the store-unavailable DENY (there is no resource to name — the
/// store could not be asked).
struct OidcLoginDenyDecision {
    bool denied{false};
    std::optional<std::string> scim_id;
};

/// ADR-2001 §4 — the deny-at-login backstop's resolve-and-decide step.
/// Resolves `(iss, sub)` via `ScimStore::linked_resource_active` and
/// collapses its state into the single question the login path needs: MUST
/// this login be denied, and if so, which SCIM resource drove it? Called
/// from `/auth/callback` TWICE — once before any mint, once again
/// immediately after (the codex-caught check-then-mint race) — so both call
/// sites share exactly one decision function rather than each hand-rolling
/// the mapping.
///
/// `link_claim_value` is the SAME externalId candidate link-formation uses
/// (`cfg_.oidc_scim_link_claim == "oid" ? claims.oid : claims.sub` at the
/// call site) — needed to distinguish "genuinely deleted" from
/// "DELETE'd then re-CREATE'd under a new scim_id" on the orphaned-link
/// path below (governance unhappy-path finding U1: without this, a
/// returning re-provisioned user is permanently locked out, because the
/// re-link that would repoint their stale `identity_links` row to the new
/// `scim_id` runs at `link_oidc_login_to_scim`, AFTER this check).
///
/// `denied == true` iff:
///  - `scim_store` is present but could not answer
///    (`linked_resource_active`'s OUTER `nullopt`) — fail-closed, never
///    treated as "no link"; `scim_id` is `nullopt` (no resource to name —
///    the caller's audit row must say "store unavailable", never
///    "resource inactive", U6);
///  - the linked resource resolved DEACTIVATED (engaged, `scim_id` set,
///    `active == false`) — `scim_id` carries the linked resource's id;
///  - the linked resource resolved ORPHANED (engaged, `scim_id` set,
///    `active == nullopt` — the `scim_resources` row was hard-deleted) AND
///    no ACTIVE resource exists for `link_claim_value`
///    (`ScimStore::find_unique_active_by_external_id` returns `nullopt`) —
///    i.e. genuinely deprovisioned, not re-provisioned; `scim_id` carries
///    the stale (now-gone) linked resource's id.
///
/// `denied == false` (`scim_id` always `nullopt`) iff:
///  - `scim_store` is null — SCIM/ADR-2001 linkage is not configured at all
///    (mirrors `link_oidc_login_to_scim`'s null-safety: no store means no
///    link could ever have formed, so there is nothing to deny against —
///    this is "feature off", not "store degraded", and must not block
///    every OIDC login on a deployment that never enabled SCIM);
///  - no `identity_links` row exists for this identity (engaged,
///    `scim_id == nullopt`) — an unlinked OIDC identity is not a
///    deprovisioned SCIM user;
///  - the linked resource resolved ACTIVE (engaged, `active == true`);
///  - the linked resource resolved ORPHANED, but an ACTIVE resource now
///    exists for `link_claim_value` — the identity was DELETE'd then
///    re-CREATE'd under a new `scim_id` (a returning, re-provisioned
///    user). PROCEED lets the login continue; the re-link at
///    `link_oidc_login_to_scim` (which runs right after this check
///    succeeds) repoints the stale `(iss, sub)` link row to the new
///    `scim_id`, so the NEXT login resolves clean via the ordinary
///    active-link path. `find_unique_active_by_external_id` is issuer-
///    blind by externalId (ADR-2001 §5's documented single-issuer
///    precondition — same one link-formation already relies on), so this
///    reprovision check is safe only under that same single-issuer
///    assumption.
///
/// The INACTIVE (deactivated, not orphaned) branch deliberately does NOT
/// run this reprovision check: reactivation is `active:true` on the SAME
/// `scim_id`, which `linked_resource_active` already resolves back to
/// PROCEED on the very next read (no latched denial — see the
/// `test_oidc_scim_link.cpp` "reactivated identity" case), and the partial-
/// unique index on `scim_resources.external_id` prevents a SECOND active
/// resource sharing the externalId while the inactive row still holds it —
/// so only the orphaned (hard-deleted) case can have a reprovision-under-
/// new-id sibling to find.
///
/// Pure decision function: no audit, no metrics, no redirect — the caller
/// owns every side effect of a DENY (the byte-identical `sso_failed`
/// redirect, the `auth.oidc.deprovisioned_denied` audit row carrying
/// `scim_id` when known, the `yuzu_auth_oidc_deprovisioned_denied_total`
/// bump, and — on the post-mint call only — invalidating the session just
/// minted).
[[nodiscard]] OidcLoginDenyDecision
oidc_login_denied_deprovisioned(ScimStore* scim_store, const std::string& iss,
                                const std::string& sub, const std::string& link_claim_value);

} // namespace yuzu::server::oidc
