#include "oidc_scim_link.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/scim_store.hpp>

#include <spdlog/spdlog.h>

#include <array>
#include <utility>

namespace yuzu::server::oidc {

namespace {

/// Mirrors `OidcProvider::validate_claims`'s `sub`/`oid` rule
/// (oidc_provider.cpp) exactly: non-empty, <=255 bytes, no byte <0x20 or
/// ==0x7F. Duplicated deliberately rather than shared — `validate_claims`
/// decides whether to REJECT A LOGIN over a malformed claim (fail-closed,
/// only for the configured link claim); this decides whether a claim VALUE
/// is safe to trust into a durable observation row (a login that already
/// succeeded, evaluated for every candidate claim regardless of which one
/// is configured). Same rule, different gate.
bool is_sane_claim_value(const std::string& v) {
    constexpr std::size_t kMaxLen = 255;
    if (v.empty() || v.size() > kMaxLen)
        return false;
    for (unsigned char c : v) {
        if (c < 0x20 || c == 0x7F)
            return false;
    }
    return true;
}

void bump_link_write_failure(yuzu::MetricsRegistry* metrics) {
    if (metrics)
        metrics->counter("yuzu_scim_oidc_link_write_failures_total").increment();
}

} // namespace

void link_oidc_login_to_scim(ScimStore* scim_store, const std::string& iss, const std::string& sub,
                             const std::string& oid, const std::string& link_claim_value,
                             yuzu::MetricsRegistry* metrics) {
    if (!scim_store)
        return;

    if (!link_claim_value.empty()) {
        if (auto match = scim_store->find_unique_active_by_external_id(link_claim_value)) {
            // Exactly one active match — `find_unique_active_by_external_id`
            // already folded zero AND more-than-one matches into nullopt, so
            // reaching here means the link is unambiguous.
            if (!scim_store->upsert_link(iss, sub, match->scim_id)) {
                spdlog::warn("ADR-2001: failed to persist identity link (iss={}, scim_id={}) — "
                            "login proceeds; D2 detector will surface this via the login "
                            "observation",
                            iss, match->scim_id);
                bump_link_write_failure(metrics);
            }
        }
    }

    // D2 tripwire (governance Gate 7 BLOCKING fix, the crux): record an
    // observation for EACH candidate claim that is present and sane — not
    // just `link_claim_value` (the configured one). This is what lets a
    // later deprovision's `observation_matches(external_id)` find the
    // NON-configured candidate under a misconfigured
    // `--oidc-scim-link-claim` (see the .hpp doc comment).
    const std::array<std::pair<const char*, const std::string&>, 2> candidates{{
        {"sub", sub},
        {"oid", oid},
    }};
    for (const auto& [claim_name, claim_value] : candidates) {
        if (!is_sane_claim_value(claim_value))
            continue;
        if (!scim_store->record_login_observation(iss, sub, claim_name, claim_value)) {
            spdlog::warn("ADR-2001: failed to record OIDC login observation (iss={}, claim={})",
                        iss, claim_name);
            bump_link_write_failure(metrics);
        }
    }
}

OidcLoginDenyDecision oidc_login_denied_deprovisioned(ScimStore* scim_store, const std::string& iss,
                                                      const std::string& sub,
                                                      const std::string& link_claim_value) {
    // No store configured at all — SCIM/ADR-2001 linkage cannot have formed,
    // so there is nothing to deny against. This is deliberately DIFFERENT
    // from a non-null-but-unusable store (below), which fails closed.
    if (!scim_store)
        return {.denied = false, .scim_id = std::nullopt};

    auto result = scim_store->linked_resource_active(iss, sub);
    if (!result)
        return {.denied = true, .scim_id = std::nullopt}; // store could not answer: deny, no id to name

    if (!result->scim_id)
        return {.denied = false, .scim_id = std::nullopt}; // no linked identity: proceed

    if (!result->active) {
        // Orphaned: the linked scim_id's scim_resources row is gone
        // (hard-DELETEd). Governance U1 fix — distinguish "genuinely
        // deleted" from "DELETE'd then re-CREATE'd under a new scim_id"
        // before denying, or a returning re-provisioned user is
        // permanently locked out (the re-link that would repoint their
        // stale (iss,sub) row runs AFTER this check, at
        // link_oidc_login_to_scim). Deliberately NOT applied to the
        // explicit-inactive branch below — see the .hpp doc comment for
        // why only the orphaned case can have a reprovision sibling.
        if (scim_store->find_unique_active_by_external_id(link_claim_value)) {
            // An ACTIVE resource now exists for this externalId — the
            // identity was re-provisioned under a new scim_id. Proceed;
            // the imminent link_oidc_login_to_scim call repoints the
            // stale link row to the new id, so the NEXT login resolves
            // clean via the ordinary active-link path.
            return {.denied = false, .scim_id = std::nullopt};
        }
        // No active resource for this externalId — genuinely deprovisioned
        // (not re-provisioned). Deny and name the stale (now-gone) resource.
        return {.denied = true, .scim_id = result->scim_id};
    }

    if (!*result->active) {
        // Explicitly deactivated (active == false, resource still exists) —
        // deny unconditionally. No reprovision check here: reactivation is
        // active:true on the SAME scim_id (the very next read already
        // resolves PROCEED), and the partial-unique index on
        // scim_resources.external_id blocks a second active resource
        // sharing this externalId while the inactive row still holds it.
        return {.denied = true, .scim_id = result->scim_id};
    }

    return {.denied = false, .scim_id = std::nullopt}; // active == true: proceed
}

} // namespace yuzu::server::oidc
