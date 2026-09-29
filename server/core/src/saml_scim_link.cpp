#include "saml_scim_link.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/scim_store.hpp>

#include <spdlog/spdlog.h>

namespace yuzu::server::saml {

namespace {

// The two NameID Format URIs this codebase treats as STABLE — see the
// header doc. `test_saml_provider.cpp`'s fixture default matches the
// emailAddress one, so the existing (pre-PR4a) test suite's default
// assertions are already linkable without modification.
constexpr const char* kPersistentFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
constexpr const char* kEmail11Format    = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

void bump_link_write_failure(yuzu::MetricsRegistry* metrics) {
    if (metrics)
        metrics->counter("yuzu_scim_saml_link_write_failures_total").increment();
}

// Gate 7 fix (#3072 happy/unhappy-path + architect convergent MEDIUM):
// unlike `name_id`/`entity_id` (bounded+validated by
// `saml::is_valid_saml_component` before this function is ever reached —
// see saml_principal.hpp), `name_id_format` is NOT one of those durable
// join-key components and reaches here straight off the wire. It is only
// ever OBSERVED (never a link key by itself — linkability is decided by
// `is_linkable_name_id_format` below), but an unbounded value from a
// hostile/misconfigured pinned IdP could still bloat the observations
// table's btree index or fail the write outright. Bound it the same way
// `is_valid_saml_component` bounds the other two (<=255 bytes, no byte
// <0x20 or ==0x7F) but — deliberately unlike that function — treat a
// value that fails the check as "format unspecified" (normalize to "")
// rather than reject the login: this field is defense-in-depth observation
// data, not a trust-boundary durable key, and a malformed format must
// never turn into a login-time denial. An already-empty format passes
// through unchanged (record_saml_login_observation now stores it as such,
// see scim_store.hpp).
std::string normalize_name_id_format_for_observation(const std::string& name_id_format) {
    constexpr std::size_t kMaxLen = 255;
    if (name_id_format.empty())
        return name_id_format;
    if (name_id_format.size() > kMaxLen)
        return {};
    for (unsigned char c : name_id_format) {
        if (c < 0x20 || c == 0x7F)
            return {};
    }
    return name_id_format;
}

} // namespace

bool is_linkable_name_id_format(const std::string& name_id_format) {
    return name_id_format == kPersistentFormat || name_id_format == kEmail11Format;
}

SamlScimLinkOutcome link_saml_login_to_scim(ScimStore* scim_store, const std::string& entity_id,
                                            const std::string& name_id,
                                            const std::string& name_id_format,
                                            yuzu::MetricsRegistry* metrics) {
    if (!scim_store)
        return SamlScimLinkOutcome::not_linkable;

    // ADR-2001 #3072 D2 tripwire — record the observation UNCONDITIONALLY,
    // before the linkable-format gate below, so even an unstable-format
    // login is observed (mirrors link_oidc_login_to_scim's per-candidate-
    // claim observation loop). Observe-only: the NameID is never normalized
    // here, and this never influences link formation. `name_id_format`
    // IS bounded/normalized (Gate 7 fix, see the helper above) before it
    // reaches the store — an oversized or control-byte format collapses to
    // "" (unspecified) rather than growing the observations table
    // unbounded; the linkability gate below still consumes the RAW
    // `name_id_format` (a malformed value can never equal either stable
    // format string anyway, so this changes no behaviour there).
    const std::string observed_format = normalize_name_id_format_for_observation(name_id_format);
    if (!scim_store->record_saml_login_observation(entity_id, name_id, observed_format)) {
        spdlog::warn("ADR-2001 #3072: failed to record SAML login observation (entity_id={})",
                    entity_id);
        bump_link_write_failure(metrics);
    }

    if (!is_linkable_name_id_format(name_id_format))
        return SamlScimLinkOutcome::not_linkable; // transient/unspecified/missing — never a durable join key

    auto lookup = scim_store->find_unique_active_by_external_id_checked(name_id);
    switch (lookup.status) {
    case ActiveExternalIdLookupStatus::store_error:
        return SamlScimLinkOutcome::lookup_store_error;
    case ActiveExternalIdLookupStatus::no_match:
        return SamlScimLinkOutcome::no_active_match;
    case ActiveExternalIdLookupStatus::ambiguous:
        return SamlScimLinkOutcome::ambiguous_match;
    case ActiveExternalIdLookupStatus::matched:
        break;
    }

    const auto& match = *lookup.resource;
    if (!scim_store->upsert_saml_link(entity_id, name_id, match.scim_id)) {
        spdlog::warn("ADR-2001 PR4a: failed to persist SAML identity link (entity_id={}, "
                    "scim_id={}) — login proceeds",
                    entity_id, match.scim_id);
        bump_link_write_failure(metrics);
        return SamlScimLinkOutcome::link_write_error;
    }
    return SamlScimLinkOutcome::linked;
}

SamlLoginDenyDecision saml_login_denied_deprovisioned(ScimStore* scim_store,
                                                       const std::string& entity_id,
                                                       const std::string& name_id) {
    // No store configured at all — SCIM/ADR-2001 linkage cannot have formed,
    // so there is nothing to deny against. Deliberately DIFFERENT from a
    // non-null-but-unusable store (below), which fails closed.
    if (!scim_store)
        return {.denied = false, .scim_id = std::nullopt};

    auto result = scim_store->saml_linked_resource_active(entity_id, name_id);
    if (!result)
        return {.denied = true, .scim_id = std::nullopt}; // store could not answer: deny, no id to name

    if (!result->scim_id)
        return {.denied = false, .scim_id = std::nullopt}; // no linked identity: proceed

    if (!result->active) {
        // Orphaned: the linked scim_id's scim_resources row is gone
        // (hard-DELETEd). Distinguish "genuinely deleted" from "DELETE'd
        // then re-CREATE'd under a new scim_id" before denying, or a
        // returning re-provisioned user is permanently locked out (the
        // re-link that would repoint the stale (entity_id,name_id) row
        // runs AFTER this check, at link_saml_login_to_scim). Deliberately
        // NOT applied to the explicit-inactive branch below — same
        // rationale as the OIDC helper (see the .hpp doc comment).
        //
        // SAML has no separate link_claim_value — the join key is always
        // name_id itself (see the .hpp doc comment).
        if (scim_store->find_unique_active_by_external_id(name_id)) {
            // An ACTIVE resource now exists for this externalId — the
            // identity was re-provisioned under a new scim_id. Proceed;
            // the imminent link_saml_login_to_scim call repoints the stale
            // link row to the new id, so the NEXT login resolves clean via
            // the ordinary active-link path.
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

} // namespace yuzu::server::saml
