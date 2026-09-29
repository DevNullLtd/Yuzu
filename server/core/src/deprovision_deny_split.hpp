#pragma once

#include <string>
#include <string_view>

#include <yuzu/metrics.hpp>

/// @file deprovision_deny_split.hpp
///
/// ADR-2001 #3069 — the ONE home for the genuine-vs-store-unavailable
/// deny-counter split shared by all four OIDC/SAML deny-at-login sites in
/// `auth_routes.cpp` (primary check + post-mint recheck, times two
/// protocols). Extracted so the real logic and its unit tests
/// (`test_oidc_scim_link.cpp` / `test_saml_scim_link.cpp`) drive the SAME
/// code — a hand-copied test mirror of the increment logic cannot catch a
/// predicate flip at a real call site (Gate 7 quality-engineer finding).
///
/// Every call site already keys this split on the SAME predicate its audit
/// `reason=` string switches on: `decision.scim_id` absent means the
/// `ScimStore` could not be asked (fail-closed, availability signal, never a
/// genuine deprovision-deny); present means a real deactivated/orphaned SCIM
/// resource was resolved (the CC6.8-alertable signal). This helper takes
/// that predicate as a plain bool so it stays decoupled from the OIDC- and
/// SAML-specific decision types (`OidcLoginDenyDecision` /
/// `SamlLoginDenyDecision`) — both already collapse to the same
/// `scim_id.has_value()` fact before calling in.

namespace yuzu::server {

/// Bumps exactly one of `genuine_counter` / `store_unavailable_counter` on
/// `m`, keyed on `scim_id_present`. Callers keep their own unconditional
/// bump of the site's TOTAL counter (`yuzu_auth_{oidc,saml}_deprovisioned_
/// denied_total`) immediately before calling this — this helper only owns
/// the split, not the total. `m` may be null (metrics registry unwired,
/// matching every call site's existing `if (auto* m = ...)` guard) — a
/// no-op in that case.
inline void record_deprovision_deny_split(yuzu::MetricsRegistry* m,
                                           std::string_view genuine_counter,
                                           std::string_view store_unavailable_counter,
                                           bool scim_id_present) {
    if (m == nullptr) return;
    if (scim_id_present) {
        m->counter(std::string(genuine_counter)).increment();
    } else {
        m->counter(std::string(store_unavailable_counter)).increment();
    }
}

} // namespace yuzu::server
