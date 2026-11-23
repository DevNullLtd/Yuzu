#pragma once

// scoped_gate_outcome.hpp -- the typed refusal class of the per-device scoped gate.
//
// The scoped gate (`AuthRoutes::require_scoped_permission_outcome`) answers with its own status,
// body, audit row and metric exactly as it always has; this type does not change any of them. It
// only tells a caller WHY the gate refused, so a caller that must tell "denied" from "an
// authorization read failed" can do so without re-reading a store. A caller admits ONLY on
// `== ScopedGateOutcome::Admitted`.

#include <cstdint>
#include <string_view>

namespace yuzu::server {

enum class ScopedGateOutcome : std::uint8_t {
    /// A definitive refusal: the gate answered 403, or 400 for a service token's empty agent id.
    /// The zero value ON PURPOSE, so a value-initialised outcome refuses.
    Denied = 0,
    /// require_auth refused the request (401).
    Unauthenticated,
    /// The gate could not evaluate authority and answered 503 itself.
    Unavailable,
    /// The RBAC-enforced branch refused with its fail-closed 403 BECAUSE a read failed (ADR-0041);
    /// the management-group store's read failed first.
    MgmtGroupReadDegraded,
    /// The same fail-closed 403, but the RBAC store's own read failed first.
    RbacReadDegraded,
    /// The only admitting value.
    Admitted,
};

static_assert(ScopedGateOutcome{} == ScopedGateOutcome::Denied,
              "a value-initialised outcome must be a refusal");
static_assert(ScopedGateOutcome{} != ScopedGateOutcome::Admitted,
              "the zero value must never admit");

/// The store whose read failed, for the two degraded classes; empty for every other class. No
/// `default:`, so -Werror=switch / /we4062 forces a new enumerator to be handled here; an
/// out-of-range value falls to the trailing statement and has no label.
[[nodiscard]] constexpr std::string_view degraded_store(ScopedGateOutcome outcome) noexcept {
    switch (outcome) {
        case ScopedGateOutcome::MgmtGroupReadDegraded: return "mgmt_group_store";
        case ScopedGateOutcome::RbacReadDegraded: return "rbac_store";
        case ScopedGateOutcome::Denied:
        case ScopedGateOutcome::Unauthenticated:
        case ScopedGateOutcome::Unavailable:
        case ScopedGateOutcome::Admitted: break;
    }
    return "";
}

} // namespace yuzu::server
