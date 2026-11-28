#pragma once

/// @file live_admission.hpp
/// The ONE admission step of the per-device live read against the shared held-open budget
/// (`SseSurface::kLiveRead`), used by all three holders of that surface: the REST route
/// `POST /api/v1/dex/devices/{id}/live`, the MCP tool `get_device_live` and the quarantine
/// release-confirm wait. The surface cap constant is passed in this one place, so the three cannot
/// disagree about how many reads may be held.
///
/// What it decides, in order:
///   1. a server that is draining (or stopping) refuses at once: outcome `shutting_down`, no lease;
///   2. otherwise the lease is taken (per principal `kPerPrincipalLiveRead`, across principals
///      `kLiveReadSurfaceCap`, both under the budget's one mutex), and an over-budget request is
///      refused with the budget's own reject token mapped onto its outcome;
///   3. the drain predicate is asked AGAIN once the lease is held: the shutdown drain counts the
///      `kLiveRead` leases after it sets its flag, so a lease it did not count was taken after
///      this second read, and is given back.
///
/// A null budget is the unmetered seam (tests only; production always wires one): it admits
/// without a lease unless the server is draining.

#include "live_outcome.hpp"
#include "stream_budget.hpp"

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server::live {

/// The outcome label of a budget reject token. Anything that is not the per-principal or the
/// surface token is the global cap (the token a null `reject_reason` stands for).
[[nodiscard]] inline LiveOutcome outcome_for_reject_reason(std::string_view why) noexcept {
    if (why == detail::StreamBudget::kRejectPerPrincipal)
        return LiveOutcome::kOverBudgetPrincipal;
    if (why == detail::StreamBudget::kRejectSurface)
        return LiveOutcome::kOverBudgetSurface;
    return LiveOutcome::kOverBudgetGlobal;
}

struct LiveAdmission {
    /// Held for the life of the read; empty when refused or when the budget is the null seam.
    detail::StreamBudget::Lease lease;
    /// Set when the read is refused: kShuttingDown or one of the three kOverBudget* outcomes.
    std::optional<LiveOutcome> refused;
    /// The budget's reject token for an over-budget refusal (`kReject*`), empty otherwise.
    std::string_view reject_reason;
};

/// Admit one live read for `principal`. `draining` may be empty (never draining).
[[nodiscard]] inline LiveAdmission admit_live_read(detail::StreamBudget* budget,
                                                   const std::function<bool()>& draining,
                                                   const std::string& principal) {
    LiveAdmission out;
    if (draining && draining()) {
        out.refused = LiveOutcome::kShuttingDown;
        return out;
    }
    if (budget == nullptr)
        return out;
    auto acquired = budget->try_acquire(detail::SseSurface::kLiveRead, principal,
                                        detail::kPerPrincipalLiveRead,
                                        detail::StreamBudget::Admission::kEnforceCaps,
                                        detail::kLiveReadSurfaceCap);
    if (!acquired.lease) {
        out.reject_reason = acquired.reject_reason != nullptr
                                ? std::string_view(acquired.reject_reason)
                                : std::string_view(detail::StreamBudget::kRejectGlobal);
        out.refused = outcome_for_reject_reason(out.reject_reason);
        return out;
    }
    if (draining && draining()) {
        out.refused = LiveOutcome::kShuttingDown; // `acquired.lease` releases on the way out
        return out;
    }
    out.lease = std::move(acquired.lease);
    return out;
}

} // namespace yuzu::server::live
