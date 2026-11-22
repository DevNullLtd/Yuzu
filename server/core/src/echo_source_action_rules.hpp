#pragma once

// echo_source_action_rules.hpp -- the pure core shared by the Echo retention-paused source
// re-enable and purge surfaces: the closed metric vocabulary, the one mapping from the scoped
// gate's refusal class to a result and an audit detail, and the repeat bound.
//
// Surfaces: the dashboard fragments (`surface=dashboard`, both actions) and the REST purge
// (`surface=rest`, purge only). Both write the SAME two counter families with the SAME closed
// result set, so one query reads either surface or their sum.
//
// Nothing here reads a store, a clock or a request: the caller passes the clock and the
// gate's own `ScopedGateOutcome`, and a unit test feeds both directly.

#include <yuzu/metrics.hpp>

#include "dispatch_denial.hpp"
#include "scoped_gate_outcome.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace yuzu::server::echo_source {

inline constexpr std::string_view kPurgeTotal = "yuzu_echo_source_purge_total";
inline constexpr std::string_view kReenableTotal = "yuzu_echo_source_reenable_total";
inline constexpr std::string_view kSurfaceDashboard = "dashboard";
inline constexpr std::string_view kSurfaceRest = "rest";

/// The fixed result tokens. The six dispatch-denial tokens (`detail::kAllDispatchDenialReasons`)
/// complete the closed set; they are taken from `detail::to_string`, never re-typed here.
inline constexpr std::array<std::string_view, 9> kFixedResults{
    "success",       "agent_not_connected", "invalid_input",
    "denied",        "scope_violation",     "rate_limited",
    "infra_unavailable", "audit_unavailable", "store_unavailable",
};

/// The labels of one series, in this order: `result` then `surface`.
[[nodiscard]] inline yuzu::Labels labels(std::string_view result, std::string_view surface) {
    return {{"result", std::string(result)}, {"surface", std::string(surface)}};
}

/// Increment one series of @p family. A no-op when metrics are not wired.
inline void count(yuzu::MetricsRegistry* m, std::string_view family, std::string_view surface,
                  std::string_view result) {
    if (m != nullptr)
        m->counter(std::string(family), labels(result, surface)).increment();
}

/// Describe both families and create every series at 0, so the first refusal of any kind reads
/// as an increase from 0 rather than a series appearing: purge on both surfaces, re-enable on
/// the dashboard only. The HELP text is ASCII and an inline literal of each `describe(` call
/// (scripts/ci/check-metrics-help-ascii.sh reads only literals passed directly to it).
inline void describe_and_seed(yuzu::MetricsRegistry& m) {
    m.describe("yuzu_echo_source_reenable_total",
               "Operator-triggered Echo source re-enable attempts from the dashboard, by result "
               "and surface. surface is dashboard. result is one of success, "
               "agent_not_connected, invalid_input, denied, scope_violation, rate_limited, "
               "infra_unavailable, audit_unavailable, store_unavailable, or the chokepoint's "
               "refusal reason when the dispatch itself was refused (unclassified, ambiguous, "
               "anonymous_operator, forbidden, approval_required, kill_switched).",
               "counter");
    m.describe("yuzu_echo_source_purge_total",
               "Operator-triggered Echo retention-paused source purge (destructive) attempts, by "
               "result and surface. surface is dashboard or rest. result is one of success, "
               "agent_not_connected, invalid_input, denied, scope_violation, rate_limited, "
               "infra_unavailable, audit_unavailable, store_unavailable, or the chokepoint's "
               "refusal reason when the dispatch itself was refused (unclassified, ambiguous, "
               "anonymous_operator, forbidden, approval_required, kill_switched). rate_limited "
               "is written by the dashboard only. Counts DISPATCH outcomes; the agent's "
               "rows_deleted / source_not_paused outcome is in the command response record.",
               "counter");
    // `counter(...)` creates the series at 0; it is never incremented here.
    auto seed = [&m](std::string_view family, std::string_view surface) {
        for (const auto r : kFixedResults)
            m.counter(std::string(family), labels(r, surface));
        for (const auto reason : detail::kAllDispatchDenialReasons)
            m.counter(std::string(family), labels(detail::to_string(reason), surface));
    };
    seed(kPurgeTotal, kSurfaceDashboard);
    seed(kPurgeTotal, kSurfaceRest);
    seed(kReenableTotal, kSurfaceDashboard);
}

// -- The ONE mapping from the scoped gate's refusal class ------------------------------------
//
// Every switch below has no `default:`, so -Werror=switch (/we4062 on MSVC) forces a new
// `ScopedGateOutcome` enumerator to be handled. The statement after each switch is the plain
// denial answer, so an out-of-range value is treated as a denial: never as admitted and never
// as a 503.

/// The metric `result` for a refusal. @p after_audit_row is true for the recheck that follows
/// the `attempted` audit row. Never called with `Admitted`; the switch is total only so it is
/// exhaustive.
[[nodiscard]] constexpr std::string_view refusal_result(ScopedGateOutcome outcome,
                                                        bool after_audit_row) {
    switch (outcome) {
        case ScopedGateOutcome::Unavailable: return "infra_unavailable";
        case ScopedGateOutcome::MgmtGroupReadDegraded:
        case ScopedGateOutcome::RbacReadDegraded: return "store_unavailable";
        case ScopedGateOutcome::Unauthenticated: return "denied";
        case ScopedGateOutcome::Denied:
        case ScopedGateOutcome::Admitted: break;
    }
    return after_audit_row ? "denied" : "scope_violation";
}

/// The audit detail's leading token for a refusal. The two degraded classes end with the store
/// that failed, the same label the gate's own `auth.scoped_permission_required` row carries.
[[nodiscard]] constexpr std::string_view refusal_detail(ScopedGateOutcome outcome,
                                                        bool after_audit_row) {
    switch (outcome) {
        case ScopedGateOutcome::Unavailable: return "scoped_gate_unavailable";
        case ScopedGateOutcome::MgmtGroupReadDegraded:
            return "store_unavailable store=mgmt_group_store";
        case ScopedGateOutcome::RbacReadDegraded: return "store_unavailable store=rbac_store";
        case ScopedGateOutcome::Unauthenticated:
            return after_audit_row ? "permission_revoked" : "session_revoked";
        case ScopedGateOutcome::Denied:
        case ScopedGateOutcome::Admitted: break;
    }
    return after_audit_row ? "permission_revoked" : "scope_violation";
}

static_assert(refusal_detail(ScopedGateOutcome::MgmtGroupReadDegraded, false)
                  .ends_with(degraded_store(ScopedGateOutcome::MgmtGroupReadDegraded)),
              "the management-group detail must end with the store label");
static_assert(refusal_detail(ScopedGateOutcome::RbacReadDegraded, true)
                  .ends_with(degraded_store(ScopedGateOutcome::RbacReadDegraded)),
              "the RBAC detail must end with the store label");

/// True when the gate could not evaluate authority at all (it answered 503 itself, or an
/// authorization read failed). Such a refusal is answered 503, never as the 404 a plain denial
/// gets.
[[nodiscard]] constexpr bool could_not_evaluate(ScopedGateOutcome outcome) {
    switch (outcome) {
        case ScopedGateOutcome::Unavailable:
        case ScopedGateOutcome::MgmtGroupReadDegraded:
        case ScopedGateOutcome::RbacReadDegraded: return true;
        case ScopedGateOutcome::Denied:
        case ScopedGateOutcome::Unauthenticated:
        case ScopedGateOutcome::Admitted: break;
    }
    return false;
}

/// The audit `result` of a refusal written BEFORE the `attempted` row: `failure` for a
/// definitive denial (a scope violation), `denied` for every refusal that is not one (a session
/// that ended, an authorization that could not be evaluated).
[[nodiscard]] constexpr std::string_view admission_audit_result(ScopedGateOutcome outcome) {
    switch (outcome) {
        case ScopedGateOutcome::Unavailable:
        case ScopedGateOutcome::MgmtGroupReadDegraded:
        case ScopedGateOutcome::RbacReadDegraded:
        case ScopedGateOutcome::Unauthenticated: return "denied";
        case ScopedGateOutcome::Denied:
        case ScopedGateOutcome::Admitted: break;
    }
    return "failure";
}

/// The repeat bound on a dashboard purge or re-enable: one dispatch per (action, device, source)
/// per `kWindowSec`, held from the gate's admission to the end of the request.
///
/// A request HOLDS its key from `try_acquire` until it ends the hold exactly once, by
/// `release` (nothing was dispatched) or `commit` (a dispatch started the window). While a key is
/// held every other acquire is refused, so an in-progress request and a repeat cannot both reach
/// the dispatch. `Slot` ends the hold in its destructor.
///
/// The clock is a parameter and the class never reads one. The mutex guards map operations only
/// and is never held across an audit write or a dispatch.
///
/// State is per server process and lost on restart: N replicas allow N dispatches per window.
/// The map is bounded: with `kCap` keys held or inside their window, every further purge and
/// re-enable is refused for up to `kWindowSec`. Reaching that takes `kCap` dispatches by
/// authorized callers inside one window, so it is an availability limit, not a bypass (the bound
/// is on a destructive action, so it fails closed).
class EchoActionCooldown {
public:
    static constexpr std::int64_t kWindowSec = 30;
    static constexpr std::size_t kCap = 4096;

    /// `nullopt`: the caller now HOLDS @p key and must end the hold exactly once. Otherwise the
    /// seconds to wait (at least 1; the full window for a held key or a full map).
    [[nodiscard]] std::optional<std::int64_t> try_acquire(const std::string& key,
                                                          std::int64_t now) {
        std::lock_guard<std::mutex> lk(mu_);
        if (const auto it = slots_.find(key); it != slots_.end()) {
            if (it->second == kHeld)
                return kWindowSec;
            if (now < it->second)
                return std::max<std::int64_t>(1, it->second - now);
            it->second = kHeld; // the window ended: this caller holds it now
            return std::nullopt;
        }
        if (slots_.size() >= kCap) {
            std::erase_if(slots_, [now](const auto& kv) {
                return kv.second != kHeld && kv.second <= now;
            });
            if (slots_.size() >= kCap)
                return kWindowSec;
        }
        slots_.emplace(key, kHeld);
        return std::nullopt;
    }

    /// End a hold: nothing was dispatched, the key is free.
    void release(const std::string& key) {
        std::lock_guard<std::mutex> lk(mu_);
        slots_.erase(key);
    }

    /// End a hold: a dispatch started at @p dispatched_at, so the window ends `kWindowSec` later.
    void commit(const std::string& key, std::int64_t dispatched_at) {
        std::lock_guard<std::mutex> lk(mu_);
        slots_[key] = dispatched_at + kWindowSec;
    }

    /// Ends the hold taken by a successful `try_acquire`, by `commit` when a dispatch time was
    /// recorded and by `release` otherwise. Construct it on the line after the acquire.
    class Slot {
    public:
        Slot(EchoActionCooldown& cooldown, std::string key)
            : cooldown_(cooldown), key_(std::move(key)) {}
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;
        Slot(Slot&&) = delete;
        Slot& operator=(Slot&&) = delete;
        ~Slot() {
            if (dispatched_at_)
                cooldown_.commit(key_, *dispatched_at_);
            else
                cooldown_.release(key_);
        }

        /// Record that the dispatch is about to start at @p now.
        void dispatching(std::int64_t now) { dispatched_at_ = now; }
        /// The dispatch reached nobody (or was refused): free the key.
        void nothing_sent() { dispatched_at_.reset(); }

    private:
        EchoActionCooldown& cooldown_;
        std::string key_;
        std::optional<std::int64_t> dispatched_at_;
    };

private:
    /// A request holds the key. Never an epoch second.
    static constexpr std::int64_t kHeld = std::numeric_limits<std::int64_t>::max();

    std::mutex mu_;
    std::unordered_map<std::string, std::int64_t> slots_; ///< kHeld, or the second the window ends
};

} // namespace yuzu::server::echo_source
