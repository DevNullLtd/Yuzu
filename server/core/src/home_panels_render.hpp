#pragma once

/// @file home_panels_render.hpp
/// PURE renderers for the three Dashboard panels HM-2 added (on Home at first,
/// moved to the Dashboard in the 2026-10-14 design delta): Compliance by policy
/// ("lowest 5"), Recent events (the audit read), Server health. Value structs
/// in, HTML string out: no store, no clock, no request. Every dynamic string
/// goes through `html_escape`. The route layer (`home_panels_routes`, and the
/// one health registration in `health_routes.cpp`) owns gating and reads.
///
/// Each renderer returns a complete `<section class="panel" id="dash-...">`
/// so the fragment can replace the page's placeholder with `hx-swap=outerHTML`.
/// A failed or refused read is a distinct sentence, never an empty value and
/// never a zero (P17).

#include "compliance_types.hpp" // Policy, ComplianceSummary
#include "home_render.hpp"     // Fact<T>, FactState
#include "audit_store.hpp"      // AuditEvent

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::home_panels {

// HM-1's `Fact<T>` carries every figure. Activity's "administrators only" is a
// Denied fact whose `need` is this sentinel (it is not a `Securable:Op`).
using home::Fact;
using home::FactState;
using home::compliance_level; // "ok" >= 90, "warn" >= 70, else "bad"
inline constexpr const char* kAdminOnlyNeed = "Administrator";

// ── Compliance by policy ─────────────────────────────────────────────────

struct PolicyBar {
    std::string name;
    std::int64_t compliant{0};
    std::int64_t total{0}; ///< 0 = "No results yet" (never 0 percent)
};

struct PolicyPanel {
    std::vector<PolicyBar> lowest; ///< at most `kPolicyRows`, lowest first
    std::size_t enabled_total{0};  ///< enabled policies, for "Lowest 5 of N"
};

inline constexpr std::size_t kPolicyRows = 5;
inline constexpr std::size_t kActivityRows = 8;

/// Join the policy list with the one-read per-policy summaries. Disabled
/// policies are dropped. Policies with results rank by pass percent ascending
/// (ties by name, then id); policies with no results follow, so a fresh policy
/// is never mistaken for the worst one.
[[nodiscard]] PolicyPanel select_lowest_policies(const std::vector<Policy>& policies,
                                                 const std::vector<ComplianceSummary>& summaries);

/// 0..100, clamped before it can reach `style=`. `total <= 0` -> 0 (callers
/// must test `total == 0` first and show "No results yet").
[[nodiscard]] int pass_percent(std::int64_t compliant, std::int64_t total);


[[nodiscard]] std::string render_policies_panel(const Fact<PolicyPanel>& f, std::int64_t as_of_secs);

// ── Recent events ────────────────────────────────────────────────────────
// Rendered as the Dashboard's five-column "Recent events" table (time, who,
// action, target, severity). The Severity column is the audit row's `result`
// (success / failure / denied / other), coloured by that value and nothing
// else: no severity is invented beyond what the row carries.

struct ActivityRow {
    std::int64_t timestamp{0};
    std::string principal;
    std::string action;
    std::string target; ///< "type:id", "" when neither is set
    std::string result; ///< "success" | "failure" | "denied" | other
};

/// Copies ONLY time, principal, action, target and result. `detail`,
/// `source_ip`, `user_agent`, `session_id` and `principal_role` never leave
/// the audit row.
[[nodiscard]] std::vector<ActivityRow> to_activity_rows(const std::vector<AuditEvent>& events);

[[nodiscard]] std::string render_activity_panel(const Fact<std::vector<ActivityRow>>& f,
                                                std::int64_t as_of_secs,
                                                const std::string& audit_href);

// ── Server health ────────────────────────────────────────────────────────

struct HealthPanel {
    bool healthy{false};
    bool pg_reachable{false};
    std::vector<std::string> failing_stores; ///< store keys reporting not-ok
    std::int64_t uptime_seconds{0};
    std::string version;
    std::int64_t agents_online{0};
    /// Present only for a caller whose Execution:Read admitted with no scope.
    std::optional<std::int64_t> executions_running;
};

/// Parse the `/api/health` document. nullopt when it is not JSON or lacks the
/// required fields (`status`, `stores`, `uptime_seconds`, `agents.online`).
/// `executions.in_flight` is read here but dropped by the route unless the
/// caller is unconfined.
[[nodiscard]] std::optional<HealthPanel> parse_health_json(const std::string& body);

[[nodiscard]] std::string render_health_panel(const Fact<HealthPanel>& f, std::int64_t as_of_secs);

// ── Shared ───────────────────────────────────────────────────────────────

/// "HH:MM" of an epoch second, UTC.
[[nodiscard]] std::string hhmm_utc(std::int64_t epoch_secs);

} // namespace yuzu::server::home_panels
