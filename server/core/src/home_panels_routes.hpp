#pragma once

/// @file home_panels_routes.hpp
/// HM-2 fragments for the Dashboard: `GET /fragments/dashboard/policies` and
/// `GET /fragments/dashboard/activity` (the Recent events table).
/// (`GET /fragments/dashboard/health` is registered from `health_routes.cpp`,
/// because it must capture the `health_handler` lambda; it uses the same pure
/// renderers.) The file name and the `home_panels` namespace are historical:
/// the panels began on the Home page and moved to the Dashboard in the
/// 2026-10-14 design delta.
///
/// GATING, per fragment, in this order:
///   1. `deny_service_scoped_fn` (audit verb `dashboard.fragment.access_denied`).
///   2. `auth_fn`.
///   3. the figure's own gate, run against a SCRATCH response: a refusal is a
///      200 panel note and the gate's body never reaches the page (htmx drops
///      4xx bodies, so a 403 would hang the panel on "Loading").
/// Policies: `fleet_read_fn("Policy","Read")`; an engaged scope is a Limited
/// note (the per-policy counts are the store's unfiltered aggregate).
/// Activity: effective administrators only (REVIEW A6/A7); the role check runs
/// BEFORE any `perm_fn("AuditLog","Read")` call so a non-holder never writes an
/// `auth.permission_required` denial row into the panel they would read. The
/// panel is NOT confined: a confined operator holding AuditLog:Read sees what
/// `GET /api/audit` returns. `detail`, `source_ip`, `user_agent`, `session_id`
/// and `principal_role` are never rendered.

#include "authz_gates.hpp"
#include "compliance_api.hpp"
#include "home_panels_render.hpp"

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

namespace home_panels {

struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using DenyServiceScopedFn =
        std::function<bool(const httplib::Request&, httplib::Response&, const std::string& action,
                           const std::string& message, const std::string& target_type,
                           const std::string& target_id)>;
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;
    /// Policies joined with the one-read per-policy counts; nullopt = degraded.
    /// NOT confined: only called when the gate returned `scope == nullopt`.
    using PoliciesFn = std::function<std::optional<PolicyPanel>()>;
    /// Newest-first audit rows (limit applied by the callee); nullopt = degraded.
    using AuditFn = std::function<std::optional<std::vector<AuditEvent>>(int limit)>;
    using NowFn = std::function<std::int64_t()>; ///< epoch seconds

    AuthFn auth_fn;
    DenyServiceScopedFn deny_service_scoped_fn;
    FleetReadFn fleet_read_fn;
    PermFn perm_fn;
    PoliciesFn policies_fn;
    AuditFn audit_fn;
    NowFn now_fn;
    /// Nav-resolved "Audit log" target; empty = no audit page, button omitted.
    std::string audit_href;
};

/// The production `Deps::policies_fn` body: the enabled policies (first 100, the
/// store's page size) joined with ONE `compliance_by_policy()` read. nullopt when
/// either read is degraded, so a failed read is never shown as "no results".
/// NOT confined: callers hold the fleet-read gate AND `scope == nullopt`.
[[nodiscard]] std::optional<PolicyPanel> read_policy_panel(const ComplianceApi& api);

/// Registers exactly 2 routes. Throws `std::invalid_argument` if a required
/// closure is unbound (a wiring bug caught at boot).
void register_dashboard_panel_routes(HttpRouteSink& sink, Deps deps);

} // namespace home_panels
} // namespace yuzu::server
