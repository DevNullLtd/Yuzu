#pragma once

/// @file home_routes.hpp
/// `GET /home` and `GET /fragments/home/summary`. Presentation over seams: every
/// figure comes through an injected closure (ADR-0031 style), so the routes are
/// unit-testable through `TestRouteSink` with no store, clock or Postgres.
///
/// AUTH, per figure, each against a scratch `httplib::Response` so a refusal never
/// reaches the page (htmx drops 4xx/5xx bodies, so every fragment answers 200 with a
/// panel note instead):
///   devices      `fleet_read_fn("Inventory","Read")`   scope engaged -> roster path, filtered
///   compliance   `fleet_read_fn("Policy","Read")`      scope engaged -> Limited
///   failed exec  `fleet_read_fn("Execution","Read")`   scope engaged -> Limited
///   approvals    `perm_fn("Approval","Read")`
///   enrolment    effective admin only (UX visibility, not authorization)
/// `deny_service_scoped_fn` runs first on every fragment (audit verb
/// `home.fragment.access_denied`). Home never polls and writes no audit row on success.

#include <yuzu/server/auth.hpp>

#include "app_shell.hpp"
#include "authz_gates.hpp"
#include "home_render.hpp"
#include "http_route_sink.hpp"
#include "inventory_routes.hpp"

#include <httplib.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace yuzu::server::home {

/// Newest-first `failed` executions read size (the executions list cap).
inline constexpr std::size_t kFailedReadCap = 100;

/// Row cap of the roster read behind `Deps::roster_fn`. A full read is a lower bound,
/// not the fleet. server.cpp pins this to `OfflineEndpointStore::kQueryRowCap`.
inline constexpr std::size_t kRosterReadCap = 100000;

struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using DenyServiceScopedFn =
        std::function<bool(const httplib::Request&, httplib::Response&, const std::string& action,
                           const std::string& message, const std::string& target_type,
                           const std::string& target_id)>;
    using FleetReadFn = std::function<authz::FleetReadGate(
        const httplib::Request&, httplib::Response&, const std::string& securable_type,
        const std::string& operation)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type,
                                      const std::string& operation)>;
    /// Server clock, epoch seconds.
    using NowFn = std::function<std::int64_t()>;
    /// The UNFILTERED 30-day roster (`build_hw_roster`); the gate's scope is the sole filter.
    using RosterFn = std::function<InventoryDevicesResult()>;
    /// Fleet-wide SQL estate counts (HB-1 seam), partitioned. `nullopt` = degraded.
    /// Optional: when empty the roster path serves every caller. NOT CONFINED: only
    /// ever called for a caller whose gate returned `scope == nullopt`.
    using FleetEstateFn = std::function<std::optional<EstateCounts>(std::int64_t now_ms)>;
    /// `ComplianceApi::fleet_compliance()` reduced to the figure. `nullopt` = degraded.
    using ComplianceFn = std::function<std::optional<ComplianceFigure>()>;
    /// Newest `kFailedReadCap` `failed` executions. `nullopt` = degraded.
    using FailedFn = std::function<std::optional<std::vector<FailedRow>>()>;
    /// Exact pending count plus the oldest submission when the list was not truncated.
    using ApprovalsFn = std::function<std::optional<ApprovalFigure>()>;
    /// Agents awaiting enrolment. `nullopt` = degraded.
    using EnrolmentFn = std::function<std::optional<std::int64_t>()>;

    AuthFn auth_fn;
    DenyServiceScopedFn deny_service_scoped_fn;
    FleetReadFn fleet_read_fn;
    PermFn perm_fn;
    NowFn now_fn;
    RosterFn roster_fn;
    FleetEstateFn fleet_estate_fn;
    ComplianceFn compliance_fn;
    FailedFn failed_fn;
    ApprovalsFn approvals_fn;
    EnrolmentFn enrolment_fn;
};

/// Resolve button targets through the nav by key, with today's page as the
/// fallback, so Home merges before or after the pages that own those links.
[[nodiscard]] Links resolve_links(std::span<const yuzu::server::shell::NavGroup> groups);

/// State tally over a scoped roster slice: the three segments partition the total.
[[nodiscard]] EstateCounts tally_roster(const std::vector<InventoryDeviceRow>& rows);

class HomeRoutes {
public:
    void register_routes(httplib::Server& svr, Deps deps);
    void register_routes(HttpRouteSink& sink, Deps deps);

private:
    [[nodiscard]] SummaryView build_summary(const httplib::Request& req,
                                            const auth::Session& session) const;

    Deps deps_;
};

} // namespace yuzu::server::home
