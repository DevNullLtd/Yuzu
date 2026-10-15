#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn's return type
#include "dex_window.hpp" // ADR-0031 WS-A4: dex_iso_since (+ the window/os resolvers) -- pure, re-exported here

/// @file dex_view_types.hpp
/// STORE-FREE symbols hoisted out of `dex_routes.hpp` (ADR-0031 WS-A4 prep) so a
/// family that only needs these narrow seam types (today: `device`) does not have
/// to drag in the whole DEX surface — `dex_routes.hpp` itself transitively pulls
/// store headers (`app_perf_daily_store.hpp`/`app_perf_fleet_store.hpp` via
/// `dex_app_perf_ui.hpp` -> `dex_app_perf_model.hpp`). This header's own include
/// closure MUST stay store-free (std + `dispatch_confined_arms.hpp` only) —
/// verify manually on every change (no automated check covers this header yet;
/// `scripts/ci/check-seam-closure.py` only enforces the `network`/`verify`/
/// `compliance` families today).
///
/// `dex_routes.hpp` includes this header and its own `DexRoutes::DispatchFn` /
/// `::ResponsesFn` / `::AuditFn` nested aliases now just re-point at the
/// free-standing ones below — ONE definition, no ODR duplication.

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include <httplib.h>

namespace yuzu::server {

/// One agent's stored response to a dispatched command — the narrow seam the
/// device perf panel needs from the ResponseStore (a struct, not a store dep,
/// keeps DexRoutes/DeviceRoutes decoupled and the routes testable with a fake).
struct DexAgentResponse {
    std::string agent_id;
    int status{0}; ///< CommandResponse::Status enum value (0=RUNNING, 1=SUCCESS, 2=FAILURE, …)
    std::string output;
    std::string error_detail;
};

/// A4: dispatch a plugin command to specific agents (same 5-param shape as
/// DashboardRoutes' DispatchFn). Used ONLY for the canned `tar.sql` device
/// perf query. May be empty → the perf panel renders "unavailable".
using DexDispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
    const std::string& plugin, const std::string& action,
    const std::vector<std::string>& agent_ids, const std::string& scope_expr,
    const std::unordered_map<std::string, std::string>& parameters)>;

/// A4: read the stored responses for a command_id (narrow ResponseStore
/// seam). May be empty → the perf panel renders "unavailable".
// #1634 seam-scoping: the poll reads are scoped to the originating agent AT THE
// STORE SEAM (the lambda passes ResponseQuery{.agent_id=...} to ResponseStore),
// not only post-filtered in the route. A dropped/refactored post-filter therefore
// cannot become a cross-agent disclosure. Every caller passes the agent_id it
// already validated for scope.
using DexResponsesFn = std::function<std::vector<DexAgentResponse>(
    const std::string& command_id, const std::string& agent_id)>;

/// Audit hook — used to log per-device drill-down opens (behavioral PII).
/// May be empty (audit then degrades to a no-op). **Bool-returning** (was
/// void pre-#1549 review): returns true iff the event was persisted (or the
/// deployment runs audit-off — both look the same to a caller), false on a
/// silent persistence failure. PII-emitting drill-downs capture this and
/// surface the gap to the operator (Sec-Audit-Failed header) so a dropped
/// works-council/SOC 2 evidence row is visible. The dashboard is an HTML/HTMX
/// surface served to a browser, so on a failure it STILL renders the fragment
/// (a transient audit hiccup must not blank the dashboard) but flags the gap —
/// unlike the strict-fail-closed REST per-device endpoints.
using DexAuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                      const std::string& result, const std::string& target_type,
                                      const std::string& target_id, const std::string& detail)>;

// `dex_iso_since` (and the window/os resolvers) are now declared in the pure
// `dex_window.hpp` (included above) and re-exported here transitively, so every
// existing caller is unaffected while the core `DexApi` impl can resolve a
// window without this httplib-coupled header.

/// Friendly display label for an obs_type; unknown types fall back to the
/// HTML-escaped raw obs_type (forward-compatible, render-safe).
std::string dex_signal_label(const std::string& obs_type);

} // namespace yuzu::server
