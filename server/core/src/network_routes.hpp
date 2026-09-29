#pragma once

/// @file network_routes.hpp
/// Dedicated /network dashboard — the NETWORK-QUALITY lens (per-connection
/// RTT / retransmit / loss / throughput) plus the net/device/app LOCALIZATION
/// evidence. NOT an NPM clone: the leapfrog is correlation against the device
/// perf + process/service data already in the edge warehouse, which a
/// network-only tool structurally cannot do. v1 surfaces EVIDENCE + measured
/// co-occurrence; the causal verdict is a post-v1 overlay (the edge ships
/// facts, never a verdict).
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only
/// (CSP blocks hx-on). Reuses the shared full-page shell
/// (guardian_page_ui.cpp kGuardianDetailPageHtml) + its `.gp-*` component CSS —
/// same chrome as the Guardian/DEX detail pages. Read-only; the data-bearing
/// fragments gate on GuaranteedState:Read (same securable as the Guardian/DEX
/// read surface — a dedicated Network:Read perm is deferred).

#include <yuzu/server/auth.hpp>

#include "network_api.hpp" // ADR-0031 WS-A4: the public in-process /network API seam
#include "network_perf_model.hpp"

#include <httplib.h>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

/// PURE: the /fragments/network/overview content — fleet-now quality cards
/// (an OS-blended rollup over the same per-device facts as the per-OS
/// yuzu_fleet_net_* gauges, via the shared network_perf_rules) + the
/// co-occurrence headline (network/device/app,
/// counted never blamed) + drill links into /fragments/network/devices.
/// `now` is the ALREADY-RESOLVED fleet rollup (NetworkApi::fleet_now) — this
/// function is pure aggregation display, no store-shaped input.
std::string render_network_overview_fragment(const NetPerfFleetNow& now);

/// PURE: the /fragments/network/devices drill — renders the ONE device list
/// serving every /network drill (worst-by-metric / co-occurrence band /
/// not-reporting / cohort). `rows` is already resolved (NetworkApi::device_list);
/// `available_keys`/`cohort_key` back the cohort picker + per-row drill links
/// (NetworkApi::fleet_now's `available_keys`, and the caller's own resolved
/// cohort key — both PURE inputs, no store-shaped type).
std::string render_network_devices_fragment(const std::vector<NetPerfDeviceRow>& rows,
                                            const std::vector<std::string>& available_keys,
                                            const std::string& cohort_key, NetPerfMetric metric,
                                            bool not_reporting, NetCoocFilter cooc,
                                            const std::optional<std::string>& cohort_filter,
                                            int limit);

/// /network routes — /network (page shell) + the read-only HTMX fragments.
class NetworkRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;

    /// Behavioral-PII access audit — same shape as DexRoutes::AuditFn (bool
    /// persist-signal). Added alongside the /fragments/network/devices
    /// service-scoped-token deny (SEC-3 sibling class, Gate 8 review): that
    /// fragment names every reporting agent_id fleet-wide and had NO audit
    /// capability at all until this fix.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// The public in-process /network API (ADR-0031 WS-A4) — the SAME seam
    /// GET /api/v1/network/* and the MCP network tools call, so the dashboard
    /// fragments can never disagree with those siblings. Nullable → the
    /// fragments render an honest "unavailable" placeholder (the pre-seam
    /// slice-2 state, before a provider is wired).
    using NetworkApiPtr = std::shared_ptr<const NetworkApi>;

    /// Register the /network routes. The page shell is auth-only static chrome;
    /// the data-bearing fragments gate on GuaranteedState:Read.
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         NetworkApiPtr api = nullptr);

    /// HttpRouteSink overload — same registration against the polymorphic seam
    /// so the handlers are unit-testable in-process via TestRouteSink (no
    /// httplib acceptor; the #438 TSan trap). The httplib::Server& overload
    /// wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         NetworkApiPtr api = nullptr);

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    AuditFn audit_fn_;
    NetworkApiPtr api_;
};

} // namespace yuzu::server
