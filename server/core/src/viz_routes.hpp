#pragma once

/**
 * viz_routes.hpp -- /viz/fleet REST + fragment routes (PR 3 of 11)
 *
 * Surfaces the FleetTopologyStore over two HTTP endpoints:
 *   GET /api/v1/viz/fleet/topology      -- JSON, agentic-first
 *   GET /fragments/viz/fleet/topology   -- HTMX fragment carrying the JSON
 *                                          inside <script type="application/json">
 *                                          for the renderer to consume on swap.
 *
 * Both routes share the same RBAC gate (Response.Read), audit envelope, and
 * metric set. The fragment is identical-data for agentic-first parity (A1):
 * any operator action that the dashboard can do, an MCP / REST agent can do.
 *
 * Kill switch: the constructor takes a `kill_switch` flag (`yuzu_viz_disabled`
 * runtime config + `--no-viz` server flag). When set, both routes return 503
 * with a structured error envelope rather than serving topology data.
 *
 * Page-size cap: `?machines_max=N` defaults to 5000. When the materialised
 * snapshot exceeds the cap, the route returns 413 + audit_log("oversize"),
 * never partially-truncated data (truncation would mislead operators about
 * which subset they're seeing).
 */

#include <yuzu/server/auth.hpp>

#include "offline_endpoint_store.hpp" // OfflineRosterFn

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <functional>
#include <optional>
#include <string>

namespace yuzu {
class MetricsRegistry;
} // namespace yuzu

namespace yuzu::server {

class FleetTopologyStore;
class HttpRouteSink;

class VizRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    using AuditFn = std::function<void(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// Per-route limit on materialised machine count. Requests that would
    /// produce a snapshot larger than this respond 413; the operator must
    /// either lower scope or raise the cap. Default mirrors the plan's
    /// 5000-machine pilot ceiling.
    static constexpr int kDefaultMachinesMax = 5000;
    /// Hard ceiling on the operator-supplied `machines_max` query param.
    /// Without this, an attacker who reaches Response.Read could request
    /// machines_max=2^31 to bypass DoS protection (M-1).
    static constexpr int kMachinesMaxCeiling = 100000;

    /// Retention horizon for stale-flagged offline hosts (#1320 PR 3). A host
    /// whose last heartbeat is within this window but absent from the live
    /// in-memory snapshot renders as a stale cube; beyond it, the row is
    /// withheld so a long-departed host eventually stops cluttering the view.
    static constexpr int kOfflineStaleWindowSecs = 7 * 24 * 3600; // 7 days

    VizRoutes() = default;

    /// Wire route handlers and dependency callbacks. `kill_switch` may be
    /// null; when non-null and observed `true`, both routes return 503.
    /// `metrics` may be null; metric calls become no-ops. `offline_roster_fn` may
    /// be empty (then offline hosts are not stale-flagged — legacy behavior).
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         FleetTopologyStore* store, yuzu::MetricsRegistry* metrics,
                         const std::atomic<bool>* kill_switch,
                         OfflineRosterFn offline_roster_fn = {});

    /// Sink-based overload for in-process unit tests (#438 — TestRouteSink).
    /// Same registration semantics as the httplib::Server overload.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         FleetTopologyStore* store, yuzu::MetricsRegistry* metrics,
                         const std::atomic<bool>* kill_switch,
                         OfflineRosterFn offline_roster_fn = {});

private:
    /// Shared handler body used by both routes. `as_fragment` controls whether
    /// the response body is the raw JSON or a script-wrapped HTMX fragment.
    void handle_topology(const httplib::Request& req, httplib::Response& res, bool as_fragment);

    /// Per-host drill-down handler — slices one MachineNode out of the fleet
    /// snapshot. `as_fragment` controls JSON vs `<script>`-wrapped fragment.
    void handle_host_topology(const httplib::Request& req, httplib::Response& res,
                              bool as_fragment);

    // auth_fn is accepted in the public register_routes signature for parity
    // with sibling routes (see offload_routes.hpp:39) but discarded -- the
    // perm_fn lambda already wraps require_auth. No member here.
    PermFn perm_fn_;
    AuditFn audit_fn_;
    FleetTopologyStore* store_{nullptr};
    yuzu::MetricsRegistry* metrics_{nullptr};
    const std::atomic<bool>* kill_switch_{nullptr};
    /// Durable last-known endpoint roster (#1320 PR 3, typed by #5531). Empty = unwired.
    OfflineRosterFn offline_roster_fn_;
};

} // namespace yuzu::server
