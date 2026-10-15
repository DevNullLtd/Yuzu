#pragma once

/// @file app_usage_routes.hpp
/// Wave 7 PR7.2 — the single in-server REST surface over `AppUsageStore`:
/// `GET /api/v1/forensics/agents/{agent_id}/app-usage`. Renders one agent's
/// per-executable last-used projection (ADR-0016 §5, adjudication P3
/// retained-window semantics — see `app_usage_store.hpp`'s file banner).
///
/// Provider closures are injected (store-decoupled), the `SleRoutes` /
/// `InventoryRoutes` / `DexRoutes` precedent (the #438 TSan trap) — every
/// handler is unit-testable in-process via `TestRouteSink` without a live
/// Postgres. `server.cpp` binds the closures to `AppUsageStore`.
///
/// AUTH: a scoped `Forensics`/`Read` gate on the agent (`scoped_perm_fn`, the
/// `SleRoutes`/`device_routes` precedent — tier + management group, 403
/// outside scope). Per-device app-usage data is Administrator-only by design
/// (`Forensics` is deliberately absent from the seeded Viewer read-list,
/// docs/authz-model.md §4) — see `test_authz_topology_floor.cpp` for the
/// RBAC-off/RBAC-on matrix this gate depends on. Per-device scope is
/// MANDATORY — fail CLOSED (503 `scope gate not configured`) if the gate is
/// unwired, rather than silently widening to a global read.
///
/// AUDIT: renders per-executable usage rows (behavioural data), so it joins
/// the per-open behavioural-audit tier (`emit_behavioral_audit`, the
/// `dex.device.view`/`sle.agent.view` convention) under the
/// `app_usage.agent.view` action, and FAILS CLOSED (503 + `Sec-Audit-Failed`)
/// when the access-audit row cannot persist — set BEFORE the store read
/// (per-open, not per-row).
///
/// DEGRADE != EMPTY: the provider (`agent_usage_snapshot_fn`) returns
/// `std::nullopt` on a store/pool/query degrade -> the route answers 503
/// (A4 envelope, retryable), NEVER a silent empty/zero 200. An empty `apps`
/// vector = the agent genuinely reported no rows for the retained window ->
/// 200 with `data.apps` as an empty array and `data.collected_at` still the
/// real batch collection time (#C2 — sourced from the store's `usage_state`
/// parent row, not derived from a row that may not exist). The rows read and
/// the `collected_at` read happen together in the provider's own single
/// transaction (`AppUsageStore::get_agent_usage_snapshot`) rather than as two
/// separate provider calls, so a concurrent write between them can't produce
/// a response mixing one snapshot's rows with another's `collected_at`.

#include "app_usage_store.hpp" // AgentLastUsedRow, AppUsageSnapshot

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

/// `GET /api/v1/forensics/agents/{agent_id}/app-usage`. Providers are
/// injected closures; see the file header for the auth/audit posture.
class AppUsageRoutes {
public:
    /// Per-device tier + management-group scope gate (ancestor-aware; writes
    /// 401/403/503). Wraps `require_scoped_permission`; wired fail-closed.
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;

    /// One agent's rows + batch `collected_at`, together (REAL data via
    /// `AppUsageStore::get_agent_usage_snapshot`, ONE transaction — see that
    /// method's doc comment for the race a two-call split would reopen).
    /// `std::nullopt` on a degrade (-> 503). An empty `rows` = the agent
    /// genuinely reported no rows for the retained window; `collected_at`
    /// sourced from the `usage_state` parent row (NOT `rows.front().
    /// collected_at`, which loses the value on a legitimate empty-snapshot
    /// replace, #C2) — a value of 0 is legitimate (both "never collected" and
    /// an agent-reported 0 read back as 0; the route does not distinguish
    /// them).
    using AgentUsageSnapshotFn =
        std::function<std::optional<AppUsageSnapshot>(const std::string& agent_id)>;

    /// who/when/what audit sink (bool = persisted; false = a persist failure
    /// OR a throwing sink, routed through the #1647 throw-safe kernel).
    using AuditFn = std::function<bool(const httplib::Request& req, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    void register_routes(httplib::Server& svr, ScopedPermFn scoped_perm_fn,
                         AgentUsageSnapshotFn agent_usage_snapshot_fn, AuditFn audit_fn = {});

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no
    /// httplib acceptor; the #438 TSan trap). The httplib::Server& overload
    /// wraps + delegates.
    void register_routes(HttpRouteSink& sink, ScopedPermFn scoped_perm_fn,
                         AgentUsageSnapshotFn agent_usage_snapshot_fn, AuditFn audit_fn = {});

private:
    ScopedPermFn scoped_perm_fn_;
    AgentUsageSnapshotFn agent_usage_snapshot_fn_;
    AuditFn audit_fn_;
};

} // namespace yuzu::server
