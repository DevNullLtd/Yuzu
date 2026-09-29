#pragma once

/// @file sle_routes.hpp
/// SLE (Software Licensing & Entitlements, ADR-0024) in-server REST surface —
/// `/api/v1/sle/*`. Per ADR-0024 "Placement under ADR-1005", the server owns the
/// **discovery mechanism** only: the raw per-agent detected-licence drill and the
/// agent-decommission erasure trigger. The **compliance/posture** surfaces
/// (`/sle/summary`, `/sle/licenses`, the fan-out list, and the compliance MCP
/// tool) are use-case-engine (SAM UCE module) interpretation and are NOT built
/// in-server; the `query_software_licenses` MCP read is the discovery twin
/// (mcp_server.cpp) of the drill, per ADR-1005 Decision 1.
///
/// Provider closures are injected (store-decoupled) so every handler is
/// unit-testable in-process via TestRouteSink without a live Postgres — the
/// InventoryRoutes / DexRoutes precedent (the #438 TSan trap). server.cpp binds
/// the closures to `SoftwareLicensingStore` and the agent-decommission cascade.
///
/// AUTH (ADR-0024 Decision 9/10/11):
///   * `/sle/agents/{agent_id}` (GET) — the single-agent DRILL: the working
///     ancestor-aware per-device scoped gate (`scoped_perm_fn`, the `device_routes`
///     precedent — tier + management group, 403 outside scope), because it is also
///     Decision 11's privacy-verification surface. It renders `user_scope`/
///     `user_ref` (personal data, ADR-0024 Decision 11), so it joins the per-open
///     behavioural-audit tier (`emit_behavioral_audit`, the `dex.device.view`
///     convention) and FAILS CLOSED (503 + `Sec-Audit-Failed`) when the access-audit
///     row cannot persist.
///   * `/sle/agents/{agent_id}` (DELETE) — the audited durable-erasure trigger
///     (ADR-0024 Decision 9, amended Wave 7 PR7.2; Decision 11): ONE SCOPED
///     securable, `Decommission:Delete` — a device-level erasure grant that
///     authorizes for the cascade's WHOLE blast radius, not the individual
///     securables that govern each store's READ. It erases FIVE per-agent stores:
///     `InventoryStore`, `SoftwareInventoryStore`, `DeviceInventoryStore` (ADR-0016,
///     read-gated by `Inventory`), `AppPerfDailyStore` (DEX behavioural PII,
///     read-gated by `GuaranteedState`), and `SoftwareLicensingStore` (read-gated by
///     `SoftwareLicensing`). A companion package (Wave 7 PR7.2) adds a sixth store,
///     `AppUsageStore` (read-gated by `Forensics`). This was originally a
///     hand-maintained conjunction over the per-store securables (rejected as of
///     Decision 9's reversal — see the ADR): it stopped scaling once a fourth
///     securable (`Forensics`, via `AppUsageStore`) was set to join the cascade, per
///     the repo's own STOP rule. Compat: the seeded matrix is
///     unchanged (Administrator + ITServiceOwner keep the ability with no
///     migration, via `seed_defaults()`); an operator-authored custom role that had
///     assembled the old per-store Delete grants is refused (403 naming
///     `Decommission:Delete`) until granted the new securable — breaking by design.
///     The old per-store Delete grants are NOT revoked and keep gating their own
///     stores' other routes. Scoped, so a group-confined holder cannot erase out of
///     scope. AUDIT-BEFORE-ERASE fail-closed (`sle.agent.decommission|attempt`),
///     then the per-store outcome (`success`/`partial`). Because each store's
///     `delete_agent` now returns committed status (`[[nodiscard]] bool`, false →
///     `Failed`, #1947), `DecommissionResult` is honest — `r.ok()` means every
///     store's DELETE committed, a `Failed` store yields 500 (the cascade is
///     idempotent; re-issue the DELETE).
///
/// FAIL-CLOSED GATE (ADR-0024 Decision 10): server.cpp builds `scoped_perm_fn` on
/// the `rbac_enforcement_in_effect()` primitive, NOT the raw `is_rbac_enabled()`
/// shape whose corrupt-rbac.db fall-through to a legacy-open Read is the #1717
/// fail-open. This class only calls the injected closures; the fail-closed wiring
/// lives at the server.cpp call site.
///
/// DEGRADE ≠ EMPTY (ADR-0024 Decision 4): the drill provider returns `std::nullopt`
/// on a store/pool/query degrade → the route answers 503 (A4 envelope, retryable),
/// NEVER a silent empty 200.

#include "agent_decommission.hpp"       // DecommissionResult (the DELETE route)
#include "software_licensing_store.hpp" // AgentLicenseRow

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

/// `/api/v1/sle/*` in-server discovery routes. Providers are injected closures;
/// see the file header for the per-route auth posture.
class SleRoutes {
public:
    /// Per-device tier + management-group scope gate (ancestor-aware; writes
    /// 401/403/503). Wraps `require_scoped_permission`; wired fail-closed (G-1).
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;

    /// One agent's detected-licence rows (the `/sle/agents/{id}` drill — REAL data
    /// via `SoftwareLicensingStore::agent_licenses`). `std::nullopt` on a degrade
    /// (→ 503). An empty value = the agent genuinely reported no licences.
    using AgentLicensesFn =
        std::function<std::optional<std::vector<AgentLicenseRow>>(const std::string& agent_id)>;

    /// The agent-decommission cascade (the DELETE erasure route). Fans
    /// `delete_agent` across every registered per-agent store and returns the
    /// per-store outcome. Wired in server.cpp to `ServerImpl::decommission_agent`.
    using DecommissionFn = std::function<DecommissionResult(const std::string& agent_id)>;

    /// who/when/what audit sink (bool = persisted; false = a persist failure OR a
    /// throwing sink, routed through the #1647 throw-safe kernel). Reused signature.
    using AuditFn = std::function<bool(const httplib::Request& req, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    void register_routes(httplib::Server& svr, ScopedPermFn scoped_perm_fn,
                         AgentLicensesFn agent_licenses_fn, DecommissionFn decommission_fn,
                         AuditFn audit_fn = {});

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, ScopedPermFn scoped_perm_fn,
                         AgentLicensesFn agent_licenses_fn, DecommissionFn decommission_fn,
                         AuditFn audit_fn = {});

private:
    ScopedPermFn scoped_perm_fn_;
    AgentLicensesFn agent_licenses_fn_;
    DecommissionFn decommission_fn_;
    AuditFn audit_fn_;
};

} // namespace yuzu::server
