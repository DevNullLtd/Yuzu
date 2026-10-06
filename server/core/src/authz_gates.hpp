#pragma once

#include "authz_model.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

/// @file authz_gates.hpp
/// The two composite authority gates for list/fan-out and single-agent
/// reads, both defined out-of-line as `AuthRoutes` methods (authz_gates.cpp)
/// because they need `AuthRoutes`'s private `rbac_store_`/`mgmt_group_store_`/
/// `tag_store_`/`require_auth`/`audit_log`. Declared here rather than
/// directly in auth_routes.hpp only to keep `ListAuthority`'s definition
/// (and its `AuthRoutes`-only construction) out of that already-large header.
///
/// Names carry the split deliberately: `require_fleet_read` is
/// self-sufficient — it decides the management-group axis itself, a caller
/// does not additionally gate on `require_permission` for the same
/// `(securable_type, operation)` (see its own doc comment for why pairing
/// them is the exact bug this gate exists to not repeat). `confine_agent_target`
/// is confinement-axis ONLY — it does not decide RBAC at all, and a caller
/// must pair it with `require_scoped_permission` to get a full authority
/// decision. `authorize_*` was tried first and dropped (fjarvis/Kimi K2.7,
/// PR #3216 follow-up review) because it reads as a complete authority
/// verdict for both, which is only true of the first.
///
/// PHASE 0 (PR #3216): wired, tested, called by NO route at that point. The
/// default-deny flip (#2298 PR 3, `require_permission`'s service branch)
/// landed separately and never calls these either — `require_fleet_read`
/// REPLACES the `require_permission` call on a route it migrates, it is
/// never paired with it (see its own doc comment's "SELF-SUFFICIENT"
/// paragraph and #3218).
///
/// PHASE 2 (#3290): first live caller landed — `GET /api/v1/inventory/software`
/// + its MCP twin `query_installed_software` migrated onto `require_fleet_read`,
/// which also gained the elevated/engine/mcp_tier caller-class branches it
/// was missing at Phase 0 (see `require_fleet_read`'s own doc comment).
/// `grep -rl "require_fleet_read\|confine_agent_target"` to check the
/// current caller count before trusting this as exhaustive — more routes
/// migrate incrementally per the Phase-2 backlog
/// (`docs/security-reviews/service-scope-phase2-migrations-2026-08.md`).
namespace yuzu::server {
class AuthRoutes;
class RbacStore;
}

namespace yuzu::server::authz {

/// Outcome of the ITServiceOwner authority-ceiling read. TRI-STATE on purpose: the
/// ceiling's callers disagree on what a failed read means, and the helper must not
/// pre-decide it for them.
///   Admit    - the role holds the pair as an `allow` row.
///   Deny     - an explicit `deny` row, OR the pair is absent (which is also how an
///              operator revoke looks: `remove_permission` DELETEs the row and records
///              `revoked_seed_defaults`, so a revoked default is simply absent here).
///   Degraded - the checked read itself failed (store closed, pool timeout, query error).
/// `require_permission` / `require_scoped_permission` map Degraded to the same 403 as
/// Deny (their documented fail-closed contract); `require_fleet_read` maps it
/// to a retryable 503 because it is an infrastructure fault, not a definitive deny.
enum class CeilingVerdict : std::uint8_t { Admit, Deny, Degraded };

/// The ceiling verdict and, for a Degraded verdict, the closed
/// `yuzu_server_rbac_read_degrade_total` reason label, returned as ONE value so the two
/// cannot be separated or read before they are set. `degrade_reason` points only at a
/// string literal ("pool_acquire_timeout" or "query_error") and is `nullptr` for any
/// verdict other than Degraded.
struct CeilingResult {
    CeilingVerdict verdict = CeilingVerdict::Deny;
    const char* degrade_reason = nullptr;
};

/// THE one ITServiceOwner ceiling check (extend, never fork): a service-scoped token can
/// never exceed what the ITServiceOwner role grants, whatever its minter holds. Both this
/// and `RbacStore::role_permission_allowed_checked` use the one row loop: first matching
/// row decides, `allow` admits, `deny` or absent refuses; the failed-read case is reported
/// as Degraded (with its reason label) instead of being folded into a deny. The helper
/// itself never touches metrics.
[[nodiscard]] CeilingResult service_ceiling_check(const RbacStore& store,
                                                  const std::string& securable_type,
                                                  const std::string& operation);

/// Closed `yuzu_server_rbac_read_degrade_total` reason label for a failed role-permission
/// read: a message starting `kRbacErrPoolAcquireTimeout` or `kRbacErrCircuitBreakerOpen`
/// (rbac_store.hpp) => "pool_acquire_timeout", anything else => "query_error". Pure (no
/// metrics, no store); split out of `service_ceiling_check` so the mapping is unit-testable
/// without a store that can be made to time out.
[[nodiscard]] const char* ceiling_degrade_reason(std::string_view read_error) noexcept;

/// Why `require_fleet_read` did not produce a `ListAuthority`. This is
/// structural bookkeeping, not a caller dispatch surface — every failure
/// path has already written `res` itself before returning one of these; a
/// caller must not re-decode a `GateFailure` into a status code of its own.
enum class GateFailure : std::uint8_t {
    Unauthenticated, ///< 401 — `require_auth` failed and already wrote the
                     ///< response.
    Forbidden,       ///< 403 — a real deny: the management-group axis
                     ///< returned a genuine `ListReadDecision::DenyAll` (may
                     ///< still mask an in-query store error —
                     ///< `authorize_list_read`'s own documented weakening,
                     ///< see rbac_store.hpp; unchanged here).
    Degraded,        ///< 503 — infrastructure unavailable, retryable: a
                     ///< null/not-open RBAC store, or the service-scope
                     ///< axis's tag-store lookup failing (null `tag_store_`,
                     ///< or a degraded/failed query), or, for a service-scoped
                     ///< token, the ITServiceOwner ceiling read failing
                     ///< (`service_ceiling_check` returned Degraded; a
                     ///< DEFINITIVE ceiling deny is Forbidden).
};

/// Move-only witness over an already-composed `VisibleSet` — the product of
/// `AuthRoutes::require_fleet_read`. `in_scope`/`filter` are the only
/// operations exposed on the witness itself.
///
/// Ergonomic, not structural: the stores this wraps still accept ordinary
/// unfiltered queries called directly, so `ListAuthority` does not make an
/// unconfined query path unreachable — it makes the confined path the easy,
/// obvious one. Only `AuthRoutes` can construct one (friend), which is what
/// keeps "call the gate" the sole way to obtain a witness.
class ListAuthority {
public:
    ListAuthority(ListAuthority&&) noexcept = default;
    ListAuthority& operator=(ListAuthority&&) noexcept = default;
    ListAuthority(const ListAuthority&) = delete;
    ListAuthority& operator=(const ListAuthority&) = delete;

    /// Whether `agent_id` is admitted — see `authz::in_scope`.
    [[nodiscard]] bool in_scope(const std::string& agent_id) const {
        return authz::in_scope(visible_, agent_id);
    }

    /// Narrow an already-resolved id list to this authority — see
    /// `authz::filter_to_scope`.
    template <class Ids> [[nodiscard]] std::vector<std::string> filter(const Ids& ids) const {
        return authz::filter_to_scope(ids, visible_);
    }

    /// True iff this authority is TOP (unfiltered) — a non-service session
    /// with a global management-group grant. Callers that branch on this to
    /// choose an unfiltered store query still get a real filter for every
    /// other case, including every service-scoped session (never top).
    [[nodiscard]] bool unfiltered() const { return !visible_.has_value(); }

    /// The raw `VisibleSet`, for a caller that must hand the scope to a
    /// store query (e.g. a SQL id-list) rather than filter an
    /// already-resolved list.
    [[nodiscard]] const VisibleSet& visible_for_query() const { return visible_; }

private:
    friend class yuzu::server::AuthRoutes;
    explicit ListAuthority(VisibleSet visible) : visible_(std::move(visible)) {}

    VisibleSet visible_;
};

/// The REST/MCP transport-layer seam for `AuthRoutes::require_fleet_read`
/// (#3290 Phase 2) — the injected-callback twin of `ListReadGate`
/// (auth_routes.hpp), not `ListAuthority` above. `ListAuthority` is
/// move-only with an `AuthRoutes`-friend-only constructor specifically so
/// only "call the gate" can produce one; that is the right shape for a
/// direct in-process caller but the wrong shape for `RestApiV1`/`McpServer`,
/// which receive authorization as an injected `std::function` (same pattern
/// as `RestApiV1::ListReadFn`/`ListReadGate`) — a test fixture needs to be
/// able to FAKE an admit without a real RbacStore, and `RbacStore` is
/// Postgres-only (ADR-0041), so no unit fixture can drive a real
/// `ListAuthority` to an admit without a live PG instance. A plain,
/// copyable, fail-closed-by-default aggregate is the seam; production code
/// builds one from a real `ListAuthority` at the wiring site in server.cpp.
struct FleetReadGate {
    /// false ⇒ the response is already fully rendered (401/403/503) by
    /// `require_fleet_read` itself — same bool-means-"res already written"
    /// contract as `ListReadGate::admitted`.
    bool admitted{false};
    /// The composed `meet(mgmt, service)` scope — nullopt = unfiltered
    /// (TOP); engaged (including empty) = filter to exactly these agents.
    /// Fails closed to `deny_all()` (engaged-empty), not TOP, so a caller
    /// that forgets to overwrite this on the admitted path filters
    /// everything out rather than leaking the whole fleet.
    VisibleSet scope{deny_all()};
};

} // namespace yuzu::server::authz
