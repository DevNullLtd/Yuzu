#pragma once

/// #4990: who may read Forensics-plugin rows out of the response store.
///
/// `resolve_forensics_visible` is the ONE production resolver behind every operator surface's
/// `ForensicsVisibilityFn`. Its answer is TRI-STATE: a `std::expected<authz::VisibleSet,
/// ForensicsUnknown>`.
///   * Granted  (value, an ADR-0033 `authz::VisibleSet`):
///       `nullopt`      = the caller holds a global `Forensics:Read` (may read every Forensics row)
///       present subset = RBAC enforcement is on and the caller holds a management-group-scoped
///                        `Forensics:Read`: only those agents' Forensics rows
///   * Denied   (value, present EMPTY): a DEFINITIVE answer, there is no grant (also a caller class
///                        that never carries per-agent authority here). Correct behavior, silent.
///   * Unknown  (error, `ForensicsUnknown`): the question could not be answered (a store degrade or
///                        an unwired dependency). Never admits a Forensics row. A surface that
///                        hands a machine caller rows must answer a retryable 503 rather than a 200
///                        with the Forensics rows silently missing; an HTML surface shows a visible
///                        notice, never an empty or "no results" state.
///
/// Deliberately NOT modeled on `response_visible_set_fn`, which returns `nullopt` whenever RBAC is
/// off: right for `Response:Read` (an unconfined read), wrong here, where a global grant is the only
/// thing that may admit, and with RBAC off `Forensics:Read` is floored to administrators
/// (`authz_topology_floor.hpp`). The global proof therefore goes through
/// `AuthRoutes::has_permission` (the quiet twin of `require_permission`, the only gate family that
/// carries the floor) and NEVER through `require_fleet_read` / `probe_fleet_read` /
/// `authorize_list_read`, which admit every authenticated caller when enforcement is off.
///
/// Unwired means present-empty: `tier_filter_for` turns a missing resolver into `deny_all()`, and a
/// missing plugin set into a filter that refuses every row.

#include <cstdint>
#include <expected>
#include <functional>
#include <string_view>

#include <httplib.h>

#include "authz_model.hpp"
#include "mcp_retry.hpp" // mcp::kMcpStoreFaultRetryMs: the one transient-fault retry floor
#include "response_tier_filter.hpp"
#include "rest_a4_envelope_http.hpp"

namespace yuzu::server {

class AuthRoutes;
class ManagementGroupStore;
class RbacStore;
} // namespace yuzu::server

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// Why the resolver could not answer. A CLOSED set: the names below are the `reason` label of
/// `yuzu_server_forensics_tier_withheld_total` (seeded from `kForensicsUnknownReasons`).
enum class ForensicsUnknown : std::uint8_t {
    RbacUnavailable, ///< the authorization read answered 503 (an unavailable authorization store)
    ScopeReadFailed, ///< the management-group scoped-visibility lookup failed
    Unwired,         ///< a dependency the resolver needs was never wired (impossible in production)
};

/// The `reason` label spelling of `u`.
[[nodiscard]] constexpr std::string_view to_string(ForensicsUnknown u) noexcept {
    switch (u) {
    case ForensicsUnknown::RbacUnavailable:
        return "rbac_unavailable";
    case ForensicsUnknown::ScopeReadFailed:
        return "scope_read_failed";
    case ForensicsUnknown::Unwired:
        return "unwired";
    }
    return "unwired"; // out-of-range value: the closed set's catch-all, never an unbounded label
}

inline constexpr ForensicsUnknown kForensicsUnknownReasons[] = {
    ForensicsUnknown::RbacUnavailable, ForensicsUnknown::ScopeReadFailed, ForensicsUnknown::Unwired};

/// The resolver's tri-state answer (see the header comment).
using ForensicsVisibility = std::expected<authz::VisibleSet, ForensicsUnknown>;

/// Per-request resolver wired once in `server.cpp` and passed to each surface.
using ForensicsVisibilityFn = std::function<ForensicsVisibility(const httplib::Request&)>;

/// The stores the production resolver reads. Borrowed; a null auth/RBAC/management-group member
/// makes the answer Unknown (never "unrestricted"). `metrics` is optional: unset (a harness) the
/// resolver counts nothing.
struct ForensicsVisibilityDeps {
    AuthRoutes* auth_routes{nullptr};
    const RbacStore* rbac_store{nullptr};
    const ManagementGroupStore* mgmt_store{nullptr};
    yuzu::MetricsRegistry* metrics{nullptr};
};

/// `yuzu_server_forensics_tier_withheld_total{reason}`: one increment per resolver call that
/// answered Unknown, i.e. a read whose Forensics rows were withheld because the caller's authority
/// could not be determined (the read was refused with a 503 or showed a notice). `reason` is the
/// CLOSED set `kForensicsUnknownReasons` (`to_string`): `rbac_unavailable`, `scope_read_failed`,
/// `unwired`. A definitive refusal (Denied) is correct behavior and is never counted, so the
/// series stays flat on a healthy server whatever the callers' roles. Operational, not
/// `event="security"`.
inline constexpr const char* kForensicsTierWithheldMetric =
    "yuzu_server_forensics_tier_withheld_total";

/// Describe the metric and pre-seed every closed-set reason to 0, so the family exists on a healthy
/// server and `increase()` sees the first event. Called once at server start.
void seed_forensics_tier_metrics(yuzu::MetricsRegistry& metrics);

/// The production resolver. Order is load-bearing:
///   1. `AuthRoutes::probe_permission(req, scratch, "Forensics", "Read")` true => `nullopt`
///      (global). It is `has_permission` with the gate's own response kept in a scratch object, so
///      it decides the same things (JIT elevation, engine principals (RBAC-only), MCP tier, service
///      scope (a service-scoped token never proves Forensics), the RBAC-off legacy floor), writes no
///      denial row for a cookie session, and lets a 503 (an unavailable authorization store) be told
///      apart from a 403. A 503 => Unknown(RbacUnavailable).
///   2. else, only when RBAC enforcement is in effect and the caller is an ordinary session (not a
///      service-scoped token, not an engine principal, not an MCP-tier token):
///      `RbacStore::visible_agents_for_permission` => that subset. A lookup failure =>
///      Unknown(ScopeReadFailed).
///   3. else Denied (present-empty).
/// Step 2 skips caller classes the global probe treats specially because their authority is not
/// "the minting user's grants": using the owner's scoped grants for them would widen them.
/// Known limit: `require_permission`'s RBAC branch answers a degraded `check_permission` with a 403,
/// not a 503, so for a caller other than an engine principal a degrade that hits only step 1 and
/// not step 2 classifies as Denied; the `yuzu_server_rbac_read_degrade_total` series is the signal
/// for that case. (An engine principal alone answers 503 when the RBAC store is not open, which is
/// Unknown(RbacUnavailable); a query-level degrade is a 403, Denied, for every caller class.)
[[nodiscard]] ForensicsVisibility resolve_forensics_visible(const ForensicsVisibilityDeps& deps,
                                                            const httplib::Request& req);

/// The filter a surface passes to every `ResponseStore` read: the resolver's answer applied to the
/// Forensics plugin set. An unwired resolver (empty `fn`) is Denied (`deny_all()`); an unwired
/// plugin set (`nullptr`, impossible in production because boot refuses without one) refuses every
/// row. An Unknown answer is returned as the error so a surface cannot read the store without
/// deciding what to tell the caller: it must not hand a machine caller a partial 200.
[[nodiscard]] inline std::expected<ResponseTierFilter, ForensicsUnknown>
tier_filter_for(const httplib::Request& req, const ForensicsVisibilityFn& fn,
                const ForensicsPluginSet* plugins) {
    if (!plugins)
        return ResponseTierFilter::refuse_unwired();
    if (!fn)
        return ResponseTierFilter::exclude(*plugins, authz::deny_all());
    auto visible = fn(req);
    if (!visible)
        return std::unexpected(visible.error());
    return ResponseTierFilter::exclude(*plugins, std::move(*visible));
}

/// `retry_after_ms` a REST/MCP refusal advertises: the generic transient-fault floor
/// (`mcp::kMcpStoreFaultRetryMs`, also what the sibling store-degrade 503s answer).
inline constexpr std::int64_t kForensicsUnknownRetryMs = mcp::kMcpStoreFaultRetryMs;

/// The machine-surface refusal for an Unknown answer: a retryable A4 503. No `.permission` field
/// (a grant would not fix an outage) and no content of the read. The route must return afterwards.
inline void respond_forensics_tier_unknown(httplib::Response& res) {
    detail::A4ErrorOpts opts; // not a designated initializer: this header is in many TUs
    opts.retry_after_ms = kForensicsUnknownRetryMs;
    opts.remediation = "retry the request";
    res.status = 503;
    res.set_content(detail::a4_error(res,
                                     "authorization for this read could not be resolved; "
                                     "refusing to serve a partial result",
                                     opts),
                    "application/json");
}

} // namespace yuzu::server
