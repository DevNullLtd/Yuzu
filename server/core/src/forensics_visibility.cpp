#include "forensics_visibility.hpp"

#include <string>
#include <unordered_set>

#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include "auth_routes.hpp"
#include "dispatch_destructive_gate.hpp" // kForensicsSecurable
#include "management_group_store.hpp"
#include "rbac_store.hpp"
#include "refusal_log_throttle.hpp"

namespace yuzu::server {

void seed_forensics_tier_metrics(yuzu::MetricsRegistry& metrics) {
    metrics.describe(kForensicsTierWithheldMetric,
                     "Reads whose Forensics-tier visibility could not be resolved, by reason "
                     "(rbac_unavailable = the authorization read answered unavailable; "
                     "scope_read_failed = the management-group scoped-visibility lookup failed; "
                     "unwired = a dependency of the resolver was never wired). The read is refused "
                     "with a retryable 503 or shows a notice; no Forensics row is served. A "
                     "definitive refusal is not counted.",
                     "counter");
    for (const auto reason : kForensicsUnknownReasons)
        metrics.counter(kForensicsTierWithheldMetric, {{"reason", std::string(to_string(reason))}});
}

namespace {

/// Record one Unknown answer: the counter on every call (the evidence is never throttled), and a
/// warning at most once per minute per reason. The line names the reason only: never a principal,
/// a path or a row.
std::unexpected<ForensicsUnknown> note_unknown(const ForensicsVisibilityDeps& deps,
                                               ForensicsUnknown why) {
    const std::string reason{to_string(why)};
    if (deps.metrics)
        deps.metrics->counter(kForensicsTierWithheldMetric, {{"reason", reason}}).increment();
    static RefusalLogThrottle throttle;
    if (throttle.should_warn(reason))
        spdlog::warn("Forensics-tier visibility could not be resolved (reason={}); the read is "
                     "refused or shows a notice and no Forensics row is served "
                     "(at most one log per 60 s per reason; the counter records all)",
                     reason);
    return std::unexpected(why);
}

} // namespace

ForensicsVisibility resolve_forensics_visible(const ForensicsVisibilityDeps& deps,
                                              const httplib::Request& req) {
    if (!deps.auth_routes)
        return note_unknown(deps, ForensicsUnknown::Unwired); // nothing may be proven

    const std::string securable{kForensicsSecurable};
    // 1. Global proof. Quiet (no cookie-session denial row), but it IS the gate's own decision:
    //    elevation, engine principals, MCP tier, service scope, RBAC and the RBAC-off admin-only
    //    floor are all decided inside it. The gate's response is kept in a scratch object only to
    //    tell an unavailable authorization store (503) from a definitive refusal (401/403).
    httplib::Response gate_response;
    if (deps.auth_routes->probe_permission(req, gate_response, securable, "Read"))
        return ForensicsVisibility{std::in_place, std::nullopt}; // Granted, global
    if (gate_response.status == 503)
        return note_unknown(deps, ForensicsUnknown::RbacUnavailable);

    // 2. A management-group-scoped grant, only meaningful while enforcement is in effect (with it
    //    off there are no scoped grants, and Forensics:Read is admin-only through step 1).
    if (!deps.rbac_store)
        return note_unknown(deps, ForensicsUnknown::Unwired);
    if (!rbac_enforcement_in_effect(deps.rbac_store))
        return ForensicsVisibility{std::in_place, authz::deny_all()}; // Denied
    if (!deps.mgmt_store)
        return note_unknown(deps, ForensicsUnknown::Unwired);
    const auto session = deps.auth_routes->resolve_session(req);
    if (!session)
        return ForensicsVisibility{std::in_place, authz::deny_all()}; // Denied
    // These callers' authority is not "the user's own scoped grants": a service-scoped token is
    // default-denied fleet data, an engine principal resolves RBAC-only against global grants, and
    // an MCP-tier token is bounded by its tier before RBAC. Reading the owner's scoped grants for
    // them would widen them, so they get nothing beyond the global proof above.
    if (!session->token_scope_service.empty() || session->is_engine() || !session->mcp_tier.empty())
        return ForensicsVisibility{std::in_place, authz::deny_all()}; // Denied

    auto visible = deps.rbac_store->visible_agents_for_permission(session->username, securable,
                                                                   "Read", deps.mgmt_store);
    if (!visible)
        return note_unknown(deps, ForensicsUnknown::ScopeReadFailed); // never nullopt, never "none"
    return ForensicsVisibility{
        std::in_place, authz::VisibleSet{std::unordered_set<std::string>(visible->begin(), visible->end())}};
}

} // namespace yuzu::server
