#pragma once

/// @file revocation_source_admin_gate.hpp
/// The administrator gate of the revocation-source surface (ADR-0070 R1): REST and MCP both ask it
/// INSTEAD OF trusting the `RevocationSource` securable alone.
///
/// WHY A SECOND GATE. R1 requires the surface to be admin-only in BOTH RBAC states, so it is not
/// grantable: a custom role holding `RevocationSource:Write` (or `:Read`) must still be refused.
/// The securable is seeded to Administrator only and, under RBAC off, `Write` is already
/// admin-only and `Read` is in the topology floor - but a custom role can be granted the pair
/// under RBAC on, and the registered URLs are egress targets whose fetch-status field would make
/// the fetcher a request-forgery and port-scan oracle for whoever holds the grant. So every route
/// and tool ALSO passes `is_rbac_administrator` (rbac_admin_predicate.hpp): EXTENDED, never
/// forked. This header adds no rule to that predicate; it only composes its outcomes with the
/// shared wording and, for a write, the regime re-check every other DURABLE-authority call site
/// makes.
///
/// WRITES re-verify against the regime durably true right now
/// (`RbacStore::check_caller_authorized_under_current_regime`): the predicate's branch selection
/// reads a replica-local cached enforcement view that can lag a real commit, and a source
/// registered under a stale view is an egress target that persists. READS skip the re-check: a
/// stale-view read discloses nothing the cached view would not, and the read is audited.
///
/// The REST surface passes `RbacAdminSurface::kRest` (an MCP-tier bearer token of ANY tier is
/// structurally denied there - REST has no maker-checker flow); MCP passes `kMcp` (its own ladder
/// - tier, `requires_approval`'s ticket - governs). The parameter has no default, as the
/// predicate's own does.

#include "rbac_admin_predicate.hpp"
#include "revocation_source_service.hpp"

namespace yuzu::server::revocation_source {

[[nodiscard]] inline AdminDecision decide_admin(const auth::Session& session, AuthDB* auth_db,
                                                RbacStore* rbac_store, RbacAdminSurface surface,
                                                bool is_write) {
    using O = AdminDecision::Outcome;
    const auto unavailable = [] {
        return AdminDecision{O::kUnavailable, std::string(kRbacAdminGateUnavailableAuditReason),
                             std::string(kRbacAdminGateUnavailableMessage)};
    };
    if (rbac_store == nullptr || !rbac_store->is_open())
        return unavailable();
    switch (is_rbac_administrator(session, auth_db, rbac_store, surface)) {
    case RbacAdminGate::kAdmin:
        break;
    case RbacAdminGate::kUnavailable:
        return unavailable();
    case RbacAdminGate::kDenied:
        return {O::kDenied, std::string(kRbacAdminGateDeniedAuditReason),
                std::string(kRbacAdminGateDeniedMessage)};
    }
    if (is_write) {
        switch (rbac_store->check_caller_authorized_under_current_regime(session.username)) {
        case RbacRegimeAuthority::kAuthorized:
            break;
        case RbacRegimeAuthority::kUnavailable:
            return {O::kUnavailable, std::string(kRbacRegimeAuthorityUnavailableAuditReason),
                    std::string(kRbacAdminGateUnavailableMessage)};
        case RbacRegimeAuthority::kNotAuthorized:
            return {O::kDenied,
                    "caller does not hold authority under the regime that is durably true right now",
                    std::string(kRbacAdminGateDeniedMessage)};
        }
    }
    return {O::kAdmin, {}, {}};
}

} // namespace yuzu::server::revocation_source
