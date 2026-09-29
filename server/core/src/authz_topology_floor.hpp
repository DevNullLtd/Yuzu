#pragma once

#include <string_view>

/// @file authz_topology_floor.hpp
/// The ONE place the "topology floor" set is decided (#2376).
///
/// THE DEFECT: `RbacStore::rbac_enabled_` defaults FALSE (a fresh install runs
/// with RBAC off), and with RBAC off `AuthRoutes::require_permission` /
/// `require_scoped_permission` fall through to the legacy branch, which
/// allows every `Read` to any authenticated non-engine session. On a default
/// install that hands a plain `user` fleet-wide read of the authorization
/// TOPOLOGY itself — the access-review export (SOC 2 CC6.2 evidence), the
/// RBAC role graph (`/api/v1/rbac/roles`), and the engine-principal grant
/// graph.
///
/// THE RULE: the reads named below require admin REGARDLESS of the RBAC
/// on/off toggle. This floor is applied ONLY inside the legacy (RBAC-off)
/// fallback of `require_permission`/`require_scoped_permission` — it never
/// overrides a live RBAC grant. That ordering matters: #2324 cut a dedicated
/// `AccessReview` securable specifically so a non-admin `Reviewer` role could
/// be seeded with `AccessReview:Read`; if this floor ran ahead of (or
/// instead of) the live-RBAC branch it would deny that seeded role and
/// destroy the whole reason the securable exists. The floor exists to close
/// the RBAC-OFF gap only.
///
/// The floor is deliberately NOT configurable — a toggle that can re-open a
/// security floor is a footgun, not a feature.
///
/// `Security:Read` was considered and deliberately EXCLUDED: it is too
/// coarse for this purpose — it also gates quarantine visibility, CA
/// issued-certs, `/ca/root-csr`, and KEK status, which are operational reads,
/// not authorization topology. `ApiToken:Read` and `ManagementGroup:Read`
/// were likewise considered and excluded for the same reason.
///
/// #4028 (api-parity programme #2146) extended the floor's ORIGINAL
/// "authorization topology" framing above to a second, related case: the
/// eight Settings read-twins (`GET /api/v1/settings/*` +
/// `GET /api/v2/agent/plugin-policy` — its deprecated `/v1/` predecessor
/// stayed on `require_admin`, #4144) were previously gated by
/// `AuthRoutes::require_admin` — a whole-route role check with no RBAC-off
/// fallback at all. Migrating them onto RBAC securables
/// (`TlsConfig`/`PluginSigning`/`ServerConfig`/`AnalyticsConfig`, all
/// `Read`) without also flooring them here would silently WIDEN every one
/// of them from admin-only to any-authenticated-user on the RBAC-off
/// default install — the exact defect class this file exists to close, even
/// though TLS/plugin-signing config isn't "authorization topology" in the
/// narrow sense the paragraph above describes. Any future route that
/// migrates an admin-only gate onto a new Read securable should apply the
/// same reasoning: the floor exists to preserve an EXISTING admin-only
/// posture across the RBAC-off toggle, not only to protect the RBAC graph
/// itself.
///
/// EXTEND this set, never fork it — a second copy of a floor set is exactly
/// the kind of drift the repo's other chokepoints (`dispatch_confined_arms.hpp`,
/// `principal_quota_gate.hpp`) exist to prevent.
///
/// `legacy_self_service_allow.hpp` is this file's counterpart in the SAME two
/// legacy branches (#2963) — checked in the same order, at the same two call
/// sites — but widening rather than flooring: a narrow, self-targeted
/// exception from the "non-Read needs admin" rule, never overriding this
/// floor (a floored pair can never also be self-service-exempt).
namespace yuzu::server {

/// One (securable, operation) pair in the topology floor.
struct TopologyFloorEntry {
    std::string_view securable;
    std::string_view operation;
};

/// The topology floor set. `EnginePrincipal` is the securable cut in this
/// same change (#2376) to carry the ADR-0031 engine-principal inventory and
/// grant-graph reads away from the over-broad `Security:Read`; it is seeded
/// in `rbac_store.cpp`'s `seed_defaults()`. Matching here is by string, so
/// this list has no compile-time dependency on that seeding.
inline constexpr TopologyFloorEntry kTopologyFloor[] = {
    {"AccessReview", "Read"},
    {"UserManagement", "Read"},
    {"EnginePrincipal", "Read"},
    // #4028 — Settings read-twins, migrated off admin_fn_ onto RBAC; see the
    // file-header note above for why these floor despite not being
    // "authorization topology" in the original narrow sense.
    {"TlsConfig", "Read"},
    {"PluginSigning", "Read"},
    {"ServerConfig", "Read"},
    {"AnalyticsConfig", "Read"},
    // #4031: Enrollment (auto-approve rules + pending-agent visibility) and
    // OidcConfig (OIDC SSO config) REST v1 twins moved these two reads off
    // `admin_fn_` (a role gate, unconditional regardless of the RBAC
    // toggle) onto `perm_fn_`/`require_permission` with a freshly-minted,
    // Administrator-only securable. Without floor entries here, an
    // RBAC-off deployment (the default) would silently WIDEN both reads
    // from admin-only to any authenticated user via the generic "Read is
    // always allowed" legacy fallback below — exactly the risk #4028
    // (the sibling settings-fragment issue sharing this same #520
    // MCP-policy question) flags for the identical admin_fn_-to-perm_fn_
    // migration shape. Not "authorization topology" in the strict sense
    // this file's header describes, but the same floor mechanism applies
    // to any admin_fn_->perm_fn_ migration that must preserve its
    // admin-only posture under RBAC-off — see the file header's "EXTEND
    // this set, never fork it" rule.
    {"Enrollment", "Read"},
    {"OidcConfig", "Read"},
    // Wave 7 PR7.2 (app_usage): docs/authz-model.md §4 documents every
    // Forensics read as Administrator-only, and Forensics is absent from the
    // Viewer read-list. Without this entry, an RBAC-off default install
    // (rbac_enabled_ false) would serve the app-usage REST route and its MCP
    // twin to any authenticated cookie session via the legacy Read-allow at
    // auth_routes.cpp:1145 — the same defect class every other entry in this
    // set closes. The floor lives only in the legacy branch, so a live RBAC
    // grant (e.g. a seeded Administrator) still admits; plugin dispatch is
    // unaffected (it authorizes via has_permission + the AdminOrApproval
    // switch in agent_registry.hpp:243-285, not this branch).
    {"Forensics", "Read"},
};

/// True when `(securable, operation)` is in the topology floor, i.e. the
/// legacy RBAC-off fallback must deny it to a non-admin regardless of the
/// generic "Read is always allowed" legacy rule.
[[nodiscard]] inline bool topology_floor_applies(std::string_view securable,
                                                 std::string_view operation) noexcept {
    for (const auto& entry : kTopologyFloor) {
        if (entry.securable == securable && entry.operation == operation)
            return true;
    }
    return false;
}

} // namespace yuzu::server
