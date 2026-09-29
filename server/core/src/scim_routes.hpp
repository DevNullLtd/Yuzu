#pragma once

/// @file scim_routes.hpp
/// SCIM v2 provisioning REST surface (slice 3 of 3): `/scim/v2/*`.
///
/// Wires the storage layer (`ScimStore`, slice 1) and JSON codec (`yuzu::
/// server::scim`, slice 2) into an HTTP surface an enterprise IdP (Okta/
/// Entra) drives to auto-provision and auto-deprovision Yuzu operators, and
/// (#2021, slice 2) auto-manage Group membership feeding SCIM-group->Yuzu-
/// role resolution.
///
/// SECURITY-CRITICAL — role application core: `recompute_scim_user_role`
/// (scim_routes.cpp) re-derives a SCIM-provisioned user's role from their
/// CURRENT SCIM group memberships (via `auth::resolve_role_from_groups` and
/// the configured `--scim-admin-group`) every time membership could have
/// changed (Group POST/PUT/PATCH/DELETE, User POST/revive). It is gated on
/// the SAME provenance guard as every other mutation on this surface
/// (`AuthDB::get_provisioning_source(username) == "scim"`) — a Group
/// `members[].value` that resolves to a local/break-glass/non-SCIM account
/// NEVER changes that account's role, even if an IdP is compromised or
/// misconfigured into referencing it.
///
/// AUTH MODEL: every route (including discovery) is gated on a static Bearer
/// token validated against `ScimStore` (sha256 + constant-time compare) —
/// there is no session/cookie/CSRF surface here; the fixed audit principal
/// `"scim-service"` stands in for "there is no human operator on this path".
///
/// SECURITY INVARIANT (provenance guard): SCIM may only ever mutate an auth
/// account IT provisioned. Every deactivate/reactivate/delete re-checks
/// `AuthDB::get_provisioning_source(username) == "scim"` immediately before
/// calling into `AuthManager` — see `scim_routes.cpp`'s `provenance_ok`. A
/// mismatch (including a locally-created admin, which has no `provisioning_
/// source == "scim"` row) is refused with 404 (never 403 — a 403 would
/// confirm the local account's existence to the IdP) and audited at
/// `scim.user.provenance_denied`.
///
/// Follows the CaRoutes pattern: a production overload wraps httplib::Server
/// in an HttplibRouteSink; a test-only overload registers directly against
/// an HttpRouteSink so tests can dispatch in-process (no socket, TSan-safe,
/// #438).

#include <yuzu/server/auth.hpp>
#include <yuzu/server/scim_store.hpp>

#include "http_route_sink.hpp"

#include <httplib.h>

#include <string>

namespace yuzu::server {

class AuditStore;
class EnginePrincipalStore;
class ApiTokenStore;
class AnalyticsEventStore;
struct Config;

/// Testable core of the `--scim-enable` fail-closed boot guard (SOC 2 CC6.2,
/// S-BOOTGUARD-TEST) — extracted from main.cpp so the token/HTTPS
/// preconditions have direct unit coverage instead of only being exercised
/// end-to-end by booting a server. Mirrors `break_glass_account_problem`'s
/// pattern (auth_db.hpp): a thin main-side wrapper logs `err` and returns
/// EXIT_FAILURE. Returns true (leaving `err` untouched) when the
/// configuration is safe to boot with: SCIM disabled, or SCIM enabled with
/// BOTH a non-empty token AND HTTPS. Never touches disk/network — pure
/// config validation.
bool scim_boot_guard_ok(const Config& cfg, std::string& err);

class ScimRoutes {
public:
    /// Production overload — wraps `svr` in an HttplibRouteSink and delegates.
    /// `scim_store`/`auth_mgr`/`audit_store` are non-owning; the caller (server.cpp)
    /// only constructs/registers this class when `--scim-enable` is set, so in
    /// practice all three are always non-null on this path — the null checks in
    /// scim_routes.cpp are defense-in-depth for the test harness and any future
    /// caller that constructs it before its deps are ready. `scim_admin_group`
    /// is `Config::scim_admin_group` (`--scim-admin-group`/
    /// `YUZU_SCIM_ADMIN_GROUP`) — empty means no SCIM group ever promotes to
    /// admin (see `recompute_scim_user_role`).
    ///
    /// `token_store` (ADR-2001 Sec.3, nullable -- same non-null-in-practice
    /// posture as scim_store/auth_mgr/audit_store above: server.cpp
    /// constructs ApiTokenStore unconditionally alongside ScimStore, both
    /// born-on-PG) is where the deprovision seams (deactivate(), the DELETE
    /// handler, and create-with-active:false) revoke API tokens
    /// credentials-FIRST, across the resolved slug + linked-OIDC principal
    /// set, before the account is marked inactive. A null/closed
    /// token_store fails the deprovision closed (503) rather than silently
    /// skipping the revoke.
    ///
    /// `analytics_store` (ADR-2001 D1, nullable, same deferred-wiring
    /// posture) — the D1 "make it LOUD" signal needs a real SEVERITY
    /// channel, and `AuditEvent`/`AuditStore` (what every other call on
    /// this surface writes to) has no severity field at all: its `result`
    /// column is success/denied/failure/partial, never a severity level.
    /// The one severity-carrying mechanism in this codebase is
    /// `AnalyticsEvent::severity` via `AnalyticsEventStore` — the same
    /// channel `AuthRoutes::emit_event` uses for `Severity::kCritical`
    /// break-glass-login events. D1 reuses that mechanism rather than
    /// inventing a parallel one; a null store degrades to "no critical
    /// analytics event" (the AuditStore row + the
    /// `yuzu_scim_deprovision_role_refused_with_active_link_total` metric
    /// still fire either way).
    void register_routes(httplib::Server& svr, ScimStore* scim_store, auth::AuthManager* auth_mgr,
                         AuditStore* audit_store, std::string scim_admin_group = {},
                         EnginePrincipalStore* engine_principal_store = nullptr,
                         ApiTokenStore* token_store = nullptr,
                         AnalyticsEventStore* analytics_store = nullptr);

    /// Testable overload — register against an in-process sink (no socket).
    void register_routes(HttpRouteSink& sink, ScimStore* scim_store, auth::AuthManager* auth_mgr,
                         AuditStore* audit_store, std::string scim_admin_group = {},
                         EnginePrincipalStore* engine_principal_store = nullptr,
                         ApiTokenStore* token_store = nullptr,
                         AnalyticsEventStore* analytics_store = nullptr);
};

} // namespace yuzu::server
