#pragma once

/// @file rbac_enforcement_read.hpp
/// The ONE builder behind the machine twins of `GET /fragments/access/enforcement`:
/// `GET /api/v1/rbac/enforcement` (REST) and the MCP tool `get_rbac_enforcement` (#6033).
///
/// It returns three facts, and the two groups answer DIFFERENT questions:
///   * `enabled` / `unconfirmed` describe the freshness of this replica's cached enforcement
///     view (`is_rbac_enabled()` and `rbac_enabled_view_degraded()`). When `unconfirmed` is true
///     enforcement is to be treated as IN EFFECT whatever `enabled` says: a stale "off" is
///     treated as on, and a stale "on" is on either way (`enabled:false, unconfirmed:true` and
///     `enabled:true, unconfirmed:true` are both possible).
///   * `administrator` is `rbac_admin_hint` on the CALLER's surface. The builder calls it once and
///     neither forces nor suppresses the result when the view is degraded. The predicate behind
///     it does consult the cached enforcement label, but only to choose which durable source
///     answers (Administrator grant rows when enforcement is on or unconfirmed, the local
///     account role when it is off); the answer itself is read from those durable rows and then
///     the regime check. So it is not independent of cache state. While the cached value is a
///     stale OFF (`enabled:false, unconfirmed:true`) an account with no Administrator grant row
///     reads `unconfirmed`, because the predicate cannot tell a missing grant from a stale view.
///     While it is a stale ON (`enabled:true, unconfirmed:true`) the label is `enabled`, so the
///     same account reads `may_not`: a missing grant row is then a confirmed absence. Every
///     combination of the two groups is legitimate. The HTML fragment skips the hint on a
///     degraded view only because it cannot draw a usable switch then; that is a rendering
///     decision, not an authority fact, and this builder deliberately does NOT copy it. An
///     engine, or (on REST) an MCP-tier credential, is `may_not` from structural checks before
///     any store is read. A service-scoped token never reaches this builder: both transports
///     refuse it first.
///
/// `administrator` is ADVISORY. `may` means the RBAC administration routes would admit this
/// credential's durable authority now. It does NOT promise a mutation succeeds: REST MFA
/// step-up, the MCP tier and approval ladder, and the enforcement route's destination-regime 409
/// are all outside it (a readonly-tier MCP administrator reads `may` and is still refused by the
/// tool's own tier check). `may_not` on REST for an MCP-tier token means "this credential cannot
/// administer RBAC through REST", not "its owner is not an administrator".
///
/// SURFACE: `RbacAdminSurface` has NO default by design (routed A2/A1 row, clause 5). The REST
/// route passes `kRest`, the MCP tool passes `kMcp`; this builder forwards it verbatim and never
/// picks one. Do NOT put the verdict on the shared `build_me_body` (REST /api/v1/me, legacy
/// /api/me and MCP get_me share it, and one builder cannot pass one surface for all three).
///
/// This builder is the SECOND production caller of `rbac_admin_hint` (the first is the
/// `rbac_admin_hint_fn` lambda in server.cpp). It consumes the answer and changes no admission
/// input of either function: it calls the hint once, on the caller's own session, and returns a
/// label. It returns nothing about any other principal.
///
/// It reads the cached view ONLY through the two display accessors, in the order the
/// enforcement fragment's wiring pins (the view first, then the staleness flag); it never reads
/// `rbac_enforcement_label()`, which routed A2/A1 clause 4 reserves.

#include <expected>
#include <string>
#include <string_view>

#include "rbac_admin_hint.hpp"
#include "rbac_admin_predicate.hpp"
#include "rbac_store.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

namespace yuzu::server {

struct RbacEnforcementRead {
    bool enabled = false;     ///< `is_rbac_enabled()`: this replica's cached view, for display.
    bool unconfirmed = false; ///< `rbac_enabled_view_degraded()`: that view could not be confirmed.
    RbacAdminHint administrator = RbacAdminHint::kUnconfirmed;
};

/// The wire spelling of the verdict on both transports: `may`, `may_not`, `unconfirmed`.
[[nodiscard]] constexpr std::string_view to_string(RbacAdminHint h) noexcept {
    switch (h) {
    case RbacAdminHint::kMay:
        return "may";
    case RbacAdminHint::kMayNot:
        return "may_not";
    case RbacAdminHint::kUnconfirmed:
        return "unconfirmed";
    }
    return "unconfirmed"; // an enumerator this switch does not know is "could not confirm"
}

/// Reads the enforcement state and the caller's verdict. The error string is for the server log
/// ONLY (it is a fixed server-authored string, never driver text); a transport answers a
/// retryable 503-class refusal and never echoes it. An unwired or closed RBAC store is the only
/// error, and it is returned BEFORE the hint is consulted (so a closed store never yields a
/// verdict of any kind, `may_not` included); a degraded view is NOT an error, it is
/// `unconfirmed:true`.
[[nodiscard]] inline std::expected<RbacEnforcementRead, std::string>
read_rbac_enforcement(const auth::Session& session, AuthDB* auth_db, const RbacStore* rbac_store,
                      RbacAdminSurface surface) {
    if (!rbac_store || !rbac_store->is_open())
        return std::unexpected(std::string("rbac store not open"));
    RbacEnforcementRead r;
    r.enabled = rbac_store->is_rbac_enabled();
    r.unconfirmed = rbac_store->rbac_enabled_view_degraded();
    r.administrator = rbac_admin_hint(session, auth_db, rbac_store, surface);
    return r;
}

} // namespace yuzu::server
