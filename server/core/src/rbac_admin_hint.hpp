#pragma once

/// @file rbac_admin_hint.hpp
/// The answer type of `rbac_admin_hint` (rbac_admin_predicate.hpp), and nothing else.
///
/// It lives in its own header so the Access page's route and render layers
/// (`access_routes.*`, `access_render.*`) can name the three outcomes without including
/// `rbac_admin_predicate.hpp` and, through it, `auth_db.hpp`. Only the predicate header and the
/// auth database header are kept out of them: `access_routes.hpp` and `access_render.hpp`
/// already include `rbac_store.hpp` for the grant and role types they render. The one call site
/// of the function is the wiring lambda in `server.cpp`.
namespace yuzu::server {

/// What the Users and roles page may draw for the RBAC administration controls (Assign role, the
/// enforcement switch). ADVISORY ONLY: it decides how a control is drawn, never whether an
/// action is allowed. Every action keeps its own unchanged gate. The page draws three kinds of
/// control from it: Assign role, the enforcement switch and the per-row Remove controls.
/// kUnconfirmed disables Assign role and the switch with a reason and omits the Remove controls
/// (they are drawn only while the hint is kMay).
enum class RbacAdminHint {
    kMay,         ///< The routes would admit this caller's authority right now.
    kMayNot,      ///< The routes would refuse it (403-class).
    kUnconfirmed, ///< A required store could not answer (503-class). NEVER word this as kMayNot.
};

} // namespace yuzu::server
