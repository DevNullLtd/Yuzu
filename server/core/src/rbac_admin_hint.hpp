#pragma once

/// @file rbac_admin_hint.hpp
/// The answer type of `rbac_admin_hint` (rbac_admin_predicate.hpp), and nothing else.
///
/// It lives in its own header so the Access page's route and render layers
/// (`access_routes.*`, `access_render.*`) can name the three outcomes without including
/// `rbac_admin_predicate.hpp`, which pulls in `rbac_store.hpp` and `auth_db.hpp`. Those two files
/// stay store-free; the one call site of the function is the wiring lambda in `server.cpp`.
namespace yuzu::server {

/// What the Users and roles page may draw for the RBAC administration controls (Assign role, the
/// enforcement switch). ADVISORY ONLY: it decides how a control is drawn, never whether an
/// action is allowed. Every action keeps its own unchanged gate.
enum class RbacAdminHint {
    kMay,         ///< The routes would admit this caller's authority right now.
    kMayNot,      ///< The routes would refuse it (403-class).
    kUnconfirmed, ///< A required store could not answer (503-class). NEVER draw this as kMayNot.
};

} // namespace yuzu::server
