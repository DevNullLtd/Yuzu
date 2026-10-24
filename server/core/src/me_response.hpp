#pragma once

/// @file me_response.hpp
/// ONE builder for the caller's self-description, shared by REST `GET /api/v1/me`
/// (wrapped in the ok_json envelope), legacy `GET /api/me` (raw, no envelope) and
/// MCP `get_me` (wrapped by tool_result). `docs/api-twin-recipe.md` Rule 1: the
/// three surfaces call the same function, so the JSON cannot drift apart.
///
/// Pure with respect to I/O except the one RBAC read injected through
/// `RbacView::read_roles`. No httplib, no MCP types, no audit: callers own the
/// transport, the Cache-Control header and (MCP only) the audit row.
///
/// Role lookup rules (the reasons this is not a copy of the old inline code):
///  - The principal namespace is chosen from the SESSION's principal kind, never
///    from the shape of `username`. An engine session (`Session::is_engine()`)
///    reads principal type "engine" keyed by its full `engine:<slug>` username
///    (the key `RbacStore::assign_role` stores engine grants under); every other
///    session reads principal type "user". A human whose username happens to start
///    with `engine:` is still a "user" lookup.
///  - The read is the CHECKED accessor. A store fault is reported as
///    `rbac_roles_resolved:false` with `rbac_role` and `rbac_roles` OMITTED, never
///    collapsed into an empty list and then a fabricated Viewer.
///  - An engine principal never gets a fabricated role: with RBAC off, or with no
///    engine grant, `rbac_role` is omitted. The legacy Administrator/Viewer
///    fallback is for human sessions only.
///  - `rbac_roles` are DIRECT assignments only (principal_roles rows for this
///    principal). Roles granted through group membership are not included.
///  - `rbac_role` is the alphabetically first direct role (the store orders by
///    role_name). It is a deprecated display field kept for dashboard
///    compatibility; `effective_role` / `role` are the authority summary.

#include <yuzu/server/auth.hpp>

#include "admin_gate.hpp"
#include "rbac_store.hpp"
#include "web_utils.hpp" // format_iso_utc

#include <nlohmann/json.hpp>

#include <chrono>
#include <expected>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::me_response {

/// Direct role names for (principal_type, principal_id), or the store's error text.
using RolesReadFn = std::function<std::expected<std::vector<std::string>, std::string>(
    std::string_view principal_type, std::string_view principal_id)>;

/// The RBAC facts the builder needs, decoupled from the concrete store so the
/// namespace choice and the degrade arms are testable without Postgres.
struct RbacView {
    /// `rbac_store && rbac_store->is_rbac_enabled()`.
    bool enabled{false};
    /// Only consulted when `enabled`. Unset while enabled is treated as an
    /// unresolved read (fail safe), never as "no roles".
    RolesReadFn read_roles;
};

/// Principal type the session's grants are stored under. Keyed on the session's
/// principal kind, NEVER on a username prefix.
[[nodiscard]] inline std::string_view rbac_principal_type(const auth::Session& s) noexcept {
    return s.is_engine() ? "engine" : "user";
}

/// Adapt the concrete store. A null store is RBAC off, as the old inline code did.
[[nodiscard]] inline RbacView rbac_view(RbacStore* store) {
    RbacView v;
    if (store == nullptr || !store->is_rbac_enabled())
        return v;
    v.enabled = true;
    v.read_roles = [store](std::string_view type, std::string_view id)
        -> std::expected<std::vector<std::string>, std::string> {
        auto rows = store->get_principal_roles_checked(std::string(type), std::string(id));
        if (!rows)
            return std::unexpected(rows.error());
        std::vector<std::string> names;
        names.reserve(rows->size());
        for (const auto& r : *rows)
            names.push_back(r.role_name);
        return names;
    };
    return v;
}

/// The self-description object. Key order is stable (insertion order).
[[nodiscard]] inline nlohmann::ordered_json build_me_json(const auth::Session& s,
                                                           const RbacView& rbac) {
    using J = nlohmann::ordered_json;
    J j = J::object();

    // #1837: `username` is the STABLE authorization principal (an opaque
    // `oidc:<iss>#<sub>` id for SSO sessions); `display_name` is the readable label
    // ("" for a legacy session created before the field existed, so fall back).
    j["username"] = s.username;
    j["display_name"] = s.display_name.empty() ? s.username : s.display_name;
    j["role"] = auth::role_to_string(s.role);
    j["principal_kind"] = s.principal_kind;
    j["auth_source"] = s.auth_source;
    j["mcp_tier"] = s.mcp_tier;
    j["scope_service"] = s.token_scope_service;
    j["rbac_enabled"] = rbac.enabled;

    const bool engine = s.is_engine();
    // Human-only fallback: the legacy role mapped to its RBAC role name.
    const char* const legacy_role = s.role == auth::Role::admin ? "Administrator" : "Viewer";

    if (!rbac.enabled) {
        if (!engine)
            j["rbac_role"] = legacy_role;
        j["rbac_roles"] = J::array();
        j["rbac_roles_resolved"] = true;
    } else {
        std::expected<std::vector<std::string>, std::string> roles =
            std::unexpected(std::string("roles reader not wired"));
        if (rbac.read_roles)
            roles = rbac.read_roles(rbac_principal_type(s), s.username);
        if (!roles) {
            // Store degraded: say so, invent nothing.
            j["rbac_roles_resolved"] = false;
        } else {
            if (!roles->empty())
                j["rbac_role"] = roles->front();
            else if (!engine)
                j["rbac_role"] = legacy_role;
            J arr = J::array();
            for (const auto& r : *roles)
                arr.push_back(r);
            j["rbac_roles"] = std::move(arr);
            j["rbac_roles_resolved"] = true;
        }
    }

    // Session self-description (#5779, #4208). `role` stays the persisted role;
    // these report what the server will actually honour. No store read, no gate
    // call, no audit row.
    const bool elevated = auth::is_elevated(s);
    j["effective_role"] = auth::role_to_string(auth::effective_role(s));
    j["elevated"] = elevated;
    if (elevated) {
        j["elevated_until"] = format_iso_utc(
            std::chrono::duration_cast<std::chrono::seconds>(s.elevated_until.time_since_epoch())
                .count());
    }
    j["can_access_settings"] = authz::admin_gate_verdict(s) == authz::AdminGate::Admit;
    return j;
}

/// The same object as a serialized JSON string, for the REST/legacy transports.
[[nodiscard]] inline std::string build_me_body(const auth::Session& s, const RbacView& rbac) {
    return build_me_json(s, rbac).dump();
}

[[nodiscard]] inline std::string build_me_body(const auth::Session& s, RbacStore* store) {
    return build_me_body(s, rbac_view(store));
}

} // namespace yuzu::server::me_response
