#pragma once

/// @file developer_render.hpp
///
/// Pure HTML renderers for the System > Developer and API page (SYS-4). Every
/// function takes the JSON body of one of the shared discovery builders
/// (`build_routes_catalog`, `build_permissions_catalog`, `plugin_docs_catalog`,
/// `build_plugins_catalog`) so the page, the REST routes and the MCP tools read
/// the same data and cannot drift. No I/O, no registry, no store: a unit test
/// feeds fixture JSON.
///
/// Rules every renderer follows: every dynamic string goes through
/// `html_escape`; a degraded catalogue renders a fixed "could not be read"
/// sentence, never an empty table; lists are bounded and say so; the route
/// `description` field (free text, the only place a route's RBAC requirement is
/// stated) is never rendered.

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu::server::developer {

inline constexpr std::size_t kRoutesCap = 300; // also the Permissions row cap
inline constexpr std::size_t kPluginsCap = 200;
inline constexpr std::size_t kFilterMaxLen = 128;

/// The `q` filter text bounded to kFilterMaxLen bytes (a longer value is cut,
/// not rejected). Control characters become spaces.
[[nodiscard]] std::string clean_filter(std::string_view raw);

/// A fixed-sentence state box. `kind` is "fail" (role=alert), "denied" or
/// "empty" (role=note). `text` is escaped.
[[nodiscard]] std::string render_state(std::string_view kind, std::string_view text);

/// API panel body. `operation_count` is the catalogue's `count`; 0 is treated
/// as unavailable (build_routes_catalog answers count 0 with HTTP 200 when the
/// document fails to parse).
[[nodiscard]] std::string render_api_panel(std::size_t operation_count);

/// Routes table from the `/discover/routes` body, filtered by `q` on path or
/// summary (case-insensitive substring).
[[nodiscard]] std::string render_routes_table(const nlohmann::json& routes_doc, std::string_view q);

/// Permissions table from the `/discover/permissions` body: one row per
/// `Securable:Operation` that at least one role allows, with those roles.
/// `roles_omitted` renders the denied note and the taxonomy counts only.
[[nodiscard]] std::string render_permissions_table(const nlohmann::json& permissions_doc,
                                                   std::string_view q);

/// Plugins table from the build-embedded `/discover/plugin-docs` body, plus the
/// control that lazily loads the devices-reported list.
[[nodiscard]] std::string render_plugins_table(const nlohmann::json& docs_doc);

/// Plugins currently reported by connected devices (from the `/discover/plugins`
/// body), each marked documented only when its name is in `docs_doc`.
[[nodiscard]] std::string render_observed_plugins(const nlohmann::json& plugins_doc,
                                                  const nlohmann::json& docs_doc);

} // namespace yuzu::server::developer
