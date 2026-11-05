#pragma once

/// @file software_collection_settings_routes.hpp
/// REST routes for the per-management-group software collection settings (SAM-34, roadmap 3.7a):
///
///   GET /api/v1/inventory/software/collection-settings
///   GET /api/v1/inventory/software/collection-settings/{group_id}
///   PUT /api/v1/inventory/software/collection-settings/{group_id}
///   GET /api/v1/inventory/software/hosts/{agent_id}/collection-settings
///
/// The fleet list needs the global `ManagementGroup:Read` grant. A group's document is readable
/// with that grant or as an ITServiceOwner of the group or any ancestor; it is written with the
/// global `ManagementGroup:Write` grant or as an ITServiceOwner of the group or an ancestor, and the
/// root group and any priority change need the global grant. The group fallback never admits a
/// service-scoped, MCP-tier or engine session (the MCP tier belt lives inside the permission gate,
/// so a fallback must not re-admit what the gate refused). The host route resolves the effective
/// settings of one device through the pure resolver (collection_settings_resolve.hpp) and is
/// gated by the device-scoped `Inventory:Read`.
///
/// A PUT is audited ahead of the write (`requested`, fail-closed 503 when the row cannot be stored)
/// and again with its outcome. Saving never triggers a collection: this class has no dispatch or
/// sync-runner dependency. Registered from server.cpp ahead of `RestApiV1::register_routes`, because
/// the bare list path would otherwise be taken by the generic `GET /api/v1/inventory/{a}/{b}`.

#include "http_route_sink.hpp"
#include "management_group_store.hpp"
#include "plugin_config_store.hpp"
#include "software_collection_settings_store.hpp"

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class SoftwareCollectionSettingsRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    /// Global permission gate (wraps require_permission); false == the response is written.
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type,
                                      const std::string& operation)>;
    /// RBAC-unavailable-aware probe (AuthRoutes::probe_permission_unavailable_aware): false with
    /// a 503 body when the answer could not be determined, false with a 403 body on a refusal.
    using ProbePermFn = PermFn;
    /// Device-scoped permission gate (require_scoped_permission).
    using ScopedPermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                            const std::string& securable_type,
                                            const std::string& operation,
                                            const std::string& agent_id)>;
    using AuditFn = std::function<bool(const httplib::Request& req, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    struct Deps {
        AuthFn auth_fn;
        PermFn perm_fn;            ///< ManagementGroup:Read for the fleet list
        ProbePermFn probe_perm_fn; ///< global ManagementGroup:Read/Write probe
        ScopedPermFn scoped_perm_fn; ///< Inventory:Read scoped to the agent
        AuditFn audit_fn;
        SoftwareCollectionSettingsStore* store{nullptr};  ///< borrowed; null answers 503
        ManagementGroupStore* mgmt_store{nullptr};        ///< borrowed; null answers 503
        PluginConfigStore* plugin_config_store{nullptr};  ///< borrowed; null answers 503
    };

    void register_routes(HttpRouteSink& sink, Deps deps);
};

} // namespace yuzu::server
