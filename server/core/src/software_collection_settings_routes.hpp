#pragma once

/// @file software_collection_settings_routes.hpp
/// REST routes for the per-management-group software collection settings (SAM-34, roadmap 3.7a):
///
///   GET /api/v1/inventory/software/collection-settings
///   GET /api/v1/inventory/software/collection-settings/{group_id}
///   PUT /api/v1/inventory/software/collection-settings/{group_id}
///   GET /api/v1/inventory/software/hosts/{agent_id}/collection-settings
///
/// Settings are managed by fleet administrators, and this build has no group-scoped delegation. A
/// write needs the global `ManagementGroup:Write` grant (the administrator role while RBAC
/// enforcement is off, the default). The list and a group's document take the same
/// `ManagementGroup:Read` gate as the sibling management-group routes: the global grant while RBAC
/// enforcement is on, any signed-in non-service-scoped session while it is off. An RBAC read that
/// cannot be completed is a 503, never a 403 or an admit, on the per-group GET and the PUT only (the
/// unavailable-aware probe); the list (`perm_fn`) and the host route (`scoped_perm_fn`) keep the
/// shared deny-on-degrade gate (ADR-0041) and answer 403. The host route resolves the effective
/// settings of one device through the pure resolver (collection_settings_resolve.hpp) and is gated
/// by the device-scoped `Inventory:Read`.
///
/// A PUT is audited ahead of the write (`requested`, fail-closed 503 when the row cannot be stored),
/// re-checks the write grant immediately ahead of the store call, and is audited again with its
/// outcome. Saving never triggers a collection: this class has no dispatch or
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
        PermFn perm_fn;            ///< ManagementGroup:Read for the fleet list (403 on degrade)
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
