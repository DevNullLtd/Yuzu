#pragma once

/// @file integrations_sync_routes.hpp
/// The six read fragments behind the Integrations page's webhook, offload
/// target and directory-sync panels, plus the page-controller script route.
/// Reads only: every write the page makes goes to the existing JSON routes
/// (`/api/webhooks`, `/api/v1/offload-targets`, `/api/directory/*`), which keep
/// their own `Infrastructure:Write` / `Directory:Write` gates. No new write
/// route and no dispatch path.
///
/// Data arrives through injected closures (`SyncDeps`) so route tests need no
/// Postgres; `bind_stores` builds the production closures over the real stores.
/// A closure's `ReadError` is the only way a read can fail: it is rendered as a
/// failure box, never as an empty list.

#include "http_route_sink.hpp"
#include "integrations_sync_render.hpp"

#include <httplib.h>

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {
class RbacStore;
}

namespace yuzu::server::integrations {

struct SyncDeps {
    /// `require_admin`: writes the 403 and its audit row itself when it denies.
    using AdminFn = std::function<bool(const httplib::Request&, httplib::Response&)>;
    /// Bool-returning audit hook; `false` = the row was not persisted. The
    /// users fragment fails closed on `false`.
    using AuditReadFn =
        std::function<bool(const httplib::Request&, const std::string& action,
                           const std::string& result, const std::string& target_type,
                           const std::string& target_id, const std::string& detail)>;

    AdminFn admin_fn;
    AuditReadFn audit_read;

    // Webhooks. `limit` is the row cap the route asked for (shown cap + 1).
    std::function<std::expected<std::vector<Webhook>, ReadError>(int limit)> webhooks_list;
    std::function<std::optional<Webhook>(std::int64_t id)> webhook_get;
    /// `nullopt` = the read failed.
    std::function<std::optional<std::vector<WebhookDelivery>>(std::int64_t id, int limit)>
        webhook_deliveries;

    // Offload targets.
    std::function<std::expected<std::vector<OffloadTarget>, ReadError>(int limit)> offload_list;
    /// `ReadError` = degraded (never "not found"); an empty optional = not found.
    std::function<std::expected<std::optional<OffloadTarget>, ReadError>(std::int64_t id)>
        offload_get;
    std::function<std::optional<std::vector<OffloadDelivery>>(std::int64_t id, int limit)>
        offload_deliveries;

    // Directory sync.
    std::function<std::expected<SyncStatus, ReadError>()> directory_status;
    std::function<std::expected<std::int64_t, ReadError>()> directory_user_count;
    std::function<std::expected<std::vector<DirectoryGroup>, ReadError>()> directory_groups;
    std::function<std::expected<std::vector<DirectoryUser>, ReadError>()> directory_users;
    std::function<std::expected<std::vector<std::string>, ReadError>()> role_names;
};

/// Production closures over the real stores. Any pointer may be null (every
/// read then answers `ReadError::unavailable`).
[[nodiscard]] SyncDeps bind_stores(WebhookStore* webhooks, OffloadTargetStore* offload,
                               DirectorySync* directory, const RbacStore* rbac);

/// Registers the six fragments and `GET /static/yuzu-integrations-sync.js`.
void register_integrations_sync_routes(HttpRouteSink& sink, SyncDeps deps);

} // namespace yuzu::server::integrations
