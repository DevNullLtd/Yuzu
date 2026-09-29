#pragma once

/// @file data_inventory_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-11) — the 3-route generic plugin-data Inventory API
/// (Issue 7.17): arbitrary per-agent-per-plugin JSON blobs a plugin last
/// reported (`InventoryStore`, distinct from the daily-sync
/// `SoftwareInventoryStore`/`DeviceInventoryStore` pair — ADR-0016 — and from
/// the `/inventory` dashboard's `InventoryRoutes` class, which reads THOSE
/// two typed stores, not this one). Every handler body is copied verbatim
/// from server.cpp; the changes are the receiver (`web_server_->` ->
/// `sink.`), the gate closure (`require_permission` -> `deps.perm_fn`), and
/// the member access (`inventory_store_.` -> `deps.store->`).
///
/// NAMESPACE: `yuzu::server::data_inventory`, not `yuzu::server::inventory`
/// — deliberately, to avoid colliding with `inventory_routes.hpp`'s
/// `InventoryDeviceRow`/`InventoryRoutes` etc., which live directly in
/// `yuzu::server` (no nested `inventory` namespace of its own) and back the
/// unrelated `/inventory` dashboard page.
///
/// Routes (3) — gate in parens, all backed by `deps.store` (`InventoryStore`,
/// null or `!is_open()` -> 503 on every route, matching the pre-extraction
/// inline code's guard exactly):
///   GET  /api/inventory/tables            (perm_fn Inventory:Read)
///   GET  /api/inventory/:agent_id/:plugin (perm_fn Inventory:Read)
///   POST /api/inventory/query             (perm_fn Inventory:Read)
///
/// UNAUDITED — all 3 (pure reads; matches the pre-extraction inline code,
/// which never called `audit_log` on any of these routes). This module
/// deliberately carries no `AuditFn` in `Deps`.
///
/// GLOBAL, NOT PER-TARGET: all 3 routes gate on the plain global
/// `perm_fn(Inventory, Read)`, never a scoped/per-agent check — matches the
/// pre-extraction inline code exactly. `GET /api/inventory/:agent_id/:plugin`
/// discloses one agent's collected data to ANY global `Inventory:Read`
/// holder with no management-group confinement; `POST /api/inventory/query`
/// likewise has no scope narrowing on its `agent_id`/`plugin` filters. This
/// is a pre-existing posture, not a defect introduced or fixed by this
/// mechanical move — a future confinement pass (mirroring `custom_properties_
/// routes.hpp`'s per-target `scoped_perm_fn`) is a separate, deliberate
/// change.

#include <httplib.h>

#include <functional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class InventoryStore;
} // namespace yuzu::server

namespace yuzu::server::data_inventory {

/// Construction deps for `register_data_inventory_routes`. Every
/// closure/pointer is bound once at start_web_server() time in server.cpp
/// and never reseated.
struct Deps {
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;

    PermFn perm_fn;
    /// `ServerImpl::inventory_store_`. Null or `!is_open()` -> every route
    /// answers 503 without touching it.
    InventoryStore* store{nullptr};
};

/// Register all 3 Inventory API routes against `sink`.
void register_data_inventory_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::data_inventory
