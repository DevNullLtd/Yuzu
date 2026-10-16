#pragma once

/// @file device_estate_routes.hpp
/// GET /fragments/hardware/ci/stored-data?id= — the "Stored data" panel of a device record.
/// Read-only: the erase is the existing `DELETE /api/v1/sle/agents/{id}`, called by page JS.
/// htmx drops non-2xx bodies, so a refused or unprobeable gate is a 200 note (probed against
/// a throwaway Response); only an unauthenticated caller gets the real 401.

#include "inventory_routes.hpp" // InventoryDeviceRow
#include "offline_endpoint_store.hpp" // PresenceReadError
#include "quarantine_visible.hpp" // QuarantineScopedPermFn (status-bearing scoped probe)

#include <expected>
#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class HttpRouteSink;

class DeviceEstateRoutes {
public:
    /// One device's identity (hostname) — `hw_identity_fn` in server.cpp.
    using IdentityFn = std::function<std::expected<std::optional<InventoryDeviceRow>, PresenceReadError>(
        const std::string& agent_id)>;

    struct Deps {
        QuarantineScopedPermFn scoped_perm_fn; ///< status-bearing, writes to the Response it is given
        IdentityFn identity_fn;
    };

    void register_routes(HttpRouteSink& sink, Deps deps);

private:
    Deps deps_;
};

} // namespace yuzu::server
