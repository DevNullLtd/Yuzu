#pragma once

/// @file device_containment_routes.hpp
/// Dashboard fragments for device containment (quarantine) on /hardware:
///   GET /fragments/hardware/quarantine              the Quarantined devices panel
///   GET /fragments/hardware/ci/containment?id=[&banner=1]   the record's Containment lens
///                                                   / the record-header banner
///
/// Read-only twins of `GET /api/v1/quarantine`: the same admit-then-filter rules, via the
/// shared `quarantine_visible_records` (quarantine_visible.hpp).
/// Create and release are NOT here: the page JS calls the existing `POST` and
/// `DELETE /api/v1/quarantine` through the shared dialog module.
///
/// htmx does not swap a non-2xx body, so every gate refusal and every degraded read is
/// answered 200 with an honest note (the gate itself is probed against a throwaway
/// Response); only an unauthenticated caller gets the real 401.

#include "authz_gates.hpp"      // authz::FleetReadGate
#include "inventory_routes.hpp" // InventoryRoutes::AuthFn / HostnamesFn, InventoryDeviceRow
#include "offline_endpoint_store.hpp" // PresenceReadError
#include "quarantine_visible.hpp"

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class HttpRouteSink;

class DeviceContainmentRoutes {
public:
    using AuthFn = InventoryRoutes::AuthFn;
    using HostnamesFn = InventoryRoutes::HostnamesFn;
    /// `AuthRoutes::require_fleet_read` bound at the wiring site: the ADR-0017 list chokepoint.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    /// Point read of one device's active record (`QuarantineStore::get_status`).
    using StatusFn = std::function<std::expected<std::optional<QuarantineRecord>, std::string>(
        const std::string& agent_id)>;
    /// One device's identity (hostname, OS, online) — `hw_identity_fn` in server.cpp.
    using IdentityFn = std::function<std::expected<std::optional<InventoryDeviceRow>, PresenceReadError>(
        const std::string& agent_id)>;

    struct Deps {
        AuthFn auth_fn;
        /// Per-device probe for the single-device lens/banner (one device, one decision). The
        /// panel's list read does NOT use it: that goes through the list gate below.
        QuarantineScopedPermFn scoped_perm_fn; ///< status-bearing, writes to the Response it is given
        /// ADR-0017 list chokepoint for the Quarantined panel (`Security:Read`): one decision
        /// per view, its scope pushed into the store query. Unwired = the panel refuses.
        FleetReadFn fleet_read_fn;
        QuarantineListFn list_fn;
        StatusFn status_fn;
        IdentityFn identity_fn;
        HostnamesFn hostnames_fn;
        std::function<std::int64_t()> now_secs_fn; ///< empty = the system clock
    };

    /// The Quarantined devices panel shows at most this many visible records, newest first.
    static constexpr std::size_t kPanelCap = 200;

    void register_routes(HttpRouteSink& sink, Deps deps);

private:
    Deps deps_;
};

} // namespace yuzu::server
