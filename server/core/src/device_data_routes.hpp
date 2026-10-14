#pragma once

/// @file device_data_routes.hpp
/// Server-rendered per-device data fragments for the Hardware record's "Tags and
/// properties" lens: custom properties and property schemas.
///
/// Every fragment here is a read-only HTML twin of routes that already exist:
///   GET /fragments/hardware/ci/properties?id=
///       <- GET /api/agents/{id}/properties and GET /api/property-schemas
///          (dashboard JSON; no REST v1 or MCP twin exists, ledger `planned:#2146`).
/// Writes are NOT fragments: the page JS (`static/yuzu-device-data.js`) calls the
/// existing JSON routes through the shared dialog module.
///
/// STATUS SEMANTICS: htmx does not swap a non-2xx body, so a denied or degraded read
/// is a 200 carrying a note that names the grant or the failure (never an empty
/// list). Every probe runs against a throwaway `Response`, so the gate's own 403
/// body is never written to the real response. Each denied probe still writes one
/// permission-denied audit row (the loud-probe cost the stream discloses): probes run
/// once per fragment open, never in a polled fragment and never per list row.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "device_data_render.hpp"

namespace yuzu::server {

class HttpRouteSink;

namespace device_data {

struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    /// Per-device permission probe (wraps require_scoped_permission against a
    /// throwaway Response). true = the caller holds `securable:op` for the device.
    using ScopedProbeFn = std::function<bool(const httplib::Request&, const std::string& securable,
                                             const std::string& op, const std::string& agent_id)>;
    /// Global permission probe (wraps require_permission against a throwaway Response).
    using GlobalProbeFn = std::function<bool(const httplib::Request&, const std::string& securable,
                                             const std::string& op)>;
    /// nullopt = the store is unwired or degraded (rendered as a banner, never empty).
    using PropertiesFn =
        std::function<std::optional<std::vector<PropertyRow>>(const std::string& agent_id)>;
    using SchemasFn = std::function<std::optional<std::vector<SchemaRow>>()>;

    AuthFn auth_fn;
    ScopedProbeFn scoped_probe_fn;
    GlobalProbeFn global_probe_fn;
    PropertiesFn properties_fn;
    SchemasFn schemas_fn;
};

/// Registers the fragments on `sink`. Fails fast (std::invalid_argument) when a
/// required closure is unwired, so a mis-wired server never serves an ungated read.
void register_device_data_routes(HttpRouteSink& sink, Deps deps);

} // namespace device_data
} // namespace yuzu::server
