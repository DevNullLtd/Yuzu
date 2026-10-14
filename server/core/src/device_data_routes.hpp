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

/// Dependencies of the two behavioural-data fragments (application usage and detected
/// licences). They twin GET /api/v1/forensics/agents/{id}/app-usage and
/// GET /api/v1/sle/agents/{id}: same per-device gate, same audit verb, same fail-closed
/// order (audit row BEFORE the read; when it cannot persist, no data is returned).
struct UsageDeps {
    enum class Probe { Allowed, Denied, Unavailable };
    using AuthFn = Deps::AuthFn;
    /// Per-device gate probe against a throwaway Response. Unavailable = the
    /// authorization subsystem is degraded (the REST twins answer 503 there).
    using ProbeFn = std::function<Probe(const httplib::Request&, const std::string& securable,
                                        const std::string& op, const std::string& agent_id)>;
    /// Same shape as the REST routes' AuditFn: true = persisted (or audit is off).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// nullopt = store unwired or degraded.
    using UsageFn = std::function<std::optional<AppUsageData>(const std::string& agent_id)>;
    using LicencesFn =
        std::function<std::optional<std::vector<LicenceRow>>(const std::string& agent_id)>;

    AuthFn auth_fn;
    ProbeFn probe_fn;
    AuditFn audit_fn; // null = audit-off deployment (serves, per the AuditFn contract)
    UsageFn usage_fn;
    LicencesFn licences_fn;
};

/// GET /fragments/hardware/ci/app-usage?id= and /fragments/hardware/ci/licences?id=.
/// Fails fast on an unwired gate or reader; the audit sink may be null.
void register_device_usage_routes(HttpRouteSink& sink, UsageDeps deps);

/// Registers the fragments on `sink`. Fails fast (std::invalid_argument) when a
/// required closure is unwired, so a mis-wired server never serves an ungated read.
void register_device_data_routes(HttpRouteSink& sink, Deps deps);

} // namespace device_data
} // namespace yuzu::server
