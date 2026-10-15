#pragma once

/// @file offload_routes.hpp
/// Phase 8.3 (#255) — REST endpoints for the response-offload control
/// plane. Mirrors the WebhookRoutes shape: a sibling routes class registered
/// directly on httplib::Server, gated on Infrastructure:Read/Write.

#include <yuzu/server/auth.hpp>

#include "audited_write.hpp"
#include "http_route_sink.hpp"
#include "offload_target_store.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class OffloadRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    /// Returns whether the row was persisted: create and delete write an `attempted` row FIRST
    /// and refuse (503, `Sec-Audit-Failed`) when this reports false (ADR-0033 section 9).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// Mounts:
    ///   GET    /api/v1/offload-targets
    ///   POST   /api/v1/offload-targets
    ///   GET    /api/v1/offload-targets/:id
    ///   DELETE /api/v1/offload-targets/:id
    ///   GET    /api/v1/offload-targets/:id/deliveries
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         OffloadTargetStore* offload_store, WriteGate write_gate = {});

    /// Sink-based overload — used by tests to register routes against an
    /// in-process TestRouteSink without httplib::Server's TSan-hostile
    /// acceptor (#438).
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         OffloadTargetStore* offload_store, WriteGate write_gate = {});
};

} // namespace yuzu::server
