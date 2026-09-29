#pragma once

#include <yuzu/server/auth.hpp>

#include "http_route_sink.hpp"
#include "webhook_store.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

/// Webhook REST endpoints extracted from server.cpp (Phase 4 decomposition).
class WebhookRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    using AuditFn = std::function<void(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using EmitEventFn = std::function<void(const std::string& event_type,
                                           const httplib::Request& req,
                                           const nlohmann::json& attrs,
                                           const nlohmann::json& payload)>;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         EmitEventFn emit_event_fn, WebhookStore* webhook_store);

    /// Sink-based overload — used by tests to register routes against an
    /// in-process TestRouteSink without httplib::Server's TSan-hostile
    /// acceptor (#438). Mirrors OffloadRoutes' dual-overload shape (gov
    /// Gate 3 quality-engineer: this store had no REST-handler-level test
    /// coverage at all before this overload existed).
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         EmitEventFn emit_event_fn, WebhookStore* webhook_store);
};

} // namespace yuzu::server
