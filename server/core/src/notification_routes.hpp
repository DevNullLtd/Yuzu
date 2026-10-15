#pragma once

#include <yuzu/server/auth.hpp>

#include "notification_store.hpp"

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink; // server/core/src/http_route_sink.hpp

/// Notification REST endpoints extracted from server.cpp (Phase 4 decomposition).
class NotificationRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    /// Returns whether the row was persisted. The two bell mutations write an `attempted` row
    /// FIRST and refuse (503, `Sec-Audit-Failed`) when this reports false (ADR-0033 §9).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// The caller's resolved session, for the same-site decision on the two POSTs. Unwired or
    /// unresolved is treated as a cookie session, so the gate stays closed.
    using ResolveSessionFn = std::function<std::optional<auth::Session>(const httplib::Request&)>;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         NotificationStore* notification_store,
                         ResolveSessionFn resolve_session_fn = {},
                         std::vector<std::string> csrf_trusted_origins = {});

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         NotificationStore* notification_store,
                         ResolveSessionFn resolve_session_fn = {},
                         std::vector<std::string> csrf_trusted_origins = {});
};

} // namespace yuzu::server
