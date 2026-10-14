#pragma once

/// @file access_audit_routes.hpp
/// Audit and reviews page (Phase 2 UI): the audit half.
///
/// Routes (all GET):
///   /access/audit                         page; 302 /login without a session
///   /fragments/access/audit/log           audit-log panel; loud AuditLog:Read
///   /fragments/access/audit/sample        authentication sample; loud AuditLog:Read; user-initiated
///   /fragments/access/audit/retention     retention panel; loud ServerConfig:Read
///   /static/yuzu-audit.js                 the page's client glue
///
/// Twins (ADR-1005). The log fragment reads the same store with the same gate and the same
/// filters as `GET /api/v1/audit` + MCP `query_audit_log`, and renders only the twin's field
/// set; the sample fragment is `GET /api/v1/audit/auth-sample`; retention is
/// `GET /api/v1/settings/data-retention`. Nothing here adds a capability.
///
/// Honest limits, all stated in the UI: 50 rows per page, offset ceiling `kAuditMaxOffset`
/// (a request past it is refused with a note, never clamped), no filtered total.

#include <yuzu/server/auth.hpp>

#include "audit_store.hpp"

#include <httplib.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

namespace access_audit {

struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    /// The LOUD gate (`require_permission`): on false it has already written the 403 and its audit row.
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string&, const std::string&)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// One audit read. nullopt = the store is closed or did not answer (never an empty vector
    /// for that). `pool_size` receives the sample candidate pool when non-null.
    using QueryFn = std::function<std::optional<std::vector<AuditEvent>>(const AuditQuery&,
                                                                         std::size_t* pool_size)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    AuditFn audit_fn;
    QueryFn query_fn;
    /// `Config::audit_retention_days`, read per call so a runtime change shows.
    std::function<int()> retention_days_fn;
    /// Epoch seconds; the time window is now - range. Injected so tests never read a clock.
    std::function<std::int64_t()> now_fn;
};

/// Throws `std::invalid_argument` when any `Deps` member is unbound.
void register_access_audit_routes(HttpRouteSink& sink, Deps deps);

} // namespace access_audit
} // namespace yuzu::server
