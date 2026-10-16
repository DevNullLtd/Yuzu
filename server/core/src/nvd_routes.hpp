#pragma once

/// @file nvd_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 follow-up) — the 3 NVD CVE-feed routes, which sat contiguous
/// in server.cpp (all right after `/api/agents`). Every handler body is
/// copied verbatim from server.cpp; the changes are the receiver
/// (`web_server_->` -> `sink.`), the gate closure (`require_permission` ->
/// `deps.perm_fn`), and member accesses (`nvd_db_.` -> `deps.nvd_db->`,
/// `nvd_sync_.` -> `deps.nvd_sync->`).
///
/// Routes (4) — gate in parens, no route here uses auth_fn:
///   GET  /api/nvd/status         (perm_fn Infrastructure:Read)
///   POST /api/nvd/sync           (perm_fn Infrastructure:Execute; audited nvd.sync.request)
///   POST /api/nvd/match          (perm_fn Infrastructure:Read)
///   GET  /fragments/auto/nvd     (perm_fn Infrastructure:Read; status card over the SAME
///                                 status JSON as /api/nvd/status, so they cannot disagree)

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class NvdDatabase;
class NvdSyncManager;
} // namespace yuzu::server

namespace yuzu::server::nvd {

/// Construction deps for `register_nvd_routes`. Every closure/pointer is
/// bound once at start_web_server() time in server.cpp and never reseated.
struct Deps {
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;

    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    PermFn perm_fn; // no route in this group uses auth_fn
    AuditFn audit_fn; // server.cpp's hoisted audit closure; null = audit-off (tests)
    NvdDatabase* nvd_db{nullptr};
    NvdSyncManager* nvd_sync{nullptr};
};

/// The status object `GET /api/nvd/status` serves: `{"enabled":false}` when the catalog DB
/// is closed, otherwise enabled / total_cves and (when sync exists) the sync fields. Shared
/// with the status fragment so the two surfaces cannot drift.
nlohmann::json status_json(const NvdDatabase* db, const NvdSyncManager* sync);

/// PURE: the status card over `status_json`. Every dynamic string is escaped and the sync
/// error is length-capped.
std::string render_nvd_status(const nlohmann::json& status);

/// Register all 4 NVD CVE-feed routes against `sink`.
void register_nvd_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::nvd
