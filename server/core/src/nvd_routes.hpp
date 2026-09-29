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
/// Routes (3) — gate in parens, no route here uses auth_fn:
///   GET  /api/nvd/status   (perm_fn Infrastructure:Read)
///   POST /api/nvd/sync     (perm_fn Infrastructure:Execute)
///   POST /api/nvd/match    (perm_fn Infrastructure:Read)

#include <httplib.h>

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

    PermFn perm_fn; // no route in this group uses auth_fn
    NvdDatabase* nvd_db{nullptr};
    NvdSyncManager* nvd_sync{nullptr};
};

/// Register all 3 NVD CVE-feed routes against `sink`.
void register_nvd_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::nvd
