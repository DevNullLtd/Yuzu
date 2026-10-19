#pragma once

/// @file route_inventory.hpp
/// A process-wide record of every route registered through `HttplibRouteSink`,
/// keyed by the `httplib::Server` it was registered on. Written at boot, read
/// once by the step-up coverage sweep (`unclassified_registrations`,
/// `step_up_gate.hpp`) after every route owner has registered; nothing on the
/// request path touches it.
///
/// WHY it is keyed by server: the process may hold more than one
/// `httplib::Server` (the plaintext redirect listener, in-process test
/// servers), and only the main web server's table is the served surface. The key
/// is an opaque address used for identity only, never dereferenced.
///
/// WHAT is recorded: the method and the pattern string exactly as handed to the
/// sink (a raw-string pattern is the same bytes httplib stores and reports back
/// as `Request::matched_route`). Every verb is recorded; the sweep, not this
/// class, decides which are mutating. Registrations are de-duplicated per
/// server, so a pattern registered twice is one entry.
///
/// `TestRouteSink` (tests) does not record here: tests get their registrations
/// from `TestRouteSink::registered_routes()`.

#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

class RouteInventory {
public:
    using Route = std::pair<std::string, std::string>; // (method, pattern)

    /// The single process-wide instance.
    static RouteInventory& instance();

    /// Record one registration on `server`. Thread-safe.
    void record(const void* server, std::string_view method, std::string_view pattern);

    /// Every distinct registration on `server`, sorted by (method, pattern). Empty
    /// for an unknown server.
    [[nodiscard]] std::vector<Route> routes_for(const void* server) const;

    /// Drop everything recorded for `server`. A new server may reuse a destroyed
    /// one's address, so the owner of a server calls this before it registers.
    void forget(const void* server);

private:
    mutable std::mutex mu_;
    std::unordered_map<const void*, std::set<Route>> by_server_;
};

} // namespace yuzu::server
