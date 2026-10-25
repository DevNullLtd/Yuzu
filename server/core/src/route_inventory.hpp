#pragma once

/// @file route_inventory.hpp
/// A process-wide record of every route registered through `HttplibRouteSink`,
/// keyed by the `httplib::Server` it was registered on. Written at boot, read
/// once by the step-up coverage sweep (`step_up_unclassified_registrations`,
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
/// as `Request::matched_route`). Every verb is recorded, and before the seal the
/// sweep (not this class) decides which are mutating. Once a server is sealed,
/// `record()` itself consults the step-up policy table (`step_up_policy.hpp`) to
/// decide what to admit; see SEALING. Registrations are de-duplicated per server,
/// so a pattern registered twice is one entry.
///
/// SEALING: once the boot sweep has passed, the owner of a server calls `seal()` for it. From
/// then on `record()` admits a mutating registration (POST/PUT/DELETE/PATCH) only if its exact
/// `(method, pattern)` has a row in the step-up policy table; any other is refused (a critical
/// log naming the route) and `HttplibRouteSink` throws instead of registering it. Registrations
/// that have a row, and non-mutating verbs, stay allowed. This covers registrations made
/// through the sink; the L3 source scan covers code that bypasses it. An unsealed server is
/// unaffected.
///
/// `TestRouteSink` (tests) does not record here: tests get their registrations
/// from `TestRouteSink::registered_routes()`.

#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::server {

class RouteInventory {
public:
    using Route = std::pair<std::string, std::string>; // (method, pattern)

    /// The single process-wide instance.
    static RouteInventory& instance();

    /// Record one registration on `server`. Thread-safe. Returns false, and records nothing,
    /// when `server` is sealed and this is a mutating registration with no step-up policy row;
    /// the caller must then NOT register the route.
    [[nodiscard]] bool record(const void* server, std::string_view method,
                              std::string_view pattern);

    /// Seal `server`'s inventory (see SEALING above). Idempotent. Thread-safe.
    void seal(const void* server);

    [[nodiscard]] bool is_sealed(const void* server) const;

    /// Every distinct registration on `server`, sorted by (method, pattern). Empty
    /// for an unknown server.
    [[nodiscard]] std::vector<Route> routes_for(const void* server) const;

    /// Drop everything recorded for `server`, including its seal. A new server may reuse a
    /// destroyed one's address, so the owner of a server calls this before it registers.
    void forget(const void* server);

private:
    mutable std::mutex mu_;
    std::unordered_map<const void*, std::set<Route>> by_server_;
    std::unordered_set<const void*> sealed_;
};

} // namespace yuzu::server
