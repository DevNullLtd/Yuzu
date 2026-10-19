#pragma once

// HttpRouteSink — abstraction over the route-registration surface of
// httplib::Server, introduced to let route owners (SettingsRoutes,
// RestApiV1, McpServer) be unit-tested in-process without spinning up
// httplib::Server's threaded acceptor.
//
// Why: httplib::Server's `bind_to_any_port + listen_after_bind on a
// std::thread` pattern crashes under TSan with no TSan report — the
// segfault is in httplib's internal state machine, not a race TSan caught
// (issue #438). Test fixtures that bind real ports therefore can't run
// under the Sanitizers (TSan) CI job.
//
// The fix is a thin polymorphic seam at the route-registration boundary:
//   - Production code constructs HttplibRouteSink(svr) and passes a
//     reference to register_routes — same calls, same handlers, same
//     server, no behavioural change.
//   - Tests construct an in-process sink (see tests/unit/server/test_route_sink.hpp)
//     that captures the (method, path, handler) triples, supports
//     httplib-style :param and regex path matching, and dispatches a
//     synthesized httplib::Request directly into the captured handler.
//     No socket, no acceptor thread, nothing for TSan to fight with.

#include "route_inventory.hpp"

#include <httplib.h>

#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server {

/// Interface that mirrors the subset of httplib::Server's route-registration
/// API that Yuzu's route owners use. Production code keeps using
/// httplib::Server end-to-end; this seam exists for in-process test dispatch.
class HttpRouteSink {
public:
    using Handler = httplib::Server::Handler;

    virtual ~HttpRouteSink() = default;

    virtual void Get(const std::string& pattern, Handler handler) = 0;
    virtual void Post(const std::string& pattern, Handler handler) = 0;
    virtual void Put(const std::string& pattern, Handler handler) = 0;
    virtual void Delete(const std::string& pattern, Handler handler) = 0;
    virtual void Patch(const std::string& pattern, Handler handler) = 0;
    virtual void Options(const std::string& pattern, Handler handler) = 0;
};

/// Concrete sink that forwards every registration to a wrapped
/// httplib::Server. Production callers construct one of these on the
/// stack at the register_routes call site and pass it through.
///
/// Each registration is also recorded in `RouteInventory` (method + pattern,
/// keyed by the wrapped server) so the boot-time step-up coverage sweep can see
/// every route the server will serve. The recording is one mutex-guarded set
/// insert at boot and changes nothing about what is registered.
class HttplibRouteSink : public HttpRouteSink {
public:
    explicit HttplibRouteSink(httplib::Server& svr) : svr_(svr) {}

    void Get(const std::string& p, Handler h) override     { record("GET", p);     svr_.Get(p, std::move(h)); }
    void Post(const std::string& p, Handler h) override    { record("POST", p);    svr_.Post(p, std::move(h)); }
    void Put(const std::string& p, Handler h) override     { record("PUT", p);     svr_.Put(p, std::move(h)); }
    void Delete(const std::string& p, Handler h) override  { record("DELETE", p);  svr_.Delete(p, std::move(h)); }
    void Patch(const std::string& p, Handler h) override   { record("PATCH", p);   svr_.Patch(p, std::move(h)); }
    void Options(const std::string& p, Handler h) override { record("OPTIONS", p); svr_.Options(p, std::move(h)); }

private:
    void record(std::string_view method, const std::string& pattern) {
        RouteInventory::instance().record(&svr_, method, pattern);
    }

    httplib::Server& svr_;
};

} // namespace yuzu::server
