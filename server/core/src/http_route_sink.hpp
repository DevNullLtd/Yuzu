#pragma once

// HttpRouteSink — abstraction over the route-registration surface of
// httplib::Server, introduced to let route owners (SettingsRoutes,
// RestApiV1, McpServer) be unit-tested in-process without spinning up
// httplib::Server's threaded acceptor.
//
// Why: httplib::Server's `bind_to_any_port + listen_after_bind on a
// std::thread` pattern crashes under TSan with no TSan report — the
// segfault is in httplib's internal state machine, not a race TSan caught
// (issue #438). Most loopback fixtures are therefore compiled out under
// the Sanitizers (TSan) CI job; the socket cases in test_post_read_stage.cpp
// are the exception and run there with the CI gai shim.
//
// The fix is a thin polymorphic seam at the route-registration boundary:
//   - Production code constructs HttplibRouteSink(svr) and passes a
//     reference to register_routes. The sink registers each handler on the
//     same server wrapped in the server's post-read stage (body cap + step-up),
//     and throws std::logic_error rather than register a route that stage
//     could not cover.
//   - Tests construct an in-process sink (see tests/unit/server/test_route_sink.hpp)
//     that captures the (method, path, handler) triples, supports
//     httplib-style :param and regex path matching, and dispatches a
//     synthesized httplib::Request directly into the captured handler.
//     No socket, no acceptor thread, nothing for TSan to fight with.

#include "post_read_stage.hpp"
#include "route_inventory.hpp"

#include <httplib.h>

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server {

/// Interface that mirrors the subset of httplib::Server's route-registration
/// API that Yuzu's route owners use. Production registers through
/// `HttplibRouteSink` below (which wraps and records each handler); an
/// in-process test sink (tests/unit/server/test_route_sink.hpp) dispatches
/// without a socket.
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

/// Whether a `HttplibRouteSink` insists on a post-read stage for its server. `Required` is the
/// default and fails closed; `ExemptNoStage` is the only opt-out and must be spelled out.
enum class StageRequirement {
    Required,
    ExemptNoStage,
};

/// Concrete sink that registers every route on a wrapped httplib::Server, behind the server's
/// post-read stage. Production callers construct one of these on the stack at the register_routes
/// call site and pass it through.
///
/// Each registration is also recorded in `RouteInventory` (method + pattern, keyed by the wrapped
/// server) so the boot-time step-up coverage sweep can see every route the server will serve.
/// Recording is one mutex-guarded set insert at boot and does not change what is registered. After
/// the boot sweep the server's inventory is sealed (`RouteInventory::seal`); from then on a mutating
/// registration with no step-up policy row is not registered, and the sink throws
/// `std::logic_error` naming it.
///
/// Each handler is registered wrapped in the post-read stage installed for the wrapped server
/// (`PostReadStageRegistry`, `post_read_stage.hpp`), so the stage runs after the body is read and
/// before the handler, and a `Handled` answer short-circuits the handler. The stage is looked up
/// once, at registration, which is why it must be installed before the first route.
///
/// FAIL-CLOSED: the default `StageRequirement::Required` makes a registration on a server with NO
/// stage installed throw `std::logic_error` BEFORE anything is recorded or registered, so a route
/// owner built on a server that forgot the install cannot serve an uncapped, ungated route. The one
/// way out is the explicit, greppable `StageRequirement::ExemptNoStage`, used by the plaintext
/// redirect listener (it only answers 301) and by tests that do not exercise the stage.
class HttplibRouteSink : public HttpRouteSink {
public:
    explicit HttplibRouteSink(httplib::Server& svr,
                              StageRequirement requirement = StageRequirement::Required)
        : svr_(svr), requirement_(requirement) {}

    void Get(const std::string& p, Handler h) override     { auto w = wrap(p, std::move(h)); record("GET", p);     svr_.Get(p, std::move(w)); }
    void Post(const std::string& p, Handler h) override    { auto w = wrap(p, std::move(h)); record("POST", p);    svr_.Post(p, std::move(w)); }
    void Put(const std::string& p, Handler h) override     { auto w = wrap(p, std::move(h)); record("PUT", p);     svr_.Put(p, std::move(w)); }
    void Delete(const std::string& p, Handler h) override  { auto w = wrap(p, std::move(h)); record("DELETE", p);  svr_.Delete(p, std::move(w)); }
    void Patch(const std::string& p, Handler h) override   { auto w = wrap(p, std::move(h)); record("PATCH", p);   svr_.Patch(p, std::move(w)); }
    void Options(const std::string& p, Handler h) override { auto w = wrap(p, std::move(h)); record("OPTIONS", p); svr_.Options(p, std::move(w)); }

private:
    /// `h` run behind the server's post-read stage. With no stage installed: `h` itself under
    /// `ExemptNoStage`, otherwise a `std::logic_error` (fail closed; see the class comment).
    Handler wrap(const std::string& pattern, Handler h) const {
        const auto stage = PostReadStageRegistry::instance().stage_for(&svr_);
        if (!stage) {
            if (requirement_ == StageRequirement::Required)
                throw std::logic_error("refused to register " + pattern +
                                       ": no post-read stage is installed for this server, so the body "
                                       "cap and step-up chokepoint would not run for it");
            return h;
        }
        return [stage, h = std::move(h)](const httplib::Request& req, httplib::Response& res) {
            if ((*stage)(req, res) == httplib::Server::HandlerResponse::Handled)
                return;
            h(req, res);
        };
    }

    void record(std::string_view method, const std::string& pattern) {
        if (!RouteInventory::instance().record(&svr_, method, pattern))
            throw std::logic_error("refused to register " + std::string(method) + " " + pattern +
                                   ": no MFA step-up policy row and the route table is sealed");
    }

    httplib::Server& svr_;
    StageRequirement requirement_;
};

} // namespace yuzu::server
