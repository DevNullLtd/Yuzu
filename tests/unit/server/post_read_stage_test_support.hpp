#pragma once

/// @file post_read_stage_test_support.hpp
/// Socket-test fixtures install the production post-read stage the way `server.cpp` does: into
/// `PostReadStageRegistry` for their `httplib::Server`, BEFORE any route, with the routes then
/// registered through an `HttplibRouteSink` (which wraps each handler with the stage). A fixture
/// that hung the stage on `set_pre_request_handler` instead would test a placement production no
/// longer uses, and from cpp-httplib v0.47.0 would see an empty `req.body`.
///
/// `PostReadStageScope` drops the server's registry and inventory entries on both ends: a test
/// server can reuse a destroyed one's address, and `PostReadStageRegistry::install` refuses a
/// server whose address still has routes recorded.

#include "../../../server/core/src/http_route_sink.hpp"
#include "../../../server/core/src/post_read_stage.hpp"
#include "../../../server/core/src/route_inventory.hpp"

#include <httplib.h>

#include <utility>

namespace yuzu::test {

class PostReadStageScope {
public:
    PostReadStageScope(httplib::Server& svr, server::PostReadStageRegistry::Stage stage)
        : svr_(&svr) {
        forget();
        server::PostReadStageRegistry::instance().install(svr_, std::move(stage));
    }
    ~PostReadStageScope() { forget(); }
    PostReadStageScope(const PostReadStageScope&) = delete;
    PostReadStageScope& operator=(const PostReadStageScope&) = delete;

private:
    void forget() {
        server::RouteInventory::instance().forget(svr_);
        server::PostReadStageRegistry::instance().forget(svr_);
    }
    httplib::Server* svr_;
};

} // namespace yuzu::test
