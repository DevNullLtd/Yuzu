/**
 * test_post_read_stage.cpp: `PostReadStageRegistry` and the handler wrapper `HttplibRouteSink`
 * installs from it (server/core/src/post_read_stage.hpp, http_route_sink.hpp).
 *
 * The wrapper is what keeps the #2407 post-read body cap and the MFA step-up chokepoint running
 * AFTER the request body has been read: cpp-httplib v0.47.0 and later run
 * `set_pre_request_handler` BEFORE the body is read, so the stage cannot live there. These tests
 * pin the wrapper's own contract (order, short-circuit, ordering guard, unwrapped servers); the
 * production stage's behaviour is pinned by test_step_up_wiring.cpp and test_body_cap_policy.cpp.
 *
 * The behavioural cases bind a loopback port, which crashes httplib under TSan (#438), so they
 * are compiled out of the TSan build; the registry cases need no socket and always run.
 */

#include "../../../server/core/src/http_route_sink.hpp"
#include "../../../server/core/src/post_read_stage.hpp"
#include "../../../server/core/src/route_inventory.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using yuzu::server::HttplibRouteSink;
using yuzu::server::PostReadStageRegistry;
using yuzu::server::RouteInventory;
using yuzu::server::ScopedPostReadStage;
using yuzu::server::StageRequirement;

namespace {

using Handled = httplib::Server::HandlerResponse;

const httplib::Server::Handler kNoop = [](const httplib::Request&, httplib::Response&) {
};

PostReadStageRegistry::Stage pass_stage() {
    return [](const httplib::Request&, httplib::Response&) {
        return Handled::Unhandled;
    };
}

/// Drops a server's registry and inventory entries on both ends: a test server can reuse a
/// destroyed one's address.
struct Clean {
    explicit Clean(const void* s) : server(s) { forget(); }
    ~Clean() { forget(); }
    Clean(const Clean&) = delete;
    Clean& operator=(const Clean&) = delete;
    void forget() {
        RouteInventory::instance().forget(server);
        PostReadStageRegistry::instance().forget(server);
    }
    const void* server;
};

} // namespace

TEST_CASE("post-read stage: install refuses an empty stage and a second install",
          "[postread][registry]") {
    httplib::Server svr;
    Clean clean(&svr);
    auto& reg = PostReadStageRegistry::instance();

    CHECK(reg.stage_for(&svr) == nullptr);
    CHECK_THROWS_AS(reg.install(&svr, PostReadStageRegistry::Stage{}), std::logic_error);
    CHECK(reg.stage_for(&svr) == nullptr);

    reg.install(&svr, pass_stage());
    CHECK(reg.stage_for(&svr) != nullptr);
    CHECK_THROWS_AS(reg.install(&svr, pass_stage()), std::logic_error);
    CHECK(reg.stage_for(&svr) != nullptr);
}

TEST_CASE("post-read stage: install after a route was recorded throws, so no route is left "
          "unwrapped",
          "[postread][registry]") {
    httplib::Server svr;
    Clean clean(&svr);
    HttplibRouteSink sink(svr, StageRequirement::ExemptNoStage);
    sink.Get("/yuzu_test_before_install", kNoop);

    CHECK_THROWS_AS(PostReadStageRegistry::instance().install(&svr, pass_stage()),
                    std::logic_error);
    CHECK(PostReadStageRegistry::instance().stage_for(&svr) == nullptr);
}

TEST_CASE("post-read stage: ScopedPostReadStage drops the stage and the inventory record on "
          "reset and on destruction, and an empty or moved-from guard is inert",
          "[postread][registry][raii]") {
    httplib::Server svr;
    Clean clean(&svr);
    auto& reg = PostReadStageRegistry::instance();
    reg.install(&svr, pass_stage());
    {
        HttplibRouteSink sink(svr);
        sink.Get("/yuzu_test_scoped_guard", kNoop);
    }
    REQUIRE(!RouteInventory::instance().routes_for(&svr).empty());

    ScopedPostReadStage guard(svr);
    CHECK(static_cast<bool>(guard));
    ScopedPostReadStage moved(std::move(guard));
    CHECK_FALSE(static_cast<bool>(guard));
    CHECK(static_cast<bool>(moved));
    guard.reset(); // moved-from: must not touch the registry
    CHECK(reg.stage_for(&svr) != nullptr);

    moved.reset();
    CHECK_FALSE(static_cast<bool>(moved));
    CHECK(reg.stage_for(&svr) == nullptr);
    CHECK(RouteInventory::instance().routes_for(&svr).empty());
    moved.reset(); // idempotent

    // Move-assignment: the target's old registration is dropped, the source's is kept.
    httplib::Server other;
    Clean clean_other(&other);
    reg.install(&svr, pass_stage());
    reg.install(&other, pass_stage());
    ScopedPostReadStage ga(svr);
    ScopedPostReadStage gb(other);
    ga = std::move(gb);
    CHECK(reg.stage_for(&svr) == nullptr);   // ga's old server was forgotten
    CHECK(reg.stage_for(&other) != nullptr); // gb's registration travelled into ga
    CHECK_FALSE(static_cast<bool>(gb));      // the moved-from guard no longer owns anything
    CHECK(static_cast<bool>(ga));
    ga.reset();
    CHECK(reg.stage_for(&other) == nullptr);

    // Self-move-assignment is a no-op: the guard keeps its registration (no reset, no double
    // forget). Through a reference so the compiler's -Wself-move does not fire.
    reg.install(&svr, pass_stage());
    ScopedPostReadStage self(svr);
    ScopedPostReadStage& self_ref = self;
    self = std::move(self_ref);
    CHECK(static_cast<bool>(self));
    CHECK(reg.stage_for(&svr) != nullptr);
    self.reset();
    CHECK_FALSE(static_cast<bool>(self));
    CHECK(reg.stage_for(&svr) == nullptr);

    // The destructor does the same: the address is then free for a server that reuses it.
    reg.install(&svr, pass_stage());
    {
        ScopedPostReadStage scoped(svr);
        CHECK(reg.stage_for(&svr) != nullptr);
    }
    CHECK(reg.stage_for(&svr) == nullptr);
    CHECK_NOTHROW(reg.install(&svr, pass_stage())); // a reused address is installable again
}

TEST_CASE("post-read stage: a stage is per server and forget drops only that server's",
          "[postread][registry]") {
    httplib::Server a;
    httplib::Server b;
    Clean clean_a(&a);
    Clean clean_b(&b);
    auto& reg = PostReadStageRegistry::instance();

    reg.install(&a, pass_stage());
    CHECK(reg.stage_for(&a) != nullptr);
    CHECK(reg.stage_for(&b) == nullptr);

    const auto held = reg.stage_for(&a);
    reg.forget(&a);
    CHECK(reg.stage_for(&a) == nullptr);
    CHECK(held != nullptr);        // a handler that captured it keeps it alive
    reg.install(&a, pass_stage()); // and the server may install again after a forget
}

#ifndef YUZU_TSAN_BUILD

namespace {

/// A loopback server whose routes are registered through the sink, with an optional stage.
struct StageServer {
    httplib::Server svr;
    std::thread th;
    int port{0};
    std::atomic<int> handler_calls{0};
    std::atomic<int> stage_calls{0};
    std::mutex mu;
    std::vector<std::string> order; // "stage" / "handler", in call order
    std::string stage_saw_body;
    std::string handler_saw_body;
    Clean clean{&svr};

    void start(PostReadStageRegistry::Stage stage) {
        const bool staged = static_cast<bool>(stage);
        if (staged)
            PostReadStageRegistry::instance().install(&svr, std::move(stage));
        HttplibRouteSink sink(svr, staged ? StageRequirement::Required
                                          : StageRequirement::ExemptNoStage);
        sink.Post("/yuzu_test_post", [this](const httplib::Request& req, httplib::Response& res) {
            handler_calls.fetch_add(1);
            {
                std::lock_guard lk(mu);
                order.push_back("handler");
                handler_saw_body = req.body;
            }
            res.status = 200;
            res.set_content("handled", "text/plain");
        });
        sink.Get("/yuzu_test_get", [this](const httplib::Request&, httplib::Response& res) {
            handler_calls.fetch_add(1);
            res.set_content("got", "text/plain");
        });
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        th = std::thread([this] { svr.listen_after_bind(); });
        svr.wait_until_ready();
        REQUIRE(svr.is_running());
    }

    ~StageServer() {
        if (th.joinable()) {
            svr.wait_until_ready();
            svr.stop();
            th.join();
        }
    }
};

} // namespace

TEST_CASE("post-read stage: the wrapper runs the stage after the body is read and before the "
          "handler",
          "[postread][wiring]") {
    StageServer s;
    s.start([&s](const httplib::Request& req, httplib::Response&) {
        s.stage_calls.fetch_add(1);
        std::lock_guard lk(s.mu);
        s.order.push_back("stage");
        s.stage_saw_body = req.body;
        return Handled::Unhandled;
    });

    httplib::Client cli("127.0.0.1", s.port);
    const std::string body(5000, 'b');
    auto r = cli.Post("/yuzu_test_post", body, "text/plain");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body == "handled");
    CHECK(s.stage_calls.load() == 1);
    CHECK(s.handler_calls.load() == 1);
    {
        std::lock_guard lk(s.mu);
        REQUIRE(s.order.size() == 2);
        CHECK(s.order[0] == "stage");
        CHECK(s.order[1] == "handler");
        CHECK(s.stage_saw_body == body); // the body was already read when the stage ran
        CHECK(s.handler_saw_body == body);
    }
}

TEST_CASE("post-read stage: the stage sees a chunked body in full", "[postread][wiring]") {
    StageServer s;
    s.start([&s](const httplib::Request& req, httplib::Response&) {
        std::lock_guard lk(s.mu);
        s.stage_saw_body = req.body;
        return Handled::Unhandled;
    });

    httplib::Client cli("127.0.0.1", s.port);
    const std::string body(70000, 'c');
    size_t sent = 0;
    auto r = cli.Post(
        "/yuzu_test_post",
        [&](size_t, httplib::DataSink& sink) {
            if (sent >= body.size()) {
                sink.done();
                return true;
            }
            const size_t n = std::min<size_t>(8192, body.size() - sent);
            sink.write(body.data() + sent, n);
            sent += n;
            return true;
        },
        "text/plain");
    REQUIRE(r);
    CHECK(r->status == 200);
    std::lock_guard lk(s.mu);
    CHECK(s.stage_saw_body == body);
}

TEST_CASE("post-read stage: Handled from the stage answers the request and skips the handler",
          "[postread][wiring]") {
    StageServer s;
    s.start([&s](const httplib::Request&, httplib::Response& res) {
        s.stage_calls.fetch_add(1);
        res.status = 413;
        res.set_content("refused", "text/plain");
        return Handled::Handled;
    });

    httplib::Client cli("127.0.0.1", s.port);
    auto r = cli.Post("/yuzu_test_post", "x", "text/plain");
    REQUIRE(r);
    CHECK(r->status == 413);
    CHECK(r->body == "refused");
    CHECK(s.stage_calls.load() == 1);
    CHECK(s.handler_calls.load() == 0);

    // The wrapper covers every verb the sink registers, GET included.
    auto g = cli.Get("/yuzu_test_get");
    REQUIRE(g);
    CHECK(g->status == 413);
    CHECK(s.handler_calls.load() == 0);
}

TEST_CASE("post-read stage: a server with no stage installed registers its handlers unwrapped",
          "[postread][wiring]") {
    StageServer s;
    s.start({});

    httplib::Client cli("127.0.0.1", s.port);
    auto r = cli.Post("/yuzu_test_post", "x", "text/plain");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(s.handler_calls.load() == 1);
    CHECK(s.stage_calls.load() == 0);
    CHECK(PostReadStageRegistry::instance().stage_for(&s.svr) == nullptr);
}

TEST_CASE("post-read stage: a sink on a server with no stage installed refuses every verb and "
          "registers nothing (fail closed)",
          "[postread][wiring]") {
    httplib::Server svr;
    Clean clean(&svr);
    HttplibRouteSink sink(svr); // StageRequirement::Required is the default

    CHECK_THROWS_AS(sink.Get("/yuzu_test_nostage", kNoop), std::logic_error);
    CHECK_THROWS_AS(sink.Post("/yuzu_test_nostage", kNoop), std::logic_error);
    CHECK_THROWS_AS(sink.Put("/yuzu_test_nostage", kNoop), std::logic_error);
    CHECK_THROWS_AS(sink.Delete("/yuzu_test_nostage", kNoop), std::logic_error);
    CHECK_THROWS_AS(sink.Patch("/yuzu_test_nostage", kNoop), std::logic_error);
    CHECK_THROWS_AS(sink.Options("/yuzu_test_nostage", kNoop), std::logic_error);

    // Nothing was recorded either, so a later install is still allowed (the refusal came first).
    CHECK(RouteInventory::instance().routes_for(&svr).empty());
    CHECK_NOTHROW(PostReadStageRegistry::instance().install(&svr, pass_stage()));
}

TEST_CASE("post-read stage: ExemptNoStage is the explicit opt-out and registers the handler as-is",
          "[postread][wiring]") {
    httplib::Server svr;
    Clean clean(&svr);
    HttplibRouteSink sink(svr, StageRequirement::ExemptNoStage);
    CHECK_NOTHROW(sink.Get("/yuzu_test_exempt", kNoop));
    CHECK(RouteInventory::instance().routes_for(&svr).size() == 1);
}

TEST_CASE("post-read stage: one server's stage does not wrap another server's routes",
          "[postread][wiring]") {
    StageServer wrapped;
    StageServer plain;
    wrapped.start([&wrapped](const httplib::Request&, httplib::Response& res) {
        wrapped.stage_calls.fetch_add(1);
        res.status = 403;
        return Handled::Handled;
    });
    plain.start({});

    httplib::Client c1("127.0.0.1", wrapped.port);
    httplib::Client c2("127.0.0.1", plain.port);
    auto r1 = c1.Post("/yuzu_test_post", "x", "text/plain");
    auto r2 = c2.Post("/yuzu_test_post", "x", "text/plain");
    REQUIRE(r1);
    REQUIRE(r2);
    CHECK(r1->status == 403);
    CHECK(r2->status == 200);
    CHECK(plain.handler_calls.load() == 1);
}

#endif // !YUZU_TSAN_BUILD
