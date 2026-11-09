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
 * The behavioural cases bind a loopback port. They run in every build, TSan included (the CI
 * gai shim keeps httplib's resolver out of TSan's way, #438), alongside the socket-free registry
 * cases.
 */

#include "../../../server/core/src/http_route_sink.hpp"
#include "../../../server/core/src/post_read_stage.hpp"
#include "../../../server/core/src/route_inventory.hpp"
#include "../test_helpers.hpp"

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
        // One handler on every other verb, all through the sink, so a verb that registered the
        // unwrapped handler is visible to the all-verbs assertion below.
        const auto plain = [this](const httplib::Request&, httplib::Response& res) {
            handler_calls.fetch_add(1);
            res.status = 200;
            res.set_content("verb", "text/plain");
        };
        sink.Get("/yuzu_test_get", plain);
        sink.Put("/yuzu_test_verb", plain);
        sink.Delete("/yuzu_test_verb", plain);
        sink.Patch("/yuzu_test_verb", plain);
        sink.Options("/yuzu_test_verb", plain);
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

    // The wrapper covers every verb the sink registers: each answers 413 and none reaches its
    // handler.
    const std::vector<std::pair<std::string, httplib::Result>> verbs = [&cli] {
        std::vector<std::pair<std::string, httplib::Result>> v;
        v.emplace_back("GET", cli.Get("/yuzu_test_get"));
        v.emplace_back("PUT", cli.Put("/yuzu_test_verb", "x", "text/plain"));
        v.emplace_back("DELETE", cli.Delete("/yuzu_test_verb"));
        v.emplace_back("PATCH", cli.Patch("/yuzu_test_verb", "x", "text/plain"));
        v.emplace_back("OPTIONS", cli.Options("/yuzu_test_verb"));
        return v;
    }();
    for (const auto& [verb, res] : verbs) {
        INFO(verb);
        REQUIRE(res);
        CHECK(res->status == 413);
    }
    CHECK(s.handler_calls.load() == 0);
    // The stage ran once for the POST above and once for each of the five verbs here.
    CHECK(s.stage_calls.load() == 6);
}

TEST_CASE("post-read stage: an exempt server with no stage installed serves its handlers "
          "as registered",
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

TEST_CASE("post-read stage: the two process-global registries are safe under concurrent "
          "install, record, lookup and forget on distinct servers",
          "[postread][registry][concurrency]") {
    // Socket-free: the registry and the inventory are process-wide. A production boot registers
    // the main listener and the plaintext redirect listener (two server keys) from one thread,
    // and tests or a later listener may touch them from others. Each worker owns its own
    // never-listening server. A start gate makes the workers overlap, so a plain (non-TSan)
    // build also has a chance to see a lost update; TSan is the detector that proves the
    // mutexes do their job.
    constexpr int kThreads = 8;
    constexpr int kRounds = 100;
    std::atomic<bool> go{false};
    std::atomic<int> failures{0};
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    // Joins every started worker on every exit, including a failed thread start part-way through
    // the loop: a joinable std::thread destroyed during unwinding would terminate the whole test
    // binary. (No std::jthread: Apple libc++ lacks it.)
    yuzu::test::ScopeExit joiner{[&] {
        go = true;
        for (auto& w : workers)
            if (w.joinable())
                w.join();
    }};
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&] {
            try {
                httplib::Server svr;
                auto& reg = PostReadStageRegistry::instance();
                Clean clean(&svr);
                while (!go.load())
                    std::this_thread::yield();
                for (int r = 0; r < kRounds; ++r) {
                    reg.install(&svr, pass_stage());
                    HttplibRouteSink sink(svr);
                    sink.Get("/yuzu_test_concurrent_registry", kNoop);
                    if (reg.stage_for(&svr) == nullptr ||
                        RouteInventory::instance().routes_for(&svr).empty())
                        failures.fetch_add(1);
                    RouteInventory::instance().forget(&svr);
                    reg.forget(&svr);
                    if (reg.stage_for(&svr) != nullptr ||
                        !RouteInventory::instance().routes_for(&svr).empty())
                        failures.fetch_add(1);
                }
            } catch (...) {
                failures.fetch_add(1);
            }
        });
    }
    go = true;
    for (auto& w : workers)
        w.join();
    CHECK(failures.load() == 0);
}

TEST_CASE("post-read stage: a regex route does not match a path longer than httplib's regex "
          "route path limit, so neither the stage nor the handler runs for it",
          "[postread][wiring][regex_cap][body_cap][bounds][integration]") {
    // From cpp-httplib 0.59.0 a regex route (any pattern with a capture group, `(.+)` included)
    // is skipped for a path longer than CPPHTTPLIB_REGEX_ROUTE_PATH_MAX_LENGTH (256 bytes by
    // default), where 0.37.1 had no such limit. An unmatched path never reaches a handler, so the
    // effect on the routes that carry an id in the path (`/api/v1/tokens/(.+)` and the like) is a
    // refusal (httplib's own 404), never an ungated pass. The upgrade guide and the changelog
    // state the number, so a httplib that changes the limit, or a build that sets the macro, must
    // fail here before that text goes stale.
    REQUIRE(CPPHTTPLIB_REGEX_ROUTE_PATH_MAX_LENGTH == 256);

    httplib::Server svr;
    Clean clean(&svr);
    std::atomic<int> stage_calls{0};
    std::atomic<int> handler_calls{0};
    PostReadStageRegistry::instance().install(
        &svr, [&](const httplib::Request&, httplib::Response&) {
            stage_calls.fetch_add(1);
            return Handled::Unhandled;
        });
    HttplibRouteSink sink(svr);
    sink.Get(R"(/yuzu_test_re/(.+))", [&](const httplib::Request&, httplib::Response& res) {
        handler_calls.fetch_add(1);
        res.set_content("ok", "text/plain");
    });
    const int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&] { svr.listen_after_bind(); });
    // Stops and joins on every exit, including a failed REQUIRE below: a joinable std::thread
    // destroyed during unwinding would terminate the whole test binary. The wait sits inside the
    // joinable() test because stop() is a no-op until the accept loop is running.
    yuzu::test::ScopeExit joiner{[&] {
        if (th.joinable()) {
            svr.wait_until_ready();
            svr.stop();
            th.join();
        }
    }};
    svr.wait_until_ready();

    const std::string prefix = "/yuzu_test_re/";
    const auto at_limit =
        prefix + std::string(CPPHTTPLIB_REGEX_ROUTE_PATH_MAX_LENGTH - prefix.size(), 'a');
    const auto over_limit = at_limit + "a";
    REQUIRE(at_limit.size() == CPPHTTPLIB_REGEX_ROUTE_PATH_MAX_LENGTH);

    httplib::Client cli("127.0.0.1", port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    const auto shortp = cli.Get(prefix + std::string(40, 'a'));
    const auto atp = cli.Get(at_limit);
    const auto overp = cli.Get(over_limit);

    REQUIRE(shortp);
    CHECK(shortp->status == 200);
    REQUIRE(atp);
    CHECK(atp->status == 200);
    REQUIRE(overp);
    CHECK(overp->status == 404);
    CHECK(handler_calls.load() == 2);
    CHECK(stage_calls.load() == 2);
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
