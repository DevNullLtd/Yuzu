/**
 * test_mcp_body_cap.cpp — the MCP transport body cap on the wire (#2437).
 *
 * The cap's DECISION is a pure function unit-tested in test_web_utils.cpp
 * (`mcp_body_exceeds_cap`). What THIS file pins is the part that lives in
 * httplib rather than in our code, and that no in-process fixture can reach:
 *
 *   1. A `/mcp/v1/` POST over the cap is answered 413 and the route handler
 *      never runs.
 *   2. **The body is never read off the socket.** This is the load-bearing
 *      library assumption behind putting the cap in the pre-routing handler
 *      at all — httplib invokes `pre_routing_handler_` in `routing()` BEFORE
 *      `read_content`, so returning `Handled` costs a header parse instead of
 *      buffering the payload. If a future vcpkg baseline bump reorders that,
 *      the cap silently stops being a DoS control and starts being a late
 *      rejection of something already in memory. Nothing else in the suite
 *      would notice.
 *   3. Sibling surfaces on the same server are NOT capped.
 *
 * `McpTestServer` in test_mcp_server.cpp dispatches the MCP handler in-process
 * with a hand-built `httplib::Request` and never constructs an
 * `httplib::Server`, so none of the above is observable there.
 *
 * CORRECTED CLAIM (#2407 R5, 2026-08-07): this fixture's `mcp_body_exceeds_cap`
 * / `mcp_body_unmeasurable` call below is NOT "the same call the pre-routing
 * lambda in server.cpp makes" — it never was after the #2407 unification, and
 * a comment here claiming otherwise is exactly the kind of unverified parity
 * claim that let the R1 CRITICAL bypass ship. Production's pre-routing
 * handler resolves through `resolve_body_cap` + `body_unmeasurable` +
 * `has_non_identity_content_encoding` (server.cpp), NOT these two functions —
 * they are PRODUCTION-DEAD (no call site outside tests). They are kept, and
 * this fixture still uses them, for two reasons unrelated to production
 * parity: (1) `test_web_utils.cpp` pins their own pure-function behaviour
 * independently, and (2) THIS fixture still proves items 1-3 above — the
 * wire-level, httplib-specific properties (body never read off the socket,
 * sibling surfaces uncapped) — against a REAL `httplib::Server`, which no
 * pure-function test can reach, using these two functions purely as a
 * stand-in decision to drive that wire behaviour. Whether to delete them is
 * an open question this file's owner cannot resolve alone: doing so would
 * also require removing `test_web_utils.cpp`'s coverage of them, which is
 * outside this file's scope — left as a follow-up rather than done here.
 *
 * SKIPPED UNDER ThreadSanitizer (#438), for the same reason as the
 * test_security_headers.cpp integration block: this deliberately exercises
 * httplib::Server's middleware wiring — the exact surface (threaded acceptor +
 * TSan interceptors) that crashes the TSan build. The pure-function coverage
 * in test_web_utils.cpp is TSan-safe and keeps the decision logic checked.
 */

#include "test_loopback_http.hpp"
#include "web_utils.hpp"

#include <httplib.h>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>

#if defined(__has_feature)
#  if __has_feature(thread_sanitizer)
#    define YUZU_TSAN_BUILD 1
#  endif
#endif
#if defined(__SANITIZE_THREAD__)
#  define YUZU_TSAN_BUILD 1
#endif

#ifndef YUZU_TSAN_BUILD

#ifndef _WIN32
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <unistd.h>
#endif

using yuzu::server::mcp_body_exceeds_cap;
using yuzu::server::mcp_body_unmeasurable;

namespace {

// A deliberately tiny cap so the tests move bytes, not megabytes. The
// production value (4 MiB) is pinned in test_mcp_server.cpp; what matters
// here is the BEHAVIOUR at the boundary, which is cap-independent.
constexpr std::uint64_t kTestCap = 1024;

struct BodyCapTestServer {
    httplib::Server svr;
    std::thread server_thread;
    int port{0};
    std::atomic<int> mcp_handler_calls{0};
    std::atomic<int> other_handler_calls{0};
    // Rejection witness (#2757): incremented exactly where the pre-routing
    // handler below decides to reject, so a Windows connection-reset
    // fallback (test_loopback_http.hpp) can prove the rejection actually
    // ran for a given request rather than accepting any lost response.
    std::atomic<int> rejections{0};

    void start() {
        svr.Post("/mcp/v1/", [this](const httplib::Request&, httplib::Response& res) {
            mcp_handler_calls.fetch_add(1);
            res.set_content(R"({"ok":true})", "application/json");
        });
        svr.Post("/api/v1/bundles", [this](const httplib::Request&, httplib::Response& res) {
            other_handler_calls.fetch_add(1);
            res.set_content(R"({"ok":true})", "application/json");
        });
        // A STAND-IN refusal decision using two now-production-dead pure
        // functions (see this file's header comment, #2407 R5) — NOT the
        // production branch's actual expression, which resolves through
        // `resolve_body_cap`/`body_unmeasurable`/`has_non_identity_content_
        // encoding` in server.cpp instead. Effectively equivalent in
        // OUTCOME for this fixture's cases (refuse an over-cap or
        // unmeasurable /mcp/ body), which is all items 1-3 above need; not
        // a claim of implementation identity. Production additionally
        // emits the metric, the throttled warn and the whole-branch
        // try/catch, and distinguishes 411 from 413/415; none of that is
        // replicated here, so this fixture proves the decision reaches the
        // wire, not the response taxonomy.
        svr.set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res)
                                        -> httplib::Server::HandlerResponse {
            if (mcp_body_exceeds_cap(req.path, req.get_header_value_u64("Content-Length", 0),
                                     kTestCap) ||
                mcp_body_unmeasurable(req.path, req.method, req.has_header("Content-Length"),
                                      req.get_header_value("Transfer-Encoding"),
                                      req.get_header_value("Content-Encoding"))) {
                res.status = 413;
                res.set_content(R"({"error":{"code":413,"message":"too large"}})",
                                "application/json");
                rejections.fetch_add(1);
                return httplib::Server::HandlerResponse::Handled;
            }
            return httplib::Server::HandlerResponse::Unhandled;
        });
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        server_thread = std::thread([this]() { svr.listen_after_bind(); });
        // wait_until_ready() rather than a bounded is_running() poll: it exits
        // on is_running_ OR is_decommissioned, so it terminates on bind failure
        // too, and it cannot hand the dtor a not-yet-running server (see below).
        svr.wait_until_ready();
        REQUIRE(svr.is_running());
    }

    ~BodyCapTestServer() {
        // ORDERING IS LOAD-BEARING, and the naive version deadlocks.
        // httplib's Server::stop() is a NO-OP while is_running_ is false
        // (httplib.h:10691) - it only shuts the listening socket when the
        // accept loop has already started. So if this dtor runs while the
        // listen thread is still starting up (a throw from start(), or a
        // descheduled thread on a contended CI box), stop() does nothing, the
        // thread THEN enters the accept loop, and join() blocks forever - a
        // hung job on a shared 4-agent runner, which is worse than a red test.
        // wait_until_ready() first guarantees stop() has something to stop.
        // GUARD ON joinable() FIRST. wait_until_ready() loops on
        // `!is_running_ && !is_decommissioned`, and BOTH stay false when no
        // listen thread was ever spawned - the std::thread ctor throwing
        // EAGAIN (four runner agents share one box), or this object being
        // destroyed before start() is called at all. The previous round
        // replaced a hang with a narrower hang. The wait exists solely to make
        // stop() effective against a thread that WILL enter the accept loop,
        // so it belongs inside the joinable() test.
        if (server_thread.joinable()) {
            svr.wait_until_ready();
            svr.stop();
            server_thread.join();
        }
    }
};

} // namespace

TEST_CASE("MCP body cap: an oversized POST is 413'd and never reaches the handler",
          "[mcp][bounds][integration]") {
    BodyCapTestServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    // 1025 B crosses CPPHTTPLIB_EXPECT_100_THRESHOLD (1024), so this request
    // also exercises the Expect: 100-continue path - see
    // test_loopback_http.hpp for why that matters on Windows.
    yuzu::test::expect_pre_routing_rejection(
        [&] { return cli.Post("/mcp/v1/", std::string(kTestCap + 1, 'x'), "application/json"); },
        413, ts.rejections);
    CHECK(ts.mcp_handler_calls.load() == 0);
}

TEST_CASE("MCP body cap: a request exactly at the cap is served normally",
          "[mcp][bounds][integration]") {
    BodyCapTestServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    // The boundary matters on the wire, not just in the predicate: an
    // off-by-one here rejects a request the published contract accepts.
    auto r = cli.Post("/mcp/v1/", std::string(kTestCap, 'x'), "application/json");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(ts.mcp_handler_calls.load() == 1);
}

TEST_CASE("MCP body cap: sibling surfaces on the same server are not capped",
          "[mcp][bounds][integration]") {
    BodyCapTestServer ts;
    ts.start();

    httplib::Client cli("127.0.0.1", ts.port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);

    // The regression this guards: reaching for Server::set_payload_max_length
    // instead of a per-path check would break the multipart certificate
    // upload and content distribution, which share this httplib instance.
    auto r = cli.Post("/api/v1/bundles", std::string(kTestCap * 4, 'x'), "application/json");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(ts.other_handler_calls.load() == 1);
}

#ifndef _WIN32
TEST_CASE("MCP body cap: the 413 arrives without the body being read",
          "[mcp][bounds][integration]") {
    // THE point of putting the cap in pre-routing. We declare a huge
    // Content-Length and send NO body at all, so the two orderings give
    // visibly different answers on the wire:
    //   * cap consulted BEFORE the body read -> 413 (what we assert)
    //   * body read first                    -> 400, httplib failing the
    //                                           content read for a body that
    //                                           never arrives
    // Measured, not assumed: neutering the fixture's guard flips this exact
    // assertion from "413" to "HTTP/1.1 400 Bad Request". That is what makes
    // this a real discriminator for the ORDERING rather than a restatement of
    // the three tests above. Note it does NOT hang — httplib answers 400
    // promptly — so the receive timeout below is a safety net, not the
    // mechanism under test.
    //
    // Raw socket because httplib::Client will not let us declare a length we
    // do not then send. POSIX-only: winsock needs WSAStartup and different
    // types, and the three tests above already cover the rejection itself on
    // every platform — this one covers the library-ordering assumption.
    BodyCapTestServer ts;
    ts.start();

    // RAII, not a bare `::close(fd)` at the end: every REQUIRE below throws on
    // failure, so a manual close would leak the descriptor on each early exit
    // — and a leaked fd in a suite this size eventually exhausts the process
    // limit and fails an unrelated test somewhere else.
    struct Fd {
        int v;
        explicit Fd(int f) : v(f) {}
        ~Fd() {
            if (v >= 0)
                ::close(v);
        }
        Fd(const Fd&) = delete;
        Fd& operator=(const Fd&) = delete;
    } sock{::socket(AF_INET, SOCK_STREAM, 0)};
    REQUIRE(sock.v >= 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(ts.port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::connect(sock.v, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

    // Fail rather than hang if the ordering assumption breaks.
    timeval tv{};
    tv.tv_sec = 10;
    // REQUIRE, not fire-and-forget: if this fails the recv below has no
    // timeout and a broken assumption becomes a HUNG job rather than a
    // failed test. (Windows note if the _WIN32 guard is ever lifted:
    // winsock also defines `timeval`, but SO_RCVTIMEO there wants a DWORD
    // of MILLISECONDS - a naive port compiles and silently misbehaves.)
    REQUIRE(::setsockopt(sock.v, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);

    const std::string headers = "POST /mcp/v1/ HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: 100000000\r\n"
                                "\r\n"; // ...and then nothing.
    REQUIRE(::send(sock.v, headers.data(), headers.size(), 0) ==
            static_cast<ssize_t>(headers.size()));

    char buf[256] = {};
    const ssize_t n = ::recv(sock.v, buf, sizeof(buf) - 1, 0);

    INFO("recv returned " << n << " bytes: " << std::string(buf, n > 0 ? n : 0));
    REQUIRE(n > 0); // 0 or -1 here = httplib waited for a body that never came
    CHECK(std::string(buf, static_cast<size_t>(n)).starts_with("HTTP/1.1 413"));
    CHECK(ts.mcp_handler_calls.load() == 0);
}
#endif // !_WIN32

#endif // !YUZU_TSAN_BUILD
