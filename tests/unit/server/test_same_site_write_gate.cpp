/**
 * test_same_site_write_gate.cpp - cookie-session writes require a same-site Origin or Referer.
 *
 * Runs a real httplib::Server on an ephemeral loopback port, with a pre-routing handler that
 * mirrors the production call order: probe and pre-session paths return first, a session is
 * resolved (401 for API-style paths, a redirect for page-style ones), then `detail::apply_same_site_write_gate` is
 * called with the held session, then the request is routed to canary handlers. The production
 * lambda lives inside the server class and cannot be instantiated in a unit test, so this
 * fixture is a model of it, and the call site itself is pinned separately by the source-text
 * gate; this file proves the gate FUNCTION behaves correctly inside a live httplib pipeline.
 *
 * The session resolver below is likewise a MODEL of the real resolver's precedence (a valid
 * session cookie is consulted first, then the Authorization and token headers), not a proof of
 * it: the real resolver needs a store and is covered by its own Postgres-gated case.
 *
 * Every refusal case asserts: status 403, the A4 envelope (code, message, remediation, no
 * permission field, correlation id), exactly one audit row whose detail carries the closed-set
 * reason token, exactly one counter increment on the right series, and that neither the route
 * handler nor the pre-request stage ran. On Windows a lost early-4xx response (#2757, see
 * test_loopback_http.hpp) skips the response-level assertions but never the row, counter and
 * handler deltas.
 *
 * Paths are neutral canaries; no production route is named here. The one pre-session path and
 * the one probe path below are data for the exemption-by-placement case, and each is checked
 * against the production predicate so a change to that predicate fails this file loudly.
 *
 * Whole file compiled out under TSan: loopback httplib hits #2504 there.
 */
#include "health_routes.hpp"
#include "same_site_write_gate.hpp"
#include "same_site_write_policy.hpp"
#include "test_loopback_http.hpp"
#include "web_utils.hpp"

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define YUZU_TSAN_BUILD 1
#endif
#endif
#if defined(__SANITIZE_THREAD__)
#define YUZU_TSAN_BUILD 1
#endif

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#ifndef YUZU_TSAN_BUILD

namespace {

using namespace yuzu::server;
using yuzu::server::detail::SameSiteAuditPrincipal;
using yuzu::server::detail::SameSiteFaultHook;
using yuzu::server::detail::SameSiteFaultPoint;
using json = nlohmann::json;

// Pre-session / probe data for the exemption-by-placement case (see the file header).
constexpr std::string_view kPreSessionPath = "/login";
constexpr std::string_view kProbePath = "/livez";

constexpr const char* kCanary = "/api/v1/canary";
constexpr const char* kFragmentCanary = "/fragments/canary";
// A second body-cap path class, so per-class counter series are told apart.
constexpr const char* kOtherClassCanary = "/api/v1/hardware/canary";
constexpr const char* kOwnCheckCanary = "/api/v1/canary-own-check";
// One entry of the guarded-read table stands in for the whole set (the policy test loops over it).
constexpr std::string_view kGuardedReadCanary = kFetchMetadataGuardedPaths[0];

constexpr const char* kCookieOk = "yuzu_session=cookie-ok";
constexpr const char* kCookieSaml = "yuzu_session=cookie-saml";

struct AuditRow {
    std::string action, result, principal_id, principal_role, principal_cls, target_type,
        target_id, detail;
};

struct Pipeline {
    httplib::Server svr;
    std::thread server_thread;
    int port{0};
    yuzu::MetricsRegistry metrics;
    std::vector<std::string> trusted_origins;
    bool listener_is_tls{false}; // the web listener's TLS state, handed to the gate

    std::mutex mu;
    std::vector<AuditRow> rows;
    std::string last_body;
    std::atomic<bool> fail_audit{false};
    std::atomic<bool> throw_audit{false};
    std::atomic<int> fault_point{-1}; // SameSiteFaultPoint to throw at, or -1

    std::atomic<int> gate_rejections{0}; // witness for expect_pre_routing_rejection
    std::atomic<int> handler_hits{0};
    std::atomic<int> pre_request_hits{0};
    std::atomic<int> post_routing_hits{0};
    std::atomic<int> last_post_routing_status{0};

    detail::SameSitePrincipalAuditFn audit_fn;
    SameSiteFaultHook fault_hook;

    explicit Pipeline(std::vector<std::string> raw_trusted = {}, bool tls = false)
        : listener_is_tls(tls) {
        trusted_origins = normalise_trusted_origins(raw_trusted);
        audit_fn = [this](const httplib::Request&, const std::string& action,
                          const std::string& result, const SameSiteAuditPrincipal& p,
                          const std::string& tt, const std::string& tid, const std::string& d) {
            if (throw_audit.load())
                throw std::runtime_error("audit sink down");
            push_row({action, result, p.id, p.role, p.cls, tt, tid, d});
            return !fail_audit.load();
        };
        fault_hook = [this](SameSiteFaultPoint p) {
            if (fault_point.load() == static_cast<int>(p))
                throw std::runtime_error("injected fault");
        };
        start();
    }

    ~Pipeline() {
        if (server_thread.joinable()) {
            svr.wait_until_ready();
            svr.stop();
            server_thread.join();
        }
    }

    void push_row(AuditRow r) {
        std::lock_guard lk(mu);
        rows.push_back(std::move(r));
    }
    [[nodiscard]] std::size_t row_count() {
        std::lock_guard lk(mu);
        return rows.size();
    }
    [[nodiscard]] AuditRow row(std::size_t i) {
        std::lock_guard lk(mu);
        return rows.at(i);
    }
    [[nodiscard]] std::string seen_body() {
        std::lock_guard lk(mu);
        return last_body;
    }

    // MODEL of the real resolver's precedence: a valid session cookie first, then the
    // Authorization header, then the token header. An unknown cookie value falls through.
    [[nodiscard]] static std::optional<auth::Session> resolve(const httplib::Request& req) {
        auto make = [](std::string user, std::string source, std::string kind) {
            auth::Session s;
            s.username = std::move(user);
            s.role = auth::Role::user;
            s.auth_source = std::move(source);
            s.principal_kind = std::move(kind);
            return s;
        };
        const std::string cookie = req.get_header_value("Cookie");
        if (cookie.find("yuzu_session=cookie-ok") != std::string::npos)
            return make("alice", "local", "human");
        if (cookie.find("yuzu_session=cookie-oidc") != std::string::npos)
            return make("alice", "oidc", "human");
        if (cookie.find("yuzu_session=cookie-saml") != std::string::npos)
            return make("alice", "saml", "human");
        const std::string authz = req.get_header_value("Authorization");
        if (authz == "Bearer tok-ok")
            return make("svc", "api_token", "human");
        if (authz == "Bearer tok-engine")
            return make("eng", "engine_token", "engine");
        if (req.get_header_value("X-Yuzu-Token") == "tok-ok")
            return make("svc", "api_token", "human");
        return std::nullopt;
    }

    void start() {
        auto ok = [this](const httplib::Request& req, httplib::Response& res) {
            handler_hits.fetch_add(1);
            {
                std::lock_guard lk(mu);
                last_body = req.body;
            }
            res.set_content(R"({"ok":true})", "application/json");
        };
        svr.Get(kCanary, ok);
        svr.Post(kCanary, ok);
        svr.Put(kCanary, ok);
        svr.Patch(kCanary, ok);
        svr.Delete(kCanary, ok);
        svr.Options(kCanary, ok);
        svr.Get(std::string(kGuardedReadCanary), ok);
        svr.Post(kFragmentCanary, ok);
        svr.Post(kOtherClassCanary, ok);
        svr.Post(std::string(kPreSessionPath), ok);
        svr.Post(std::string(kProbePath), ok);
        // A route that carries its own copy of the check: a central refusal must produce ONE
        // row, because this handler never runs.
        svr.Post(kOwnCheckCanary, [this](const httplib::Request& req, httplib::Response& res) {
            handler_hits.fetch_add(1);
            const auto s = resolve(req);
            if (s && browser_write_is_cross_site(s->auth_source, req.get_header_value("Host"),
                                                 req.get_header_value("Origin"),
                                                 req.get_header_value("Referer"),
                                                 trusted_origins)) {
                push_row({"csrf.denied", "denied", s->username, "user", "human", "Endpoint",
                          "POST " + req.path, "own copy"});
                res.status = 403;
                res.set_content(R"({"error":"own copy"})", "application/json");
                return;
            }
            res.set_content(R"({"ok":true})", "application/json");
        });

        svr.set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res)
                                        -> httplib::Server::HandlerResponse {
            // Pre-session placement: these return before any session is resolved, so they
            // never reach the gate. Same order as the production handler.
            if (health::is_probe_path(req.path))
                return httplib::Server::HandlerResponse::Unhandled;
            if (is_login_exempt_path(req.path))
                return httplib::Server::HandlerResponse::Unhandled;

            const auto session = resolve(req);
            if (!session) {
                if (req.path.starts_with("/api/")) {
                    res.status = 401;
                    res.set_content(
                        R"({"error":{"code":401,"message":"unauthorized"},"meta":{"api_version":"v1"}})",
                        "application/json");
                } else {
                    res.set_redirect("/canary-signin");
                }
                return httplib::Server::HandlerResponse::Handled;
            }

            if (detail::apply_same_site_write_gate(req, res, *session, trusted_origins,
                                                   listener_is_tls, metrics, audit_fn,
                                                   &fault_hook)) {
                gate_rejections.fetch_add(1);
                return httplib::Server::HandlerResponse::Handled;
            }
            return httplib::Server::HandlerResponse::Unhandled;
        });

        // Runs only after a route matched (httplib dispatch), so it is the witness that a
        // refusal precedes everything past routing.
        svr.set_pre_request_handler([this](const httplib::Request&, httplib::Response&)
                                        -> httplib::Server::HandlerResponse {
            pre_request_hits.fetch_add(1);
            return httplib::Server::HandlerResponse::Unhandled;
        });
        // Runs when the response is written, including after a pre-routing refusal.
        svr.set_post_routing_handler([this](const httplib::Request&, httplib::Response& res) {
            last_post_routing_status.store(res.status);
            post_routing_hits.fetch_add(1);
        });

        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0); // before the thread exists: a throw here has nothing to join
        server_thread = std::thread([this]() { svr.listen_after_bind(); });
        svr.wait_until_ready();
        if (!svr.is_running()) {
            // Join first: REQUIRE throws out of the constructor, and a joinable std::thread
            // member destroyed by that unwind would std::terminate().
            svr.stop();
            server_thread.join();
        }
        REQUIRE(svr.is_running());
    }

    [[nodiscard]] std::string origin() const { return "http://127.0.0.1:" + std::to_string(port); }

    [[nodiscard]] httplib::Result send(const std::string& method, const std::string& path,
                                        const httplib::Headers& h = {},
                                        const std::string& body = "{}",
                                        const std::string& ctype = "application/json") const {
        httplib::Client cli("127.0.0.1", port);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(5);
        cli.set_write_timeout(5);
        if (method == "GET")
            return cli.Get(path, h);
        if (method == "HEAD")
            return cli.Head(path, h);
        if (method == "OPTIONS")
            return cli.Options(path, h);
        if (method == "POST")
            return cli.Post(path, h, body, ctype);
        if (method == "PUT")
            return cli.Put(path, h, body, ctype);
        if (method == "PATCH")
            return cli.Patch(path, h, body, ctype);
        if (method == "DELETE")
            return cli.Delete(path, h, body, ctype);
        throw std::runtime_error("unsupported method in test helper");
    }

    [[nodiscard]] double series(std::string_view path_class, std::string_view reason) {
        return metrics
            .counter(std::string(detail::kSameSiteDeniedCounter),
                     {{"path_class", std::string(path_class)}, {"reason", std::string(reason)}})
            .value();
    }
    // Sum over every path class the production pre-seed loop knows, and every reason.
    [[nodiscard]] double total() {
        double t = 0;
        for (const auto& e : kBodyCapTable)
            for (auto r : kSameSiteDenyReasons)
                t += series(e.path_class, r);
        return t;
    }
};

[[nodiscard]] std::string class_of(const std::string& method, const std::string& path) {
    return std::string(resolve_body_cap(method, path).path_class);
}

[[nodiscard]] bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

struct Snapshot {
    std::size_t rows;
    int hits, pre, gate;
    double total, series;
};
Snapshot snap(Pipeline& f, std::string_view path_class = {}, std::string_view reason = {}) {
    return {f.row_count(),
            f.handler_hits.load(),
            f.pre_request_hits.load(),
            f.gate_rejections.load(),
            f.total(),
            path_class.empty() ? 0.0 : f.series(path_class, reason)};
}

/// True when `r` holds a response. A missing response fails on POSIX. On Windows a lost 4xx after
/// a pre-routing answer is the documented #2757 mechanism: tolerated only for an RST-class error
/// (and, when a witness is given, only if it advanced), returning false so the caller skips its
/// response-level assertions while still asserting rows, counters and handler deltas.
bool response_or_tolerated_loss(const httplib::Result& r, const std::atomic<int>* witness = nullptr,
                                int witness_before = 0) {
    if (r)
        return true;
    INFO("no response read; httplib error = " << httplib::to_string(r.error()));
#ifdef _WIN32
    const auto err = r.error();
    REQUIRE((err == httplib::Error::Read || err == httplib::Error::Write ||
             err == httplib::Error::ConnectionClosed));
    if (witness)
        REQUIRE(witness->load() > witness_before);
    WARN("Windows: a pre-routing answer was lost to a connection reset (#2757)");
    return false;
#else
    (void)witness;
    (void)witness_before;
    REQUIRE(r);
    return false;
#endif
}

/// The audit detail a central refusal writes: fixed text plus the closed-set reason token.
[[nodiscard]] std::string refusal_detail(std::string_view reason) {
    return "cross-site or header-less browser write refused; reason=" + std::string(reason);
}

/// Sends the request and asserts the full contract of a central refusal. Returns the response, or
/// nothing when Windows lost it (rows, counters and handler deltas are still asserted).
std::optional<httplib::Response> expect_refused(Pipeline& f, const std::string& method,
                                                const std::string& path,
                                                const httplib::Headers& h,
                                                std::string_view reason,
                                                const std::string& body = "{}",
                                                const std::string& ctype = "application/json",
                                                bool audit_lost = false) {
    INFO(method << " " << path << " expecting reason " << reason);
    const std::string cls = class_of(method, path);
    const auto before = snap(f, cls, reason);
    std::optional<httplib::Response> got;
    yuzu::test::expect_pre_routing_rejection(
        [&] {
            auto r = f.send(method, path, h, body, ctype);
            if (r)
                got = *r;
            return r;
        },
        403, f.gate_rejections);
#ifndef _WIN32
    REQUIRE(got.has_value());
#endif
    if (got) {
        const auto& res = *got;
        REQUIRE(res.status == 403);
        const auto j = json::parse(res.body, nullptr, false);
        REQUIRE_FALSE(j.is_discarded());
        CHECK(j["error"]["code"] == 403);
        CHECK(j["error"]["message"] == "cross-site request refused");
        CHECK(j["error"]["remediation"].is_string());
        CHECK_FALSE(j["error"].contains("permission"));
        CHECK(res.has_header("X-Correlation-Id"));
        CHECK(j["error"]["correlation_id"] == res.get_header_value("X-Correlation-Id"));
        if (audit_lost)
            CHECK(res.headers.count("Sec-Audit-Failed") == 1);
        else
            CHECK(res.headers.count("Sec-Audit-Failed") == 0);
    }

    CHECK(f.row_count() == before.rows + 1);
    if (f.row_count() == before.rows + 1) {
        const auto r = f.row(before.rows);
        CHECK(r.action == "csrf.denied");
        CHECK(r.result == "denied");
        CHECK(r.principal_id == "alice");
        CHECK(r.principal_role == auth::role_to_string(auth::Role::user));
        CHECK(r.principal_cls == "human");
        CHECK(r.target_type == "Endpoint");
        CHECK(r.target_id == method + " " + path);
        CHECK(r.detail == refusal_detail(reason));
    }
    CHECK(f.handler_hits.load() == before.hits);    // no route handler ran
    CHECK(f.pre_request_hits.load() == before.pre); // no pre-request stage ran
    CHECK(f.gate_rejections.load() == before.gate + 1);
    CHECK(f.total() == before.total + 1);
    CHECK(f.series(cls, reason) == before.series + 1);
    return got;
}

/// Asserts a request the gate admits: the canary ran, nothing was audited or counted.
httplib::Response expect_admitted(Pipeline& f, const std::string& method, const std::string& path,
                                  const httplib::Headers& h, const std::string& body = "{}",
                                  const std::string& ctype = "application/json") {
    INFO(method << " " << path << " expecting admission");
    const auto before = snap(f);
    auto r = f.send(method, path, h, body, ctype);
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(f.handler_hits.load() == before.hits + 1);
    CHECK(f.pre_request_hits.load() == before.pre + 1);
    CHECK(f.gate_rejections.load() == before.gate);
    CHECK(f.row_count() == before.rows);
    CHECK(f.total() == before.total);
    return *r;
}

/// Asserts a request that never reaches the gate (no credential): the given status, no trace.
/// No witness is passed to the loss tolerance: the 401 is answered by the pre-routing handler
/// before the gate, and nothing counts those answers, so there is nothing to advance. A lost
/// answer on Windows therefore skips only the status check; the handler, gate, row and counter
/// deltas are still asserted.
void expect_not_gated(Pipeline& f, const std::string& method, const std::string& path,
                      const httplib::Headers& h, int status) {
    INFO(method << " " << path << " expecting status " << status);
    const auto before = snap(f);
    auto r = f.send(method, path, h);
    if (response_or_tolerated_loss(r))
        CHECK(r->status == status);
    CHECK(f.handler_hits.load() == before.hits);
    CHECK(f.gate_rejections.load() == before.gate);
    CHECK(f.row_count() == before.rows);
    CHECK(f.total() == before.total);
}

const httplib::Headers kCookie{{"Cookie", kCookieOk}};

#ifndef _WIN32
/// Sends a raw request head (declaring a body it never sends) and returns the first response
/// bytes. Used to prove a refusal does not wait for the body.
std::string raw_exchange(int port, const std::string& request_head) {
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
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // The POSIX sockaddr_in -> sockaddr cast: connect() takes the generic base type.
    REQUIRE(::connect(sock.v, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    timeval tv{};
    tv.tv_sec = 5;
    REQUIRE(::setsockopt(sock.v, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);
    REQUIRE(::send(sock.v, request_head.data(), request_head.size(), 0) ==
            static_cast<ssize_t>(request_head.size()));
    char buf[256] = {};
    const ssize_t n = ::recv(sock.v, buf, sizeof(buf) - 1, 0);
    REQUIRE(n > 0);
    return std::string(buf, static_cast<std::size_t>(n));
}
#endif

} // namespace

// -- Methods ---------------------------------------------------------------------------------

TEST_CASE("same-site pipeline: every write method without headers is refused for a cookie session",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    for (const char* m : {"POST", "PUT", "DELETE", "PATCH"})
        expect_refused(f, m, kCanary, kCookie, kSameSiteReasonNoHeaders);
}

TEST_CASE("same-site pipeline: reads and preflight are never gated", "[csrf][same_site][pipeline]") {
    Pipeline f;
    const httplib::Headers foreign{{"Cookie", kCookieOk}, {"Origin", "http://evil.example"}};
    for (const char* m : {"GET", "HEAD", "OPTIONS"}) {
        expect_admitted(f, m, kCanary, kCookie);
        expect_admitted(f, m, kCanary, foreign);
    }
}

// -- Origin and Referer ----------------------------------------------------------------------

TEST_CASE("same-site pipeline: a same-site Origin is admitted on every write method",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    const httplib::Headers h{{"Cookie", kCookieOk}, {"Origin", f.origin()}};
    for (const char* m : {"POST", "PUT", "DELETE", "PATCH"})
        expect_admitted(f, m, kCanary, h);
}

TEST_CASE("same-site pipeline: a foreign Origin is refused", "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_refused(f, "POST", kCanary, {{"Cookie", kCookieOk}, {"Origin", "http://evil.example"}},
                   kSameSiteReasonOriginMismatch);
    expect_refused(f, "DELETE", kCanary, {{"Cookie", kCookieOk}, {"Origin", "null"}},
                   kSameSiteReasonOriginMismatch);
}

TEST_CASE("same-site pipeline: a same-site Referer alone is admitted",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_admitted(f, "POST", kCanary,
                    {{"Cookie", kCookieOk}, {"Referer", f.origin() + "/page"}});
}

TEST_CASE("same-site pipeline: a foreign Referer alone is refused", "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_refused(f, "POST", kCanary,
                   {{"Cookie", kCookieOk}, {"Referer", "http://evil.example/"}},
                   kSameSiteReasonRefererMismatch);
}

TEST_CASE("same-site pipeline: a foreign Origin is refused even with a same-site Referer",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_refused(f, "POST", kCanary,
                   {{"Cookie", kCookieOk},
                    {"Origin", "http://evil.example"},
                    {"Referer", f.origin() + "/page"}},
                   kSameSiteReasonOriginMismatch);
}

TEST_CASE("same-site pipeline: an OIDC cookie session is gated like a local one",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_refused(f, "POST", kCanary, {{"Cookie", "yuzu_session=cookie-oidc"}},
                   kSameSiteReasonNoHeaders);
    expect_admitted(f, "POST", kCanary,
                    {{"Cookie", "yuzu_session=cookie-oidc"}, {"Origin", f.origin()}});
}

TEST_CASE("same-site pipeline: a SAML cookie session is gated like a local one",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_refused(f, "POST", kCanary, {{"Cookie", kCookieSaml}}, kSameSiteReasonNoHeaders);
    expect_admitted(f, "POST", kCanary, {{"Cookie", kCookieSaml}, {"Origin", f.origin()}});
}

TEST_CASE("same-site pipeline: a Referer alone decides on PUT, PATCH and DELETE",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    for (const char* m : {"PUT", "PATCH", "DELETE"}) {
        expect_admitted(f, m, kCanary, {{"Cookie", kCookieOk}, {"Referer", f.origin() + "/page"}});
        expect_refused(f, m, kCanary, {{"Cookie", kCookieOk}, {"Referer", "http://evil.example/"}},
                       kSameSiteReasonRefererMismatch);
    }
}

TEST_CASE("same-site pipeline: with two Origin headers the first one decides",
          "[csrf][same_site][pipeline]") {
    // Pins the current behaviour, not a design goal: httplib's get_header_value returns the
    // first of a repeated header, and the gate reads the header through it. A browser never
    // sends two Origin headers; the case documents what a hand-built request gets.
    Pipeline f;
    expect_admitted(f, "POST", kCanary,
                    {{"Cookie", kCookieOk},
                     {"Origin", f.origin()},
                     {"Origin", "http://evil.example"}});
    expect_refused(f, "POST", kCanary,
                   {{"Cookie", kCookieOk},
                    {"Origin", "http://evil.example"},
                    {"Origin", f.origin()}},
                   kSameSiteReasonOriginMismatch);
}

TEST_CASE("same-site pipeline: a refused write does not spend the session, a retry is admitted",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_refused(f, "POST", kCanary, kCookie, kSameSiteReasonNoHeaders);
    // The same cookie, now with a same-site Origin: admitted, and nothing more is counted.
    expect_admitted(f, "POST", kCanary, {{"Cookie", kCookieOk}, {"Origin", f.origin()}});
    CHECK(f.total() == 1.0);
    CHECK(f.row_count() == 1);
    CHECK(f.handler_hits.load() == 1);
    // And the session still reads: the refusal did not invalidate it.
    expect_admitted(f, "GET", kCanary, kCookie);
}

// -- Trusted origins -------------------------------------------------------------------------

TEST_CASE("same-site pipeline: a declared trusted origin is admitted behind a rewritten Host",
          "[csrf][same_site][pipeline]") {
    // Raw operator input, normalised exactly as at boot, then handed to the gate.
    Pipeline f({"https://Console.example/"});
    REQUIRE(f.trusted_origins.size() == 1);
    expect_admitted(f, "POST", kCanary,
                    {{"Cookie", kCookieOk},
                     {"Host", "yuzu-server:8080"},
                     {"Origin", "https://console.example"}});
    // A different scheme is a different origin.
    expect_refused(f, "POST", kCanary,
                   {{"Cookie", kCookieOk},
                    {"Host", "yuzu-server:8080"},
                    {"Origin", "http://console.example"}},
                   kSameSiteReasonOriginMismatch);
}

TEST_CASE("same-site pipeline: a TLS listener requires an https Origin",
          "[csrf][same_site][pipeline]") {
    Pipeline f({}, /*tls=*/true);
    const std::string https_origin = "https://127.0.0.1:" + std::to_string(f.port);
    expect_admitted(f, "POST", kCanary, {{"Cookie", kCookieOk}, {"Origin", https_origin}});
    expect_refused(f, "POST", kCanary, {{"Cookie", kCookieOk}, {"Origin", f.origin()}},
                   kSameSiteReasonOriginMismatch);
    // Token callers are not gated on a TLS listener either.
    expect_admitted(f, "POST", kCanary,
                    {{"Authorization", "Bearer tok-ok"}, {"Origin", f.origin()}});
}

TEST_CASE("same-site pipeline: with no trusted origin a rewritten Host is refused",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_refused(f, "POST", kCanary,
                   {{"Cookie", kCookieOk},
                    {"Host", "yuzu-server:8080"},
                    {"Origin", "https://console.example"}},
                   kSameSiteReasonOriginMismatch);
}

// -- Token callers ---------------------------------------------------------------------------

TEST_CASE("same-site pipeline: token callers are never refused", "[csrf][same_site][pipeline]") {
    Pipeline f;
    const httplib::Headers bearer{{"Authorization", "Bearer tok-ok"}};
    const httplib::Headers bearer_foreign{{"Authorization", "Bearer tok-ok"},
                                          {"Origin", "http://evil.example"}};
    const httplib::Headers xtoken{{"X-Yuzu-Token", "tok-ok"}};
    const httplib::Headers engine{{"Authorization", "Bearer tok-engine"}};
    for (const char* m : {"POST", "PUT", "DELETE", "PATCH"}) {
        expect_admitted(f, m, kCanary, bearer);
        expect_admitted(f, m, kCanary, bearer_foreign);
        expect_admitted(f, m, kCanary, xtoken);
        expect_admitted(f, m, kCanary, engine);
    }
}

// -- Mixed credentials (modelled resolver precedence) ----------------------------------------

TEST_CASE("same-site pipeline: a valid cookie wins over a token and is gated",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    // The resolver consults a valid cookie before the Authorization header, so a request that
    // also carries a token (valid or not) is a cookie-session request.
    expect_refused(f, "POST", kCanary,
                   {{"Cookie", kCookieOk}, {"Authorization", "Bearer tok-bad"}},
                   kSameSiteReasonNoHeaders);
    expect_refused(f, "POST", kCanary,
                   {{"Cookie", kCookieOk}, {"Authorization", "Bearer tok-ok"}},
                   kSameSiteReasonNoHeaders);
    expect_refused(f, "POST", kCanary, {{"Cookie", kCookieOk}, {"X-Yuzu-Token", "tok-ok"}},
                   kSameSiteReasonNoHeaders);
}

TEST_CASE("same-site pipeline: a stale cookie falls through to the token session",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_admitted(f, "POST", kCanary,
                    {{"Cookie", "yuzu_session=stale"}, {"Authorization", "Bearer tok-ok"}});
}

TEST_CASE("same-site pipeline: a token value presented only as a cookie is unauthenticated",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    // Not a session: 401 from the authentication step, never a 403 from the gate.
    expect_not_gated(f, "POST", kCanary, {{"Cookie", "yuzu_session=tok-ok"}}, 401);
}

TEST_CASE("same-site pipeline: an unknown extra credential header grants nothing",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_refused(f, "POST", kCanary, {{"Cookie", kCookieOk}, {"X-Canary-Grant", "junk.junk"}},
                   kSameSiteReasonNoHeaders);
    expect_not_gated(f, "POST", kCanary, {{"X-Canary-Grant", "junk.junk"}}, 401);
    expect_admitted(f, "POST", kCanary,
                    {{"Authorization", "Bearer tok-ok"}, {"X-Canary-Grant", "junk.junk"}});
}

// -- Authentication precedes the gate --------------------------------------------------------

TEST_CASE("same-site pipeline: an unauthenticated write is answered by authentication, not the gate",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_not_gated(f, "POST", kCanary, {}, 401);
    expect_not_gated(f, "DELETE", kCanary, {{"Origin", "http://evil.example"}}, 401);
    expect_not_gated(f, "POST", kFragmentCanary, {}, 302);
}

// -- Path classes ----------------------------------------------------------------------------

TEST_CASE("same-site pipeline: the JSON refusal is the same on page-style and other-class paths",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    REQUIRE(class_of("POST", kOtherClassCanary) != class_of("POST", kCanary));
    expect_refused(f, "POST", kFragmentCanary, kCookie, kSameSiteReasonNoHeaders);
    expect_refused(f, "POST", kOtherClassCanary, kCookie, kSameSiteReasonNoHeaders);
    expect_admitted(f, "POST", kFragmentCanary, {{"Cookie", kCookieOk}, {"Origin", f.origin()}});
    expect_admitted(f, "POST", kOtherClassCanary, {{"Cookie", kCookieOk}, {"Referer", f.origin()}});
}

// -- Envelope, accounting, ordering ----------------------------------------------------------

TEST_CASE("same-site pipeline: the refusal is the A4 envelope", "[csrf][same_site][pipeline]") {
    Pipeline f;
    const auto got = expect_refused(f, "POST", kCanary, kCookie, kSameSiteReasonNoHeaders);
    if (!got)
        return; // Windows lost the response (#2757); the shared helper already asserted the rest
    const auto& res = *got;
    CHECK(res.get_header_value("Content-Type").starts_with("application/json"));
    const auto j = json::parse(res.body);
    CHECK(j["error"]["retry_after_ms"].is_null());
    CHECK(j["meta"]["api_version"] == "v1");
    CHECK_FALSE(j["error"]["remediation"].get<std::string>().empty());
    CHECK(contains(j["error"]["remediation"].get<std::string>(), "--csrf-trusted-origin"));
}

TEST_CASE("same-site pipeline: each refusal is counted exactly once on its own series",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_refused(f, "POST", kCanary, kCookie, kSameSiteReasonNoHeaders);
    expect_refused(f, "POST", kCanary, kCookie, kSameSiteReasonNoHeaders);
    expect_refused(f, "PUT", kCanary, {{"Cookie", kCookieOk}, {"Origin", "http://evil.example"}},
                   kSameSiteReasonOriginMismatch);
    expect_refused(f, "POST", kOtherClassCanary,
                   {{"Cookie", kCookieOk}, {"Referer", "http://evil.example/"}},
                   kSameSiteReasonRefererMismatch);
    CHECK(f.total() == 4.0);
    CHECK(f.series(class_of("POST", kCanary), kSameSiteReasonNoHeaders) == 2.0);
    CHECK(f.series(class_of("PUT", kCanary), kSameSiteReasonOriginMismatch) == 1.0);
    CHECK(f.series(class_of("POST", kOtherClassCanary), kSameSiteReasonRefererMismatch) == 1.0);
    CHECK(f.series(class_of("POST", kCanary), kSameSiteReasonGateError) == 0.0);
    CHECK(f.row_count() == 4);
}

TEST_CASE("same-site pipeline: a refusal precedes the pre-request stage and the route handler",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    const int witness0 = f.gate_rejections.load();
    const auto r0 = f.send("POST", kCanary, kCookie);
    if (response_or_tolerated_loss(r0, &f.gate_rejections, witness0))
        CHECK(r0->status == 403);
    CHECK(f.pre_request_hits.load() == 0);
    CHECK(f.handler_hits.load() == 0);
    // The response-writing stage still runs for a pre-routing answer.
    CHECK(f.post_routing_hits.load() == 1);
    CHECK(f.last_post_routing_status.load() == 403);

    const auto r1 = f.send("POST", kCanary, {{"Cookie", kCookieOk}, {"Origin", f.origin()}});
    REQUIRE(r1);
    CHECK(r1->status == 200);
    CHECK(f.pre_request_hits.load() == 1);
    CHECK(f.handler_hits.load() == 1);
}

TEST_CASE("same-site pipeline: a route with its own check yields one row on a central refusal",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_refused(f, "POST", kOwnCheckCanary, kCookie, kSameSiteReasonNoHeaders);
    CHECK(f.row_count() == 1);
    expect_admitted(f, "POST", kOwnCheckCanary, {{"Cookie", kCookieOk}, {"Origin", f.origin()}});
}

// -- Body handling ---------------------------------------------------------------------------

TEST_CASE("same-site pipeline: form, empty-form, plain-text and multipart bodies are refused alike",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_refused(f, "POST", kCanary, kCookie, kSameSiteReasonNoHeaders, "a=1&b=2",
                   "application/x-www-form-urlencoded");
    expect_refused(f, "POST", kCanary, kCookie, kSameSiteReasonNoHeaders, "",
                   "application/x-www-form-urlencoded");
    expect_refused(f, "POST", kCanary, kCookie, kSameSiteReasonNoHeaders, "x=1", "text/plain");
    const std::string multipart =
        "--yuzuboundary\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\n"
        "Content-Type: text/plain\r\n\r\nhello\r\n--yuzuboundary--\r\n";
    expect_refused(f, "POST", kCanary, kCookie, kSameSiteReasonNoHeaders, multipart,
                   "multipart/form-data; boundary=yuzuboundary");
    CHECK(f.seen_body().empty()); // no handler ever saw a body
}

TEST_CASE("same-site pipeline: the same bodies reach the handler with a same-site Origin",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    const httplib::Headers h{{"Cookie", kCookieOk}, {"Origin", f.origin()}};
    expect_admitted(f, "POST", kCanary, h, "x=1", "text/plain");
    CHECK(f.seen_body() == "x=1");
    expect_admitted(f, "POST", kCanary, h, "", "application/x-www-form-urlencoded");
    CHECK(f.seen_body().empty());
}

#ifndef _WIN32
TEST_CASE("same-site pipeline: the refusal does not wait for the declared body",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    // Content-Length: 5 and not one body byte is ever sent. A refusal that waited for the body
    // would stall until raw_exchange's 5 s receive timeout and fail its REQUIRE(n > 0).
    const auto reply = raw_exchange(
        f.port, "POST " + std::string(kCanary) + " HTTP/1.1\r\nHost: 127.0.0.1:" +
                    std::to_string(f.port) + "\r\nCookie: " + kCookieOk +
                    "\r\nContent-Length: 5\r\n\r\n");
    CHECK(reply.starts_with("HTTP/1.1 403"));
    CHECK(f.handler_hits.load() == 0);
    CHECK(f.pre_request_hits.load() == 0);
    CHECK(f.gate_rejections.load() == 1);
    CHECK(f.row_count() == 1);
}
#endif

// -- Exemption by placement ------------------------------------------------------------------

TEST_CASE("same-site pipeline: pre-session and probe paths never reach the gate",
          "[csrf][same_site][pipeline]") {
    // The data below is only meaningful while the production predicates still classify it so.
    REQUIRE(is_login_exempt_path(kPreSessionPath));
    REQUIRE(health::is_probe_path(kProbePath));

    Pipeline f;
    for (const auto path : {kPreSessionPath, kProbePath}) {
        // No credential at all: reaches the handler (no 401), no row, no count.
        expect_admitted(f, "POST", std::string(path), {});
        // A cookie with a foreign Origin: still never evaluated, exemption is by path.
        expect_admitted(f, "POST", std::string(path),
                        {{"Cookie", kCookieOk}, {"Origin", "http://evil.example"}});
    }
    CHECK(f.gate_rejections.load() == 0);
}

// -- Audit and internal-failure behaviour ----------------------------------------------------

TEST_CASE("same-site pipeline: an audit sink that reports failure still refuses, and says so",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    f.fail_audit = true;
    expect_refused(f, "POST", kCanary, kCookie, kSameSiteReasonNoHeaders, "{}",
                   "application/json", /*audit_lost=*/true);
    CHECK(f.total() == 1.0);
}

TEST_CASE("same-site pipeline: an audit sink that throws still refuses, counted once",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    f.throw_audit = true;
    expect_admitted(f, "GET", kCanary, kCookie); // reads never touch the sink
    const auto before = snap(f);
    auto r = f.send("POST", kCanary, kCookie);
    if (response_or_tolerated_loss(r, &f.gate_rejections, before.gate)) {
        CHECK(r->status == 403);
        CHECK(r->headers.count("Sec-Audit-Failed") == 1);
    }
    CHECK(f.handler_hits.load() == before.hits);
    CHECK(f.total() == before.total + 1);
    CHECK(f.series(class_of("POST", kCanary), kSameSiteReasonNoHeaders) == 1.0);
    CHECK(f.series(class_of("POST", kCanary), kSameSiteReasonGateError) == 0.0);
}

TEST_CASE("same-site pipeline: an internal fault before the audit row is a counted gate error",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    f.fault_point = static_cast<int>(SameSiteFaultPoint::kBeforeAudit);
    const auto before = snap(f);
    auto r = f.send("POST", kCanary, kCookie);
    if (response_or_tolerated_loss(r, &f.gate_rejections, before.gate)) {
        CHECK(r->status == 403);
        CHECK(r->headers.count("Sec-Audit-Failed") == 1); // the row was never attempted
    }
    CHECK(f.row_count() == before.rows);
    CHECK(f.handler_hits.load() == before.hits);
    CHECK(f.series(class_of("POST", kCanary), kSameSiteReasonGateError) == 1.0);
    CHECK(f.total() == before.total + 1);
}

TEST_CASE("same-site pipeline: an internal fault after the count does not count twice",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    f.fault_point = static_cast<int>(SameSiteFaultPoint::kAfterCount);
    const auto before = snap(f);
    auto r = f.send("POST", kCanary, kCookie);
    if (response_or_tolerated_loss(r, &f.gate_rejections, before.gate)) {
        CHECK(r->status == 403);
        CHECK(r->headers.count("Sec-Audit-Failed") == 0); // the row was persisted
    }
    CHECK(f.row_count() == before.rows + 1);
    CHECK(f.handler_hits.load() == before.hits);
    CHECK(f.series(class_of("POST", kCanary), kSameSiteReasonNoHeaders) == 1.0);
    CHECK(f.series(class_of("POST", kCanary), kSameSiteReasonGateError) == 0.0);
    CHECK(f.total() == before.total + 1);
}

TEST_CASE("same-site pipeline: a render fault still leaves a 403 refusal",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    f.fault_point = static_cast<int>(SameSiteFaultPoint::kInRender);
    const auto before = snap(f);
    auto r = f.send("POST", kCanary, kCookie);
    if (response_or_tolerated_loss(r, &f.gate_rejections, before.gate))
        CHECK(r->status == 403);
    CHECK(f.handler_hits.load() == before.hits);
    CHECK(f.pre_request_hits.load() == before.pre);
    CHECK(f.total() == before.total + 1);
    CHECK(f.row_count() == before.rows + 1);
}

// -- Hostile headers -------------------------------------------------------------------------

TEST_CASE("same-site pipeline: oversized and control-byte headers are refused without breaking the server",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    // Under httplib's header line cap: reaches the gate and is refused as a mismatch.
    expect_refused(f, "POST", kCanary,
                   {{"Cookie", kCookieOk}, {"Origin", "http://" + std::string(7000, 'a')}},
                   kSameSiteReasonOriginMismatch);
#ifndef _WIN32
    // A control byte in a header value: the client library will not send one, so go raw. The
    // request must end in a refusal of some kind (the parser's 400 or the gate's 403), never
    // reach the handler, and not disturb the next request.
    {
        const auto before_raw = snap(f);
        const auto reply = raw_exchange(
            f.port, "POST " + std::string(kCanary) + " HTTP/1.1\r\nHost: 127.0.0.1:" +
                        std::to_string(f.port) + "\r\nCookie: " + kCookieOk +
                        "\r\nReferer: http://evil.example/\x01\r\nContent-Length: 0\r\n\r\n");
        CHECK((reply.starts_with("HTTP/1.1 400") || reply.starts_with("HTTP/1.1 403")));
        CHECK(f.handler_hits.load() == before_raw.hits);
        CHECK(f.pre_request_hits.load() == before_raw.pre);
    }
#endif

    // Over the cap: httplib refuses the request while parsing, before any handler stage.
    const auto before = snap(f);
    auto r = f.send("POST", kCanary,
                    {{"Cookie", kCookieOk}, {"Origin", "http://" + std::string(9000, 'a')}});
    if (r)
        CHECK(r->status == 400);
    CHECK(f.gate_rejections.load() == before.gate);
    CHECK(f.pre_request_hits.load() == before.pre);
    CHECK(f.handler_hits.load() == before.hits);

    // The server is still serving afterwards.
    expect_admitted(f, "POST", kCanary, {{"Cookie", kCookieOk}, {"Origin", f.origin()}});
}

#endif // YUZU_TSAN_BUILD

// -- Guarded reads -----------------------------------------------------------------------------

TEST_CASE("same-site pipeline: a guarded read with cross-site fetch metadata is refused",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    const std::string path(kGuardedReadCanary);
    for (const char* sfs : {"cross-site", "same-site", "garbage"}) {
        INFO(sfs);
        expect_refused(f, "GET", path, {{"Cookie", kCookieOk}, {"Sec-Fetch-Site", sfs}},
                       kSameSiteReasonOriginMismatch);
    }
    // A same-site Origin does not rescue a refusing fetch-metadata value.
    expect_refused(f, "GET", path,
                   {{"Cookie", kCookieOk}, {"Sec-Fetch-Site", "cross-site"}, {"Origin", f.origin()}},
                   kSameSiteReasonOriginMismatch);
}

TEST_CASE("same-site pipeline: a guarded read with same-origin or none metadata is admitted",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    const std::string path(kGuardedReadCanary);
    for (const char* sfs : {"same-origin", "none", "Same-Origin"})
        expect_admitted(f, "GET", path, {{"Cookie", kCookieOk}, {"Sec-Fetch-Site", sfs}});
}

TEST_CASE("same-site pipeline: a guarded read without fetch metadata falls back to Origin and Referer",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    const std::string path(kGuardedReadCanary);
    expect_refused(f, "GET", path, kCookie, kSameSiteReasonNoHeaders);
    expect_refused(f, "GET", path, {{"Cookie", kCookieOk}, {"Origin", "http://evil.example"}},
                   kSameSiteReasonOriginMismatch);
    expect_refused(f, "GET", path, {{"Cookie", kCookieOk}, {"Referer", "http://evil.example/"}},
                   kSameSiteReasonRefererMismatch);
    expect_admitted(f, "GET", path, {{"Cookie", kCookieOk}, {"Origin", f.origin()}});
    expect_admitted(f, "GET", path, {{"Cookie", kCookieOk}, {"Referer", f.origin() + "/page"}});
}

TEST_CASE("same-site pipeline: a token caller is admitted on a guarded read",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    const std::string path(kGuardedReadCanary);
    expect_admitted(f, "GET", path, {{"Authorization", "Bearer tok-ok"}});
    expect_admitted(f, "GET", path,
                    {{"Authorization", "Bearer tok-ok"}, {"Sec-Fetch-Site", "cross-site"}});
    expect_admitted(f, "GET", path, {{"Authorization", "Bearer tok-engine"}});
}

TEST_CASE("same-site pipeline: HEAD on a guarded read is refused like GET",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    const std::string path(kGuardedReadCanary);
    const std::string cls = class_of("HEAD", path);
    const auto before = snap(f, cls, kSameSiteReasonOriginMismatch);
    yuzu::test::expect_pre_routing_rejection(
        [&] {
            return f.send("HEAD", path, {{"Cookie", kCookieOk}, {"Sec-Fetch-Site", "cross-site"}});
        },
        403, f.gate_rejections);
    CHECK(f.row_count() == before.rows + 1);
    if (f.row_count() == before.rows + 1) {
        const auto r = f.row(before.rows);
        CHECK(r.action == "csrf.denied");
        CHECK(r.target_id == "HEAD " + path);
        CHECK(r.detail == refusal_detail(kSameSiteReasonOriginMismatch));
    }
    CHECK(f.handler_hits.load() == before.hits);
    CHECK(f.total() == before.total + 1);
    CHECK(f.series(cls, kSameSiteReasonOriginMismatch) == before.series + 1);
    expect_admitted(f, "HEAD", path, {{"Cookie", kCookieOk}, {"Sec-Fetch-Site", "same-origin"}});
}

TEST_CASE("same-site pipeline: an ordinary read with cross-site fetch metadata stays ungated",
          "[csrf][same_site][pipeline]") {
    Pipeline f;
    expect_admitted(f, "GET", kCanary, {{"Cookie", kCookieOk}, {"Sec-Fetch-Site", "cross-site"}});
}
