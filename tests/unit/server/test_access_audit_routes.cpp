/**
 * @file test_access_audit_routes.cpp
 * @brief HTTP-level coverage of access_audit_routes.{hpp,cpp}, driven in-process through
 *        TestRouteSink. Every closure is injected; nothing reads a clock or a store.
 *
 * Pinned, in order of consequence:
 *   - the loud gate runs BEFORE any parse or read, on exactly the twin's securable
 *     (AuditLog:Read for log and sample, ServerConfig:Read for retention);
 *   - `limit` is never read from the client (the store sees 51), `offset` is refused past
 *     10,000 rather than clamped, a NUL byte in a filter is refused, nothing else widens the query;
 *   - an unreadable store is a 200 red box and the data is never rendered as empty;
 *   - the log read writes no audit row (as its twin), the sample read writes exactly one;
 *   - `register_access_audit_routes` binds the REAL gates (source scan of server.cpp is in
 *     test_access_audit_wiring_lexical.py).
 */

#include "access_audit_render.hpp"
#include "access_audit_routes.hpp"
#include "access_audit_ui.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;

namespace {

constexpr const char* kDenyBody = R"({"error":{"code":403,"message":"permission denied"}})";
constexpr std::int64_t kNow = 2'000'000'000;

AuditEvent ev(std::int64_t id, std::string action = "auth.login", std::string principal = "dave") {
    AuditEvent e;
    e.id = id;
    e.timestamp = 1'999'999'000;
    e.principal = std::move(principal);
    e.action = std::move(action);
    e.result = "ok";
    return e;
}

int count_substr(const std::string& hay, const std::string& needle) {
    int n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

std::vector<AuditEvent> rows(int n) {
    std::vector<AuditEvent> r;
    for (int i = 0; i < n; ++i)
        r.push_back(ev(1000 - i));
    return r;
}

// `sink` is LAST: its handlers capture `this` and must not outlive the other members.
struct Harness {
    bool session_present{true};
    bool allow{true};
    std::vector<std::pair<std::string, std::string>> gate_calls;
    int query_calls{0};
    AuditQuery last_query;
    std::size_t* last_pool_ptr{nullptr};
    std::optional<std::vector<AuditEvent>> result{std::vector<AuditEvent>{}};
    std::size_t pool{0};
    struct Audit {
        std::string action, result, tt, ti, detail;
    };
    std::vector<Audit> audits;
    bool audit_ok{true};
    bool audit_throws{false};
    int retention{365};
    yuzu::server::test::TestRouteSink sink;

    access_audit::Deps deps() {
        access_audit::Deps d;
        d.auth_fn = [this](const httplib::Request&,
                           httplib::Response& res) -> std::optional<auth::Session> {
            if (!session_present) {
                res.status = 401;
                return std::nullopt;
            }
            return auth::Session{};
        };
        d.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& t,
                           const std::string& o) {
            gate_calls.emplace_back(t, o);
            if (allow)
                return true;
            res.status = 403;
            res.set_content(kDenyBody, "application/json");
            return false;
        };
        d.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string& tt, const std::string& ti, const std::string& dt) {
            if (audit_throws)
                throw std::runtime_error("audit sink down");
            audits.push_back({a, r, tt, ti, dt});
            return audit_ok;
        };
        d.query_fn = [this](const AuditQuery& q, std::size_t* pool_ptr)
            -> std::optional<std::vector<AuditEvent>> {
            ++query_calls;
            last_query = q;
            last_pool_ptr = pool_ptr;
            if (pool_ptr)
                *pool_ptr = pool;
            return result;
        };
        d.retention_days_fn = [this] { return retention; };
        d.now_fn = [] { return kNow; };
        return d;
    }
    void wire() { access_audit::register_access_audit_routes(sink, deps()); }
    std::unique_ptr<httplib::Response> get(const std::string& path) { return sink.dispatch("GET", path); }
};

} // namespace

TEST_CASE("audit routes: registration fails fast when any dependency is unbound",
          "[access-audit][routes]") {
    using Member = std::function<void(access_audit::Deps&)>;
    const std::vector<Member> unbind = {
        [](access_audit::Deps& d) { d.auth_fn = nullptr; },
        [](access_audit::Deps& d) { d.perm_fn = nullptr; },
        [](access_audit::Deps& d) { d.audit_fn = nullptr; },
        [](access_audit::Deps& d) { d.query_fn = nullptr; },
        [](access_audit::Deps& d) { d.retention_days_fn = nullptr; },
        [](access_audit::Deps& d) { d.now_fn = nullptr; },
    };
    for (const auto& f : unbind) {
        Harness h;
        auto d = h.deps();
        f(d);
        CHECK_THROWS_AS(access_audit::register_access_audit_routes(h.sink, d), std::invalid_argument);
    }
}

TEST_CASE("audit routes: the page redirects without a session and makes no gate or store call",
          "[access-audit][routes]") {
    Harness h;
    h.wire();
    h.session_present = false;
    auto res = h.get("/access/audit");
    REQUIRE(res);
    CHECK(res->status == 302);
    CHECK(res->get_header_value("Location") == "/login");

    h.session_present = true;
    res = h.get("/access/audit");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK(res->get_header_value("Cache-Control") == "no-store");
    CHECK(res->body == kAccessAuditHtml);
    CHECK(h.gate_calls.empty());
    CHECK(h.query_calls == 0);
}

TEST_CASE("audit routes: a denied caller gets the gate's exact response and costs no read",
          "[access-audit][routes]") {
    Harness h;
    h.wire();
    h.allow = false;
    for (const char* path :
         {"/fragments/access/audit/log", "/fragments/access/audit/sample",
          "/fragments/access/audit/retention"}) {
        INFO(path);
        const auto res = h.get(path);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body == kDenyBody);
        CHECK(res->get_header_value("Cache-Control").empty());
    }
    CHECK(h.query_calls == 0);
    CHECK(h.audits.empty());
}

TEST_CASE("audit routes: each fragment is gated on exactly its twin's securable",
          "[access-audit][routes]") {
    Harness h;
    h.wire();
    (void)h.get("/fragments/access/audit/log");
    (void)h.get("/fragments/access/audit/sample");
    (void)h.get("/fragments/access/audit/retention");
    using P = std::pair<std::string, std::string>;
    CHECK(h.gate_calls == std::vector<P>{{"AuditLog", "Read"}, {"AuditLog", "Read"},
                                         {"ServerConfig", "Read"}});
}

TEST_CASE("audit log: default request reads the last 24 hours, 51 rows, nothing else widened",
          "[access-audit][routes]") {
    Harness h;
    h.wire();
    const auto res = h.get("/fragments/access/audit/log");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK(res->get_header_value("Cache-Control") == "no-store");
    REQUIRE(h.query_calls == 1);
    const auto& q = h.last_query;
    CHECK(q.principal.empty());
    CHECK(q.action.empty());
    CHECK(q.target_type.empty());
    CHECK(q.target_id.empty());
    CHECK(q.action_prefixes.empty());
    CHECK_FALSE(q.random_sample);
    CHECK(q.since == kNow - 86400);
    CHECK(q.until == 0);
    CHECK(q.limit == 51);
    CHECK(q.offset == 0);
    CHECK(h.last_pool_ptr == nullptr);
    // The log read writes no audit row, exactly like GET /api/v1/audit.
    CHECK(h.audits.empty());
}

TEST_CASE("audit log: the range selects the window and a junk range is refused unread",
          "[access-audit][routes]") {
    Harness h;
    h.wire();
    (void)h.get("/fragments/access/audit/log?range=1h");
    CHECK(h.last_query.since == kNow - 3600);
    (void)h.get("/fragments/access/audit/log?range=7d");
    CHECK(h.last_query.since == kNow - 604800);
    (void)h.get("/fragments/access/audit/log?range=24h");
    CHECK(h.last_query.since == kNow - 86400);
    CHECK(h.query_calls == 3);

    for (const char* bad : {"range=junk", "range=", "range=30d", "range=1H"}) {
        INFO(bad);
        const auto res = h.get(std::string("/fragments/access/audit/log?") + bad);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring(std::string(access_audit::kBadRange)));
    }
    CHECK(h.query_calls == 3);
}

TEST_CASE("audit log: limit from the client is ignored, the store always sees 51",
          "[access-audit][routes]") {
    Harness h;
    h.wire();
    for (const char* l : {"5", "1", "100000", "-3", "abc"}) {
        (void)h.get(std::string("/fragments/access/audit/log?limit=") + l);
        INFO(l);
        CHECK(h.last_query.limit == 51);
    }
}

TEST_CASE("audit log: offset is validated to 0..10000 and refused, never clamped",
          "[access-audit][routes]") {
    Harness h;
    h.wire();
    for (const auto& [raw, want] : std::vector<std::pair<std::string, int>>{
             {"0", 0}, {"50", 50}, {"10000", 10000}, {"007", 7}}) {
        INFO(raw);
        const auto before = h.query_calls;
        (void)h.get("/fragments/access/audit/log?offset=" + raw);
        CHECK(h.query_calls == before + 1);
        CHECK(h.last_query.offset == want);
    }
    // Empty means the first page.
    (void)h.get("/fragments/access/audit/log?offset=");
    CHECK(h.last_query.offset == 0);

    const int reads = h.query_calls;
    for (const char* bad : {"10001", "99999999", "-5", "abc", "12abc", " 5", "+5", "1e3",
                            "99999999999999999999999999"}) {
        INFO(bad);
        const auto res = h.get(std::string("/fragments/access/audit/log?offset=") + bad);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring(std::string(access_audit::kBadOffset)));
        CHECK_THAT(res->body, !ContainsSubstring("<table"));
    }
    CHECK(h.query_calls == reads);
}

TEST_CASE("audit log: a NUL byte in a filter is refused unread", "[access-audit][routes]") {
    Harness h;
    h.wire();
    for (const char* p : {"principal=a%00b", "action=a%00b"}) {
        INFO(p);
        const auto res = h.get(std::string("/fragments/access/audit/log?") + p);
        REQUIRE(res);
        CHECK_THAT(res->body, ContainsSubstring(std::string(access_audit::kBadText)));
    }
    CHECK(h.query_calls == 0);
}

TEST_CASE("audit log: principal and action pass through verbatim and come back percent-encoded",
          "[access-audit][routes]") {
    Harness h;
    h.result = rows(51);
    h.wire();
    const auto res = h.get(
        "/fragments/access/audit/log?principal=oidc%3Ahttps%3A%2F%2Fx%2Fy%23sub&action=a%26b%3Dc");
    REQUIRE(res);
    CHECK(h.last_query.principal == "oidc:https://x/y#sub");
    CHECK(h.last_query.action == "a&b=c");
    CHECK_THAT(res->body, ContainsSubstring("principal=oidc%3Ahttps%3A%2F%2Fx%2Fy%23sub"));
    CHECK_THAT(res->body, ContainsSubstring("action=a%26b%3Dc"));
}

TEST_CASE("audit log: 51 rows render 50 with an Older link, 50 do not, 0 is an empty state",
          "[access-audit][routes]") {
    Harness h;
    h.wire();
    h.result = rows(51);
    auto res = h.get("/fragments/access/audit/log");
    REQUIRE(res);
    CHECK(count_substr(res->body, "aria-controls=") == 50);  // helper below
    CHECK_THAT(res->body, ContainsSubstring("offset=50"));

    h.result = rows(50);
    res = h.get("/fragments/access/audit/log");
    CHECK_THAT(res->body, !ContainsSubstring("offset=50"));

    h.result = std::vector<AuditEvent>{};
    res = h.get("/fragments/access/audit/log");
    CHECK_THAT(res->body, ContainsSubstring("No events match"));
}

TEST_CASE("audit log: an unreadable store is a 200 red box, not an empty table",
          "[access-audit][routes]") {
    Harness h;
    h.wire();
    h.result = std::nullopt;
    const auto res = h.get("/fragments/access/audit/log");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(res->body, !ContainsSubstring("<table"));
    CHECK_THAT(res->body, !ContainsSubstring("No events match"));
    CHECK(h.audits.empty());
}

TEST_CASE("audit sample: scope, limit bounds and the one audit row", "[access-audit][routes]") {
    Harness h;
    h.wire();
    h.result = rows(3);
    h.pool = 842;
    auto res = h.get("/fragments/access/audit/sample");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store");
    REQUIRE(h.query_calls == 1);
    const auto& q = h.last_query;
    CHECK(q.action_prefixes ==
          std::vector<std::string>{"auth.", "mfa.", "session.", "engine_principal."});
    CHECK(q.random_sample);
    CHECK(q.limit == 100);
    CHECK(q.since == 0);
    CHECK(q.until == 0);
    CHECK(h.last_pool_ptr != nullptr);
    CHECK_THAT(res->body, ContainsSubstring("3 rows drawn from 842 candidates"));
    // Exactly the twin's audit tuple.
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "audit.auth_sample.exported");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].tt == "AuditLog");
    CHECK(h.audits[0].ti == "auth-sample");
    CHECK(h.audits[0].detail == "from=0 to=0 limit=100 returned=3");
    CHECK(res->get_header_value("Sec-Audit-Failed").empty());

    for (const auto& [raw, ok] : std::vector<std::pair<std::string, bool>>{
             {"1", true}, {"1000", true}, {"0", false}, {"1001", false}, {"abc", false},
             {"-1", false}, {"10x", false}, {"99999999999999999999", false}}) {
        INFO(raw);
        const int before = h.query_calls;
        res = h.get("/fragments/access/audit/sample?limit=" + raw);
        REQUIRE(res);
        CHECK(h.query_calls == before + (ok ? 1 : 0));
        if (ok)
            CHECK(h.last_query.limit == std::stoi(raw));
        else
            CHECK_THAT(res->body, ContainsSubstring(std::string(access_audit::kBadSample)));
    }
}

TEST_CASE("audit sample: a dropped or throwing audit write sets the header and says so",
          "[access-audit][routes]") {
    for (const bool throws : {false, true}) {
        INFO(throws);
        Harness h;
        h.wire();
        h.result = rows(1);
        h.audit_ok = false;
        h.audit_throws = throws;
        const auto res = h.get("/fragments/access/audit/sample");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK_THAT(res->body, ContainsSubstring("its audit record could not be written"));
    }
}

TEST_CASE("audit sample: an unreadable store is a red box and writes no audit row",
          "[access-audit][routes]") {
    Harness h;
    h.wire();
    h.result = std::nullopt;
    const auto res = h.get("/fragments/access/audit/sample");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring(std::string(access_audit::kSampleUnavailable)));
    CHECK(h.audits.empty());
}

TEST_CASE("audit retention: shows the configured days, read per call", "[access-audit][routes]") {
    Harness h;
    h.wire();
    auto res = h.get("/fragments/access/audit/retention");
    REQUIRE(res);
    CHECK(res->get_header_value("Cache-Control") == "no-store");
    CHECK_THAT(res->body, ContainsSubstring("<b>365 days</b>"));
    h.retention = 30;
    res = h.get("/fragments/access/audit/retention");
    CHECK_THAT(res->body, ContainsSubstring("<b>30 days</b>"));
    CHECK(h.query_calls == 0);
}

TEST_CASE("audit routes: the glue script is served uncached", "[access-audit][routes]") {
    Harness h;
    h.wire();
    const auto res = h.get("/static/yuzu-audit.js");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->get_header_value("Content-Type"), ContainsSubstring("application/javascript"));
    CHECK_THAT(res->get_header_value("Cache-Control"), ContainsSubstring("no-store"));
    CHECK_THAT(res->body, ContainsSubstring("toggle-row"));
}
