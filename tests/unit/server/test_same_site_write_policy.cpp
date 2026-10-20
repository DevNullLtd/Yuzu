/**
 * test_same_site_write_policy.cpp - cookie-session writes require a same-site Origin or Referer.
 *
 * Two layers:
 *   1. The pure decision (`evaluate_same_site_write`, same_site_write_policy.hpp): a truth table
 *      over method x auth_source x Origin x Referer x Host x trusted origins. Every refuse row
 *      asserts the exact reason, so a drift in the reason derivation cannot hide behind a bare
 *      `refuse == true`.
 *   2. The gate function (`detail::apply_same_site_write_gate`, same_site_write_gate.hpp) called
 *      directly on a hand-built request/response: its normal output and its exception-path
 *      contract (exactly-once counting, the audit-failure header, the status-only fallback),
 *      driven by a throwing audit sink and the test-only fault hook.
 *
 * Paths are neutral canaries; no production route is named here.
 */

#include "same_site_write_gate.hpp"
#include "same_site_write_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::SameSiteAuditPrincipal;
using yuzu::server::detail::SameSiteFaultHook;
using yuzu::server::detail::SameSiteFaultPoint;
using yuzu::server::detail::SameSitePrincipalAuditFn;

namespace {

constexpr std::string_view kHost = "yuzu.example:8080";
constexpr std::string_view kSameOrigin = "http://yuzu.example:8080";
constexpr std::string_view kForeignOrigin = "http://evil.example";

const std::vector<std::string>& trusted() {
    static const std::vector<std::string> v{"https://console.example", "bare.example"};
    return v;
}

SameSiteDecision decide(std::string_view method, std::string_view source, std::string_view origin,
                      std::string_view referer, std::string_view host = kHost,
                      const std::vector<std::string>& tr = trusted()) {
    return evaluate_same_site_write(method, source, host, origin, referer, tr);
}

void require_pass(const SameSiteDecision& d) {
    REQUIRE_FALSE(d.refuse);
    REQUIRE(d.reason.empty());
}

void require_refuse(const SameSiteDecision& d, std::string_view reason) {
    REQUIRE(d.refuse);
    REQUIRE(d.reason == reason);
}

} // namespace

// -- Layer 1: the pure decision ----------------------------------------------------------------

TEST_CASE("same-site policy: GET, HEAD and OPTIONS are never gated", "[csrf][same_site]") {
    for (std::string_view m : {"GET", "HEAD", "OPTIONS"}) {
        CAPTURE(m);
        require_pass(decide(m, "local", "", ""));
        require_pass(decide(m, "local", kForeignOrigin, ""));
    }
}

TEST_CASE("same-site policy: every other method is a write and fails closed",
          "[csrf][same_site]") {
    // Lower-case "get" and the empty method are not reads either.
    for (std::string_view m : {"POST", "PUT", "DELETE", "PATCH", "BREW", "get", "head", ""}) {
        CAPTURE(m);
        require_refuse(decide(m, "local", "", ""), kSameSiteReasonNoHeaders);
    }
}

TEST_CASE("same-site policy: token sources are not riding a cookie", "[csrf][same_site]") {
    for (std::string_view s : {"api_token", "mcp_token", "engine_token"}) {
        CAPTURE(s);
        require_pass(decide("POST", s, kForeignOrigin, ""));
        require_pass(decide("POST", s, "", ""));
        require_pass(decide("DELETE", s, "", "http://evil.example/"));
    }
}

TEST_CASE("same-site policy: cookie sources with no headers are refused", "[csrf][same_site]") {
    // The empty string is an unresolved source and is treated as a cookie session.
    for (std::string_view s : {"local", "oidc", "saml", ""}) {
        CAPTURE(s);
        require_refuse(decide("POST", s, "", ""), kSameSiteReasonNoHeaders);
    }
}

TEST_CASE("same-site policy: an unrecognised source is gated", "[csrf][same_site]") {
    // A hypothetical seventh auth_source must not silently inherit the token exemption.
    require_refuse(decide("POST", "future_source", "", ""), kSameSiteReasonNoHeaders);
    require_refuse(decide("POST", "future_source", kForeignOrigin, ""), kSameSiteReasonOriginMismatch);
    require_pass(decide("POST", "future_source", kSameOrigin, ""));
}

TEST_CASE("same-site policy: Origin decides when present", "[csrf][same_site]") {
    require_pass(decide("POST", "local", kSameOrigin, ""));
    require_refuse(decide("POST", "local", kForeignOrigin, ""), kSameSiteReasonOriginMismatch);
    // Origin wins over Referer: a same-site Referer does not rescue a foreign Origin.
    require_refuse(decide("POST", "local", kForeignOrigin, "http://yuzu.example:8080/canary"),
                   kSameSiteReasonOriginMismatch);
    // And a same-site Origin is not undone by a foreign Referer.
    require_pass(decide("POST", "local", kSameOrigin, "http://evil.example/"));
}

TEST_CASE("same-site policy: Referer decides when Origin is absent", "[csrf][same_site]") {
    require_pass(decide("POST", "local", "", "http://yuzu.example:8080/canary"));
    require_refuse(decide("POST", "local", "", "http://evil.example/"),
                   kSameSiteReasonRefererMismatch);
}

TEST_CASE("same-site policy: trusted origins", "[csrf][same_site]") {
    const std::string_view proxied_host = "yuzu-server:8080";
    // A scheme-qualified entry matches that scheme only.
    require_pass(decide("POST", "local", "https://console.example", "", proxied_host));
    require_refuse(decide("POST", "local", "http://console.example", "", proxied_host),
                   kSameSiteReasonOriginMismatch);
    // A bare host entry matches either scheme.
    require_pass(decide("POST", "local", "https://bare.example", "", proxied_host));
    require_pass(decide("POST", "local", "http://bare.example", "", proxied_host));
    // Nothing trusted: the same Origin is foreign.
    require_refuse(decide("POST", "local", "https://console.example", "", proxied_host, {}),
                   kSameSiteReasonOriginMismatch);
}

TEST_CASE("same-site policy: default ports compare equal", "[csrf][same_site]") {
    require_pass(decide("POST", "local", "https://yuzu.example:443", "", "yuzu.example"));
    require_pass(decide("POST", "local", "https://yuzu.example", "", "yuzu.example:443"));
    require_refuse(decide("POST", "local", "https://yuzu.example", "", "yuzu.example:8443"),
                   kSameSiteReasonOriginMismatch);
}

TEST_CASE("same-site policy: IPv6 literal hosts", "[csrf][same_site]") {
    require_pass(decide("POST", "local", "http://[::1]:8080", "", "[::1]:8080"));
    // Records current behaviour: a bracket-only literal has no numeric port to strip, so it is
    // left intact on both sides and compares equal.
    require_pass(decide("POST", "local", "http://[::1]", "", "[::1]"));
    require_refuse(decide("POST", "local", "http://[::1]:9090", "", "[::1]:8080"),
                   kSameSiteReasonOriginMismatch);
}

TEST_CASE("same-site policy: host comparison is byte-wise", "[csrf][same_site]") {
    // Records current behaviour for both rows; the comparison does not fold case or a
    // trailing dot.
    require_refuse(decide("POST", "local", kSameOrigin, "", "YUZU.example:8080"),
                   kSameSiteReasonOriginMismatch);
    require_refuse(decide("POST", "local", kSameOrigin, "", "yuzu.example.:8080"),
                   kSameSiteReasonOriginMismatch);
}

TEST_CASE("same-site policy: Origin null, userinfo and embedded URLs are refused",
          "[csrf][same_site]") {
    require_refuse(decide("POST", "local", "null", ""), kSameSiteReasonOriginMismatch);
    // "null" never survives normalisation into the trusted set (the predicate would match a
    // raw bare entry, so the boot-time normaliser is what keeps this refused).
    const std::vector<std::string> raw{"null", "https://console.example"};
    const auto normalised = normalise_trusted_origins(raw);
    REQUIRE(normalised == std::vector<std::string>{"https://console.example"});
    require_refuse(decide("POST", "local", "null", "", kHost, normalised),
                   kSameSiteReasonOriginMismatch);
    require_refuse(decide("POST", "local", "http://alice@yuzu.example:8080", ""),
                   kSameSiteReasonOriginMismatch);
    // The host is cut at the first '/', so a same-site URL smuggled into the query is inert.
    require_refuse(decide("POST", "local", "http://evil.example/?u=http://yuzu.example:8080", ""),
                   kSameSiteReasonOriginMismatch);
}

TEST_CASE("same-site policy: hostile header bytes are refused without throwing",
          "[csrf][same_site]") {
    const std::string huge(64 * 1024, 'a');
    const std::string ctl = std::string("http://yuzu.example:8080") + '\x01' + "x";
    SameSiteDecision d;
    REQUIRE_NOTHROW(d = decide("POST", "local", huge, ""));
    require_refuse(d, kSameSiteReasonOriginMismatch);
    REQUIRE_NOTHROW(d = decide("POST", "local", ctl, ""));
    require_refuse(d, kSameSiteReasonOriginMismatch);
    REQUIRE_NOTHROW(d = decide("POST", "local", "", "http://evil.example/\r\nX-Injected: 1"));
    require_refuse(d, kSameSiteReasonRefererMismatch);
}

TEST_CASE("same-site policy: an empty Host never matches a named origin", "[csrf][same_site]") {
    // An HTTP/1.0 client without a Host header cannot prove same-site.
    require_refuse(decide("POST", "local", kSameOrigin, "", ""), kSameSiteReasonOriginMismatch);
}

TEST_CASE("same-site policy: the auth_source enumeration is pinned", "[csrf][same_site]") {
    // The six values the session can carry. If a seventh appears, this fails deliberately.
    std::set<std::string_view> all(kTokenAuthSources.begin(), kTokenAuthSources.end());
    all.insert(kCookieAuthSources.begin(), kCookieAuthSources.end());
    const std::set<std::string_view> expected{"local",     "oidc",      "saml",
                                              "api_token", "mcp_token", "engine_token"};
    REQUIRE(all == expected);
    // Every listed token source is exempt and every listed cookie source is gated.
    for (auto s : kTokenAuthSources)
        require_pass(decide("POST", s, "", ""));
    for (auto s : kCookieAuthSources)
        require_refuse(decide("POST", s, "", ""), kSameSiteReasonNoHeaders);
}

TEST_CASE("same-site policy: the reason set is closed", "[csrf][same_site]") {
    const std::set<std::string_view> closed(kSameSiteDenyReasons.begin(),
                                            kSameSiteDenyReasons.end());
    REQUIRE(closed.size() == 4);
    REQUIRE(closed.contains("gate_error"));

    // Walk a spread of refusals: each reason is in the set, and the decision function never
    // produces the exception-path reason.
    const std::array<SameSiteDecision, 4> ds{
        decide("POST", "local", "", ""), decide("POST", "local", kForeignOrigin, ""),
        decide("POST", "local", "", "http://evil.example/"), decide("PATCH", "oidc", "null", "")};
    for (const auto& d : ds) {
        REQUIRE(d.refuse);
        REQUIRE(closed.contains(d.reason));
        REQUIRE(d.reason != kSameSiteReasonGateError);
    }
}

// -- Layer 2: the gate function ----------------------------------------------------------------

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
    SameSiteAuditPrincipal principal;
};

// One hand-built request/response pair plus the observation points the gate writes to.
struct GateRig {
    httplib::Request req;
    httplib::Response res;
    yuzu::server::auth::Session session;
    yuzu::MetricsRegistry metrics;
    std::vector<AuditRow> rows;
    SameSitePrincipalAuditFn audit;
    SameSiteFaultHook hook;
    bool use_hook{false};

    explicit GateRig(std::string method = "POST", std::string_view source = "local") {
        req.method = std::move(method);
        req.path = "/api/v1/canary";
        req.remote_addr = "192.0.2.7";
        req.set_header("Host", std::string(kHost));
        session.username = "alice";
        session.auth_source = std::string(source);
        audit = [this](const httplib::Request&, const std::string& action,
                       const std::string& result, const SameSiteAuditPrincipal& p,
                       const std::string& tt, const std::string& tid, const std::string& d) {
            rows.push_back({action, result, tt, tid, d, p});
            return true;
        };
    }

    [[nodiscard]] bool run() {
        return yuzu::server::detail::apply_same_site_write_gate(req, res, session, trusted(),
                                                                metrics, audit,
                                                                use_hook ? &hook : nullptr);
    }

    [[nodiscard]] double series(std::string_view reason) {
        return metrics
            .counter(std::string(yuzu::server::detail::kSameSiteDeniedCounter),
                     {{"path_class", "default"}, {"reason", std::string(reason)}})
            .value();
    }

    [[nodiscard]] double total() {
        double t = 0;
        for (auto r : kSameSiteDenyReasons)
            t += series(r);
        return t;
    }

    [[nodiscard]] std::size_t audit_header_count() const {
        return res.headers.count("Sec-Audit-Failed");
    }
};

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("same-site gate: the entry point is noexcept", "[csrf][same_site]") {
    static_assert(noexcept(yuzu::server::detail::apply_same_site_write_gate(
        std::declval<const httplib::Request&>(), std::declval<httplib::Response&>(),
        std::declval<const yuzu::server::auth::Session&>(),
        std::declval<std::span<const std::string>>(), std::declval<yuzu::MetricsRegistry&>(),
        std::declval<const SameSitePrincipalAuditFn&>())));
    SUCCEED();
}

TEST_CASE("same-site gate: a header-less cookie write is refused with the full output",
          "[csrf][same_site]") {
    GateRig g;
    REQUIRE(g.run());

    REQUIRE(g.res.status == 403);
    REQUIRE(contains(g.res.body, "\"code\":403"));
    REQUIRE(contains(g.res.body, "cross-site request refused"));
    REQUIRE(contains(g.res.body, "\"remediation\""));
    REQUIRE_FALSE(contains(g.res.body, "\"permission\""));
    REQUIRE(g.res.has_header("X-Correlation-Id"));
    REQUIRE(g.audit_header_count() == 0);

    REQUIRE(g.rows.size() == 1);
    const auto& r = g.rows[0];
    REQUIRE(r.action == "csrf.denied");
    REQUIRE(r.result == "denied");
    REQUIRE(r.target_type == "Endpoint");
    REQUIRE(r.target_id == "POST /api/v1/canary");
    REQUIRE(r.detail == "cross-site or header-less browser write refused; reason=no_origin_no_referer");
    REQUIRE(r.principal.id == "alice");
    REQUIRE(r.principal.cls == "human");
    REQUIRE_FALSE(r.principal.role.empty());

    REQUIRE(g.series(kSameSiteReasonNoHeaders) == 1.0);
    REQUIRE(g.total() == 1.0);
}

TEST_CASE("same-site gate: each refusal reason increments exactly its own series",
          "[csrf][same_site]") {
    {
        GateRig g;
        g.req.set_header("Origin", std::string(kForeignOrigin));
        REQUIRE(g.run());
        REQUIRE(g.rows.size() == 1);
        REQUIRE(g.rows[0].detail ==
                "cross-site or header-less browser write refused; reason=origin_mismatch");
        REQUIRE(g.series(kSameSiteReasonOriginMismatch) == 1.0);
        REQUIRE(g.total() == 1.0);
    }
    {
        GateRig g;
        g.req.set_header("Referer", "http://evil.example/");
        REQUIRE(g.run());
        REQUIRE(g.rows.size() == 1);
        REQUIRE(g.rows[0].detail ==
                "cross-site or header-less browser write refused; reason=referer_mismatch");
        REQUIRE(g.series(kSameSiteReasonRefererMismatch) == 1.0);
        REQUIRE(g.total() == 1.0);
    }
}

TEST_CASE("same-site gate: admitted requests leave no trace", "[csrf][same_site]") {
    SECTION("same-site Origin") {
        GateRig g;
        g.req.set_header("Origin", std::string(kSameOrigin));
        REQUIRE_FALSE(g.run());
        REQUIRE(g.res.status != 403); // untouched by the gate
        REQUIRE(g.res.body.empty());
        REQUIRE(g.rows.empty());
        REQUIRE(g.total() == 0.0);
    }
    SECTION("token source without headers") {
        GateRig g("POST", "api_token");
        REQUIRE_FALSE(g.run());
        REQUIRE(g.rows.empty());
        REQUIRE(g.total() == 0.0);
    }
    SECTION("read method without headers") {
        GateRig g("GET");
        REQUIRE_FALSE(g.run());
        REQUIRE(g.rows.empty());
        REQUIRE(g.total() == 0.0);
    }
}

TEST_CASE("same-site gate: an empty audit sink is audit-off, not an audit failure",
          "[csrf][same_site]") {
    GateRig g;
    g.audit = nullptr;
    REQUIRE(g.run());
    REQUIRE(g.res.status == 403);
    REQUIRE(g.audit_header_count() == 0);
    REQUIRE(g.series(kSameSiteReasonNoHeaders) == 1.0);
}

TEST_CASE("same-site gate: a sink reporting failure sets the audit-failed header once",
          "[csrf][same_site]") {
    GateRig g;
    g.audit = [](const httplib::Request&, const std::string&, const std::string&,
                 const SameSiteAuditPrincipal&, const std::string&, const std::string&,
                 const std::string&) { return false; };
    REQUIRE(g.run());
    REQUIRE(g.res.status == 403);
    REQUIRE(g.audit_header_count() == 1);
    REQUIRE(g.series(kSameSiteReasonNoHeaders) == 1.0);
    REQUIRE(g.series(kSameSiteReasonGateError) == 0.0);
}

TEST_CASE("same-site gate: a throwing audit sink is a lost row, not a gate error",
          "[csrf][same_site]") {
    GateRig g;
    g.audit = [](const httplib::Request&, const std::string&, const std::string&,
                 const SameSiteAuditPrincipal&, const std::string&, const std::string&,
                 const std::string&) -> bool { throw std::runtime_error("sink down"); };
    REQUIRE_NOTHROW(g.run());
    REQUIRE(g.res.status == 403);
    REQUIRE(g.audit_header_count() == 1);
    // The audit helper converts the throw to false, so the normal series counts it.
    REQUIRE(g.series(kSameSiteReasonNoHeaders) == 1.0);
    REQUIRE(g.series(kSameSiteReasonGateError) == 0.0);
    REQUIRE(contains(g.res.body, "cross-site request refused"));
}

TEST_CASE("same-site gate: a non-std exception from the sink is contained", "[csrf][same_site]") {
    GateRig g;
    g.audit = [](const httplib::Request&, const std::string&, const std::string&,
                 const SameSiteAuditPrincipal&, const std::string&, const std::string&,
                 const std::string&) -> bool { throw 42; };
    REQUIRE_NOTHROW(g.run());
    REQUIRE(g.res.status == 403);
    REQUIRE(g.audit_header_count() == 1);
    REQUIRE(g.total() == 1.0);
}

TEST_CASE("same-site gate: a fault before the audit row counts as gate_error and marks the loss",
          "[csrf][same_site]") {
    GateRig g;
    g.use_hook = true;
    g.hook = [](SameSiteFaultPoint p) {
        if (p == SameSiteFaultPoint::kBeforeAudit)
            throw std::runtime_error("injected");
    };
    REQUIRE_NOTHROW(g.run());
    REQUIRE(g.res.status == 403);
    // The row was never attempted, so the evidence is missing: header present exactly once.
    REQUIRE(g.audit_header_count() == 1);
    REQUIRE(g.rows.empty());
    REQUIRE(g.series(kSameSiteReasonGateError) == 1.0);
    // The normal series was never reached, so it must not also count this request.
    REQUIRE(g.series(kSameSiteReasonNoHeaders) == 0.0);
    REQUIRE(g.total() == 1.0);
    REQUIRE(contains(g.res.body, "cross-site request refused"));
}

TEST_CASE("same-site gate: a fault after the counter does not double count", "[csrf][same_site]") {
    GateRig g;
    g.use_hook = true;
    g.hook = [](SameSiteFaultPoint p) {
        if (p == SameSiteFaultPoint::kAfterCount)
            throw std::runtime_error("injected");
    };
    REQUIRE_NOTHROW(g.run());
    REQUIRE(g.res.status == 403);
    REQUIRE(g.rows.size() == 1);
    // The row was persisted, so no audit-failed header.
    REQUIRE(g.audit_header_count() == 0);
    REQUIRE(g.series(kSameSiteReasonNoHeaders) == 1.0);
    REQUIRE(g.series(kSameSiteReasonGateError) == 0.0);
    REQUIRE(g.total() == 1.0);
    // Either the full A4 body or the constant fallback is acceptable; both name the refusal.
    REQUIRE(contains(g.res.body, "cross-site request refused"));
}

TEST_CASE("same-site gate: a persistent render fault leaves a refusal, counted once",
          "[csrf][same_site]") {
    GateRig g;
    g.use_hook = true;
    g.hook = [](SameSiteFaultPoint p) {
        if (p == SameSiteFaultPoint::kInRender)
            throw std::runtime_error("injected");
    };
    REQUIRE_NOTHROW(g.run());
    REQUIRE(g.res.status == 403);
    REQUIRE(g.rows.size() == 1);
    REQUIRE(g.audit_header_count() == 0);
    REQUIRE(g.series(kSameSiteReasonNoHeaders) == 1.0);
    REQUIRE(g.series(kSameSiteReasonGateError) == 0.0);
    REQUIRE(g.total() == 1.0);
    // The A4 render failed both times, so the body is the constant fallback (an empty body
    // would also honour the contract; the constant one is what this build produces).
    REQUIRE((g.res.body.empty() || contains(g.res.body, "cross-site request refused")));
    REQUIRE_FALSE(contains(g.res.body, "\"remediation\""));
}

TEST_CASE("same-site gate: a transient render fault is recovered by the second attempt",
          "[csrf][same_site]") {
    GateRig g;
    g.use_hook = true;
    std::atomic<int> renders{0};
    g.hook = [&renders](SameSiteFaultPoint p) {
        if (p == SameSiteFaultPoint::kInRender && renders.fetch_add(1) == 0)
            throw std::runtime_error("injected once");
    };
    REQUIRE_NOTHROW(g.run());
    REQUIRE(renders.load() == 2);
    REQUIRE(g.res.status == 403);
    REQUIRE(contains(g.res.body, "\"remediation\""));
    REQUIRE(g.series(kSameSiteReasonNoHeaders) == 1.0);
    REQUIRE(g.total() == 1.0);
}

TEST_CASE("same-site gate: faults on an admitted request are never reached", "[csrf][same_site]") {
    GateRig g;
    g.req.set_header("Origin", std::string(kSameOrigin));
    g.use_hook = true;
    g.hook = [](SameSiteFaultPoint) { throw std::runtime_error("must not fire"); };
    REQUIRE_FALSE(g.run());
    REQUIRE(g.res.status != 403); // untouched by the gate
    REQUIRE(g.total() == 0.0);
}

TEST_CASE("same-site gate: hostile header bytes never reach the audit row or the warning",
          "[csrf][same_site]") {
    GateRig g;
    g.req.set_header("Origin", "http://evil.example/\x01-marker-in-origin");
    g.req.path = "/api/v1/canary\x02-marker-in-path";
    REQUIRE(g.run());
    REQUIRE(g.rows.size() == 1);
    // The detail is fixed text plus the closed-set reason token and carries no header bytes;
    // the target has control bytes neutralised.
    // httplib may drop a header value carrying a control byte, so the reason is whichever the
    // decision derived; the token is always from the closed set.
    REQUIRE(g.rows[0].detail.starts_with("cross-site or header-less browser write refused; reason="));
    REQUIRE_FALSE(contains(g.rows[0].detail, "marker-in-origin"));
    REQUIRE_FALSE(contains(g.rows[0].target_id, "\x02"));
    REQUIRE(g.res.status == 403);
}

TEST_CASE("same-site gate: a read method returns before any work", "[csrf][same_site]") {
    // The method check is the first statement: no audit sink call, no counter, no fault point,
    // and the response is untouched, even for a header-less cookie session.
    for (const char* m : {"GET", "HEAD", "OPTIONS"}) {
        CAPTURE(m);
        GateRig g(m);
        int sink_calls = 0;
        g.audit = [&sink_calls](const httplib::Request&, const std::string&, const std::string&,
                                const SameSiteAuditPrincipal&, const std::string&,
                                const std::string&, const std::string&) {
            ++sink_calls;
            return true;
        };
        g.use_hook = true;
        g.hook = [](SameSiteFaultPoint) { throw std::runtime_error("must not fire"); };
        REQUIRE_FALSE(g.run());
        REQUIRE(sink_calls == 0);
        REQUIRE(g.total() == 0.0);
        REQUIRE(g.res.status != 403);
        REQUIRE(g.res.body.empty());
        REQUIRE(g.res.headers.empty());
    }
}

// -- The log throttle ---------------------------------------------------------------------------

namespace {
constexpr std::int64_t kSec = 1'000'000'000LL;
using yuzu::server::detail::SameSiteLogThrottle;
using yuzu::server::detail::same_site_log_slot;
} // namespace

TEST_CASE("same-site log throttle: the first call on a slot logs, a second within 60 s does not",
          "[csrf][same_site]") {
    SameSiteLogThrottle t;
    const auto s = same_site_log_slot(kSameSiteReasonNoHeaders);
    REQUIRE(t.allow(s, 5 * kSec)); // an early steady_clock value still logs the first time
    REQUIRE_FALSE(t.allow(s, 5 * kSec));
    REQUIRE_FALSE(t.allow(s, 64 * kSec));
    REQUIRE_FALSE(t.allow(s, 65 * kSec - 1));
    REQUIRE(t.allow(s, 65 * kSec)); // exactly 60 s after the last logged one
    REQUIRE_FALSE(t.allow(s, 66 * kSec));
}

TEST_CASE("same-site log throttle: each reason has its own slot", "[csrf][same_site]") {
    SameSiteLogThrottle t;
    std::set<std::size_t> slots;
    for (auto r : kSameSiteDenyReasons)
        slots.insert(same_site_log_slot(r));
    REQUIRE(slots.size() == kSameSiteDenyReasons.size());
    // An unknown reason folds into the gate_error slot, never a refusal slot.
    REQUIRE(same_site_log_slot("future_reason") == same_site_log_slot(kSameSiteReasonGateError));

    REQUIRE(t.allow(same_site_log_slot(kSameSiteReasonNoHeaders), 100 * kSec));
    // A flood of one reason does not suppress the first log of another.
    REQUIRE_FALSE(t.allow(same_site_log_slot(kSameSiteReasonNoHeaders), 101 * kSec));
    REQUIRE(t.allow(same_site_log_slot(kSameSiteReasonOriginMismatch), 101 * kSec));
    REQUIRE(t.allow(same_site_log_slot(kSameSiteReasonRefererMismatch), 101 * kSec));
    REQUIRE(t.allow(same_site_log_slot(kSameSiteReasonGateError), 101 * kSec));
    REQUIRE_FALSE(t.allow(same_site_log_slot(kSameSiteReasonGateError), 102 * kSec));
}

TEST_CASE("same-site log throttle: a backwards or out-of-range input is harmless",
          "[csrf][same_site]") {
    SameSiteLogThrottle t;
    REQUIRE(t.allow(0, 1000 * kSec));
    REQUIRE_FALSE(t.allow(0, 10 * kSec)); // clock behind the last log: suppressed, not logged
    // An out-of-range slot folds into the last slot instead of indexing out of bounds.
    REQUIRE(t.allow(99, 1000 * kSec));
    REQUIRE_FALSE(t.allow(SameSiteLogThrottle::kSlots - 1, 1001 * kSec));
    static_assert(noexcept(t.allow(0, 0)));
}
