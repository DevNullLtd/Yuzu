/**
 * test_principal_quota_denial.cpp — PR 4.4 (ADR-1005 class engine
 * principals) the governance-mandated classifier-completeness lock (#2291)
 * for `server/core/src/principal_quota_denial.hpp`.
 *
 * For EVERY rejected QuotaDecision variant — limit in {kConcurrency, kRate}
 * x side in {kEngine, kOperator} (4 combinations) — this file asserts that
 * `classify_quota_denial` is the single source of truth and that BOTH
 * transport render adapters (`render_quota_denial_rest`,
 * `render_quota_denial_mcp`) derive every shared wire fact (HTTP status,
 * Retry-After, retry_after_ms, message, remediation) from that SAME
 * QuotaDenial — differing ONLY in envelope shape (A4 JSON vs JSON-RPC
 * id:null). A future edit that lets REST and MCP disagree on any shared
 * fact fails the "THE LOCK" assertions below even if each transport's own
 * shape checks still individually pass.
 *
 * Pure functions/types — no PostgreSQL required.
 */

#include "principal_quota.hpp"
#include "principal_quota_denial.hpp"
#include "principal_quota_gate.hpp" // apply_engine_quota_gate + is_streaming_path — see the
                                    // streaming+MCP body-shape TEST_CASE below

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>

using nlohmann::json;
using yuzu::MetricsRegistry;
using yuzu::server::PrincipalQuota;
using yuzu::server::PrincipalQuotaConfig;
using yuzu::server::QuotaDecision;
using yuzu::server::QuotaLimit;
using yuzu::server::QuotaSide;
using yuzu::server::detail::apply_engine_quota_gate;
using yuzu::server::detail::classify_quota_denial;
using yuzu::server::detail::is_streaming_path;
using yuzu::server::detail::render_quota_denial_mcp;
using yuzu::server::detail::render_quota_denial_rest;

namespace {

QuotaDecision make_rejected(QuotaLimit limit, QuotaSide side, std::int64_t retry_after_ms) {
    QuotaDecision d;
    d.admitted = false;
    d.limit = limit;
    d.side = side;
    d.retry_after_ms = retry_after_ms;
    return d;
}

struct Combo {
    QuotaLimit limit;
    QuotaSide side;
    const char* expect_limit;
    const char* expect_side;
};

constexpr Combo kCombos[] = {
    {QuotaLimit::kConcurrency, QuotaSide::kEngine, "concurrency", "engine"},
    {QuotaLimit::kConcurrency, QuotaSide::kOperator, "concurrency", "operator"},
    {QuotaLimit::kRate, QuotaSide::kEngine, "rate", "engine"},
    {QuotaLimit::kRate, QuotaSide::kOperator, "rate", "operator"},
};

} // namespace

TEST_CASE("classify_quota_denial + dual-transport render: completeness lock across all "
          "4 (limit,side) combinations",
          "[quota][classifier]") {
    for (const auto& c : kCombos) {
        INFO("limit=" << c.expect_limit << " side=" << c.expect_side);
        constexpr std::int64_t kRetryAfterMs = 4321;
        auto decision = make_rejected(c.limit, c.side, kRetryAfterMs);

        // ---- classify_quota_denial: the single source of truth ----
        auto q = classify_quota_denial(decision);
        CHECK(q.http_status == 429);
        CHECK(q.retry_after_ms == kRetryAfterMs); // fact-preserving, not recomputed
        CHECK(std::string(q.side) == c.expect_side);
        CHECK(std::string(q.limit) == c.expect_limit);
        CHECK_FALSE(q.message.empty());
        CHECK_FALSE(q.remediation.empty());

        // N1 / SHOULD (consistency-auditor, governance hardening round):
        // pin the EXACT message strings the docs hardcode
        // (principal_quota_denial.hpp's own file header + QuotaDenial::
        // message doc comment) so an edit to either message can't silently
        // drift from the documented text without failing a test.
        if (c.limit == QuotaLimit::kRate) {
            CHECK(q.message == "per-principal rate limit exceeded");
        } else {
            CHECK(q.message == "per-principal concurrency cap exceeded");
        }

        // ---- REST render: A4 envelope ----
        httplib::Response rest_res;
        const std::string rest_cid = "cid-rest-0001";
        render_quota_denial_rest(rest_res, q, rest_cid);
        CHECK(rest_res.status == 429);
        REQUIRE(rest_res.has_header("Retry-After"));
        CHECK(rest_res.get_header_value("X-Correlation-Id") == rest_cid);

        json rest_body = json::parse(rest_res.body);
        REQUIRE(rest_body.contains("error"));
        CHECK(rest_body["error"]["code"] == 429);
        CHECK(rest_body["error"]["message"] == q.message);
        CHECK(rest_body["error"]["correlation_id"] == rest_cid);
        CHECK(rest_body["error"]["retry_after_ms"] == kRetryAfterMs);
        CHECK(rest_body["error"]["remediation"] == q.remediation);
        REQUIRE(rest_body.contains("meta"));
        CHECK(rest_body["meta"]["api_version"] == "v1");

        // ---- MCP render: JSON-RPC 2.0, id:null ----
        httplib::Response mcp_res;
        const std::string mcp_cid = "cid-mcp-0002";
        render_quota_denial_mcp(mcp_res, q, mcp_cid);
        CHECK(mcp_res.status == 429);
        REQUIRE(mcp_res.has_header("Retry-After"));

        json mcp_body = json::parse(mcp_res.body);
        CHECK(mcp_body["jsonrpc"] == "2.0");
        REQUIRE(mcp_body.contains("id"));
        CHECK(mcp_body["id"].is_null());
        CHECK(mcp_body["error"]["code"] == -32010); // mcp::kMcpSessionCap
        CHECK(mcp_body["error"]["message"] == q.message);
        REQUIRE(mcp_body["error"].contains("data"));
        CHECK(mcp_body["error"]["data"]["correlation_id"] == mcp_cid);
        CHECK(mcp_body["error"]["data"]["retry_after_ms"] == kRetryAfterMs);
        CHECK(mcp_body["error"]["data"]["remediation"] == q.remediation);

        // ---- THE LOCK: both transports derived the SAME shared facts from
        // the SAME QuotaDenial `q` — they must differ ONLY in envelope
        // shape (A4 object vs JSON-RPC error.data), never in the facts
        // themselves. A future render adapter that recomputes or overrides
        // a fact instead of reading it from `q` breaks one of these. ----
        CHECK(rest_res.status == mcp_res.status);
        CHECK(rest_res.get_header_value("Retry-After") == mcp_res.get_header_value("Retry-After"));
        CHECK(rest_body["error"]["retry_after_ms"] == mcp_body["error"]["data"]["retry_after_ms"]);
        CHECK(rest_body["error"]["message"] == mcp_body["error"]["message"]);
        CHECK(rest_body["error"]["remediation"] == mcp_body["error"]["data"]["remediation"]);
    }
}

TEST_CASE("classify_quota_denial contract: production never invokes it on an admitted decision; "
          "the kNone fallback is defensive-only",
          "[quota][classifier]") {
    // Production call sites (server.cpp's pre-routing chokepoint) always
    // guard classify_quota_denial behind `!d.admitted` / `!slot.admitted()`
    // — an admitted QuotaDecision is never fed to the classifier because
    // there is nothing to deny (see principal_quota_denial.hpp's file
    // header). This documents the deliberately-defensive fallback: calling
    // it anyway does not crash, and QuotaLimit::kNone (which should never
    // reach here on a real rejection) falls back to the "concurrency"
    // branch per the header comment in principal_quota_denial.hpp.
    QuotaDecision admitted;
    admitted.admitted = true;
    admitted.limit = QuotaLimit::kNone;
    admitted.side = QuotaSide::kEngine;

    auto q = classify_quota_denial(admitted);
    CHECK(q.http_status == 429);                      // still filled in; caller's job not to render this
    CHECK(std::string(q.limit) == "concurrency");      // documented defensive default for kNone
    CHECK(std::string(q.side) == "engine");
}

TEST_CASE("gate + classifier: a rejected GET /mcp/v1/ request (the streaming SSE path) still "
          "renders the JSON-RPC id:null -32010 shape — NEVER the REST A4 body — proving streaming "
          "does not special-case the mcp-vs-rest transport pick (the earlier review-flagged gap: "
          "the old streaming test asserted status-code-only, never the body shape, on the mcp "
          "path)",
          "[quota][classifier][gate]") {
    // Rate-only bucket (burst=1) so the SECOND call is guaranteed to reject
    // on the rate dimension deterministically, regardless of UP-1's
    // concurrency reservation on the first call.
    PrincipalQuotaConfig cfg{.max_concurrency = 1000, .rate_per_second = 1.0, .burst = 1.0};
    PrincipalQuota q(cfg);
    MetricsRegistry reg;

    httplib::Request req;
    req.method = "GET"; // GET /mcp/v1/ is the streaming allowlist entry (is_streaming_path)
    req.path = "/mcp/v1/";
    REQUIRE(is_streaming_path(req));

    // First call: admits (post-UP-1 this also reserves a real concurrency
    // slot) — release it immediately so this test isolates the rate
    // dimension, matching the primitive's own rate-isolation tests.
    httplib::Response res1;
    bool rejected1 = true;
    auto slot1 = apply_engine_quota_gate("engine", "engine_token", "engine:mcp-stream", req, res1,
                                         q, reg, rejected1);
    REQUIRE_FALSE(rejected1);
    REQUIRE(slot1.has_value());
    slot1.reset();

    // Second call: bucket exhausted -> rejected. Streaming does not change
    // the mcp-vs-rest render pick inside the gate — it's still the plain
    // `/mcp/` path-prefix check.
    httplib::Response res2;
    bool rejected2 = false;
    auto slot2 = apply_engine_quota_gate("engine", "engine_token", "engine:mcp-stream", req, res2,
                                         q, reg, rejected2);
    CHECK(rejected2);
    CHECK_FALSE(slot2.has_value());
    CHECK(res2.status == 429);

    json body = json::parse(res2.body);
    CHECK(body["jsonrpc"] == "2.0");
    REQUIRE(body.contains("id"));
    CHECK(body["id"].is_null());
    CHECK(body["error"]["code"] == -32010); // mcp::kMcpSessionCap
    CHECK(body["error"]["message"] == "per-principal rate limit exceeded");
    REQUIRE(body["error"].contains("data"));
    CHECK_FALSE(body["error"]["data"]["correlation_id"].get<std::string>().empty());

    // Never the REST A4 shape (no top-level "meta"/"error.correlation_id" —
    // those are the A4 envelope's field names, not JSON-RPC's).
    CHECK_FALSE(body.contains("meta"));
    CHECK_FALSE(body["error"].contains("correlation_id"));
}
