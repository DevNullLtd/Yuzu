/**
 * test_principal_quota_chokepoint.cpp — PR 4.4 (ADR-1005 class engine
 * principals, per-principal quota cap) integration-adjacent coverage for
 * the pre-routing/post-routing chokepoint wired in `server.cpp`'s
 * `ServerImpl` (the `if (session->principal_kind == "engine") { ... }`
 * block around server.cpp:5561-5606, and the `detail::tls_quota_slot().reset()`
 * release at the post-routing handler around server.cpp:5637).
 *
 * SCOPE / HONEST GAP NOTE — read before extending this file:
 *
 *   The actual GATE DECISION — engine-only guard (now the S1 TWO-PREDICATE
 *   check: principal_kind=="engine" OR auth_source=="engine_token"),
 *   classify -> metric -> mcp-vs-rest render pick — is now extracted into
 *   `principal_quota_gate.hpp`'s `apply_engine_quota_gate` +
 *   `is_streaming_path`, a pure(ish), header-exported free function server.cpp's
 *   pre-routing lambda calls thinly. The `[quota][gate]` TEST_CASEs below
 *   drive THAT function directly with plain `string_view`s for
 *   principal_kind/auth_source/principal_id (no `auth::Session` needed) and
 *   real `httplib::Request`/`Response`/`PrincipalQuota`/`MetricsRegistry`
 *   objects — this is the real security decision, not a stand-in for it.
 *   Every branch of `apply_engine_quota_gate` is exercised: the non-engine
 *   early return, non-streaming admit, non-streaming concurrency reject
 *   (REST and MCP transports), streaming admit (UP-1 FIX: a streaming
 *   request now DOES take a concurrency slot, exactly like non-streaming —
 *   the old "streaming never gets a slot" assertion was wrong-by-design and
 *   is replaced below), streaming rate reject, and the
 *   `yuzu_server_principal_quota_admits_total{side}` counter.
 *
 *   `[quota][gate][stream]` additionally covers
 *   `detail::adopt_quota_slot_into_stream` — the UP-1 handoff that moves the
 *   pending slot out of `detail::tls_quota_slot()` into a streaming route's
 *   resource-releaser so the reservation survives for the stream's actual
 *   lifetime (not just until post-routing). Includes a cross-thread release
 *   case (the pre-routing thread stashes; a DIFFERENT thread — modelling the
 *   stream's own thread — invokes the returned releaser).
 *
 *   `--principal-max-concurrency 0` / `--principal-rate-limit -1` failing
 *   CLI11's `PositiveNumber` check at parse (main.cpp) is NOT covered here —
 *   there is no CLI-parse test harness in tests/unit/server for main.cpp's
 *   `CLI::App`, and fabricating one is out of this file's scope. That
 *   validation is boot-tested only.
 *
 *   The earlier `[quota][chokepoint]` TEST_CASEs above (still present,
 *   unmodified) predate that extraction and instead drive the underlying
 *   `PrincipalQuota` + `classify_quota_denial` + `render_quota_denial_*`
 *   primitives directly with the same wiring constants/call sequence the
 *   gate uses — kept as-is since they still add value (e.g. real
 *   multi-threaded slot-release coverage) and are not superseded.
 *
 *   What is STILL NOT exercised here (the residual, narrower gap): real
 *   HTTP session resolution/cookie/bearer-token auth (server.cpp resolves
 *   `session->principal_kind`/`session->username` before calling the gate —
 *   covered by `test_engine_principal_integration.cpp`'s session-synthesis
 *   tests, not this file), and httplib's own request
 *   dispatch/thread-affinity for `tls_quota_slot()` — the caller-owned
 *   thread_local stash/release around the gate's returned `optional<QuotaSlot>`
 *   stays in server.cpp by design (see principal_quota_gate.hpp's file
 *   header: "those stay in server.cpp because they are wiring, not the
 *   security decision"). That thread-affinity wiring is a plain
 *   stash-on-admit / reset-on-post-routing pattern with no decision logic of
 *   its own; the slot's own RAII release semantics (what actually matters
 *   for correctness — a leaked slot would self-throttle a healthy
 *   principal) ARE covered, both via `QuotaSlot::reset()`/dtor in the
 *   primitive tests (test_principal_quota.cpp) and via the gate's admit
 *   case below (case 2) which resets the slot it returns.
 *   `test_on_behalf_guard.cpp` remains the sibling ADR-1005 example of this
 *   same "test the exported pure/production function directly" approach for
 *   its own pre-routing guard.
 *
 * PG env: not required by this file (PrincipalQuota is pure in-memory), but
 * the surrounding test binary is built PG-enabled per the task's build env.
 */

#include "principal_quota_gate.hpp" // transitively: principal_quota.hpp, principal_quota_denial.hpp

#include <catch2/catch_test_macros.hpp>

#include "rest_audit.hpp"
#include "mcp_stream.hpp"
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <cstdint>
#include <latch>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using nlohmann::json;
using yuzu::MetricsRegistry;
using yuzu::server::PrincipalQuota;
using yuzu::server::PrincipalQuotaConfig;
using yuzu::server::QuotaDecision;
using yuzu::server::QuotaLimit;
using yuzu::server::QuotaSide;
using yuzu::server::QuotaSlot;
using yuzu::server::detail::apply_engine_quota_gate;
using yuzu::server::detail::classify_quota_denial;
using yuzu::server::detail::is_streaming_path;
using yuzu::server::detail::render_quota_denial_mcp;
using yuzu::server::detail::render_quota_denial_rest;

namespace {

// Mirrors server.cpp's ServerImpl constructor wiring (server.cpp:354-356):
// PrincipalQuota principal_quota_(PrincipalQuotaConfig{
//     .max_concurrency = cfg_.principal_max_concurrency,
//     .rate_per_second = cfg_.principal_rate_limit,
//     .burst = 2.0 * cfg_.principal_rate_limit});
// Values below mirror Config's own defaults (server.hpp:228-229:
// principal_max_concurrency{16}, principal_rate_limit{20.0}).
PrincipalQuotaConfig production_shaped_config() {
    return PrincipalQuotaConfig{
        .max_concurrency = 16, .rate_per_second = 20.0, .burst = 2.0 * 20.0};
}

// Pre-seeds the exact 4 (side x limit) series server.cpp's ServerImpl
// constructor pre-seeds to 0 (server.cpp:429-434), so absent() alerts stay
// meaningful — see docs/observability-conventions.md.
void preseed_quota_metric(MetricsRegistry& reg) {
    reg.describe("yuzu_server_principal_quota_exhausted_total",
                 "Per-principal quota-cap exhaustions by side and limit dimension", "counter");
    for (auto side : {"engine", "operator"}) {
        for (auto limit : {"concurrency", "rate"}) {
            reg.counter("yuzu_server_principal_quota_exhausted_total",
                        {{"side", side}, {"limit", limit}});
        }
    }
}

// The exact metric-increment call server.cpp makes at each of the two
// reject sites (server.cpp:5577-5579, 5591-5593).
void record_quota_exhaustion(MetricsRegistry& reg,
                             const yuzu::server::detail::QuotaDenial& q) {
    reg.counter("yuzu_server_principal_quota_exhausted_total", {{"side", q.side}, {"limit", q.limit}})
        .increment();
}

// Mirrors server.cpp's ServerImpl constructor pre-seed of the admits
// companion counter (server.cpp:411-416) — side in {engine, operator}, both
// pre-seeded to 0 even though "operator" is dormant until Phase 5.
void preseed_admits_metric(MetricsRegistry& reg) {
    reg.describe("yuzu_server_principal_quota_admits_total",
                 "Per-principal quota-cap admits (successful try_acquire) by side", "counter");
    for (auto side : {"engine", "operator"}) {
        reg.counter("yuzu_server_principal_quota_admits_total", {{"side", side}});
    }
}

double metric_value(MetricsRegistry& reg, const std::string& name, const yuzu::Labels& labels) {
    return reg.counter(name, labels).value();
}

} // namespace

// ── Per-principal, not per-IP + engine-only (#1973) ─────────────────────────

TEST_CASE("Chokepoint wiring: an engine principal's concurrency overflow is per-principal — a "
          "distinct engine principal (standing in for a same-source-IP human/other session) is "
          "unaffected",
          "[quota][chokepoint]") {
    auto cfg = production_shaped_config();
    cfg.max_concurrency = 4; // small, deterministic cap for this test
    PrincipalQuota q(cfg);

    // "engine:acme" issues max_concurrency+1 concurrent non-streaming
    // requests — exactly the try_acquire() call the chokepoint makes on the
    // non-streaming branch (server.cpp:5588).
    std::vector<QuotaSlot> slots;
    for (int i = 0; i < cfg.max_concurrency; ++i) {
        auto slot = q.try_acquire("engine:acme", QuotaSide::kEngine);
        REQUIRE(slot.admitted());
        slots.push_back(std::move(slot));
    }
    auto overflow = q.try_acquire("engine:acme", QuotaSide::kEngine);
    CHECK_FALSE(overflow.admitted());
    CHECK(overflow.decision().limit == QuotaLimit::kConcurrency);

    // A distinct principal identity — what a per-IP limiter would have
    // conflated with "engine:acme" if they shared a source IP, but
    // PrincipalQuota keys strictly by principal id — must be completely
    // unaffected, admitting its own full cap.
    //
    // NOTE (the acknowledged gap, see file header): in production this
    // "unaffected" party is usually a HUMAN session that the chokepoint's
    // `if (session->principal_kind == "engine")` guard never even submits
    // to PrincipalQuota at all — a stronger guarantee than "admits its own
    // cap" that this test cannot exercise without a live ServerImpl. What
    // IS exercised here is PrincipalQuota's own per-principal-id keying,
    // which is the mechanism the #1973 fix relies on.
    std::vector<QuotaSlot> other_slots;
    for (int i = 0; i < cfg.max_concurrency; ++i) {
        auto other = q.try_acquire("engine:other", QuotaSide::kEngine);
        CHECK(other.admitted());
        other_slots.push_back(std::move(other)); // hold — a temporary would release immediately
    }
    CHECK(q.in_flight("engine:acme") == cfg.max_concurrency);
    CHECK(q.in_flight("engine:other") == cfg.max_concurrency);
}

// ── Metric: exact +1 per reject, all 4 series pre-seeded to 0 ──────────────

TEST_CASE("Chokepoint wiring: yuzu_server_principal_quota_exhausted_total is pre-seeded (4 "
          "series, all 0) and increments by exactly 1 per rejection, labeled by (side,limit)",
          "[quota][chokepoint]") {
    MetricsRegistry reg;
    preseed_quota_metric(reg);

    const yuzu::Labels all_series[] = {
        {{"side", "engine"}, {"limit", "concurrency"}},
        {{"side", "engine"}, {"limit", "rate"}},
        {{"side", "operator"}, {"limit", "concurrency"}},
        {{"side", "operator"}, {"limit", "rate"}},
    };
    for (const auto& labels : all_series) {
        CHECK(reg.counter("yuzu_server_principal_quota_exhausted_total", labels).value() == 0.0);
    }

    // Simulate a rejected non-streaming engine request (concurrency) — the
    // exact classify -> metric sequence at server.cpp:5589-5593.
    auto cfg = production_shaped_config();
    cfg.max_concurrency = 1;
    PrincipalQuota q(cfg);
    auto held = q.try_acquire("engine:acme", QuotaSide::kEngine);
    REQUIRE(held.admitted());
    auto rejected = q.try_acquire("engine:acme", QuotaSide::kEngine);
    REQUIRE_FALSE(rejected.admitted());
    auto denial = classify_quota_denial(rejected.decision());
    record_quota_exhaustion(reg, denial);

    CHECK(reg.counter("yuzu_server_principal_quota_exhausted_total",
                       {{"side", "engine"}, {"limit", "concurrency"}})
              .value() == 1.0);
    // The other 3 series are untouched.
    CHECK(reg.counter("yuzu_server_principal_quota_exhausted_total",
                       {{"side", "engine"}, {"limit", "rate"}})
              .value() == 0.0);
    CHECK(reg.counter("yuzu_server_principal_quota_exhausted_total",
                       {{"side", "operator"}, {"limit", "concurrency"}})
              .value() == 0.0);
    CHECK(reg.counter("yuzu_server_principal_quota_exhausted_total",
                       {{"side", "operator"}, {"limit", "rate"}})
              .value() == 0.0);

    // A second, independent rejection (rate dimension this time) increments
    // only its own series by exactly 1.
    auto rate_cfg = PrincipalQuotaConfig{.max_concurrency = 1000, .rate_per_second = 1.0, .burst = 1.0};
    PrincipalQuota rate_q(rate_cfg);
    auto first = rate_q.try_rate_only("engine:acme", QuotaSide::kEngine);
    REQUIRE(first.admitted);
    auto rate_rejected = rate_q.try_rate_only("engine:acme", QuotaSide::kEngine);
    REQUIRE_FALSE(rate_rejected.admitted);
    record_quota_exhaustion(reg, classify_quota_denial(rate_rejected));

    CHECK(reg.counter("yuzu_server_principal_quota_exhausted_total",
                       {{"side", "engine"}, {"limit", "rate"}})
              .value() == 1.0);
    CHECK(reg.counter("yuzu_server_principal_quota_exhausted_total",
                       {{"side", "engine"}, {"limit", "concurrency"}})
              .value() == 1.0); // unchanged by the second, unrelated rejection
}

// ── Slot release: served requests leave in_flight at 0 ─────────────────────

TEST_CASE("Chokepoint wiring: served non-streaming requests release their slot — in_flight "
          "returns to 0 (proves the post-routing tls_quota_slot().reset() release)",
          "[quota][chokepoint]") {
    auto cfg = production_shaped_config();
    cfg.max_concurrency = 3;
    PrincipalQuota q(cfg);

    // Serial "requests": pre-routing acquires, handler runs, post-routing
    // releases — exactly the acquire-then-reset() sequence at
    // server.cpp:5588+5604 (pre-routing) and :5637 (post-routing).
    for (int i = 0; i < 10; ++i) {
        auto slot = q.try_acquire("engine:acme", QuotaSide::kEngine);
        REQUIRE(slot.admitted());
        CHECK(q.in_flight("engine:acme") == 1);
        slot.reset(); // the post-routing handler's tls_quota_slot().reset()
        CHECK(q.in_flight("engine:acme") == 0);
    }

    // Concurrent "requests" on separate worker threads (httplib dispatches
    // one worker thread per in-flight request) — each acquires, "serves",
    // and releases; after every thread joins, in_flight must be exactly 0.
    // A leaked slot here would silently self-throttle a healthy principal.
    constexpr int kThreads = 8;
    std::latch start_latch(kThreads);
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&] {
            start_latch.arrive_and_wait();
            auto slot = q.try_acquire("engine:concurrent", QuotaSide::kEngine);
            if (slot.admitted()) {
                slot.reset(); // release immediately, as post-routing does
            }
        });
    }
    for (auto& t : threads) t.join();

    CHECK(q.in_flight("engine:concurrent") == 0);
}

// ── Dual transport at the (simulated) live chokepoint ───────────────────────

namespace {

// Mirrors the trivial routing predicate at server.cpp:5565
// (`const bool is_mcp = req.path.starts_with("/mcp/");`) — a plain path
// prefix check, not quota decision logic, so replicating it here does not
// risk drifting from the enforcement gate itself.
bool looks_like_mcp_path(std::string_view path) { return path.starts_with("/mcp/"); }

} // namespace

TEST_CASE("Chokepoint wiring: dual transport render — REST path gets an A4 body, MCP path gets "
          "a JSON-RPC id:null body, from the SAME rejected decision",
          "[quota][chokepoint]") {
    auto cfg = production_shaped_config();
    cfg.max_concurrency = 1;
    PrincipalQuota q(cfg);
    auto held = q.try_acquire("engine:acme", QuotaSide::kEngine);
    REQUIRE(held.admitted());
    auto rejected = q.try_acquire("engine:acme", QuotaSide::kEngine);
    REQUIRE_FALSE(rejected.admitted());
    auto denial = classify_quota_denial(rejected.decision());

    for (std::string_view path : {"/api/v1/devices", "/mcp/v1/"}) {
        INFO("path=" << path);
        httplib::Response res;
        const std::string cid = "cid-dual-0003";
        if (looks_like_mcp_path(path)) {
            render_quota_denial_mcp(res, denial, cid);
            CHECK(res.status == 429);
            json body = json::parse(res.body);
            CHECK(body["jsonrpc"] == "2.0");
            CHECK(body["id"].is_null());
            CHECK(body["error"]["code"] == -32010);
            CHECK(body["error"]["data"]["retry_after_ms"] == denial.retry_after_ms);
        } else {
            render_quota_denial_rest(res, denial, cid);
            CHECK(res.status == 429);
            json body = json::parse(res.body);
            REQUIRE(body.contains("error"));
            CHECK(body["error"]["code"] == 429);
            CHECK(body["error"]["retry_after_ms"] == denial.retry_after_ms);
            CHECK(body["meta"]["api_version"] == "v1");
        }
    }
}

// ── Streaming exemption: never holds a concurrency slot ────────────────────

TEST_CASE("Chokepoint wiring: an engine principal repeatedly hitting a streaming path never "
          "consumes a concurrency slot (rate-only)",
          "[quota][chokepoint]") {
    auto cfg = production_shaped_config();
    cfg.rate_per_second = 1000.0; // fast refill so many polls admit
    cfg.burst = 1000.0;
    PrincipalQuota q(cfg);

    // Simulates GET /api/v1/events polls — the streaming branch at
    // server.cpp:5568-5586 calls try_rate_only(), never try_acquire(), so
    // no concurrency slot is ever reserved regardless of how many times the
    // principal hits the endpoint.
    for (int i = 0; i < 50; ++i) {
        auto d = q.try_rate_only("engine:acme", QuotaSide::kEngine);
        REQUIRE(d.admitted);
        CHECK(q.in_flight("engine:acme") == 0);
    }
    CHECK(q.in_flight("engine:acme") == 0);
    CHECK(q.principal_count() == 1); // tracked for rate purposes only
}

// ═══════════════════════════════════════════════════════════════════════════
// [quota][gate] — apply_engine_quota_gate: the real gate DECISION, driven
// directly (principal_quota_gate.hpp). Every branch below.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

// The 4 pre-seeded (side,limit) label combinations, reused across the gate
// cases below to assert "only the expected series moved".
const yuzu::Labels kAllQuotaSeries[] = {
    {{"side", "engine"}, {"limit", "concurrency"}},
    {{"side", "engine"}, {"limit", "rate"}},
    {{"side", "operator"}, {"limit", "concurrency"}},
    {{"side", "operator"}, {"limit", "rate"}},
};

double series_value(MetricsRegistry& reg, const yuzu::Labels& labels) {
    return reg.counter("yuzu_server_principal_quota_exhausted_total", labels).value();
}

} // namespace

TEST_CASE("apply_engine_quota_gate: non-engine principal_kind passes through completely "
          "untouched — never reaches the quota primitive, never renders, never increments the "
          "metric (the guard a regression here would throttle human/agent traffic)",
          "[quota][gate]") {
    for (std::string_view kind : {"human", "agent", ""}) {
        INFO("principal_kind=" << kind);
        auto cfg = production_shaped_config();
        cfg.max_concurrency = 1;
        PrincipalQuota q(cfg);
        MetricsRegistry reg;
        preseed_quota_metric(reg);
        preseed_admits_metric(reg);

        httplib::Request req;
        req.method = "GET";
        req.path = "/api/v1/devices";
        httplib::Response res;
        bool rejected = true; // must be flipped to false by the gate
        // auth_source "local" — neither predicate of S1 is set (principal_kind
        // is non-engine per the loop, auth_source is not "engine_token").
        auto slot = apply_engine_quota_gate(kind, "local", "whoever", req, res, q, reg, rejected);

        CHECK_FALSE(rejected);
        CHECK_FALSE(slot.has_value());
        CHECK(res.status == -1); // httplib::Response's default — proves res was never touched
        CHECK(q.principal_count() == 0); // the quota primitive was never even looked up

        for (const auto& labels : kAllQuotaSeries) {
            CHECK(series_value(reg, labels) == 0.0);
        }
        CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total", {{"side", "engine"}}) ==
              0.0);
    }
}

TEST_CASE("apply_engine_quota_gate: engine principal, non-streaming path, within cap -> admits, "
          "returns the slot for the caller to own, in_flight reflects it while alive and clears "
          "on release",
          "[quota][gate]") {
    auto cfg = production_shaped_config();
    cfg.max_concurrency = 4;
    PrincipalQuota q(cfg);
    MetricsRegistry reg;
    preseed_quota_metric(reg);
    preseed_admits_metric(reg);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices";
    httplib::Response res;
    bool rejected = true;
    auto slot = apply_engine_quota_gate("engine", "engine_token", "engine:x", req, res, q, reg,
                                        rejected);

    CHECK_FALSE(rejected);
    REQUIRE(slot.has_value());
    CHECK(slot->admitted());
    CHECK(q.in_flight("engine:x") == 1);
    CHECK(res.status == -1); // the gate does not touch res on admit — caller renders nothing
    // Admits companion (item 4): incremented on every admitted engine
    // request, side="engine" only.
    CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total", {{"side", "engine"}}) ==
          1.0);
    CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total", {{"side", "operator"}}) ==
          0.0);

    slot.reset(); // caller-owned release (mirrors server.cpp's tls_quota_slot().reset())
    CHECK(q.in_flight("engine:x") == 0);

    for (const auto& labels : kAllQuotaSeries) {
        CHECK(series_value(reg, labels) == 0.0); // an admit is not an exhaustion
    }
}

TEST_CASE("apply_engine_quota_gate: engine principal, non-streaming REST path, concurrency "
          "exhausted -> 429 A4 body, metric{engine,concurrency}+1, no slot returned",
          "[quota][gate]") {
    auto cfg = production_shaped_config();
    cfg.max_concurrency = 2;
    PrincipalQuota q(cfg);
    MetricsRegistry reg;
    preseed_quota_metric(reg);
    preseed_admits_metric(reg);

    // Saturate the cap directly against the primitive first (standing in for
    // max_concurrency prior in-flight requests already admitted by the gate).
    std::vector<QuotaSlot> held;
    for (int i = 0; i < cfg.max_concurrency; ++i) {
        auto s = q.try_acquire("engine:x", QuotaSide::kEngine);
        REQUIRE(s.admitted());
        held.push_back(std::move(s));
    }

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices"; // not in the streaming allowlist
    httplib::Response res;
    bool rejected = false;
    auto slot = apply_engine_quota_gate("engine", "engine_token", "engine:x", req, res, q, reg,
                                        rejected);

    CHECK(rejected);
    CHECK_FALSE(slot.has_value());
    CHECK(res.status == 429);

    json body = json::parse(res.body);
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == 429);
    CHECK(body["meta"]["api_version"] == "v1");
    REQUIRE(res.has_header("Retry-After"));

    CHECK(series_value(reg, {{"side", "engine"}, {"limit", "concurrency"}}) == 1.0);
    CHECK(series_value(reg, {{"side", "engine"}, {"limit", "rate"}}) == 0.0);
    CHECK(series_value(reg, {{"side", "operator"}, {"limit", "concurrency"}}) == 0.0);
    CHECK(series_value(reg, {{"side", "operator"}, {"limit", "rate"}}) == 0.0);
    // A rejection is never an admit.
    CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total", {{"side", "engine"}}) ==
          0.0);
}

TEST_CASE("apply_engine_quota_gate: engine principal, concurrency exhausted on an /mcp/ path -> "
          "429 JSON-RPC id:null body, error.code -32010, correct metric label — proves the "
          "mcp-vs-rest pick inside the real gate",
          "[quota][gate]") {
    auto cfg = production_shaped_config();
    cfg.max_concurrency = 1;
    PrincipalQuota q(cfg);
    MetricsRegistry reg;
    preseed_quota_metric(reg);

    auto held = q.try_acquire("engine:x", QuotaSide::kEngine);
    REQUIRE(held.admitted());

    httplib::Request req;
    // A POST /mcp/v1/ with NO SSE Accept header is a plain one-shot tool call, not a streaming
    // path (streamed POST needs `Accept: text/event-stream` — 2f PR 3b, is_streaming_path). This
    // test exercises the mcp-vs-rest 429 render pick, which does not depend on streaming-ness.
    req.method = "POST";
    req.path = "/mcp/v1/";
    httplib::Response res;
    bool rejected = false;
    auto slot =
        apply_engine_quota_gate("engine", "engine_token", "engine:x", req, res, q, reg, rejected);

    CHECK(rejected);
    CHECK_FALSE(slot.has_value());
    CHECK(res.status == 429);
    REQUIRE(res.has_header("Retry-After"));

    json body = json::parse(res.body);
    CHECK(body["jsonrpc"] == "2.0");
    REQUIRE(body.contains("id"));
    CHECK(body["id"].is_null());
    CHECK(body["error"]["code"] == -32010); // mcp::kMcpSessionCap
    REQUIRE(body["error"].contains("data"));
    // The gate mints its own correlation id lazily on the reject path (no cid
    // is passed in anymore) — assert the shape (make_correlation_id's
    // "req-<hex-ms>-<hex-seq>" format), not a caller-supplied literal.
    const std::string cid = body["error"]["data"]["correlation_id"].get<std::string>();
    CHECK_FALSE(cid.empty());
    CHECK(cid.starts_with("req-"));

    CHECK(series_value(reg, {{"side", "engine"}, {"limit", "concurrency"}}) == 1.0);
    CHECK(series_value(reg, {{"side", "engine"}, {"limit", "rate"}}) == 0.0);
}

TEST_CASE("apply_engine_quota_gate: rejection reuses an already-set X-Correlation-Id instead of "
          "minting a fresh one (the lazy-mint-or-reuse contract documented on apply_engine_quota_"
          "gate's reject path)",
          "[quota][gate]") {
    auto cfg = production_shaped_config();
    cfg.max_concurrency = 1;
    PrincipalQuota q(cfg);
    MetricsRegistry reg;
    preseed_quota_metric(reg);

    auto held = q.try_acquire("engine:x", QuotaSide::kEngine);
    REQUIRE(held.admitted());

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices";
    httplib::Response res;
    res.set_header("X-Correlation-Id", "preset-cid-0007"); // stamped by an earlier stage
    bool rejected = false;
    auto slot =
        apply_engine_quota_gate("engine", "engine_token", "engine:x", req, res, q, reg, rejected);

    CHECK(rejected);
    CHECK_FALSE(slot.has_value());
    CHECK(res.status == 429);
    CHECK(res.get_header_value("X-Correlation-Id") == "preset-cid-0007");

    json body = json::parse(res.body);
    CHECK(body["error"]["correlation_id"] == "preset-cid-0007");
}

TEST_CASE("apply_engine_quota_gate: UP-1 FIX — an engine principal on a streaming path DOES take "
          "a full concurrency slot on admit (exactly like non-streaming); a streaming-path "
          "concurrency-exhausted rejection carries limit=kConcurrency (it is no longer exempt)",
          "[quota][gate]") {
    for (std::string_view path : {"/api/v1/events", "/mcp/v1/"}) {
        INFO("streaming path=" << path);
        auto cfg = production_shaped_config();
        cfg.max_concurrency = 1; // deterministic: the very next admit on this principal rejects
        cfg.rate_per_second = 1000.0;
        cfg.burst = 1000.0; // rate is never the rejecting dimension in this case
        PrincipalQuota q(cfg);
        MetricsRegistry reg;
        preseed_quota_metric(reg);
        preseed_admits_metric(reg);

        httplib::Request req;
        req.method = "GET"; // both paths are GET-only in the streaming allowlist
        req.path = std::string(path);
        REQUIRE(is_streaming_path(req)); // sanity: this IS the streaming branch being exercised

        // First call: admitted — and, post-UP-1, a REAL concurrency slot is
        // reserved, same as a non-streaming admit would be. This is the
        // behavior change the old "streaming never gets a slot" assertion
        // got backwards (the DoS `try_rate_only` used to leave open).
        httplib::Response res1;
        bool rejected1 = true;
        auto slot1 = apply_engine_quota_gate("engine", "engine_token", "engine:x", req, res1, q,
                                             reg, rejected1);
        CHECK_FALSE(rejected1);
        REQUIRE(slot1.has_value());
        CHECK(slot1->admitted());
        CHECK(q.in_flight("engine:x") == 1); // the slot IS held — not rate-only bookkeeping
        CHECK(res1.status == -1);            // untouched on admit
        CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total",
                           {{"side", "engine"}}) == 1.0);

        // Second call, slot1 still held: concurrency (cap=1) rejects — the
        // gate never even reaches the rate dimension, exactly like a
        // non-streaming request would behave.
        httplib::Response res2;
        bool rejected2 = false;
        auto slot2 = apply_engine_quota_gate("engine", "engine_token", "engine:x", req, res2, q,
                                             reg, rejected2);
        CHECK(rejected2);
        CHECK_FALSE(slot2.has_value());
        CHECK(q.in_flight("engine:x") == 1); // unchanged — the reject leaves state untouched
        CHECK(res2.status == 429);

        CHECK(series_value(reg, {{"side", "engine"}, {"limit", "concurrency"}}) == 1.0);
        CHECK(series_value(reg, {{"side", "engine"}, {"limit", "rate"}}) == 0.0);
        // The reject did not admit — admits stays at exactly 1 (from the
        // first call only).
        CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total",
                           {{"side", "engine"}}) == 1.0);

        // This is the caller's cue (server.cpp's stream content-provider
        // registration) to move slot1 into adopt_quota_slot_into_stream —
        // covered directly in the [quota][gate][stream] section below.
        // Release here so the next loop iteration (the other path) starts
        // clean.
        slot1.reset();
        CHECK(q.in_flight("engine:x") == 0);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// [quota][gate][stream] — detail::adopt_quota_slot_into_stream: the UP-1
// handoff that moves a pending pre-routing slot into a streaming route's
// own resource-releaser so the reservation survives the stream's actual
// lifetime (server.cpp:6727, the `/events` SSE content provider).
// ═══════════════════════════════════════════════════════════════════════════

// The noexcept guarantees round 8 made STRUCTURAL rather than commentary. These are
// compile-time, deliberately: the throw they contain (std::mutex::lock failing) cannot
// be manufactured at runtime by any sanitizer or fault injector we have, so a
// static_assert is the only instrument that can hold the line. If someone removes the
// specifier, this fails to compile rather than failing in production as a terminate.
//
// Why it matters here specifically: this release path runs from ~QuotaSlot, which runs
// from an httplib content-provider releaser, which httplib invokes from ~Response. A
// destructor is implicitly noexcept, so a throw escaping it calls std::terminate BEFORE
// unwinding can reach any caller's try/catch — containment at the call site is
// impossible, and an earlier round shipped a guard that wrongly claimed otherwise.
static_assert(std::is_nothrow_destructible_v<yuzu::server::QuotaSlot>,
              "~QuotaSlot runs inside ~Response; a throwing destructor is std::terminate");
static_assert(noexcept(std::declval<yuzu::server::QuotaSlot&>().reset()),
              "QuotaSlot::reset must be noexcept — see the destructor chain above");

// The link where the ACTUAL containment lives is PrincipalQuota::release (the try/catch
// around the lock), but it is PRIVATE — only QuotaSlot may call it — so no assert can
// name it from here. QuotaSlot::reset() is the reachable public pin and is asserted
// above; it is the caller, so if release stopped being noexcept, reset() could not
// remain noexcept without swallowing, and that assert fires.

TEST_CASE("try_persist_audit_for_principal: every field lands in the slot it names",
          "[quota][audit][stream]") {
    // The static_assert on this helper checks arity and return type ONLY, so a sink whose
    // arguments were transposed would satisfy it silently. The actor is a named struct for
    // that reason, but the plumbing from struct to sink still has to be right — and it was
    // not: the first version of this path stamped principal_class from bare credential
    // presentation, so an engine principal's attach row said "engine" and its close row
    // said "agent". Nothing bound this sink, so nothing noticed.
    struct Captured {
        std::string action, result, id, role, cls, target_type, target_id, detail;
        bool called = false;
    } got;

    yuzu::server::mcp::StreamAuditPrincipal actor{
        .id = "engine:acme", .role = "admin", .cls = "engine"};

    yuzu::server::mcp::StreamPrincipalAuditFn sink =
        [&got](const httplib::Request&, const std::string& action,
                       const std::string& result,
                       const yuzu::server::mcp::StreamAuditPrincipal& p,
                       const std::string& target_type, const std::string& target_id,
                       const std::string& detail) -> bool {
        got = {action, result, p.id, p.role, p.cls, target_type, target_id, detail, true};
        return true;
    };

    httplib::Request req;
    const bool ok = yuzu::server::detail::try_persist_audit_for_principal(
        sink, req, "mcp.stream.close", "success", actor, "McpSession", "abcd1234",
        "reason=credential_revoked");

    CHECK(ok);
    REQUIRE(got.called);
    CHECK(got.action == "mcp.stream.close");
    CHECK(got.result == "success");
    CHECK(got.id == "engine:acme");
    CHECK(got.role == "admin");
    CHECK(got.cls == "engine"); // NOT "agent" — the field the mismatch showed up in
    CHECK(got.target_type == "McpSession");
    CHECK(got.target_id == "abcd1234");
    CHECK(got.detail == "reason=credential_revoked");
}

TEST_CASE("try_persist_audit_for_principal: audit-off is not a persist failure, a throw is",
          "[quota][audit][stream]") {
    // Posture must match try_persist_audit exactly: an unwired sink means audit is off
    // (serve, report success); a throwing sink is contained and reported as a failure,
    // because this runs inside a destructor where an escape is std::terminate.
    httplib::Request req;
    yuzu::server::mcp::StreamAuditPrincipal actor{.id = "alice", .role = "user", .cls = {}};

    yuzu::server::mcp::StreamPrincipalAuditFn unwired;
    CHECK(yuzu::server::detail::try_persist_audit_for_principal(
        unwired, req, "a", "success", actor, "T", "id", "d"));

    yuzu::server::mcp::StreamPrincipalAuditFn thrower =
        [](const httplib::Request&, const std::string&, const std::string&,
                      const yuzu::server::mcp::StreamAuditPrincipal&, const std::string&,
                      const std::string&, const std::string&) -> bool {
        throw std::runtime_error("audit backend exploded");
    };
    CHECK_FALSE(yuzu::server::detail::try_persist_audit_for_principal(
        thrower, req, "a", "success", actor, "T", "id", "d"));
}

TEST_CASE("Composed stream releaser: a real ~Response returns the engine QuotaSlot",
          "[quota][gate][stream][teardown]") {
    // The end-to-end shape the MCP GET channel actually installs, exercised through a
    // genuine httplib::Response destructor rather than by calling the releaser by hand.
    //
    // The gap this closes: the adopter is well covered in isolation, and the saturation
    // rig runs a live server but with NO engine principal — so tls_quota_slot() is empty
    // there and the adopted branch never executed end-to-end in any test. That left the
    // exact composition three governance rounds churned (inner noexcept lambda ->
    // adopt_quota_slot_into_stream -> outer noexcept guard) unverified as a whole.
    using yuzu::server::detail::adopt_quota_slot_into_stream;
    using yuzu::server::detail::tls_quota_slot;

    tls_quota_slot().reset(); // defensive: no carry-over from an earlier test

    yuzu::server::PrincipalQuota q{yuzu::server::PrincipalQuotaConfig{.max_concurrency = 4}};
    auto slot = q.try_acquire("engine:teardown", yuzu::server::QuotaSide::kEngine);
    REQUIRE(slot.admitted());
    REQUIRE(q.in_flight("engine:teardown") == 1);

    // Hand it to the thread_local exactly as the pre-routing chokepoint does.
    tls_quota_slot() = std::move(slot);
    REQUIRE(tls_quota_slot().has_value());

    bool inner_ran = false;
    {
        httplib::Response res;
        res.set_chunked_content_provider(
            "text/event-stream",
            [](std::size_t, httplib::DataSink& sink) {
                sink.done();
                return true;
            },
            // Byte-for-byte the composition handle_get_tail installs.
            [inner = adopt_quota_slot_into_stream(
                 [&inner_ran](bool) noexcept { inner_ran = true; })](bool ok) noexcept {
                try {
                    inner(ok);
                } catch (...) {
                }
            });
        // Adoption happens during argument evaluation, so the slot has already left
        // the thread_local — post-routing's unconditional reset is then a no-op and
        // cannot double-release.
        CHECK_FALSE(tls_quota_slot().has_value());
        CHECK(q.in_flight("engine:teardown") == 1); // still held: the stream is "open"
    } // ~Response fires the releaser

    CHECK(inner_ran);
    // THE assertion: the reservation came back. If the composition ever stops calling
    // through — a wrapper that forgets `inner`, an adopter that drops the slot — this
    // is the only thing in the suite that notices.
    CHECK(q.in_flight("engine:teardown") == 0);
    CHECK_FALSE(tls_quota_slot().has_value());
}

TEST_CASE("adopt_quota_slot_into_stream: moves the pending slot out of tls_quota_slot(), the "
          "returned releaser releases it exactly once and forwards `success` to the wrapped "
          "inner releaser — including when invoked from a DIFFERENT thread than the one that "
          "acquired it (the pre-routing-thread -> stream-thread handoff)",
          "[quota][gate][stream]") {
    using yuzu::server::detail::adopt_quota_slot_into_stream;
    using yuzu::server::detail::tls_quota_slot;

    // Defensive: this thread_local could carry state from an earlier test
    // in the same binary/thread if one forgot to release — start clean.
    tls_quota_slot().reset();

    auto cfg = production_shaped_config();
    cfg.max_concurrency = 4;
    PrincipalQuota q(cfg);
    MetricsRegistry reg;
    preseed_quota_metric(reg);
    preseed_admits_metric(reg);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/events"; // a real streaming path (doesn't change this unit's behavior)
    httplib::Response res;
    bool rejected = true;
    auto slot =
        apply_engine_quota_gate("engine", "engine_token", "engine:stream", req, res, q, reg,
                                rejected);
    REQUIRE_FALSE(rejected);
    REQUIRE(slot.has_value());
    CHECK(q.in_flight("engine:stream") == 1);

    // Mirror server.cpp's pre-routing stash exactly (server.cpp:5570).
    tls_quota_slot() = std::move(*slot);
    REQUIRE(tls_quota_slot().has_value());

    std::atomic<int> inner_calls{0};
    std::atomic<bool> inner_last_success{false};
    auto releaser = adopt_quota_slot_into_stream(
        [&](bool success) {
            ++inner_calls;
            inner_last_success = success;
        });

    // (a) tls_quota_slot() is now empty — the slot was MOVED out, not
    // copied (QuotaSlot is move-only, so this also proves no double-owner).
    CHECK_FALSE(tls_quota_slot().has_value());
    // Not yet released — the slot's lifetime now belongs to `releaser`,
    // which has not fired yet.
    CHECK(q.in_flight("engine:stream") == 1);

    // (b/cross-thread) invoke the returned releaser from a DIFFERENT
    // std::thread than the one that acquired the slot — models the real
    // pre-routing-thread -> stream-thread handoff (the release path
    // re-locks PrincipalQuota's mutex, so this is the correctness point
    // that actually matters, not just a same-thread sanity check).
    std::thread release_thread([&] { releaser(/*success=*/true); });
    release_thread.join();

    CHECK(inner_calls.load() == 1);
    CHECK(inner_last_success.load() == true);
    CHECK(q.in_flight("engine:stream") == 0); // decremented correctly across the thread boundary

    // Idempotent per the header doc comment: invoking the same releaser
    // again must not crash or double-decrement (QuotaSlot::reset() is
    // idempotent; `inner` itself is a plain lambda and IS called again —
    // the idempotency guarantee is specifically about the held slot).
    releaser(/*success=*/false);
    CHECK(inner_calls.load() == 2);
    CHECK(inner_last_success.load() == false);
    CHECK(q.in_flight("engine:stream") == 0); // still 0 — no double-release underflow
}

TEST_CASE("adopt_quota_slot_into_stream: no-op passthrough when tls_quota_slot() is empty (a "
          "non-engine request on a streaming path) — inner is still invoked, unchanged, no crash "
          "on an empty slot",
          "[quota][gate][stream]") {
    using yuzu::server::detail::adopt_quota_slot_into_stream;
    using yuzu::server::detail::tls_quota_slot;

    tls_quota_slot().reset(); // ensure a clean starting state for this thread
    REQUIRE_FALSE(tls_quota_slot().has_value());

    std::atomic<int> inner_calls{0};
    std::atomic<bool> inner_last_success{false};
    auto releaser = adopt_quota_slot_into_stream([&](bool success) {
        ++inner_calls;
        inner_last_success = success;
    });

    // Still empty — adopt is a true no-op when there was nothing to adopt.
    CHECK_FALSE(tls_quota_slot().has_value());

    releaser(/*success=*/true);
    CHECK(inner_calls.load() == 1);
    CHECK(inner_last_success.load() == true);

    // Safe to invoke from a different thread too, same as the slot-pending
    // case — the passthrough releaser carries no thread affinity.
    std::thread t([&] { releaser(/*success=*/false); });
    t.join();
    CHECK(inner_calls.load() == 2);
    CHECK(inner_last_success.load() == false);
}

TEST_CASE("apply_engine_quota_gate: a RATE (not concurrency) rejection on a non-streaming engine "
          "path labels metric{engine,rate} and the 429 body's retry_after_ms is classify's own "
          "value carried verbatim",
          "[quota][gate]") {
    PrincipalQuotaConfig cfg{.max_concurrency = 1000, .rate_per_second = 1.0, .burst = 1.0};
    PrincipalQuota q(cfg);
    MetricsRegistry reg;
    preseed_quota_metric(reg);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices"; // NOT in the streaming allowlist -> non-streaming try_acquire()

    // First call: admits (burst=1.0) and reserves a concurrency slot too —
    // release it immediately so the ceiling (1000) plays no role in the
    // second call's rejection, isolating the rate dimension.
    httplib::Response res1;
    bool rejected1 = true;
    auto slot1 = apply_engine_quota_gate("engine", "engine_token", "engine:x", req, res1, q, reg,
                                         rejected1);
    CHECK_FALSE(rejected1);
    REQUIRE(slot1.has_value());
    slot1.reset();

    // Second call: same exhausted bucket -> rate reject (concurrency is nowhere near its
    // 1000 ceiling, so this can only be the rate dimension).
    httplib::Response res2;
    bool rejected2 = false;
    auto slot2 = apply_engine_quota_gate("engine", "engine_token", "engine:x", req, res2, q, reg,
                                         rejected2);
    CHECK(rejected2);
    CHECK_FALSE(slot2.has_value());
    CHECK(res2.status == 429);

    json body = json::parse(res2.body);
    const std::int64_t body_retry_after_ms = body["error"]["retry_after_ms"].get<std::int64_t>();
    CHECK(body_retry_after_ms > 0);

    // "matches classify's": classify_quota_denial is fact-preserving (locked
    // by test_principal_quota_denial.cpp) — round-tripping the body's own
    // retry_after_ms through classify_quota_denial on an equivalent rejected
    // (limit=kRate, side=kEngine) decision must hand the SAME value straight
    // back, proving the gate's rendered body carries classify's computed
    // value verbatim rather than some other, independently-derived number.
    QuotaDecision equivalent;
    equivalent.admitted = false;
    equivalent.limit = QuotaLimit::kRate;
    equivalent.side = QuotaSide::kEngine;
    equivalent.retry_after_ms = body_retry_after_ms;
    auto reclassified = classify_quota_denial(equivalent);
    CHECK(reclassified.retry_after_ms == body_retry_after_ms);
    CHECK(std::string(reclassified.limit) == "rate");
    CHECK(std::string(reclassified.side) == "engine");

    CHECK(series_value(reg, {{"side", "engine"}, {"limit", "rate"}}) == 1.0);
    CHECK(series_value(reg, {{"side", "engine"}, {"limit", "concurrency"}}) == 0.0);
}

// ═══════════════════════════════════════════════════════════════════════════
// [quota][gate] — item 4: yuzu_server_principal_quota_admits_total{side}.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("apply_engine_quota_gate: yuzu_server_principal_quota_admits_total{side=\"engine\"} "
          "increments by exactly 1 per ADMITTED engine request (any principal); a rejected "
          "request never bumps it; both admits and exhausted series are live and pre-seeded",
          "[quota][gate]") {
    auto cfg = production_shaped_config();
    cfg.max_concurrency = 1;
    PrincipalQuota q(cfg);
    MetricsRegistry reg;
    preseed_quota_metric(reg);
    preseed_admits_metric(reg);

    for (const char* side : {"engine", "operator"}) {
        CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total", {{"side", side}}) ==
              0.0);
    }
    for (const auto& labels : kAllQuotaSeries) {
        CHECK(series_value(reg, labels) == 0.0);
    }

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices";

    // Admit #1 on "engine:x".
    httplib::Response res1;
    bool rejected1 = true;
    auto slot1 = apply_engine_quota_gate("engine", "engine_token", "engine:x", req, res1, q, reg,
                                         rejected1);
    CHECK_FALSE(rejected1);
    REQUIRE(slot1.has_value());
    CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total", {{"side", "engine"}}) ==
          1.0);

    // Reject on the same principal (cap=1, slot1 still held) — must NOT
    // bump admits.
    httplib::Response res2;
    bool rejected2 = false;
    auto slot2 = apply_engine_quota_gate("engine", "engine_token", "engine:x", req, res2, q, reg,
                                         rejected2);
    CHECK(rejected2);
    CHECK_FALSE(slot2.has_value());
    CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total", {{"side", "engine"}}) ==
          1.0); // unchanged by the rejection
    CHECK(series_value(reg, {{"side", "engine"}, {"limit", "concurrency"}}) == 1.0);

    slot1.reset();

    // Admit #2 on a DIFFERENT principal — admits is a side-scoped counter,
    // never per-principal, so it accumulates across distinct principals.
    httplib::Response res3;
    bool rejected3 = true;
    auto slot3 = apply_engine_quota_gate("engine", "engine_token", "engine:y", req, res3, q, reg,
                                         rejected3);
    CHECK_FALSE(rejected3);
    REQUIRE(slot3.has_value());
    CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total", {{"side", "engine"}}) ==
          2.0);
    slot3.reset();

    // side="operator" stays untouched — dormant in 4.4 (every 4.4 caller
    // debits kEngine; see principal_quota.hpp's QuotaSide doc comment).
    CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total", {{"side", "operator"}}) ==
          0.0);
}

// ═══════════════════════════════════════════════════════════════════════════
// [quota][gate] — item 5 (S1): the two-predicate engine classification —
// principal_kind=="engine" OR auth_source=="engine_token".
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("apply_engine_quota_gate: S1 two-predicate classification — auth_source==\"engine_"
          "token\" alone (principal_kind is NOT \"engine\") still gates the request through the "
          "real quota primitive, not a passthrough",
          "[quota][gate]") {
    auto cfg = production_shaped_config();
    cfg.max_concurrency = 1;
    PrincipalQuota q(cfg);
    MetricsRegistry reg;
    preseed_quota_metric(reg);
    preseed_admits_metric(reg);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices";

    // "human" principal_kind, but auth_source is the engine-token predicate
    // (mirrors mcp_server.cpp's sibling deny_if_engine_session belt, keyed
    // on the same two fields — see apply_engine_quota_gate's S1 doc
    // comment) — the gate MUST treat this as an engine principal.
    httplib::Response res1;
    bool rejected1 = true;
    auto slot1 = apply_engine_quota_gate("human", "engine_token", "engine:z", req, res1, q, reg,
                                         rejected1);
    CHECK_FALSE(rejected1);
    REQUIRE(slot1.has_value()); // gated -> real admitted slot, not a passthrough nullopt
    CHECK(q.in_flight("engine:z") == 1);
    CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total", {{"side", "engine"}}) ==
          1.0);

    // Second call on the same principal, cap=1, slot1 still held -> proves
    // the primitive was genuinely engaged (a passthrough would never
    // reject).
    httplib::Response res2;
    bool rejected2 = false;
    auto slot2 = apply_engine_quota_gate("human", "engine_token", "engine:z", req, res2, q, reg,
                                         rejected2);
    CHECK(rejected2);
    CHECK_FALSE(slot2.has_value());
    CHECK(res2.status == 429);
    CHECK(series_value(reg, {{"side", "engine"}, {"limit", "concurrency"}}) == 1.0);

    slot1.reset();
}

TEST_CASE("apply_engine_quota_gate: S1 two-predicate classification — principal_kind==\"engine\" "
          "alone (auth_source is NOT \"engine_token\") also gates the request — either predicate "
          "is sufficient",
          "[quota][gate]") {
    auto cfg = production_shaped_config();
    cfg.max_concurrency = 1;
    PrincipalQuota q(cfg);
    MetricsRegistry reg;
    preseed_quota_metric(reg);
    preseed_admits_metric(reg);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices";

    httplib::Response res;
    bool rejected = true;
    // auth_source "local" — the mundane, non-engine value a direct-login
    // session would carry — but principal_kind alone is "engine".
    auto slot =
        apply_engine_quota_gate("engine", "local", "engine:w", req, res, q, reg, rejected);
    CHECK_FALSE(rejected);
    REQUIRE(slot.has_value());
    CHECK(q.in_flight("engine:w") == 1);
    CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total", {{"side", "engine"}}) ==
          1.0);
    slot.reset();
}

TEST_CASE("apply_engine_quota_gate: S1 two-predicate classification — NEITHER predicate set "
          "passes through completely untouched (nullopt, no primitive lookup, no metric)",
          "[quota][gate]") {
    auto cfg = production_shaped_config();
    cfg.max_concurrency = 1;
    PrincipalQuota q(cfg);
    MetricsRegistry reg;
    preseed_quota_metric(reg);
    preseed_admits_metric(reg);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/devices";

    httplib::Response res;
    bool rejected = true;
    auto slot = apply_engine_quota_gate("human", "local", "whoever", req, res, q, reg, rejected);

    CHECK_FALSE(rejected);
    CHECK_FALSE(slot.has_value());
    CHECK(res.status == -1);
    CHECK(q.principal_count() == 0);
    for (const auto& labels : kAllQuotaSeries) {
        CHECK(series_value(reg, labels) == 0.0);
    }
    CHECK(metric_value(reg, "yuzu_server_principal_quota_admits_total", {{"side", "engine"}}) ==
          0.0);
}

TEST_CASE("is_streaming_path: POST /mcp/v1/ streams ONLY with an SSE Accept (2f PR 3b streamed-"
          "POST carve); a plain POST is not a streaming path, and the GET registry is unchanged",
          "[quota][gate][2f]") {
    auto post = [](const std::string& path, const char* accept) {
        httplib::Request req;
        req.method = "POST";
        req.path = path;
        if (accept != nullptr)
            req.set_header("Accept", accept);
        return is_streaming_path(req);
    };

    // The streamed-POST carve: POST /mcp/v1/ is a streaming path IFF the client opted into SSE.
    CHECK(post("/mcp/v1/", "text/event-stream"));                       // streamed intent
    CHECK(post("/mcp/v1/", "application/json, text/event-stream"));     // SSE listed among ranges
    CHECK(post("/mcp/v1/", "text/event-stream; charset=utf-8"));        // params on the SSE range are ignored
    CHECK_FALSE(post("/mcp/v1/", nullptr));                             // plain one-shot tool call
    CHECK_FALSE(post("/mcp/v1/", "application/json"));                  // explicit non-SSE
    CHECK_FALSE(post("/mcp/v1/", "application/json; q=text/event-stream")); // #2073: substring only in a param
    CHECK_FALSE(post("/other", "text/event-stream"));                   // only /mcp/v1/ streams on POST

    // The GET registry is untouched — every GET route still streams unconditionally, no Accept
    // required (GET /mcp/v1/, /events, /api/v1/events, /sse/executions/{id}).
    auto get = [](const std::string& path) {
        httplib::Request req;
        req.method = "GET";
        req.path = path;
        return is_streaming_path(req);
    };
    CHECK(get("/mcp/v1/"));
    CHECK(get("/events"));
    CHECK(get("/api/v1/events"));
    CHECK(get("/sse/executions/abc123"));
    CHECK_FALSE(get("/api/v1/devices"));

    // Other methods never stream.
    httplib::Request del;
    del.method = "DELETE";
    del.path = "/mcp/v1/";
    CHECK_FALSE(is_streaming_path(del));
}
