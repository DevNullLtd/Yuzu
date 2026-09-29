/**
 * test_kek_routes.cpp — HTTP-level coverage for the KEK (key-encryption-key)
 * rotation REST surface under POST/GET /api/v1/secrets/kek/... (#2395 track D).
 *
 * Modelled on test_ca_routes.cpp's Harness: registers KekRoutes against an
 * in-process TestRouteSink (no socket, TSan-safe, #438) with a fully
 * controllable STUB `KekOps` — no Postgres, no SecretCodec, so every
 * `KekOpResult::Failure` can be driven deterministically. None of these
 * cases carry `[pg]` — see the codec-level tests in test_secret_codec.cpp
 * for the real Postgres-backed rotation/rewrap behaviour.
 *
 * Coverage: permission gates (Security:Write for rotate/rewrap, Security:Read
 * for status) and their short-circuit; every failure->HTTP-status mapping;
 * the HalfCommitted remediation string (#2395 rule A: must send the caller
 * to /rewrap, must NOT invite a /rotate retry); no internal-error string
 * leak (#2395 rule B); unset/empty KekOps answering 503 without crashing;
 * audit rows (kek.rotate/kek.rewrap, target Secret/kek, Sec-Audit-Failed on
 * a dropped audit row, no audit row at all on the read-only /status route);
 * body handling (absent/`{}` body accepted, unknown key rejected, oversized
 * body rejected); and the /rotate response shape (new_version +
 * rotation_complete present, rows_rewrapped deliberately absent).
 */

#include "kek_routes.hpp"
#include "kek_rotate_control.hpp" // detail::kek_op_outcome_label — #2530 G8-F2 mapping-lock test
#include "mcp_server.hpp"        // detail::kek_mcp_failure_tag — #2530 G8-F2 mapping-lock test
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

// Wires KekRoutes against an in-process sink with a fully-stubbed KekOps —
// no real codec/pool, so every KekOpResult::Failure is driven directly by
// the test. `rotate_set`/`rewrap_set`/`status_set` toggle whether the
// corresponding std::function is populated at all (unset -> route answers
// 503 without ever touching a stub).
struct Harness {
    test::TestRouteSink sink;
    std::vector<AuditRow> audits;
    bool perm_allow{true};
    bool audit_succeeds{true};
    std::string last_perm_type;
    std::string last_perm_op;

    bool rotate_set{true};
    bool rewrap_set{true};
    bool status_set{true};
    int rotate_calls{0};
    int rewrap_calls{0};
    int status_calls{0};
    KekOpResult rotate_result{};
    KekOpResult rewrap_result{};
    KekOpResult status_result{};

    void wire() {
        KekRoutes routes;
        KekRoutes::PermFn perm = [this](const httplib::Request&, httplib::Response& res,
                                        const std::string& type, const std::string& op) {
            last_perm_type = type;
            last_perm_op = op;
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})", "application/json");
                return false;
            }
            return true;
        };
        KekRoutes::AuditFn audit = [this](const httplib::Request&, const std::string& a,
                                          const std::string& r, const std::string& tt,
                                          const std::string& ti, const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds;
        };
        KekOps ops;
        if (rotate_set)
            ops.rotate = [this]() {
                ++rotate_calls;
                return rotate_result;
            };
        if (rewrap_set)
            ops.rewrap = [this]() {
                ++rewrap_calls;
                return rewrap_result;
            };
        if (status_set)
            ops.status = [this]() {
                ++status_calls;
                return status_result;
            };
        routes.register_routes(sink, perm, audit, std::move(ops));
    }
};

} // namespace

// ── Permission gates ──────────────────────────────────────────────────────

TEST_CASE("kek_routes: /rotate and /rewrap gate on Security:Write", "[kek_routes][security]") {
    Harness h;
    h.wire();

    auto rotate = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    CHECK(h.last_perm_type == "Security");
    CHECK(h.last_perm_op == "Write");

    auto rewrap = h.sink.Post("/api/v1/secrets/kek/rewrap", "");
    REQUIRE(rewrap);
    CHECK(h.last_perm_type == "Security");
    CHECK(h.last_perm_op == "Write");
}

TEST_CASE("kek_routes: /status gates on Security:Read", "[kek_routes][security]") {
    Harness h;
    h.wire();

    auto status = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(status);
    CHECK(h.last_perm_type == "Security");
    CHECK(h.last_perm_op == "Read");
}

TEST_CASE("kek_routes: a denying perm_fn short-circuits every route before the seam is touched",
          "[kek_routes][security]") {
    Harness h;
    h.perm_allow = false;
    h.wire();

    auto rotate = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    CHECK(rotate->status == 403);
    CHECK(h.rotate_calls == 0);

    auto rewrap = h.sink.Post("/api/v1/secrets/kek/rewrap", "");
    REQUIRE(rewrap);
    CHECK(rewrap->status == 403);
    CHECK(h.rewrap_calls == 0);

    auto status = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(status);
    CHECK(status->status == 403);
    CHECK(h.status_calls == 0);

    CHECK(h.audits.empty()); // denial happens before any audit_fn call
}

// ── Failure -> HTTP status mapping ───────────────────────────────────────

TEST_CASE("kek_routes: every KekOpResult::Failure maps to the documented HTTP status",
          "[kek_routes]") {
    struct Case {
        KekOpResult::Failure failure;
        int expected_status;
    };
    const Case cases[] = {
        {KekOpResult::Failure::Unavailable, 503},
        {KekOpResult::Failure::Conflict, 409},
        {KekOpResult::Failure::Cooldown, 429},
        {KekOpResult::Failure::VersionCeiling, 409},
        {KekOpResult::Failure::QueryCanceled, 503},
        {KekOpResult::Failure::ClockAnomaly, 503},
        {KekOpResult::Failure::HalfCommitted, 500},
        {KekOpResult::Failure::Internal, 500},
    };

    for (const auto& c : cases) {
        INFO("rotate, failure=" << static_cast<int>(c.failure));
        Harness h;
        h.rotate_result.failure = c.failure;
        h.wire();
        auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
        REQUIRE(res);
        CHECK(res->status == c.expected_status);
    }

    for (const auto& c : cases) {
        INFO("rewrap, failure=" << static_cast<int>(c.failure));
        Harness h;
        h.rewrap_result.failure = c.failure;
        h.wire();
        auto res = h.sink.Post("/api/v1/secrets/kek/rewrap", "");
        REQUIRE(res);
        CHECK(res->status == c.expected_status);
    }

    for (const auto& c : cases) {
        INFO("status, failure=" << static_cast<int>(c.failure));
        Harness h;
        h.status_result.failure = c.failure;
        h.wire();
        auto res = h.sink.Get("/api/v1/secrets/kek/status");
        REQUIRE(res);
        CHECK(res->status == c.expected_status);
    }
}

// #2530 G8-F2: the audit `detail` threaded to audit_fn for a failing
// rotate/rewrap must be EXACTLY failure_tag()'s tag, for every Failure — not
// just "some non-empty string", which is all the pre-existing audit tests
// above check. Compared against the exported failure_tag twin
// (detail::kek_route_failure_tag) rather than a hand-copied literal, so a
// change to the production switch can't silently drift from what this test
// expects.
TEST_CASE("kek_routes: the audited failure detail is exactly failure_tag()'s tag, for every "
          "Failure",
          "[kek_routes][security]") {
    struct Case {
        KekOpResult::Failure failure;
        const char* audit_detail; // the exact failure_tag() literal this failure must audit
    };
    const Case cases[] = {
        {KekOpResult::Failure::Unavailable, "failure=unavailable"},
        {KekOpResult::Failure::Conflict, "failure=conflict"},
        {KekOpResult::Failure::Cooldown, "failure=cooldown"},
        {KekOpResult::Failure::VersionCeiling, "failure=ceiling"},
        {KekOpResult::Failure::QueryCanceled, "failure=query_canceled"},
        {KekOpResult::Failure::ClockAnomaly, "failure=clock_anomaly"},
        {KekOpResult::Failure::HalfCommitted, "failure=half_committed"},
        {KekOpResult::Failure::Internal, "failure=internal"},
    };
    for (const auto& c : cases) {
        INFO("rotate, failure=" << static_cast<int>(c.failure));
        Harness h;
        h.rotate_result.failure = c.failure;
        h.wire();
        auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
        REQUIRE(res);
        REQUIRE(h.audits.size() == 1);
        // Literal, so this can't be tautological against the same production
        // function under test, PLUS a cross-check against the exported
        // production twin so a deliberate vocabulary change surfaces as a
        // double-update, not a silent drift.
        CHECK(h.audits[0].detail == c.audit_detail);
        CHECK(h.audits[0].detail == detail::kek_route_failure_tag(c.failure));
    }
    for (const auto& c : cases) {
        INFO("rewrap, failure=" << static_cast<int>(c.failure));
        Harness h;
        h.rewrap_result.failure = c.failure;
        h.wire();
        auto res = h.sink.Post("/api/v1/secrets/kek/rewrap", "");
        REQUIRE(res);
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].detail == c.audit_detail);
        CHECK(h.audits[0].detail == detail::kek_route_failure_tag(c.failure));
    }
}

// #2530 G8-F2 — the mapping-lock #2284 says must exist. Three independent
// switches classify the same nine `KekOpResult::Failure` values into
// operator-facing tags: kek_routes.cpp's failure_tag() (REST audit detail,
// "failure=xxx"), mcp_server.cpp's kek_failure_tag() (MCP audit detail, same
// "failure=xxx" shape), and kek_rotate_control.hpp's kek_op_outcome_label()
// (the bare Prometheus label value, no "failure=" prefix, plus a tenth case
// — None -> "success" — that the other two never see since routes only call
// them on a non-None failure). This test is deliberately NOT a refactor to
// one shared table (out of scope for #2530 — see the hardening contract);
// it exists so the three switches drifting apart is a red CI run, not a
// silent metrics/audit mismatch discovered during an incident.
TEST_CASE("kek_routes: failure_tag/kek_failure_tag/kek_op_outcome_label agree for every "
          "Failure",
          "[kek_routes][mcp][security]") {
    const KekOpResult::Failure failures[] = {
        KekOpResult::Failure::Unavailable,   KekOpResult::Failure::Conflict,
        KekOpResult::Failure::Cooldown,      KekOpResult::Failure::VersionCeiling,
        KekOpResult::Failure::QueryCanceled, KekOpResult::Failure::ClockAnomaly,
        KekOpResult::Failure::HalfCommitted, KekOpResult::Failure::Internal,
        KekOpResult::Failure::None,
    };
    for (auto f : failures) {
        INFO("failure=" << static_cast<int>(f));
        const std::string_view rest_tag = detail::kek_route_failure_tag(f);
        const std::string_view mcp_tag = mcp::detail::kek_mcp_failure_tag(f);
        const std::string_view outcome = detail::kek_op_outcome_label(f);

        // REST and MCP agree byte-for-byte, INCLUDING the case neither
        // route ever actually calls this on (None) — failure_tag()/
        // kek_failure_tag() both fall back to "failure=internal" there,
        // and the two fallbacks must still agree.
        CHECK(rest_tag == mcp_tag);

        if (f == KekOpResult::Failure::None) {
            CHECK(outcome == "success");
            continue;
        }
        // outcome is the same token as the "failure=xxx" tag, minus the
        // "failure=" prefix — e.g. "failure=ceiling" <-> "ceiling".
        REQUIRE(rest_tag.starts_with("failure="));
        CHECK(rest_tag.substr(std::string_view("failure=").size()) == outcome);
    }
}

// ── #2530 D: retry_after_ms presence/absence ─────────────────────────────

TEST_CASE("kek_routes: #2530 D — VersionCeiling/QueryCanceled/ClockAnomaly carry NO "
          "retry_after_ms; Cooldown/Conflict DO",
          "[kek_routes]") {
    struct Case {
        KekOpResult::Failure failure;
        bool expect_retry_hint;
    };
    const Case cases[] = {
        {KekOpResult::Failure::Cooldown, true},
        {KekOpResult::Failure::Conflict, true},
        {KekOpResult::Failure::VersionCeiling, false},
        {KekOpResult::Failure::QueryCanceled, false},
        {KekOpResult::Failure::ClockAnomaly, false},
    };
    for (const auto& c : cases) {
        INFO("failure=" << static_cast<int>(c.failure));
        Harness h;
        h.rotate_result.failure = c.failure;
        h.wire();
        auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
        REQUIRE(res);
        auto body = json::parse(res->body);
        REQUIRE(body["error"].contains("retry_after_ms")); // A4: always a key, nullable
        if (c.expect_retry_hint)
            CHECK_FALSE(body["error"]["retry_after_ms"].is_null());
        else
            CHECK(body["error"]["retry_after_ms"].is_null());
    }
}

TEST_CASE("kek_routes: Cooldown's retry_after_ms is the seam-provided honest value when set, "
          "and a sane fallback when the seam left it unset",
          "[kek_routes]") {
    Harness h;
    h.rotate_result.failure = KekOpResult::Failure::Cooldown;
    h.rotate_result.cooldown_retry_after_ms = 1234;
    h.wire();
    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(res);
    REQUIRE(res->status == 429);
    auto body = json::parse(res->body);
    CHECK(body["error"]["retry_after_ms"] == 1234);

    Harness h2;
    h2.rotate_result.failure = KekOpResult::Failure::Cooldown;
    h2.wire(); // cooldown_retry_after_ms left at its 0 default
    auto res2 = h2.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(res2);
    auto body2 = json::parse(res2->body);
    CHECK_FALSE(body2["error"]["retry_after_ms"].is_null());
    CHECK(body2["error"]["retry_after_ms"].get<std::int64_t>() > 0); // a fallback, never a false "0"
}

TEST_CASE("kek_routes: QueryCanceled's remediation names statement_timeout/load/cancellation/"
          "scan-size and never claims the condition is transient",
          "[kek_routes]") {
    Harness h;
    h.rotate_result.failure = KekOpResult::Failure::QueryCanceled;
    h.wire();
    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    auto body = json::parse(res->body);
    const std::string remediation = body["error"]["remediation"].get<std::string>();
    CHECK(remediation.find("statement_timeout") != std::string::npos);
    CHECK(remediation.find("load") != std::string::npos);
    CHECK(remediation.find("cancel") != std::string::npos);
    CHECK(remediation.find("scan") != std::string::npos);
    CHECK(remediation.find("not necessarily transient") != std::string::npos);
}

TEST_CASE("kek_routes: ClockAnomaly is distinct from Cooldown — no retry hint, message names "
          "the untrustworthy clock",
          "[kek_routes]") {
    Harness h;
    h.rotate_result.failure = KekOpResult::Failure::ClockAnomaly;
    h.wire();
    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    auto body = json::parse(res->body);
    CHECK(body["error"]["retry_after_ms"].is_null());
    const std::string message = body["error"]["message"].get<std::string>();
    const std::string remediation = body["error"]["remediation"].get<std::string>();
    CHECK((message.find("clock") != std::string::npos ||
           remediation.find("clock") != std::string::npos));
}

// #2530 G7-B6: the 503 body must report the observed skew MAGNITUDE, not
// just the boolean fact of the anomaly — this is what lets an operator tell
// "a few seconds of jitter" (self-clears) from "dated a year out" (does
// not) at a glance.
TEST_CASE("kek_routes: ClockAnomaly's message interpolates the seam-provided skew magnitude",
          "[kek_routes]") {
    Harness h;
    h.rotate_result.failure = KekOpResult::Failure::ClockAnomaly;
    h.rotate_result.clock_skew_secs = 31536000; // ~1 year — the "not just jitter" case
    h.wire();
    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    auto body = json::parse(res->body);
    const std::string message = body["error"]["message"].get<std::string>();
    CHECK(message.find("31536000") != std::string::npos);
    const std::string remediation = body["error"]["remediation"].get<std::string>();
    // The remediation must say there is NO bypass for this specific failure —
    // it is the one 503 in this surface with no configuration escape at all.
    CHECK(remediation.find("does NOT self-clear") != std::string::npos);
}

TEST_CASE("kek_routes: VersionCeiling names --kek-max-live-versions and never implies waiting "
          "helps",
          "[kek_routes]") {
    Harness h;
    h.rotate_result.failure = KekOpResult::Failure::VersionCeiling;
    h.wire();
    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(res);
    REQUIRE(res->status == 409);
    auto body = json::parse(res->body);
    CHECK(body["error"]["retry_after_ms"].is_null());
    const std::string remediation = body["error"]["remediation"].get<std::string>();
    CHECK(remediation.find("--kek-max-live-versions") != std::string::npos);
}

// ── #2530 B2: GET /status diagnostic snapshot fields ─────────────────────

TEST_CASE("kek_routes: GET /status's 200 body carries live_versions, lock_held, and "
          "lock_holder_pid",
          "[kek_routes]") {
    Harness h;
    h.status_result.active_version = 3;
    h.status_result.live_versions = 4;
    h.status_result.lock_held = true;
    h.status_result.lock_holder_pid = 4242;
    h.wire();
    auto res = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["live_versions"] == 4);
    CHECK(body["lock_held"] == true);
    CHECK(body["lock_holder_pid"] == 4242);

    Harness h2;
    h2.status_result.lock_held = false;
    h2.status_result.lock_holder_pid = std::nullopt;
    h2.wire();
    auto res2 = h2.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(res2);
    auto body2 = json::parse(res2->body);
    CHECK(body2["lock_held"] == false);
    CHECK(body2["lock_holder_pid"].is_null());
}

// #2530 H1 (Hermes round 2): `lock_holder_captured_at` carries the instant
// the lock_held/lock_holder_pid snapshot was taken, so a stale reading is
// visible as stale rather than authoritative — never fabricated when the
// snapshot itself is undetermined.
TEST_CASE("kek_routes: GET /status's 200 body carries lock_holder_captured_at as an ISO-8601 "
          "string alongside a determined lock_held, and null when undetermined",
          "[kek_routes]") {
    Harness h;
    h.status_result.active_version = 3;
    h.status_result.lock_held = true;
    h.status_result.lock_holder_pid = 4242;
    h.status_result.lock_holder_captured_at = std::chrono::system_clock::time_point{
        std::chrono::seconds{1735689600}}; // 2025-01-01T00:00:00Z
    h.wire();
    auto res = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = json::parse(res->body);
    REQUIRE(body.contains("lock_holder_captured_at"));
    CHECK(body["lock_holder_captured_at"] == "2025-01-01T00:00:00Z");

    // Undetermined snapshot (query failure) — the seam never populates
    // lock_held/lock_holder_pid/lock_holder_captured_at in that case; the
    // route must serialise all three as JSON null, never fabricate a
    // timestamp for a snapshot that was never taken.
    Harness h2;
    REQUIRE_FALSE(h2.status_result.lock_held.has_value());
    REQUIRE_FALSE(h2.status_result.lock_holder_captured_at.has_value());
    h2.wire();
    auto res2 = h2.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(res2);
    auto body2 = json::parse(res2->body);
    REQUIRE(body2.contains("lock_holder_captured_at"));
    CHECK(body2["lock_holder_captured_at"].is_null());
}

// #2530 T5 — a seam that could NOT determine `live_versions`/`lock_held`
// (the underlying Postgres query failed) leaves them default-constructed
// `std::nullopt`, and the route MUST serialise that as JSON `null` — never a
// fabricated `0`/`false`, and never by omitting the key (the key stays
// present so a client can tell "unknown" apart from "server predates this
// field" without a version check). This is the defect this task closes:
// `lock_held: false` on a query failure reads as "no wedge" during the
// exact incident (a stuck secrets_kek_op lock) this field exists to
// diagnose.
TEST_CASE("kek_routes: GET /status serialises undetermined live_versions/lock_held as JSON "
          "null, never a fabricated 0/false, key still present",
          "[kek_routes]") {
    Harness h;
    h.status_result.active_version = 3;
    // Default-constructed KekOpResult: live_versions/lock_held are
    // std::nullopt — exactly what the seam leaves them at on a query
    // failure (server.cpp's status lambda never assigns them in that case).
    REQUIRE_FALSE(h.status_result.live_versions.has_value());
    REQUIRE_FALSE(h.status_result.lock_held.has_value());
    h.wire();
    auto res = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = json::parse(res->body);
    REQUIRE(body.contains("live_versions"));
    CHECK(body["live_versions"].is_null());
    REQUIRE(body.contains("lock_held"));
    CHECK(body["lock_held"].is_null());
    // Never fabricated to the misleading truthy-negative values.
    CHECK(body["live_versions"] != 0);
    CHECK(body["lock_held"] != false);
}

TEST_CASE("kek_routes: an unset KekOps member answers 503 without ever being invoked",
          "[kek_routes]") {
    Harness h;
    h.rotate_set = false;
    h.rewrap_set = false;
    h.status_set = false;
    h.wire();

    auto rotate = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    CHECK(rotate->status == 503);
    CHECK(h.rotate_calls == 0);

    auto rewrap = h.sink.Post("/api/v1/secrets/kek/rewrap", "");
    REQUIRE(rewrap);
    CHECK(rewrap->status == 503);
    CHECK(h.rewrap_calls == 0);

    auto status = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(status);
    CHECK(status->status == 503);
    CHECK(h.status_calls == 0);
}

TEST_CASE("kek_routes: a default-constructed KekOps (every std::function unset) never crashes",
          "[kek_routes]") {
    // Not via Harness's per-field toggles (which still populate a lambda when
    // *_set is true) — register a genuinely default-constructed KekOps{}
    // directly, so an empty std::function invocation would be a std::bad_function_call
    // crash if the route ever dereferenced it without the `if (!ops.rotate)` guard.
    test::TestRouteSink sink;
    KekRoutes routes;
    KekRoutes::PermFn perm = [](const httplib::Request&, httplib::Response&,
                                const std::string&, const std::string&) { return true; };
    KekRoutes::AuditFn audit = [](const httplib::Request&, const std::string&, const std::string&,
                                  const std::string&, const std::string&,
                                  const std::string&) { return true; };
    routes.register_routes(sink, perm, audit, KekOps{});

    auto rotate = sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    CHECK(rotate->status == 503);

    auto rewrap = sink.Post("/api/v1/secrets/kek/rewrap", "");
    REQUIRE(rewrap);
    CHECK(rewrap->status == 503);

    auto status = sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(status);
    CHECK(status->status == 503);
}

// ── HalfCommitted remediation (#2395 rule A) ─────────────────────────────

TEST_CASE("kek_routes: HalfCommitted tells the caller to call /rewrap and NEVER invites a "
          "/rotate retry",
          "[kek_routes][security]") {
    Harness h;
    h.rotate_result.failure = KekOpResult::Failure::HalfCommitted;
    h.wire();

    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(res);
    REQUIRE(res->status == 500);
    auto body = json::parse(res->body);
    const std::string remediation = body["error"]["remediation"].get<std::string>();
    const std::string message = body["error"]["message"].get<std::string>();

    // MUST tell the caller to resume via /rewrap.
    CHECK(remediation.find("/api/v1/secrets/kek/rewrap") != std::string::npos);
    CHECK(remediation.find("resume") != std::string::npos);
    // The remediation legitimately MENTIONS /rotate once — as the "do NOT
    // retry" warning — so this must NEVER be a bare invitation: every mention
    // of "/rotate" must be preceded, on the same string, by an explicit
    // negation ("do NOT"/"do not"/"never").
    auto rotate_pos = remediation.find("/api/v1/secrets/kek/rotate");
    REQUIRE(rotate_pos != std::string::npos); // the warning itself must be present
    const std::string prefix = remediation.substr(0, rotate_pos);
    CHECK((prefix.find("do NOT") != std::string::npos || prefix.find("do not") != std::string::npos ||
           prefix.find("DO NOT") != std::string::npos || prefix.find("never") != std::string::npos ||
           prefix.find("Never") != std::string::npos));
    (void)message;
}

// ── No internal error string leak (#2395 rule B) ─────────────────────────

TEST_CASE("kek_routes: an Internal failure never leaks a database/codec-shaped string",
          "[kek_routes][security]") {
    // KekOpResult carries no string field at all for Internal — there is
    // structurally no channel for a codec-internal string to reach this
    // struct (kek_routes.hpp rule B). This test pins the OBSERVABLE
    // behaviour: the body is the fixed generic message, nothing else.
    Harness h;
    h.rotate_result.failure = KekOpResult::Failure::Internal;
    h.wire();

    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(res);
    REQUIRE(res->status == 500);
    auto body = json::parse(res->body);
    CHECK(body["error"]["message"].get<std::string>() == "internal error");

    // Positive assertion on the generic message rather than trying to
    // enumerate every possible leak shape.
    const std::string dumped = res->body;
    CHECK(dumped.find("PQerrorMessage") == std::string::npos);
    CHECK(dumped.find("postgres") == std::string::npos);
    CHECK(dumped.find("Postgres") == std::string::npos);
    CHECK(dumped.find("libpq") == std::string::npos);
    CHECK(dumped.find("SELECT") == std::string::npos);
    CHECK(dumped.find("relation \"") == std::string::npos); // Postgres's `relation "x" does not exist` shape
}

// ── Audit ─────────────────────────────────────────────────────────────────

TEST_CASE("kek_routes: a successful rotate/rewrap audits kek.rotate/kek.rewrap against "
          "Secret/kek",
          "[kek_routes][security]") {
    Harness h;
    h.rotate_result.new_version = 7;
    h.rotate_result.rotation_complete = true;
    h.wire();

    auto rotate = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    REQUIRE(rotate->status == 200);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "kek.rotate");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_type == "Secret");
    CHECK(h.audits[0].target_id == "kek");

    Harness h2;
    h2.rewrap_result.rows_rewrapped = 3;
    h2.wire();
    auto rewrap = h2.sink.Post("/api/v1/secrets/kek/rewrap", "");
    REQUIRE(rewrap);
    REQUIRE(rewrap->status == 200);
    REQUIRE(h2.audits.size() == 1);
    CHECK(h2.audits[0].action == "kek.rewrap");
    CHECK(h2.audits[0].result == "success");
    CHECK(h2.audits[0].target_type == "Secret");
    CHECK(h2.audits[0].target_id == "kek");
}

TEST_CASE("kek_routes: a failing rotate/rewrap still audits a failure row against Secret/kek",
          "[kek_routes][security]") {
    Harness h;
    h.rotate_result.failure = KekOpResult::Failure::Conflict;
    h.wire();
    auto rotate = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    REQUIRE(rotate->status == 409);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "kek.rotate");
    CHECK(h.audits[0].result == "failure");
    CHECK(h.audits[0].target_type == "Secret");
    CHECK(h.audits[0].target_id == "kek");
}

TEST_CASE("kek_routes: a dropped audit row on a successful rotate sets Sec-Audit-Failed",
          "[kek_routes][security]") {
    Harness h;
    h.audit_succeeds = false;
    h.wire();
    auto rotate = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    REQUIRE(rotate->status == 200); // the rotate itself still succeeded
    CHECK(rotate->get_header_value("Sec-Audit-Failed") == "true");
}

TEST_CASE("kek_routes: GET /status never emits an audit row, success or failure",
          "[kek_routes][security]") {
    Harness h;
    h.wire();
    auto ok = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    CHECK(h.audits.empty());

    Harness h2;
    h2.status_result.failure = KekOpResult::Failure::Internal;
    h2.wire();
    auto fail = h2.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(fail);
    REQUIRE(fail->status == 500);
    CHECK(h2.audits.empty());
}

// ── Body handling ─────────────────────────────────────────────────────────

TEST_CASE("kek_routes: rotate/rewrap accept both an absent body and an empty {} body",
          "[kek_routes]") {
    Harness h;
    h.wire();
    auto absent = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(absent);
    CHECK(absent->status == 200);

    Harness h2;
    h2.wire();
    auto empty_obj = h2.sink.Post("/api/v1/secrets/kek/rotate", "{}");
    REQUIRE(empty_obj);
    CHECK(empty_obj->status == 200);
}

TEST_CASE("kek_routes: a body with an unknown key is rejected 400 (mass-assignment guard)",
          "[kek_routes][security]") {
    Harness h;
    h.wire();
    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", R"({"force":true})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.rotate_calls == 0); // the seam must never be reached
}

TEST_CASE("kek_routes: an oversized body is rejected 413 before JSON parsing", "[kek_routes]") {
    Harness h;
    h.wire();
    std::string big = R"({"pad":")" + std::string(70000, 'x') + R"("})";
    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", big);
    REQUIRE(res);
    CHECK(res->status == 413);
    CHECK(h.rotate_calls == 0);
}

// ── Response shape ─────────────────────────────────────────────────────────

TEST_CASE("kek_routes: /rotate's 200 body carries new_version + rotation_complete and "
          "deliberately omits rows_rewrapped",
          "[kek_routes]") {
    Harness h;
    h.rotate_result.new_version = 42;
    h.rotate_result.rotation_complete = true;
    h.rotate_result.rows_rewrapped = 99; // seam-internal value; must not leak into the body
    h.wire();

    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["new_version"] == 42);
    CHECK(body["rotation_complete"] == true);
    CHECK_FALSE(body.contains("rows_rewrapped"));
}

TEST_CASE("kek_routes: /rewrap's 200 body carries rows_rewrapped", "[kek_routes]") {
    Harness h;
    h.rewrap_result.rows_rewrapped = 5;
    h.wire();
    auto res = h.sink.Post("/api/v1/secrets/kek/rewrap", "");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["rows_rewrapped"] == 5);
}

TEST_CASE("kek_routes: GET /status's 200 body carries active_version, oldest_in_use "
          "(null when absent), and rotation_complete",
          "[kek_routes]") {
    Harness h;
    h.status_result.active_version = 3;
    h.status_result.oldest_in_use = std::nullopt;
    h.status_result.rotation_complete = true;
    h.wire();
    auto res = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["active_version"] == 3);
    CHECK(body["oldest_in_use"].is_null());
    CHECK(body["rotation_complete"] == true);

    Harness h2;
    h2.status_result.active_version = 3;
    h2.status_result.oldest_in_use = 2;
    h2.status_result.rotation_complete = false;
    h2.wire();
    auto res2 = h2.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(res2);
    auto body2 = json::parse(res2->body);
    CHECK(body2["oldest_in_use"] == 2);
    CHECK(body2["rotation_complete"] == false);
}
