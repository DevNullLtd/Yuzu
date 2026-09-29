// test_kek_rotate_control.cpp — #2530 B3/B4: the KEK rotate control-flow
// decision helpers in kek_rotate_control.hpp.
//
// These are pure, Postgres-free functions extracted from the
// `kek_ops.rotate` seam closure in server.cpp specifically so the two most
// consequence-laden properties of the #2530 rotate hardening — the exact
// ORDER of the three durable preconditions, and half-commit classification
// WINNING over a query_canceled kind — can be pinned by a fast unit test
// instead of only exercised (if at all) through a live rotate against a
// real database. No `[pg]` tag anywhere in this file: nothing here touches
// Postgres.

#include "kek_rotate_control.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <limits>

using yuzu::server::KekOpResult;
using yuzu::server::pg::SecretCodec;
using yuzu::server::detail::classify_rotate_mint_failure;
using yuzu::server::detail::evaluate_rotate_preconditions;
using yuzu::server::detail::kek_ceiling_is_risk_acceptance;
using yuzu::server::detail::kek_op_outcome_label;
using yuzu::server::detail::kKekMaxLiveVersionsDefault;
using Kind = SecretCodec::LifecycleError::Kind;
using RotateClock = SecretCodec::RotateClock;

namespace {
constexpr std::chrono::seconds kOneHour{3600};
constexpr std::uint32_t kMaxLive = 32;
} // namespace

// ── #2530 B3: precondition ORDER ─────────────────────────────────────────

TEST_CASE("evaluate_rotate_preconditions: a clock anomaly is reported as ClockAnomaly, "
          "never as Cooldown — even when the durable cooldown would ALSO trip",
          "[kek_rotate_control]") {
    RotateClock clock;
    clock.any_rows = true;
    clock.clock_anomaly = true;
    // since_newest deliberately well inside the cooldown window too, so if
    // the order were ever flipped this would silently start passing as
    // Cooldown instead of failing loudly as ClockAnomaly.
    clock.since_newest = std::chrono::seconds{10};
    // #2530 G7-B6: the skew magnitude must reach the outcome unmodified —
    // this is what lets the seam report it in the 503 body and log line.
    clock.future_skew_secs = 45;

    const auto out = evaluate_rotate_preconditions(clock, kOneHour, /*live=*/0, kMaxLive);
    CHECK(out.failure == KekOpResult::Failure::ClockAnomaly);
    // ClockAnomaly deliberately carries no retry hint (contract D) — the
    // timestamp a Cooldown hint would be computed from is the very thing
    // just proven untrustworthy.
    CHECK(out.cooldown_retry_after_ms == 0);
    CHECK(out.clock_skew_secs == 45);
}

TEST_CASE("evaluate_rotate_preconditions: the durable cooldown is checked before the ceiling — "
          "a rotate inside the cooldown window is refused even when ALSO at the ceiling",
          "[kek_rotate_control]") {
    RotateClock clock;
    clock.any_rows = true;
    clock.clock_anomaly = false;
    clock.since_newest = std::chrono::seconds{10}; // well inside a 1h window

    const auto out =
        evaluate_rotate_preconditions(clock, kOneHour, /*live=*/kMaxLive, kMaxLive);
    CHECK(out.failure == KekOpResult::Failure::Cooldown);
    CHECK(out.cooldown_retry_after_ms > 0);
}

TEST_CASE("evaluate_rotate_preconditions: the ceiling refuses before minting once the cooldown "
          "and clock checks both pass",
          "[kek_rotate_control]") {
    RotateClock clock;
    clock.any_rows = true;
    clock.clock_anomaly = false;
    clock.since_newest = std::chrono::seconds{7200}; // outside a 1h window

    const auto out =
        evaluate_rotate_preconditions(clock, kOneHour, /*live=*/kMaxLive, kMaxLive);
    CHECK(out.failure == KekOpResult::Failure::VersionCeiling);
    CHECK(out.cooldown_retry_after_ms == 0); // ceiling carries no retry hint (contract D)
}

TEST_CASE("evaluate_rotate_preconditions: the ceiling trips at, not only above, the configured "
          "maximum",
          "[kek_rotate_control]") {
    RotateClock clock;
    clock.any_rows = true;
    clock.since_newest = kOneHour * 2;

    CHECK(evaluate_rotate_preconditions(clock, kOneHour, kMaxLive, kMaxLive).failure ==
          KekOpResult::Failure::VersionCeiling);
    CHECK(evaluate_rotate_preconditions(clock, kOneHour, kMaxLive - 1, kMaxLive).failure ==
          KekOpResult::Failure::None); // one below the ceiling: proceed
}

TEST_CASE("evaluate_rotate_preconditions: every precondition passing returns None (proceed to "
          "mint)",
          "[kek_rotate_control]") {
    RotateClock clock;
    clock.any_rows = true;
    clock.clock_anomaly = false;
    clock.since_newest = kOneHour * 2;

    const auto out = evaluate_rotate_preconditions(clock, kOneHour, /*live=*/1, kMaxLive);
    CHECK(out.failure == KekOpResult::Failure::None);
    CHECK(out.cooldown_retry_after_ms == 0);
}

TEST_CASE("evaluate_rotate_preconditions: no kek_meta rows yet (any_rows=false) never trips the "
          "durable cooldown, regardless of since_newest",
          "[kek_rotate_control]") {
    RotateClock clock;
    clock.any_rows = false;
    clock.since_newest = std::chrono::seconds{0}; // would trip if any_rows were true

    const auto out = evaluate_rotate_preconditions(clock, kOneHour, /*live=*/0, kMaxLive);
    CHECK(out.failure == KekOpResult::Failure::None);
}

// ── #2530 D: honest cooldown_retry_after_ms ──────────────────────────────

TEST_CASE("evaluate_rotate_preconditions: cooldown_retry_after_ms is derived from the durable "
          "timestamp, not a fixed fallback",
          "[kek_rotate_control]") {
    RotateClock clock;
    clock.any_rows = true;
    clock.since_newest = std::chrono::seconds{100};

    // 3600s window, 100s elapsed -> 3500s = 3,500,000ms remaining. NOT the
    // 300000ms fixed fallback kek_routes.cpp falls back to when the seam
    // leaves this field at its 0 default.
    const auto out = evaluate_rotate_preconditions(clock, kOneHour, /*live=*/0, kMaxLive);
    REQUIRE(out.failure == KekOpResult::Failure::Cooldown);
    CHECK(out.cooldown_retry_after_ms == 3500000);
    CHECK(out.cooldown_retry_after_ms != 300000);
}

TEST_CASE("evaluate_rotate_preconditions: a different configured interval changes the honest "
          "retry hint accordingly",
          "[kek_rotate_control]") {
    RotateClock clock;
    clock.any_rows = true;
    clock.since_newest = std::chrono::seconds{30};

    const auto out = evaluate_rotate_preconditions(clock, std::chrono::seconds{60},
                                                    /*live=*/0, kMaxLive);
    REQUIRE(out.failure == KekOpResult::Failure::Cooldown);
    CHECK(out.cooldown_retry_after_ms == 30000); // 30s remaining of a 60s window
}

// ── #2530 D post-review fix: cooldown_retry_after_ms SATURATES, never wraps ──
// `cooldown_retry_after_ms` is a `std::uint32_t` millisecond count
// (kek_routes.hpp), and prior to this fix a naive
// `static_cast<std::uint32_t>(remaining_ms)` silently WRAPPED once
// `remaining_ms` exceeded UINT32_MAX (~4,294,967,295 ms, ~49.7 days) — a
// quarterly (90-day) KEK rotation policy is ordinary enterprise practice,
// not a contrived edge, and would have reported a near-zero retry hint,
// inviting exactly the retry storm this honest-hint field exists to
// prevent. These cases pin the saturating fix at, either side of, and well
// past the wrap boundary.

TEST_CASE("evaluate_rotate_preconditions: cooldown_retry_after_ms saturates at UINT32_MAX just "
          "past the uint32-millisecond wrap boundary (49.7 days + 1s), instead of wrapping to a "
          "near-zero value",
          "[kek_rotate_control]") {
    RotateClock clock;
    clock.any_rows = true;
    clock.since_newest = std::chrono::seconds{0};

    // 4294968s = 4,294,968,000ms = UINT32_MAX (4,294,967,295) + 705ms. A
    // naive `static_cast<uint32_t>` wraps this to 704ms (4294968000 mod
    // 2^32) — exactly the senior-review defect. Must saturate instead.
    const auto out = evaluate_rotate_preconditions(clock, std::chrono::seconds{4294968},
                                                    /*live=*/0, kMaxLive);
    REQUIRE(out.failure == KekOpResult::Failure::Cooldown);
    CHECK(out.cooldown_retry_after_ms == std::numeric_limits<std::uint32_t>::max());
    CHECK(out.cooldown_retry_after_ms != 704); // the old, wrapped, wrong value
}

TEST_CASE("evaluate_rotate_preconditions: an ordinary quarterly (90-day) rotation interval "
          "saturates rather than reporting the wrapped 40.3-day value",
          "[kek_rotate_control]") {
    RotateClock clock;
    clock.any_rows = true;
    clock.since_newest = std::chrono::seconds{0};

    constexpr std::chrono::seconds kQuarterly{7776000}; // 90 days — an ordinary policy
    const auto out = evaluate_rotate_preconditions(clock, kQuarterly, /*live=*/0, kMaxLive);
    REQUIRE(out.failure == KekOpResult::Failure::Cooldown);
    CHECK(out.cooldown_retry_after_ms == std::numeric_limits<std::uint32_t>::max());
    // 7,776,000,000ms mod 2^32 = 3,481,032,704ms ~= 40.3 days — the value
    // the wrap bug would have reported (matches the senior review's table).
    CHECK(out.cooldown_retry_after_ms != 3481032704ULL);
}

TEST_CASE("evaluate_rotate_preconditions: cooldown_retry_after_ms is reported exactly, NOT "
          "saturated, just under the uint32-millisecond boundary",
          "[kek_rotate_control]") {
    RotateClock clock;
    clock.any_rows = true;
    clock.since_newest = std::chrono::seconds{0};

    // 4294967s = 4,294,967,000ms, 295ms under UINT32_MAX — saturating here
    // too would ALSO be dishonest (just an over-long hint instead of a
    // wrapped one), so this must be the exact value.
    const auto out = evaluate_rotate_preconditions(clock, std::chrono::seconds{4294967},
                                                    /*live=*/0, kMaxLive);
    REQUIRE(out.failure == KekOpResult::Failure::Cooldown);
    CHECK(out.cooldown_retry_after_ms == 4294967000ULL);
    CHECK(out.cooldown_retry_after_ms != std::numeric_limits<std::uint32_t>::max());
}

// ── #2530 B4: half-commit classification WINS ────────────────────────────
// This is the highest-consequence assertion in this file (per the #2530
// contract): telling an operator to retry /rotate on a half-committed
// rotation mints a spurious, unretirable (#2525) extra KEK version every
// time it happens.

TEST_CASE("classify_rotate_mint_failure: a post-mint query_canceled failure is HalfCommitted, "
          "NOT QueryCanceled",
          "[kek_rotate_control]") {
    const auto failure = classify_rotate_mint_failure(/*version_advanced=*/true,
                                                       Kind::query_canceled);
    CHECK(failure == KekOpResult::Failure::HalfCommitted);
    CHECK(failure != KekOpResult::Failure::QueryCanceled);
}

TEST_CASE("classify_rotate_mint_failure: version_advanced wins over EVERY LifecycleError::Kind, "
          "not just query_canceled",
          "[kek_rotate_control]") {
    for (const auto kind : {Kind::query_canceled, Kind::database, Kind::provider,
                            Kind::precondition, Kind::crypto}) {
        INFO("kind=" << static_cast<int>(kind));
        CHECK(classify_rotate_mint_failure(/*version_advanced=*/true, kind) ==
              KekOpResult::Failure::HalfCommitted);
    }
}

TEST_CASE("classify_rotate_mint_failure: only refines to QueryCanceled when the version did NOT "
          "advance",
          "[kek_rotate_control]") {
    CHECK(classify_rotate_mint_failure(/*version_advanced=*/false, Kind::query_canceled) ==
          KekOpResult::Failure::QueryCanceled);
}

TEST_CASE("classify_rotate_mint_failure: a pre-mint non-query_canceled failure is Internal",
          "[kek_rotate_control]") {
    for (const auto kind : {Kind::database, Kind::provider, Kind::precondition, Kind::crypto}) {
        INFO("kind=" << static_cast<int>(kind));
        CHECK(classify_rotate_mint_failure(/*version_advanced=*/false, kind) ==
              KekOpResult::Failure::Internal);
    }
}

// ── #2530 B7: outcome-label vocabulary ───────────────────────────────────

TEST_CASE("kek_op_outcome_label: covers exactly the fixed #2530 B7 vocabulary", "[kek_rotate_control]") {
    CHECK(kek_op_outcome_label(KekOpResult::Failure::None) == "success");
    CHECK(kek_op_outcome_label(KekOpResult::Failure::Unavailable) == "unavailable");
    CHECK(kek_op_outcome_label(KekOpResult::Failure::Conflict) == "conflict");
    CHECK(kek_op_outcome_label(KekOpResult::Failure::Cooldown) == "cooldown");
    CHECK(kek_op_outcome_label(KekOpResult::Failure::VersionCeiling) == "ceiling");
    CHECK(kek_op_outcome_label(KekOpResult::Failure::QueryCanceled) == "query_canceled");
    CHECK(kek_op_outcome_label(KekOpResult::Failure::ClockAnomaly) == "clock_anomaly");
    CHECK(kek_op_outcome_label(KekOpResult::Failure::HalfCommitted) == "half_committed");
    CHECK(kek_op_outcome_label(KekOpResult::Failure::Internal) == "internal");
}

// ── #2530 B5: the ceiling risk-acceptance predicate ──────────────────────
// Shared by main.cpp's boot-time spdlog::warn and server.cpp's
// `server.kek_ceiling_raised` audit event — both call sites must agree on
// exactly what counts as "above default" or one could fire without the
// other.

TEST_CASE("kek_ceiling_is_risk_acceptance: false at and below the default, true above it",
          "[kek_rotate_control]") {
    CHECK_FALSE(kek_ceiling_is_risk_acceptance(kKekMaxLiveVersionsDefault - 1));
    CHECK_FALSE(kek_ceiling_is_risk_acceptance(kKekMaxLiveVersionsDefault));
    CHECK(kek_ceiling_is_risk_acceptance(kKekMaxLiveVersionsDefault + 1));
    CHECK(kek_ceiling_is_risk_acceptance(1000));
}

TEST_CASE("kek_ceiling_is_risk_acceptance: the shared default matches the documented #2530 B5 "
          "value (32)",
          "[kek_rotate_control]") {
    // Pins the literal so a future edit to the shipped default is a
    // deliberate, reviewed change to this test, not a silent drift between
    // server.hpp's Config::kek_max_live_versions default, main.cpp's CLI
    // ->default_val, and this constant.
    CHECK(kKekMaxLiveVersionsDefault == 32);
}
