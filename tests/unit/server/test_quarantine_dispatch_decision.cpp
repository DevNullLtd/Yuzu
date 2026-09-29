/**
 * test_quarantine_dispatch_decision.cpp — locks the pure decision core behind
 * the #3127 fix: a store write outcome of "already active" must still
 * dispatch (the retry-dead-end bug), and a response may only claim
 * "isolated" when dispatch was actually accepted and didn't throw (the
 * phantom-isolated-success bug). Pure header, no I/O, no store, no MCP
 * transport, no agent — see quarantine_dispatch_decision.hpp.
 */

#include "quarantine_dispatch_decision.hpp"

#include <catch2/catch_test_macros.hpp>

#include <vector>

using yuzu::server::QuarantineRecordWrite;
using yuzu::server::QuarantineResponse;
using yuzu::server::quarantine_response_shape;
using yuzu::server::should_dispatch_isolation;

TEST_CASE("should_dispatch_isolation: created and already_active dispatch, store_error does not",
          "[server][quarantine]") {
    // The #3127 retry fix, load-bearing: a record that already exists must
    // NOT dead-end the caller with a terminal error — it must still drive
    // dispatch against the stored intent.
    CHECK(should_dispatch_isolation(QuarantineRecordWrite::already_active) == true);
    CHECK(should_dispatch_isolation(QuarantineRecordWrite::created) == true);
    // The write never happened; nothing durable backs a dispatch.
    CHECK(should_dispatch_isolation(QuarantineRecordWrite::store_error) == false);
}

TEST_CASE("quarantine_response_shape: store_error always retryable, regardless of dispatch state",
          "[server][quarantine]") {
    // store_error short-circuits before dispatch is ever attempted in the
    // handler, but the pure function must still answer sanely if called with
    // any (agents_reached, dispatch_threw) pair — it must never claim
    // isolated on a write that never happened.
    CHECK(quarantine_response_shape(QuarantineRecordWrite::store_error, 0, false) ==
          QuarantineResponse::store_error_retryable);
    CHECK(quarantine_response_shape(QuarantineRecordWrite::store_error, 5, false) ==
          QuarantineResponse::store_error_retryable);
    CHECK(quarantine_response_shape(QuarantineRecordWrite::store_error, 5, true) ==
          QuarantineResponse::store_error_retryable);
    CHECK(quarantine_response_shape(QuarantineRecordWrite::store_error, 0, true) ==
          QuarantineResponse::store_error_retryable);
}

TEST_CASE("quarantine_response_shape: created — the exact phantom-isolation bug",
          "[server][quarantine]") {
    // THE BUG: the prior handler reported success on agents_reached==0
    // (device offline/unreachable) as if the device were isolated. That is
    // exactly what must now classify unconfirmed_retryable, not isolated.
    CHECK(quarantine_response_shape(QuarantineRecordWrite::created, 0, false) ==
          QuarantineResponse::unconfirmed_retryable);
    // The confirmed-success case: at least one agent reached, no throw.
    CHECK(quarantine_response_shape(QuarantineRecordWrite::created, 1, false) ==
          QuarantineResponse::isolated);
}

TEST_CASE("quarantine_response_shape: a thrown dispatch is never isolated",
          "[server][quarantine]") {
    // Even if some earlier partial state left agents_reached positive, a
    // caught dispatch exception must never be reported as isolated.
    CHECK(quarantine_response_shape(QuarantineRecordWrite::created, 1, /*dispatch_threw=*/true) ==
          QuarantineResponse::unconfirmed_retryable);
    CHECK(quarantine_response_shape(QuarantineRecordWrite::already_active, 3,
                                     /*dispatch_threw=*/true) ==
          QuarantineResponse::unconfirmed_retryable);
}

TEST_CASE("quarantine_response_shape: already_active — the retry re-dispatch path",
          "[server][quarantine]") {
    // already_active behaves exactly like created for response-shape purposes
    // once dispatch has been (re-)attempted: agents_reached and dispatch_threw
    // are the only inputs that matter past the write classification.
    CHECK(quarantine_response_shape(QuarantineRecordWrite::already_active, 0, false) ==
          QuarantineResponse::unconfirmed_retryable);
    CHECK(quarantine_response_shape(QuarantineRecordWrite::already_active, 2, false) ==
          QuarantineResponse::isolated);
}

TEST_CASE("quarantine_response_shape: full decision table over every "
          "(write x agents_reached x threw) combination",
          "[server][quarantine]") {
    using W = QuarantineRecordWrite;
    using R = QuarantineResponse;
    struct Case {
        W write;
        int agents_reached;
        bool dispatch_threw;
        R expected;
    };
    const std::vector<Case> cases = {
        // created
        {W::created, 0, false, R::unconfirmed_retryable},
        {W::created, 0, true, R::unconfirmed_retryable},
        {W::created, 1, false, R::isolated},
        {W::created, 1, true, R::unconfirmed_retryable},
        {W::created, 4, false, R::isolated},
        {W::created, 4, true, R::unconfirmed_retryable},
        // already_active
        {W::already_active, 0, false, R::unconfirmed_retryable},
        {W::already_active, 0, true, R::unconfirmed_retryable},
        {W::already_active, 1, false, R::isolated},
        {W::already_active, 1, true, R::unconfirmed_retryable},
        {W::already_active, 4, false, R::isolated},
        {W::already_active, 4, true, R::unconfirmed_retryable},
        // store_error: always retryable, independent of the other two axes
        {W::store_error, 0, false, R::store_error_retryable},
        {W::store_error, 0, true, R::store_error_retryable},
        {W::store_error, 1, false, R::store_error_retryable},
        {W::store_error, 1, true, R::store_error_retryable},
        {W::store_error, 4, false, R::store_error_retryable},
        {W::store_error, 4, true, R::store_error_retryable},
    };
    REQUIRE(cases.size() == 18); // 3 write outcomes x {0,1,4} agents_reached x {false,true} threw

    for (const auto& c : cases) {
        CAPTURE(static_cast<int>(c.write), c.agents_reached, c.dispatch_threw);
        CHECK(quarantine_response_shape(c.write, c.agents_reached, c.dispatch_threw) ==
              c.expected);
    }
}

TEST_CASE("QuarantineRecordWrite / QuarantineResponse: no unreachable branch",
          "[server][quarantine]") {
    // Compile-time exhaustiveness: should_dispatch_isolation's own body is a
    // `switch` with no `default:` over every QuarantineRecordWrite
    // enumerator (quarantine_dispatch_decision.hpp) — a fourth enumerator
    // added there fails to compile before this file even runs. static_assert
    // (not a runtime loop) also proves the function actually is constexpr,
    // which the header's [[nodiscard]] constexpr signature claims.
    static_assert(should_dispatch_isolation(QuarantineRecordWrite::created));
    static_assert(should_dispatch_isolation(QuarantineRecordWrite::already_active));
    static_assert(!should_dispatch_isolation(QuarantineRecordWrite::store_error));
    static_assert(quarantine_response_shape(QuarantineRecordWrite::created, 1, false) ==
                   QuarantineResponse::isolated);
    static_assert(quarantine_response_shape(QuarantineRecordWrite::created, 0, false) ==
                   QuarantineResponse::unconfirmed_retryable);
    static_assert(quarantine_response_shape(QuarantineRecordWrite::store_error, 0, false) ==
                   QuarantineResponse::store_error_retryable);
    // Every response shape is reachable from at least one input combination
    // exercised above: isolated (created,1,false), unconfirmed_retryable
    // (created,0,false), store_error_retryable (store_error,0,false).
    CHECK(quarantine_response_shape(QuarantineRecordWrite::created, 1, false) ==
          QuarantineResponse::isolated);
    CHECK(quarantine_response_shape(QuarantineRecordWrite::created, 0, false) ==
          QuarantineResponse::unconfirmed_retryable);
    CHECK(quarantine_response_shape(QuarantineRecordWrite::store_error, 0, false) ==
          QuarantineResponse::store_error_retryable);
}
