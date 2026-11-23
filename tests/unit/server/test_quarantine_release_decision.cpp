/**
 * test_quarantine_release_decision.cpp -- the pure tables behind the release half of device
 * containment (#7585b): what the reconciler does with a device's reply to a status read or a
 * mutation, what DELETE does with the outcome of its confirming write, how the route waits for a
 * reply, and which status replies stay at the default lifetime. Pure header: no Postgres, no
 * store, no clock, no thread, see quarantine_release_decision.hpp.
 */

#include "quarantine_release_decision.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

using S = QuarantineEndpointState;
using K = ReconcileKind;
using A = StatusReplyAction;

// Every state a reply can carry, so a table row is checked against each of them.
const std::vector<S> kAllStates{S::active, S::active_unproven, S::inactive, S::busy, S::unconfirmed};

StatusReplyFacts status_facts(K kind, S state, bool confirms = false, bool was_confirmed = false,
                              bool parked = false, bool sent = false) {
    return StatusReplyFacts{.kind = kind,
                            .state = state,
                            .confirms = confirms,
                            .was_confirmed = was_confirmed,
                            .owed_parked = parked,
                            .owed_release_sent = sent};
}

MutationReplyFacts mutation_facts(K kind, bool was_apply, S state, bool for_unconfirmed = false,
                                  bool allow_set_unchanged = false) {
    return MutationReplyFacts{.kind = kind,
                              .was_apply = was_apply,
                              .apply_for_unconfirmed = for_unconfirmed,
                              .allow_set_unchanged = allow_set_unchanged,
                              .state = state};
}

} // namespace

// ── decide_status_reply ─────────────────────────────────────────────────────

TEST_CASE("decide_status_reply: a releasing record ends only on inactive, whatever else is said",
          "[quarantine][release_decision]") {
    for (const S state : kAllStates) {
        CAPTURE(endpoint_state_name(state));
        // `confirms` and the owed flags are irrelevant to a releasing record.
        const auto a = decide_status_reply(status_facts(K::releasing, state, /*confirms=*/true,
                                                        /*was_confirmed=*/true, true, true));
        CHECK(a == (state == S::inactive ? A::end_record : A::release_next));
    }
}

TEST_CASE("decide_status_reply: an owed record clears on inactive, then parks or releases by what "
          "this session has done",
          "[quarantine][release_decision]") {
    for (const S state : kAllStates) {
        CAPTURE(endpoint_state_name(state));
        if (state == S::inactive) {
            // inactive clears the mark first, parked or not
            CHECK(decide_status_reply(status_facts(K::owed, state, false, false, true, true)) ==
                  A::clear_owed);
            CHECK(decide_status_reply(status_facts(K::owed, state)) == A::clear_owed);
            continue;
        }
        CHECK(decide_status_reply(status_facts(K::owed, state, false, false, /*parked=*/true,
                                               /*sent=*/true)) == A::owed_keep_parked);
        CHECK(decide_status_reply(status_facts(K::owed, state, false, false, true, false)) ==
              A::owed_keep_parked);
        CHECK(decide_status_reply(status_facts(K::owed, state, false, false, false,
                                               /*sent=*/true)) == A::owed_park);
        CHECK(decide_status_reply(status_facts(K::owed, state)) == A::owed_release_next);
    }
}

TEST_CASE("decide_status_reply: an active record confirms, drifts or stays unconfirmed; inactive "
          "alone never ends it",
          "[quarantine][release_decision]") {
    for (const S state : kAllStates) {
        CAPTURE(endpoint_state_name(state));
        CHECK(decide_status_reply(status_facts(K::active, state, /*confirms=*/true)) == A::confirm);
        CHECK(decide_status_reply(status_facts(K::active, state, true, /*was_confirmed=*/true)) ==
              A::confirm);
        CHECK(decide_status_reply(status_facts(K::active, state, false, /*was_confirmed=*/true)) ==
              A::drift);
        CHECK(decide_status_reply(status_facts(K::active, state)) == A::stay_unconfirmed);
    }
    // A device's own `inactive` on an ACTIVE record is drift (or unconfirmed), never an end.
    const auto inactive_active = decide_status_reply(status_facts(K::active, S::inactive, false, true));
    CHECK(inactive_active != A::end_record);
    CHECK(inactive_active != A::clear_owed);
}

// ── decide_mutation_reply ───────────────────────────────────────────────────

TEST_CASE("decide_mutation_reply: allow_set_kept only for an apply of a never-confirmed record that "
          "carried the note",
          "[quarantine][release_decision]") {
    using M = MutationReplyAction;
    for (const S state : kAllStates) {
        CAPTURE(endpoint_state_name(state));
        CHECK(decide_mutation_reply(mutation_facts(K::active, true, state, true, true)) ==
              M::allow_set_kept);
        // missing any one of the three conditions
        CHECK(decide_mutation_reply(mutation_facts(K::active, true, state, false, true)) !=
              M::allow_set_kept);
        CHECK(decide_mutation_reply(mutation_facts(K::active, true, state, true, false)) !=
              M::allow_set_kept);
        CHECK(decide_mutation_reply(mutation_facts(K::active, false, state, true, true)) !=
              M::allow_set_kept);
    }
}

TEST_CASE("decide_mutation_reply: an owed release answered busy is unspent; other busy waits; "
          "everything else reads status next",
          "[quarantine][release_decision]") {
    using M = MutationReplyAction;
    CHECK(decide_mutation_reply(mutation_facts(K::owed, false, S::busy)) == M::owed_release_unspent);
    // an owed entry never sends an apply, but the table must not read one as the unspent release
    CHECK(decide_mutation_reply(mutation_facts(K::owed, true, S::busy)) == M::wait_claim_interval);
    CHECK(decide_mutation_reply(mutation_facts(K::releasing, false, S::busy)) ==
          M::wait_claim_interval);
    CHECK(decide_mutation_reply(mutation_facts(K::active, true, S::busy)) == M::wait_claim_interval);
    for (const K kind : {K::active, K::releasing, K::owed})
        for (const bool apply : {true, false})
            for (const S state : {S::active, S::active_unproven, S::inactive, S::unconfirmed}) {
                CAPTURE(endpoint_state_name(state));
                CHECK(decide_mutation_reply(mutation_facts(kind, apply, state)) == M::verify_next);
            }
}

// ── release_next / forced_answer ────────────────────────────────────────────

TEST_CASE("release_next: the confirming mark decides, and a refused or failed mark is not a "
          "confirmation",
          "[quarantine][release_decision]") {
    using R = ReleaseNext;
    for (const bool force : {false, true}) {
        CAPTURE(force);
        CHECK(release_next(QuarantineWrite::ok, force) == R::answer_released);
        CHECK(release_next(QuarantineWrite::not_quarantined, force) ==
              R::answer_already_ended_confirmed);
        const R otherwise = force ? R::mark_forced : R::answer_releasing;
        CHECK(release_next(QuarantineWrite::apply_in_flight, force) == otherwise);
        CHECK(release_next(QuarantineWrite::store_error, force) == otherwise);
        CHECK(release_next(std::nullopt, force) == otherwise); // the device did not answer inactive
    }
}

TEST_CASE("forced_answer: ok forces, a zero-row mark is already ended, anything else is "
          "retryable and keeps the record releasing",
          "[quarantine][release_decision]") {
    using F = ForcedAnswer;
    CHECK(forced_answer(QuarantineWrite::ok) == F::forced);
    CHECK(forced_answer(QuarantineWrite::not_quarantined) == F::already_ended);
    CHECK(forced_answer(QuarantineWrite::store_error) == F::store_unavailable);
    CHECK(forced_answer(QuarantineWrite::apply_in_flight) == F::store_unavailable); // fail closed
}

// ── await_status_reply ──────────────────────────────────────────────────────

TEST_CASE("await_status_reply: a reply on the first poll makes no pause", "[quarantine][release_decision]") {
    int polls = 0;
    int pauses = 0;
    const auto reply = await_status_reply(
        10,
        [&]() -> std::optional<std::string> {
            ++polls;
            return "status|inactive";
        },
        [&] { ++pauses; });
    REQUIRE(reply.has_value());
    CHECK(reply->state == S::inactive);
    CHECK(polls == 1);
    CHECK(pauses == 0);
}

TEST_CASE("await_status_reply: an empty read then a reply returns it after exactly one pause (the "
          "late confirmation, #7584a)",
          "[quarantine][release_decision]") {
    int polls = 0;
    int pauses = 0;
    std::optional<std::string> stored; // what the device has answered so far
    const auto reply = await_status_reply(
        10,
        [&]() -> std::optional<std::string> {
            ++polls;
            return stored;
        },
        [&] {
            ++pauses;
            stored = "status|inactive"; // the reply lands between the first and second poll
        });
    REQUIRE(reply.has_value());
    CHECK(reply->state == S::inactive);
    CHECK(polls == 2);
    CHECK(pauses == 1);
}

TEST_CASE("await_status_reply: never a reply returns nothing after max_polls polls and max_polls-1 "
          "pauses",
          "[quarantine][release_decision]") {
    int polls = 0;
    int pauses = 0;
    const auto reply = await_status_reply(
        4,
        [&]() -> std::optional<std::string> {
            ++polls;
            return std::nullopt; // a degraded read looks the same as an empty one
        },
        [&] { ++pauses; });
    CHECK_FALSE(reply.has_value());
    CHECK(polls == 4);
    CHECK(pauses == 3);

    polls = pauses = 0;
    const auto none = await_status_reply(
        0, [&]() -> std::optional<std::string> { ++polls; return "status|active"; }, [&] { ++pauses; });
    CHECK_FALSE(none.has_value());
    CHECK(polls == 0);
    CHECK(pauses == 0);
}

TEST_CASE("await_status_reply: a payload without a status line keeps polling", "[quarantine][release_decision]") {
    int polls = 0;
    const auto reply = await_status_reply(
        5,
        [&]() -> std::optional<std::string> {
            // a partial frame first (no status line), then the real answer
            return ++polls < 3 ? "note|probe_target=203.0.113.9:443" : "note|x\nstatus|inactive";
        },
        [] {});
    REQUIRE(reply.has_value());
    CHECK(reply->state == S::inactive);
    CHECK(polls == 3);
    // a refusal still has a status line, so it ends the wait as `unconfirmed`
    const auto refused = await_status_reply(
        5, []() -> std::optional<std::string> { return "status|refused|privilege_unavailable"; }, [] {});
    REQUIRE(refused.has_value());
    CHECK(refused->state == S::unconfirmed);
}

// ── status_reply_is_evidence ────────────────────────────────────────────────

TEST_CASE("status_reply_is_evidence: true for an end, a clear, drift and a FIRST confirm; false for "
          "every other reply",
          "[quarantine][release_decision]") {
    CHECK(status_reply_is_evidence(A::end_record, false));
    CHECK(status_reply_is_evidence(A::end_record, true));
    CHECK(status_reply_is_evidence(A::clear_owed, false));
    CHECK(status_reply_is_evidence(A::clear_owed, true));
    CHECK(status_reply_is_evidence(A::drift, true));
    CHECK(status_reply_is_evidence(A::confirm, /*was_confirmed=*/false)); // the first confirm
    CHECK_FALSE(status_reply_is_evidence(A::confirm, /*was_confirmed=*/true)); // a repeat confirm
    for (const bool was_confirmed : {false, true}) {
        CHECK_FALSE(status_reply_is_evidence(A::release_next, was_confirmed));
        CHECK_FALSE(status_reply_is_evidence(A::owed_keep_parked, was_confirmed));
        CHECK_FALSE(status_reply_is_evidence(A::owed_park, was_confirmed));
        CHECK_FALSE(status_reply_is_evidence(A::owed_release_next, was_confirmed));
        CHECK_FALSE(status_reply_is_evidence(A::stay_unconfirmed, was_confirmed));
    }
}
