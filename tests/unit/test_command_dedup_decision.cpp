// Pure unit tests for command_dedup_decision.hpp — the claim/replay/RUNNING DECISION
// core extracted from agent.cpp's Subscribe command-read loop (HA WS-0, issue #3668).
//
// These pin the DECISION only. They cannot see whether agent.cpp still calls it: that is
// pinned lexically by tests/test_agent_command_dedup_wiring_lexical.py (agent.cpp is not
// gRPC-test-harnessed, so there is no behavioural seam for the shell). The store itself is
// covered by test_command_dedup_store.cpp. No gRPC, no store, no protobuf.

#include "command_dedup_decision.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::agent::ClaimStatus;
using yuzu::agent::DedupAction;
using yuzu::agent::DedupState;
using yuzu::agent::decide_after_claim;
using yuzu::agent::should_claim;

TEST_CASE("decide_after_claim: first sighting proceeds and owns the claim",
          "[command_dedup][decision]") {
    auto d = decide_after_claim(ClaimStatus::Claimed, DedupState::InFlight, false);
    CHECK(d.action == DedupAction::Proceed);
    CHECK(d.owns_claim);
    CHECK_FALSE(d.count_claim_error);
}

TEST_CASE("decide_after_claim: store error fails OPEN and owns nothing and is counted",
          "[command_dedup][decision]") {
    auto d = decide_after_claim(ClaimStatus::Error, DedupState::InFlight, false);
    CHECK(d.action == DedupAction::Proceed);
    // Must not own a claim: releasing on queue-full would delete a concurrent first
    // delivery's row.
    CHECK_FALSE(d.owns_claim);
    // Invariant 7: the degradation stays observable.
    CHECK(d.count_claim_error);
}

TEST_CASE("decide_after_claim: terminal duplicate replays the stored outcome",
          "[command_dedup][decision]") {
    auto d = decide_after_claim(ClaimStatus::Duplicate, DedupState::Terminal, true);
    CHECK(d.action == DedupAction::ReplayStored);
    CHECK_FALSE(d.owns_claim);
    CHECK_FALSE(d.count_claim_error);
}

TEST_CASE("decide_after_claim: in-flight duplicate answers RUNNING",
          "[command_dedup][decision]") {
    for (bool parses : {false, true}) {
        // stored_blob_parses is irrelevant to an in-flight row.
        auto d = decide_after_claim(ClaimStatus::Duplicate, DedupState::InFlight, parses);
        CHECK(d.action == DedupAction::AnswerRunning);
        CHECK_FALSE(d.owns_claim);
    }
}

TEST_CASE("decide_after_claim: terminal duplicate with an unparsable blob answers RUNNING and never re-runs",
          "[command_dedup][decision]") {
    auto d = decide_after_claim(ClaimStatus::Duplicate, DedupState::Terminal, false);
    CHECK(d.action == DedupAction::AnswerRunning);
    CHECK_FALSE(d.owns_claim);
}

TEST_CASE("decide_after_claim: no Duplicate input ever proceeds (invariant 4)",
          "[command_dedup][decision]") {
    for (auto state : {DedupState::InFlight, DedupState::Terminal})
        for (bool parses : {false, true}) {
            auto d = decide_after_claim(ClaimStatus::Duplicate, state, parses);
            CHECK(d.action != DedupAction::Proceed);
            CHECK_FALSE(d.owns_claim);
        }
}

TEST_CASE("decide_after_claim: Claimed and Error ignore the stored-outcome inputs",
          "[command_dedup][decision]") {
    // state / stored_blob_parses are meaningful only for Duplicate; a stale value there
    // must never turn a fresh claim into a replay, or an Error into a non-proceed.
    for (auto state : {DedupState::InFlight, DedupState::Terminal})
        for (bool parses : {false, true}) {
            auto claimed = decide_after_claim(ClaimStatus::Claimed, state, parses);
            CHECK(claimed.action == DedupAction::Proceed);
            CHECK(claimed.owns_claim);
            CHECK_FALSE(claimed.count_claim_error);

            auto error = decide_after_claim(ClaimStatus::Error, state, parses);
            CHECK(error.action == DedupAction::Proceed);
            CHECK_FALSE(error.owns_claim);
            CHECK(error.count_claim_error);
        }
}

TEST_CASE("decide_after_claim: only Claimed ever owns the claim",
          "[command_dedup][decision]") {
    for (auto status : {ClaimStatus::Claimed, ClaimStatus::Duplicate, ClaimStatus::Error})
        for (auto state : {DedupState::InFlight, DedupState::Terminal})
            for (bool parses : {false, true}) {
                auto d = decide_after_claim(status, state, parses);
                CHECK(d.owns_claim == (status == ClaimStatus::Claimed));
            }
}

TEST_CASE("decide_after_claim: an out-of-range status fails SAFE and never proceeds",
          "[command_dedup][decision]") {
    auto d = decide_after_claim(static_cast<ClaimStatus>(99), DedupState::InFlight, false);
    CHECK(d.action == DedupAction::AnswerRunning);
    CHECK_FALSE(d.owns_claim);
}

TEST_CASE("should_claim: __guard__ is the ONLY reserved name that bypasses the claim",
          "[command_dedup][decision]") {
    CHECK_FALSE(should_claim(true, "cmd-1", "__guard__"));
    // Invariant 3: the gate is the literal, so dedup is the SAFE DEFAULT for every other
    // reserved name, including one that does not exist yet.
    CHECK(should_claim(true, "cmd-1", "__sync__"));
    CHECK(should_claim(true, "cmd-1", "__update__"));
    CHECK(should_claim(true, "cmd-1", "__guard__x"));
    CHECK(should_claim(true, "cmd-1", "__guard_"));
    // Exact literal only: a case variant is a different plugin name and is claimed.
    CHECK(should_claim(true, "cmd-1", "__GUARD__"));
    CHECK(should_claim(true, "cmd-1", "echo"));
    CHECK(should_claim(true, "cmd-1", ""));
}

TEST_CASE("should_claim: an empty command_id or an absent store is never claimed",
          "[command_dedup][decision]") {
    CHECK_FALSE(should_claim(true, "", "echo"));
    CHECK_FALSE(should_claim(false, "cmd-1", "echo"));
    CHECK_FALSE(should_claim(false, "", "echo"));
}
