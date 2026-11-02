#pragma once

/// @file command_dedup_decision.hpp
/// Pure decision core for the agent's durable command-dedup claim block (HA WS-0,
/// ADR-2002, issue #3668) — factored out of agent.cpp's Subscribe command-read
/// loop per this repo's "pure core, thin shell" discipline (see
/// sync_now_decision.hpp, docs/testing/unit-test-conventions.md). agent.cpp is not
/// gRPC-test-harnessed, so before this extraction nothing tested the claim block's
/// decision at all: CommandDedupStore's own tests cover the store, not the loop's
/// use of it.
///
/// Two layers pin it, and neither covers the other's half:
///   - tests/unit/test_command_dedup_decision.cpp pins the DECISION (these
///     functions), plus the compile-time checks at the bottom of this header.
///   - tests/test_agent_command_dedup_wiring_lexical.py pins the SHELL's use of it
///     (agent.cpp still calls both functions, acts on `owns_claim` and
///     `count_claim_error`, and `continue`s after answering a duplicate). It is
///     lexical, so a relocation that keeps the tokens but changes control flow is
///     review-enforced.
///
/// The claim itself (`CommandDedupStore::claim`) is a side effect, so the decision
/// is split around it:
///
///   1. should_claim()        — BEFORE the claim: is this command claimed at all?
///   2. decide_after_claim()  — AFTER the claim: replay / answer RUNNING / proceed.
///
/// Invariants this header is the tested home of (docs/command-dedup.md):
///   - #3  `__guard__` is the ONLY dispatch that bypasses the claim. The gate is the
///         literal, NOT the reserved-name set, so dedup stays the SAFE DEFAULT for
///         `__sync__` and any future reserved name (e.g. an OTA `__update__`).
///   - #4  A duplicate NEVER re-executes. Terminal replays the stored frame;
///         InFlight — and a Terminal whose stored blob will not parse — answers
///         RUNNING (indeterminate). No Duplicate input ever yields Proceed.
///   - #7  A store failure (ClaimStatus::Error) is a DELIBERATE fail-OPEN: the
///         command proceeds undeduplicated, owns no claim, and the decision flags
///         `count_claim_error` so the shell MUST make it observable
///         (`yuzu_agent_dedup_claim_errors_total`), never silent.
///
/// What stays OUTSIDE (unchanged in agent.cpp): the claim() call, parsing the stored
/// blob, logging, metrics, the `sent_at` refresh on replay, the RUNNING frame's
/// text, stream_write_mu_ + Write + continue, and the queue-full release() (its
/// gate `command_dedup_ && claimed_here` takes `claimed_here` from `owns_claim`
/// below).
///
/// Header-only and proto-free: the shell parses the stored blob into a
/// pb::CommandResponse (only for Duplicate+Terminal) and passes the bool, so this
/// header includes none of the generated-proto path.

#include <yuzu/agent/command_dedup_store.hpp>

#include <string_view>

namespace yuzu::agent {

/// What the Subscribe loop does with a command after consulting dedup.
enum class DedupAction {
    Proceed,       ///< fall through to dispatch (Claimed, or fail-open Error)
    ReplayStored,  ///< duplicate, terminal outcome parsed: write the stored frame, do not run
    AnswerRunning, ///< duplicate, no usable terminal outcome: write RUNNING, do not run
};

struct DedupDecision {
    DedupAction action{DedupAction::Proceed};
    /// True only when THIS delivery's claim succeeded (ClaimStatus::Claimed). Becomes
    /// the shell's `claimed_here`, gating the queue-full release() so it can never
    /// delete a concurrent first delivery's in-flight row (invariant 1).
    bool owns_claim{false};
    /// True when the store failed (ClaimStatus::Error): the shell MUST increment
    /// `yuzu_agent_dedup_claim_errors_total` (invariant 7 — fail-open stays observable).
    bool count_claim_error{false};
};

/// The one reserved plugin name that bypasses the claim (invariant 3).
///
/// COUPLED to agent.cpp's reserved-name dispatch: the claim is skipped for this name
/// ONLY because that dispatch branch resolves the command itself (its own write +
/// `continue`). If the claim bypass and that branch named different strings, a
/// bypassed command would fall through to plugin dispatch, or a claimed one would be
/// left unresolved (RUNNING-forever on every re-send). agent.cpp therefore compares
/// against this constant at the dispatch site, and the wiring gate pins that.
inline constexpr std::string_view kDedupBypassPlugin = "__guard__";

/// Whether this command goes through CommandDedupStore::claim() at all.
///
/// False when there is no store (durable dedup unavailable — already surfaced via
/// `yuzu.dedup_degraded`), when `command_id` is empty (it cannot be keyed; the shell
/// logs the replay-protection warning), or when the plugin is the literal
/// `__guard__`. Everything else — including `__sync__` and any future reserved
/// name — is claimed.
[[nodiscard]] constexpr bool should_claim(bool store_present, std::string_view command_id,
                                          std::string_view plugin) noexcept {
    return store_present && !command_id.empty() && plugin != kDedupBypassPlugin;
}

/// Decide what to do once claim() has answered.
///
///   status             - ClaimResult::status.
///   state              - ClaimResult::state (meaningful only for Duplicate).
///   stored_blob_parses - whether the shell parsed ClaimResult::response into a
///                         CommandResponse; only consulted for Duplicate+Terminal.
[[nodiscard]] constexpr DedupDecision decide_after_claim(ClaimStatus status, DedupState state,
                                                         bool stored_blob_parses) noexcept {
    switch (status) {
    case ClaimStatus::Claimed:
        return {DedupAction::Proceed, /*owns_claim=*/true, /*count_claim_error=*/false};
    case ClaimStatus::Error:
        // Deliberate fail-open: run undeduplicated, own nothing, make it observable.
        return {DedupAction::Proceed, /*owns_claim=*/false, /*count_claim_error=*/true};
    case ClaimStatus::Duplicate:
        if (state == DedupState::Terminal && stored_blob_parses)
            return {DedupAction::ReplayStored, false, false};
        // InFlight, or a Terminal outcome we cannot replay: indeterminate, never re-run.
        return {DedupAction::AnswerRunning, false, false};
    }
    // Unreachable for a valid ClaimStatus. Fail SAFE: a corrupt/unknown status must
    // never read as "go ahead and execute" with a claim we do not own.
    return {DedupAction::AnswerRunning, false, false};
}

// Compile-time self-checks: these invariants fail the BUILD on every compiler, not only
// the unit-test run. Invariant 3 (literal-only bypass), 4 (no Duplicate proceeds) and
// the fail-safe for a status this function does not know.
static_assert(!should_claim(true, "c", "__guard__"));
static_assert(should_claim(true, "c", "__sync__"));
static_assert(should_claim(true, "c", "__update__"));
static_assert(!should_claim(true, "", "echo"));
static_assert(!should_claim(false, "c", "echo"));
static_assert(decide_after_claim(ClaimStatus::Duplicate, DedupState::InFlight, true).action ==
              DedupAction::AnswerRunning);
static_assert(decide_after_claim(ClaimStatus::Duplicate, DedupState::Terminal, false).action ==
              DedupAction::AnswerRunning);
static_assert(decide_after_claim(static_cast<ClaimStatus>(99), DedupState::InFlight, false)
                  .action == DedupAction::AnswerRunning);

} // namespace yuzu::agent
