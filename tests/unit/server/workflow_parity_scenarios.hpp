/**
 * workflow_parity_scenarios.hpp -- the ONE table of replay-parity scenarios (#2146).
 *
 * Two matrices prove the same rule ("a replay of a keyed workflow run says what the first answer
 * said, and `completed` only for a success"): the stand-in matrix in
 * test_workflow_execute_twins.cpp (no Postgres, a hand-written engine that persists the step rows
 * it scripts) and the real-engine matrix in test_workflow_engine.cpp ([pg], the rows the engine
 * itself writes). Both take each scenario's expected first-answer class and reason from THIS table
 * via `parity_scenario("<key>")`, so a scenario that both run is expected to end the same way in
 * both.
 *
 * Which matrix runs which scenario is declared here (`in`), and a scenario only one matrix runs
 * says why in `why_one_sided`. tests/test_workflow_parity_scenarios_lexical.py compares the keys
 * each source file passes to `parity_scenario("...")` with this table, so a scenario added to one
 * matrix (or dropped from one) without the table failing a gate is not possible. Keys are
 * lower-case words joined by underscores; each is passed as a plain string literal.
 */
#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

namespace yuzu::server::parity {

enum class Matrix { kStandIn, kReal, kBoth };

struct Scenario {
    std::string_view key;
    std::string_view expected_class;  // the first answer's run_outcome token
    std::string_view expected_reason; // the closed-set reason the outcome counter carries
    Matrix in;
    std::string_view why_one_sided; // empty for kBoth
};

// clang-format off
inline constexpr Scenario kScenarios[] = {
    {"succeeded", "succeeded", "none", Matrix::kBoth, ""},
    {"continue_later_step_missed", "partial", "none", Matrix::kBoth, ""},
    {"continue_first_step_missed", "partial", "none", Matrix::kBoth, ""},
    {"nothing_reached", "failed", "quarantined", Matrix::kBoth, ""},
    {"same_instruction_twice", "partial", "none", Matrix::kBoth, ""},
    {"retried_to_success", "succeeded", "none", Matrix::kBoth, ""},
    {"retried_still_failing_only_step", "failed", "quarantined", Matrix::kBoth, ""},
    {"late_denied", "aborted", "late_denied", Matrix::kBoth, ""},
    {"late_denied_first_step", "aborted", "late_denied", Matrix::kBoth, ""},
    {"definition_changed", "aborted", "definition_changed", Matrix::kBoth, ""},
    {"interrupted_after_step_1", "interrupted", "server_shutdown", Matrix::kBoth, ""},
    {"interrupted_before_anything_sent", "interrupted", "server_shutdown", Matrix::kBoth, ""},
    {"credential_revoked", "aborted", "credential_revoked", Matrix::kBoth, ""},
    {"credential_indeterminate", "aborted", "credential_indeterminate", Matrix::kBoth, ""},
    {"deadline_between_steps", "aborted", "deadline_exceeded", Matrix::kBoth, ""},
    {"deadline_before_first_attempt", "aborted", "deadline_exceeded", Matrix::kBoth, ""},
    {"dispatch_threw", "failed", "dispatch_exception", Matrix::kBoth, ""},
    // The stand-in scripts an engine status of `failed`; the real engine reaches a non-completed run
    // whose every attempted step reached only through cancel_execution, so its row ends `cancelled`.
    // Both must call it partial: the engine's own word is never the replay's.
    {"engine_not_completed_every_attempted_step_reached", "partial", "none", Matrix::kBoth, ""},
    {"retried_still_failing_then_continue", "partial", "none", Matrix::kReal,
     "the stand-in has no per-step retry policy beside onFailure, only a scripted engine status"},
    {"abort_later_step_missed", "partial", "none", Matrix::kReal,
     "the stand-in scripts the engine status instead of running an onFailure policy"},
    {"late_denied_then_continue", "aborted", "late_denied", Matrix::kReal,
     "the stand-in has no per-step onFailure: continue to carry on from"},
};
// clang-format on

inline constexpr std::size_t kScenarioCount = sizeof(kScenarios) / sizeof(kScenarios[0]);

/// The scenario for `key`. An unknown key throws, so a typo fails the case that spelled it.
[[nodiscard]] inline const Scenario& parity_scenario(std::string_view key) {
    for (const auto& s : kScenarios) {
        if (s.key == key)
            return s;
    }
    throw std::logic_error("unknown workflow parity scenario: " + std::string(key));
}

[[nodiscard]] constexpr bool runs_in_real(const Scenario& s) {
    return s.in != Matrix::kStandIn;
}
[[nodiscard]] constexpr bool runs_in_stand_in(const Scenario& s) {
    return s.in != Matrix::kReal;
}

} // namespace yuzu::server::parity
