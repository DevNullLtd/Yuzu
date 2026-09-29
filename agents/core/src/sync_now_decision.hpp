#pragma once

/// @file sync_now_decision.hpp
/// Pure decision core for the agent's `__sync__.now` reserved command
/// (ADR-0016 update) — factored out of agent.cpp's main gRPC command-read
/// loop (agents/core/src/agent.cpp, the `cmd.plugin() == "__sync__"` branch)
/// per this repo's "pure core, thin shell" test discipline
/// (docs/testing/unit-test-conventions.md): the branch's actual DECISION —
/// given the requested action/source, whether the daily-sync scheduler is
/// even running, and (if so) what it says about the requested source — is
/// pulled out into decide_sync_now() below so it is unit-testable with zero
/// gRPC dependency and no live command-processing loop. Deliberately
/// proto-free, mirroring guardian_arm_heartbeat.hpp's GuardianArmStats /
/// guardian_emit_decider.hpp's EmitResult: `yuzu::agent::v1::CommandResponse
/// ::Status` is NOT used here — agent.cpp maps SyncNowDecision::Status onto
/// the proto enum at the call site — so this header stays includable from a
/// plain unit test with none of the generated-proto include path.
///
/// What stays OUTSIDE this function (unchanged in agent.cpp's loop): the
/// "source" parameter default-resolution (the cmd.parameters() lookup),
/// the yuzu_agent_commands_executed_total metrics counter, `sync_wake_`
/// (breaking the scheduler thread's sleep on a SUCCESS), record_command_
/// terminal (the dedup-terminal write — MUST happen before the stream Write;
/// see agent.cpp's own comment on this command), and the actual
/// stream->Write. None of those are "decision" logic — they are the shell's
/// side effects on the live agent / live stream.
///
/// Header-only inline (same shape as guardian_emit_decider.hpp): no state
/// crosses a DLL boundary. The one non-trivial dependency, SyncScheduler, is
/// itself gRPC/SQLite-free (see sync_scheduler.hpp) and already unit-tested
/// standalone (tests/unit/test_inventory_sync.cpp) via injected fake
/// kv_get/kv_set/sender lambdas — this header's own tests reuse that exact
/// construction pattern, against the real (not mocked) SyncScheduler.

#include "sync_scheduler.hpp"

#include <string>
#include <string_view>

namespace yuzu::agent {

/// Result of deciding a `__sync__.now` command — maps 1:1 onto the subset of
/// CommandResponse fields the loop populates for this reserved command
/// (status / exit_code / output).
struct SyncNowDecision {
    enum class Status { Success, Failure };
    Status status{Status::Failure};
    int exit_code{0};
    std::string output;
};

/// Decide the response for a `__sync__.now` reserved command.
///
///   action            - cmd.action(); only "now" is a recognised action.
///   source_param      - the "source" command parameter, ALREADY defaulted by
///                        the caller to SyncScheduler::kAllSources when the
///                        parameter is absent or empty.
///   inventory_disable - cfg_.inventory_disable; used only to pick between the
///                        two "scheduler not running" FAILURE messages.
///   sched             - the agent's current sync_scheduler_, or null when the
///                        daily-sync framework isn't running (e.g.
///                        --inventory-disable, or not yet connected).
///
/// Calls sched->request_now(source_param) exactly once when sched is
/// non-null (matching the original inline `else if (auto armed = ...)`) —
/// request_now() itself has a side effect, arming the scheduler's pending
/// list for its next tick, so this is a "decision" only in the sense the
/// original inline code was: the arm happens as part of computing the reply.
[[nodiscard]] inline SyncNowDecision decide_sync_now(std::string_view action,
                                                      std::string_view source_param,
                                                      bool inventory_disable,
                                                      SyncScheduler* sched) {
    if (action != "now") {
        return {SyncNowDecision::Status::Failure, 2,
                "unknown __sync__ action: " + std::string(action)};
    }
    if (!sched) {
        return {SyncNowDecision::Status::Failure, 1,
                inventory_disable ? "daily-sync disabled (--inventory-disable)"
                                   : "daily-sync not running (not connected)"};
    }
    auto armed = sched->request_now(source_param);
    if (armed.empty()) {
        std::string valid;
        for (const auto& n : sched->source_names())
            valid += (valid.empty() ? "" : ",") + n;
        return {SyncNowDecision::Status::Failure, 2,
                "unknown sync source '" + std::string(source_param) +
                    "' — expected one of " + valid + " or all"};
    }
    std::string names;
    for (const auto& n : armed)
        names += (names.empty() ? "" : ",") + n;
    return {SyncNowDecision::Status::Success, 0, "requested|" + names};
}

} // namespace yuzu::agent
