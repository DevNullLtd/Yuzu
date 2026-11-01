#pragma once

#include <string>
#include <string_view>
#include <type_traits>

/// @file gateway_forward_guard.hpp
/// The spawn/setup guard around `ServerImpl::forward_gateway_pending`'s per-command body,
/// extracted from `server.cpp` so its failure handling is unit-testable without a live
/// gateway stub, a thread spawn that can be made to fail, or an `AgentServiceImpl`.
///
/// Header-only and I/O-free: no logging, no protobuf, no registry. The resolver (the terminal
/// write) and the two log lines are injected as callables, so `server.cpp` supplies the real
/// `apply_gateway_forward_terminal_failure` and `spdlog` calls and the tests supply recorders.
///
/// What the guard exists to do: the per-command body allocates and spawns a thread, and either
/// can throw (`bad_alloc`, `std::system_error`) under exactly the resource pressure that
/// makes a spawn fail. Dispatch has already counted each drained command as SENT, so an
/// escape would unwind the drain loop and destroy every not-yet-forwarded command with no
/// terminal response. `guarded_forward` catches, resolves the command terminally (best
/// effort, never twice) and returns, so the caller's loop continues to the next command.
///
/// The three pieces of state the handler needs outlive the body, hence `ForwardAttempt`:
///   - `cmd_id` / `agent_id` are copies the body takes BEFORE it moves the drained entry into
///     the worker closure. While they are empty the entry has not been moved from, so the
///     handler falls back to it (lazily, through the fallback callables).
///   - `resolve_attempted` goes up immediately before the one non-idempotent step
///     (`process_gateway_response`, via `resolve_with_flag`); once up, the handler never
///     resolves the command a second time.
namespace yuzu::server {

/// Closed reason code and stored detail text for a command whose forwarding could not be set
/// up or started. The detail is what `build_gateway_forward_terminal_failure` prefixes with
/// `[reason]` and persists; its wording is part of the stored-row contract.
inline constexpr std::string_view kGatewayForwardSpawnFailedReason = "gateway_forward_spawn_failed";
inline constexpr std::string_view kGatewayForwardSpawnFailedDetail =
    "The server could not set up or start the thread that forwards this command to the "
    "gateway (resource exhaustion), command not delivered";

struct ForwardAttempt {
    std::string cmd_id;
    std::string agent_id;
    bool resolve_attempted = false;

    void reset() noexcept {
        cmd_id.clear();
        agent_id.clear();
        resolve_attempted = false;
    }
};

/// "Build, THEN raise the flag, THEN apply." Every allocation (the detail text, the protobuf)
/// happens in `build`, while the flag is still down: a `bad_alloc` there leaves the flag false,
/// so the handler still resolves the command. The flag goes up immediately before `apply`,
/// the one non-idempotent step, whose partial failure the handler does NOT retry.
template <class Build, class Apply>
void resolve_with_flag(ForwardAttempt& attempt, Build&& build, Apply&& apply) {
    const auto response = build();
    attempt.resolve_attempted = true;
    apply(response);
}

/// Run `body(attempt)` for one drained command; on ANY exception resolve it terminally and
/// return normally.
///
///   fallback_cmd_id()   -> const std::string&   the drained entry's own command id
///   fallback_agent_id() -> const std::string&   the drained entry's own agent id
///       Both are evaluated only inside the handler and only while the matching hoisted copy
///       is empty: the entry is moved from once the body has taken its copies, so evaluating
///       them eagerly (or after the move) would read a moved-from entry.
///   resolve(agent_id, cmd_id, reason, detail)   the terminal write (may throw)
///   log_setup_failed(agent_id, cmd_id, resolved)   error line for the not-yet-resolved case
///   log_not_retried(cmd_id)   error line for the resolve-already-attempted case
///
/// Every resolver and logger call keeps its own try/catch(...): the resolver allocates, so
/// under the same pressure it can fail too, and a logger can throw; neither may escape and
/// stop the caller's loop.
template <class Body, class FallbackCmdId, class FallbackAgentId, class Resolver,
          class LogSetupFailed, class LogNotRetried>
void guarded_forward(ForwardAttempt& attempt, Body&& body, FallbackCmdId&& fallback_cmd_id,
                     FallbackAgentId&& fallback_agent_id, Resolver&& resolve,
                     LogSetupFailed&& log_setup_failed, LogNotRetried&& log_not_retried) {
    static_assert(std::is_same_v<std::invoke_result_t<FallbackCmdId&>, const std::string&>,
                  "fallback_cmd_id must return const std::string& (no temporary)");
    static_assert(std::is_same_v<std::invoke_result_t<FallbackAgentId&>, const std::string&>,
                  "fallback_agent_id must return const std::string& (no temporary)");
    attempt.reset();
    try {
        body(attempt);
    } catch (...) {
        if (!attempt.resolve_attempted) {
            bool resolved = false;
            try {
                const std::string& cid =
                    attempt.cmd_id.empty() ? fallback_cmd_id() : attempt.cmd_id;
                const std::string& aid =
                    attempt.agent_id.empty() ? fallback_agent_id() : attempt.agent_id;
                resolve(aid, cid, kGatewayForwardSpawnFailedReason,
                        kGatewayForwardSpawnFailedDetail);
                resolved = true;
            } catch (...) { // NOLINT(bugprone-empty-catch): reported just below
            }
            try {
                const std::string& cid =
                    attempt.cmd_id.empty() ? fallback_cmd_id() : attempt.cmd_id;
                const std::string& aid =
                    attempt.agent_id.empty() ? fallback_agent_id() : attempt.agent_id;
                log_setup_failed(aid, cid, resolved);
            } catch (...) { // NOLINT(bugprone-empty-catch): last resort; the loop continues
            }
        } else {
            try {
                log_not_retried(attempt.cmd_id);
            } catch (...) { // NOLINT(bugprone-empty-catch): last resort; the loop continues
            }
        }
    }
}

} // namespace yuzu::server
