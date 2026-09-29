/**
 * runner_status.hpp — the ONE mapping from a bounded-runner outcome to the
 * ABI4 plugin→host result seam (ADR-3002 acquisition-ladder migration).
 * Consumers: every Wave-2 runner-migration plugin package (users, certificates,
 * discovery, network_actions, wol, quarantine, services, interaction) — the
 * first forwarders of a bounded-runner outcome through this seam.
 *
 * Lives in agents/core (not agents/shared): classify_runner_failure takes a
 * yuzu::agent::SubprocessResult, so it carries a core dependency edge and
 * doesn't qualify as an agents/shared zero-dependency leaf (cpp-conventions.md).
 * Every plugin already links yuzu_agent_core_dep, so this needs no extra
 * meson wiring at any consumer.
 * Maps every outcome EXCEPT `exited`: whether a nonzero exit code is an error
 * is the caller's domain (a nonzero `ping` exit means "host down", not a plugin
 * failure), so `exited` returns nullopt and the caller owns the status (or
 * leaves it for the agent's exit-code derivation).
 *
 * `line_limit` is deliberately NOT in that exemption — it is a truthful
 * OK/PARTIAL, not a silent success. ADR-3002 "Honest termination reporting"
 * names it in the reason enum and requires the reason to survive to the wire,
 * naming the plugin execute() integer return as the narrowing point that must
 * not flatten it.
 *
 * Kept a pure classification + a thin forwarding wrapper so the table is
 * fixture-testable without a context or a spawn.
 */
#pragma once

#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.hpp>

#include <optional>

namespace yuzu::agent {

struct RunnerFailureStatus {
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    const char* provenance; // static string; the host copies it synchronously
};

// Pure. nullopt => the child exited normally: the CALLER owns exit-code
// semantics. Every other reason, line_limit included, is reported.
inline std::optional<RunnerFailureStatus> classify_runner_failure(
    const SubprocessResult& r) {
    switch (r.termination_reason) {
    case TerminationReason::spawn_error:
        return RunnerFailureStatus{YUZU_RESULT_STATUS_UNAVAILABLE,
                                   YUZU_RESULT_COMPLETENESS_PARTIAL,
                                   "subprocess_runner:spawn_error"};
    case TerminationReason::deadline:
        return RunnerFailureStatus{YUZU_RESULT_STATUS_CONSTRAINED,
                                   YUZU_RESULT_COMPLETENESS_PARTIAL,
                                   "subprocess_runner:deadline"};
    case TerminationReason::cancelled:
        return RunnerFailureStatus{YUZU_RESULT_STATUS_CONSTRAINED,
                                   YUZU_RESULT_COMPLETENESS_PARTIAL,
                                   "subprocess_runner:cancelled"};
    case TerminationReason::signaled:
        return RunnerFailureStatus{YUZU_RESULT_STATUS_CONSTRAINED,
                                   YUZU_RESULT_COMPLETENESS_PARTIAL,
                                   "subprocess_runner:signaled"};
    case TerminationReason::line_limit:
        // A deliberate bounded stop: the runner SIGKILLed a still-producing
        // child once the line cap was reached. Not a failure — hence OK, not
        // CONSTRAINED — but the output is deliberately incomplete, so it is
        // PARTIAL and it carries its own reason.
        //
        // This must NOT fall through to nullopt with `exited`. ADR-3002's
        // "Honest termination reporting" names line_limit in the reason enum
        // and requires that "the reason must also survive to the wire",
        // identifying the plugin execute() integer return as the narrowing
        // point that must not flatten the distinction. Returning nullopt here
        // IS that flattening: an autonomous consumer could not tell a scan
        // deliberately cut at N lines from one that ran to completion.
        return RunnerFailureStatus{YUZU_RESULT_STATUS_OK,
                                   YUZU_RESULT_COMPLETENESS_PARTIAL,
                                   "subprocess_runner:line_limit"};
    case TerminationReason::exited:
        // Genuinely the caller's domain: whether a nonzero exit is an error is
        // plugin-specific (a nonzero `ping` exit means "host down").
        return std::nullopt;
    }
    return std::nullopt; // unreachable; keeps -Wswitch happy across compilers
}

// Thin non-pure wrapper: forwards a runner failure through the ABI4 result
// seam. Returns true when a status was set (the caller should usually stop
// treating the output as complete).
inline bool forward_runner_failure(yuzu::CommandContext& ctx,
                                   const SubprocessResult& r) {
    const auto s = classify_runner_failure(r);
    if (!s)
        return false;
    ctx.set_result_status(s->status, s->completeness, s->provenance);
    return true;
}

} // namespace yuzu::agent
