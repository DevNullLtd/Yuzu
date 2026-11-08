/**
 * virtualization_legs.hpp -- shared seam between the virtualization plugin TU and its three
 * per-OS leg TUs (mgmt_posture_legs.hpp shape).
 *
 * Holds (a) the per-OS entry-point declarations, (b) report, the SINGLE owner of every
 * `status|<action>|...` row (no leg and no parser writes one), pairing each status with its result
 * status/completeness (report_host is its `host` form), (c) execute_action, the plugin's whole
 * execute() body (dispatch over the Legs table + ABI containment), and (d) `decide`, the OS-free
 * pairing of the pure classifiers with the status decision for `host`. The leg TUs keep only the
 * OS shell: they read, fill a Facts and call report_host(ctx, decide(facts)). The `wsl` action's
 * decision lives in virtualization_wsl_parsers.hpp (decide_wsl).
 *
 * Reason propagation, one rule: every failed-read token (and the permanent `cpuid:unavailable`
 * limitation, when it is why the kind is unknown) goes into one ConstraintAccumulator; the
 * status is `constrained` iff the accumulator is non-empty and its joined string is the status
 * row's reason. Each entry point is a READ and returns 0: a degraded read is not a failed
 * command.
 */
#pragma once

#include "virtualization_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::virtualization {

int run_windows(yuzu::CommandContext& ctx);
int run_linux(yuzu::CommandContext& ctx);
int run_macos(yuzu::CommandContext& ctx);
int run_windows_wsl(yuzu::CommandContext& ctx);
int run_linux_wsl(yuzu::CommandContext& ctx);
int run_macos_wsl(yuzu::CommandContext& ctx);

enum class StatusState { supported, constrained, unsupported };

inline std::string_view status_token(StatusState s) {
    switch (s) {
    case StatusState::supported:
        return "supported";
    case StatusState::constrained:
        return "constrained";
    case StatusState::unsupported:
        return "unsupported";
    }
    return "unsupported";
}

inline std::string format_status_row(std::string_view action, StatusState s,
                                     std::string_view reason) {
    std::string r = "status|";
    r += action;
    r += '|';
    r += status_token(s);
    r += '|';
    r += reason.empty() ? std::string{"-"} : yuzu::util::safe_output_field(reason);
    return r;
}

/// What a leg decided: the status, its reason token(s), and the data rows.
struct Posture {
    StatusState status = StatusState::supported;
    std::string reason;
    std::vector<std::string> rows;
};

/// Writes the status row FIRST, then the data rows, then the paired result status.
/// `unsupported` (a leg that read nothing) pairs with UNAVAILABLE/UNKNOWN.
inline void report(yuzu::CommandContext& ctx, std::string_view action, const Posture& p) {
    ctx.write_output(format_status_row(action, p.status, p.reason));
    for (const auto& r : p.rows)
        ctx.write_output(r);
    switch (p.status) {
    case StatusState::constrained:
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              p.reason);
        break;
    case StatusState::unsupported:
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                              p.reason);
        break;
    case StatusState::supported:
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        break;
    }
}

inline void report_host(yuzu::CommandContext& ctx, const Posture& p) { report(ctx, "host", p); }

/// A leg that read nothing: ONE `unsupported` status row carrying the token.
/// Callers: execute_action's catch arm (`<os>:leg:exception`) and the non-Windows `wsl` legs.
inline void report_unavailable(yuzu::CommandContext& ctx, std::string_view action,
                               std::string_view token) {
    report(ctx, action, Posture{StatusState::unsupported, std::string{token}, {}});
}

/// The OS-free decision: classify the host and the container, accumulate every constraint token.
inline Posture decide(const Facts& f) {
    const Classification host = classify(f);
    const ContainerVerdict container = classify_container(f);

    yuzu::shared::ConstraintAccumulator acc;
    for (const auto& t : host.tokens)
        acc.add_failure(t);
    if (container.read_failed)
        acc.add_failure(container.evidence);
    // A marker hit hides a failed cgroup read from the verdict; the status still reports it.
    if (f.container.mode == ContainerInputs::Mode::linux_read && !f.container.reason.empty())
        acc.add_failure(f.container.reason);

    Posture p;
    p.status = acc.any_failure() ? StatusState::constrained : StatusState::supported;
    p.reason = acc.reason();
    p.rows.push_back(format_host_row(host));
    p.rows.push_back(format_container_row(container));
    return p;
}

using LegFn = int (*)(yuzu::CommandContext&);

/// The per-OS leg of each action.
struct Legs {
    LegFn host;
    LegFn wsl;
};

/// The WHOLE body of the plugin's execute(): dispatch and the single ABI containment.
/// Status-row contract: one status row per dispatch, with three exceptions. (1) An unknown
/// action writes ONE non-status line (`unknown action: <name>`, invalid UTF-8 replaced and the
/// rest escaped) and returns 1: no status row. (2) A leg that throws AFTER report already
/// wrote its row gets the catch arm's `unsupported` row (named for the action) appended, so
/// there are TWO and the LAST status row wins. (3) The recovery itself allocates, so it is
/// guarded too: if it throws as well, the dispatch returns 1 rather than unwinding across the
/// plugin ABI.
inline int execute_action(yuzu::CommandContext& ctx, std::string_view action, const Legs& legs,
                          std::string_view leg_exception_token) {
    std::string_view known = "host";
    try {
        LegFn leg = nullptr;
        if (action == "host") {
            leg = legs.host;
        } else if (action == "wsl") {
            leg = legs.wsl;
            known = "wsl";
        } else {
            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(
                                 yuzu::util::sanitize_utf8(std::string{action})));
            return 1;
        }
        return leg(ctx);
    } catch (...) {
        try {
            report_unavailable(ctx, known, leg_exception_token);
        } catch (...) {
            return 1;
        }
        return 0;
    }
}

} // namespace yuzu::virtualization
