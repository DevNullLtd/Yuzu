#pragma once
/**
 * services_set_start_mode.hpp -- the Linux `services.set_start_mode` body, behind a runner seam.
 *
 * The body (mode validation, the prior `is-enabled` read, the best-effort unmask, the privileged
 * change, the closed-set readback, the re-mask after a failed change, the masked-runtime refusal,
 * the `state|`/`note|` lines and the typed CONSTRAINED status) is a template over its three
 * collaborators so tests/unit/test_services_parsers.cpp can drive it with a FAKE runner and a
 * recording sink, with no systemd, no sudo and no subprocess:
 *
 *   Ctx            write_output(std::string_view) and set_result_status(status, completeness,
 *                  provenance): a yuzu::CommandContext in the plugin, a recording fake in tests
 *   run_command    (const std::vector<std::string>& argv, bool merge_stderr = true) ->
 *                  yuzu::agent::SubprocessResult
 *   forward_failure(const SubprocessResult&)   forwards a runner-level failure (the plugin passes
 *                  yuzu::agent::forward_runner_failure bound to its ctx)
 *
 * The privileged argv is dev's systemctl_set_start_mode_argv (services_parsers.hpp): a non-root
 * agent goes through the root-owned yuzu-svc-helper, a root agent runs systemctl itself.
 */

#include "services_parsers.hpp"

#include <yuzu/agent/runner_status.hpp>
#include <yuzu/agent/subprocess_runner.hpp>

#include <format>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::services {

template <class Ctx, class Run, class Forward>
inline int set_start_mode_linux(Ctx& ctx, Run&& run_command, Forward&& forward_failure,
                                std::string_view systemctl_path, std::string_view name,
                                std::string_view mode, bool euid_is_root) {
    if (mode != "automatic" && mode != "manual" && mode != "disabled") {
        ctx.write_output(
            std::format("error|invalid mode '{}': must be automatic, manual, or disabled", mode));
        return 1;
    }
    const char* verb = mode == "automatic" ? "enable" : mode == "manual" ? "disable" : "mask";
    const auto build = [&](std::string_view v) {
        return yuzu::services::systemctl_set_start_mode_argv(systemctl_path, v, name,
                                                             euid_is_root);
    };
    const std::vector<std::string> argv = build(verb);

    bool was_masked = false;
    if (yuzu::services::start_mode_needs_unmask(mode)) {
        // `enable` and `disable` both fail on a masked unit, so for automatic and manual unmask
        // first. Best-effort: its result is intentionally not inspected (a unit that was never
        // masked has nothing to unmask and `unmask` exits 0 for it; the following enable or
        // disable is the actual mode change). The state is read first (unprivileged, stderr
        // unmerged) so a failed change can put the mask back (remask_after_failure below).
        // services/set_start_mode_linux#2 (docs/agent-spawn-sink-manifest.md): the prior-state
        // read; the post-change readback below is the same site.
        const auto prior = run_command({std::string{systemctl_path}, "is-enabled", "--",
                                        std::string(name)},
                                       /*merge_stderr=*/false);
        if (!yuzu::services::start_prior_state_known(prior)) {
            // The first read did not run, was cut by the deadline, or gave a state this plugin does
            // not know: whether the unit is masked is UNKNOWN, and unmasking a unit that is in fact
            // masked would leave it unmasked if the change then fails (nothing could be restored).
            // Nothing is changed.
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "services:start_mode_prior_unreadable");
            ctx.write_output(std::format(
                "error|set_start_mode: could not read the current state of '{}' (is-enabled "
                "did not run to completion or answered with an unrecognised state), so mode '{}' "
                "was not applied and nothing was changed",
                name, mode));
            return 1;
        }
        was_masked = prior.tool_ran && !prior.timed_out &&
                     yuzu::services::start_state_is_masked(prior.output);
        if (prior.tool_ran && !prior.timed_out &&
            yuzu::services::start_state_is_runtime_masked(prior.output)) {
            // masked-runtime: `unmask` cannot remove a runtime mask and a re-mask would write a
            // persistent one, so nothing is changed.
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "services:start_mode_runtime_mask");
            ctx.write_output(std::format(
                "error|set_start_mode: '{}' is masked for this boot only (is-enabled: "
                "masked-runtime); the privileged helper cannot remove a runtime mask, so mode "
                "'{}' was not applied and nothing was changed. Remove it with `systemctl unmask "
                "--runtime` as root, or reboot",
                name, mode));
            return 1;
        }
        run_command(build("unmask"));
    }
    // A failed change after the unmask would leave the unit LESS restricted than it was found:
    // put the mask back through the same helper and say so on a separate line.
    auto remask_after_failure = [&]() {
        if (!yuzu::services::start_mode_should_remask(mode, was_masked, /*change_succeeded=*/false))
            return;
        const auto r = run_command(build("mask"));
        if (r.tool_ran && !r.timed_out && r.exit_code == 0)
            ctx.write_output(std::format("note|remasked: '{}' was masked before this call and the "
                                         "change failed, so the mask was restored", name));
        else
            ctx.write_output(std::format("note|remask_failed: '{}' was masked before this call, the "
                                         "change failed and the mask could not be restored; the "
                                         "unit may now be unmasked", name));
    };

    auto res = run_command(argv);
    // A runner-level failure (spawn error / deadline / cancelled / signaled)
    // must be reported through the ABI4 status seam as a distinguishable
    // TIMEOUT/CONSTRAINED (or UNAVAILABLE) status -- never collapsed into
    // the generic "exit=-1" error string below, which previously hid the
    // difference between "systemctl ran and failed" and "the runner never
    // got a real exit at all". The decision itself is the pure
    // yuzu::services::decide_set_start_mode_outcome (services_parsers.hpp,
    // fixture-tested in tests/unit/test_services_parsers.cpp); only the
    // ctx.set_result_status forwarding stays here.
    auto outcome = yuzu::services::decide_set_start_mode_outcome("systemctl", name, res);
    if (outcome.runner_failed) {
        forward_failure(res);
    }
    if (!outcome.ok) {
        ctx.write_output(outcome.message);
        remask_after_failure();
        return 1;
    }

    // WP13 UP11: a root-owned helper that exits 0 without acting (empty/replaced file) would
    // otherwise be reported as success. Read the unit's state back (no privilege needed) and
    // require it to match the requested mode; a readback that did not run, or any state outside
    // the closed set for the mode, is a failure.
    std::string st_state;
    {
        // stderr is NOT merged: a SysV-only unit prints "X is not a native service, redirecting
        // to systemd-sysv-install." on stderr before the state, and the first output line must be
        // the state itself (the parser is deliberately not loosened to scan for one).
        auto st = run_command({std::string{systemctl_path}, "is-enabled", "--", std::string(name)},
                              /*merge_stderr=*/false);
        if (yuzu::agent::classify_runner_failure(st).has_value())
            forward_failure(st);
        if (!yuzu::services::start_mode_readback_matches(mode, st)) {
            ctx.write_output(std::format(
                "error|set_start_mode: '{}' is not in mode '{}' after the privileged helper ran "
                "(is-enabled: '{}'); the helper may not have acted, or the unit is in a state "
                "that mode does not accept (for example linked). Check `systemctl is-enabled` "
                "on the host before retrying",
                name, mode, st.output.substr(0, st.output.find('\n'))));
            remask_after_failure();
            return 1;
        }
        st_state = st.output;
    }

    ctx.write_output("status|ok");
    ctx.write_output(std::format("service|{}", name));
    ctx.write_output(std::format("mode|{}", mode));
    // The state the unit is actually in (first is-enabled line), so a caller can tell a unit
    // that will auto-start from one that cannot be enabled or disabled.
    {
        std::string state = st_state.substr(0, st_state.find('\n'));
        while (!state.empty() && (state.back() == '\r' || state.back() == ' '))
            state.pop_back();
        ctx.write_output(std::format("state|{}", state));
        if (yuzu::services::start_state_is_unchangeable(state)) {
            ctx.write_output(std::format(
                "note|'{}' is '{}': systemctl cannot enable or disable it, so the requested mode "
                "does not change whether it starts at boot{}", name, state,
                was_masked ? "; it was masked before this call and is now unmasked" : ""));
            // The requested change was accepted but could not be applied to this unit kind: a
            // typed CONSTRAINED/PARTIAL so a machine reader does not take `status|ok` for "the
            // unit now starts (or no longer starts) at boot". rc stays 0: the command ran and the
            // unit is in a state `systemctl enable|disable` itself accepts (the host's
            // SUCCESS/FAILURE comes from rc; the typed status travels separately).
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "services:start_mode_unchangeable");
        }
    }
    return 0;
}

} // namespace yuzu::services
