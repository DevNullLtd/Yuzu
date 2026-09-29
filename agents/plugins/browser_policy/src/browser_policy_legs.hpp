/**
 * browser_policy_legs.hpp — shared seam between the browser_policy plugin TU
 * and its three per-OS leg TUs (peripherals_legs.hpp / disk_actions_legs.hpp
 * are the sibling shape).
 *
 * Each `run_<os>` is a READ and returns 0 unconditionally: a degraded read
 * is not a failed command, and the degradation is reported through the CC-07
 * typed status (`mark_result_read`) AND as one in-band `status` row (the
 * response queries do not return the typed status today). Only the Linux leg
 * reads today; the Windows and macOS legs are PLANNED placeholders that report
 * `mark_result_planned` (UNAVAILABLE, one `status` row) so a host they cannot
 * yet inspect never reads as "no policy configured". Declared unconditionally so
 * the plugin TU and every leg TU see one signature on every OS; only the
 * DEFINITION is self-gated (each leg .cpp wraps its body in
 * `#if defined(_WIN32|__linux__|__APPLE__)`), and the plugin TU calls only
 * the host leg — a single-OS build never links the other two.
 *
 * WHEN A LEG LANDS (Windows registry, macOS plist): replace its `mark_result_planned`
 * body with a real read that reports through `mark_result_read` BEFORE writing rows, then
 * grep the tree for "planned" and "follows as its own PR" and update every hit -- known
 * sites at the time this was written: the descriptor legs in browser_policy_plugin.cpp
 * (support level, mechanism, notes; the leg-hash changes, so run `plugin_doc_gen.py
 * --stamp` for both samples), the yaml header comment, `platforms` and the `scope`/`source`
 * column wording, the README (How it works, the mermaid diagram, Privileges, Result
 * status, Sensitivity, Sample, Caveats 3), the planned blocks in
 * test_browser_policy_local_dispatcher.cpp, docs/agent-privilege-model.md's row, the
 * capability matrix row and counts, the capability-map cell, the catalogue header comment,
 * the agent_registry description, and the changelog fragment. The grep is the actual
 * completeness check; this list is a starting point, not a closed set.
 */
#pragma once

#include "browser_policy_parsers.hpp" // format_status_row

#include <yuzu/plugin.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::browser_policy {

int run_windows(yuzu::CommandContext& ctx);
int run_linux(yuzu::CommandContext& ctx);
int run_macos(yuzu::CommandContext& ctx);

/// Reason literal for an exception that escaped a leg (never crosses the
/// plugin ABI: run_guarded, below, catches it and reports it through this token).
#if defined(_WIN32)
inline constexpr std::string_view kExceptionToken = "windows:leg:exception";
#elif defined(__APPLE__)
inline constexpr std::string_view kExceptionToken = "macos:leg:exception";
#else
inline constexpr std::string_view kExceptionToken = "linux:leg:exception";
#endif

/// The ONE place a leg's exception is contained (frozen-seam rule: nothing
/// crosses the plugin ABI). Runs `leg(ctx)`; if it throws, reports
/// UNAVAILABLE/PARTIAL with kExceptionToken and returns 1. The plugin TU runs
/// its WHOLE execute body through this — the unknown-action refusal included.
/// The unit suite drives THIS template with a throwing leg (MUTATION: dropping
/// the catch, the set_result_status call or the token fails the exception case
/// in test_browser_policy_local_dispatcher.cpp). It cannot drive the plugin
/// TU's use of it: the real legs cannot be made to throw on demand, so that one
/// call site (browser_policy_plugin.cpp `execute`) is guarded by construction
/// and by review, not by a test.
template <typename Leg>
[[nodiscard]] inline int run_guarded(yuzu::CommandContext& ctx, Leg&& leg) {
    try {
        return leg(ctx);
    } catch (...) {
        // Each report is its own guard: building or writing the row, and the typed status
        // itself (the SDK copies the provenance into a std::string), can each throw on an
        // allocation failure, and none may let a second exception cross the plugin ABI. If the
        // typed status cannot be set, the rc of 1 below still makes the host report a failure.
        // A leg that throws AFTER it has already reported (an allocation failure inside
        // write_output) therefore leaves an `unavailable` row behind its own output: "written
        // first, at most one" holds for every outcome except that one.
        try {
            ctx.write_output(format_status_row(kStateUnavailable, kExceptionToken));
        } catch (...) {
        }
        try {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, kExceptionToken);
        } catch (...) {
        }
        return 1;
    }
}

/// Emits every row, one write_output each.
inline void write_rows(yuzu::CommandContext& ctx, const std::vector<std::string>& rows) {
    for (const auto& row : rows)
        ctx.write_output(row);
}

/// The ONE seam every leg reports a READ's outcome through (CC-07). Call it
/// BEFORE writing the rows, so the outcome leads the stream; rows written later
/// stand either way.
///   failure_reason empty  -> OK/FULL. Zero rows here is a genuinely absent
///                            policy set (browser not installed, nothing
///                            managed) — no row of any kind is written for it.
///   failure_reason set    -> CONSTRAINED/PARTIAL with the (comma-joined,
///                            `<os>:<detail>`) reason, AND one in-band
///                            `status|...|constrained|...|<reason>` row: some
///                            root, directory, file or value could not be read
///                            or decoded, so the rows are a lower bound, never
///                            proof of absence.
inline void mark_result_read(yuzu::CommandContext& ctx, std::string_view failure_reason) {
    if (!failure_reason.empty()) {
        ctx.write_output(format_status_row(kStateConstrained, failure_reason));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              failure_reason);
        return;
    }
    ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
}

/// The seam a PLANNED leg reports through: UNAVAILABLE/PARTIAL with the
/// `<os>:planned` provenance token, never CONSTRAINED, so a leg that has not
/// shipped is not counted as a degraded read, and ONE in-band
/// `status|...|unavailable|...|<os>:planned` row, no policy rows. A caller must
/// treat it as "this host was not inspected", never as an empty policy set.
inline void mark_result_planned(yuzu::CommandContext& ctx, std::string_view os_token) {
    ctx.write_output(format_status_row(kStateUnavailable, os_token));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          os_token);
}

} // namespace yuzu::browser_policy
