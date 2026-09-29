/**
 * network_actions_parsers.hpp — pure, header-only helper(s) for
 * network_actions_plugin.cpp (ADR-3002 pure-core/thin-shell discipline:
 * testable decision logic lives here, free of I/O, subprocess spawning, or
 * any OS call, so it is fixture-testable without a runner/context).
 */
#pragma once

#include <cstddef>
#include <string_view>
#include <vector>

namespace yuzu::network_actions {

// Linux flush_dns resolves to whichever of resolvectl/systemd-resolve
// probe_tool_path actually found (see network_actions_plugin.cpp's
// flush_dns_linux site) and then must invoke it with the RIGHT verb spelling:
// resolvectl (systemd-resolved's modern CLI) takes a bare subcommand
// ("flush-caches"); the older systemd-resolve CLI predates that convention
// and takes a long option ("--flush-caches") instead. This picks the verb
// that matches whichever absolute tool path was resolved.
inline std::string_view resolver_flush_flag(std::string_view tool_path) {
    constexpr std::string_view kSystemdResolve = "systemd-resolve";
    if (tool_path.size() >= kSystemdResolve.size() &&
        tool_path.substr(tool_path.size() - kSystemdResolve.size()) == kSystemdResolve) {
        return "--flush-caches";
    }
    return "flush-caches";
}

// Linux flush_dns's retry loop (network_actions_plugin.cpp) tries
// resolvectl, then falls back to systemd-resolve on ANY failure of the
// first attempt -- absent, OR present but failing at runtime (spawn error,
// service stopped/masked, dbus unreachable) -- restoring the old
// `resolvectl ... || systemd-resolve ... || true` shell chain's
// retry-ON-FAILURE semantics. A presence-only probe (try resolvectl if the
// file exists, never retry if it then fails) would silently narrow that
// away.
//
// One outcome per candidate, in try order (resolvectl first,
// systemd-resolve second).
struct DnsFlushAttemptOutcome {
    bool found{false};     // probe_tool_path found this candidate on disk
    bool succeeded{false}; // found AND the subprocess ran with exit code 0
};

struct DnsFlushDecision {
    bool attempted{false};              // at least one candidate was found and run
    std::size_t winning_index{static_cast<std::size_t>(-1)}; // index of the
                                         // last candidate actually run (the
                                         // one whose SubprocessResult the
                                         // caller should report), or -1 if
                                         // none was ever found
    bool ok{false};                     // final reported status
};

// Pure decision mirroring the real retry loop: given the per-candidate
// outcomes in try order, decide which candidate the loop stops at and
// whether the final reported status is success. A not-found candidate
// (found=false) is always skipped without being "attempted". A found
// candidate whose run failed (found=true, succeeded=false) is also skipped
// past to the next candidate -- retry-on-ANY-failure, not just
// retry-on-absence -- and the loop stops examining later candidates the
// moment one succeeds (mirrors the real loop's `break`).
inline DnsFlushDecision decide_dns_flush(const std::vector<DnsFlushAttemptOutcome>& attempts) {
    DnsFlushDecision decision;
    for (std::size_t i = 0; i < attempts.size(); ++i) {
        if (!attempts[i].found)
            continue; // not present on disk -- try the next candidate
        decision.attempted = true;
        decision.winning_index = i;
        if (attempts[i].succeeded) {
            decision.ok = true;
            return decision; // success -- do not consider later candidates
        }
        // found but failed (spawn error or nonzero exit); fall through to
        // the next candidate, matching the old `||` chain
    }
    return decision;
}

} // namespace yuzu::network_actions
