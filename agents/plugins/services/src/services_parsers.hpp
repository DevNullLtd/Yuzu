/**
 * services_parsers.hpp — pure output parsers for the services plugin's
 * Linux (`systemctl list-units`) and macOS (`launchctl list`) enumeration
 * paths (Wave-2 PR2.2a, ADR-3002 acquisition-ladder migration, rung 2/3).
 *
 * Header-only, no I/O: services_plugin.cpp owns running systemctl/launchctl
 * through the bounded, shell-free runner (yuzu::agent::run_bounded_subprocess)
 * and hands this header the captured stdout, so every parser here is
 * unit-testable directly against fixture text with no live systemctl/
 * launchctl dependency (see tests/unit/test_services_parsers.cpp).
 *
 * The fixtures in that test file are hand-constructed-but-format-accurate —
 * built from the documented `systemctl list-units --no-legend` and
 * `launchctl list` column layouts, not a live capture from a running host.
 *
 * Mirrors the split services_macos_launchd.hpp already established in this
 * package (parse_print_disabled / startup_type_for): a pure parser header
 * the plugin .cpp includes and feeds captured text, kept independent of the
 * .cpp's anonymous namespace so it stays separately includable/testable.
 *
 * macOS's parse_launchctl_list() (governance A0 round-4, CA-1/pd-6) no
 * longer runs its own independent tab-split/header-skip loop: it converges
 * onto the shared raw row decoder + structural validator
 * (agents/shared/launchctl_list.hpp, the same A0 lift TAR's
 * tar_service_parsers.hpp already converged onto), which is the ONLY thing
 * this file's former copy was missing -- a header-shape check and an
 * empty-input check. Without either, a truncated/zero-line `launchctl list`
 * capture parsed as a clean "0 services" success, the identical defect class
 * UP2-2 (round 2) fixed for TAR at HIGH. See parse_launchctl_list's own doc
 * comment below for the mapping details.
 */
#pragma once

#include <launchctl_list.hpp> // yuzu::shared::{LaunchctlRow,LaunchctlParseResult,parse_launchctl_list}

#include <yuzu/agent/runner_status.hpp>     // yuzu::agent::classify_runner_failure
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::SubprocessResult

#include <cctype>
#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <utility> // std::move
#include <vector>

namespace yuzu::services {

/// Validate a service name / launchd label before trusting it into the
/// pipe-delimited plugin protocol, into a shell-free argv element, or as a
/// startup_type_for() join key. Allows alphanumeric, hyphens, underscores,
/// dots, and '@' (systemd template instances like getty@tty1.service).
///
/// Own copy, independent of services_macos_launchd.hpp's
/// is_safe_launchd_label (identical character class) — same rationale as
/// that header's own comment: each header stays self-contained and
/// independently testable rather than depending on the other.
///
/// NOTE: this allowlist permits a LEADING '-' (e.g. "-foo"), which is safe
/// for the pipe-delimited protocol but NOT safe as a bare argv element to a
/// tool that parses leading-hyphen arguments as flags — callers passing a
/// validated name into systemctl/launchctl argv must still separate it with
/// an explicit "--" argv element (see services_plugin.cpp's set_start_mode
/// argv construction).
inline bool is_safe_service_name(std::string_view name) {
    if (name.empty() || name.size() > 256)
        return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.' &&
            c != '@') {
            return false;
        }
    }
    return true;
}

/// One row of `systemctl list-units --type=service [--all|--state=running]
/// --no-pager --no-legend` output: "UNIT LOAD ACTIVE SUB DESCRIPTION...".
struct SystemdUnitEntry {
    std::string name;        // UNIT
    std::string status;      // SUB (e.g. "running", "dead", "exited")
    std::string description; // remainder of the line
};

/// Parse the captured stdout of `systemctl list-units`. Tolerant of CRLF
/// line endings, a leading whitespace/bullet column (systemctl marks a
/// failed unit with "*"), and short/blank lines (skipped, never thrown).
/// `--no-legend` means there is no header row to skip.
inline std::vector<SystemdUnitEntry> parse_systemctl_list_units(std::string_view output) {
    std::vector<SystemdUnitEntry> services;

    for (std::size_t scan = 0; scan < output.size();) {
        const std::size_t nl = output.find('\n', scan);
        const std::size_t end = (nl == std::string_view::npos) ? output.size() : nl;
        std::string line{output.substr(scan, end - scan)};
        scan = (nl == std::string_view::npos) ? output.size() : nl + 1;
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        if (line.empty())
            continue;

        // Trim leading whitespace and the bullet systemctl marks a failed
        // unit with.
        auto start = line.find_first_not_of(" *");
        if (start == std::string::npos)
            continue;
        line = line.substr(start);

        SystemdUnitEntry entry;
        std::size_t pos = 0;
        auto next_token = [&]() -> std::string {
            auto s = line.find_first_not_of(' ', pos);
            if (s == std::string::npos)
                return {};
            auto e = line.find(' ', s);
            if (e == std::string::npos)
                e = line.size();
            pos = e;
            return line.substr(s, e - s);
        };

        entry.name = next_token();   // UNIT
        next_token();                // LOAD
        next_token();                // ACTIVE
        entry.status = next_token(); // SUB
        auto desc_start = line.find_first_not_of(' ', pos);
        if (desc_start != std::string::npos) {
            entry.description = line.substr(desc_start);
        }

        services.push_back(std::move(entry));
    }

    return services;
}

/// One row of `launchctl list` output: "PID\tStatus\tLabel".
struct LaunchdEntry {
    std::string label;
    std::string pid;
    std::string status;
};

/// Defensive row cap mirroring the C-8 row_cap precedent (licensing_wmi.hpp):
/// real macOS systems run in the low hundreds of launchd services, so this
/// bounds worst-case memory/output size without affecting normal
/// enumeration. Rows beyond the cap are still counted in total_seen below.
inline constexpr std::size_t kMaxServiceRows = 512;

struct LaunchdListResult {
    std::vector<LaunchdEntry> services;
    // Count of every entry that passed the label-safety + running_only
    // filters BEFORE the row_cap, so the caller can emit an honest
    // truncation sentinel when rows were dropped.
    std::size_t total_seen = 0;
    // True iff yuzu::shared::parse_launchctl_list judged the capture
    // structurally untrustworthy (a missing/garbled header row, or zero
    // lines at all despite a clean exit) -- governance A0 round-4, CA-1: a
    // truncated/corrupted `launchctl list` capture must never be reported as
    // a genuine "0 services" answer. `services`/`total_seen` are always 0
    // when this is true. The CALLER (services_plugin.cpp's do_list) must
    // check this and report a degraded status, the same discipline as the
    // existing runner-failure path (forward_list_degrade).
    bool malformed{false};
};

/// Parse the captured stdout of `launchctl list`. `running_only` drops rows
/// whose pid is "-" (not currently running); launchctl has no CLI flag for
/// this, so the filter happens here, mirroring the original inline check.
/// Every label is validated via is_safe_service_name before being trusted
/// into the result -- an unsafe label (e.g. containing '|') would otherwise
/// corrupt the pipe-delimited protocol the caller emits it into, or a
/// startup_type_for() join key.
///
/// Converged onto the shared raw-row decoder + structural validator
/// (agents/shared/launchctl_list.hpp) rather than this file's own former
/// independent tab-split/header-skip loop (governance A0 round-4, CA-1/pd-6)
/// -- mirrors tar_service_parsers.hpp's launchctl_rows_to_services(): a thin
/// mapper from yuzu::shared::LaunchctlRow's raw pid/status facts onto this
/// file's LaunchdEntry (string) vocabulary, not a second parse. pid/status
/// round-trip through the shared decoder's std::from_chars pass -- byte-
/// identical to the old raw-substring fields for every real capture (every
/// fixture/sample in this tree shows status as a clean base-10 integer; "-"
/// only ever appears in the PID column, which round-trips via
/// nullopt -> "-" below).
inline LaunchdListResult parse_launchctl_list(std::string_view output, bool running_only,
                                              std::size_t row_cap = kMaxServiceRows) {
    LaunchdListResult result;

    // Split into lines matching yuzu::agent::SubprocessResult::lines' own
    // contract (blank lines dropped, a trailing '\r' stripped) so behaviour
    // is identical whether fed a live SubprocessResult::output blob
    // (services_plugin.cpp's production call) or a fixture string
    // (tests/unit/test_services_parsers.cpp).
    std::vector<std::string> lines;
    for (std::size_t pos = 0; pos < output.size();) {
        auto nl = output.find('\n', pos);
        std::string_view line =
            (nl == std::string_view::npos) ? output.substr(pos) : output.substr(pos, nl - pos);
        pos = (nl == std::string_view::npos) ? output.size() : nl + 1;
        while (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (!line.empty())
            lines.emplace_back(line);
    }

    auto raw = yuzu::shared::parse_launchctl_list(lines);
    result.malformed = raw.malformed;
    if (raw.malformed)
        return result; // caller must report a degraded status, never "0 services"

    for (auto& row : raw.rows) {
        // Guard the label before it is ever trusted into the pipe-delimited
        // protocol or used as a startup_type_for() join key.
        if (!is_safe_service_name(row.label))
            continue;
        if (running_only && !row.pid.has_value())
            continue;

        // Count every qualifying service BEFORE the cap so the caller can
        // tell a truncated inventory from a complete one.
        ++result.total_seen;
        if (result.services.size() < row_cap) {
            result.services.push_back(LaunchdEntry{
                std::move(row.label), row.pid.has_value() ? std::to_string(*row.pid) : "-",
                std::to_string(row.status)});
        }
    }

    return result;
}

// ── set_start_mode call-site decision ────────────────────────────────────

/// Outcome of a `set_start_mode` mutation call (systemctl enable/disable/
/// mask on Linux, launchctl enable/disable on macOS), decided from the raw
/// SubprocessResult -- the exact logic do_set_start_mode_linux/_macos apply
/// after run_command() returns, extracted here so it is fixture-testable
/// without a live systemctl/launchctl/sudo dependency (services_plugin.cpp
/// keeps the actual run_bounded_subprocess call; only this decision moves).
struct SetStartModeOutcome {
    bool ok{false};
    // True iff the runner itself never produced a real exit (spawn error /
    // deadline / cancelled / signaled) -- the caller must forward this
    // through the ABI4 result-status seam (yuzu::agent::forward_runner_
    // failure) BEFORE emitting `message` below, so the operator sees a
    // distinguishable CONSTRAINED/UNAVAILABLE status rather than a bare
    // "exit=-1".
    bool runner_failed{false};
    // Populated only when !ok -- ready to hand straight to write_output().
    // Empty when ok (the caller emits its own status|ok/service|/mode|
    // rows).
    std::string message;
};

/// tool_label names the failing tool in the emitted error string
/// ("systemctl" or "launchctl"). `res.output` (captured via merge_stderr,
/// see run_command in services_plugin.cpp) is threaded into the message so
/// a sudo denial ("sudo: a password is required") is diagnosable instead of
/// discarded.
inline SetStartModeOutcome decide_set_start_mode_outcome(
    std::string_view tool_label, std::string_view name,
    const yuzu::agent::SubprocessResult& res) {
    if (yuzu::agent::classify_runner_failure(res).has_value()) {
        return SetStartModeOutcome{
            /*ok=*/false, /*runner_failed=*/true,
            std::format("error|{} command failed for '{}' (runner did not complete)", tool_label,
                        name)};
    }
    if (!res.tool_ran || res.exit_code != 0) {
        const std::string detail = res.output.empty() ? std::string{}
                                                       : std::format(": {}", res.output);
        return SetStartModeOutcome{
            /*ok=*/false, /*runner_failed=*/false,
            std::format("error|{} command failed for '{}' (exit={}){}", tool_label, name,
                        res.tool_ran ? res.exit_code : -1, detail)};
    }
    return SetStartModeOutcome{/*ok=*/true, /*runner_failed=*/false, {}};
}

} // namespace yuzu::services
