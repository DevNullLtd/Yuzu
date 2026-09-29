/**
 * software_actions_plugin.cpp — Software upgrade info plugin for Yuzu
 *
 * Actions:
 *   "list_upgradable" — List packages/apps that can be upgraded (read-only).
 *   "installed_count" — Quick count of installed packages/apps.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   upgradable|name|current|available
 *   count|N
 *
 * ADR-3002 acquisition-ladder migration (Wave 4, PR4.3b): every popen/_popen
 * shell-out is replaced — Windows' installed_count by a native Reg*W subkey
 * count (rung 1, zero subprocesses), everything else by the shared
 * agent-core bounded argv runner (rung 2, run_bounded_subprocess /
 * probe_tool_path) — no shell, no PATH search, no string-as-code surface. A
 * runner-level failure (spawn error / deadline / cancelled / signaled) is
 * always forwarded through the ABI4 result-status seam via
 * forward_runner_failure — never silently reported as a clean result.
 */

#include <yuzu/plugin.hpp>

#include <chrono>
#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/agent/runner_status.hpp>     // yuzu::agent::forward_runner_failure
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path

#include "software_actions_parsers.hpp" // yuzu::software_actions::{parse_*, count_*, yum_checkupdate_is_success}

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681) — from_wide for %LOCALAPPDATA%
#pragma comment(lib, "advapi32.lib")
#endif

namespace {

// Read-only enumeration tools (apt/yum/dpkg-query/rpm/pkgutil): quick local
// reads, generous enough never to fire on a healthy endpoint.
constexpr std::chrono::milliseconds kQuickToolDeadline{20'000};
// winget (hits its configured source over the network) and softwareupdate -l
// (observed to take tens of seconds against Apple's catalog) are both
// slower, single-shot, read-only calls — a longer ceiling that still bounds
// a wedged tool rather than pinning the instruction worker indefinitely.
constexpr std::chrono::milliseconds kSlowToolDeadline{60'000};

#ifdef _WIN32

// RAII closer for an HKEY (installed_apps_plugin.cpp's HKeyCloser pattern —
// a tiny local copy rather than pulling in that plugin's headers).
struct HKeyCloser {
    HKEY h;
    explicit HKeyCloser(HKEY k) : h(k) {}
    ~HKeyCloser() {
        if (h)
            RegCloseKey(h);
    }
    HKeyCloser(const HKeyCloser&) = delete;
    HKeyCloser& operator=(const HKeyCloser&) = delete;
};

// software_actions/installed_count_windows — NOT a spawn site (rung 1, no
// subprocess): a native RegOpenKeyExW + RegQueryInfoKeyW subkey count of the
// default (non-redirected) view of the Uninstall key.
//
// Same KEY and same VIEW as the `powershell -Command` one-liner it replaces
// (that script also read only the default view via Get-ItemProperty against
// the bare HKLM:\...\Uninstall\* path — no WOW6432Node, no HKCU), but NOT a
// byte-identical number: this is a raw subkey count, whereas
// `(Get-ItemProperty ...).Count` counted property-bearing objects, so a
// value-less subkey contributed nothing there and contributes 1 here. The
// count is a fleet-inventory gauge, not a reconciled figure, and the honest
// read is "programs registered under Uninstall".
//
// KNOWN LIMITATION, unchanged from the payload replaced: the 64-bit view omits
// 32-bit applications registered under WOW6432Node. Reading both views would
// change the reported number on every Windows host, so it is deliberately NOT
// bundled into this migration.
//
// Returns -1 on any registry failure so the caller can report an honest
// degrade rather than a fabricated zero.
[[nodiscard]] int registry_uninstall_subkey_count() {
    HKEY hkey{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                       L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ,
                       &hkey) != ERROR_SUCCESS) {
        return -1;
    }
    HKeyCloser guard{hkey};
    DWORD subkey_count = 0;
    if (RegQueryInfoKeyW(hkey, nullptr, nullptr, nullptr, &subkey_count, nullptr, nullptr,
                         nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return -1;
    }
    // DWORD -> int: an Uninstall key cannot approach INT_MAX subkeys, and the
    // signed type is what carries the -1 "read failed" sentinel. Explicit so a
    // future -Wconversion sweep reads as deliberate.
    return static_cast<int>(subkey_count);
}

// winget ships as a per-user App Execution Alias at
// %LOCALAPPDATA%\\Microsoft\\WindowsApps\\winget.exe. That alias is a ZERO-BYTE
// IO_REPARSE_TAG_APPEXECLINK reparse point, NOT a PE image -- verified on a
// live Windows host: GetFileAttributesW reports 0x420 (ARCHIVE|REPARSE_POINT),
// length 0, reparse tag 0x8000001b, and GetBinaryTypeW fails with
// ERROR_CANT_ACCESS_FILE (1920).
//
// probe_tool_path()'s Windows backend gates on GetBinaryTypeW, so probing this
// candidate ALWAYS returns "" and the whole winget leg would be dead code whose
// failure was indistinguishable from the declared "alias not available" case.
// The path is therefore handed straight to the runner: run_bounded_subprocess
// is the authority on what it can actually spawn, and CreateProcess DOES follow
// an APPEXECLINK. A genuinely absent winget then surfaces as the runner's own
// spawn_error -> UNAVAILABLE, which is distinguishable from a winget that ran.
[[nodiscard]] std::string winget_candidate_path() {
    wchar_t buf[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return {};
    return yuzu::win::from_wide(buf, static_cast<int>(n)) +
           "\\Microsoft\\WindowsApps\\winget.exe";
}

#endif // _WIN32

// forward_runner_failure() returns true for line_limit too, which the seam
// deliberately classifies as YUZU_RESULT_STATUS_OK -- "Not a failure". Keying
// execute()'s integer return off "a status was set" would flatten that back
// into a failure, which is precisely the narrowing ADR-3002's honest-
// termination rule names the plugin return as. So the return code keys off the
// classified STATUS, never off "something was reported".
[[nodiscard]] bool runner_status_is_failure(const yuzu::agent::SubprocessResult& res) {
    const auto s = yuzu::agent::classify_runner_failure(res);
    return s.has_value() && s->status != YUZU_RESULT_STATUS_OK;
}

// A capture output may honestly be derived from: the child ran, the runner did
// not cut it short, the capture was not truncated, and the exit code is one the
// caller accepts (exit-code semantics are the caller's domain per
// runner_status.hpp, so each site passes its own verdict). A truncated capture
// matters as much as a failed one here: both count actions COUNT LINES, so a
// capture that stopped early silently undercounts -- the same false-negative
// reasoning licensing_linux.cpp applies to a truncated `rpm -qa`.
[[nodiscard]] bool capture_usable(const yuzu::agent::SubprocessResult& res, bool exit_ok) {
    return yuzu::software_actions::capture_is_complete(res.tool_ran, res.timed_out,
                                                       res.output_truncated, exit_ok) &&
           !runner_status_is_failure(res);
}

// Report a degrade for a tool that produced nothing usable, and NEVER emit a
// data line alongside it. Prefers the runner's own provenance (spawn error,
// deadline, truncation); falls back to `reason` when the tool merely ran and
// returned a failing exit code, which the runner does not classify.
void degrade(yuzu::CommandContext& ctx, const yuzu::agent::SubprocessResult& res,
             const char* reason) {
    if (!yuzu::agent::forward_runner_failure(ctx, res)) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              reason);
    }
}

// ── list_upgradable action ─────────────────────────────────────────────────

int do_list_upgradable(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    auto tool = winget_candidate_path();
    if (tool.empty()) {
        // No %LOCALAPPDATA% in this token's environment: the alias path cannot
        // even be constructed, so nothing about this host's upgrades is known.
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "software_actions:localappdata_unset");
        return 1;
    }
    // software_actions/list_upgradable_windows#1 (docs/agent-spawn-sink-manifest.md)
    auto res = yuzu::agent::run_bounded_subprocess(
        {tool, "upgrade", "--accept-source-agreements"},
        yuzu::agent::SubprocessOptions{.deadline = kSlowToolDeadline});
    // A runner-level outcome or a truncated capture disqualifies the whole
    // table: parsing a half-captured table would report a SHORTER upgrade list
    // as though it were complete. The exit code is not part of this test --
    // winget returns a documented nonzero for several benign states -- so a
    // nonzero exit only matters when nothing parsed (below), where it is the
    // difference between "up to date" and "the query failed".
    if (!capture_usable(res, /*exit_ok=*/true)) {
        degrade(ctx, res, "software_actions:winget_failed");
        return 1;
    }
    auto parsed = yuzu::software_actions::parse_winget_upgrade(res.output);

    // CommandContext exposes no way to READ back a status already set (the
    // daemon-side store is unconditional last-write-wins, agent.cpp), so this
    // local flag is the only way to know, a few lines down, that the table is
    // already known-incomplete -- which is exactly what decides whether "up
    // to date" may be written. Track ONE reason (else-if, not three
    // independent ifs): setting a second reason after the first would only
    // overwrite it with no way to recover the earlier one, silently losing
    // diagnostic fidelity even though the STATUS itself stays correct either
    // way (same shape as discovery_scan_plan.hpp's worst_of() accumulator).
    bool table_incomplete = false;
    if (parsed.header_unrecognized) {
        // The table was found but its header did not yield the five expected
        // column origins, so every row below is reported name-only. Say so —
        // an operator must be able to tell "these packages are upgradable and
        // here are the versions" from "these packages are upgradable and the
        // version columns could not be read".
        table_incomplete = true;
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "software_actions:winget_header_unrecognized");
    } else if (parsed.unmapped_lines > 0) {
        // Some post-separator line looked like data but did not fit the
        // header's columns, so it was dropped rather than emitted with values
        // borrowed from a neighbouring column. A vanished package must not be
        // indistinguishable from a host with fewer upgrades -- INCLUDING the
        // degenerate case where every row was dropped this way, which must
        // not read as "up to date" below.
        table_incomplete = true;
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "software_actions:winget_rows_unmapped");
    } else if (yuzu::software_actions::nonzero_exit_with_partial_rows(res.exit_code,
                                                                      parsed.rows.empty())) {
        // See nonzero_exit_with_partial_rows()'s doc comment: winget exited
        // nonzero but the table still parsed rows, so the caller must not
        // derive "ok" from an undeclared status.
        table_incomplete = true;
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "software_actions:winget_partial_exit");
    }
    if (parsed.rows.empty()) {
        if (res.exit_code != 0) {
            // Nothing parsed AND a failing exit: no basis to claim this host is
            // up to date.
            degrade(ctx, res, "software_actions:winget_failed");
            return 1;
        }
        if (!yuzu::software_actions::winget_up_to_date_claimable(
                /*rows_empty=*/true, res.exit_code, parsed.separator_found, table_incomplete)) {
            // See winget_up_to_date_claimable()'s doc comment: either no
            // recognisable table was found at all, or one WAS found but every
            // row was dropped as unmapped -- in both cases nothing about this
            // host's upgrades was established, and a CONSTRAINED status may
            // already be set (table_incomplete) from above. The non-committal
            // "-" line is kept for output-shape compatibility; the status is
            // what tells an operator it is not a genuine "up to date".
            if (!table_incomplete) {
                ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED,
                                      YUZU_RESULT_COMPLETENESS_PARTIAL,
                                      "software_actions:winget_no_table");
            }
            ctx.write_output("upgradable|none|-|-");
            return 1;
        }
        ctx.write_output("upgradable|none|System is up to date|-");
        return 0;
    }
    for (const auto& r : parsed.rows) {
        ctx.write_output(
            std::format("upgradable|{}|{}|{}", r.name, r.current_version, r.available_version));
    }
    return 0;

#elif defined(__linux__)
    bool found = false;
    yuzu::agent::SubprocessResult apt_res, yum_res;
    bool apt_tried = false, yum_tried = false;
    bool apt_ok = false, yum_ok = false;

    auto apt = yuzu::agent::probe_tool_path({"/usr/bin/apt", "/bin/apt"});
    if (!apt.empty()) {
        apt_tried = true;
        // software_actions/list_upgradable_linux#1 (docs/agent-spawn-sink-manifest.md)
        apt_res = yuzu::agent::run_bounded_subprocess(
            {apt, "list", "--upgradable"},
            yuzu::agent::SubprocessOptions{.deadline = kQuickToolDeadline});
        apt_ok = capture_usable(apt_res, apt_res.exit_code == 0);
        if (apt_ok) {
            for (const auto& r : yuzu::software_actions::parse_apt_list_upgradable(apt_res.output)) {
                ctx.write_output(
                    std::format("upgradable|{}|{}|{}", r.name, r.old_version, r.new_version));
                found = true;
            }
        }
    }
    if (apt_tried && apt_ok) {
        // apt ran cleanly. Whatever it reported IS the answer for a dpkg host --
        // falling through to dnf here would let an unrelated dnf failure
        // overwrite apt's authoritative "nothing to upgrade" with a degrade.
        if (found)
            return 0;
        ctx.write_output("upgradable|none|System is up to date|-");
        return 0;
    }
    if (!found) {
        auto yum = yuzu::agent::probe_tool_path({"/usr/bin/yum", "/usr/bin/dnf"});
        if (!yum.empty()) {
            yum_tried = true;
            // software_actions/list_upgradable_linux#2 (docs/agent-spawn-sink-manifest.md)
            yum_res = yuzu::agent::run_bounded_subprocess(
                {yum, "check-update"}, yuzu::agent::SubprocessOptions{.deadline = kQuickToolDeadline});
            // yum/dnf check-update exits 100 when updates ARE available -- a
            // success-with-data exit code, never a failure (see
            // yum_checkupdate_is_success's doc comment; confirmed against a
            // real fedora:40 run, which exits 100 with a leading blank line).
            yum_ok = capture_usable(
                yum_res, yuzu::software_actions::yum_checkupdate_is_success(yum_res.exit_code));
            if (yum_ok) {
                for (const auto& r : yuzu::software_actions::parse_yum_checkupdate(yum_res.output)) {
                    ctx.write_output(std::format("upgradable|{}|-|{}", r.name, r.new_version));
                    found = true;
                }
            }
        }
    }
    if (found) {
        if (apt_tried && !apt_ok) {
            // apt was tried and FAILED, but yum/dnf still found rows -- yum's
            // rows are real data and stay in the output, but apt's failure
            // must not be silently swallowed by yum's later success: a
            // consumer that only reads status would see a clean CONSTRAINED-
            // free result even though one of the two managers this host has
            // installed could not be queried this cycle.
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "software_actions:apt_list_upgradable_failed");
        }
        return 0;
    }

    // Nothing was emitted. Say WHY. "System is up to date" is a positive
    // assertion about the host and must be reserved for the one case that
    // actually justifies it -- a package manager that RAN CLEAN and reported
    // nothing. A tool that failed, or that was never found, produces a
    // degraded status and no reassuring line: reporting a broken query as
    // "up to date" is the Wave-3 firewall false-safe shape.
    if (yum_tried && !yum_ok) {
        degrade(ctx, yum_res, "software_actions:yum_check_update_failed");
        return 1;
    }
    if (apt_tried && !apt_ok) {
        degrade(ctx, apt_res, "software_actions:apt_list_upgradable_failed");
        return 1;
    }
    if (!apt_tried && !yum_tried) {
        // Neither package manager is present (Alpine/apk, Arch/pacman, a SUSE
        // image without rpm at the probed paths). Nothing was enumerated, so
        // nothing can be claimed about this host's upgrades.
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "software_actions:no_supported_package_manager");
        return 1;
    }
    ctx.write_output("upgradable|none|System is up to date|-");
    return 0;

#elif defined(__APPLE__)
    auto tool = yuzu::agent::probe_tool_path({"/usr/sbin/softwareupdate"});
    if (tool.empty()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "software_actions:softwareupdate_not_present");
        return 1;
    }
    // software_actions/list_upgradable_macos#1 (docs/agent-spawn-sink-manifest.md)
    auto res = yuzu::agent::run_bounded_subprocess(
        {tool, "-l"}, yuzu::agent::SubprocessOptions{.deadline = kSlowToolDeadline});
    // The exit code is deliberately NOT part of the capture-usability test:
    // softwareupdate -l has been observed to exit nonzero on some macOS
    // releases while still printing a valid, parseable table (the sibling
    // windows_updates_plugin.cpp's do_missing() makes the identical choice
    // for this exact tool, deliberately excluding exit_code from ITS
    // capture-usability test, for the same reason). Gating the WHOLE capture
    // on exit_code would discard real pending-update data whenever that
    // happens. The misparse concern an earlier version of this function
    // guarded against by gating here -- a failing run's diagnostic text
    // getting emitted as a package name -- is independently closed by
    // parse_softwareupdate_list's own shape rule below (an entry must carry
    // the "*" marker or a Label: field; a diagnostic line can no longer be
    // emitted as a package name), so the exit code doesn't need to gate the
    // capture to prevent that.
    if (!capture_usable(res, /*exit_ok=*/true)) {
        degrade(ctx, res, "software_actions:softwareupdate_failed");
        return 1;
    }
    auto labels = yuzu::software_actions::parse_softwareupdate_list(res.output);
    if (yuzu::software_actions::nonzero_exit_with_partial_rows(res.exit_code, labels.empty())) {
        // Nonzero exit but real labels parsed -- report the partial rather
        // than either trusting it as fully clean or (the bug this replaces)
        // discarding real data by failing capture_usable outright.
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "software_actions:softwareupdate_partial_exit");
    }
    if (labels.empty()) {
        if (res.exit_code != 0) {
            // Nothing parsed AND a failing exit: no basis to claim this host
            // is up to date.
            degrade(ctx, res, "software_actions:softwareupdate_failed");
            return 1;
        }
        ctx.write_output("upgradable|none|System is up to date|-");
        return 0;
    }
    for (const auto& label : labels)
        ctx.write_output(std::format("upgradable|{}|-|-", label));
    return 0;

#else
    ctx.write_output("error|platform not supported");
    return 1;
#endif
}

// ── installed_count action ─────────────────────────────────────────────────

int do_installed_count(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    auto count = registry_uninstall_subkey_count();
    auto line = yuzu::software_actions::installed_count_line(count);
    if (!line) {
        // Registry read failed: report the degrade through the ABI4 status
        // seam and write NO `count|` line at all. Emitting `count|0` here
        // would be a fabricated zero — a consumer reading the output lines
        // would see "this host has zero installed programs", which is the
        // false-clean shape the antivirus plugin's `exclusion_count|0`
        // invariant (tests/unit/test_antivirus_local_dispatcher.cpp) exists
        // to forbid: a count line must never coexist with a degraded status.
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "software_actions:registry_query_failed");
        return 1;
    }
    ctx.write_output(*line);
    return 0;

#elif defined(__linux__)
    // Every branch below obeys one rule, the same one the Windows leg states:
    // a `count|` line is a factual claim about this host, so it is emitted ONLY
    // for a complete, trustworthy capture. A failed, truncated or absent tool
    // yields a degraded status and NO count line -- `count|0` would assert
    // "zero installed programs", the false-clean shape the antivirus plugin's
    // `exclusion_count|0` invariant forbids.
    auto dpkg = yuzu::agent::probe_tool_path({"/usr/bin/dpkg-query", "/bin/dpkg-query"});
    if (!dpkg.empty()) {
        // software_actions/installed_count_linux#1 (docs/agent-spawn-sink-manifest.md)
        auto res = yuzu::agent::run_bounded_subprocess(
            {dpkg, "-W", "-f=${db:Status-Abbrev}\\n"},
            yuzu::agent::SubprocessOptions{.deadline = kQuickToolDeadline});
        if (!capture_usable(res, res.exit_code == 0)) {
            degrade(ctx, res, "software_actions:dpkg_query_failed");
            return 1;
        }
        ctx.write_output(std::format(
            "count|{}", yuzu::software_actions::count_dpkg_status_abbrev_installed(res.output)));
        return 0;
    }
    auto rpm = yuzu::agent::probe_tool_path({"/usr/bin/rpm", "/bin/rpm"});
    if (!rpm.empty()) {
        // software_actions/installed_count_linux#2 (docs/agent-spawn-sink-manifest.md)
        auto res = yuzu::agent::run_bounded_subprocess(
            {rpm, "-qa"}, yuzu::agent::SubprocessOptions{.deadline = kQuickToolDeadline});
        if (!capture_usable(res, res.exit_code == 0)) {
            degrade(ctx, res, "software_actions:rpm_query_failed");
            return 1;
        }
        ctx.write_output(
            std::format("count|{}", yuzu::software_actions::count_nonempty_lines(res.output)));
        return 0;
    }
    // Neither package manager present (Alpine/apk, Arch/pacman, SUSE without
    // rpm at the probed paths) -- installed_apps already treats such hosts as
    // in-fleet, so this is a reachable state, not a theoretical one.
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          "software_actions:no_supported_package_manager");
    return 1;

#elif defined(__APPLE__)
    auto tool = yuzu::agent::probe_tool_path({"/usr/sbin/pkgutil"});
    if (tool.empty()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "software_actions:pkgutil_not_present");
        return 1;
    }
    // software_actions/installed_count_macos#1 (docs/agent-spawn-sink-manifest.md)
    auto res = yuzu::agent::run_bounded_subprocess(
        {tool, "--pkgs"}, yuzu::agent::SubprocessOptions{.deadline = kQuickToolDeadline});
    if (!capture_usable(res, res.exit_code == 0)) {
        degrade(ctx, res, "software_actions:pkgutil_query_failed");
        return 1;
    }
    ctx.write_output(
        std::format("count|{}", yuzu::software_actions::count_nonempty_lines(res.output)));
    return 0;

#else
    ctx.write_output("error|platform not supported");
    return 1;
#endif
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Wave 4 PR4.3b: migrated off popen/_popen on every OS.
// list_upgradable: Linux (apt/yum via bounded argv runner) and macOS
// (softwareupdate via bounded argv runner) are SUPPORTED/rung 2. Windows
// (winget via bounded argv runner) is CONSTRAINED/rung 2 — the winget App
// Execution Alias is a per-user-session mechanism that can be unavailable to
// the agent's service context, in which case an honest empty/unavailable
// result is reported rather than a failure.
// installed_count: Linux (dpkg-query/rpm via bounded argv runner) and macOS
// (pkgutil --pkgs via bounded argv runner) are SUPPORTED/rung 2. Windows is
// SUPPORTED/rung 1 — a native Reg*W subkey count of the Uninstall key,
// replacing the prior `powershell -Command` shell-out (ADR-3002 Decision 5
// pins any `powershell -Command` payload at rung 3 forever; this is not a
// tighter rung-3 wrapper of that payload but its outright replacement by a
// zero-subprocess native read).
const YuzuActionDescriptor kActionDescriptors[] = {
    {"list_upgradable",
     /* linux   = */
     {YUZU_SUPPORT_SUPPORTED, 2, "apt/yum check-update via bounded argv runner", nullptr},
     /* macos   = */
     {YUZU_SUPPORT_SUPPORTED, 2, "softwareupdate -l via bounded argv runner", nullptr},
     /* windows = */
     {YUZU_SUPPORT_CONSTRAINED, 2, "winget via bounded argv runner",
      "winget is a PER-USER App Execution Alias under %LOCALAPPDATA%; under the shipped "
      "LocalSystem service account that path does not exist, so this leg resolves only when the "
      "agent runs in a user-session context. An unresolvable winget reports UNAVAILABLE, never a "
      "clean empty result"}},
    {"installed_count",
     /* linux   = */
     {YUZU_SUPPORT_SUPPORTED, 2, "dpkg-query/rpm via bounded argv runner", nullptr},
     /* macos   = */
     {YUZU_SUPPORT_SUPPORTED, 2, "pkgutil --pkgs via bounded argv runner", nullptr},
     /* windows = */
     {YUZU_SUPPORT_SUPPORTED, 1, "native Reg*W subkey count of the Uninstall key",
      "reads only the default (64-bit) registry view, matching the powershell payload it "
      "replaced; 32-bit applications registered under WOW6432Node are not counted"}},
};

} // namespace

class SoftwareActionsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "software_actions"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Lists upgradable packages and counts installed software";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list_upgradable", "installed_count", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "list_upgradable")
            return do_list_upgradable(ctx);
        if (action == "installed_count")
            return do_installed_count(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(SoftwareActionsPlugin)
