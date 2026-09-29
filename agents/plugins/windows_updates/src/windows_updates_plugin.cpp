/**
 * windows_updates_plugin.cpp — Windows updates / package updates plugin for Yuzu
 *
 * Actions:
 *   "installed"          — List recently installed updates/packages.
 *   "missing"            — List available updates/packages that can be installed.
 *   "pending_reboot"     — Detect if the endpoint requires a reboot after updates.
 *   "patch_connectivity" — Test connectivity to patch/update servers (DNS, TCP, HTTPS).
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   update|kb_id|description|date
 *   package|name|version
 *   available|title|severity
 *   source_name|true/false|detail          (per-check rows)
 *   reboot_required|true/false|reasons    (summary row)
 *   target|url|dns_ok|bool|dns_ms|N|...   (connectivity results)
 */

#include <yuzu/plugin.hpp>

#include "windows_updates_parsers.hpp" // pure installed/missing parse+format helpers

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <objbase.h>       // CoInitializeEx/CoCreateInstance/IID_IUnknown -- WIN32_LEAN_AND_MEAN
                           // drops these from windows.h's own includes (ole2.h), so pull them in
                           // explicitly rather than relying on a transitive include elsewhere
#include <oleauto.h>       // SysFreeString (BStrGuard's deleter) -- same reasoning as objbase.h
                           // above; currently reachable transitively via win_com.hpp, but this
                           // TU calls SysFreeString directly (via BStrGuard) so it should not
                           // depend on staying reachable through another header's own includes
#include <win_com.hpp>     // shared yuzu::shared::win ComInit/ComPtr<T>/BStr
#include <win_str.hpp>     // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <wmi_bounded.hpp> // shared yuzu::shared::wmi::run_bounded_wmi_query (bounded, never WBEM_INFINITE)
#include <wuapi.h>         // IUpdateSession/IUpdateSearcher/ISearchJob (Windows Update Agent COM API)
#include <yuzu/agent/wua_noop_callback.hpp> // process-lifetime BeginSearch callback singleton
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>

#include <spdlog/spdlog.h>
#include <yuzu/agent/runner_status.hpp>     // yuzu::agent::forward_runner_failure (ABI4 result seam)
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess (ADR-3002 rung 2)
#endif

namespace {

// ── subprocess helpers ─────────────────────────────────────────────────────

#if defined(__linux__)
// Linux-only: its three call sites (do_pending_reboot's uname -r / ls -t
// /boot/vmlinuz-* / needs-restarting -r, see the comment below) are all
// Linux-branch-only, so guarding this to __APPLE__ too just produced an
// unused-function warning on every macOS build for no reason.
std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}
#endif

// run_command_lines (the vector<string> popen wrapper) is gone: every call
// site that used it has been migrated onto run_tool()/run_bounded_subprocess
// (POSIX) or WMI/WUA COM (Windows) below. Only run_command (the
// single-string variant, above) survives, still used by do_pending_reboot's
// Linux branch (uname -r / ls -t /boot/vmlinuz-* / needs-restarting -r) --
// those three sites are out of scope for this installed/missing-focused
// migration and are intentionally left as-is (raw popen, no bound).

#ifndef _WIN32
// Per-call wall-clock bound for the installed/missing tool probes (rpm/apt/
// yum/system_profiler). Generous enough never to fire in practice, short
// enough that a wedged tool cannot pin the instruction worker indefinitely
// -- same ceiling as the users plugin's kUsersCmdDeadline.
constexpr std::chrono::seconds kUpdatesCmdDeadline{10};

// macOS `softwareupdate -l` specifically contacts Apple's servers (unlike
// the local-only probes above) and can legitimately take 30-120s -- shared
// by every call site that runs this exact command (do_missing,
// do_pending_reboot) so the bound can't drift out of sync between them
// (governance Gate 3 cross-platform finding: do_missing used to fall
// through to the generic 10s kUpdatesCmdDeadline for this call, which a
// real softwareupdate invocation would very likely exceed).
constexpr std::chrono::seconds kSoftwareUpdateDeadline{60};

/// Outcome of run_tool(): the captured lines PLUS the raw runner result, so
/// a caller can forward the latter through the ABI4 result seam
/// (yuzu::agent::forward_runner_failure) itself instead of this helper
/// deciding that on the caller's behalf.
struct ToolOutcome {
    std::vector<std::string> lines;
    yuzu::agent::SubprocessResult res;
};

/// Direct-argv replacement for the old shell-string popen hop (ADR-3002 rung
/// 2): the same bounded, fork-lock-covered runner, but exec'd straight to
/// argv[0] with no shell in between -- no shell-quoting/injection surface,
/// and a `2>/dev/null` suffix an old shell string carried is simply this
/// call's default merge_stderr=false. `max_lines` (0 = unlimited) maps to
/// what used to be a `| head -N` pipe. `deadline` defaults to
/// kUpdatesCmdDeadline (10s, right for the local/fast package-manager
/// probes this helper mostly serves) but is overridable -- macOS
/// `softwareupdate -l` contacts Apple's servers and needs the same longer
/// bound do_pending_reboot's own direct run_bounded_subprocess call already
/// uses for the identical command. Mirrors users_plugin.cpp's run_tool
/// (users/src/users_plugin.cpp) exactly -- same calling convention, same
/// degraded-run warning shape.
ToolOutcome run_tool(std::vector<std::string> argv, std::size_t max_lines = 0,
                     std::chrono::seconds deadline = kUpdatesCmdDeadline) {
    if (argv.empty() || argv.front().empty()) {
        return ToolOutcome{{}, yuzu::agent::SubprocessResult{}};
    }
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = deadline,
                                             .max_lines = max_lines,
                                             .stop_after_max_lines = max_lines != 0});
    if (res.timed_out || !res.tool_ran || res.output_truncated) {
        spdlog::warn("windows_updates: degraded run (timed_out={}, tool_ran={}, truncated={}): {}",
                     res.timed_out, res.tool_ran, res.output_truncated, argv.front());
    }
    return ToolOutcome{std::move(res.lines), std::move(res)};
}
#endif // !_WIN32

#ifdef _WIN32
// RAII owner for a BSTR returned by an out-parameter (e.g. IUpdate::
// get_Title/get_MsrcSeverity), so the allocation is freed on every exit
// path -- including a throwing conversion between the accessor call and
// the manual SysFreeString that used to follow it (adversarial review
// finding: CLAUDE.md's "non-RAII manual cleanup in new C++" governance
// floor). Not agents/shared/win_com.hpp's BStr: that class only allocates
// (SysAllocString/SysAllocStringLen), it has no adopt-an-existing-BSTR
// constructor, and win_com.hpp belongs to sibling PR3.3-a -- extending it
// here would touch a file this branch does not own. std::unique_ptr with a
// SysFreeString deleter needs nothing from that file.
using BStrGuard = std::unique_ptr<std::remove_pointer_t<BSTR>, decltype(&::SysFreeString)>;

// A deadline-exceeded search's ISearchJob is aborted and released WITHOUT
// calling CleanUp() (see do_missing() below). CleanUp() genuinely blocks
// with no documented bound, so running it -- inline or on a background
// thread -- risks the same class of defect either way: the host's
// reconnect/shutdown path does dlclose()/FreeLibrary() this plugin on a
// live process (see agents/core/include/yuzu/agent/subprocess_runner.hpp's
// header comment), and any thread still executing this module's code when
// that happens crashes into unmapped memory. A detached CleanUp() thread
// cannot be made safe against that race without an agent-core-owned
// killable broker boundary that outlives the plugin's own unload (a larger
// change than this migration's scope; ADR-3002's "Considered alternatives"
// rejects the equivalent per-plugin-runner shape for a subprocess reaper
// for the identical reason). Dropping CleanUp() entirely accepts a bounded,
// WUA-internal resource residue on the rare genuinely-wedged search in
// exchange for removing the unload race outright.
#endif // _WIN32

// ── installed action ───────────────────────────────────────────────────────

int do_installed(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    // In-process bounded WMI query (ADR-3002 rung 1: a daemon-mediated call
    // through the WMI service, same status as the registry/wevtapi calls
    // elsewhere in this Wave -- no child process spawned at all) replacing
    // the old `powershell -Command Get-HotFix` interpreter shell-out.
    //
    // The old PowerShell pipeline sorted by InstalledOn descending and took
    // the first 50. WQL SELECT gives no equivalent ordering guarantee for a
    // data class query (ORDER BY is an event-query-only WQL feature), so
    // that sort+cap is deliberately dropped here rather than faked: this
    // returns every row WMI hands back, bounded only by
    // BoundedQueryOptions::row_cap (default 512) -- a disclosed behaviour
    // change, not an oversight.
    auto res = yuzu::shared::wmi::run_bounded_wmi_query(
        L"root\\cimv2", L"SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering");
    if (res.error) {
        const auto fail = yuzu::windows_updates::classify_wmi_error(*res.error);
        ctx.set_result_status(fail.status, fail.completeness, fail.provenance);
        ctx.write_output(std::format("update|none|WMI query failed: {}", *res.error));
        return 0;
    }

    std::vector<yuzu::windows_updates::HotfixRow> hotfixes;
    hotfixes.reserve(res.rows.size());
    for (const auto& row : res.rows) {
        yuzu::windows_updates::HotfixRow h;
        if (auto it = row.find("HotFixID"); it != row.end())
            h.hotfix_id = it->second;
        if (auto it = row.find("Description"); it != row.end())
            h.description = it->second;
        if (auto it = row.find("InstalledOn"); it != row.end())
            h.installed_on = it->second;
        hotfixes.push_back(std::move(h));
    }

    if (res.truncated) {
        // Not a failure -- an honest partial (the row cap was hit): OK,
        // PARTIAL, same shape runner_status.hpp uses for line_limit.
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "wmi_bounded:row_cap_truncated");
    }

    auto lines = yuzu::windows_updates::format_hotfix_rows(hotfixes);
    if (lines.empty()) {
        ctx.write_output("update|none|No updates found|-");
        return 0;
    }
    for (const auto& line : lines) {
        ctx.write_output(line);
    }

#elif defined(__linux__)
    // Try rpm first, then apt -- direct argv via the bounded runner (ADR-3002
    // rung 2), replacing the old `| head -50` shell pipeline (max_lines=50,
    // stop_after_max_lines=true is the in-process equivalent).
    // sink: windows_updates/do_installed#1 -- rpm -qa --last, no rung-1 API
    // for this data on Linux (see docs/agent-spawn-sink-manifest.md)
    auto rpm = run_tool({"/usr/bin/rpm", "-qa", "--last"}, 50);
    if (!rpm.lines.empty()) {
        // Forward rpm's own outcome (e.g. the 50-line cap truncating a
        // longer install history) even though it returned data.
        yuzu::agent::forward_runner_failure(ctx, rpm.res);
        for (const auto& line : yuzu::windows_updates::parse_rpm_last(rpm.lines)) {
            ctx.write_output(line);
        }
    } else {
        // sink: windows_updates/do_installed#2 -- apt list --installed
        // fallback when rpm produces no output, no rung-1 API on Linux
        auto apt = run_tool({"/usr/bin/apt", "list", "--installed"}, 50);
        yuzu::agent::forward_runner_failure(ctx, apt.res);
        if (apt.lines.empty()) {
            ctx.write_output("package|none|No packages found");
            return 0;
        }
        for (const auto& line : yuzu::windows_updates::parse_apt_installed(apt.lines)) {
            ctx.write_output(line);
        }
    }

#elif defined(__APPLE__)
    // The old `| grep -E '^ {4}\w|Install Date:' | head -100` filtering
    // stage moved into parse_install_history_macos (no shell to pipe
    // through once this is direct argv) -- max_lines=2000 here is a
    // generous RAW-output safety cap only; the real 100-MATCHED-line cap is
    // enforced by the pure parser, matching the old pipeline's semantics
    // (head -100 acted on the already-grepped stream, not the raw one).
    // sink: windows_updates/do_installed#3 -- system_profiler
    // SPInstallHistoryDataType, no rung-1 API for this data on macOS
    auto sp = run_tool({"/usr/sbin/system_profiler", "SPInstallHistoryDataType"}, 2000);
    // Forward sp's outcome before branching on its output -- a deadline-cut
    // run can still have produced some (incomplete) rows.
    yuzu::agent::forward_runner_failure(ctx, sp.res);
    if (sp.lines.empty()) {
        ctx.write_output("update|none|No update history found");
        return 0;
    }
    auto lines = yuzu::windows_updates::parse_install_history_macos(sp.lines);
    if (lines.empty()) {
        ctx.write_output("update|none|No update history found");
        return 0;
    }
    for (const auto& line : lines) {
        ctx.write_output(line);
    }

#else
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

// ── missing action ─────────────────────────────────────────────────────────

int do_missing(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    // In-process WUA COM search replacing the old `powershell -Command
    // New-Object -ComObject Microsoft.Update.Session` interpreter shell-out.
    // Deliberately NOT IUpdateSearcher::Search() -- that is a synchronous,
    // unbounded broker call forbidden by ADR-3002 (it can hang for minutes
    // against an offline/broken WSUS with nothing to catch it). This uses
    // the async BeginSearch()/ISearchJob API instead, polling
    // ISearchJob::IsCompleted under an explicit deadline so a wedged search
    // is aborted rather than hung on. This whole leg is the one part of this
    // migration that could not be verified on this (non-Windows) host --
    // written carefully from the documented WUA COM API surface, to be
    // confirmed on a real Windows host.
    using yuzu::shared::win::BStr;
    using yuzu::shared::win::ComInit;
    using yuzu::shared::win::ComPtr;

    ComInit com_init;
    if (!com_init.ok()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "windows_updates:com_init_failed");
        ctx.write_output("available|none|COM initialization failed");
        return 0;
    }

    ComPtr<IUpdateSession> session;
    HRESULT hr = CoCreateInstance(CLSID_UpdateSession, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IUpdateSession, reinterpret_cast<void**>(session.put()));
    if (FAILED(hr)) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "windows_updates:cocreate_updatesession_failed");
        ctx.write_output(std::format("available|none|Failed to create update session ({:#010x})",
                                     static_cast<unsigned long>(hr)));
        return 0;
    }

    ComPtr<IUpdateSearcher> searcher;
    hr = session->CreateUpdateSearcher(searcher.put());
    if (FAILED(hr)) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "windows_updates:create_searcher_failed");
        ctx.write_output(std::format("available|none|Failed to create update searcher ({:#010x})",
                                     static_cast<unsigned long>(hr)));
        return 0;
    }

    // BeginSearch requires a live callback object even though this call
    // polls the job itself; yuzu::agent::wua_noop_search_completed_callback()
    // is a borrowed, process-lifetime singleton (see wua_noop_callback.hpp)
    // -- not owned here, so no ComPtr/AddRef/Release on this end. A
    // plugin-local callback would be unsafe to hand to WUA: it can still be
    // holding a reference to it past this call's own bounded timeout, and a
    // plugin-resident vtable is unmapped the moment the agent dlclose()s
    // this module.
    BStr criteria(L"IsInstalled=0");
    VARIANT state;
    VariantInit(&state);

    ComPtr<ISearchJob> job;
    hr = searcher->BeginSearch(criteria.get(), yuzu::agent::wua_noop_search_completed_callback(),
                               state, job.put());
    if (FAILED(hr)) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "windows_updates:begin_search_failed");
        ctx.write_output(std::format("available|none|Failed to start update search ({:#010x})",
                                     static_cast<unsigned long>(hr)));
        return 0;
    }

    // ADR-3002: never block unbounded on a broker call. No caller-supplied
    // timeout is plumbed into this plugin's actions today, so this is a
    // hardcoded budget rather than a derived one -- 120s is generous for a
    // normal search (typically seconds) while still bounding a wedged one.
    constexpr auto kSearchDeadline = std::chrono::seconds(120);
    constexpr auto kSearchPollInterval = std::chrono::milliseconds(500);
    const auto search_deadline = std::chrono::steady_clock::now() + kSearchDeadline;

    bool completed = false;
    for (;;) {
        VARIANT_BOOL is_completed = VARIANT_FALSE;
        hr = job->get_IsCompleted(&is_completed);
        if (FAILED(hr))
            break;
        if (is_completed == VARIANT_TRUE) {
            completed = true;
            break;
        }
        if (std::chrono::steady_clock::now() >= search_deadline)
            break;
        Sleep(static_cast<DWORD>(kSearchPollInterval.count()));
    }

    if (!completed) {
        // Deliberate bounded stop, not a crash/hang -- but ISearchJob::
        // CleanUp() is documented to block until the async operation has
        // actually finished, so calling it here (inline OR on a detached
        // thread outliving this call) would either reintroduce the
        // unbounded wait CleanUp() itself has, or risk that thread still
        // running this module's code after the host dlclose()s/
        // FreeLibrary()s the plugin on its reconnect/shutdown path -- a
        // fatal use-after-unload race ADR-3002 rejects this exact shape
        // for (see the comment above do_installed(), below BStrGuard).
        // Request the abort and drop the job's own reference via `job`'s
        // normal RAII destructor at scope exit -- no extra ref, no
        // background thread, no CleanUp() call. This accepts a bounded,
        // WUA-internal resource residue on a genuinely wedged search in
        // exchange for eliminating the unload race outright.
        job->RequestAbort();
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "windows_updates:search_deadline_exceeded");
        ctx.write_output("available|none|Update search did not complete within the time budget");
        return 0;
    }

    ComPtr<ISearchResult> result;
    hr = searcher->EndSearch(job.get(), result.put());
    if (FAILED(hr)) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "windows_updates:end_search_failed");
        ctx.write_output(std::format("available|none|Failed to retrieve search results ({:#010x})",
                                     static_cast<unsigned long>(hr)));
        return 0;
    }

    OperationResultCode result_code = orcNotStarted;
    hr = result->get_ResultCode(&result_code);
    if (FAILED(hr)) {
        // An accessor failure here is not "no result" -- it means we don't
        // actually know whether the search succeeded. Fail closed rather
        // than falling through to the success path below.
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "windows_updates:get_result_code_failed");
        ctx.write_output("available|none|Failed to read update-search status");
        return 0;
    }
    if (result_code == orcFailed || result_code == orcAborted) {
        // Never report a failed/aborted search as "no updates" -- that would
        // be false assurance, not an honest empty result.
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "windows_updates:search_result_failed");
        ctx.write_output("available|none|Update search completed with a failure result");
        return 0;
    }

    ComPtr<IUpdateCollection> updates;
    hr = result->get_Updates(updates.put());
    if (FAILED(hr) || !updates) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "windows_updates:get_updates_failed");
        ctx.write_output("available|none|Failed to enumerate search results");
        return 0;
    }

    LONG count = 0;
    if (FAILED(updates->get_Count(&count))) {
        // Same reasoning as get_ResultCode above -- an unreadable count is
        // not zero updates, it's an unknown count.
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "windows_updates:get_update_count_failed");
        ctx.write_output("available|none|Failed to count search results");
        return 0;
    }

    std::vector<yuzu::windows_updates::UpdateRow> rows;
    rows.reserve(count > 0 ? static_cast<size_t>(count) : 0);
    bool item_read_failed = false;
    for (LONG i = 0; i < count; ++i) {
        ComPtr<IUpdate> update;
        if (FAILED(updates->get_Item(i, update.put())) || !update) {
            // Don't silently drop it -- a skipped item means the collection
            // we're about to report is incomplete, not exhaustive.
            item_read_failed = true;
            continue;
        }

        yuzu::windows_updates::UpdateRow row;
        BSTR title_raw = nullptr;
        if (SUCCEEDED(update->get_Title(&title_raw)) && title_raw) {
            // Adopted into the RAII guard immediately -- from_wide() below
            // allocates a std::string and is not noexcept; if it throws,
            // title_bstr's destructor still runs during unwind and frees
            // the BSTR (was: a raw SysFreeString call AFTER from_wide()
            // that a throw would skip, leaking the COM allocation).
            BStrGuard title_bstr(title_raw, &::SysFreeString);
            row.title = yuzu::win::from_wide(title_bstr.get());
        }
        BSTR severity_raw = nullptr;
        if (SUCCEEDED(update->get_MsrcSeverity(&severity_raw)) && severity_raw) {
            BStrGuard severity_bstr(severity_raw, &::SysFreeString);
            row.msrc_severity = yuzu::win::from_wide(severity_bstr.get());
        }
        rows.push_back(std::move(row));
    }

    if (result_code == orcSucceededWithErrors || item_read_failed) {
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "windows_updates:search_result_partial");
    }

    auto lines = yuzu::windows_updates::format_update_rows(rows);
    if (lines.empty()) {
        ctx.write_output("available|none|No pending updates");
        return 0;
    }
    for (const auto& line : lines) {
        ctx.write_output(line);
    }

#elif defined(__linux__)
    // sink: windows_updates/do_missing#1 -- apt list --upgradable, no
    // rung-1 API for this data on Linux
    auto apt = run_tool({"/usr/bin/apt", "list", "--upgradable"});
    auto avail = yuzu::windows_updates::parse_apt_upgradable(apt.lines);
    // apt genuinely finding nothing to upgrade (a clean exit, not a spawn/
    // deadline/timeout degradation) is real "up to date" data, not evidence
    // that apt is unavailable -- don't fall through to yum on it, and don't
    // let a subsequent yum spawn failure overwrite that honest result.
    const bool apt_complete = apt.res.tool_ran &&
                              apt.res.termination_reason == yuzu::agent::TerminationReason::exited &&
                              apt.res.exit_code == 0;
    if (!avail.empty()) {
        // Forward apt's own outcome (e.g. a line_limit truncation) even
        // though it returned data -- non-empty output does not mean the
        // acquisition was complete.
        yuzu::agent::forward_runner_failure(ctx, apt.res);
        for (const auto& line : avail) {
            ctx.write_output(line);
        }
    } else if (apt_complete) {
        ctx.write_output("available|none|System is up to date");
    } else {
        // sink: windows_updates/do_missing#2 -- yum check-update, fallback
        // when apt produces no matching rows, no rung-1 API on Linux
        auto yum = run_tool({"/usr/bin/yum", "check-update"});
        auto yum_lines = yuzu::windows_updates::parse_yum_checkupdate(yum.lines);
        if (yum_lines.empty()) {
            // A successful "nothing to update" exit is the common case here
            // and forward_runner_failure is a no-op for it (classify_runner_
            // failure returns nullopt for a normal `exited` termination) --
            // this only actually reports a status for a genuine spawn/
            // deadline/cancel/signal degradation.
            yuzu::agent::forward_runner_failure(ctx, yum.res);
            ctx.write_output("available|none|System is up to date");
        } else {
            yuzu::agent::forward_runner_failure(ctx, yum.res);
            for (const auto& line : yum_lines) {
                ctx.write_output(line);
            }
        }
    }

#elif defined(__APPLE__)
    // sink: windows_updates/do_missing#3 -- softwareupdate -l, no rung-1
    // API for this data on macOS. kSoftwareUpdateDeadline (60s), not the
    // generic kUpdatesCmdDeadline (10s) this helper defaults to -- this
    // call contacts Apple's servers and can legitimately take much longer
    // than a local package-manager probe.
    auto su = run_tool({"/usr/sbin/softwareupdate", "-l"}, 0, kSoftwareUpdateDeadline);
    // Forward su's outcome before branching on its output -- a truncated or
    // deadline-cut run can still have produced some lines.
    yuzu::agent::forward_runner_failure(ctx, su.res);
    if (su.lines.empty()) {
        ctx.write_output("available|none|No updates available");
        return 0;
    }
    for (const auto& line : yuzu::windows_updates::parse_softwareupdate_list(su.lines)) {
        ctx.write_output(line);
    }

#else
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

// ── pending reboot action ─────────────────────────────────────────────────

int do_pending_reboot(yuzu::CommandContext& ctx) {
    std::vector<std::string> reasons;

#ifdef _WIN32
    // All three reboot probes below test key/value EXISTENCE only -- no value
    // string is ever decoded -- so they carry no encoding and stay Reg*A (#1682
    // stored-vs-transient audit).
    // Check 1: Windows Update RebootRequired registry key
    {
        HKEY hkey = nullptr;
        bool found = (RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            R"(SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired)",
            0, KEY_READ, &hkey) == ERROR_SUCCESS);
        if (found) {
            RegCloseKey(hkey);
            reasons.push_back("windows_update_reboot");
        }
        ctx.write_output(std::format("windows_update_reboot|{}|{}",
                                     found ? "true" : "false",
                                     found ? "Registry key exists" : ""));
    }

    // Check 2: Component Based Servicing RebootPending
    {
        HKEY hkey = nullptr;
        bool found = (RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending)",
            0, KEY_READ, &hkey) == ERROR_SUCCESS);
        if (found) {
            RegCloseKey(hkey);
            reasons.push_back("cbs_reboot");
        }
        ctx.write_output(std::format("cbs_reboot|{}|{}",
                                     found ? "true" : "false",
                                     found ? "Registry key exists" : ""));
    }

    // Check 3: Pending file rename operations.
    // Presence-only: the value's bytes are never decoded into a string (only its
    // size is read to detect a non-empty value), so this carries no encoding and
    // stays Reg*A -- no cp1252 mojibake risk (#1682 stored-vs-transient audit).
    {
        HKEY hkey = nullptr;
        bool found = false;
        if (RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                R"(SYSTEM\CurrentControlSet\Control\Session Manager)",
                0, KEY_READ, &hkey) == ERROR_SUCCESS) {
            DWORD size = 0;
            if (RegQueryValueExA(hkey, "PendingFileRenameOperations", nullptr,
                                 nullptr, nullptr, &size) == ERROR_SUCCESS && size > 0) {
                found = true;
                reasons.push_back("pending_file_rename");
            }
            RegCloseKey(hkey);
        }
        ctx.write_output(std::format("pending_file_rename|{}|{}",
                                     found ? "true" : "false",
                                     found ? "Non-empty value" : ""));
    }

#elif defined(__linux__)
    // Check 1: /var/run/reboot-required (Debian/Ubuntu)
    {
        std::error_code ec;
        bool found = std::filesystem::exists("/var/run/reboot-required", ec);
        if (found)
            reasons.push_back("reboot_required_file");
        ctx.write_output(std::format("reboot_required_file|{}|{}",
                                     found ? "true" : "false",
                                     found ? "/var/run/reboot-required exists" : ""));
    }

    // Check 2: Running kernel vs installed kernel mismatch
    {
        bool found = false;
        // sink: windows_updates/do_pending_reboot#2 -- uname -r, grandfathered
        // rung-3 exception (docs/agent-spawn-sink-manifest.md), tracked #2380
        auto running = run_command("uname -r");
        // Use ls -t (sort by mtime) instead of sort -V for portability (busybox/Alpine)
        // sink: windows_updates/do_pending_reboot#3 -- ls -t /boot/vmlinuz-* |
        // head -1, grandfathered rung-3 exception (same manifest doc), #2380
        auto latest = run_command("ls -t /boot/vmlinuz-* 2>/dev/null | head -1");
        if (!latest.empty()) {
            // Strip "vmlinuz-" prefix and path
            auto pos = latest.rfind("vmlinuz-");
            if (pos != std::string::npos) {
                auto installed = latest.substr(pos + 8);
                if (!running.empty() && !installed.empty() && running != installed) {
                    found = true;
                    reasons.push_back("kernel_mismatch");
                }
                ctx.write_output(std::format("kernel_mismatch|{}|running={} installed={}",
                                             found ? "true" : "false", running, installed));
            }
        }
        if (latest.empty()) {
            // Fallback: needs-restarting (RHEL/CentOS/Fedora)
            // sink: windows_updates/do_pending_reboot#4 -- needs-restarting -r,
            // grandfathered rung-3 exception (same manifest doc), tracked #2380
            auto output = run_command("needs-restarting -r 2>&1");
            bool needs = output.find("Reboot is required") != std::string::npos;
            if (needs) {
                found = true;
                reasons.push_back("needs_restarting");
            }
            ctx.write_output(std::format("needs_restarting|{}|{}",
                                         needs ? "true" : "false",
                                         needs ? "needs-restarting reports reboot required" : ""));
        }
    }

#elif defined(__APPLE__)
    // Check: softwareupdate -l output containing "restart". softwareupdate
    // -l contacts Apple servers and may take 30-120s; migrated off the old
    // popen()-based run_command_lines() (no timeout at all -- could hang
    // indefinitely on a headless/offline Mac) onto run_bounded_subprocess
    // (ADR-3002 rung 2, direct argv, no shell). 60s is generous for the
    // normal contacts-Apple-servers latency while still bounding a
    // wedged/offline check instead of hanging forever.
    {
        // sink: windows_updates/do_pending_reboot#1 -- softwareupdate -l,
        // no rung-1 API for this data on macOS. kSoftwareUpdateDeadline is
        // file-scoped (shared with do_missing's identical call, above).
        auto res = yuzu::agent::run_bounded_subprocess(
            {"/usr/sbin/softwareupdate", "-l"},
            yuzu::agent::SubprocessOptions{.deadline = kSoftwareUpdateDeadline});
        yuzu::agent::forward_runner_failure(ctx, res);

        bool found = false;
        for (const auto& line : res.lines) {
            // Case-insensitive search for "restart"
            std::string lower = line;
            for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lower.find("restart") != std::string::npos) {
                found = true;
                reasons.push_back("softwareupdate_restart");
                break;
            }
        }
        ctx.write_output(std::format("softwareupdate_restart|{}|{}",
                                     found ? "true" : "false",
                                     found ? "Update requires restart" : ""));
    }

#else
    ctx.write_output("error|false|platform not supported");
    return 0;
#endif

    // Summary line
    bool any = !reasons.empty();
    std::string reason_str;
    for (size_t i = 0; i < reasons.size(); ++i) {
        if (i > 0) reason_str += ',';
        reason_str += reasons[i];
    }
    ctx.write_output(std::format("reboot_required|{}|{}",
                                 any ? "true" : "false", reason_str));
    return 0;
}

// ── connectivity helpers ──────────────────────────────────────────────────

struct ConnTarget {
    std::string url;
    std::string host;
    int port{443};
    std::string path;
    bool use_tls{true};
};

ConnTarget parse_url(const std::string& url) {
    ConnTarget t;
    t.url = url;
    std::string_view sv = url;
    if (sv.starts_with("https://")) {
        sv.remove_prefix(8); t.use_tls = true; t.port = 443;
    } else if (sv.starts_with("http://")) {
        sv.remove_prefix(7); t.use_tls = false; t.port = 80;
    }
    auto slash = sv.find('/');
    auto host_part = sv.substr(0, slash);
    t.path = (slash != std::string_view::npos) ? std::string(sv.substr(slash)) : "/";
    auto colon = host_part.find(':');
    if (colon != std::string_view::npos) {
        t.host = std::string(host_part.substr(0, colon));
        try { t.port = std::stoi(std::string(host_part.substr(colon + 1))); } catch (...) {}
    } else {
        t.host = std::string(host_part);
    }
    return t;
}

struct DnsResult {
    bool ok{false};
    std::string ip;
    int64_t ms{-1};
    std::string error;
};

DnsResult test_dns(const std::string& host) {
    DnsResult r;
    auto start = std::chrono::steady_clock::now();
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    auto elapsed = std::chrono::steady_clock::now() - start;
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    if (rc != 0) {
        r.error = "name resolution failed";
        return r;
    }
    r.ok = true;
    char buf[64]{};
    if (res->ai_family == AF_INET) {
        inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr, buf, sizeof(buf));
    } else if (res->ai_family == AF_INET6) {
        inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(res->ai_addr)->sin6_addr, buf, sizeof(buf));
    }
    r.ip = buf;
    freeaddrinfo(res);
    return r;
}

struct TcpResult {
    bool ok{false};
    int64_t ms{-1};
    std::string error;
};

TcpResult test_tcp(const std::string& host, int port, int timeout_s) {
    TcpResult r;
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    auto port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        r.error = "dns failed";
        return r;
    }

    auto start = std::chrono::steady_clock::now();

#ifdef _WIN32
    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) { freeaddrinfo(res); r.error = "socket failed"; return r; }
    unsigned long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    connect(sock, res->ai_addr, static_cast<int>(res->ai_addrlen));
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    timeval tv;
    tv.tv_sec = timeout_s;
    tv.tv_usec = 0;
    int sel = select(0, nullptr, &writefds, nullptr, &tv);
    auto elapsed = std::chrono::steady_clock::now() - start;
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    if (sel > 0) {
        int err = 0;
        int err_len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &err_len);
        r.ok = (err == 0);
        if (!r.ok) r.error = "connection refused";
    } else {
        r.error = (sel == 0) ? "timeout" : "select failed";
    }
    closesocket(sock);
#else
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); r.error = "socket failed"; return r; }
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    connect(sock, res->ai_addr, res->ai_addrlen);
    struct pollfd pfd{sock, POLLOUT, 0};
    int sel = poll(&pfd, 1, timeout_s * 1000);
    auto elapsed = std::chrono::steady_clock::now() - start;
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    if (sel > 0) {
        int err = 0;
        socklen_t err_len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &err_len);
        r.ok = (err == 0);
        if (!r.ok) r.error = "connection refused";
    } else {
        r.error = (sel == 0) ? "timeout" : "poll failed";
    }
    close(sock);
#endif

    freeaddrinfo(res);
    return r;
}

std::vector<std::string> get_default_patch_targets() {
    std::vector<std::string> targets;
#ifdef _WIN32
    targets.push_back("https://windowsupdate.microsoft.com");
    targets.push_back("https://update.microsoft.com");
    targets.push_back("https://download.windowsupdate.com");
    // Check for a WSUS URL in the registry. Reg*W + reg_sz_to_utf8 so a non-ASCII
    // WSUS hostname survives as UTF-8 rather than cp1252 mojibake (#1662 / #1682);
    // wide literals are used directly since the subkey/value names are constants.
    HKEY hkey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            LR"(SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate)",
            0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        wchar_t buf[512]{};
        DWORD buf_size = sizeof(buf); // BYTES; buf read back as wchar_t (LPBYTE is align-1)
        DWORD type = 0;
        const LONG rc = RegQueryValueExW(hkey, L"WUServer", nullptr, &type,
                                         reinterpret_cast<LPBYTE>(buf), &buf_size);
        RegCloseKey(hkey); // closed before the allocating convert -- no leak window (#1682 R1)
        if (rc == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ) &&
            buf_size >= sizeof(wchar_t)) {
            std::string wsus = yuzu::win::reg_sz_to_utf8(buf, buf_size);
            if (!wsus.empty()) targets.push_back(wsus);
        }
    }
#elif defined(__linux__)
    // Try to read apt sources.list for repository URLs
    auto parse_apt_sources = [&](const std::string& path) {
        std::ifstream f(path);
        if (!f) return;
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            // deb http://... or deb-src http://...
            auto http_pos = line.find("http");
            if (http_pos != std::string::npos) {
                auto end = line.find(' ', http_pos);
                auto url = line.substr(http_pos, end == std::string::npos ? std::string::npos : end - http_pos);
                // Extract just the host URL (drop the path for connectivity test)
                auto parsed = parse_url(url);
                auto base = std::string(parsed.use_tls ? "https://" : "http://") + parsed.host;
                if (std::find(targets.begin(), targets.end(), base) == targets.end())
                    targets.push_back(base);
            }
        }
    };
    parse_apt_sources("/etc/apt/sources.list");
    // Check sources.list.d
    namespace fs = std::filesystem;
    std::error_code ec;
    for (auto& entry : fs::directory_iterator("/etc/apt/sources.list.d", ec)) {
        if (entry.path().extension() == ".list")
            parse_apt_sources(entry.path().string());
    }
    if (targets.empty()) {
        targets.push_back("https://archive.ubuntu.com");
        targets.push_back("https://security.ubuntu.com");
    }
#elif defined(__APPLE__)
    targets.push_back("https://swscan.apple.com");
    targets.push_back("https://swdist.apple.com");
#endif
    return targets;
}

int do_patch_connectivity(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto targets_str = params.get("targets");
    int timeout_s = 10;
    auto timeout_str = params.get("timeout_seconds", "10");
    try { timeout_s = std::stoi(std::string{timeout_str}); } catch (...) {}
    if (timeout_s < 1) timeout_s = 1;
    if (timeout_s > 60) timeout_s = 60;

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    std::vector<std::string> targets;
    if (targets_str.empty()) {
        targets = get_default_patch_targets();
    } else {
        // Split on comma
        std::string s{targets_str};
        size_t pos = 0;
        while (pos < s.size()) {
            auto comma = s.find(',', pos);
            auto token = s.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
            // Trim whitespace
            auto start = token.find_first_not_of(" \t");
            if (start != std::string::npos) {
                auto end = token.find_last_not_of(" \t");
                targets.push_back(token.substr(start, end - start + 1));
            }
            if (comma == std::string::npos) break;
            pos = comma + 1;
        }
    }

    int reachable = 0;
    int failed = 0;

    for (const auto& url : targets) {
        auto target = parse_url(url);

        // DNS test
        auto dns = test_dns(target.host);
        ctx.write_output(std::format("target|{}|dns_ok|{}|dns_ms|{}|ip|{}",
            url, dns.ok ? "true" : "false", dns.ms,
            dns.ok ? dns.ip : dns.error));

        if (!dns.ok) { ++failed; continue; }

        // TCP test
        auto tcp = test_tcp(target.host, target.port, timeout_s);
        ctx.write_output(std::format("target|{}|tcp_ok|{}|tcp_ms|{}",
            url, tcp.ok ? "true" : "false", tcp.ms));

        if (!tcp.ok) {
            ctx.write_output(std::format("target|{}|tcp_error|{}", url, tcp.error));
            ++failed;
            continue;
        }

        ++reachable;
    }

    ctx.write_output(std::format("summary|targets_tested|{}|targets_reachable|{}|targets_failed|{}",
        targets.size(), reachable, failed));

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// installed/missing (this migration): Linux/macOS moved off popen shell
// strings onto direct argv through yuzu::agent::run_bounded_subprocess (no
// shell, ADR-3002 rung 2 -- rpm/apt on Linux, system_profiler/softwareupdate
// on macOS). Windows moved off `powershell -Command` (an interpreter shell-
// out, rung 3) onto in-process calls with no child process at all: a bounded
// WMI query (installed) and the async WUA COM search API (missing) -- both
// daemon-mediated broker calls, same rung-1 status as the registry/wevtapi
// calls elsewhere in this Wave (see runner_status.hpp's EvtNext comment for
// the precedent).
// pending_reboot: Windows is pure Reg*A presence checks (rung 1, untouched).
// Linux combines a filesystem::exists probe with uname/ls/needs-restarting
// shell calls (rung 3, untouched -- out of scope for this migration, see the
// run_command_lines removal note above). macOS's softwareupdate -l call
// moved off unbounded popen (rung 3) onto run_bounded_subprocess with an
// explicit 60s deadline (rung 2) -- still CONSTRAINED (a slow update check
// is still slow), but bounded now instead of able to hang indefinitely.
// patch_connectivity: pure BSD/Winsock sockets (getaddrinfo/connect/poll or
// select) on all three OSes -- rung 1 everywhere, untouched.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"installed",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 2, "rpm+apt", nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "system_profiler", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "wmi_bounded_query", nullptr}},
    {"missing",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 2, "apt+yum", nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "softwareupdate", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "wua_com_async_search", nullptr}},
    {"pending_reboot",
     /* linux   = */
     {YUZU_SUPPORT_SUPPORTED, 3, "filesystem+uname+vmlinuz_ls+needs_restarting", nullptr},
     /* macos   = */
     {YUZU_SUPPORT_CONSTRAINED, 2, "softwareupdate",
      "bounded (60s deadline) since this migration, but still a slow network call -- "
      "no longer able to hang indefinitely on an offline/headless Mac"},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "registry", nullptr}},
    {"patch_connectivity",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 1, "raw_sockets", nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 1, "raw_sockets", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "raw_sockets", nullptr}},
};

} // namespace

class WindowsUpdatesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "windows_updates"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Updates/packages: installed, available, pending-reboot, patch connectivity";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"installed", "missing", "pending_reboot",
                                     "patch_connectivity", nullptr};
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
                yuzu::Params params) override {
        if (action == "installed")
            return do_installed(ctx);
        if (action == "missing")
            return do_missing(ctx);
        if (action == "pending_reboot")
            return do_pending_reboot(ctx);
        if (action == "patch_connectivity")
            return do_patch_connectivity(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(WindowsUpdatesPlugin)
