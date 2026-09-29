/**
 * power_health_plugin.cpp — battery/thermal/power_plan read-only + a single
 * destructive set_power_plan action, tri-OS.
 *
 * Actions:
 *   "battery"        — one row per power source: present, state, percent,
 *                       time_to_empty_min, cycle_count, health_percent.
 *   "thermal"         — Windows/Linux: per-zone Celsius, or an explicit
 *                       CONSTRAINED "no_thermal_zones_exposed" success line
 *                       when the mechanism reports zero live instances (the
 *                       measured normal case on desktop hardware — see
 *                       power_health_parsers.hpp). macOS: NSProcessInfo's
 *                       4-level thermal-pressure enum, never degrees.
 *   "power_plan"      — Windows: enumerate power schemes + which is active
 *                       (PowrProf). macOS: UNSUPPORTED (no named schemes).
 *                       Linux: PLANNED (platform_profile, not implemented).
 *   "set_power_plan"  — Windows ONLY mutating action of this plugin: resolve
 *                       a GUID/friendly-name scheme param to EXACTLY one
 *                       match, read the prior active scheme, set, then
 *                       read back and verify — every failure branch is a
 *                       typed status paired with a non-zero exit code
 *                       (P-012). Every failure BEFORE PowerSetActiveScheme
 *                       is called (missing param, incomplete enumeration,
 *                       no/ambiguous match, prior-read failure) leaves NO
 *                       mutation applied. A failure AFTER the set call
 *                       succeeds (post-set read-back timeout or mismatch)
 *                       means the mutation itself may already be in effect
 *                       — final state is reported as unknown, never
 *                       claimed unchanged; `previous_guid` is still emitted
 *                       so the caller can verify/revert manually. On
 *                       macOS/Linux this reports the same unsupported/
 *                       planned posture as "power_plan" and never mutates.
 *
 * Mechanisms are bound by 2026-09-04 hardware measurement (runDir/
 * probe-findings.md), not the roadmap. Windows battery-PRESENT was verified
 * on real hardware during PR #4009's review (HP ZBook Firefly); macOS
 * battery-PRESENT remains fixture-only — the run host was a desktop.
 *
 * BOUNDED CALLS (P-001 adapted, #3925 — never worsen bounded_wait.hpp's
 * contract): PowrProf's PowerEnumerate/PowerReadFriendlyName/
 * PowerGetActiveScheme/PowerSetActiveScheme and PDH's PdhCollectQueryData
 * are the calls with real-world hang potential (a stuck driver, a slow WMI-
 * backed provider under the hood of a PDH counter), so each is wrapped in
 * bounded_call_tracked() below — GetSystemPowerStatus/CallNtPowerInformation
 * are fast, bounded-by-construction syscalls and are called directly.
 * bounded_call_tracked() additionally maintains g_outstanding_calls, a
 * plugin-local RAII-guarded counter bracketing each CALLING thread's wait
 * (not the detached thread's own work — see the guard's doc comment for why)
 * that shutdown() drains with a short BOUNDED quiesce — see shutdown()'s own
 * comment for the full unload-safety rationale and its citation of
 * plugin.hpp:245 / discovery_plugin.cpp:446.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   key|field1|field2|...
 *
 * Platform implementations:
 *   Windows: GetSystemPowerStatus/CallNtPowerInformation (battery), PDH
 *            (thermal), PowrProf (power_plan/set_power_plan) — no WMI, no
 *            powercfg or any subprocess, no COM/CoInitialize* anywhere.
 *   macOS:   IOPSCopyPowerSourcesInfo/IOPSCopyPowerSourcesList (battery),
 *            NSProcessInfo.thermalState + IOPMGetThermalWarningLevel
 *            (thermal) — power_health_macos.mm, per
 *            docs/native-objcpp-conventions.md.
 *   Linux:   /sys/class/power_supply (battery), /sys/class/thermal
 *            (thermal) — CONSTRAINED rung 1, fixture-verified; no live
 *            venue in this run. power_plan is PLANNED, not implemented.
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field (plg-H1 precedent)

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "bounded_wait.hpp" // yuzu::shared::bounded_call — ../../shared include dir
#include "power_health_parsers.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <pdh.h>
#include <pdhmsg.h>
#include <powrprof.h>
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "powrprof.lib")

#include "win_str.hpp" // yuzu::win::from_wide — ../../shared include dir

// ACCESS_SCHEME comes from <powrprof.h> as an ENUMERATOR of POWER_DATA_ACCESSOR,
// which is what PowerEnumerate's 4th parameter is typed as.
//
// DO NOT REINTRODUCE A `#ifndef ACCESS_SCHEME` FALLBACK. An enumerator is not a
// macro, so the preprocessor cannot see it: `#ifndef ACCESS_SCHEME` is ALWAYS
// true, the fallback ALWAYS fires, and a `#define ACCESS_SCHEME 16` then
// shadows the real enumerator with a plain int at every call site. C++ does not
// implicitly convert int to an unscoped enum, so PowerEnumerate stops compiling
// (MSVC C2664, "cannot convert argument 4 from 'int' to 'POWER_DATA_ACCESSOR'")
// — and the numeric value being correct is what makes it look harmless. There is
// no preprocessor test for an enumerator; the header either declares it or the
// build fails loudly on an undeclared identifier, which is the outcome we want.

#elif defined(__APPLE__)
// Battery/thermal come from power_health_macos.mm's Objective-C++ boundary
// (declared below) — no OS headers needed directly in this TU.
#else
#include <dirent.h>

#include <fstream>
#include <sstream>
#endif

#ifndef _WIN32
#ifndef __APPLE__
namespace {
// Move-only RAII owner for a DIR* (repo's RAII-ownership rule — PH-015):
// takes ownership only once opendir() has actually succeeded (so an
// early-return on a failed open never constructs a guard over a null
// handle), and closedir()s exactly once on every exit path, including an
// exception thrown while iterating.
class DirHandle {
public:
    explicit DirHandle(DIR* d) noexcept : dir_{d} {}
    ~DirHandle() {
        if (dir_)
            closedir(dir_);
    }
    DirHandle(const DirHandle&) = delete;
    DirHandle& operator=(const DirHandle&) = delete;
    [[nodiscard]] DIR* get() const noexcept { return dir_; }

private:
    DIR* dir_;
};
} // namespace
#endif
#endif

namespace {

using namespace std::chrono_literals;

// Used for every PowrProf/PDH bounded_call site; shutdown()'s quiesce
// deadline is 2x this, matching the plugin.hpp:245 "short bounded quiesce"
// contract.
constexpr auto kBoundedCallTimeout = 2000ms;

// Plugin-local outstanding-call counter, separate from bounded_wait.hpp's
// own internal ceiling (which bounds total concurrent detached threads
// across the whole agent, not this plugin's shutdown visibility). Never
// touched directly outside OutstandingGuard/shutdown() below.
std::atomic<int> g_outstanding_calls{0};

// Queries deliberately abandoned on the timeout path below, and the ceiling on
// them. The bounded-call ceiling does NOT bound this: it caps CONCURRENT
// detached threads, and a chronically slow provider produces calls that exceed
// the timeout but still complete, so the slot is freed every time and the
// ceiling never engages while one PDH_HQUERY leaks per poll, forever. Only a
// permanent black hole is self-limiting. Past the ceiling this leg stops
// opening queries at all and answers unavailable, which is honest and bounded
// -- an agent leaking handles indefinitely is neither.
std::atomic<int> g_abandoned_pdh_queries{0};
constexpr int kMaxAbandonedPdhQueries = 16;

// RAII guard bracketing ONE bounded_call_tracked() invocation from the
// CALLING thread's own perspective: increments on construction, decrements
// on destruction — both always run on the calling thread's own stack,
// never inside bounded_call()'s detached thread.
//
// An earlier version of this counter incremented on the calling thread but
// decremented from INSIDE the detached thread's own lambda, once fn()
// itself finished — intended to make g_outstanding_calls reflect "real
// in-flight work" rather than merely "the caller stopped waiting". Review
// (PH-001/PH-008) correctly rejected that shape on two independent
// grounds: (1) plugin.hpp:245 is explicit that surviving background work
// "must never touch this plugin's own code or statics" after shutdown's
// bounded wait gives up — a decrement running from that detached thread
// past shutdown()'s own return is exactly the touch it forbids; (2) the
// decrement lived inside bounded_call()'s try_acquire()-gated lambda, so a
// call rejected outright at bounded_wait.hpp's own kMaxOutstandingBoundedCalls
// ceiling (fn() never invoked at all) incremented g_outstanding_calls with
// no matching decrement ever running — a permanent leak per rejection.
//
// This shape fixes both: the guard's lifetime is exactly the calling
// thread's bounded_call() invocation, so it decrements deterministically
// whether that call succeeds, times out, or is ceiling-rejected — and it
// never touches anything from the detached thread at all. What it can no
// longer observe is whether the underlying fn() body is STILL physically
// running past its own timeout on bounded_call()'s detached thread — but
// that residual is bounded_call()'s own pre-existing, governance-accepted
// hazard (identical in kind to discovery_plugin.cpp's use of the same
// primitive), not something a plugin-local counter could safely extend
// visibility into without reintroducing the exact bug just described. See
// shutdown()'s own comment for what the quiesce this counter feeds
// actually bounds.
class OutstandingGuard {
public:
    OutstandingGuard() noexcept { ++g_outstanding_calls; }
    ~OutstandingGuard() noexcept { --g_outstanding_calls; }
    OutstandingGuard(const OutstandingGuard&) = delete;
    OutstandingGuard& operator=(const OutstandingGuard&) = delete;
};

// Wraps yuzu::shared::bounded_call, additionally tracking — via
// OutstandingGuard, held for the full width of this call on the CALLING
// thread — how many bounded_call_tracked() invocations this plugin's
// execute() call sites are currently blocked inside, so shutdown() can
// quiesce on it.
template <typename Fn>
auto bounded_call_tracked(Fn fn) -> std::optional<std::invoke_result_t<Fn>> {
    OutstandingGuard guard;
    return yuzu::shared::bounded_call(kBoundedCallTimeout, std::move(fn));
}

// As above, but reporting WHY an empty result came back. A caller holding an
// OS handle that fn() uses needs that distinction: a timeout means a detached
// thread may still be using the handle, a ceiling rejection means fn() never
// ran at all. See bounded_wait.hpp's BoundedCallStatus.
template <typename Fn>
auto bounded_call_tracked_ex(Fn fn) -> yuzu::shared::BoundedCallResult<Fn> {
    OutstandingGuard guard;
    return yuzu::shared::bounded_call_ex(kBoundedCallTimeout, std::move(fn));
}

// ─────────────────────────────────────────────────────────── battery ──────

#ifdef _WIN32
int do_battery(yuzu::CommandContext& ctx) {
    SYSTEM_POWER_STATUS sps{};
    const bool sps_ok = GetSystemPowerStatus(&sps) != 0;
    if (!sps_ok) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "GetSystemPowerStatus failed");
        ctx.write_output(yuzu::power_health::format_battery_row({}));
        return 0;
    }

    // CallNtPowerInformation(SystemBatteryState) is a fast, direct syscall
    // (no PowrProf/PDH-style external provider behind it) — no bounded_call
    // wrapping needed, per this file's header comment.
    SYSTEM_BATTERY_STATE nt{};
    const bool nt_ok = CallNtPowerInformation(SystemBatteryState, nullptr, 0, &nt, sizeof(nt)) == 0;

    yuzu::power_health::WindowsBatteryRaw raw;
    raw.ac_line_status = sps.ACLineStatus;
    raw.battery_flag = sps.BatteryFlag;
    raw.battery_life_percent = sps.BatteryLifePercent;
    raw.battery_life_time = sps.BatteryLifeTime == 0xFFFFFFFFu ? -1 : static_cast<int32_t>(sps.BatteryLifeTime);
    raw.nt_info_valid = nt_ok;
    raw.nt_battery_present = nt_ok && nt.BatteryPresent != 0;
    raw.nt_charging = nt_ok && nt.Charging != 0;
    raw.nt_discharging = nt_ok && nt.Discharging != 0;

    ctx.write_output(yuzu::power_health::format_battery_row(yuzu::power_health::classify_windows_battery(raw)));
    return 0;
}
#elif defined(__APPLE__)
int do_battery(yuzu::CommandContext& ctx) {
    const auto sources = yuzu::power_health::macos_native::query_battery_sources();
    if (sources.empty()) {
        // Honest "no power source enumerated at all" — never fabricated.
        ctx.write_output(yuzu::power_health::format_battery_row({}));
        return 0;
    }
    for (const auto& v : sources)
        ctx.write_output(yuzu::power_health::format_battery_row(yuzu::power_health::interpret_iops_source(v)));
    return 0;
}
#else
int do_battery(yuzu::CommandContext& ctx) {
    DIR* raw_dir = opendir("/sys/class/power_supply");
    if (!raw_dir) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "/sys/class/power_supply not readable");
        ctx.write_output(yuzu::power_health::format_battery_row({}));
        return 0;
    }
    const DirHandle dir{raw_dir}; // ownership taken only after a successful open

    bool any_battery_row = false;
    struct dirent* entry = nullptr;
    while ((entry = readdir(dir.get())) != nullptr) {
        const std::string name = entry->d_name;
        if (name == "." || name == "..")
            continue;
        std::ifstream uevent("/sys/class/power_supply/" + name + "/uevent");
        if (!uevent)
            continue;
        std::ostringstream contents;
        contents << uevent.rdbuf();
        if (auto row = yuzu::power_health::parse_linux_power_supply_uevent(contents.str())) {
            any_battery_row = true;
            ctx.write_output(yuzu::power_health::format_battery_row(*row));
        }
    }

    if (!any_battery_row)
        ctx.write_output(yuzu::power_health::format_battery_row({})); // no Battery-type supply found
    return 0;
}
#endif

// ──────────────────────────────────────────────────────────── thermal ─────

#ifdef _WIN32
int do_thermal(yuzu::CommandContext& ctx) {
    PDH_HQUERY query = nullptr;
    if (g_abandoned_pdh_queries.load(std::memory_order_relaxed) >= kMaxAbandonedPdhQueries) {
        // Refuse to add to an already-bounded residue. Reported distinctly so an
        // operator sees a degraded provider rather than a silent absence.
        ctx.write_output(
           yuzu::power_health::format_thermal_line({"unavailable", "pdh_provider_degraded", {}}));
        return 0;
    }

    if (PdhOpenQueryW(nullptr, 0, &query) != ERROR_SUCCESS) {
        ctx.write_output(yuzu::power_health::format_thermal_line({"unavailable", "pdh_open_failed", {}}));
        return 0;
    }

    PDH_HCOUNTER counter = nullptr;
    // A zero-instance wildcard counter path can itself fail to add with
    // PDH_CSTATUS_NO_INSTANCE — measured on the-rig. That specific status
    // IS the "no_thermal_zones_exposed" explicit success case; any OTHER
    // add failure (access denied, bad path, out of memory, ...) is a
    // genuine PDH error and must not be folded into the same honest
    // CONSTRAINED line (PH-010) — it is reported as "unavailable" instead.
    const PDH_STATUS add_status =
        PdhAddEnglishCounterW(query, L"\\Thermal Zone Information(*)\\Temperature", 0, &counter);
    if (add_status == PDH_CSTATUS_NO_INSTANCE) {
        PdhCloseQuery(query);
        ctx.write_output(
            yuzu::power_health::format_thermal_line({"constrained", "no_thermal_zones_exposed", {}}));
        return 0;
    }
    if (add_status != ERROR_SUCCESS) {
        PdhCloseQuery(query);
        ctx.write_output(
            yuzu::power_health::format_thermal_line({"unavailable", "pdh_add_counter_failed", {}}));
        return 0;
    }

    const auto collected =
        bounded_call_tracked_ex([query]() { return PdhCollectQueryData(query) == ERROR_SUCCESS; });
    if (collected.status == yuzu::shared::BoundedCallStatus::Rejected) {
        // The outstanding-call ceiling refused the call, so PdhCollectQueryData
        // was NEVER invoked and no thread was ever created against this handle.
        // Nothing can be racing it, so it closes normally. This path is
        // deliberately separated from the timeout below: rejection is what
        // happens when the agent is already loaded, i.e. in bursts, so leaking
        // here would be an unbounded handle leak under exactly the conditions
        // that provoke it -- and it would buy nothing, since the accepted
        // trade below exists only to avoid racing a LIVE call.
        PdhCloseQuery(query);
        ctx.write_output(
            yuzu::power_health::format_thermal_line({"unavailable", "pdh_collect_rejected", {}}));
        return 0;
    }
    if (collected.status == yuzu::shared::BoundedCallStatus::TimedOut) {
        // Timed out — bounded_call()'s detached thread may still be executing
        // PdhCollectQueryData(query) against this exact handle. Closing it here
        // would race a live PDH call on another thread (a cross-thread
        // handle-lifetime violation, not merely an unload-safety one —
        // PH-002), so on THIS path the query is intentionally LEAKED rather
        // than closed: one leaked PDH_HQUERY per timed-out poll is the accepted
        // trade over a use-after-close, matching plugin.hpp:245's "accept a
        // bounded resource residue instead" guidance applied to a live handle.
        g_abandoned_pdh_queries.fetch_add(1, std::memory_order_relaxed);
        ctx.write_output(
            yuzu::power_health::format_thermal_line({"unavailable", "pdh_collect_timed_out", {}}));
        return 0;
    }
    if (!*collected.value) {
        PdhCloseQuery(query); // the call itself returned (no longer racing another thread)
        ctx.write_output(
            yuzu::power_health::format_thermal_line({"unavailable", "pdh_collect_failed", {}}));
        return 0;
    }

    // A FETCH FAILURE IS NOT "no thermal zones".
    //
    // interpret_windows_pdh_thermal() reports an empty sample set as the
    // explicit, positive claim `no_thermal_zones_exposed` -- which is the right
    // answer for a desktop that genuinely exposes none, and a lie if we simply
    // failed to read. The add-counter step twenty lines above already takes
    // care to keep those apart (PH-010); the fetch step did not, so a
    // PDH_MORE_DATA from an instance appearing between the sizing and the real
    // call, or any other fetch error, was reported as a host with no thermal
    // sensors. Track it and report it as its own outcome.
    DWORD buffer_size = 0, item_count = 0;
    const PDH_STATUS size_status =
       PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &buffer_size, &item_count, nullptr);
    // PDH_MORE_DATA is the EXPECTED answer to a sizing call; anything else that
    // is not success means the sizing itself failed.
    bool fetch_ok = (size_status == ERROR_SUCCESS || size_status == PDH_MORE_DATA);

    std::vector<yuzu::power_health::PdhThermalSample> samples;
    if (fetch_ok && item_count > 0 && buffer_size > 0) {
        std::vector<std::byte> buf(buffer_size);
        auto* items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(buf.data());
        const PDH_STATUS fetch_status =
           PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &buffer_size, &item_count, items);
        fetch_ok = (fetch_status == ERROR_SUCCESS);
        if (fetch_ok) {
            for (DWORD i = 0; i < item_count; ++i) {
                // Only a VALID/NEW sample is an honest reading (PH-10) —
                // PDH_CSTATUS_* error codes (a stale/invalid instance, a
                // dropped counter) must never be reported as a healthy
                // temperature.
                if (items[i].FmtValue.CStatus != PDH_CSTATUS_VALID_DATA &&
                    items[i].FmtValue.CStatus != PDH_CSTATUS_NEW_DATA)
                    continue;
                samples.push_back({yuzu::win::from_wide(items[i].szName ? items[i].szName : L""),
                                    items[i].FmtValue.doubleValue});
            }
        }
    }
    PdhCloseQuery(query);

    if (!fetch_ok) {
        // Distinct from both "no zones" and "the query would not open".
        ctx.write_output(
           yuzu::power_health::format_thermal_line({"unavailable", "pdh_fetch_failed", {}}));
        return 0;
    }

    ctx.write_output(yuzu::power_health::format_thermal_line(
        yuzu::power_health::interpret_windows_pdh_thermal(samples, /*query_opened_ok=*/true)));
    return 0;
}
#elif defined(__APPLE__)
int do_thermal(yuzu::CommandContext& ctx) {
    long ns_state = 0;
    bool iopm_found = false;
    int32_t iopm_level = 0;
    yuzu::power_health::macos_native::query_thermal(ns_state, iopm_found, iopm_level);
    ctx.write_output(yuzu::power_health::format_thermal_line(
        yuzu::power_health::interpret_macos_thermal(ns_state, iopm_found, iopm_level)));
    return 0;
}
#else
int do_thermal(yuzu::CommandContext& ctx) {
    DIR* raw_dir = opendir("/sys/class/thermal");
    if (!raw_dir) {
        ctx.write_output(
            yuzu::power_health::format_thermal_line({"unavailable", "sys_class_thermal_not_readable", {}}));
        return 0;
    }
    const DirHandle dir{raw_dir}; // ownership taken only after a successful open

    yuzu::power_health::ThermalReport report;
    struct dirent* entry = nullptr;
    while ((entry = readdir(dir.get())) != nullptr) {
        const std::string name = entry->d_name;
        if (name.rfind("thermal_zone", 0) != 0)
            continue;
        std::ifstream type_file("/sys/class/thermal/" + name + "/type");
        std::ifstream temp_file("/sys/class/thermal/" + name + "/temp");
        if (!type_file || !temp_file)
            continue;
        std::string type;
        std::string temp;
        std::getline(type_file, type);
        std::getline(temp_file, temp);
        if (auto celsius = yuzu::power_health::parse_linux_thermal_temp(temp))
            report.zones.emplace_back(type.empty() ? name : type, *celsius);
    }

    if (report.zones.empty()) {
        report.status = "constrained";
        report.detail = "no_thermal_zones_exposed";
    } else {
        report.status = "ok";
    }
    ctx.write_output(yuzu::power_health::format_thermal_line(report));
    return 0;
}
#endif

// ────────────────────────────────────────────────────────── power plan ────

#ifdef _WIN32

yuzu::power_health::EnumerateResult enumerate_schemes_raw() {
    yuzu::power_health::EnumerateResult out;
    for (ULONG index = 0;; ++index) {
        GUID guid{};
        DWORD size = sizeof(guid);
        const DWORD rc = PowerEnumerate(nullptr, nullptr, nullptr, ACCESS_SCHEME, index,
                                         reinterpret_cast<UCHAR*>(&guid), &size);
        if (rc == ERROR_NO_MORE_ITEMS) {
            out.complete = true;
            break;
        }
        if (rc != ERROR_SUCCESS)
            break; // honest INCOMPLETE enumeration (PH-004) — never silently
                    // treated as the full list; out.complete stays false

        yuzu::power_health::GuidBytes gb;
        gb.data1 = guid.Data1;
        gb.data2 = guid.Data2;
        gb.data3 = guid.Data3;
        for (int i = 0; i < 8; ++i)
            gb.data4[static_cast<std::size_t>(i)] = guid.Data4[i];

        DWORD name_size = 0;
        PowerReadFriendlyName(nullptr, &guid, nullptr, nullptr, nullptr, &name_size);
        std::string name;
        if (name_size > 0) {
            std::vector<wchar_t> name_buf(name_size / sizeof(wchar_t) + 1, L'\0');
            if (PowerReadFriendlyName(nullptr, &guid, nullptr, nullptr,
                                       reinterpret_cast<UCHAR*>(name_buf.data()),
                                       &name_size) == ERROR_SUCCESS) {
                name = yuzu::win::from_wide(name_buf.data());
            }
        }
        out.schemes.push_back({gb, name});
    }
    return out;
}

std::optional<yuzu::power_health::GuidBytes> get_active_scheme_raw() {
    GUID* active = nullptr;
    if (PowerGetActiveScheme(nullptr, &active) != ERROR_SUCCESS || active == nullptr)
        return std::nullopt;
    yuzu::power_health::GuidBytes gb;
    gb.data1 = active->Data1;
    gb.data2 = active->Data2;
    gb.data3 = active->Data3;
    for (int i = 0; i < 8; ++i)
        gb.data4[static_cast<std::size_t>(i)] = active->Data4[i];
    LocalFree(active);
    return gb;
}

bool set_active_scheme_raw(const yuzu::power_health::GuidBytes& gb) {
    GUID guid{};
    guid.Data1 = gb.data1;
    guid.Data2 = gb.data2;
    guid.Data3 = gb.data3;
    for (int i = 0; i < 8; ++i)
        guid.Data4[i] = gb.data4[static_cast<std::size_t>(i)];
    return PowerSetActiveScheme(nullptr, &guid) == ERROR_SUCCESS;
}

int do_power_plan(yuzu::CommandContext& ctx) {
    const auto schemes_result = bounded_call_tracked([] { return enumerate_schemes_raw(); });
    if (!schemes_result) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "bounded_call timed out enumerating power schemes");
        ctx.write_output("power_plan|-|-|0|timeout");
        return 0;
    }
    if (!schemes_result->complete) {
        // An ordinary mid-list PowerEnumerate error (PH-004/PH-011): report
        // it honestly as a constrained/incomplete inventory rather than
        // silently presenting a partial list as the whole one.
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "PowerEnumerate ended on a non-terminal error; inventory is incomplete");
        ctx.write_output("power_plan|-|-|0|enumeration_incomplete");
        return 0;
    }
    if (schemes_result->schemes.empty()) {
        // Enumeration ran to completion and genuinely found nothing —
        // still an explicit line, never silent-empty output.
        ctx.write_output("power_plan|-|-|0|no_schemes_enumerated");
        return 0;
    }

    const auto active_result = bounded_call_tracked([] { return get_active_scheme_raw(); });
    if (!active_result || !active_result->has_value()) {
        // The active-scheme read genuinely failed/timed out — report every
        // row's active flag as unknown ("-"), never fabricate every scheme
        // as inactive (PH-011): the caller cannot honestly know which
        // scheme is active without this read.
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "failed to read the active scheme; active flag is unknown for every row");
        for (const auto& scheme : schemes_result->schemes) {
            ctx.write_output(std::format("power_plan|{}|{}|-|active_unknown",
                                          yuzu::power_health::format_guid(scheme.guid),
                                          yuzu::util::safe_output_field(scheme.friendly_name)));
        }
        return 0;
    }
    const auto active = **active_result;

    for (const auto& scheme : schemes_result->schemes) {
        const bool is_active = yuzu::power_health::guids_equal(active, scheme.guid);
        // Scheme friendly names are operator-settable (powercfg -changename),
        // so they are untrusted input to the pipe-delimited grammar.
        ctx.write_output(std::format("power_plan|{}|{}|{}|ok", yuzu::power_health::format_guid(scheme.guid),
                                      yuzu::util::safe_output_field(scheme.friendly_name),
                                      is_active ? 1 : 0));
    }
    return 0;
}

int do_set_power_plan(yuzu::CommandContext& ctx, yuzu::Params params) {
    const auto scheme_param = params.get("scheme");

    // Bind the pure sequencing logic (power_health_parsers.hpp,
    // do_set_power_plan_sequence — PH-005) to the real bounded PowrProf
    // calls. read_active is reused for BOTH the prior-scheme read and the
    // post-set read-back — do_set_power_plan_sequence itself decides when
    // each runs, never this shell.
    const yuzu::power_health::SetPowerPlanOps ops{
        /* .enumerate   = */ [] { return bounded_call_tracked([] { return enumerate_schemes_raw(); }); },
        /* .read_active = */ [] { return bounded_call_tracked([] { return get_active_scheme_raw(); }); },
        /* .set_active  = */
        [](const yuzu::power_health::GuidBytes& g) {
            return bounded_call_tracked([g] { return set_active_scheme_raw(g); });
        },
    };

    const auto result = yuzu::power_health::do_set_power_plan_sequence(scheme_param, ops);

    using Outcome = yuzu::power_health::SetPowerPlanOutcome;
    const auto fmt_or_dash = [](const std::optional<yuzu::power_health::GuidBytes>& g) {
        return g ? yuzu::power_health::format_guid(*g) : std::string("-");
    };

    switch (result.outcome) {
    case Outcome::MissingParam:
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "missing required param 'scheme'");
        ctx.write_output(yuzu::power_health::format_set_power_plan_row("error", "missing_param", "", ""));
        return 1;
    case Outcome::Timeout:
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "bounded_call timed out enumerating power schemes; no mutation attempted");
        ctx.write_output(yuzu::power_health::format_set_power_plan_row("error", "timeout", "", ""));
        return 1;
    case Outcome::EnumerationIncomplete:
        ctx.set_result_status(
            YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "PowerEnumerate ended on a non-terminal error; refusing to resolve a scheme name "
            "against an incomplete inventory; no mutation attempted");
        ctx.write_output(yuzu::power_health::format_set_power_plan_row("error", "enumeration_incomplete", "", ""));
        return 1;
    case Outcome::Ambiguous:
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "scheme name matched more than one scheme; no mutation attempted");
        ctx.write_output(yuzu::power_health::format_set_power_plan_row("error", "ambiguous", "", ""));
        return 1;
    case Outcome::NoMatch:
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "no scheme matched the given name/GUID; no mutation attempted");
        ctx.write_output(yuzu::power_health::format_set_power_plan_row("error", "no_match", "", ""));
        return 1;
    case Outcome::ReadPriorFailed:
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "failed to read the prior active scheme; no mutation attempted");
        ctx.write_output(yuzu::power_health::format_set_power_plan_row("error", "read_prior_failed", "", ""));
        return 1;
    case Outcome::SetFailed:
        // Deliberately does NOT claim "no mutation applied". SetFailed folds an
        // ordinary API failure together with a TIMEOUT (see SetPowerPlanOutcome's
        // comment), and a timed-out PowerSetActiveScheme may still have landed —
        // the plugin cannot tell. Claiming no mutation is the one wording that
        // would stop an operator going to check, on the exact path where the
        // final state is unknown. previous_guid is reported so they can revert.
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "PowerSetActiveScheme failed or timed out; the mutation was NOT "
                               "confirmed and, on a timeout, may still have been applied — final "
                               "state is unknown; previous_guid is reported for manual "
                               "verification/revert");
        ctx.write_output(yuzu::power_health::format_set_power_plan_row("error", "set_failed", fmt_or_dash(result.previous_guid), ""));
        return 1;
    case Outcome::ReadbackFailed:
        // The set call itself already reported success — final state is
        // UNKNOWN, never claimed unchanged (PH-007). previous_guid is
        // still reported so the caller can verify/revert manually.
        ctx.set_result_status(
            YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "post-set read-back failed; the mutation may already be applied and final state is "
            "unknown — previous_guid is reported for manual verification/revert");
        ctx.write_output(yuzu::power_health::format_set_power_plan_row(
            "error", "readback_failed", fmt_or_dash(result.previous_guid), ""));
        return 1;
    case Outcome::ReadbackMismatch:
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "post-set read-back scheme does not match the target; final state is uncertain");
        // previous_guid/new_guid keep their declared meaning here too: the
        // scheme in force BEFORE the mutation, and what the read-back actually
        // observed. The target that was asked for is named in the status text
        // rather than overloading a declared column with a third meaning.
        ctx.write_output(yuzu::power_health::format_set_power_plan_row(
            "error", "readback_mismatch", fmt_or_dash(result.previous_guid),
            fmt_or_dash(result.new_guid)));
        return 1;
    case Outcome::Ok:
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        // Four fields after the discriminator on EVERY branch, success included.
        // content/definitions/power_health.yaml declares the result columns
        // positionally (status, reason, previous_guid, new_guid), so a success
        // row that omitted `reason` shifted previous_guid into reason and
        // new_guid into previous_guid — corrupting exactly the value an
        // operator needs in order to revert.
        ctx.write_output(yuzu::power_health::format_set_power_plan_row(
            "ok", "", fmt_or_dash(result.previous_guid), fmt_or_dash(result.new_guid)));
        return 0;
    }

    // Unreachable — SetPowerPlanOutcome's cases above are exhaustive
    // (-Wswitch would flag a future enumerator added without a case here).
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                           "unrecognised internal outcome");
    ctx.write_output(yuzu::power_health::format_set_power_plan_row("error", "internal", "", ""));
    return 1;
}

#else // !_WIN32 — macOS UNSUPPORTED / Linux PLANNED, neither ever mutates

int do_power_plan(yuzu::CommandContext& ctx) {
#ifdef __APPLE__
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                           "macOS has no named power schemes; IOPMSetPMPreferences is SPI, not adopted");
    ctx.write_output("power_plan|-|-|0|unsupported_on_macos");
#else
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                           "power_plan is PLANNED (platform_profile) — not implemented in this package");
    ctx.write_output("power_plan|-|-|0|planned_not_implemented");
#endif
    return 0;
}

int do_set_power_plan(yuzu::CommandContext& ctx, yuzu::Params /*params*/) {
#ifdef __APPLE__
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                           "macOS has no named power schemes; no mutation attempted");
    ctx.write_output(yuzu::power_health::format_set_power_plan_row("error", "unsupported_on_macos", "", ""));
#else
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                           "power_plan mutation is PLANNED on Linux, not implemented; no mutation attempted");
    ctx.write_output(yuzu::power_health::format_set_power_plan_row("error", "planned_not_implemented", "", ""));
#endif
    // Genuinely did not mutate — non-zero, same contract as the Windows
    // failure branches (exit code and typed status agree in every branch).
    return 1;
}

#endif // _WIN32

// Windows rung/mechanism strings live only in kActionDescriptors below;
// Linux battery/thermal are CONSTRAINED rung 1, fixture-verified with no
// live venue in this run (see the file header + probe-findings.md).
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "battery",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "/sys/class/power_supply uevent parsing",
         "fixture-verified; no live Linux venue in this run"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IOPSCopyPowerSourcesInfo/IOPSCopyPowerSourcesList",
         "IOPS is used deliberately over the AppleSmartBattery IORegistry node, which is "
         "present, matched and active even on a battery-less Mac mini and would report a "
         "phantom battery; the battery-PRESENT path is fixture-tested and UNVERIFIED on real "
         "Mac battery hardware — the run host was a desktop"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "GetSystemPowerStatus + CallNtPowerInformation(SystemBatteryState)",
         "no-system-battery path measured live on the-rig (BatteryFlag=128); the "
         "battery-PRESENT path is now verified on real hardware (HP ZBook Firefly, "
         "PR #4009 review), which is what caught the AC-resting state being reported "
         "as unknown rather than not_charging"},
    },
    {
        /* .action      = */ "thermal",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "/sys/class/thermal zone parsing",
         "fixture-verified; no live Linux venue in this run"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "NSProcessInfo.thermalState + IOPMGetThermalWarningLevel",
         "reports a 4-level thermal-pressure enum, never a temperature reading"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "PDH \\Thermal Zone Information(*)\\Temperature",
         "zero live counter instances is the measured normal case on desktop hardware "
         "(the-rig, 2026-09-04); reports no_thermal_zones_exposed as an explicit success, "
         "never an error or a fabricated zero"},
    },
    {
        /* .action      = */ "power_plan",
        /* .linux_leg   = */
        {YUZU_SUPPORT_PLANNED, 1, "platform_profile", "declared only; not implemented in this package"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
         "macOS has no named power schemes; IOPMSetPMPreferences is SPI — not adopted"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "PowrProf PowerEnumerate + PowerReadFriendlyName + PowerGetActiveScheme",
         "4 schemes verified live on the-rig, 2026-09-04 (agrees with powercfg /list)"},
    },
    {
        /* .action      = */ "set_power_plan",
        /* .linux_leg   = */
        {YUZU_SUPPORT_PLANNED, 1, "platform_profile", "declared only; not implemented in this package"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
         "macOS has no named power schemes; IOPMSetPMPreferences is SPI — not adopted"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "PowrProf PowerSetActiveScheme", nullptr},
    },
};

} // namespace

class PowerHealthPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "power_health"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Battery, thermal, and power-plan inventory, plus a gated power-plan switch";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"battery", "thermal", "power_plan", "set_power_plan", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    /**
     * Short BOUNDED quiesce (plugin.hpp:245): wait up to 2x
     * kBoundedCallTimeout — the timeout used at every bounded_call_tracked
     * site above — for g_outstanding_calls to drain, then log the residue
     * and return. Never an unbounded join.
     *
     * g_outstanding_calls (via OutstandingGuard, bracketed entirely on each
     * CALLING thread — see its own comment) reflects "this plugin's
     * execute() call sites are still blocked waiting inside a
     * bounded_call_tracked() invocation", not "bounded_call()'s detached
     * thread is still running fn()". Since every individual wait resolves
     * — successfully or via timeout/ceiling-rejection — within
     * kBoundedCallTimeout by construction, a 2x-timeout quiesce always
     * covers the last such in-flight wait with margin, closing the window
     * where shutdown() could otherwise return (and the host proceed to
     * unload this DSO) while another thread is still executing THIS
     * plugin's own code inside a bounded_call_tracked() call.
     *
     * What this quiesce does NOT and cannot close is bounded_call()'s own
     * pre-existing residual: once a call has timed out (or was
     * ceiling-rejected), its underlying fn() body may still be physically
     * running on bounded_call()'s own detached thread, past this
     * function's return, touching this plugin's code — that class of
     * residue is inherent to bounded_wait.hpp's own contract (not
     * introduced by anything here) and is IDENTICAL in kind to
     * discovery_plugin.cpp's shutdown() (#446), the governance-accepted
     * precedent for using this primitive inside a plugin DSO at all —
     * discovery's shutdown() is EMPTY, so 100% of its calls carry this
     * residual past unload; this plugin's residual set is strictly
     * NARROWER, limited to the (rare) calls that still haven't resolved
     * after 2x their own timeout. dlclose only happens at final process
     * exit (agent.cpp:3136-3169). Closing this residual class entirely
     * would require either a cancellable underlying PowrProf/PDH call
     * (neither API offers one) or moving bounded_call() itself out of
     * plugin DSOs altogether — both out of this package's scope; per
     * plugin.hpp:245's own guidance ("accept a bounded resource residue
     * instead"), that is the accepted trade, not a defect this file can
     * fix alone.
     */
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {
        const auto deadline = std::chrono::steady_clock::now() + 2 * kBoundedCallTimeout;
        while (g_outstanding_calls.load(std::memory_order_relaxed) > 0 &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (const int residue = g_outstanding_calls.load(std::memory_order_relaxed); residue > 0) {
            std::fprintf(stderr,
                          "power_health: shutdown quiesce timed out with %d bounded call(s) still "
                          "outstanding\n",
                          residue);
        }
    }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "battery")
            return do_battery(ctx);
        if (action == "thermal")
            return do_thermal(ctx);
        if (action == "power_plan")
            return do_power_plan(ctx);
        if (action == "set_power_plan")
            return do_set_power_plan(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(PowerHealthPlugin)
