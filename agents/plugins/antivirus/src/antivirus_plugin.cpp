/**
 * antivirus_plugin.cpp — Antivirus product detection plugin for Yuzu
 *
 * Actions:
 *   "products"      — List installed AV products.
 *   "status"        — Antivirus engine/definitions status.
 *   "av_exclusions" — Windows Defender exclusion lists (paths/processes/
 *                      extensions), merged from both the local
 *                      operator-editable hive and the GPO/MDM policy hive,
 *                      each row tagged with its source. Windows-only; a
 *                      Windows-only concept.
 *
 * Output is pipe-delimited via write_output().
 *
 * Acquisition (ADR-3002 native/argv migration): Windows reads
 * root\SecurityCenter2 and root\Microsoft\Windows\Defender directly via the
 * shared bounded WMI helper (rung 1, in-process — no more `powershell
 * Get-CimInstance`/`Get-MpComputerStatus` subprocess) and reads Defender's
 * exclusion lists directly from the registry (rung 1). Linux/macOS acquire
 * via yuzu::agent::run_bounded_subprocess — direct argv, no shell, bounded
 * deadline (rung 2; no native replacement exists for `pgrep`/PlistBuddy/
 * `systemextensionsctl` in this plugin), except the two definitions-
 * freshness reads, which are plain `stat()` calls (rung 1). See
 * docs/agent-spawn-sink-manifest.md for the per-site evidence rows.
 */

#include <yuzu/plugin.hpp>

#include "antivirus_parsers.hpp"

#include <algorithm>
#include <format>
#include <string>
#include <string_view>

#ifndef _WIN32
#include <chrono>
#include <yuzu/agent/runner_status.hpp>    // yuzu::agent::forward_runner_failure (ABI4 result seam)
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess
#endif

#if defined(__linux__) || defined(__APPLE__)
#include <ctime>       // std::tm / strftime — definitions-freshness mtime render
#include <sys/stat.h>  // ::stat() (rung 1) — ClamAV daily.cvd / XProtect bundle mtime
#endif
#if defined(__linux__)
#include <filesystem>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_reg_handle.hpp> // yuzu::win::RegKey (PR1.7)
#include <win_profiles.hpp>   // yuzu::win::enumerate_value_names (PR1.7)
#include <wmi_bounded.hpp>    // yuzu::shared::wmi::run_bounded_wmi_query (WP-A, wave 3)
#endif

namespace {

#ifndef _WIN32
// Per-call wall-clock bound for the POSIX acquisition tools (pgrep/
// PlistBuddy/systemextensionsctl). Generous enough never to fire in
// practice, short enough that a wedged tool cannot pin the instruction
// worker indefinitely — matches the users/certificates migration precedent's
// kUsersCmdDeadline.
constexpr std::chrono::seconds kAvCmdDeadline{5};
#endif

#ifdef _WIN32

// ── Windows: WMI-backed products/status, registry-backed exclusions ────────

void list_av_products_win(yuzu::CommandContext& ctx) {
    // sink: no manifest row — in-process WMI/COM (rung 1), not a spawn.
    auto result = yuzu::shared::wmi::run_bounded_wmi_query(
        L"root\\SecurityCenter2", L"SELECT displayName, productState FROM AntiVirusProduct");

    if (result.error) {
        // Most commonly root\SecurityCenter2 being entirely absent (Windows
        // Server SKUs don't ship Security Center at all), but *result.error
        // carries whatever the helper actually observed rather than
        // asserting that one cause unconditionally — a typed unavailable
        // result with real provenance, never a crash or a fabricated
        // "0 products".
        ctx.write_output(std::format("not_available|SecurityCenter2 query failed: {}",
                                     yuzu::antivirus::sanitize_field(*result.error)));
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "antivirus:securitycenter2_unavailable");
        return;
    }

    auto lines = yuzu::antivirus::render_wsc_products(result.rows);
    if (lines.empty()) {
        ctx.write_output("av_count|0");
    } else {
        for (const auto& line : lines)
            ctx.write_output(line);
    }
    if (result.truncated) {
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "antivirus:securitycenter2_truncated");
    }
}

void defender_status_win(yuzu::CommandContext& ctx) {
    // sink: no manifest row — in-process WMI/COM (rung 1), not a spawn.
    auto result = yuzu::shared::wmi::run_bounded_wmi_query(
        L"root\\Microsoft\\Windows\\Defender",
        L"SELECT RealTimeProtectionEnabled, AntivirusSignatureVersion, "
        L"AntivirusSignatureLastUpdated, QuickScanEndTime FROM MSFT_MpComputerStatus");

    if (result.error) {
        // This namespace is absent when Defender isn't the active AV or is
        // uninstalled -- a different, non-error condition from "Defender is
        // installed but the query broke" that the helper doesn't distinguish
        // today, so both are reported the same honest way rather than
        // guessing which applies.
        ctx.write_output(std::format("not_available|Defender status query failed: {}",
                                     yuzu::antivirus::sanitize_field(*result.error)));
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "antivirus:defender_namespace_unavailable");
        return;
    }
    if (result.rows.empty()) {
        ctx.write_output("status|not_available");
        return;
    }
    for (const auto& line : yuzu::antivirus::render_defender_status(result.rows.front()))
        ctx.write_output(line);
}

// Ordered worst-to-best so a plain `std::max` across all six subkey reads
// (3 kinds x 2 hives) picks the single worst outcome to forward, rather than
// whichever happened to be seen first (adversarial-review gate-2 finding:
// a later, worse failure must not be masked by an earlier, milder one).
enum class ExclusionReadOutcome {
    kOk = 0,
    kEnumerationIncomplete = 1,
    kUnavailable = 2,
    kPermissionDenied = 3,
};

// Attempts to open+enumerate one exclusion subkey (either the local
// operator-editable hive or the GPO/MDM policy hive). Returns the value
// names on success; ERROR_FILE_NOT_FOUND is folded into a genuinely-empty
// result (the subkey never existing means no exclusion of this kind was
// ever configured through this source), NOT a failure. Any other non-
// success open outcome is reported via `write_output` exactly once per call
// site (never silently swallowed into a fabricated zero) and signalled back
// via the returned outcome, for the caller to aggregate across all calls.
ExclusionReadOutcome read_exclusion_subkey(yuzu::CommandContext& ctx, const wchar_t* path,
                                           const char* kind,
                                           std::vector<std::string>& out_names) {
    yuzu::win::RegKey key;
    const LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, key.put());
    if (rc == ERROR_FILE_NOT_FOUND)
        return ExclusionReadOutcome::kOk; // a real "zero" for this source, not a lie
    if (rc == ERROR_ACCESS_DENIED) {
        // Current Windows builds ACL this key against non-admin readers.
        // Reported as its own typed status, never collapsed into a silent
        // "no exclusions" -- that would be a false negative that looks
        // like a clean posture.
        ctx.write_output(std::format("permission_denied|exclusions {} access denied", kind));
        return ExclusionReadOutcome::kPermissionDenied;
    }
    if (rc != ERROR_SUCCESS) {
        ctx.write_output(std::format("not_available|exclusions {} read failed", kind));
        return ExclusionReadOutcome::kUnavailable;
    }
    auto enumeration = yuzu::win::enumerate_value_names(key.get());
    out_names = std::move(enumeration.names);
    if (!enumeration.complete) {
        // The key opened fine but enumerate_value_names() could not confirm
        // it collected every value name (a transient RegQueryInfoKeyW/
        // RegEnumValueW failure, or the safety cap). Reported as its own
        // typed status -- never silently presented as a verified-complete,
        // possibly-clean exclusion list.
        ctx.write_output(std::format("partial|exclusions {} enumeration incomplete", kind));
        return ExclusionReadOutcome::kEnumerationIncomplete;
    }
    return ExclusionReadOutcome::kOk;
}

void av_exclusions_win(yuzu::CommandContext& ctx) {
    // Two configuration planes carry exclusions, and they are not
    // interchangeable: the operator-editable local hive, and the
    // GPO/MDM-managed policy hive (the dominant plane in an enterprise
    // deployment -- reading only the local hive would report a clean
    // posture on an endpoint whose exclusions are entirely policy-driven).
    // Each kind is read from both and merged with provenance so an
    // operator can tell which plane an exclusion came from.
    struct ExclusionSubkey {
        const wchar_t* local_path;
        const wchar_t* policy_path;
        const char* kind;
    };
    static constexpr ExclusionSubkey kSubkeys[] = {
        {L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
         L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths", "path"},
        {L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes",
         L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Processes", "process"},
        {L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions",
         L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Extensions", "extension"},
    };

    auto worst = ExclusionReadOutcome::kOk;
    std::size_t total = 0;
    for (const auto& sk : kSubkeys) {
        std::vector<std::string> local_names;
        std::vector<std::string> policy_names;
        // Both reads are attempted even if one fails -- an admin-blocked
        // local hive must not hide a still-readable policy hive, and vice
        // versa; every call's outcome feeds the worst-across-all-six
        // aggregate below, not just the first one seen.
        worst = std::max(worst, read_exclusion_subkey(ctx, sk.local_path, sk.kind, local_names));
        worst = std::max(worst, read_exclusion_subkey(ctx, sk.policy_path, sk.kind, policy_names));

        auto merged = yuzu::antivirus::merge_exclusion_sources(local_names, policy_names);
        for (const auto& line : yuzu::antivirus::render_exclusion_lines(merged, sk.kind)) {
            ctx.write_output(line);
            ++total;
        }
    }
    switch (worst) {
    case ExclusionReadOutcome::kPermissionDenied:
        ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED,
                              YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "antivirus:av_exclusions_access_denied");
        break;
    case ExclusionReadOutcome::kUnavailable:
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "antivirus:av_exclusions_open_failed");
        break;
    case ExclusionReadOutcome::kEnumerationIncomplete:
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "antivirus:av_exclusions_enumeration_incomplete");
        break;
    case ExclusionReadOutcome::kOk:
        if (total == 0)
            ctx.write_output("exclusion_count|0");
        break;
    }
}

#elif defined(__linux__)

// ── Linux: pgrep-based product/status detection ─────────────────────────────

// Shared by both do_products_linux() and do_status_linux() -- one helper,
// so a status() call checks liveness the exact same way products() does
// rather than a second, potentially-drifting implementation.
// Sink IDs for each call site live in docs/agent-spawn-sink-manifest.md as
// antivirus/<calling-function>#<n> — the CALLER (list_av_products_linux /
// list_status_linux), not this shared helper, is the site's Location.
bool pgrep_running(yuzu::CommandContext& ctx, bool& status_forwarded,
                   std::string_view process_name, bool full_cmdline) {
    auto pgrep = yuzu::agent::probe_tool_path({"/usr/bin/pgrep", "/bin/pgrep"});
    auto res = yuzu::agent::run_bounded_subprocess(
        {pgrep, full_cmdline ? "-f" : "-x", std::string(process_name)},
        yuzu::agent::SubprocessOptions{.deadline = kAvCmdDeadline});
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, res);
    return !res.lines.empty();
}

void list_av_products_linux(yuzu::CommandContext& ctx) {
    bool status_forwarded = false;
    int found = 0;

    // sink: antivirus/list_av_products_linux#1
    if (pgrep_running(ctx, status_forwarded, "clamd", false)) {
        ctx.write_output("av|ClamAV|running");
        ++found;
    }

    // sink: antivirus/list_av_products_linux#2
    if (pgrep_running(ctx, status_forwarded, "falcon-sensor", false)) {
        ctx.write_output("av|CrowdStrike Falcon|running");
        ++found;
    } else if (std::filesystem::exists("/opt/CrowdStrike")) {
        ctx.write_output("av|CrowdStrike Falcon|installed");
        ++found;
    }

    // sink: antivirus/list_av_products_linux#3
    if (pgrep_running(ctx, status_forwarded, "sophos", true)) {
        ctx.write_output("av|Sophos|running");
        ++found;
    } else if (std::filesystem::exists("/opt/sophos-av")) {
        ctx.write_output("av|Sophos|installed");
        ++found;
    }

    if (found == 0) {
        ctx.write_output("av_count|0");
    }
}

void list_status_linux(yuzu::CommandContext& ctx) {
    bool status_forwarded = false;

    // ClamAV: real liveness (same pgrep check as products()) plus a genuine
    // "definitions last updated" fact via a plain stat() on ClamAV's own
    // signature database -- rung 1, no subprocess at all -- when clamd is
    // actually present. This is the honest replacement for the previous
    // hardcoded "not_available" on every Linux status() call.
    // sink: antivirus/list_status_linux#1
    const bool clamd_running = pgrep_running(ctx, status_forwarded, "clamd", false);
    ctx.write_output(std::format("av|ClamAV|{}", clamd_running ? "running" : "not_running"));
    if (clamd_running) {
        struct stat st{};
        if (::stat("/var/lib/clamav/daily.cvd", &st) == 0) {
            char buf[32];
            std::tm tm_buf{};
            if (::gmtime_r(&st.st_mtime, &tm_buf) != nullptr &&
                std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf) > 0) {
                ctx.write_output(std::format("last_update|{}", buf));
            }
        }
    }

    // Other EDRs: presence-only, honestly constrained -- this plugin has no
    // rung-1 way to read CrowdStrike/Sophos's own definitions state on
    // Linux, so it reports detection, never fabricated freshness data.
    // sink: antivirus/list_status_linux#2
    const bool falcon_running = pgrep_running(ctx, status_forwarded, "falcon-sensor", false);
    ctx.write_output(
        std::format("av|CrowdStrike Falcon|{}", falcon_running ? "detected" : "not_detected"));

    // sink: antivirus/list_status_linux#3
    const bool sophos_running = pgrep_running(ctx, status_forwarded, "sophos", true);
    ctx.write_output(std::format("av|Sophos|{}", sophos_running ? "detected" : "not_detected"));
}

#elif defined(__APPLE__)

// ── macOS: PlistBuddy/systemextensionsctl/pgrep via the bounded runner ──────

constexpr const char* kXProtectInfoPlist =
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist";
constexpr const char* kXProtectAppInfoPlist =
    "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist";
constexpr const char* kMrtAppInfoPlist =
    "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist";

// Direct argv, no shell -- the old `2>/dev/null` suffix is simply this
// call's default merge_stderr=false (child stderr discarded), the runner's
// documented equivalent. Returns a copy (not a view) so the result outlives
// the SubprocessResult this function's own `res` goes out of scope with.
// Sink IDs live in docs/agent-spawn-sink-manifest.md as
// antivirus/<calling-function>#<n> — the CALLER, not this shared helper, is
// the site's Location.
std::string read_plist_version(yuzu::CommandContext& ctx, bool& status_forwarded,
                               const char* plist_path) {
    auto res = yuzu::agent::run_bounded_subprocess(
        {"/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", plist_path},
        yuzu::agent::SubprocessOptions{.deadline = kAvCmdDeadline});
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, res);
    return std::string(yuzu::antivirus::parse_plist_version(res.output));
}

void list_av_products_macos(yuzu::CommandContext& ctx) {
    bool status_forwarded = false;

    // XProtect: probe the definition bundle instead of asserting it — the
    // old hardcoded "active" reported protection without reading anything.
    // sink: antivirus/list_av_products_macos#1
    auto xp_ver = read_plist_version(ctx, status_forwarded, kXProtectInfoPlist);
    if (!xp_ver.empty()) {
        ctx.write_output("av|XProtect|active");
        ctx.write_output(std::format("xprotect_version|{}", xp_ver));
    } else {
        ctx.write_output("av|XProtect|unknown");
    }

    // Third-party EDR/AV: the authoritative source is the endpoint-security
    // system-extension registry (unprivileged read); modern EDRs must
    // register there. Emits an av row per extension plus a detail row with
    // bundle id and version.
    // sink: antivirus/list_av_products_macos#2
    auto sysext_res = yuzu::agent::run_bounded_subprocess(
        {"/usr/bin/systemextensionsctl", "list"},
        yuzu::agent::SubprocessOptions{.deadline = kAvCmdDeadline});
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, sysext_res);
    auto exts = yuzu::antivirus::parse_sysext_list(sysext_res.output);
    std::string es_names;
    for (const auto& ext : exts) {
        if (!yuzu::antivirus::is_endpoint_security(ext))
            continue;
        ctx.write_output(std::format("av|{}|{}", yuzu::antivirus::sanitize_field(ext.name),
                                      yuzu::antivirus::sysext_av_state(ext)));
        ctx.write_output(std::format("edr|{}|{}", yuzu::antivirus::sanitize_field(ext.bundle_id),
                                      yuzu::antivirus::sanitize_field(ext.version)));
        es_names += ext.name;
        es_names += '|';
        es_names += ext.bundle_id;
        es_names += '\n';
    }

    // Process-detection fallback for agents that predate (or sit outside)
    // the extension registry; skipped when the registry already reported
    // that vendor. The CrowdStrike daemon is falcond, not falcon.
    if (!yuzu::antivirus::contains_insensitive(es_names, "crowdstrike") &&
        !yuzu::antivirus::contains_insensitive(es_names, "falcon")) {
        // sink: antivirus/list_av_products_macos#3
        auto falcon_res = yuzu::agent::run_bounded_subprocess(
            {"/usr/bin/pgrep", "-x", "falcond"},
            yuzu::agent::SubprocessOptions{.deadline = kAvCmdDeadline});
        if (!status_forwarded)
            status_forwarded = yuzu::agent::forward_runner_failure(ctx, falcon_res);
        if (!falcon_res.lines.empty())
            ctx.write_output("av|CrowdStrike Falcon|running");
    }
    if (!yuzu::antivirus::contains_insensitive(es_names, "sophos")) {
        // sink: antivirus/list_av_products_macos#4
        auto sophos_res = yuzu::agent::run_bounded_subprocess(
            {"/usr/bin/pgrep", "-f", "sophos"},
            yuzu::agent::SubprocessOptions{.deadline = kAvCmdDeadline});
        if (!status_forwarded)
            status_forwarded = yuzu::agent::forward_runner_failure(ctx, sophos_res);
        if (!sophos_res.lines.empty())
            ctx.write_output("av|Sophos|running");
    }
}

void xprotect_status_macos(yuzu::CommandContext& ctx) {
    // Defender-status analogue built from what macOS can actually prove:
    // XProtect definition version + bundle freshness, and the
    // Remediator/MRT engine versions. No realtime_protection row — macOS
    // exposes no queryable equivalent, and asserting one would be false
    // confidence.
    bool status_forwarded = false;

    // sink: antivirus/xprotect_status_macos#1
    auto ver = read_plist_version(ctx, status_forwarded, kXProtectInfoPlist);
    if (ver.empty()) {
        ctx.write_output("status|unknown");
        return;
    }
    ctx.write_output(std::format("definition_version|{}", ver));

    // Definitions freshness: a plain stat() on the bundle's Info.plist —
    // rung 1, no subprocess (replaces the `/usr/bin/stat -f %Sm -t …` spawn
    // this used to run). Same `%Y-%m-%dT%H:%M:%S` local-time render BSD
    // stat's %Sm produced, so the operator-facing value is byte-identical.
    // sink: no manifest row — in-process stat() (rung 1), not a spawn.
    struct stat st{};
    if (::stat(kXProtectInfoPlist, &st) == 0) {
        char buf[32];
        std::tm tm_buf{};
        if (::localtime_r(&st.st_mtime, &tm_buf) != nullptr &&
            std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf) > 0) {
            ctx.write_output(std::format("last_update|{}", buf));
        }
    }

    // sink: antivirus/xprotect_status_macos#2
    auto remediator = read_plist_version(ctx, status_forwarded, kXProtectAppInfoPlist);
    if (!remediator.empty())
        ctx.write_output(std::format("remediator_version|{}", remediator));

    // sink: antivirus/xprotect_status_macos#3
    auto mrt = read_plist_version(ctx, status_forwarded, kMrtAppInfoPlist);
    if (!mrt.empty())
        ctx.write_output(std::format("mrt_version|{}", mrt));
}

#endif

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Windows: products/status now read WMI in process (rung 1); av_exclusions
// reads the registry in process (rung 1). Linux/macOS: no rung-1 API exists
// for this data in this plugin, so pgrep/PlistBuddy/systemextensionsctl/stat
// run as direct-argv bounded-runner invocations (rung 2) — never a shell.
// "status" now has a real Linux leg (ClamAV liveness + definitions mtime,
// other EDRs presence-only) instead of a hardcoded not_available row.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"products",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 2, "pgrep+filesystem_probe", nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "plistbuddy+systemextensionsctl+pgrep", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "wmi_securitycenter2", nullptr}},
    {"status",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 2, "pgrep+stat",
                       "ClamAV liveness+definitions mtime; CrowdStrike/Sophos presence-only"},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "plistbuddy+stat", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "wmi_defender_status", nullptr}},
    {"av_exclusions",
     /* linux   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only concept"},
     /* macos   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only concept"},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry",
                       "permission_denied sentinel on ACL'd key, never a silent empty list"}},
};

} // namespace

class AntivirusPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "antivirus"; }
    std::string_view version() const noexcept override { return "0.3.0"; }
    std::string_view description() const noexcept override {
        return "Antivirus product detection, status, and Defender exclusions";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"products", "status", "av_exclusions", nullptr};
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

        if (action == "products") {
#ifdef _WIN32
            list_av_products_win(ctx);
#elif defined(__linux__)
            list_av_products_linux(ctx);
#elif defined(__APPLE__)
            list_av_products_macos(ctx);
#endif
            return 0;
        }

        if (action == "status") {
#ifdef _WIN32
            defender_status_win(ctx);
#elif defined(__linux__)
            list_status_linux(ctx);
#elif defined(__APPLE__)
            xprotect_status_macos(ctx);
#else
            ctx.write_output("status|not_available");
#endif
            return 0;
        }

        if (action == "av_exclusions") {
#ifdef _WIN32
            av_exclusions_win(ctx);
#else
            // Windows-only concept: Linux/macOS have no Defender-equivalent
            // exclusion registry this plugin reads.
            ctx.write_output("unsupported|av_exclusions is Windows-only");
#endif
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(AntivirusPlugin)
