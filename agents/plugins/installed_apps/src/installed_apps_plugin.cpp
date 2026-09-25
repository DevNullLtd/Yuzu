/**
 * installed_apps_plugin.cpp — Installed applications plugin for Yuzu
 *
 * Actions:
 *   "list"  — Lists all installed applications.
 *   "query" — Searches for a specific app by name (partial match).
 *             Params: name (required).
 *   "list_inventory" — machine-scope software inventory for the daily sync
 *             (blob contract v2, ADR-0016). Emits the extended 12-field rows;
 *             fields an ecosystem does not store are EMPTY, never synthesised
 *             (no "-" placeholders, no sentinel row on an empty result).
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   app|name|version|publisher|install_date|install_location|bundle_id  (list, every field escape-aware)
 *   app|name|version|publisher                                (query)
 *   inv|name|version|publisher|install_date|kind|ecosystem|epoch|release|arch|
 *       signature_status|distro_id|distro_version                 (list_inventory)
 *
 * `list`/`query`/`list_per_user` output is a stable operator-facing contract
 * (content/definitions/installed_apps.yaml et al.). `list`'s two trailing
 * columns were added under ADR-0028's binding condition; its `app` tag, name,
 * version, publisher and install_date keep their position and value for every
 * real value (format_app_row now escapes every field) and `list` rows are never
 * hashed; never widen `query`/`list_per_user` — extend `list_inventory` for
 * anything the daily sync needs.
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <format>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

// Pure parse/format helpers for the list_inventory action (v2 rows). In a
// header so the unit test exercises the same code (pattern: #1662).
#include "installed_apps_inventory.hpp"
// Pure parse helpers for list/query/list_per_user's acquisition legs, plus
// the #2273 macOS pkgutil enrichment's own parsers (Wave 4 PR4.3a).
#include "installed_apps_parsers.hpp"

#if defined(__linux__) || defined(__APPLE__)
#include <chrono>
#include <sstream>

#include <spdlog/spdlog.h>
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path (Wave 4 PR4.3a, ADR-3002 rung 2)
#endif

#ifdef __APPLE__
// #2273: native CFBundle/SecStaticCode per-app enrichment for list_inventory.
#include "installed_apps_macos_enrich.hpp"
// Round-3 sync-speed fix: in-process receipt-plist reads (replaces most
// pkgutil --pkg-info spawns) + the system_profiler-output memoization cache.
#include "installed_apps_macos_receipts.hpp"
#include <dirent.h>
#include <sys/stat.h>
#include <algorithm>
#include <condition_variable>
#include <mutex>
#endif

#ifdef __linux__
#include <fstream>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// UTF-16<->UTF-8 registry conversion (#1662). In a header so the #1662
// regression test exercises the same code, not a re-implementation.
// Deliberately NOT replaced by agents/shared/win_str.hpp: this copy strips
// ALL trailing NULs where the shared one stops at the first, so aligning them
// would change output bytes for interior-NUL values. Both headers carry the
// do-not-merge note.
#include "installed_apps_registry_utf8.hpp"

// Shared per-user profile/hive ladder (#2771) — the canonical implementation
// this plugin's private copy was replaced by.
#include <user_profile_model.hpp>
#include <win_profiles.hpp>
#include <win_reg_handle.hpp>
#endif

namespace {

namespace parsers = yuzu::installed_apps::parsers;
#ifdef __APPLE__
namespace macos_receipts = yuzu::installed_apps::macos_receipts;
#endif

// ── subprocess helper (Linux / macOS) ──────────────────────────────────────
//
// Direct-argv, shell-free replacement for the old popen()-based run_command/
// command_exists helpers (Wave 4 PR4.3a, ADR-3002 rung 2): argv[0] is exec'd
// directly through the bounded runner -- no `/bin/sh -c` hop, so no
// shell-quoting/injection surface, and every call now carries a real
// deadline. probe_tool_path() replaces command_exists() (a stat-based probe,
// never a spawned `command -v`). Every query format string below is
// byte-for-byte what the old shell command line built -- see each call
// site's own comment for the exact escaping preserved.
#if defined(__linux__) || defined(__APPLE__)
// The inner per-call capture cap. The runner's 1 MB default is BELOW the
// 3.5 MiB capture cap sync_source_installed_software.cpp deliberately sets for
// this very action, so the default would truncate a dense host's dpkg/rpm
// enumeration *inside* the plugin -- before the outer cap that exists to
// detect exactly that could ever see it, and the outer skip-the-cycle guard
// would never fire. Sized above the outer cap so the OUTER one stays the
// binding limit (the runner clamps to 16 MiB).
constexpr std::size_t kToolOutputCap = 8u * 1024u * 1024u;

// Whole-collection budget. Each child already has its own deadline, but the
// per-item calls multiplied out to hours in aggregate, and the daily-sync
// thread is JOINED on every transient reconnect -- so an aggregate bound is
// what actually protects agent liveness (adversarial review, found by both
// reviewers).
//
// KNOWN RESIDUAL, accepted deliberately: this is checked BETWEEN items, never
// mid-item, so the true worst case is the budget plus one item -- a 20 s child
// deadline, or one synchronous CFBundle/SecStaticCode call, which has no
// cancellation or deadline facility at all. Bounding a native CF read would
// mean moving enrichment onto its own cancellable thread, a structural change
// well beyond this PR. The hours-scale exposure is closed; a single stalled
// native read remains theoretically unbounded and is recorded here rather than
// papered over.
constexpr std::chrono::seconds kCollectionBudget{120};

// An operator reading a log cannot decode `reason=3`.
constexpr const char* termination_reason_name(yuzu::agent::TerminationReason r) {
    switch (r) {
    case yuzu::agent::TerminationReason::exited:      return "exited";
    case yuzu::agent::TerminationReason::signaled:    return "signaled";
    case yuzu::agent::TerminationReason::deadline:    return "deadline";
    case yuzu::agent::TerminationReason::cancelled:   return "cancelled";
    case yuzu::agent::TerminationReason::line_limit:  return "line_limit";
    case yuzu::agent::TerminationReason::spawn_error: return "spawn_error";
    }
    return "unknown";
}

struct ToolOutcome {
    std::string output;
    // True when the acquisition did not run to completion on its own terms --
    // any termination_reason other than `exited`, or a capture truncation. NOT
    // set for a nonzero exit code (see the derivation at the assignment): a
    // benign nonzero exit must not make a healthy host skip its cycle forever.
    bool degraded = false;
    // True when probe_tool_path found the binary AND it executed. Distinguishes
    // "this ecosystem is absent" (normal: no dpkg on a Fedora box) from "the
    // tool is here and told us nothing" (suspicious).
    bool ran = false;
};

// `tolerate_nonzero_exit` marks the ONE call shape where a nonzero exit is
// benign and expected: a per-ID `pkgutil --pkg-info <id>` whose receipt was
// removed between the enumerating `--pkgs` call and this lookup exits 1
// (verified on macOS 26: a nonexistent receipt id gives rc=1). That is a
// single missing row, not a truncated enumeration. Every TOP-LEVEL enumerator
// leaves it false: dpkg-query -W, rpm -qa, pacman -Q, apk info, brew list,
// system_profiler and pkgutil --pkgs all exit 0 on a healthy host (verified),
// so a nonzero exit there means the enumeration did not complete and its
// output is a prefix -- which must never be published as the whole truth.
ToolOutcome run_tool(std::vector<std::string> argv,
                     std::chrono::seconds deadline = std::chrono::seconds{20},
                     bool tolerate_nonzero_exit = false) {
    if (argv.empty() || argv.front().empty())
        return {};
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = deadline,
                                             .output_cap_bytes = kToolOutputCap});
    // A cut-short enumeration returns empty/partial output that parses as "0
    // apps/packages" -- a silent false-negative. Warn so an operator can tell
    // a degraded enumeration from a genuinely empty one (sre-M1, matches
    // services_plugin.cpp's run_tool precedent).
    //
    // The discriminator is termination_reason, NOT the individual flags. A
    // first cut tested `timed_out || !tool_ran || output_truncated`, which
    // covers only `deadline` and `spawn_error` -- three of the enum's six
    // states slip through with all three flags clear (phase-2 review):
    //   signaled   -- the child was killed by a signal it received itself
    //                 (the OOM killer taking dpkg-query/rpm on a dense host),
    //   cancelled  -- shutdown or the global subprocess cancel fired,
    //   line_limit -- a deliberate bounded stop.
    // Each yields a TRUNCATED enumeration that would have been published as
    // the host's complete software set. `exited` is the only outcome that
    // means the tool finished on its own terms.
    //
    // A nonzero exit ALSO degrades, except on the per-ID shape above. An
    // earlier cut excluded exit_code wholesale on the reasoning that "several
    // inventory tools exit nonzero benignly" -- that was asserted, not
    // measured, and measurement did not support it: every top-level enumerator
    // this plugin runs exits 0 on a healthy host, and the only genuine benign
    // nonzero is the per-ID pkg-info lookup, which is now marked explicitly
    // instead of weakening the rule for everything.
    const bool degraded = parsers::is_degraded_run(
        res.termination_reason == yuzu::agent::TerminationReason::exited, res.exit_code,
        res.output_truncated, tolerate_nonzero_exit);
    if (degraded) {
        spdlog::warn("installed_apps: degraded run (reason={}, timed_out={}, tool_ran={}, "
                     "truncated={}, exit_code={}): {}",
                     termination_reason_name(res.termination_reason), res.timed_out, res.tool_ran,
                     res.output_truncated, res.exit_code, argv.front());
    }
    return ToolOutcome{std::move(res.output), degraded, res.tool_ran};
}
#endif

// ── App record ────────────────────────────────────────────────────────────

// One installed application as the three collectors produce it -- the same
// record type the pure `list` formatter and the Windows dedupe take
// (installed_apps_parsers.hpp), so the header templates run in the plugin with
// the plugin's own instantiation. install_location/bundle_id are the `list`
// action's trailing columns (ADR-0028 binding condition); NOT part of the
// ADR-0016 InvRecord; empty renders "-" (designed for Linux, which has no
// single install prefix / no bundle id).
using AppInfo = parsers::AppRowFields;

// Acquisition result + its health, returned together. `docs/cpp-conventions.md`
// lists output parameters as forbidden in new code, and the health flag has to
// travel with the data for the same reason list_inventory needs it: a
// cut-short enumeration is indistinguishable from a small one at the call site.
struct AppCollection {
    std::vector<AppInfo> apps;
    bool degraded = false;
};

struct InvCollection {
    std::vector<yuzu::installed_apps::inventory::InvRecord> records;
    bool degraded = false;
};

// Case-insensitive substring match
bool icontains(const std::string& haystack, const std::string& needle) {
    if (needle.empty())
        return true;
    if (haystack.size() < needle.size())
        return false;
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [](char a, char b) {
                              return std::tolower(static_cast<unsigned char>(a)) ==
                                     std::tolower(static_cast<unsigned char>(b));
                          });
    return it != haystack.end();
}

// Replace invalid UTF-8 bytes with '?' to avoid protobuf serialization errors.
// Windows registry strings are now read via the *W APIs + WideCharToMultiByte(CP_UTF8)
// and are already valid UTF-8, so this is defence-in-depth there (#1662); it remains
// load-bearing for the Linux/macOS subprocess paths, whose output encoding is unknown.
std::string sanitize_utf8(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            // ASCII
            out += s[i];
            ++i;
        } else if ((c >> 5) == 0x06 && i + 1 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02) {
            // Valid 2-byte sequence
            out += s[i];
            out += s[i + 1];
            i += 2;
        } else if ((c >> 4) == 0x0E && i + 2 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02) {
            // Valid 3-byte sequence
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            i += 3;
        } else if ((c >> 3) == 0x1E && i + 3 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 3]) >> 6) == 0x02) {
            // Valid 4-byte sequence
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            out += s[i + 3];
            i += 4;
        } else {
            out += '?';
            ++i;
        }
    }
    return out;
}

// ── Windows: read apps from a registry uninstall key ──────────────────────

#ifdef _WIN32

// to_wide / from_wide / reg_sz_to_utf8 now live in
// installed_apps_registry_utf8.hpp (included above) so the #1662 regression test
// runs the same conversion the plugin does. Pull them into this anonymous
// namespace so the existing unqualified call sites resolve unchanged.
using namespace yuzu::installed_apps::reg_utf8;

// RAII closer for an HKEY. Closing every handle into a RegLoadKeyW-mounted hive
// BEFORE the unload is load-bearing: RegUnLoadKeyW fails (ERROR_ACCESS_DENIED)
// while any subtree handle is open, so a leaked HKEY on a throw path would defeat
// the unload guard. Destruction order guarantees these callee handles close as
// the exception leaves enumerate_uninstall_key, before the caller's unload guard
// runs (#1662 Gate-8). Since #2771 that guard is agents/shared/win_reg_handle.hpp's
// ScopedUserHive (do_list_per_user's own HiveUnloadGuard was deleted, migrated
// onto the shared ladder) -- this file's HKeyCloser itself is unchanged and still
// used for every enumerate_uninstall_key call, hive-mounted or not.
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

void enumerate_uninstall_key(HKEY root, const char* subkey, REGSAM extra_sam,
                             std::vector<AppInfo>& apps) {
    HKEY hkey{};
    if (RegOpenKeyExW(root, to_wide(subkey).c_str(), 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS | extra_sam, &hkey) != ERROR_SUCCESS) {
        return;
    }
    HKeyCloser hkey_guard{hkey};

    // RegEnumKeyExW's lpcchName is a WCHAR COUNT, not a byte size. Bind the array
    // size and every reset to one constant so the byte-vs-count unit cannot skew —
    // the #1662 A->W conversion missed one reset site (gov Gate 3/4 BLOCKING).
    constexpr DWORD kNameBufLen = 256;
    wchar_t name_buf[kNameBufLen]{};
    DWORD idx = 0;
    DWORD name_len = kNameBufLen;

    while (RegEnumKeyExW(hkey, idx++, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr) ==
           ERROR_SUCCESS) {
        HKEY app_key{};
        if (RegOpenKeyExW(hkey, name_buf, 0, KEY_READ | extra_sam, &app_key) == ERROR_SUCCESS) {
            HKeyCloser app_guard{app_key};
            // Policy per value: see read_reg_string. Only InstallLocation accepts
            // REG_EXPAND_SZ; the four hashed fields and SystemComponent stay REG_SZ-only.
            auto read_str = [&](const char* value_name, bool accept_expand_sz) {
                return read_reg_string(app_key, value_name, accept_expand_sz);
            };

            auto display_name = read_str("DisplayName", false);
            if (!display_name.empty()) {
                // Meant to skip system components, but SystemComponent is a
                // REG_DWORD and read_reg_string accepts strings only, so this test
                // never matches today (tracked separately).
                auto sys_component = read_str("SystemComponent", false);
                if (sys_component == "1") {
                    name_len = kNameBufLen;
                    continue; // app_guard closes app_key
                }

                AppInfo app;
                app.name = std::move(display_name);
                app.version = read_str("DisplayVersion", false);
                app.publisher = read_str("Publisher", false);
                app.install_date = read_str("InstallDate", false);
                app.install_location = read_str("InstallLocation", /*accept_expand_sz=*/true);
                apps.push_back(std::move(app));
            }
        }
        name_len = kNameBufLen;
    }
}

AppCollection get_installed_apps_windows() {
    std::vector<AppInfo> apps;
    // Native registry reads: no subprocess outcome to propagate. See
    // do_list_inventory for why that is NOT a claim this leg cannot
    // under-report.
    const bool degraded = false;
    static const char* kUninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    // 64-bit HKLM
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_64KEY, apps);
    // 32-bit HKLM (WoW6432Node)
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_32KEY, apps);
    // Current user
    enumerate_uninstall_key(HKEY_CURRENT_USER, kUninstallKey, 0, apps);

    // Sort, `list`-only location layer, unique(): one pure pass shared with the
    // tests (installed_apps_parsers.hpp). The comparator and survivor are the
    // pre-ADR-0028 code byte-for-byte, so the ADR-0016 `inv|` rows and `query`
    // cannot move; only the survivor's install_location changes (it becomes the
    // lexicographically smallest populated one in its run).
    parsers::dedupe_uninstall_records(apps);

    return AppCollection{std::move(apps), degraded};
}
#endif

// ── Linux: detect package manager and list packages ───────────────────────

#ifdef __linux__
AppCollection get_installed_apps_linux() {
    std::vector<AppInfo> apps;
    bool degraded = false;

    if (auto path = yuzu::agent::probe_tool_path({"/usr/bin/dpkg-query", "/bin/dpkg-query", "/usr/local/bin/dpkg-query"});
        !path.empty()) {
        // installed_apps/get_installed_apps_linux#1 (docs/agent-spawn-sink-manifest.md)
        // Debian/Ubuntu. Format-string byte-for-byte matches the old shell
        // command's single-quoted argument: the "\n" below is the LITERAL
        // two-byte escape dpkg-query's own format interpreter expands (not a
        // real newline byte) -- contrast get_inventory_linux's tab-separated
        // sibling call, which embeds real tab/newline bytes instead.
        auto res = run_tool({path, "-W", "-f=${Package}|${Version}|${Maintainer}|${Status}\\n"});
        degraded = degraded || res.degraded;
        auto out = std::move(res.output);
        for (auto& rec : parsers::parse_dpkg_list(out)) {
            // parse_dpkg_list already filters to "install ok installed" rows.
            apps.push_back({std::move(rec.name), std::move(rec.version),
                            std::move(rec.publisher), "-", {}, {}});
        }
    } else if (auto path = yuzu::agent::probe_tool_path({"/usr/bin/rpm", "/bin/rpm", "/usr/local/bin/rpm"});
              !path.empty()) {
        // installed_apps/get_installed_apps_linux#2
        // RHEL/Fedora/SUSE.
        auto res = run_tool({path, "-qa", "--queryformat",
                             "%{NAME}|%{VERSION}-%{RELEASE}|%{VENDOR}|%{INSTALLTIME:date}\\n"});
        degraded = degraded || res.degraded;
        auto out = std::move(res.output);
        for (auto& rec : parsers::parse_rpm_list(out)) {
            apps.push_back({std::move(rec.name), std::move(rec.version),
                            std::move(rec.publisher), std::move(rec.install_date), {}, {}});
        }
    } else if (auto path = yuzu::agent::probe_tool_path({"/usr/bin/pacman", "/bin/pacman", "/usr/local/bin/pacman"});
              !path.empty()) {
        // installed_apps/get_installed_apps_linux#3
        // Arch Linux. Format: "name version".
        auto res = run_tool({path, "-Q"});
        degraded = degraded || res.degraded;
        auto out = std::move(res.output);
        for (auto& rec : parsers::parse_pacman_list(out))
            apps.push_back({std::move(rec.name), std::move(rec.version), "-", "-", {}, {}});
    }

    std::sort(apps.begin(), apps.end(),
              [](const AppInfo& a, const AppInfo& b) { return a.name < b.name; });
    return AppCollection{std::move(apps), degraded};
}
#endif

// ── macOS: list GUI apps and packages ─────────────────────────────────────

#ifdef __APPLE__
AppCollection get_installed_apps_macos() {
    std::vector<AppInfo> apps;
    bool degraded = false;

    // installed_apps/get_installed_apps_macos#1 (docs/agent-spawn-sink-manifest.md)
    // GUI applications from system_profiler. The `| grep` pipe stage is gone
    // (rung 2: clean argv, no shell) -- parsers::parse_system_profiler_apps
    // replicates the old grep's three-way line selection in-process (see that
    // function's own header comment), so this action's emitted rows are
    // byte-identical to before for every app the old grep admitted -- plus
    // apps whose names begin with punctuation or a non-ASCII byte, which the
    // old `\w` grep silently dropped and which are now included (additive
    // only; the one documented deviation from byte-identity).
    if (auto path = yuzu::agent::probe_tool_path({"/usr/sbin/system_profiler"});
        !path.empty()) {
        auto res = run_tool({path, "SPApplicationsDataType", "-detailLevel", "mini"});
        degraded = degraded || res.degraded;
        auto parsed = parsers::parse_system_profiler_apps(res.output);
        // Same reasoning as the inventory leg: every Mac has GUI applications,
        // so the tool running and listing none is a tool failure.
        if (res.ran && parsed.empty())
            degraded = true;
        for (auto& rec : parsed) {
            // rec.location (normally the .app bundle path) is now the `list` action's
            // install_location column (ADR-0028 binding condition). bundle_id is
            // filled separately, and only on the `list` path (with_bundle_ids).
            apps.push_back({std::move(rec.name), std::move(rec.version), "-",
                            std::move(rec.install_date), std::move(rec.location), {}});
        }
    }

    // Tie-break on install_location so same-named apps keep a deterministic order
    // across captures (a name-only sort leaves their relative order arbitrary).
    std::sort(apps.begin(), apps.end(), [](const AppInfo& a, const AppInfo& b) {
        return std::tie(a.name, a.install_location) < std::tie(b.name, b.install_location);
    });
    return AppCollection{std::move(apps), degraded};
}
#endif

// ── list_inventory collectors (blob contract v2) ──────────────────────────

namespace inv = yuzu::installed_apps::inventory;

#ifdef _WIN32
InvCollection get_inventory_windows() {
    std::vector<inv::InvRecord> recs;
    auto win = get_installed_apps_windows();
    for (auto& app : win.apps) {
        inv::InvRecord r;
        r.name = std::move(app.name);
        r.version = std::move(app.version);
        r.publisher = std::move(app.publisher);
        r.install_date = std::move(app.install_date);
        r.kind = "app";
        r.ecosystem = "windows";
        // epoch/release/signature honest-empty: the Uninstall hive stores no
        // NEVRA and no signature. arch stays empty too — inferring x64/x86
        // from which hive a key sat in would be synthesis, not storage.
        recs.push_back(std::move(r));
    }
    return InvCollection{std::move(recs), false};
}
#endif

#ifdef __linux__
InvCollection get_inventory_linux() {
    bool degraded = false;
    std::vector<inv::InvRecord> recs;

    const auto collect = [&recs, &degraded](std::vector<std::string> argv, auto parse_line) {
        auto res = run_tool(std::move(argv));
        // A cut-short package-manager enumeration parses as "fewer packages",
        // which the daily sync would otherwise commit as an authoritative
        // shrink of the host's software set. Propagate it so the whole cycle
        // is skipped instead.
        if (res.degraded)
            degraded = true;
        std::istringstream ss(res.output);
        std::string line;
        while (std::getline(ss, line)) {
            if (auto r = parse_line(line))
                recs.push_back(std::move(*r));
        }
    };

    if (auto path = yuzu::agent::probe_tool_path({"/usr/bin/dpkg-query", "/bin/dpkg-query", "/usr/local/bin/dpkg-query"});
        !path.empty()) {
        // installed_apps/get_inventory_linux#1 (docs/agent-spawn-sink-manifest.md)
        // ${db:Status-Abbrev} (want+status+eflag, 3 chars incl. a trailing
        // space for the usual empty eflag -- verified against debian:12, which
        // emits "ii ") keeps installed AND held
        // packages via its 2nd char == 'i' ("ii" want=install, "hi" want=hold)
        // — matches vuln_scan's vuln_identity.hpp (PR #1804) exactly, so the
        // two collectors agree on which packages are present. "rc"
        // (removed, config-files) and "un" (unknown) are correctly excluded;
        // this also supersedes the legacy `list` filter's narrower
        // "install ok installed" substring check, which excludes held.
        // The tabs/newline below are REAL bytes (single-backslash \t/\n,
        // compiled by C++ into actual TAB/LF characters) -- contrast the
        // legacy list format's literal two-byte "\n" escape above, which
        // dpkg-query's own interpreter expands instead.
        collect({path, "-W",
                "-f=${Package}\t${db:Status-Abbrev}\t${Version}\t${Architecture}\t${Maintainer}\n"},
                inv::parse_dpkg_inv_line);
    } else if (auto path = yuzu::agent::probe_tool_path({"/usr/bin/rpm", "/bin/rpm", "/usr/local/bin/rpm"});
              !path.empty()) {
        // installed_apps/get_inventory_linux#2
        // Raw SIGPGP (payload) + RSAHEADER (header) signature tags; signed vs
        // unsigned is computed in C++ by parse_rpm_inv_line/rpm_sig_present —
        // matches vuln_scan's vuln_identity.hpp (PR #1804) exactly, so the two
        // collectors agree on this field for the same rpm. Never a live
        // `rpm -K` verification. PACKAGER per the v2 spec (`list` keeps VENDOR
        // for its stable operator contract).
        collect({path, "-qa", "--queryformat",
                "%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{PACKAGER}\t"
                "%{INSTALLTIME:date}\t%{SIGPGP}\t%{RSAHEADER}\n"},
                inv::parse_rpm_inv_line);
    } else if (auto path = yuzu::agent::probe_tool_path({"/usr/bin/pacman", "/bin/pacman", "/usr/local/bin/pacman"});
              !path.empty()) {
        // installed_apps/get_inventory_linux#3
        collect({path, "-Q"}, inv::parse_pacman_inv_line);
    } else if (auto path = yuzu::agent::probe_tool_path({"/sbin/apk", "/usr/sbin/apk", "/bin/apk", "/usr/bin/apk", "/usr/local/bin/apk"});
              !path.empty()) {
        // installed_apps/get_inventory_linux#4
        // Alpine — first apk enumeration on the sync path (the legacy `list`
        // has no apk branch; precedent is vuln_scan's enumerator).
        collect({path, "info", "-v"}, inv::parse_apk_inv_line);
    }

    // Host-level distro identity, read once and stamped on every row (v2
    // contract). Honest-empty when /etc/os-release is absent (minimal
    // containers) or the keys are missing.
    std::string osrel;
    if (std::ifstream f{"/etc/os-release"}; f) {
        std::ostringstream buf;
        buf << f.rdbuf();
        osrel = buf.str();
    }
    const std::string distro_id = inv::parse_os_release(osrel, "ID");
    const std::string distro_version = inv::parse_os_release(osrel, "VERSION_ID");
    for (auto& r : recs) {
        r.distro_id = distro_id;
        r.distro_version = distro_version;
    }
    return InvCollection{std::move(recs), degraded};
}
#endif

#ifdef __APPLE__
// #2273: bound the native CFBundle/SecStaticCode enrichment calls -- this is
// a daily-sync collector (ADR-0016), not an interactive action, and a deep
// per-app scan is inherently more expensive than the one system_profiler
// call it decorates.
// These two are MEMORY/RUNAWAY guards, not routine limits, and that
// distinction is deliberate. Hitting either now DEGRADES the cycle (a
// knowingly-incomplete inventory must not be published as authoritative -- the
// server would read the omissions as uninstalls), so a cap set near normal
// volumes would freeze a legitimate host's inventory forever. Both are
// therefore set far above any plausible real host: measured on macOS 26, a
// pkgutil round trip is ~6 ms (100 in 0.59 s) and a native enrichment is
// faster still, so 5000 of each stays well inside kCollectionBudget, which is
// the bound that actually protects liveness. Reaching 5000 means something is
// wrong, which is exactly when degrading is right.
constexpr std::size_t kMaxEnrichApps = 5000;
constexpr std::size_t kMaxPkgutilPackages = 5000;

// Fills AppInfo::bundle_id (CFBundle only, no SecStaticCode) for the `list`
// action. Called from do_list ONLY: do_query and do_list_per_user also use
// get_installed_apps_macos() but never emit bundle_id, so filling it inside the
// acquisition would waste up to kMaxEnrichApps CFBundleCreate calls there.
// YUZU_HAVE_SECURITY_FRAMEWORK: meson.build resolves ['Security',
// 'CoreFoundation'] as ONE dependency() call that never partially resolves, so
// CFBundle is available exactly when the enrichment header's guard is.
// Same kMaxEnrichApps / over_budget shape as get_inventory_macos_uncached, but
// `list` is interactive and the column is informational: on exhaustion the
// remaining rows keep an empty bundle_id (rendered "-") and the run is NOT
// reported degraded -- unlike the daily-sync leg, where a silently hollowed-out
// security-posture field must not publish as authoritative.
// Budget semantics: kCollectionBudget is checked BETWEEN apps, so it bounds how
// many CFBundle reads start, not how long one takes -- a single wedged read (a
// stale network mount under a listed location) holds this dispatch worker until
// it returns, the accepted residual recorded at kCollectionBudget's declaration.
// A complete `list` (system_profiler + parse + this pass) measured 1.4-2.3 s wall
// for 323 apps on the reference Mac (2026-09-21); the pass is inside the run-to-run noise
// of the one system_profiler call, so the budget is a runaway guard, not the
// expected cost.
[[nodiscard]] std::vector<AppInfo> with_bundle_ids(std::vector<AppInfo> apps) {
    const auto start = std::chrono::steady_clock::now();
    const auto over_budget = [start]() {
        return std::chrono::steady_clock::now() - start > kCollectionBudget;
    };
    std::size_t located = 0, filled = 0;
    for (const auto& app : apps)
        located += !app.install_location.empty();
    for (auto& app : apps) {
        if (app.install_location.empty())
            continue;
        if (filled >= kMaxEnrichApps || over_budget()) {
            // The alphabetical tail loses bundle_id ("-", indistinguishable from
            // a bundle without one); the log line is the only signal.
            spdlog::warn("installed_apps: list bundle_id enrichment stopped after {} of {} "
                         "located apps (cap {} apps / {} s); remaining rows carry '-'",
                         filled, located, kMaxEnrichApps, kCollectionBudget.count());
            break;
        }
        ++filled;
        app.bundle_id = yuzu::installed_apps::macos_enrich::bundle_id_for(app.install_location);
    }
    return apps;
}

InvCollection get_inventory_macos_uncached() {
    bool degraded = false;
    std::vector<inv::InvRecord> recs;
    const auto collection_start = std::chrono::steady_clock::now();
    const auto over_budget = [collection_start]() {
        return std::chrono::steady_clock::now() - collection_start > kCollectionBudget;
    };

    // installed_apps/get_inventory_macos#1 (docs/agent-spawn-sink-manifest.md)
    // App records: acquired separately from get_installed_apps_macos()
    // (list/list_inventory are independent dispatches, so there's no result
    // to share across them) so this leg can keep the "Location:" field the
    // legacy list/query wire format never carried.
    if (auto path = yuzu::agent::probe_tool_path({"/usr/sbin/system_profiler"});
        !path.empty()) {
        auto res = run_tool({path, "SPApplicationsDataType", "-detailLevel", "mini"});
        if (res.degraded)
            degraded = true;
        auto apps = parsers::parse_system_profiler_apps(res.output);

        // OBSERVED during adversarial review: system_profiler can exit 0 having
        // written nothing at all. Every real Mac has GUI applications under
        // /System/Applications, so "the tool ran and found zero apps" is a
        // transient tool failure, not a true empty inventory. Left ungated it
        // publishes a pkgutil-only snapshot, and the daily sync replaces the
        // host's whole app inventory -- signature posture included -- with it.
        // The Linux legs deliberately do NOT get this check. Their acquisition
        // is a first-match-wins ladder, so a present-but-empty manager is
        // unusual there too -- but an empty Linux parse is already caught one
        // level up by sync_source_installed_software.cpp's empty-parse guard,
        // and adding a second, stricter rule there would risk permanently
        // freezing an unusual-but-legitimate host's inventory for no gain.
        if (res.ran && apps.empty()) {
            spdlog::warn("installed_apps: system_profiler ran but reported zero applications "
                         "-- treating as a degraded collection rather than an empty inventory");
            degraded = true;
        }

        std::size_t enriched = 0;
        bool enrich_budget_exhausted = false;
        for (auto& app : apps) {
            inv::InvRecord r;
            r.name = std::move(app.name);
            r.version = std::move(app.version);
            r.install_date = std::move(app.install_date); // Last Modified
            r.kind = "app";
            r.ecosystem = "macos";
            // #2273 native enrichment: CFBundle + SecStaticCode, in-process,
            // no subprocess (installed_apps_macos_enrich.hpp). Fills ONLY the
            // pre-existing, currently-honest-empty publisher/signature_status
            // fields -- ADR-0016: the hashed 12-field row is NEVER
            // added-to/reordered. bundle_id has no home in this row; see that
            // header's comment.
            if (!app.location.empty() && enriched < kMaxEnrichApps) {
                // The budget stopping enrichment is NOT a benign partial: every
                // remaining row's publisher/signature_status silently flips from
                // a real value to empty, which reads downstream as "we looked and
                // could not tell". That is precisely the security-posture field
                // this PR exists to populate, so it degrades the cycle rather
                // than publishing a quietly hollowed-out inventory.
                if (over_budget()) {
                    enrich_budget_exhausted = true;
                } else {
                    ++enriched;
                    auto enrich = yuzu::installed_apps::macos_enrich::enrich_app(app.location);
                    if (!enrich.publisher.empty())
                        r.publisher = std::move(enrich.publisher);
                    if (!enrich.signature_status.empty())
                        r.signature_status = std::move(enrich.signature_status);
                }
            }
            recs.push_back(std::move(r));
        }
        // An un-enriched row's empty signature_status is indistinguishable from
        // "we looked and could not tell", so say when the cap bit rather than
        // leaving the gap silent.
        if (enrich_budget_exhausted) {
            spdlog::warn("installed_apps: enrichment exceeded the {}s collection budget after {} "
                         "of {} apps -- reporting a degraded collection rather than publishing "
                         "rows whose publisher/signature_status silently went empty. If this "
                         "recurs the inventory will stop updating: raise the budget or "
                         "investigate the host.",
                         kCollectionBudget.count(), enriched, apps.size());
            degraded = true;
        } else if (apps.size() > enriched && enriched >= kMaxEnrichApps) {
            spdlog::warn("installed_apps: enrichment hit the {}-app guard ({} present) -- the "
                         "remainder would carry empty publisher/signature_status, so this "
                         "collection is reported degraded rather than published with the "
                         "security-posture fields silently blank",
                         kMaxEnrichApps, apps.size());
            degraded = true;
        }
    }

    // installed_apps/get_inventory_macos#2 (docs/agent-spawn-sink-manifest.md)
    // #2273: pkgutil receipts as additional inventory records -- system
    // installer packages (Command Line Tools, XProtect payloads, ...) that
    // never appear in system_profiler's GUI-app enumeration above.
    if (auto path = yuzu::agent::probe_tool_path({"/usr/sbin/pkgutil"}); !path.empty()) {
        auto pkgs = run_tool({path, "--pkgs"});
        if (pkgs.degraded)
            degraded = true;
        auto ids = parsers::parse_pkgutil_pkgs(pkgs.output);
        // Same reasoning as the system_profiler leg: macOS always has installer
        // receipts, so pkgutil running and listing none is a tool failure, not
        // an empty machine.
        if (pkgs.ran && ids.empty()) {
            spdlog::warn("installed_apps: pkgutil ran but listed zero receipts -- treating as "
                         "a degraded collection rather than an empty receipt set");
            degraded = true;
        }
        if (ids.size() > kMaxPkgutilPackages) {
            spdlog::warn("installed_apps: pkgutil receipts hit the {}-receipt guard ({} present) "
                         "-- omitting the remainder would read downstream as uninstalls, so "
                         "this collection is reported degraded instead",
                         kMaxPkgutilPackages, ids.size());
            degraded = true;
            ids.resize(kMaxPkgutilPackages);
        }

        std::size_t attempted = 0;
        std::size_t empty_lookups = 0;
        for (const auto& id : ids) {
            // An id is a reverse-domain receipt name; one starting with '-'
            // would be consumed by pkgutil's OWN option parser as a flag (no
            // shell involved -- this is argv[2] reaching getopt). Skip rather
            // than issue a call whose meaning we cannot predict.
            if (!id.empty() && id.front() == '-') {
                spdlog::warn("installed_apps: skipping option-like pkgutil receipt id '{}'", id);
                continue;
            }
            // Aggregate bound: the daily-sync thread is joined on every
            // transient reconnect, and per-item deadlines multiplied by the
            // receipt guard would otherwise add up to hours of
            // unresponsiveness. The budget, not the guard, is what bounds it.
            if (over_budget()) {
                spdlog::warn("installed_apps: pkgutil receipt collection exceeded its {}s budget "
                             "-- stopping early and reporting a degraded collection",
                             kCollectionBudget.count());
                degraded = true;
                break;
            }
            // installed_apps/get_inventory_macos#3 -- one call per receipt,
            // same bounded per-id loop shape as msi_packages_plugin.cpp's
            // established `list` action.
            //
            // Round-3 sync-speed fix: try an in-process receipt-plist read
            // FIRST (installed_apps_macos_receipts.hpp) -- same PkgutilInfo
            // shape, so a hit is indistinguishable from a spawn's result to
            // everything below. Only a miss (missing/malformed plist, id
            // rejected) falls back to the EXISTING pkgutil subprocess spawn,
            // preserving its exact degrade/empty-lookup accounting untouched
            // for that path.
            parsers::PkgutilInfo info;
            if (auto receipt = macos_receipts::read_receipt_plist(id)) {
                info = std::move(*receipt);
            } else {
                // tolerate_nonzero_exit: a receipt forgotten between the --pkgs
                // enumeration and this lookup makes pkgutil exit 1 (verified). That
                // is one missing row in a race, not a truncated enumeration, so it
                // must not degrade the whole cycle. This is the ONLY call here that
                // gets the exception.
                auto pkginfo = run_tool({path, "--pkg-info", id}, std::chrono::seconds{20},
                                        /*tolerate_nonzero_exit=*/true);
                if (pkginfo.degraded)
                    degraded = true;
                info = parsers::parse_pkgutil_pkg_info(pkginfo.output);
            }
            ++attempted;
            // The tolerated nonzero exit is scoped by call SHAPE; on its own it
            // is not scoped by RATE. One removed receipt is a benign race, but a
            // systemic per-ID failure (receipts DB partly removed, reads denied)
            // would emit every row with an empty version and still publish at
            // rc=0 -- and under the honest-empty contract an empty version reads
            // as "this ecosystem does not store one", which for a pkgutil
            // receipt is false. Count the empties and degrade on a bad ratio.
            if (info.version.empty() && info.install_time.empty())
                ++empty_lookups;
            inv::InvRecord r;
            r.name = id; // honest reverse-domain identifier -- never a
                         // derived "friendly" name (msi_packages precedent)
            r.version = info.version;
            r.install_date = info.install_time; // raw UNIX-epoch-seconds string --
                                                 // pkgutil's only time representation
                                                 // for a receipt; not reformatted so as
                                                 // not to synthesise a shape it doesn't
                                                 // natively carry.
            r.kind = "pkg";
            r.ecosystem = "macos_pkgutil";
            recs.push_back(std::move(r));
        }

        // A handful of races is normal; most of the receipts coming back empty
        // is a broken receipt store, not a fleet that uninstalled everything.
        constexpr std::size_t kMinLookupsToJudge = 10;
        if (attempted >= kMinLookupsToJudge && empty_lookups * 10 > attempted) {
            spdlog::warn("installed_apps: {} of {} pkgutil receipt lookups returned nothing "
                         "-- treating as a degraded collection rather than publishing receipts "
                         "whose version and install date read as 'not stored'",
                         empty_lookups, attempted);
            degraded = true;
        }
    }

    return InvCollection{std::move(recs), degraded};
}

// ── Round-3 sync-speed fix: memoize the whole macOS collection ─────────────
//
// ~90% of a macOS "Sync now" click's wall-clock time is get_inventory_macos_
// uncached() above (system_profiler ran fresh + per-receipt pkgutil spawns,
// even after the in-process receipt reads above cut most of those). None of
// that changes between two clicks a few minutes apart unless the operator
// actually installed/removed something, so a repeat sync within a short
// window can serve the previous result outright.
//
// Single-flight: two callers can race a miss simultaneously (the daily-sync
// thread's forced tick vs. an operator's ad-hoc list_inventory/list dispatch
// on a worker-pool thread — both reach this same in-process collector).
// Without single-flight both would run the full multi-second scan at once;
// the second caller instead waits on the first's result via a condition
// variable (same idiom as FleetTopologyStore's refill slot, server-side).
//
// NEVER memoizes a degraded outcome (a transient system_profiler/pkgutil
// hiccup must not get "stuck" cached and silently repeat for the whole TTL) —
// a degraded refresh invalidates the cache outright rather than storing it,
// so the very next call retries fresh instead of serving bad data.
struct ProfilerCache {
    std::mutex mu;
    std::condition_variable cv;
    bool refilling = false;
    std::string signature;
    std::chrono::steady_clock::time_point captured_at{};
    std::optional<InvCollection> result;
};

ProfilerCache& profiler_cache() {
    static ProfilerCache cache;
    return cache;
}

constexpr std::chrono::minutes kProfilerCacheTtl{10};

// One lstat()-based fingerprint covering every directory macOS applications
// or their receipts can appear under: the fixed system roots plus every
// local user's own ~/Applications. Concatenated inode+mtime pairs, not a
// cryptographic hash — a collision here only costs an extra cache miss
// (recomputes fresh), never a correctness issue, since the result is also
// bounded by kProfilerCacheTtl regardless.
std::string apps_root_signature() {
    std::string sig;
    auto add = [&sig](const std::string& path) {
        struct stat st{};
        if (::lstat(path.c_str(), &st) == 0)
            sig += path + ":" + std::to_string(st.st_ino) + ":" +
                   std::to_string(st.st_mtimespec.tv_sec) + ";";
        else
            sig += path + ":-;"; // absent — its appearance must still invalidate the cache
    };
    add("/Applications");
    add("/Applications/Utilities");
    add("/System/Applications");
    add("/System/Applications/Utilities");
    add("/System/Library/CoreServices");
    // Both receipt directories the fast path in installed_apps_macos_receipts.hpp
    // reads from — a .pkg-only install/removal (no app bundle at all: an Xcode
    // CLT update, an XProtect payload, most vendor installers) touches neither of
    // the roots above, so without these the signature is blind to it for a full
    // kProfilerCacheTtl (governance Gate 3: this comment already claimed receipt
    // coverage the code didn't actually have).
    for (const char* dir : yuzu::installed_apps::macos_receipts::kReceiptDirs)
        add(dir);
    if (DIR* d = ::opendir("/Users")) {
        std::vector<std::string> users;
        while (struct dirent* e = ::readdir(d)) {
            const std::string name(e->d_name);
            if (name == "." || name == "..")
                continue;
            users.push_back(name);
        }
        ::closedir(d);
        std::sort(users.begin(), users.end()); // deterministic signature regardless of readdir order
        for (const auto& u : users)
            add("/Users/" + u + "/Applications");
    }
    return sig;
}

InvCollection get_inventory_macos() {
    ProfilerCache& cache = profiler_cache();
    const std::string sig = apps_root_signature();
    std::unique_lock<std::mutex> lk(cache.mu);
    for (;;) {
        const bool fresh = cache.result.has_value() && cache.signature == sig &&
                           (std::chrono::steady_clock::now() - cache.captured_at) < kProfilerCacheTtl;
        if (fresh) {
            spdlog::debug("installed_apps: macOS inventory served from the {}-minute memo cache",
                          kProfilerCacheTtl.count());
            return *cache.result;
        }
        if (!cache.refilling)
            break; // this thread refills; fall through
        cache.cv.wait(lk); // another thread is already refilling — wait, then re-check
    }
    cache.refilling = true;
    lk.unlock();
    // get_inventory_macos_uncached() runs WITHOUT the lock held (so concurrent callers
    // can still check freshness / park on cache.cv while the real system_profiler scan
    // is in flight) — which means an exception here (bad_alloc, an unexpected parse
    // failure) unwinds past the re-lock/reset/notify below entirely. Without the
    // try/catch, `cache.refilling` would stay true FOREVER: every waiter already
    // parked in cache.cv.wait(lk), and every future caller arriving after this one,
    // would block indefinitely with nothing left to ever notify them (governance
    // Gate 6 SRE finding, HIGH — a real state-machine wedge, not hypothetical: this
    // plugin's own agent-side ThreadPool::quiesce_and_join() does an unconditional
    // blocking join with no timeout, so a wedge here can also keep the agent process
    // from exiting on SIGTERM). Reset the same way a degraded result does, notify,
    // then rethrow — the immediate caller still sees the failure; every OTHER waiter
    // is freed instead of wedged.
    try {
        InvCollection fresh_result = get_inventory_macos_uncached();
        lk.lock();
        cache.refilling = false;
        if (!fresh_result.degraded) {
            cache.signature = sig;
            cache.captured_at = std::chrono::steady_clock::now();
            cache.result = fresh_result;
        } else {
            cache.result.reset(); // never serve a degraded outcome — and don't leave a
                                  // stale-but-good entry silently standing in for it either
        }
        cache.cv.notify_all();
        lk.unlock();
        return fresh_result;
    } catch (...) {
        // `lk` may already be held here: the assignments above (cache.signature = sig,
        // cache.result = fresh_result) can themselves throw bad_alloc AFTER lk.lock()
        // succeeded but BEFORE the unlock below — an unconditional lk.lock() in that
        // case would call unique_lock::lock() on an already-owned mutex, which THROWS
        // system_error(EDEADLK) per libc++'s precondition check, masking the real
        // exception and skipping notify_all() entirely (governance Gate 8 cpp-safety:
        // the exact wedge this try/catch exists to prevent, just relocated to a
        // narrower window). owns_lock() makes this correct regardless of where the
        // throw originated.
        if (!lk.owns_lock())
            lk.lock();
        cache.refilling = false;
        cache.result.reset();
        cache.cv.notify_all();
        lk.unlock();
        throw;
    }
}

// Clears the memo cache — called from InstalledAppsPlugin::shutdown() so a
// re-init'd plugin instance in the SAME process (e.g. a test harness loading
// the plugin twice) never serves a previous instance's cached collection.
void clear_profiler_cache() {
    ProfilerCache& cache = profiler_cache();
    std::lock_guard<std::mutex> lk(cache.mu);
    cache.result.reset();
    cache.signature.clear();
    // Defense-in-depth (governance Gate 6 SRE, alongside the get_inventory_macos()
    // try/catch above): a waiter parked in cache.cv.wait() during a shutdown that
    // races an ACTIVE scan is otherwise woken only by that scan's own eventual
    // notify_all() — this gives shutdown its own independent wake, same intent as
    // dism_bounded_call.hpp's bounded/cancellable wait for a different plugin. Does
    // NOT touch `refilling`: if a scan is genuinely still in flight, it owns that
    // flag and will reset it itself when it returns (or throws, now caught above).
    cache.cv.notify_all();
}
#endif

int do_list_inventory(yuzu::CommandContext& ctx) {
    // A degraded acquisition yields a SMALLER-but-well-formed inventory, and
    // the daily sync (ADR-0016) replaces the host's authoritative software set
    // with whatever it receives. The server cannot tell an incomplete snapshot
    // from a complete one -- it hashes bytes, not completeness -- so the only
    // place this can be caught is here. sync_source_installed_software.cpp
    // already skips the whole cycle on a nonzero rc; this reports into that
    // existing contract rather than inventing a new signal.
#ifdef _WIN32
    // Windows acquires natively (registry), so there is no SUBPROCESS outcome to
    // propagate and `degraded` stays false here. That is NOT a claim the Windows
    // leg cannot under-report: enumerate_uninstall_key returns silently if
    // RegOpenKeyExW fails and stops at the first non-ERROR_SUCCESS from
    // RegEnumKeyExW, so a partial registry walk publishes as complete. That is
    // pre-existing behaviour this PR does not touch or worsen, and closing it
    // needs its own change plus Windows-side testing -- flagged in the gate
    // report rather than silently implied to be covered here.
    auto collected = get_inventory_windows();
#elif defined(__linux__)
    auto collected = get_inventory_linux();
#elif defined(__APPLE__)
    auto collected = get_inventory_macos();
#else
    InvCollection collected;
#endif

#if defined(__linux__) || defined(__APPLE__)
    if (collected.degraded) {
        spdlog::warn("installed_apps: list_inventory acquisition was degraded -- reporting "
                     "rc=1 so the daily sync skips this cycle instead of committing a "
                     "partial inventory as authoritative");
        return 1;
    }
#endif

    // No sentinel row: an empty result is empty output + rc 0. The sync
    // source's empty-parse guard skips the cycle rather than wiping state.
    for (const auto& r : collected.records) {
        if (r.name.empty())
            continue; // contract: row dropped if name is empty
        ctx.write_output(sanitize_utf8(inv::format_inv_row(r)));
    }
    return 0;
}

// Emit an honest failure row for a degraded operator-facing action and tell
// the caller to bail. Returns true when the collection is healthy and the
// action should proceed. Kept as one helper so `list`, `query` and
// `list_per_user` cannot drift apart on the wording or the rc.
bool report_if_degraded([[maybe_unused]] yuzu::CommandContext& ctx, bool degraded,
                        [[maybe_unused]] std::string_view action) {
    if (!degraded)
        return true;
#if defined(__linux__) || defined(__APPLE__)
    spdlog::warn("installed_apps: '{}' acquisition was degraded -- reporting an error rather "
                 "than presenting a partial or empty list as authoritative",
                 action);
#endif
    ctx.write_output("error|installed_apps: acquisition degraded (tool timed out, was killed, "
                     "failed to start, exited nonzero, or its output was truncated) -- result "
                     "withheld rather than reported as complete");
    return false;
}

// ── list action ───────────────────────────────────────────────────────────

int do_list(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    auto apps = get_installed_apps_windows();
#elif defined(__linux__)
    auto apps = get_installed_apps_linux();
#elif defined(__APPLE__)
    auto apps = get_installed_apps_macos();
#else
    AppCollection apps;
#endif

    // A degraded acquisition would otherwise render as the honest-empty
    // sentinel -- "no applications" presented to an operator as authoritative
    // when the tool was actually killed at its deadline or by the OOM killer.
    // Report it instead, matching services_plugin.cpp's precedent. The emitted
    // ROW format is untouched; only the failure signal is new.
    if (!report_if_degraded(ctx, apps.degraded, "list"))
        return 1;

#if defined(__APPLE__)
    // After the degraded guard: a withheld result must not pay the CFBundle pass.
    apps.apps = with_bundle_ids(std::move(apps.apps));
#endif

    if (apps.apps.empty()) {
        ctx.write_output(parsers::format_app_row({.name = "No applications found"}));
        return 0;
    }

    for (const auto& app : apps.apps)
        ctx.write_output(sanitize_utf8(parsers::format_app_row(app)));
    return 0;
}

// ── query action ──────────────────────────────────────────────────────────

int do_query(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto search = std::string(params.get("name"));
    if (search.empty()) {
        ctx.write_output("error|'name' parameter is required");
        return 1;
    }

#ifdef _WIN32
    auto apps = get_installed_apps_windows();
#elif defined(__linux__)
    auto apps = get_installed_apps_linux();
#elif defined(__APPLE__)
    auto apps = get_installed_apps_macos();
#else
    AppCollection apps;
#endif

    // Same reasoning as `list`: "found|false" from a killed enumerator is a
    // wrong answer presented as a correct one.
    if (!report_if_degraded(ctx, apps.degraded, "query"))
        return 1;

    bool found = false;
    for (const auto& app : apps.apps) {
        if (icontains(app.name, search)) {
            if (!found) {
                ctx.write_output("found|true");
                found = true;
            }
            ctx.write_output(sanitize_utf8(
                std::format("app|{}|{}|{}", app.name, app.version.empty() ? "-" : app.version,
                            app.publisher.empty() ? "-" : app.publisher)));
        }
    }

    if (!found) {
        ctx.write_output("found|false");
    }
    return 0;
}

// ABI4 capability declarations (#2204). Windows reads the registry
// Uninstall key(s) natively for all four actions (including the
// RegLoadKeyW-mounted per-user hive walk in "list_per_user") — rung 1.
// Linux and macOS now collect through the shared bounded argv runner
// (yuzu::agent::run_bounded_subprocess, ADR-3002 rung 2) — dpkg-query/rpm/
// pacman/apk on Linux, system_profiler(+brew for list_per_user)(+pkgutil +
// native SecCode/CFBundle enrichment for list_inventory, + CFBundle for `list`'s
// bundle_id) on macOS — Wave 4 PR4.3a's de-shell migration off the prior
// ungoverned rung-3 popen()/system() acquisition.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "list",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "dpkg-query/rpm/pacman via bounded argv runner", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "system_profiler via bounded argv runner + native CFBundle enrichment",
         nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "Reg*W enumeration of the Uninstall key(s)", nullptr},
    },
    {
        /* .action      = */ "query",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "dpkg-query/rpm/pacman via bounded argv runner", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "system_profiler via bounded argv runner", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "Reg*W enumeration of the Uninstall key(s)", nullptr},
    },
    {
        /* .action      = */ "list_per_user",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "dpkg-query/rpm/pacman via bounded argv runner", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "system_profiler + brew via bounded argv runner", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "Reg*W enumeration of HKU\\<SID>'s Uninstall key, mounting NTUSER.DAT via "
         "RegLoadKeyW when not already loaded",
         nullptr},
    },
    {
        /* .action      = */ "list_inventory",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "dpkg-query/rpm/pacman/apk via bounded argv runner", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "system_profiler + pkgutil via bounded argv runner + native SecCode/CFBundle "
         "enrichment",
         nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "Reg*W enumeration of the Uninstall key(s)", nullptr},
    },
};

} // namespace

class InstalledAppsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "installed_apps"; }
    std::string_view version() const noexcept override { return "1.2.0"; }
    std::string_view description() const noexcept override {
        return "Inventories installed applications and queries by name";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "query", "list_per_user", "list_inventory", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {
#ifdef __APPLE__
        clear_profiler_cache();
#endif
    }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "list")
            return do_list(ctx);
        if (action == "query")
            return do_query(ctx, params);
        if (action == "list_per_user")
            return do_list_per_user(ctx);
        if (action == "list_inventory")
            return do_list_inventory(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_list_per_user([[maybe_unused]] yuzu::CommandContext& ctx) {
#ifdef _WIN32
        // #2771: this walk used to be a full private copy of the ProfileList ->
        // HKU -> RegLoadKeyW ladder — one of three in the tree — and was the
        // weakest of them: it swallowed the RegUnLoadKeyW result, expanded
        // ProfileImagePath single-pass into a 512-wchar buffer with the return
        // value ignored (silent truncation), enabled neither SeBackup nor
        // SeRestore, and fell back to the SID as a display name in violation
        // of ADR-0024 D11. It now rides the shared ladder in
        // agents/shared/win_profiles.hpp, which is the canonical one.
        static const char* kUninstallKey =
            "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

        bool profiles_ok = false;
        bool truncated = false;
        auto records = yuzu::win::enumerate_profile_records(profiles_ok, &truncated);
        if (!profiles_ok) {
            ctx.write_output("error|profile_list_unreadable");
            return 1;
        }
        const auto hku_subkeys = yuzu::win::enumerate_hku_subkeys();
        // System SIDs are filtered here, BEFORE any per-profile read, rather
        // than after reading ProfileImagePath as the old walk did.
        const auto profiles = yuzu::profiles::build_profile_list(records, hku_subkeys);

        std::size_t privilege_missing = 0;
        for (const auto& profile : profiles) {
            std::vector<AppInfo> user_apps;
            yuzu::win::HiveAccessReport report;
            const auto status = yuzu::win::with_user_hive(
                profile.sid, profile.profile_path,
                [&](HKEY root) { enumerate_uninstall_key(root, kUninstallKey, 0, user_apps); },
                &report);

            // A leaked mount is the same system-wide fact wherever it happens,
            // so the shared renderer supplies the wording. Passing status=ok
            // deliberately emits ONLY the unload warning: registry's error
            // vocabulary is registry's contract, and not_found/mount_failed are
            // routine here (a logged-out user whose hive is locked) — one line
            // per profile per run would be noise, not signal.
            if (report.unload_failed) {
                for (const auto& line : yuzu::profiles::render_hive_access_lines(
                         yuzu::profiles::HiveAccessStatus::ok, true, report.mount_name,
                         profile.sid))
                    ctx.write_output(sanitize_utf8(line));
            }
            if (status == yuzu::win::HiveAccessStatus::privilege_missing)
                ++privilege_missing;

            // ADR-0024 D11: an unresolvable profile name is rendered "-", never
            // the SID. "-" (not "") matches this row's own convention for
            // version/publisher/install_date below, and is distinguishable from
            // a rendering fault. The SID fallback this replaces was a
            // fabricated display name.
            const std::string username =
                profile.profile_name.empty() ? std::string{"-"} : profile.profile_name;

            for (const auto& app : user_apps) {
                // The leading "user_app|" tag is LOAD-BEARING: installed_apps is
                // in result_parsing.hpp's kKeyValuePlugins, so the dashboard
                // splits these rows into (key, rest) — the opposite of the
                // registry list_profiles case, where a leading tag caused the
                // hp-B1 column shift. Do not strip it.
                ctx.write_output(sanitize_utf8(
                    std::format("user_app|{}|{}|{}|{}|{}", username,
                                app.name, app.version.empty() ? "-" : app.version,
                                app.publisher.empty() ? "-" : app.publisher,
                                app.install_date.empty() ? "-" : app.install_date)));
            }
        }

        // Both caps/failures are reported honestly rather than silently
        // shrinking the result, matching registry.list_profiles' precedent.
        if (truncated) {
            ctx.write_output(yuzu::profiles::render_profile_list_truncated_warning(
                yuzu::win::kMaxProfiles));
        }
        if (privilege_missing > 0) {
            ctx.write_output(std::format(
                "warning|privilege_missing: SeBackupPrivilege/SeRestorePrivilege could not be "
                "enabled for {} logged-out profile(s); their per-user apps are not listed",
                privilege_missing));
        }
        return 0;

#elif defined(__linux__)
        // List packages installed per-user via dpkg or per-user snap/flatpak
        // For dpkg-based systems, packages are system-wide. Report them as system.
        auto apps = get_installed_apps_linux();
        if (!report_if_degraded(ctx, apps.degraded, "list_per_user"))
            return 1;
        for (const auto& app : apps.apps) {
            ctx.write_output(sanitize_utf8(
                std::format("user_app|system|{}|{}|{}|{}", app.name,
                            app.version.empty() ? "-" : app.version,
                            app.publisher.empty() ? "-" : app.publisher,
                            app.install_date.empty() ? "-" : app.install_date)));
        }
        return 0;

#elif defined(__APPLE__)
        // On macOS, use brew list per user if Homebrew is installed
        // First list system apps
        auto apps = get_installed_apps_macos();
        if (!report_if_degraded(ctx, apps.degraded, "list_per_user"))
            return 1;
        for (const auto& app : apps.apps) {
            ctx.write_output(sanitize_utf8(
                std::format("user_app|system|{}|{}|{}|{}", app.name,
                            app.version.empty() ? "-" : app.version,
                            app.publisher.empty() ? "-" : app.publisher,
                            app.install_date.empty() ? "-" : app.install_date)));
        }

        // installed_apps/do_list_per_user#1 (docs/agent-spawn-sink-manifest.md)
        // Try Homebrew per-user (runs under current user).
        if (auto brew_path =
                yuzu::agent::probe_tool_path({"/opt/homebrew/bin/brew", "/usr/local/bin/brew"});
            !brew_path.empty()) {
            auto brew_res = run_tool({brew_path, "list", "--versions"});
            if (!report_if_degraded(ctx, brew_res.degraded, "list_per_user"))
                return 1;
            auto brew_out = std::move(brew_res.output);
            for (auto& rec : parsers::parse_brew_list(brew_out)) {
                ctx.write_output(sanitize_utf8(std::format(
                    "user_app|brew|{}|{}|-|-", rec.name, rec.version.empty() ? "-" : rec.version)));
            }
        }
        return 0;
#else
        ctx.write_output("error|per-user app inventory not supported on this platform");
        return 1;
#endif
    }
};

YUZU_PLUGIN_EXPORT(InstalledAppsPlugin)
