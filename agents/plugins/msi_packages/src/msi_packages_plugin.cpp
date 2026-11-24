/**
 * msi_packages_plugin.cpp — MSI / pkgutil package inventory plugin for Yuzu
 *
 * Actions:
 *   "list"           — Lists all installed packages.
 *   "product_codes"  — Returns compact list of package identifiers.
 *   "list_inventory" — Machine-context MSI products for the daily
 *                      installed-software inventory (see below).
 *   "installer_records" — Windows only. What Windows Installer itself recorded
 *                      per machine product (the InstallProperties registry values
 *                      and the Property table of the cached package), read-only
 *                      and bounded; see msi_installer_records.hpp.
 *
 * Windows: `list` and `product_codes` enumerate MSI products via
 *   MsiEnumProductsA; the code slot is a real {GUID} product code. They stay on
 *   the ANSI MsiEnumProductsA/MsiGetProductInfoA deliberately (behaviour freeze:
 *   every visible install context, `-` placeholders, a sentinel row).
 *   `list_inventory` is the wide-API leg (docs/cpp-conventions.md: the A variants
 *   return the system code page and corrupt non-ASCII names): it walks
 *   MsiEnumProductsExW(szUserSid=NULL, MSIINSTALLCONTEXT_MACHINE) and reads
 *   InstalledProductName / VersionString / Publisher with MsiGetProductInfoExW.
 *   Per-user products are never listed by it. The wire grammar and the pure row
 *   builder live in msi_packages_inventory.hpp. Its sixth token is the product's
 *   UpgradeCode from the Installer registry map (HKLM\SOFTWARE\Classes\Installer\
 *   UpgradeCodes, read once per dispatch with Reg*W; no file is opened).
 *   `installer_records` enumerates HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\
 *   Installer\UserData\S-1-5-18\Products (64-bit view, Reg*W), gates each LocalPackage
 *   path, holds a no-reparse handle on the file and hands the read of its Property table
 *   to agent-core (agents/core/src/msi_database_read.cpp), which owns the detached,
 *   single-flight, bounded worker so nothing here can run on a thread that outlives this
 *   plugin. No product is opened, repaired, installed or configured.
 * macOS: enumerates `pkgutil --pkgs` receipts; the code slot is the honest
 *   reverse-domain package identifier (e.g. "com.apple.pkg.Core") — never a
 *   fabricated GUID.
 * Other platforms: returns "platform not supported".
 *
 * Output is pipe-delimited via write_output():
 *   msi|code|name|version|install_location
 *   product_code|code|name
 */

#include <yuzu/plugin.hpp>

#include <chrono>
#include <expected>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "msi_installer_records.hpp"
#include "msi_packages_inventory.hpp"

namespace inv = yuzu::msi_packages::inventory;
namespace rec = yuzu::msi_packages::records;

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <msi.h>
#pragma comment(lib, "msi.lib")

#include <spdlog/spdlog.h>

#include <win_no_reparse_open.hpp> // yuzu::win::open_file_no_reparse (installer_records)
#include <win_profiles.hpp>        // enumerate_profile_list / expand_env_strings (privacy roots)
#include <win_reg_handle.hpp>      // yuzu::win::RegKey
#include <win_str.hpp> // yuzu::win::to_wide / from_wide (list_inventory W/Ex leg)

#include <yuzu/agent/msi_database_read.hpp> // bounded read of a cached package's Property table

// String property names for MsiGetProductInfoA
static constexpr const char* kInstalledProductName = "InstalledProductName";
static constexpr const char* kVersionString = "VersionString";
static constexpr const char* kInstallLocation = "InstallLocation";
#elif defined(__APPLE__)
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <memory>
#include <vector>

#include <spdlog/spdlog.h>
#include <subprocess_degradation.hpp> // yuzu::shared::is_degraded_run (Gate-8 remediation) -- the acquisition-health decision shared with installed_apps
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path (Wave 4 PR4.3a, ADR-3002 rung 2)

#include "msi_packages_macos.hpp"
#endif

namespace {

// Replace invalid UTF-8 bytes with '?' (MSI/pkgutil data can contain
// non-UTF-8 chars). Platform-agnostic, reused by both the Windows and macOS
// branches below. (Pipe/newline escaping of dynamic macOS fields happens in the
// pure format_msi_row/format_product_code_row helpers in msi_packages_macos.hpp.)
std::string sanitize_utf8(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            out += s[i];
            ++i;
        } else if ((c >> 5) == 0x06 && i + 1 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            i += 2;
        } else if ((c >> 4) == 0x0E && i + 2 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            i += 3;
        } else if ((c >> 3) == 0x1E && i + 3 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 3]) >> 6) == 0x02) {
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

#ifdef _WIN32
// Get an MSI product property as a std::string.
std::string get_product_info(const char* product_code, const char* property) {
    char buf[512]{};
    DWORD size = sizeof(buf);
    if (MsiGetProductInfoA(product_code, property, buf, &size) == ERROR_SUCCESS) {
        return std::string(buf, size);
    }
    return {};
}

static_assert(inv::kMachineContext == static_cast<unsigned>(MSIINSTALLCONTEXT_MACHINE));
static_assert(inv::kErrorMoreData == static_cast<unsigned>(ERROR_MORE_DATA));
static_assert(inv::kErrorUnknownProduct == static_cast<unsigned>(ERROR_UNKNOWN_PRODUCT));
static_assert(inv::kErrorUnknownProperty == static_cast<unsigned>(ERROR_UNKNOWN_PROPERTY));

// Walks the machine-context products, calling on_code(std::string) per product
// code. Returns nullopt when the walk ended with ERROR_NO_MORE_ITEMS, else a
// failure token.
//
// szUserSid MUST be NULL for MSIINSTALLCONTEXT_MACHINE (MS contract;
// ERROR_INVALID_PARAMETER with a SID, measured 2026-10-17; see
// tests/unit/fixtures/software-estate/msi_packages/windows/provenance.txt). szSid and
// pcchSid are NULL because the machine context has no SID. dwIndex may only be
// incremented after ERROR_SUCCESS (MS contract), so any other code ends the walk:
// there is no skip-the-bad-index-and-continue path.
template <class OnCode>
std::optional<std::string> enumerate_machine_products(unsigned ctx, OnCode&& on_code) {
    wchar_t code[39]{}; // {GUID} = 38 chars + NUL
    MSIINSTALLCONTEXT got{};
    for (DWORD i = 0;; ++i) {
        const UINT rc = MsiEnumProductsExW(nullptr, /*szUserSid=*/nullptr,
                                           static_cast<DWORD>(ctx), i, code, &got, nullptr,
                                           nullptr);
        if (rc == ERROR_NO_MORE_ITEMS)
            return std::nullopt;
        if (rc != ERROR_SUCCESS)
            return "windows:msi_enum:" + std::to_string(rc);
        on_code(yuzu::win::from_wide(code));
    }
}

// Reads one product property in the given install context. MsiGetProductInfoExW
// (not MsiGetProductInfoW) because the Ex form takes the context explicitly, so a
// per-user product with the same code can never shadow the machine row.
// An empty value means the product has no such property (ERROR_UNKNOWN_PRODUCT /
// ERROR_UNKNOWN_PROPERTY: an advertised-only product, or a property never set);
// any other failure is reported as a token so it can never read as an absent one.
std::expected<std::string, std::string> read_product_property(const std::string& code,
                                                              unsigned ctx,
                                                              std::string_view prop) {
    const std::wstring wcode = yuzu::win::to_wide(code);
    const std::wstring wprop = yuzu::win::to_wide(prop);
    DWORD cch = 256;
    std::wstring buf(cch, L'\0');
    UINT rc = MsiGetProductInfoExW(wcode.c_str(), nullptr, static_cast<MSIINSTALLCONTEXT>(ctx),
                                   wprop.c_str(), buf.data(), &cch);
    if (rc == ERROR_MORE_DATA) {
        // pcchValue excludes the NUL on both ERROR_MORE_DATA and success (MS
        // contract); retry_capacity adds it and refuses an implausible length.
        const auto cap = inv::retry_capacity(cch);
        if (!cap)
            return std::unexpected(cap.error());
        buf.assign(*cap, L'\0');
        cch = static_cast<DWORD>(*cap);
        rc = MsiGetProductInfoExW(wcode.c_str(), nullptr, static_cast<MSIINSTALLCONTEXT>(ctx),
                                  wprop.c_str(), buf.data(), &cch);
    }
    if (rc != ERROR_SUCCESS)
        return inv::classify_property_error(rc);
    // NUL-terminated scan (not the reported length): a value is cut at its first
    // NUL, as the registry readers do (win_str.hpp reg_sz_to_utf8).
    return yuzu::win::from_wide(buf.c_str());
}

// ── installer_records / upgrade-code map: registry shell ────────────────────────
//
// Reg*W only (never Reg*A), always the 64-bit view, machine hive only: the per-user
// UserData trees (a user SID) are never read. Every decision (caps, reasons, tokens,
// the privacy rule) is in msi_installer_records.hpp; this is plumbing.
constexpr const wchar_t* kProductsKey =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products";
constexpr const wchar_t* kUpgradeCodesKey = L"SOFTWARE\\Classes\\Installer\\UpgradeCodes";
constexpr const wchar_t* kProfileListKey =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
constexpr REGSAM kRead64 = KEY_READ | KEY_WOW64_64KEY;

// The pure header carries these codes as plain numbers (it includes no Windows header).
static_assert(rec::kErrorNoMoreItems == ERROR_NO_MORE_ITEMS);
static_assert(rec::kErrorAccessDenied == ERROR_ACCESS_DENIED);

bool key_absent(LSTATUS rc) { return rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND; }

// Reads one string value. An absent value is an empty string; any failure is the code. A value
// that is not a string (ERROR_INVALID_DATA) or is longer than kMaxValueChars (ERROR_MORE_DATA)
// is a failure, never a silent empty. REG_EXPAND_SZ is accepted only when `expands` (the
// caller expands it); otherwise it is ERROR_INVALID_DATA, so an unexpanded `%VAR%` path is
// never compared against a literal one.
std::expected<std::string, unsigned> read_string_value(HKEY key, const wchar_t* name,
                                                       bool expands = false) {
    DWORD type = 0;
    DWORD bytes = 0;
    LSTATUS rc = RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes);
    if (rc == ERROR_FILE_NOT_FOUND)
        return std::string{};
    if (rc != ERROR_SUCCESS)
        return std::unexpected(static_cast<unsigned>(rc));
    if (type != REG_SZ && !(type == REG_EXPAND_SZ && expands))
        return std::unexpected(static_cast<unsigned>(ERROR_INVALID_DATA));
    if (bytes > rec::kMaxValueChars * sizeof(wchar_t))
        return std::unexpected(static_cast<unsigned>(ERROR_MORE_DATA));
    std::vector<wchar_t> buf(bytes / sizeof(wchar_t) + 1, L'\0');
    DWORD got = bytes;
    rc = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()), &got);
    if (rc != ERROR_SUCCESS)
        return std::unexpected(static_cast<unsigned>(rc));
    return yuzu::win::reg_sz_to_utf8(buf.data(), got);
}

// Calls on_name(std::string) -> bool (false = stop) for each subkey name of `key`. 0 when the
// walk ended or was stopped, else the failing code. A key name is at most 255 characters, so
// the 256-character buffer cannot overflow.
template <class OnName>
LSTATUS walk_subkey_names(HKEY key, OnName&& on_name) {
    wchar_t name[256];
    for (DWORD i = 0;; ++i) {
        DWORD len = 256;
        const LSTATUS rc =
            RegEnumKeyExW(key, i, name, &len, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS)
            return ERROR_SUCCESS;
        if (rc != ERROR_SUCCESS)
            return rc;
        if (!on_name(yuzu::win::from_wide(name, static_cast<int>(len))))
            return ERROR_SUCCESS;
    }
}

// Products subkeys (packed product codes). An absent key is an empty walk.
template <class OnKey>
std::optional<std::string> enumerate_product_keys(OnKey&& on_key) {
    yuzu::win::RegKey root;
    LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kProductsKey, 0, kRead64, root.put());
    if (key_absent(rc))
        return std::nullopt;
    if (rc != ERROR_SUCCESS)
        return rec::registry_failure_token(static_cast<unsigned>(rc));
    rc = walk_subkey_names(root.get(), on_key);
    if (rc != ERROR_SUCCESS)
        return rec::registry_failure_token(static_cast<unsigned>(rc));
    return std::nullopt;
}

// The InstallProperties values of one product. nullopt = the product has no such key;
// a failure token = the read FAILED (never reported as an absent key).
std::expected<std::optional<rec::InstallProps>, std::string>
read_install_properties(const std::string& packed) {
    // `packed` was validated as 32 hex digits by the caller, so it cannot add a path segment.
    const std::wstring path =
        std::wstring(kProductsKey) + L"\\" + yuzu::win::to_wide(packed) + L"\\InstallProperties";
    yuzu::win::RegKey key;
    const LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, kRead64, key.put());
    if (key_absent(rc))
        return std::optional<rec::InstallProps>{};
    if (rc != ERROR_SUCCESS)
        return std::unexpected(rec::registry_failure_token(static_cast<unsigned>(rc)));
    rec::InstallProps p;
    const struct {
        const wchar_t* name;
        std::string* dest;
    } values[] = {{L"DisplayName", &p.display_name},       {L"DisplayVersion", &p.display_version},
                  {L"Publisher", &p.publisher},            {L"InstallLocation", &p.install_location},
                  {L"InstallSource", &p.install_source},   {L"LocalPackage", &p.local_package},
                  {L"InstallDate", &p.install_date}};
    for (const auto& v : values) {
        auto value = read_string_value(key.get(), v.name);
        if (!value)
            return std::unexpected(rec::registry_failure_token(value.error()));
        *v.dest = std::move(*value);
    }
    return p;
}

// The Installer's own package cache lives under the system Windows directory.
std::string system_windows_directory() {
    wchar_t buf[MAX_PATH]{};
    const UINT n = GetSystemWindowsDirectoryW(buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return {};
    return yuzu::win::from_wide(buf, static_cast<int>(n));
}

// The user profiles directory and each user profile's folder, for the privacy rule, and whether
// that list is COMPLETE. The LocalSystem, LocalService and NetworkService profiles are skipped:
// their folders sit under the Windows directory, where a machine install source is not a user
// path. `%SystemDrive%\Users` is only an extra root when ProfilesDirectory is absent; it is not
// a substitute for the list, because a profile redirected elsewhere is not under it. Any
// failure to read the list in full (rec::profile_list_complete: an open or enumeration fault,
// the 512-profile cap with more behind it, one unreadable profile key or path, or an unreadable
// ProfilesDirectory) is reported as incomplete, and the gate then withholds every path.
struct ProfileRoots {
    std::vector<std::string> roots;
    bool complete = false;
};

ProfileRoots read_profile_roots() {
    ProfileRoots out;
    rec::ProfileListFacts facts;
    std::string profiles_dir;
    yuzu::win::RegKey list;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kProfileListKey, 0, kRead64, list.put()) !=
        ERROR_SUCCESS) {
        facts.profiles_dir_failed = true; // the walk below reports its own open separately
    } else if (auto dir = read_string_value(list.get(), L"ProfilesDirectory", true)) {
        profiles_dir = std::move(*dir);
    } else {
        facts.profiles_dir_failed = true;
    }
    if (profiles_dir.empty())
        profiles_dir = "%SystemDrive%\\Users";
    const std::wstring expanded = yuzu::win::expand_env_strings(yuzu::win::to_wide(profiles_dir));
    out.roots.push_back(yuzu::win::from_wide(expanded.c_str(), static_cast<int>(expanded.size())));
    // The shared builder owns the system-profile filter (and drops a duplicated SID).
    const auto profiles = yuzu::win::enumerate_profile_list();
    for (const auto& p : yuzu::profiles::build_profile_list(profiles.records, {}))
        if (!p.profile_path.empty())
            out.roots.push_back(p.profile_path);
    facts.root_rc = profiles.root_rc;
    facts.last_rc = profiles.last_rc;
    facts.probe_rc = profiles.probe_rc;
    facts.truncated = profiles.truncated;
    facts.record_failures = profiles.record_failures.size();
    for (const auto& r : profiles.records)
        if (r.profile_image_path_unreadable)
            ++facts.unreadable_paths;
    // A root still holding `%` (expand_env_strings returns its input when the API fails and
    // Windows leaves an undefined variable in place) is counted as unresolved by the decision.
    out.complete = rec::profile_roots_complete(out.roots, facts);
    return out;
}

// A package opened with no reparse point followed below the drive root; the handle is held
// (share read only: no rename, delete or rewrite while it is open) until this object is
// destroyed, which the collector arranges to be after the database read.
struct OpenedPackage {
    rec::OpenStatus status = rec::OpenStatus::refused;
    yuzu::win::NoReparseHandle hold;
};

OpenedPackage open_package(const std::string& path) {
    OpenedPackage out;
    const std::wstring wide = yuzu::win::to_wide(path);
    if (wide.size() < 3)
        return out;
    const wchar_t root[] = {wide[0], L':', L'\\', L'\0'};
    if (GetDriveTypeW(root) != DRIVE_FIXED)
        return out; // refused: only a local fixed drive is ever opened
    auto opened = yuzu::win::open_file_no_reparse(wide, FILE_SHARE_READ);
    if (opened.status == yuzu::win::NoReparseOpen::absent) {
        out.status = rec::OpenStatus::absent;
        return out;
    }
    if (opened.status != yuzu::win::NoReparseOpen::ok)
        return out;
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(opened.file.get(), &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
        return out;
    out.hold = std::move(opened.file);
    out.status = rec::OpenStatus::ok;
    return out;
}

// UpgradeCodes subkeys with their value names (packed product codes), at most
// kMaxUpgradeValueNames + 1 of each. An absent key is an empty walk.
template <class OnUpgrade>
std::optional<std::string> enumerate_upgrade_codes(OnUpgrade&& on_upgrade) {
    yuzu::win::RegKey root;
    const LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kUpgradeCodesKey, 0, kRead64, root.put());
    if (key_absent(rc))
        return std::nullopt;
    if (rc != ERROR_SUCCESS)
        return rec::upgrade_map_failure_token(static_cast<unsigned>(rc));
    std::optional<std::string> failure;
    const LSTATUS walk = walk_subkey_names(root.get(), [&](std::string packed) {
        yuzu::win::RegKey sub;
        const LSTATUS orc =
            RegOpenKeyExW(root.get(), yuzu::win::to_wide(packed).c_str(), 0, kRead64, sub.put());
        if (key_absent(orc))
            return true; // removed since it was listed
        if (orc != ERROR_SUCCESS) {
            failure = rec::upgrade_map_failure_token(static_cast<unsigned>(orc));
            return false;
        }
        std::vector<std::string> names;
        wchar_t vname[256];
        for (DWORD j = 0; names.size() <= rec::kMaxUpgradeValueNames; ++j) {
            DWORD len = 256;
            const LSTATUS vrc =
                RegEnumValueW(sub.get(), j, vname, &len, nullptr, nullptr, nullptr, nullptr);
            if (vrc == ERROR_NO_MORE_ITEMS)
                break;
            if (vrc == ERROR_MORE_DATA) {
                names.emplace_back(); // longer than any packed code: counted as not a GUID
                continue;
            }
            if (vrc != ERROR_SUCCESS) {
                failure = rec::upgrade_map_failure_token(static_cast<unsigned>(vrc));
                return false;
            }
            names.push_back(yuzu::win::from_wide(vname, static_cast<int>(len)));
        }
        return on_upgrade(std::move(packed), std::move(names));
    });
    if (failure)
        return failure;
    if (walk != ERROR_SUCCESS)
        return rec::upgrade_map_failure_token(static_cast<unsigned>(walk));
    return std::nullopt;
}
#elif defined(__APPLE__)
// Direct-argv, shell-free replacement for the old `/bin/sh -c` hop (Wave 4
// PR4.3a, ADR-3002 rung 2): argv[0] (always the probed absolute pkgutil
// path) is exec'd directly through the bounded runner — no shell in
// between, so no shell-quoting/injection surface, and shell_quote() is gone
// entirely (each argv element, including a package identifier, is passed
// verbatim — execve never re-parses it). Route through the bounded,
// fork-lock-covered runner instead of a raw, deadline-less popen (K-7/
// CDX-07). This matters most here: `list` issues up to 500 sequential
// `pkgutil --pkg-info` calls, so a single wedged receipt read could
// otherwise pin the instruction worker for the whole loop — each call
// carries a hard per-call deadline. Internal newlines in the captured
// output are preserved for the pure per-line parsers in
// msi_packages_macos.hpp.
// Result + health together, same shape and reasoning as installed_apps'
// ToolOutcome: the health flag has to travel with the data because a
// cut-short receipt scan is otherwise indistinguishable from a genuinely
// small one at the call site.
struct CommandOutcome {
    std::string output;
    bool degraded = false;
};

CommandOutcome run_command(const std::vector<std::string>& argv) {
    if (argv.empty() || argv.front().empty())
        return {};
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{15}});
    // A cut-short pkgutil returns empty/partial output that parses as "no
    // packages" — a silent false-negative. Warn so an operator can tell a
    // degraded scan from a genuinely empty receipt DB (sre-M1). Shares
    // installed_apps' `is_degraded_run` (agents/shared/subprocess_degradation.hpp)
    // rather than a hand-duplicated inline check -- an earlier copy of this
    // check omitted the nonzero-exit branch entirely, so it never degraded on
    // a clean exit with a nonzero code, while claiming in comment to be
    // identical to the shared logic. Sharing the function is what makes that
    // claim true instead of merely stating it. `tolerate_nonzero_exit=false`:
    // unlike installed_apps' per-ID pkgutil lookup, nothing here has a
    // documented benign-nonzero case.
    const bool degraded = yuzu::shared::is_degraded_run(
        res.termination_reason == yuzu::agent::TerminationReason::exited, res.exit_code,
        res.output_truncated, /*tolerate_nonzero_exit=*/false);
    if (degraded) {
        spdlog::warn("msi_packages: degraded run (reason={}, timed_out={}, tool_ran={}, "
                     "truncated={}, exit_code={}): {}",
                     static_cast<int>(res.termination_reason), res.timed_out, res.tool_ran,
                     res.output_truncated, res.exit_code, argv.front());
    }
    std::string result = res.output;
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return CommandOutcome{std::move(result), degraded};
}

// Emit an honest failure row instead of falling through to the empty-result
// sentinel. Matches installed_apps_plugin.cpp's report_if_degraded — kept as
// its own tiny helper here rather than shared, since the two plugins' wire
// formats and CommandContext usage differ enough that sharing would cost more
// than it saves; the SHARED part (the health DECISION) already is.
void report_degraded(yuzu::CommandContext& ctx, std::string_view action) {
    spdlog::warn("msi_packages: '{}' acquisition was degraded -- reporting an error rather "
                 "than presenting a partial or empty list as authoritative",
                 action);
    ctx.write_output("error|msi_packages: acquisition degraded (pkgutil timed out, was killed, "
                     "failed to start, exited nonzero, or its output was truncated) -- result "
                     "withheld rather than reported as complete");
}

// pkgutil --pkg-info loops are sequential and per-package; a receipt DB can
// legitimately hold hundreds of entries, so bound the number of --pkg-info
// calls a single `list` gather issues.
constexpr std::size_t kMaxPackages = 500;
#endif

int do_list(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    char product_code[39]{}; // {GUID} = 38 chars + null
    int count = 0;
    for (DWORD idx = 0; MsiEnumProductsA(idx, product_code) == ERROR_SUCCESS; ++idx) {
        std::string_view code{product_code};
        auto name = get_product_info(product_code, kInstalledProductName);
        auto version = get_product_info(product_code, kVersionString);
        auto location = get_product_info(product_code, kInstallLocation);

        ctx.write_output(sanitize_utf8(
            std::format("msi|{}|{}|{}|{}", code, name.empty() ? "-" : name,
                        version.empty() ? "-" : version, location.empty() ? "-" : location)));
        ++count;
    }
    if (count == 0) {
        ctx.write_output("msi|No MSI packages found|-|-|-");
    }
#elif defined(__APPLE__)
    using yuzu::msi_packages::macos::derive_display_name;
    using yuzu::msi_packages::macos::parse_pkg_ids;
    using yuzu::msi_packages::macos::parse_pkg_info;

    // msi_packages/do_list#1 (docs/agent-spawn-sink-manifest.md)
    auto pkgutil_path = yuzu::agent::probe_tool_path({"/usr/sbin/pkgutil"});
    auto pkgs = run_command({pkgutil_path, "--pkgs"});
    bool degraded = pkgs.degraded;
    auto ids = parse_pkg_ids(pkgs.output);
    const std::size_t total_seen = ids.size();
    const bool truncated = total_seen > kMaxPackages;
    if (truncated)
        ids.resize(kMaxPackages);

    // Buffered locally rather than written to `ctx` as the loop runs:
    // yuzu_ctx_write_output only APPENDS (agent.cpp's CommandContextImpl::
    // append_output), with no way to retract what has already gone in. A
    // receipt walk can degrade partway through -- checking only after the
    // loop, with rows already committed to `ctx`, would leave the final
    // output a MIX of real rows and an error line, not the withheld result
    // report_degraded's own text promises. Buffer first, decide once, emit
    // once.
    std::vector<std::string> rows;
    for (const auto& id : ids) {
        // A receipt id is a reverse-domain name; one starting with '-' would be
        // eaten by pkgutil's OWN option parser as a flag. No shell is involved
        // -- this is argv[2] reaching getopt -- so quoting cannot help, and the
        // call's meaning would be unpredictable. Skip it instead.
        if (!id.empty() && id.front() == '-') {
            spdlog::warn("msi_packages: skipping option-like pkgutil receipt id '{}'", id);
            continue;
        }
        // msi_packages/do_list#2 -- one call per receipt, id passed as its
        // own argv element (no shell, so no quoting is needed at all).
        auto pkginfo = run_command({pkgutil_path, "--pkg-info", id});
        degraded = degraded || pkginfo.degraded;
        auto info = parse_pkg_info(pkginfo.output, id);
        rows.push_back(sanitize_utf8(yuzu::msi_packages::macos::format_msi_row(info)));
    }

    // Same reasoning as installed_apps: a killed or timed-out pkgutil must
    // never render as "No packages found" -- a wrong result presented as
    // correct (I3). Checked against the WHOLE walk (the initial `--pkgs`
    // enumeration and every per-id lookup), before anything is committed.
    if (degraded) {
        report_degraded(ctx, "list");
        return 1;
    }

    for (auto& row : rows)
        ctx.write_output(std::move(row));
    if (truncated) {
        // Honest truncation sentinel: the receipt DB held more packages than
        // kMaxPackages, so the inventory above is incomplete. The "__truncated__"
        // code slot cannot collide with a real reverse-domain package id, so a
        // positional downstream parser can distinguish this from a real row.
        ctx.write_output(std::format("msi|__truncated__|{}|-|-", total_seen));
    }
    if (rows.empty()) {
        ctx.write_output("msi|No packages found|-|-|-");
    }
#else
    ctx.write_output("error|platform not supported");
    return 1;
#endif
    return 0;
}

int do_product_codes(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    char product_code[39]{};
    int count = 0;
    for (DWORD idx = 0; MsiEnumProductsA(idx, product_code) == ERROR_SUCCESS; ++idx) {
        std::string_view code{product_code};
        auto name = get_product_info(product_code, kInstalledProductName);
        ctx.write_output(
            sanitize_utf8(std::format("product_code|{}|{}", code, name.empty() ? "-" : name)));
        ++count;
    }
    if (count == 0) {
        ctx.write_output("product_code|none|-");
    }
#elif defined(__APPLE__)
    using yuzu::msi_packages::macos::derive_display_name;
    using yuzu::msi_packages::macos::parse_pkg_ids;

    // Names are derived purely from the identifier (pkgutil's --pkg-info
    // receipt carries no separate display-name field either — see
    // msi_packages_macos.hpp), so this action never needs the per-package
    // --pkg-info round trip that `list` does.
    // msi_packages/do_product_codes#1 (docs/agent-spawn-sink-manifest.md)
    auto pkgs =
        run_command({yuzu::agent::probe_tool_path({"/usr/sbin/pkgutil"}), "--pkgs"});
    // Only one acquisition call on this action (no per-id round trip -- see
    // the comment above), so the health verdict is known before anything is
    // written; no buffer-then-emit restructuring needed here the way `list`
    // required.
    if (pkgs.degraded) {
        report_degraded(ctx, "product_codes");
        return 1;
    }
    auto ids = parse_pkg_ids(pkgs.output);
    int count = 0;
    for (const auto& id : ids) {
        ctx.write_output(sanitize_utf8(yuzu::msi_packages::macos::format_product_code_row(id)));
        ++count;
    }
    if (count == 0) {
        ctx.write_output("product_code|none|-");
    }
#else
    ctx.write_output("error|platform not supported");
    return 1;
#endif
    return 0;
}

// list_inventory: the machine-context roster for the daily installed-software
// sync. Buffer-then-emit: write_output only appends, and the status row must
// lead, so the whole roster is built (pure, msi_packages_inventory.hpp) first.
// A status answer is not a failed command, so every leg returns 0.
int do_list_inventory(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    // The upgrade-code map is a registry read, once per dispatch: no file is opened and no
    // worker is started for it, so the sixth token is the same every day for the same set.
    const auto upgrades = rec::build_upgrade_map(
        [](auto&& on_upgrade) { return enumerate_upgrade_codes(on_upgrade); });
    const auto roster = inv::collect(
        [](unsigned c, auto&& on_code) { return enumerate_machine_products(c, on_code); },
        read_product_property,
        [&upgrades](const std::string& code) { return upgrades.resolve(code); },
        upgrades.failure);
    if (upgrades.over_cap) {
        spdlog::warn("msi_packages: the UpgradeCodes map is over its cap; the roster is "
                     "constrained (windows:msi_upgrade_map:over_cap)");
    } else {
        if (upgrades.bad_names != 0)
            spdlog::warn(
                "msi_packages: {} UpgradeCodes name(s) are not a packed GUID and were skipped",
                upgrades.bad_names);
        if (!upgrades.failure) {
            // One line per dispatch: a sixth token left empty because no upgrade code, or more
            // than one, names the product would otherwise leave no trace.
            std::size_t no_code = 0;
            for (const auto& p : roster.products)
                if (p.upgrade_code.empty())
                    ++no_code;
            std::size_t ambiguous = 0;
            for (const auto& [code, entry] : upgrades.by_product)
                if (entry.ambiguous)
                    ++ambiguous;
            spdlog::info("msi_packages: {} of {} products have an empty upgrade_code token; "
                         "{} product(s) are named by more than one upgrade code",
                         no_code, roster.products.size(), ambiguous);
        }
    }
    for (auto& row : inv::render(roster))
        ctx.write_output(std::move(row));
    if (roster.constraint)
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              *roster.constraint);
    else
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
#else
#if defined(__APPLE__)
    constexpr std::string_view token = "macos:owned_by_installed_apps";
#else
    constexpr std::string_view token = "linux:no_msi";
#endif
    ctx.write_output(inv::unsupported_status_row(token));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          token);
#endif
    return 0;
}

// installer_records: what Windows Installer recorded per machine product. Buffer-then-emit
// (the status row leads); a status answer is not a failed command, so every leg returns 0.
int do_installer_records(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    rec::Context rctx;
    rctx.windows_dir = system_windows_directory();
    auto profile_roots = read_profile_roots();
    rctx.profile_roots = std::move(profile_roots.roots);
    rctx.profile_roots_complete = profile_roots.complete;
    const auto set = rec::collect_records(
        rctx, [](auto&& on_key) { return enumerate_product_keys(on_key); }, read_install_properties,
        open_package, [](const std::string& path, std::chrono::milliseconds deadline) {
            return yuzu::agent::msi::read_property_table(path, deadline);
        });
    if (set.non_guid_subkeys != 0)
        spdlog::warn("msi_packages: {} Products subkey(s) are not a packed GUID and were skipped",
                     set.non_guid_subkeys);
    for (auto& row : rec::render(set))
        ctx.write_output(std::move(row));
    if (set.constraints.any_failure())
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              set.constraints.reason());
    else
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
#else
#if defined(__APPLE__)
    constexpr std::string_view token = "macos:no_windows_installer";
#else
    constexpr std::string_view token = "linux:no_msi";
#endif
    ctx.write_output(rec::unsupported_status_row(token));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL, token);
#endif
    return 0;
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// windows: MsiEnumProductsA/MsiGetProductInfoA (list, product_codes) and
// MsiEnumProductsExW/MsiGetProductInfoExW (list_inventory) -- native MSI API,
// rung 1. installer_records: Reg*W over the Installer UserData tree plus a bounded,
// read-only open of the cached package database (agent-core) -- also rung 1.
// macos: pkgutil --pkgs / --pkg-info via the bounded argv runner (Wave 4
// PR4.3a, ADR-3002 rung 2) -- direct argv, no shell hop; ships via
// msi_packages_macos.hpp's pure parsers, unchanged.
// linux: no MSI/pkgutil equivalent -- the code returns "platform not
// supported" outright.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"list",
     /* linux   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "pkgutil via bounded argv runner", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "msi_api", nullptr}},
    {"product_codes",
     /* linux   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "pkgutil via bounded argv runner", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "msi_api", nullptr}},
    {"list_inventory",
     /* linux   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "no Windows Installer on Linux"},
     /* macos   = */
     {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
      "installed_apps.list_inventory owns the pkgutil receipt roster (ecosystem macos_pkgutil)"},
     /* windows = */
     {YUZU_SUPPORT_SUPPORTED, 1, "msi_api (MsiEnumProductsExW machine context)",
      "machine context only: per-user MSI products are never listed; measured as SYSTEM and "
      "as an admin user, non-elevated unmeasured"}},
    {"installer_records",
     /* linux   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "no Windows Installer on Linux"},
     /* macos   = */
     {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows Installer records exist only on Windows"},
     /* windows = */
     {YUZU_SUPPORT_SUPPORTED, 1,
      "registry (Installer UserData, Reg*W) + bounded read-only MsiOpenDatabaseW of the cached "
      "package",
      "machine context only; nothing is executed; 5000 records, 5 s per package, 45 s of "
      "package reads per dispatch; measured as SYSTEM and as an admin user on one host, other "
      "identities unmeasured"}},
};

} // namespace

class MsiPackagesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "msi_packages"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Enumerates installed packages and product codes (Windows MSI / macOS pkgutil)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "product_codes", "list_inventory",
                                     "installer_records", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    // Bounded quiesce (never an unbounded join): the package-read worker runs agent-core code
    // only, so it cannot touch this plugin after an unload whichever way this resolves; the wait
    // just lets a read that is about to finish do so before the process tears down.
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {
#ifdef _WIN32
        const auto deadline =
            std::chrono::steady_clock::now() + 2 * yuzu::agent::msi::kPackageDeadline;
        while (yuzu::agent::msi::read_in_flight() &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
#endif
    }

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        // One firewall around the whole body: nothing may throw across the frozen
        // plugin ABI. The catch reports a fixed token (never the exception text) and
        // must not throw itself (pkg_inventory report_execute_exception shape).
        try {
            if (action == "list")
                return do_list(ctx);
            if (action == "product_codes")
                return do_product_codes(ctx);
            if (action == "list_inventory")
                return do_list_inventory(ctx);
            if (action == "installer_records")
                return do_installer_records(ctx);

            ctx.write_output(std::format("unknown action: {}", action));
            return 1;
        } catch (...) {
            try {
                ctx.write_output(yuzu::shared::format_status_row(
                    action, yuzu::shared::StatusLevel::constrained, "msi_packages:exception"));
                ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                      YUZU_RESULT_COMPLETENESS_PARTIAL, "msi_packages:exception");
            } catch (...) {
            }
            return 1;
        }
    }
};

YUZU_PLUGIN_EXPORT(MsiPackagesPlugin)
