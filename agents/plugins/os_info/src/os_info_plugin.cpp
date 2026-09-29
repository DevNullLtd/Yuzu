/**
 * os_info_plugin.cpp — OS information plugin for Yuzu
 *
 * Actions:
 *   "os_name"    — Returns the full OS product name.
 *   "os_version" — Returns the OS version string.
 *   "os_build"   — Returns the OS build identifier.
 *   "os_arch"    — Returns the CPU architecture.
 *   "uptime"     — Returns system uptime in seconds and human-readable form.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 */

#include <yuzu/plugin.hpp>

#include <ctime>
#include <format>
#include <string>
#include <string_view>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/utsname.h>
#endif

#if defined(__linux__) || defined(__APPLE__)
#include <fstream>
#endif

#if defined(__APPLE__)
#include "os_info_macos.hpp"
#include <sstream>
#include <sys/sysctl.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#endif

namespace {

// ── helpers ─────────────────────────────────────────────────────────────────

#if defined(__APPLE__)
// Read a string sysctl (kern.osproductversion / kern.osversion). Empty on
// failure or absence -- both verified byte-identical to their `sw_vers`
// counterparts on this host (kern.osproductversion == `sw_vers
// -productVersion`; kern.osversion == `sw_vers -buildVersion`), but there is
// no equivalent sysctl for the product NAME, so that field never calls this.
std::string mac_sysctl_string(const char* name) {
    char buf[256]{};
    size_t len = sizeof(buf);
    if (sysctlbyname(name, buf, &len, nullptr, 0) != 0)
        return {};
    return std::string(buf);
}

// SystemVersion.plist is the one source that carries the product name; read
// it once per action call (empty on failure -- missing file, permissions).
std::string mac_read_system_version_plist() {
    std::ifstream f("/System/Library/CoreServices/SystemVersion.plist", std::ios::binary);
    if (!f)
        return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Fallback chain per field: plist -> sysctlbyname (when a sysctl exists for
// this field; nullptr skips straight to the literal) -> literal fallback.
// Never empty -- always resolves to something reportable.
std::string mac_version_field(std::string_view plist, std::string_view plist_key,
                              const char* sysctl_name, std::string_view literal_fallback) {
    if (!plist.empty()) {
        if (auto v = yuzu::os_info::parse_system_version_plist(plist, plist_key);
            v && !v->empty())
            return *v;
    }
    if (sysctl_name != nullptr) {
        auto sysctl_v = mac_sysctl_string(sysctl_name);
        if (!sysctl_v.empty())
            return sysctl_v;
    }
    return std::string(literal_fallback);
}
#endif

#ifdef _WIN32
// RtlGetVersion signature — avoids manifest-dependent version lies from
// GetVersionEx. Loaded dynamically from ntdll.
using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);

bool get_rtl_version(RTL_OSVERSIONINFOW& vi) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return false;
    auto fn = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"));
    if (!fn)
        return false;
    vi.dwOSVersionInfoSize = sizeof(vi);
    return fn(&vi) == 0; // STATUS_SUCCESS
}

std::string read_registry_string(HKEY root, const char* subkey, const char* value) {
    // Reg*W so non-ASCII OS identity strings (e.g. a localized edition) survive as
    // UTF-8 in the stored / fleet-queryable device surface rather than cp1252
    // mojibake (#1662 / #1682). Widen the names BEFORE opening the key so the only
    // operation between open and RegCloseKey is the non-allocating RegQueryValueExW;
    // the allocating reg_sz_to_utf8 runs AFTER the handle is closed, so a
    // std::bad_alloc cannot leak the HKEY (#1682 Gate-4 R1; vuln_scan's loop uses
    // HKeyCloser RAII instead).
    const std::wstring wsubkey = yuzu::win::to_wide(subkey);
    const std::wstring wvalue = yuzu::win::to_wide(value);
    HKEY hkey{};
    if (RegOpenKeyExW(root, wsubkey.c_str(), 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
        return {};
    }
    wchar_t buf[512]{};
    DWORD size = sizeof(buf); // size in BYTES; buf is written as bytes and read back
    DWORD type = 0;           // through its declared wchar_t lvalue (LPBYTE is align-1)
    const LONG rc = RegQueryValueExW(hkey, wvalue.c_str(), nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size);
    RegCloseKey(hkey); // closed before the allocating convert -- no leak window
    if (rc == ERROR_SUCCESS && type == REG_SZ && size >= sizeof(wchar_t)) {
        return yuzu::win::reg_sz_to_utf8(buf, size);
    }
    return {};
}

// Numeric read -- the value is a DWORD, never decoded into a string, so it carries
// no encoding and stays Reg*A (no cp1252 mojibake risk; #1682 audit).
DWORD read_registry_dword(HKEY root, const char* subkey, const char* value) {
    HKEY hkey{};
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
        return 0;
    }
    DWORD data = 0;
    DWORD size = sizeof(data);
    DWORD type = 0;
    if (RegQueryValueExA(hkey, value, nullptr, &type, reinterpret_cast<LPBYTE>(&data), &size) !=
        ERROR_SUCCESS) {
        data = 0;
    }
    RegCloseKey(hkey);
    return data;
}
#endif

std::string format_uptime(long long total_seconds) {
    long long days = total_seconds / 86400;
    long long hours = (total_seconds % 86400) / 3600;
    long long minutes = (total_seconds % 3600) / 60;
    return std::format("{}d {}h {}m", days, hours, minutes);
}

#ifdef __linux__
std::string read_os_release_field(const char* field) {
    std::ifstream ifs("/etc/os-release");
    if (!ifs)
        return {};
    std::string prefix = std::string(field) + "=";
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.starts_with(prefix)) {
            auto val = line.substr(prefix.size());
            // Strip surrounding quotes
            if (val.size() >= 2 && val.front() == '"' && val.back() == '"') {
                val = val.substr(1, val.size() - 2);
            }
            return val;
        }
    }
    return {};
}
#endif

constexpr const char* kWinNtCurrentVersion = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

// ── os_name action ──────────────────────────────────────────────────────────

int do_os_name(yuzu::CommandContext& ctx) {
#ifdef __linux__
    auto name = read_os_release_field("PRETTY_NAME");
    if (name.empty())
        name = "Linux";
    ctx.write_output(std::format("os_name|{}", name));

#elif defined(__APPLE__)
    auto plist = mac_read_system_version_plist();
    auto product = mac_version_field(plist, "ProductName", nullptr, "macOS");
    auto version = mac_version_field(plist, "ProductVersion", "kern.osproductversion", "unknown");
    ctx.write_output(std::format("os_name|{} {}", product, version));

#elif defined(_WIN32)
    auto name = read_registry_string(HKEY_LOCAL_MACHINE, kWinNtCurrentVersion, "ProductName");
    // Windows 11 shipped with build 22000+, but the registry ProductName
    // still says "Windows 10" on many builds. Correct it using the build number.
    if (!name.empty()) {
        auto build_str =
            read_registry_string(HKEY_LOCAL_MACHINE, kWinNtCurrentVersion, "CurrentBuildNumber");
        int build = 0;
        try {
            build = std::stoi(build_str);
        } catch (...) {}
        if (build >= 22000) {
            auto pos = name.find("Windows 10");
            if (pos != std::string::npos) {
                name.replace(pos, 10, "Windows 11");
            }
        }
    }
    ctx.write_output(std::format("os_name|{}", name.empty() ? "Windows" : name));

#else
    ctx.write_output("os_name|unknown");
#endif
    return 0;
}

// ── os_version action ───────────────────────────────────────────────────────

int do_os_version(yuzu::CommandContext& ctx) {
#if defined(__linux__) || defined(__APPLE__)
    struct utsname uts{};
    if (uname(&uts) == 0) {
        ctx.write_output(std::format("os_version|{}", uts.release));
    } else {
        ctx.write_output("os_version|unknown");
    }

#elif defined(_WIN32)
    RTL_OSVERSIONINFOW vi{};
    if (get_rtl_version(vi)) {
        ctx.write_output(std::format("os_version|{}.{}.{}", vi.dwMajorVersion, vi.dwMinorVersion,
                                     vi.dwBuildNumber));
    } else {
        ctx.write_output("os_version|unknown");
    }

#else
    ctx.write_output("os_version|unknown");
#endif

#ifdef __APPLE__
    // Also provide the user-facing product version
    auto plist = mac_read_system_version_plist();
    auto product_ver = mac_version_field(plist, "ProductVersion", "kern.osproductversion", "unknown");
    ctx.write_output(std::format("os_product_version|{}", product_ver));
#endif
    return 0;
}

// ── os_build action ─────────────────────────────────────────────────────────

int do_os_build(yuzu::CommandContext& ctx) {
#ifdef __linux__
    std::ifstream proc_ver("/proc/version");
    if (proc_ver) {
        std::string line;
        std::getline(proc_ver, line);
        // First token is typically "Linux"
        // We want the full build string, but extract the version token
        // (third whitespace-delimited field, e.g. "6.5.0-44-generic")
        std::string token;
        int field = 0;
        for (auto ch : line) {
            if (ch == ' ') {
                ++field;
                if (field == 3)
                    break;
                token.clear();
            } else {
                token += ch;
            }
        }
        ctx.write_output(std::format("os_build|{}", token.empty() ? line : token));
    } else {
        ctx.write_output("os_build|unknown");
    }

#elif defined(__APPLE__)
    auto plist = mac_read_system_version_plist();
    auto build = mac_version_field(plist, "ProductBuildVersion", "kern.osversion", "unknown");
    ctx.write_output(std::format("os_build|{}", build));

#elif defined(_WIN32)
    auto build_num =
        read_registry_string(HKEY_LOCAL_MACHINE, kWinNtCurrentVersion, "CurrentBuildNumber");
    auto ubr = read_registry_dword(HKEY_LOCAL_MACHINE, kWinNtCurrentVersion, "UBR");
    if (!build_num.empty()) {
        ctx.write_output(std::format("os_build|{}.{}", build_num, ubr));
    } else {
        ctx.write_output("os_build|unknown");
    }

#else
    ctx.write_output("os_build|unknown");
#endif
    return 0;
}

// ── os_arch action ──────────────────────────────────────────────────────────

int do_os_arch(yuzu::CommandContext& ctx) {
#if defined(__linux__) || defined(__APPLE__)
    struct utsname uts{};
    if (uname(&uts) == 0) {
        ctx.write_output(std::format("os_arch|{}", uts.machine));
    } else {
        ctx.write_output("os_arch|unknown");
    }

#elif defined(_WIN32)
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    const char* arch = "unknown";
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        arch = "x86_64";
        break;
    case PROCESSOR_ARCHITECTURE_ARM64:
        arch = "aarch64";
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        arch = "x86";
        break;
    case PROCESSOR_ARCHITECTURE_ARM:
        arch = "arm";
        break;
    }
    ctx.write_output(std::format("os_arch|{}", arch));

#else
    ctx.write_output("os_arch|unknown");
#endif
    return 0;
}

// ── uptime action ───────────────────────────────────────────────────────────

int do_uptime(yuzu::CommandContext& ctx) {
    long long seconds = -1;

#ifdef __linux__
    std::ifstream proc_uptime("/proc/uptime");
    if (proc_uptime) {
        double up = 0.0;
        proc_uptime >> up;
        seconds = static_cast<long long>(up);
    }

#elif defined(__APPLE__)
    struct timeval boottime{};
    size_t len = sizeof(boottime);
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    if (sysctl(mib, 2, &boottime, &len, nullptr, 0) == 0) {
        seconds = static_cast<long long>(std::time(nullptr) - boottime.tv_sec);
    }

#elif defined(_WIN32)
    seconds = static_cast<long long>(GetTickCount64() / 1000);
#endif

    if (seconds >= 0) {
        ctx.write_output(std::format("uptime_seconds|{}", seconds));
        ctx.write_output(std::format("uptime_display|{}", format_uptime(seconds)));
    } else {
        ctx.write_output("uptime_seconds|unknown");
        ctx.write_output("uptime_display|unknown");
    }
    return 0;
}

// ABI4 capability declarations (#2204). Every leg is now native in-process:
// Linux and Windows read native kernel/OS surfaces throughout (sysfs/proc
// reads, uname(2), the registry, RtlGetVersion, GetNativeSystemInfo,
// sysctl(2), GetTickCount64); macOS os_name/os_version/os_build read
// SystemVersion.plist (mac_read_system_version_plist +
// os_info_macos.hpp's parse_system_version_plist) with a sysctlbyname
// fallback (kern.osproductversion / kern.osversion — no equivalent exists
// for the product NAME) — zero subprocesses anywhere. Rung 1 throughout.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "os_name",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/etc/os-release", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "SystemVersion.plist + sysctlbyname", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "Reg*W CurrentVersion\\ProductName + build-number correction",
         nullptr},
    },
    {
        /* .action      = */ "os_version",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "uname(2)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "uname(2) + SystemVersion.plist + sysctlbyname", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "RtlGetVersion (ntdll)", nullptr},
    },
    {
        /* .action      = */ "os_build",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/proc/version", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "SystemVersion.plist + sysctlbyname", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "Reg*W CurrentBuildNumber + UBR", nullptr},
    },
    {
        /* .action      = */ "os_arch",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "uname(2)", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "uname(2)", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetNativeSystemInfo", nullptr},
    },
    {
        /* .action      = */ "uptime",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/proc/uptime", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "sysctl(2) KERN_BOOTTIME", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetTickCount64", nullptr},
    },
};

} // namespace

class OsInfoPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "os_info"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports OS name, version, build, architecture, and system uptime";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"os_name", "os_version", "os_build",
                                     "os_arch", "uptime",     nullptr};
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
        if (action == "os_name")
            return do_os_name(ctx);
        if (action == "os_version")
            return do_os_version(ctx);
        if (action == "os_build")
            return do_os_build(ctx);
        if (action == "os_arch")
            return do_os_arch(ctx);
        if (action == "uptime")
            return do_uptime(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(OsInfoPlugin)
