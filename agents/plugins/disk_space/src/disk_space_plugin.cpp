/**
 * disk_space_plugin.cpp — free disk-space query plugin for Yuzu
 *
 * Actions:
 *   "free" — Reports total / free bytes and percent-used for a single volume.
 *            Param `path` selects the volume (default platform root). A pure
 *            fact-read: thresholds live with the caller (pre-flight manifest),
 *            never in the plugin.
 *
 * Output is pipe-delimited, one row via write_output():
 *   disk|<path>|<total_bytes>|<free_bytes>|<percent_used>
 * On failure:
 *   error|<message>   (and a non-zero return)
 *
 * "free_bytes" is the space usable by an ordinary (unprivileged) caller —
 * GetDiskFreeSpaceExW's FreeBytesAvailableToCaller on Windows, f_bavail on POSIX
 * (statfs on macOS, statvfs on Linux) — which is the correct figure for an
 * installer headroom check (quota-aware), not the raw f_bfree.
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <string>
#include <string_view>

#if defined(__linux__)
#include <sys/statvfs.h>
#elif defined(__APPLE__)
// statfs(2) carries 64-bit block counts; statvfs's __darwin_fsblkcnt_t is 32-bit.
#include <sys/mount.h>
#include <sys/param.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#endif

namespace {

#ifdef _WIN32
// Convert a UTF-8 path to UTF-16 for the wide Win32 API. The narrow Reg*A /
// *A variants apply the system code page and silently corrupt non-ASCII paths
// (#1662) — the established idiom is the wide API + an explicit CP_UTF8 decode.
// Delegates to the shared agents/shared/win_str.hpp helper (#1681); the removed
// local copy was the same size-based (NUL-excluded) convert as yuzu::win::to_wide.
std::wstring utf8_to_wide(std::string_view s) { return yuzu::win::to_wide(s); }

// RAII guard: set the thread error mode on construction, restore on scope exit.
// Suppresses the Windows session-0 hard-error dialog around a disk query on a
// not-ready removable / BitLocker-locked volume (which would otherwise block a
// dispatch-pool worker). Thread-scoped — never the process-wide SetErrorMode,
// which would race other workers in the bounded pool.
class ThreadErrorModeGuard {
public:
    explicit ThreadErrorModeGuard(DWORD mode) noexcept {
        ::SetThreadErrorMode(mode, &prev_);
    }
    ~ThreadErrorModeGuard() { ::SetThreadErrorMode(prev_, nullptr); }
    ThreadErrorModeGuard(const ThreadErrorModeGuard&) = delete;
    ThreadErrorModeGuard& operator=(const ThreadErrorModeGuard&) = delete;

private:
    DWORD prev_ = 0;
};
#endif

int do_free(yuzu::CommandContext& ctx, yuzu::Params params) {
    constexpr std::string_view default_path =
#ifdef _WIN32
        "C:\\";
#else
        "/";
#endif
    const auto path = params.get("path", default_path);

    unsigned long long total_bytes = 0;
    unsigned long long free_bytes = 0;

#ifdef _WIN32
    const std::wstring wpath = utf8_to_wide(path);
    if (wpath.empty()) {
        ctx.write_output(std::format("error|failed to query disk space for path: {}", path));
        return 1;
    }
    ULARGE_INTEGER avail_to_caller{}, total{}, total_free{};
    BOOL ok;
    {
        // Suppress the session-0 hard-error dialog around the query (see the guard).
        ThreadErrorModeGuard err_guard{SEM_FAILCRITICALERRORS};
        ok = ::GetDiskFreeSpaceExW(wpath.c_str(), &avail_to_caller, &total, &total_free);
    }
    if (!ok) {
        ctx.write_output(std::format("error|failed to query disk space for path: {}", path));
        return 1;
    }
    total_bytes = total.QuadPart;
    free_bytes = avail_to_caller.QuadPart;

#elif defined(__APPLE__)
    // macOS: statfs(2) — f_blocks/f_bavail are 64-bit (uint64_t), so a volume
    // > ~16 TiB is reported correctly (statvfs's __darwin_fsblkcnt_t is 32-bit
    // and would truncate). f_bavail is space usable by a non-superuser (the
    // installer-headroom basis); f_bsize is the fundamental block size.
    struct statfs vfs{};
    if (statfs(std::string(path).c_str(), &vfs) != 0) {
        ctx.write_output(std::format("error|failed to stat path: {}", path));
        return 1;
    }
    const auto block_size = vfs.f_bsize;
    total_bytes = static_cast<unsigned long long>(vfs.f_blocks) * block_size;
    free_bytes = static_cast<unsigned long long>(vfs.f_bavail) * block_size;

#elif defined(__linux__)
    struct statvfs vfs{};
    if (statvfs(std::string(path).c_str(), &vfs) != 0) {
        ctx.write_output(std::format("error|failed to stat path: {}", path));
        return 1;
    }
    // Some virtual / network filesystems report f_frsize == 0; fall back to
    // f_bsize so the volume doesn't silently read as 0 total / 0 free (the
    // dex_linux_collector idiom). free_bytes is the authoritative cross-OS
    // figure; percent_used is approximate (f_bavail excludes root-reserved slack
    // on Linux, so it reads a few points higher than Windows for the same fill).
    const auto block_size = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
    total_bytes = static_cast<unsigned long long>(vfs.f_blocks) * block_size;
    free_bytes = static_cast<unsigned long long>(vfs.f_bavail) * block_size;

#else
    ctx.write_output("error|unsupported platform");
    return 1;
#endif

    const unsigned long long used_bytes = total_bytes >= free_bytes ? total_bytes - free_bytes : 0;
    const int percent_used =
        total_bytes > 0 ? static_cast<int>((used_bytes * 100ULL) / total_bytes) : 0;

    ctx.write_output(std::format("disk|{}|{}|{}|{}", path, total_bytes, free_bytes, percent_used));
    return 0;
}

// ABI4 capability declarations (#2204). "free" is a single in-process stat
// call on every OS — no subprocess anywhere in this plugin.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "free",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "statvfs(2)", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "statfs(2)", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetDiskFreeSpaceExW", nullptr},
    },
};

} // namespace

class DiskSpacePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "disk_space"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports free / total disk space for a single volume";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"free", nullptr};
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

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "free")
            return do_free(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(DiskSpacePlugin)
