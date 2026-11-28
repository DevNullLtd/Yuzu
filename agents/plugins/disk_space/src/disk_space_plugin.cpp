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

#include <bounded_wait.hpp>      // bounded_call_ex: a stalled filesystem cannot hold the command worker
#include <local_path_policy.hpp> // agents/shared: refuse UNC / device / network-mount paths

#include <chrono>
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

// What one volume query produced. A plain value type: it crosses the helper-thread boundary.
struct Measured {
    bool ok{false};
    unsigned long long total{0};
    unsigned long long free{0};
    std::string error;
};

// The OS query itself (statvfs / statfs / GetDiskFreeSpaceExW). A query on a stalled filesystem can
// block inside the kernel, so do_free runs this on a bounded helper (bounded_wait.hpp) and gives up
// after kQueryBudget instead of holding a command worker.
Measured measure_volume(const std::string& path) {
    Measured m;
    // Refuse a network or device path BEFORE any syscall: a UNC path makes the LocalSystem agent
    // authenticate to the named host; on POSIX a statvfs under a network mount can block on a dead
    // server or trigger an automount. The row names the class, never the caller's path. (Judging
    // walks the path too, so it runs on the same bounded helper as the query.)
    if (const auto refusal = yuzu::shared::local_path::local_path_refusal(path);
        yuzu::shared::local_path::refused(refusal)) {
        m.error = std::string{yuzu::shared::local_path::refusal_token(refusal)};
        return m;
    }
    unsigned long long& total_bytes = m.total;
    unsigned long long& free_bytes = m.free;

#ifdef _WIN32
    const std::wstring wpath = utf8_to_wide(path);
    if (wpath.empty()) {
        m.error = std::format("failed to query disk space for path: {}", path);
        return m;
    }
    ULARGE_INTEGER avail_to_caller{}, total{}, total_free{};
    BOOL ok;
    {
        // Suppress the session-0 hard-error dialog around the query (see the guard).
        ThreadErrorModeGuard err_guard{SEM_FAILCRITICALERRORS};
        ok = ::GetDiskFreeSpaceExW(wpath.c_str(), &avail_to_caller, &total, &total_free);
    }
    if (!ok) {
        m.error = std::format("failed to query disk space for path: {}", path);
        return m;
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
        m.error = std::format("failed to stat path: {}", path);
        return m;
    }
    const auto block_size = vfs.f_bsize;
    total_bytes = static_cast<unsigned long long>(vfs.f_blocks) * block_size;
    free_bytes = static_cast<unsigned long long>(vfs.f_bavail) * block_size;

#elif defined(__linux__)
    struct statvfs vfs{};
    if (statvfs(std::string(path).c_str(), &vfs) != 0) {
        m.error = std::format("failed to stat path: {}", path);
        return m;
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
    m.error = "unsupported platform";
    return m;
#endif

    m.ok = true;
    return m;
}

// RESIDUAL (bounded helper inside a plugin DSO; the discovery and power_health plugins record the
// same one): `bounded_call_ex` runs `fn` on a detached thread whose code lives in THIS plugin's
// DSO. After a timeout the thread can still be running (blocked in the kernel on a stalled
// filesystem or resolver) when `shutdown()` returns; the host dlclose()s plugins only at final
// process exit (agent.cpp), and the shipped DSOs happen to stay mapped (each exports
// STB_GNU_UNIQUE symbols) -- an accident, not a guarantee, and a plain DSO would fault. The
// ceiling is per DSO, not process-wide: `g_outstanding_bounded_calls` is an `inline` variable, so
// each plugin has its own 64 slots, a slot is released only by the worker, and a refused call
// reads as a timeout. Moving the primitive into agent-core would not remove the residual (the
// lambda bodies stay here), so it is accepted as the precedent trade (plugin.hpp: "accept a
// bounded resource residue instead"). The drain barrier that would close it is tracked as #8204.
// Adjudication belongs to governance, not to this file.
constexpr auto kQueryBudget = std::chrono::seconds(15);

int do_free(yuzu::CommandContext& ctx, yuzu::Params params) {
    constexpr std::string_view default_path =
#ifdef _WIN32
        "C:\\";
#else
        "/";
#endif
    const auto path = params.get("path", default_path);

    auto measured = yuzu::shared::bounded_call_ex(
        std::chrono::duration_cast<std::chrono::milliseconds>(kQueryBudget),
        [p = std::string(path)]() { return measure_volume(p); });
    if (measured.status != yuzu::shared::BoundedCallStatus::Completed || !measured.value) {
        ctx.write_output("error|timeout: the volume query did not answer (stalled filesystem?)");
        return 1;
    }
    if (!measured.value->ok) {
        ctx.write_output(std::format("error|{}", measured.value->error));
        return 1;
    }
    const unsigned long long total_bytes = measured.value->total;
    const unsigned long long free_bytes = measured.value->free;

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
