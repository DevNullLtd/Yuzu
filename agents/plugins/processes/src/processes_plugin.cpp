/**
 * processes_plugin.cpp — Process listing plugin for Yuzu
 *
 * Actions:
 *   "list"        — List running processes: PID, name.
 *   "list_hashed" — List running processes with the SHA-256 of the on-disk
 *                   executable image + its path: proc|pid|name|sha256|path.
 *   "list_tree"   — List running processes with parent PID + image hash for
 *                   tree reconstruction: proc|pid|ppid|name|sha256|path.
 *   "query"       — Filter process list by case-insensitive name match.
 *
 * Output is pipe-delimited via write_output():
 *   proc|pid|name                  (list / query)
 *   proc|pid|name|sha256|path      (list_hashed; sha256/path empty if unresolved)
 *   proc|pid|ppid|name|sha256|path (list_tree; ppid 0 = root; sha256/path empty if unresolved)
 */

#include <yuzu/agent/plugin_loader.hpp> // yuzu::agent::sha256_file
#include <yuzu/plugin.hpp>

#include <bounded_file_hash.hpp> // yuzu::shared::hash_fd_regular (Linux image hash)
#include <helper_budget.hpp>      // HelperBudget + the hash_unavailable markers
#include <image_path_cache.hpp>    // ImagePathCache / hash_row_cached: the pre-budget lookup
#include <bounded_wait.hpp>      // bounded_call_ex: a stalled filesystem cannot hold the command worker
#ifndef _WIN32
#include <image_hash_cache.hpp>   // identity-keyed (dev, inode, size, mtime) hash cache
#endif
#include <local_path_policy.hpp> // yuzu::shared::local_path (Windows/macOS image path guard)

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#endif

#ifdef __linux__
#include <dirent.h>
#include <cstdio>     // sscanf (maps identity)
#include <fcntl.h>    // open (O_NONBLOCK on the exe link)
#include <yuzu/agent/scoped_fd.hpp> // yuzu::agent::ScopedFd
#include <fstream>
#include <sys/stat.h> // fstat (identity key)
#include <sys/sysmacros.h> // makedev
#include <unistd.h>   // readlink, close
#endif

#ifdef __APPLE__
#include <libproc.h> // proc_pidpath
#include <yuzu/agent/process_enum.hpp> // yuzu::agent::enumerate_processes (sysctl KERN_PROC_ALL)
#endif

namespace {

struct ProcessInfo {
    unsigned long pid;
    unsigned long ppid = 0; // parent PID (0 when unknown / a root) — for list_tree
    std::string name;
};

std::string to_lower(std::string_view sv) {
    std::string result{sv};
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

// The wire format is pipe-delimited, one record per line. A process name (or any
// field) containing '|', CR, or LF would shift/split fields on the server-side
// positional parser, so neutralise those bytes to a space before emitting.
std::string sanitize_field(std::string s) {
    for (char& c : s)
        if (c == '|' || c == '\n' || c == '\r')
            c = ' ';
    return s;
}

#ifdef _WIN32
std::vector<ProcessInfo> enumerate_processes() {
    std::vector<ProcessInfo> procs;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return procs;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessInfo pi;
            pi.pid = pe.th32ProcessID;
            pi.ppid = pe.th32ParentProcessID;
            // Wide to narrow (#1681) — -1 convert, trailing NUL dropped.
            pi.name = yuzu::win::from_wide(pe.szExeFile);
            procs.push_back(std::move(pi));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return procs;
}
#elif defined(__linux__)
std::vector<ProcessInfo> enumerate_processes() {
    std::vector<ProcessInfo> procs;
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir)
        return procs;

    struct dirent* entry = nullptr;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Only numeric directories
        if (entry->d_type != DT_DIR)
            continue;
        bool is_pid = true;
        for (const char* p = entry->d_name; *p; ++p) {
            if (!std::isdigit(static_cast<unsigned char>(*p))) {
                is_pid = false;
                break;
            }
        }
        if (!is_pid)
            continue;

        std::string status_path = std::string("/proc/") + entry->d_name + "/status";
        std::ifstream ifs(status_path);
        if (!ifs.is_open())
            continue;

        ProcessInfo pi;
        pi.pid = std::stoul(entry->d_name);
        std::string line;
        bool have_name = false, have_ppid = false;
        while (std::getline(ifs, line)) {
            if (!have_name && line.starts_with("Name:")) {
                auto pos = line.find_first_not_of(" \t", 5);
                if (pos != std::string::npos)
                    pi.name = line.substr(pos);
                have_name = true;
            } else if (!have_ppid && line.starts_with("PPid:")) {
                auto pos = line.find_first_not_of(" \t", 5);
                if (pos != std::string::npos) {
                    try { pi.ppid = std::stoul(line.substr(pos)); } catch (...) {}
                }
                have_ppid = true;
            }
            if (have_name && have_ppid)
                break; // PPid follows Name in /proc/<pid>/status — both captured
        }
        procs.push_back(std::move(pi));
    }
    closedir(proc_dir);
    return procs;
}
#elif defined(__APPLE__)
// Wraps the agent-core sysctl(KERN_PROC_ALL) enumerator (already linked via
// yuzu_agent_core_dep) rather than shelling out to `ps`. Three mapping
// differences from a direct pass-through, all load-bearing:
//   - agent-core's ProcessInfo.name is 16-char-truncated p_comm, not a full
//     path -- prefer .cmdline (the real proc_pidpath) when it starts with
//     '/', else fall back to the truncated name (matches `ps`'s COMM column
//     honestly rather than silently truncating a resolvable name).
//   - pid 0 (kernel_task) is skipped -- `ps -ax` never listed it, but
//     KERN_PROC_ALL does, so a naive pass-through would introduce a new row.
//   - output is sorted ascending by pid -- `ps`'s natural order, whereas
//     KERN_PROC_ALL is unordered; list_hashed/list_tree feed the server's
//     device-page "Get live info" surface, which relies on this ordering.
std::vector<ProcessInfo> enumerate_processes() {
    std::vector<ProcessInfo> procs;
    for (auto& p : yuzu::agent::enumerate_processes()) {
        if (p.pid == 0)
            continue;
        ProcessInfo pi;
        pi.pid = p.pid;
        pi.ppid = p.ppid;
        pi.name = (!p.cmdline.empty() && p.cmdline.front() == '/') ? std::move(p.cmdline)
                                                                    : std::move(p.name);
        procs.push_back(std::move(pi));
    }
    std::sort(procs.begin(), procs.end(),
             [](const ProcessInfo& a, const ProcessInfo& b) { return a.pid < b.pid; });
    return procs;
}
#else
std::vector<ProcessInfo> enumerate_processes() {
    return {};
}
#endif

// Resolve a process's true on-disk executable path (NOT argv[0], which is
// spoofable) so its image can be hashed. Empty on failure — kernel threads,
// PID 0/4, access-denied, or an unsupported platform all read as "no path".
#ifdef _WIN32
// Single-owner RAII for a process HANDLE: CloseHandle runs on every scope exit,
// including an exception from a std::wstring/std::string allocation between
// acquire and release (a leak the prior manual CloseHandle could skip).
struct HandleGuard {
    HANDLE h;
    explicit HandleGuard(HANDLE handle) noexcept : h(handle) {}
    ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    explicit operator bool() const noexcept { return h && h != INVALID_HANDLE_VALUE; }
};

std::string resolve_exe_path(unsigned long pid) {
    HandleGuard hg(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hg)
        return "";
    std::wstring wbuf(4096, L'\0');
    DWORD sz = static_cast<DWORD>(wbuf.size());
    std::string path;
    if (QueryFullProcessImageNameW(hg.h, 0, wbuf.data(), &sz) && sz > 0) {
        // (#1681) QueryFullProcessImageNameW writes `sz` chars excluding the NUL,
        // so from_wide's counted form is exact (no trailing-NUL pop fires).
        path = yuzu::win::from_wide(wbuf.data(), static_cast<int>(sz));
    }
    return path; // ~HandleGuard closes the handle on every path
}
#elif defined(__linux__)
std::string resolve_exe_path(unsigned long pid) {
    std::string link = "/proc/" + std::to_string(pid) + "/exe";
    std::array<char, 4096> buf{};
    ssize_t n = readlink(link.c_str(), buf.data(), buf.size() - 1);
    if (n <= 0)
        return "";
    std::string path(buf.data(), static_cast<size_t>(n));
    // A replaced/removed binary reads as "<path> (deleted)" — strip the marker for DISPLAY only.
    // This text is never opened (Linux): the hash goes through hash_process_image's open of
    // /proc/<pid>/exe itself, which is the kernel's own reference to the running image.
    if (path.ends_with(" (deleted)"))
        path.erase(path.size() - 10);
    return path;
}
#elif defined(__APPLE__)
std::string resolve_exe_path(unsigned long pid) {
    std::array<char, PROC_PIDPATHINFO_MAXSIZE> buf{};
    int n = proc_pidpath(static_cast<int>(pid), buf.data(), buf.size());
    if (n <= 0)
        return "";
    return std::string(buf.data(), static_cast<size_t>(n));
}
#else
std::string resolve_exe_path(unsigned long) {
    return "";
}
#endif

// SHA-256 of a process's on-disk image, "" when it cannot be hashed honestly. `cache` maps an
// image identity to its hash (many PIDs share one executable).
//
// The path came from QueryFullProcessImageNameW / readlink / proc_pidpath for a process ANY user
// can start, so it is attacker-influenced:
//   Linux   - open /proc/<pid>/exe (a magic link: the open yields the very inode the process runs,
//             a "(deleted)" image included, and re-resolves no path text), O_NONBLOCK, then
//             fstat the descriptor and hash only a regular file with a byte cap and a deadline.
//             The cache is keyed by (dev, ino), not by path text.
//   Windows/macOS - refuse a network / device / non-fixed-drive path (agents/shared/
//             local_path_policy.hpp) before anything opens it: a UNC image path would make the
//             LocalSystem agent authenticate to the share's host.
constexpr std::size_t kMaxImageHashBytes = 512ull * 1024 * 1024; // 512 MiB cap
using HashCache = std::unordered_map<std::string, std::string>;

constexpr auto kPerImageBudget = std::chrono::seconds(30);
constexpr auto kActionBudget = std::chrono::seconds(120); // all images together
constexpr int kMaxStuckHelpers = 2; // helpers left behind per action, at most (2 x 30 s < the 120 s budget)

#if defined(__linux__)
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
// One image on a bounded helper (bounded_wait.hpp): an open or read of a file on a stalled
// filesystem cannot hold the command worker past the budget (the helper owns its descriptor; at most
// 64 helpers per plugin DSO; a refused or timed-out call reads `hash_unavailable:timeout`).
// The identity key (dev:ino) comes back with the hash so a replaced binary is not conflated.
struct ImageHash {
    std::string key;
    std::string hash;
};

ImageHash hash_linux_image(unsigned long pid, std::chrono::steady_clock::time_point deadline,
                           const std::shared_ptr<yuzu::shared::ImageHashCache>& cache) {
    ImageHash out;
    yuzu::shared::ScopedFile fd{::open(("/proc/" + std::to_string(pid) + "/exe").c_str(),
                                       O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)};
    if (!fd.valid())
        return out;
    struct stat st{};
    if (::fstat(fd.fd(), &st) != 0 || !S_ISREG(st.st_mode))
        return out;
    // Identity of the OPENED image (dev, inode, size, mtime): looked up after the open and before the
    // read, so the expensive hash runs once per distinct image and a replaced image never gets a
    // stale hash.
    out.key = yuzu::shared::image_identity_key(st);
    if (auto hit = cache->get(out.key)) {
        out.hash = std::move(*hit);
        return out;
    }
    auto r = yuzu::shared::hash_fd_regular(fd.fd(), kMaxImageHashBytes, deadline);
    if (r.status == yuzu::shared::HashStatus::ok) {
        out.hash = std::move(r.hex);
        cache->put(out.key, out.hash);
    } else if (r.status == yuzu::shared::HashStatus::timeout) {
        // The cooperative per-image deadline: the same marker a helper that did not finish reads,
        // never an empty hash (which means unreadable, not a regular file or over the cap).
        out.hash = yuzu::shared::kHashUnavailableTimeout;
    }
    return out;
}

// There is NO network-mount judgement on this path: the image is opened through /proc/<pid>/exe, a
// kernel reference to the running image, never through path text. The bound is the helper.
struct ImageGuard {}; // Linux needs no mount-table snapshot (see below)

// A hash cache lives for ONE action (created per dispatch, shared with that action's bounded
// helpers, gone when the action returns): an image replaced between two dispatches is always
// re-hashed. Within an action it is keyed by the OPENED image's identity (dev, inode, size, mtime,
// ctime), never by path text.
struct ActionCache {
    std::shared_ptr<yuzu::shared::ImageHashCache> identity; // shared with the action's helpers
    yuzu::shared::ImagePathCache by_path;                   // identity-keyed, plugin thread only, consulted first
};
ActionCache make_action_cache() { return {std::make_shared<yuzu::shared::ImageHashCache>(), {}}; }

// The mount namespace of a process, read from procfs (a link read, never the image): part of the
// cache key so two containers' identical images never share a hash. Empty on any failure.
std::string mount_ns_of(unsigned long pid) {
    char buf[64];
    const auto n = ::readlink(("/proc/" + std::to_string(pid) + "/ns/mnt").c_str(), buf, sizeof(buf) - 1);
    return n > 0 ? std::string(buf, static_cast<std::size_t>(n)) : std::string{};
}

// `<dev>:<inode>` shared by every mapping of the process's executable in its WHOLE /proc/<pid>/maps
// (procfs only: no access to the image's filesystem, so it cannot stall on a hung mount). Empty (no
// caching) on any failure: permission, a vanished process, no or conflicting mappings, a maps larger
// than 4 MiB (never a prefix is parsed), or the action deadline passing mid-read.
std::string image_identity_of(unsigned long pid, std::chrono::steady_clock::time_point deadline) {
    constexpr std::size_t kMapsCap = 4 * 1024 * 1024;
    std::array<char, 4096> lnk{};
    const auto ln = ::readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), lnk.data(), lnk.size() - 1);
    if (ln <= 0)
        return {};
    std::string exe(lnk.data(), static_cast<std::size_t>(ln));
    bool deleted = false;
    if (exe.ends_with(" (deleted)")) {
        exe.erase(exe.size() - 10);
        deleted = true;
    }
    yuzu::shared::ScopedFile fd{::open(("/proc/" + std::to_string(pid) + "/maps").c_str(), O_RDONLY | O_CLOEXEC)};
    if (!fd.valid())
        return {};
    const auto maps = yuzu::shared::ImagePathCache::read_complete(
        [&](char* b, std::size_t len) { return ::read(fd.fd(), b, len); }, kMapsCap,
        [&] { return std::chrono::steady_clock::now() >= deadline; });
    if (!maps)
        return {};
    return yuzu::shared::ImagePathCache::maps_identity(*maps, exe, deleted);
}

// True when `maps_id` (`<major hex>:<minor hex>:<inode>`) names the same device and inode as the opened
// image's identity key (`<st_dev>:<st_ino>:...`, image_identity_key).
bool maps_identity_matches_opened(const std::string& maps_id, const std::string& opened_key) {
    unsigned maj = 0, min = 0;
    unsigned long long ino = 0;
    if (maps_id.empty() || std::sscanf(maps_id.c_str(), "%x:%x:%llu", &maj, &min, &ino) != 3)
        return false;
    const std::string want = std::to_string(static_cast<unsigned long long>(::makedev(maj, min))) + ":" +
                             std::to_string(ino) + ":";
    return opened_key.rfind(want, 0) == 0;
}

std::string hash_process_image(unsigned long pid, const std::string& path, ActionCache& cache,
                               const ImageGuard&, std::chrono::steady_clock::time_point action_deadline,
                               yuzu::shared::HelperBudget& budget) {
    if (path.empty())
        return {};
    const auto now = std::chrono::steady_clock::now();
    // The identity cache (mount namespace + maps device/inode, never path text) answers FIRST: once the per-action cap of helpers left behind (or the action
    // budget) is reached no further helper is started and such a row says so
    // (`hash_unavailable:skipped`), but a row whose image this action already hashed keeps its hash.
    const auto maps_id = image_identity_of(pid, action_deadline);
    const auto key = yuzu::shared::ImagePathCache::make_key(mount_ns_of(pid), maps_id);
    return yuzu::shared::hash_row_cached(
        cache.by_path, key, now < action_deadline && budget.may_start(),
        [&]() -> yuzu::shared::RowHash {
            const auto remaining =
                std::min<std::chrono::steady_clock::duration>(kPerImageBudget, action_deadline - now);
            const auto deadline = now + remaining;
            auto result = yuzu::shared::bounded_call_ex(
                std::chrono::duration_cast<std::chrono::milliseconds>(remaining),
                [pid, deadline, identity = cache.identity]() {
                    return hash_linux_image(pid, deadline, identity);
                });
            budget.note(result.status);
            if (result.status != yuzu::shared::BoundedCallStatus::Completed || !result.value)
                return {std::string{yuzu::shared::kHashUnavailableTimeout}, false};
            const auto& img = *result.value;
            if (img.key.empty())
                return {std::string{}, false};
            // Remembered only when the maps identity names the very inode that was opened through
            // /proc/<pid>/exe and hashed: a process cannot plant an entry by shaping its own mappings.
            return {img.hash, maps_identity_matches_opened(maps_id, img.key)};
        });
}
#else
using ImageGuard = yuzu::shared::local_path::LocalPathGuard;
using ActionCache = HashCache; // Windows/macOS: path text within one action (judged local paths)
ActionCache make_action_cache() { return {}; }

// Windows and macOS: the image path text is judged (UNC/device/non-fixed drive, or on/symlinked into
// a listed network mount) before anything opens it, and judge + hash run on a bounded helper.
std::string hash_process_image(unsigned long, const std::string& path, ActionCache& cache,
                               const ImageGuard& guard,
                               std::chrono::steady_clock::time_point action_deadline,
                               yuzu::shared::HelperBudget& budget) {
    if (path.empty())
        return {};
    if (const auto it = cache.find(path); it != cache.end())
        return it->second;
    const auto now = std::chrono::steady_clock::now();
    std::string hash;
    if (now >= action_deadline || !budget.may_start()) {
        hash = yuzu::shared::kHashUnavailableSkipped;
    } else {
        const auto allowed =
            std::min<std::chrono::steady_clock::duration>(kPerImageBudget, action_deadline - now);
        auto result = yuzu::shared::bounded_call_ex(
            std::chrono::duration_cast<std::chrono::milliseconds>(allowed), [path, guard]() -> std::string {
                if (yuzu::shared::local_path::refused(guard.refusal(path)))
                    return {};
                return yuzu::agent::sha256_file(path, kMaxImageHashBytes);
            });
        budget.note(result.status);
        hash = yuzu::shared::hash_field_for(result.status, result.value ? std::move(*result.value) : std::string{});
    }
    cache.emplace(path, hash);
    return hash;
}
#endif

// ABI4 capability declarations (#2204). All four actions call the same
// enumerate_processes() (and, for the hashed/tree variants, resolve_exe_path
// + sha256_file) — Linux (/proc), Windows (CreateToolhelp32Snapshot +
// QueryFullProcessImageNameW), and macOS (yuzu::agent::enumerate_processes,
// sysctl KERN_PROC_ALL) are all native in-process enumerations. Rung 1
// everywhere.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "list",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/proc enumeration", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "sysctl(KERN_PROC_ALL)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "CreateToolhelp32Snapshot", nullptr},
    },
    {
        /* .action      = */ "list_hashed",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "/proc enumeration + readlink(/proc/<pid>/exe) + SHA-256",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "sysctl(KERN_PROC_ALL) + proc_pidpath + SHA-256", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "CreateToolhelp32Snapshot + QueryFullProcessImageNameW + SHA-256", nullptr},
    },
    {
        /* .action      = */ "list_tree",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "/proc enumeration + readlink(/proc/<pid>/exe) + SHA-256",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "sysctl(KERN_PROC_ALL) + proc_pidpath + SHA-256", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "CreateToolhelp32Snapshot + QueryFullProcessImageNameW + SHA-256", nullptr},
    },
    {
        /* .action      = */ "query",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/proc enumeration", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "sysctl(KERN_PROC_ALL)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "CreateToolhelp32Snapshot", nullptr},
    },
};

} // namespace

class ProcessesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "processes"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Process listing — enumerate and query running processes";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "list_hashed", "list_tree", "query", nullptr};
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
        if (action == "list") {
            return do_list(ctx);
        }
        if (action == "list_hashed") {
            return do_list_hashed(ctx);
        }
        if (action == "list_tree") {
            return do_list_tree(ctx);
        }
        if (action == "query") {
            return do_query(ctx, params);
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_list(yuzu::CommandContext& ctx) {
        auto procs = enumerate_processes();
        for (const auto& p : procs) {
            ctx.write_output(std::format("proc|{}|{}", p.pid, sanitize_field(p.name)));
        }
        return 0;
    }

    // proc|pid|ppid|name|sha256|path — the parent-PID edges the server reconstructs
    // into a live process tree (device-page "Get live info"), with the SHA-256 of the
    // on-disk image + its resolved path on each node (so the tree is the single
    // process view — no separate flat hashed list). ppid is 0 for a root / unresolved
    // parent; sha256/path are empty when the path can't be resolved or the image is
    // gone/too large. Hashing mirrors do_list_hashed (per-path cache, bounded read).
    int do_list_tree(yuzu::CommandContext& ctx) {
        auto procs = enumerate_processes();
        auto hash_cache = make_action_cache(); // one action only
        const ImageGuard guard;
        const auto action_deadline = std::chrono::steady_clock::now() + kActionBudget;
        yuzu::shared::HelperBudget budget{kMaxStuckHelpers};
        for (const auto& p : procs) {
            std::string path = resolve_exe_path(p.pid);
            std::string hash = hash_process_image(p.pid, path, hash_cache, guard, action_deadline, budget);
            ctx.write_output(std::format("proc|{}|{}|{}|{}|{}", p.pid, p.ppid,
                                         sanitize_field(p.name), hash, sanitize_field(path)));
        }
        return 0;
    }

    // proc|pid|name|sha256|path. The on-disk image is hashed (lowercase hex);
    // unique paths are hashed once (many PIDs share one executable). The hash is
    // bounded (kMaxImageHashBytes) so an oversized image can't turn a live query into a
    // multi-GB read. sha256/path are empty when the path can't be resolved (kernel
    // threads, access-denied) or the file is gone/too large — rendered honestly.
    int do_list_hashed(yuzu::CommandContext& ctx) {
        auto procs = enumerate_processes();
        auto hash_cache = make_action_cache(); // one action only
        const ImageGuard guard;
        const auto action_deadline = std::chrono::steady_clock::now() + kActionBudget;
        yuzu::shared::HelperBudget budget{kMaxStuckHelpers};
        for (const auto& p : procs) {
            std::string path = resolve_exe_path(p.pid);
            std::string hash = hash_process_image(p.pid, path, hash_cache, guard, action_deadline, budget);
            ctx.write_output(std::format("proc|{}|{}|{}|{}", p.pid, sanitize_field(p.name), hash,
                                         sanitize_field(path)));
        }
        return 0;
    }

    int do_query(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto name_filter = params.get("name");
        if (name_filter.empty()) {
            ctx.write_output("error|missing required parameter: name");
            return 1;
        }

        auto filter_lower = to_lower(name_filter);
        auto procs = enumerate_processes();
        std::vector<const ProcessInfo*> matches;

        for (const auto& p : procs) {
            auto name_lower = to_lower(p.name);
            if (name_lower.find(filter_lower) != std::string::npos) {
                matches.push_back(&p);
            }
        }

        ctx.write_output(std::format("found|{}", matches.empty() ? "false" : "true"));
        for (const auto* p : matches) {
            ctx.write_output(std::format("proc|{}|{}", p->pid, p->name));
        }
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(ProcessesPlugin)
