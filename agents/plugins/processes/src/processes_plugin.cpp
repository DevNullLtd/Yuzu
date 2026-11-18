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
#include <bounded_wait.hpp>      // bounded_call_ex: a stalled filesystem cannot hold the command worker
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
#include <fcntl.h>    // open (O_NONBLOCK on the exe link)
#include <yuzu/agent/scoped_fd.hpp> // yuzu::agent::ScopedFd
#include <fstream>
#include <sys/stat.h> // fstat (identity key)
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

#if defined(__linux__)
// One image on a bounded helper (bounded_wait.hpp): an open or read of a file on a stalled
// filesystem cannot hold the command worker past the budget (the helper owns its descriptor; at most
// 64 helpers are outstanding process-wide and a refused or timed-out call reads as an empty hash).
// The identity key (dev:ino) comes back with the hash so a replaced binary is not conflated.
struct ImageHash {
    std::string key;
    std::string hash;
};

ImageHash hash_linux_image(unsigned long pid, std::chrono::steady_clock::time_point deadline) {
    ImageHash out;
    yuzu::shared::ScopedFile fd{::open(("/proc/" + std::to_string(pid) + "/exe").c_str(),
                                       O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)};
    if (!fd.valid())
        return out;
    struct stat st{};
    if (::fstat(fd.fd(), &st) != 0 || !S_ISREG(st.st_mode))
        return out;
    out.key = std::format("{}:{}", static_cast<unsigned long long>(st.st_dev),
                          static_cast<unsigned long long>(st.st_ino));
    auto r = yuzu::shared::hash_fd_regular(fd.fd(), kMaxImageHashBytes, deadline);
    if (r.status == yuzu::shared::HashStatus::ok)
        out.hash = std::move(r.hex);
    return out;
}

// There is NO network-mount judgement on this path: the image is opened through /proc/<pid>/exe, a
// kernel reference to the running image, never through path text. The bound is the helper.
struct ImageGuard {}; // Linux needs no mount-table snapshot (see below)

std::string hash_process_image(unsigned long pid, const std::string& path, HashCache& cache,
                               const ImageGuard&, std::chrono::steady_clock::time_point action_deadline) {
    if (path.empty())
        return {};
    const auto now = std::chrono::steady_clock::now();
    if (now >= action_deadline)
        return {};
    const auto budget = std::min<std::chrono::steady_clock::duration>(kPerImageBudget, action_deadline - now);
    const auto deadline = now + budget;
    auto result = yuzu::shared::bounded_call_ex(
        std::chrono::duration_cast<std::chrono::milliseconds>(budget),
        [pid, deadline]() { return hash_linux_image(pid, deadline); });
    if (result.status != yuzu::shared::BoundedCallStatus::Completed || !result.value)
        return {};
    const auto& img = *result.value;
    if (img.key.empty())
        return {};
    if (const auto it = cache.find(img.key); it != cache.end())
        return it->second;
    cache.emplace(img.key, img.hash);
    return img.hash;
}
#else
using ImageGuard = yuzu::shared::local_path::LocalPathGuard;

// Windows and macOS: the image path text is judged (UNC/device/non-fixed drive, or on/symlinked into
// a listed network mount) before anything opens it, and judge + hash run on a bounded helper.
std::string hash_process_image(unsigned long, const std::string& path, HashCache& cache,
                               const ImageGuard& guard,
                               std::chrono::steady_clock::time_point action_deadline) {
    if (path.empty())
        return {};
    if (const auto it = cache.find(path); it != cache.end())
        return it->second;
    const auto now = std::chrono::steady_clock::now();
    std::string hash;
    if (now < action_deadline) {
        const auto budget =
            std::min<std::chrono::steady_clock::duration>(kPerImageBudget, action_deadline - now);
        auto result = yuzu::shared::bounded_call_ex(
            std::chrono::duration_cast<std::chrono::milliseconds>(budget), [path, guard]() -> std::string {
                if (yuzu::shared::local_path::refused(guard.refusal(path)))
                    return {};
                return yuzu::agent::sha256_file(path, kMaxImageHashBytes);
            });
        if (result.status == yuzu::shared::BoundedCallStatus::Completed && result.value)
            hash = std::move(*result.value);
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
        HashCache hash_cache; // image identity -> sha256
        const ImageGuard guard;
        const auto action_deadline = std::chrono::steady_clock::now() + kActionBudget;
        for (const auto& p : procs) {
            std::string path = resolve_exe_path(p.pid);
            std::string hash = hash_process_image(p.pid, path, hash_cache, guard, action_deadline);
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
        HashCache hash_cache; // image identity -> sha256
        const ImageGuard guard;
        const auto action_deadline = std::chrono::steady_clock::now() + kActionBudget;
        for (const auto& p : procs) {
            std::string path = resolve_exe_path(p.pid);
            std::string hash = hash_process_image(p.pid, path, hash_cache, guard, action_deadline);
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
