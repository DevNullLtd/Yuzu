/**
 * procfetch_plugin.cpp — Process enumeration plugin for Yuzu
 *
 * Actions:
 *   "procfetch_fetch" — Enumerates running processes on the host,
 *                       returning PID, name, executable path, and
 *                       SHA-1 hash of each executable binary.
 *
 * Output is pipe-delimited, one process per line via write_output():
 *   pid|name|path|sha1_hex
 *
 * Platform support:
 *   Linux  — /proc filesystem, OpenSSL EVP for SHA-1
 *   Windows — CreateToolhelp32Snapshot, BCrypt for SHA-1
 *
 * Performance notes:
 *   - SHA-1 results are cached by path to avoid re-hashing duplicate
 *     executables (e.g. svchost.exe × 20+).
 *   - Results are streamed per-process instead of collected first.
 *   - BCrypt provider (Windows) is opened once per fetch, not per file.
 *   - 64KB I/O buffer for faster reads.
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <format>
#include <fstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <image_hash_cache.hpp>   // identity-keyed (dev, inode, size, mtime) hash cache
#include <bounded_wait.hpp>      // bounded_call_ex: a stalled filesystem cannot hold the command worker
#include <local_path_policy.hpp> // posix_open_checked / the path guard (macOS image path)
#endif
#ifdef __APPLE__
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <unistd.h>
#endif
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <windows.h>  // must precede bcrypt.h (defines NTSTATUS)
// clang-format on
#include <bcrypt.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <local_path_policy.hpp>   // refuse UNC / device / non-fixed-drive image paths
#include <win_no_reparse_open.hpp> // handle-relative OBJ_DONT_REPARSE open
#pragma comment(lib, "bcrypt.lib")
#include <charconv>
#include <tlhelp32.h>
#endif

namespace {

// Escape pipe characters in strings so they don't break the delimiter.
std::string escape_pipes(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (char c : sv) {
        if (c == '|') {
            out += "\\|";
        } else {
            out += c;
        }
    }
    return out;
}

// -- POSIX (Linux + macOS) shared SHA-1 ---------------------------------------
#if defined(__linux__) || defined(__APPLE__)

struct EvpCtxDeleter {
    void operator()(EVP_MD_CTX* c) const noexcept { EVP_MD_CTX_free(c); }
};
using EvpCtx = std::unique_ptr<EVP_MD_CTX, EvpCtxDeleter>;

constexpr std::uint64_t kMaxImageHashBytes = 512ull * 1024 * 1024; // 512 MiB, refused (not truncated)
constexpr auto kPerImageBudget = std::chrono::seconds(30);
constexpr auto kActionBudget = std::chrono::seconds(120); // all images together

// SHA-1 of an OPEN descriptor: a regular file of at most kMaxImageHashBytes, read within `deadline`
// (cooperative; the caller bounds the call itself, see hash_image_bounded). Any failure, including
// a read error part-way, is "not hashed" (empty): never the SHA-1 of a truncated prefix.
std::string sha1_of_fd(int fd, std::chrono::steady_clock::time_point deadline) {
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        static_cast<std::uint64_t>(st.st_size) > kMaxImageHashBytes)
        return {};
    const EvpCtx ctx{EVP_MD_CTX_new()};
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha1(), nullptr) != 1)
        return {};
    unsigned char buf[65536];
    std::uint64_t total = 0;
    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline)
            return {};
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n < 0)
            return {};
        if (n == 0)
            break;
        total += static_cast<std::uint64_t>(n);
        if (total > kMaxImageHashBytes ||
            EVP_DigestUpdate(ctx.get(), buf, static_cast<size_t>(n)) != 1)
            return {};
    }
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), hash, &hash_len) != 1)
        return {};
    std::string hex;
    hex.reserve(hash_len * 2);
    for (unsigned int i = 0; i < hash_len; ++i)
        hex += std::format("{:02x}", hash[i]);
    return hex;
}

// Hash one process image on a bounded helper: the open and the read of a file on a stalled
// filesystem cannot hold the command worker past `budget` (bounded_wait.hpp; the helper owns its
// descriptor and copies, and shares the identity-keyed cache). Linux opens /proc/<pid>/exe itself
// (the kernel's reference to the running image: no path text is re-resolved); macOS opens the judged
// path handle-relative with no symlink followed. O_NONBLOCK: a FIFO is refused, never waited on.
// The cache key is the OPENED image's identity (dev, inode, size, mtime), looked up after the open and
// before the read: the readlink text is only shown, never a key, so a replaced or aliased image
// never receives another process's hash.
std::string hash_image_bounded(int pid, const std::string& path,
                               const yuzu::shared::local_path::LocalPathGuard& guard,
                               const std::shared_ptr<yuzu::shared::ImageHashCache>& cache,
                               std::chrono::steady_clock::time_point action_deadline) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= action_deadline)
        return {};
    const auto budget = std::min<std::chrono::steady_clock::duration>(kPerImageBudget, action_deadline - now);
    const auto deadline = now + budget;
    auto result = yuzu::shared::bounded_call_ex(
        std::chrono::duration_cast<std::chrono::milliseconds>(budget),
        [pid, path, guard, cache, deadline]() -> std::string {
            yuzu::shared::ScopedFile fd;
#if defined(__linux__)
            (void)path;
            (void)guard;
            fd = yuzu::shared::ScopedFile{::open(("/proc/" + std::to_string(pid) + "/exe").c_str(),
                                                 O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)};
            if (!fd.valid())
                return {};
#else
            (void)pid;
            namespace lp = yuzu::shared::local_path;
            const auto j = guard.judge(path);
            if (lp::refused(j.refusal))
                return {};
            auto o = lp::posix_open_checked(j.resolved.empty() ? path : j.resolved,
                                            O_RDONLY | O_NONBLOCK | O_NOCTTY, /*require_regular=*/true);
            if (!o.opened())
                return {};
            fd = std::move(o.file);
#endif
            struct stat st{};
            if (::fstat(fd.fd(), &st) != 0 || !S_ISREG(st.st_mode))
                return {};
            const auto key = yuzu::shared::image_identity_key(st);
            if (auto hit = cache->get(key))
                return *hit;
            auto hex = sha1_of_fd(fd.fd(), deadline);
            if (!hex.empty())
                cache->put(key, hex);
            return hex;
        });
    return result.status == yuzu::shared::BoundedCallStatus::Completed && result.value
               ? std::move(*result.value)
               : std::string{};
}

#endif // POSIX

// -- Linux implementation -----------------------------------------------------
#ifdef __linux__

std::string read_first_line(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f)
        return {};
    std::string line;
    std::getline(f, line);
    return line;
}

std::string resolve_exe(const std::filesystem::path& link) {
    try {
        return std::filesystem::read_symlink(link).string();
    } catch (const std::filesystem::filesystem_error&) {
        return {};
    }
}

void enumerate_and_stream(yuzu::CommandContext& ctx) {
    const auto image_cache = std::make_shared<yuzu::shared::ImageHashCache>();
    std::error_code ec;
    const yuzu::shared::local_path::LocalPathGuard path_guard; // one mount-table snapshot per run
    const auto action_deadline = std::chrono::steady_clock::now() + kActionBudget;

    for (const auto& entry : std::filesystem::directory_iterator("/proc", ec)) {
        if (!entry.is_directory(ec))
            continue;

        auto dirname = entry.path().filename().string();
        int pid = 0;
        auto [ptr, errc] = std::from_chars(dirname.data(), dirname.data() + dirname.size(), pid);
        if (errc != std::errc{} || ptr != dirname.data() + dirname.size())
            continue;
        if (pid <= 0)
            continue;

        std::string name = read_first_line(entry.path() / "comm");
        if (name.empty())
            continue;

        std::string exe_path = resolve_exe(entry.path() / "exe");
        std::string sha1;
        // The hash comes from /proc/<pid>/exe itself (never the readlink text, which is only shown),
        // on a bounded helper, regular files only, capped and deadline-bounded, cached by the
        // opened image's identity.
        if (!exe_path.empty())
            sha1 = hash_image_bounded(pid, exe_path, path_guard, image_cache, action_deadline);

        ctx.write_output(
            std::format("{}|{}|{}|{}", pid, escape_pipes(name), escape_pipes(exe_path), sha1));
    }
}

// -- macOS implementation -----------------------------------------------------
#elif defined(__APPLE__)

void enumerate_and_stream(yuzu::CommandContext& ctx) {
    // First call returns required buffer size.
    int needed = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    if (needed <= 0)
        return;

    std::vector<pid_t> pids(static_cast<size_t>(needed) / sizeof(pid_t) + 64, 0);
    int got =
        proc_listpids(PROC_ALL_PIDS, 0, pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
    if (got <= 0)
        return;
    size_t pid_count = static_cast<size_t>(got) / sizeof(pid_t);

    const auto image_cache = std::make_shared<yuzu::shared::ImageHashCache>();
    const yuzu::shared::local_path::LocalPathGuard path_guard; // one mount-table snapshot per run
    const auto action_deadline = std::chrono::steady_clock::now() + kActionBudget;
    char path_buf[PROC_PIDPATHINFO_MAXSIZE];

    for (size_t i = 0; i < pid_count; ++i) {
        pid_t pid = pids[i];
        if (pid <= 0)
            continue;

        path_buf[0] = '\0';
        int n = proc_pidpath(pid, path_buf, sizeof(path_buf));
        std::string exe_path;
        if (n > 0)
            exe_path.assign(path_buf, static_cast<size_t>(n));

        std::string name;
        if (!exe_path.empty()) {
            auto pos = exe_path.find_last_of('/');
            name = (pos == std::string::npos) ? exe_path : exe_path.substr(pos + 1);
        } else {
            // Fallback to short name via proc_name.
            char name_buf[PROC_PIDPATHINFO_MAXSIZE] = {0};
            if (proc_name(pid, name_buf, sizeof(name_buf)) > 0)
                name = name_buf;
        }
        if (name.empty())
            continue;

        std::string sha1;
        if (!exe_path.empty())
            sha1 = hash_image_bounded(static_cast<int>(pid), exe_path, path_guard, image_cache, action_deadline);

        ctx.write_output(std::format("{}|{}|{}|{}", static_cast<int>(pid), escape_pipes(name),
                                     escape_pipes(exe_path), sha1));
    }
}

// -- Windows implementation ---------------------------------------------------
#elif defined(_WIN32)

// wide->UTF-8 conversion now via the shared win_str.hpp (#1681); from_wide is
// behaviour-identical to the old NUL-terminated wide_to_utf8 for valid input.
using yuzu::win::from_wide;

std::string get_process_image_path(DWORD pid) {
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc)
        return {};

    wchar_t path_buf[MAX_PATH];
    DWORD path_len = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(proc, 0, path_buf, &path_len);
    CloseHandle(proc);

    if (!ok)
        return {};
    return from_wide(path_buf);
}

std::string sha1_of_file(const std::string& path, BCRYPT_ALG_HANDLE alg) {
    // The image path belongs to a process any standard user can start, so it can be a share
    // (`\\server\share\x.exe`). Opening it as the LocalSystem agent would authenticate the machine
    // account to that host. Classify BEFORE any open (a refused path reads as an empty hash, the
    // honest "not hashed" answer), then open handle-relative with no reparse point followed so a
    // junction or symlink in the path cannot redirect the open either. An empty hash means "not
    // hashed" for ANY reason (refused, could not be opened, read failure): this action's output has
    // no column that could say which.
    if (yuzu::shared::local_path::refused(yuzu::shared::local_path::local_path_refusal(path)))
        return {};
    const auto opened = yuzu::win::open_file_no_reparse(yuzu::win::to_wide(path));
    if (opened.status != yuzu::win::NoReparseOpen::ok)
        return {};
    const HANDLE file = opened.file.get(); // owned by `opened`; closed on every exit path
    if (::GetFileType(file) != FILE_TYPE_DISK)
        return {};

    // The hash handle is owned from creation: every return below destroys it exactly once.
    struct BcryptHash {
        BCRYPT_HASH_HANDLE h = nullptr;
        ~BcryptHash() {
            if (h)
                BCryptDestroyHash(h);
        }
    } hash_guard;
    BCRYPT_HASH_HANDLE& hash_handle = hash_guard.h;
    NTSTATUS status = BCryptCreateHash(alg, &hash_handle, nullptr, 0, nullptr, 0, 0);
    if (status != 0)
        return {};

    // A read error or a hash failure part-way through must NOT finish the digest: that would
    // return the SHA-1 of a truncated prefix as if it were the image's hash. Any failure is "not
    // hashed" (empty). ReadFile on a synchronous handle returns TRUE with 0 bytes at end of file.
    char buf[65536];
    DWORD bytes_read = 0;
    bool complete = false;
    for (;;) {
        if (!ReadFile(file, buf, sizeof(buf), &bytes_read, nullptr))
            break; // read error: not complete
        if (bytes_read == 0) {
            complete = true;
            break;
        }
        status = BCryptHashData(hash_handle, reinterpret_cast<PUCHAR>(buf), bytes_read, 0);
        if (status != 0)
            break;
    }
    if (!complete)
        return {};

    unsigned char hash[20]; // SHA-1 is 20 bytes
    status = BCryptFinishHash(hash_handle, hash, sizeof(hash), 0);

    if (status != 0)
        return {};

    std::string hex;
    hex.reserve(40);
    for (int i = 0; i < 20; ++i) {
        hex += std::format("{:02x}", hash[i]);
    }
    return hex;
}

void enumerate_and_stream(yuzu::CommandContext& ctx) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, 0);
    if (status != 0) {
        CloseHandle(snap);
        return;
    }

    std::unordered_map<std::string, std::string> sha_cache;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(snap);
        return;
    }

    do {
        int pid = static_cast<int>(pe.th32ProcessID);
        std::string name = from_wide(pe.szExeFile);
        if (name.empty())
            continue;

        std::string exe_path = get_process_image_path(pe.th32ProcessID);
        std::string sha1;
        if (!exe_path.empty()) {
            auto it = sha_cache.find(exe_path);
            if (it != sha_cache.end()) {
                sha1 = it->second;
            } else {
                sha1 = sha1_of_file(exe_path, alg);
                sha_cache.emplace(exe_path, sha1);
            }
        }

        ctx.write_output(
            std::format("{}|{}|{}|{}", pid, escape_pipes(name), escape_pipes(exe_path), sha1));
    } while (Process32NextW(snap, &pe));

    BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(snap);
}

#endif // platform

// ABI4 capability declarations (#2204). Every leg is a native, in-process
// enumeration + hash — no subprocess anywhere in this plugin.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "procfetch_fetch",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "/proc enumeration + OpenSSL EVP SHA-1", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "libproc (proc_listpids/proc_pidpath) + OpenSSL EVP SHA-1",
         nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "CreateToolhelp32Snapshot + BCrypt SHA-1", nullptr},
    },
};

} // namespace

class ProcfetchPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "procfetch"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Enumerates running processes with SHA-1 hashes of executables";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"procfetch_fetch", nullptr};
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
        if (action == "procfetch_fetch") {
            return do_fetch(ctx);
        }
        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_fetch(yuzu::CommandContext& ctx) {
#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32)
        enumerate_and_stream(ctx);
        return 0;
#else
        ctx.write_output("error: process enumeration not supported on this platform");
        return 1;
#endif
    }
};

YUZU_PLUGIN_EXPORT(ProcfetchPlugin)
