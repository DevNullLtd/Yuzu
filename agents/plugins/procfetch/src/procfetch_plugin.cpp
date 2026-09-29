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

#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <openssl/evp.h>
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

std::string sha1_of_file_posix(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return {};

    auto* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return {};

    if (EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    char buf[65536];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0) {
        if (EVP_DigestUpdate(ctx, buf, static_cast<size_t>(f.gcount())) != 1) {
            EVP_MD_CTX_free(ctx);
            return {};
        }
        if (f.gcount() < static_cast<std::streamsize>(sizeof(buf)))
            break;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }
    EVP_MD_CTX_free(ctx);

    std::string hex;
    hex.reserve(hash_len * 2);
    for (unsigned int i = 0; i < hash_len; ++i) {
        hex += std::format("{:02x}", hash[i]);
    }
    return hex;
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
    std::unordered_map<std::string, std::string> sha_cache;
    std::error_code ec;

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
        if (!exe_path.empty()) {
            std::error_code fe;
            if (std::filesystem::exists(exe_path, fe)) {
                auto it = sha_cache.find(exe_path);
                if (it != sha_cache.end()) {
                    sha1 = it->second;
                } else {
                    sha1 = sha1_of_file_posix(exe_path);
                    sha_cache.emplace(exe_path, sha1);
                }
            }
        }

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

    std::unordered_map<std::string, std::string> sha_cache;
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
        if (!exe_path.empty()) {
            std::error_code fe;
            if (std::filesystem::exists(exe_path, fe)) {
                auto it = sha_cache.find(exe_path);
                if (it != sha_cache.end()) {
                    sha1 = it->second;
                } else {
                    sha1 = sha1_of_file_posix(exe_path);
                    sha_cache.emplace(exe_path, sha1);
                }
            }
        }

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
    HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return {};

    BCRYPT_HASH_HANDLE hash_handle = nullptr;
    NTSTATUS status = BCryptCreateHash(alg, &hash_handle, nullptr, 0, nullptr, 0, 0);
    if (status != 0) {
        CloseHandle(file);
        return {};
    }

    char buf[65536];
    DWORD bytes_read = 0;
    while (ReadFile(file, buf, sizeof(buf), &bytes_read, nullptr) && bytes_read > 0) {
        status = BCryptHashData(hash_handle, reinterpret_cast<PUCHAR>(buf), bytes_read, 0);
        if (status != 0)
            break;
    }
    CloseHandle(file);

    unsigned char hash[20]; // SHA-1 is 20 bytes
    status = BCryptFinishHash(hash_handle, hash, sizeof(hash), 0);
    BCryptDestroyHash(hash_handle);

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
