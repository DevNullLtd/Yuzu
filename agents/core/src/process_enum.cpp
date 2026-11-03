/**
 * process_enum.cpp -- Cross-platform process enumeration
 *
 * Windows: CreateToolhelp32Snapshot + QueryFullProcessImageNameW + token user
 * Linux:   /proc/[pid]/{status,cmdline} + getpwuid_r
 * macOS:   sysctl(KERN_PROC_ALL) + proc_pidpath + getpwuid_r
 */

#include <yuzu/agent/process_enum.hpp>

#include <charconv>
#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
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
#include <sddl.h>   // ConvertSidToStringSidW (fallback)
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#pragma comment(lib, "advapi32.lib")
#elif defined(__linux__)
#include <dirent.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <cctype>
#include <cstring>
#include <fstream>
#elif defined(__APPLE__)
#include <libproc.h>
#include <pwd.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>
#endif

namespace yuzu::agent {

namespace {

#ifdef _WIN32

// wide_to_utf8 now delegates to the shared agents/shared/win_str.hpp helper
// (#1681). The removed local copy used the same allocate-(len-1)/pass-len idiom
// that drops the trailing NUL, matching yuzu::win::from_wide (null/empty -> {}).
std::string wide_to_utf8(const wchar_t* wstr) { return yuzu::win::from_wide(wstr); }

/// Try to get the full image path for a process. Falls back to empty string.
std::string get_process_image_path(DWORD pid) {
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc)
        return {};

    wchar_t path[MAX_PATH]{};
    DWORD size = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(proc, 0, path, &size);
    CloseHandle(proc);

    if (!ok)
        return {};
    return wide_to_utf8(path);
}

/// Try to get the user account running a process via its token.
std::string get_process_user(DWORD pid) {
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc)
        return {};

    HANDLE token = nullptr;
    if (!OpenProcessToken(proc, TOKEN_QUERY, &token)) {
        CloseHandle(proc);
        return {};
    }

    // Get token user info size
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0) {
        CloseHandle(token);
        CloseHandle(proc);
        return {};
    }

    std::vector<BYTE> buf(needed);
    if (!GetTokenInformation(token, TokenUser, buf.data(), needed, &needed)) {
        CloseHandle(token);
        CloseHandle(proc);
        return {};
    }

    auto* user_info = reinterpret_cast<TOKEN_USER*>(buf.data());

    wchar_t name[256]{};
    wchar_t domain[256]{};
    DWORD name_len = 256;
    DWORD domain_len = 256;
    SID_NAME_USE use{};

    if (LookupAccountSidW(nullptr, user_info->User.Sid, name, &name_len, domain, &domain_len,
                           &use)) {
        std::string result;
        auto d = wide_to_utf8(domain);
        auto n = wide_to_utf8(name);
        if (!d.empty()) {
            result = d + "\\" + n;
        } else {
            result = n;
        }
        CloseHandle(token);
        CloseHandle(proc);
        return result;
    }

    CloseHandle(token);
    CloseHandle(proc);
    return {};
}

#elif defined(__linux__) || defined(__APPLE__)

/// Resolve a numeric UID to a username via getpwuid_r.
std::string uid_to_username(uid_t uid) {
    struct passwd pwd{};
    struct passwd* result = nullptr;
    char buf[1024];
    int rc = getpwuid_r(uid, &pwd, buf, sizeof(buf), &result);
    if (rc == 0 && result)
        return result->pw_name;
    return std::to_string(uid);
}

#endif

} // namespace

namespace detail {

std::string read_proc_bytes(std::istream& in) noexcept {
    std::string out;
    try {
        for (std::istreambuf_iterator<char> it(in), end; it != end && out.size() < kProcReadCap;
             ++it)
            out.push_back(*it);
    } catch (...) {
        // Keep what was read before the failure (see the declaration).
    }
    return out;
}

#if defined(__linux__) || defined(__APPLE__)
namespace {
// Value of the first unsigned decimal number after `prefix_len` characters of `line` (spaces and
// tabs skipped); nullopt when there is none or it does not fit.
std::optional<std::uint32_t> status_u32(const std::string& line, std::size_t prefix_len) {
    const auto pos = line.find_first_not_of(" \t", prefix_len);
    if (pos == std::string::npos)
        return std::nullopt;
    std::uint32_t v = 0;
    const auto [end, ec] = std::from_chars(line.data() + pos, line.data() + line.size(), v);
    if (ec != std::errc{} || end == line.data() + pos)
        return std::nullopt;
    return v;
}
} // namespace

void parse_proc_status(std::istream& in, ProcessInfo& pi) noexcept {
    try {
        std::string line;
        bool got_name = false, got_ppid = false, got_uid = false;
        while (std::getline(in, line)) {
            // The first occurrence of each field wins; a repeated line never overwrites.
            if (!got_name && line.starts_with("Name:")) {
                const auto pos = line.find_first_not_of(" \t", 5);
                if (pos != std::string::npos)
                    pi.name = line.substr(pos);
                got_name = true;
            } else if (!got_ppid && line.starts_with("PPid:")) {
                if (const auto ppid = status_u32(line, 5))
                    pi.ppid = *ppid;
                got_ppid = true;
            } else if (!got_uid && line.starts_with("Uid:")) {
                // First field after "Uid:" is the real UID. std::from_chars stops at the
                // first space or tab, so the effective/saved/fs fields are not read.
                if (const auto uid = status_u32(line, 4))
                    pi.user = uid_to_username(static_cast<uid_t>(*uid));
                got_uid = true;
            }
            // No early exit (#6895, kept on purpose): the whole file is read so later fields stay
            // reachable; /proc/<pid>/status is kernel-generated and about a kilobyte, so stopping
            // after Uid: would save nothing measurable.
        }
    } catch (...) {
        // A failed read or an allocation failure keeps whatever parsed so far.
    }
}
#endif // __linux__ || __APPLE__

} // namespace detail

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
            pi.name = wide_to_utf8(pe.szExeFile);

            // Get full image path as cmdline (best effort)
            auto path = get_process_image_path(pe.th32ProcessID);
            pi.cmdline = path.empty() ? pi.name : path;
            // exec_path (P-004): the SAME resolved path, but with NO name
            // fallback -- empty here means genuinely unresolvable, never a
            // guess. cmdline's fallback-to-name above exists for display; a
            // removable-media correlation must not treat a bare process name
            // as a filesystem path.
            pi.exec_path = path;

            // Get user (best effort -- will fail for system/protected processes)
            pi.user = get_process_user(pe.th32ProcessID);

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
        // Only numeric directories (PIDs)
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

        ProcessInfo pi;
        pi.pid = static_cast<uint32_t>(std::stoul(entry->d_name));

        std::string base = std::string("/proc/") + entry->d_name;

        // Read /proc/[pid]/status for Name, PPid, Uid
        {
            std::ifstream ifs(base + "/status");
            if (!ifs.is_open())
                continue;
            detail::parse_proc_status(ifs, pi);
        }

        // Read /proc/[pid]/cmdline (null-separated args)
        {
            std::ifstream ifs(base + "/cmdline", std::ios::binary);
            if (ifs.is_open()) {
                // A process that exits mid-read must cost this cmdline, not the agent.
                std::string raw = detail::read_proc_bytes(ifs);
                // Replace null separators with spaces
                for (auto& c : raw) {
                    if (c == '\0')
                        c = ' ';
                }
                // Trim trailing space
                while (!raw.empty() && raw.back() == ' ')
                    raw.pop_back();
                pi.cmdline = std::move(raw);
            }
        }

        // Fallback cmdline to name if empty (kernel threads)
        if (pi.cmdline.empty())
            pi.cmdline = pi.name;

        // exec_path (P-004): resolve the /proc/<pid>/exe symlink -- the
        // kernel-verified canonical executable path, distinct from argv[0]
        // (cmdline above), which is user-controlled and often relative or a
        // bare basename. readlink returns -1/EACCES for another user's
        // process (or a zombie with no /exe target) -- left empty rather than
        // guessed, per the header contract.
        {
            char buf[4096];
            ssize_t n = readlink((base + "/exe").c_str(), buf, sizeof(buf) - 1);
            if (n > 0)
                pi.exec_path.assign(buf, static_cast<size_t>(n));
        }

        procs.push_back(std::move(pi));
    }
    closedir(proc_dir);
    return procs;
}

#elif defined(__APPLE__)

std::vector<ProcessInfo> enumerate_processes() {
    std::vector<ProcessInfo> procs;

    // Use sysctl to get all processes
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t buf_size = 0;

    // First call to determine buffer size
    if (sysctl(mib, 4, nullptr, &buf_size, nullptr, 0) < 0)
        return procs;

    // Over-allocate slightly in case new processes appear
    buf_size = buf_size * 5 / 4;
    std::vector<char> buf(buf_size);

    if (sysctl(mib, 4, buf.data(), &buf_size, nullptr, 0) < 0)
        return procs;

    size_t count = buf_size / sizeof(struct kinfo_proc);
    auto* kprocs = reinterpret_cast<struct kinfo_proc*>(buf.data());

    for (size_t i = 0; i < count; ++i) {
        ProcessInfo pi;
        pi.pid = static_cast<uint32_t>(kprocs[i].kp_proc.p_pid);
        pi.ppid = static_cast<uint32_t>(kprocs[i].kp_eproc.e_ppid);
        pi.name = kprocs[i].kp_proc.p_comm;

        // User from credential UID
        uid_t uid = kprocs[i].kp_eproc.e_ucred.cr_uid;
        pi.user = uid_to_username(uid);

        // Get executable path via proc_pidpath
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE]{};
        int ret = proc_pidpath(static_cast<int>(pi.pid), pathbuf, sizeof(pathbuf));
        if (ret > 0) {
            pi.cmdline = pathbuf;
            // exec_path (P-004): store the SAME proc_pidpath result already
            // fetched above -- no second syscall, no name fallback.
            pi.exec_path = pathbuf;
        } else {
            pi.cmdline = pi.name;
        }

        procs.push_back(std::move(pi));
    }

    return procs;
}

#else

std::vector<ProcessInfo> enumerate_processes() {
    return {};
}

#endif

} // namespace yuzu::agent
