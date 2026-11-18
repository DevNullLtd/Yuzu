#pragma once

/// @file filesystem_reserved_paths.hpp
/// WP06 F55: paths the filesystem plugin REFUSES because they hold the agent's own control-plane
/// secrets. `filesystem.read` / `search` / `get_acl` / `file_hash` are authorized by
/// `FileRetrieval:Read` with no execute gate, while the same bytes (the agent log, which has
/// carried the session credential; the mTLS key; the data directory) are reachable through
/// `agent_logging.get_log` / `status` / `diagnostics` only under `PluginSecret`. So the plugin
/// itself refuses: an agent-owned path is never readable through `FileRetrieval`.
///
/// Pure (no I/O): the plugin canonicalises the configured paths once at init
/// (`agent.data_dir`, `agent.cert_dir`, `agent.log_file`, `agent.tls_*`) and canonicalises each
/// request path with symlinks resolved before asking. CONFINEMENT IS BEST EFFORT against a writer
/// who controls a parent directory (a check-then-open window remains); it is not absolute and
/// must not be described as such. Matching is segment-boundary, never a bare prefix; on Windows
/// it is ASCII-case-insensitive.

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::filesystem::reserved {

struct Set {
    std::vector<std::string> dirs;  ///< the directory itself and everything under it
    std::vector<std::string> files; ///< the file, and `<file>.<suffix>` siblings (log rotation)

    [[nodiscard]] bool empty() const noexcept { return dirs.empty() && files.empty(); }
};

/// Normalise for comparison: '\' -> '/', collapse a trailing '/', fold ASCII case on Windows.
[[nodiscard]] inline std::string normalise(std::string_view p) {
    std::string out;
    out.reserve(p.size());
    for (char c : p) {
        char n = c == '\\' ? '/' : c;
#ifdef _WIN32
        if (n >= 'A' && n <= 'Z')
            n = static_cast<char>(n - 'A' + 'a');
#endif
        out.push_back(n);
    }
    while (out.size() > 1 && out.back() == '/')
        out.pop_back();
    return out;
}

/// True when `canonical_path` (symlinks already resolved by the caller) names a reserved dir,
/// something under one, or a reserved file (or its rotated sibling `<file>.<suffix>`).
[[nodiscard]] inline bool is_agent_reserved_path(const Set& set, std::string_view canonical_path) {
    if (canonical_path.empty())
        return false;
    const std::string p = normalise(canonical_path);
    for (const auto& raw : set.dirs) {
        const std::string d = normalise(raw);
        if (d.empty())
            continue;
        if (p == d)
            return true;
        const std::string prefix = d == "/" ? d : d + "/";
        if (p.size() > prefix.size() && p.compare(0, prefix.size(), prefix) == 0)
            return true;
    }
    for (const auto& raw : set.files) {
        const std::string f = normalise(raw);
        if (f.empty())
            continue;
        if (p == f)
            return true;
        if (p.size() > f.size() && p.compare(0, f.size(), f) == 0 && p[f.size()] == '.')
            return true;
    }
    return false;
}

/// Linux: `/proc/<pid>/...` files that hold a process's secrets or let one be read around the path
/// guard. A path whose canonical form is `/proc/<digits>/<name>` (or `/proc/<digits>/task/<tid>/<name>`)
/// is refused when `<digits>` is `own_pid` (the agent: its environ carried the enrolment token) for
/// EVERY name under it, and for any other pid when `<name>` is one of the secret-bearing files below.
/// `/proc/self` and `/proc/thread-self` are symlinks, so a canonicalised path already names the pid;
/// the literal spellings are refused as well for a caller that passes a non-canonical string.
/// Pure; non-Linux callers never pass a /proc path (it simply does not match there).
[[nodiscard]] inline bool is_proc_secret_path(std::string_view canonical_path, long own_pid) {
    constexpr std::string_view kProc = "/proc/";
    if (canonical_path.substr(0, kProc.size()) != kProc)
        return false;
    std::string_view rest = canonical_path.substr(kProc.size());
    const auto slash = rest.find('/');
    const std::string_view who = rest.substr(0, slash);
    if (who == "self" || who == "thread-self")
        return true;
    if (who.empty() || who.find_first_not_of("0123456789") != std::string_view::npos)
        return false;
    const bool own = std::to_string(own_pid) == who;
    if (own)
        return true;
    if (slash == std::string_view::npos)
        return false;
    std::string_view tail = rest.substr(slash + 1);
    // /proc/<pid>/task/<tid>/<name> -> <name>
    if (tail.substr(0, 5) == "task/") {
        const auto s2 = tail.find('/', 5);
        if (s2 == std::string_view::npos)
            return false;
        tail = tail.substr(s2 + 1);
    }
    const auto first = tail.substr(0, tail.find('/'));
    for (std::string_view name : {"environ", "mem", "maps", "smaps", "smaps_rollup", "cmdline", "fd",
                                  "fdinfo", "auxv", "stack", "syscall", "mountinfo", "cwd", "root", "exe"})
        if (first == name)
            return true;
    return false;
}

/// POSIX (macOS in particular): `/dev/fd/N`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr` name the
/// agent's own open descriptors (an inherited secret file, the log). macOS has no `/proc`, so
/// `is_proc_secret_path` cannot see them; on Linux the same names are symlinks into `/proc/self`.
/// Refused as a literal or canonical spelling. Pure; never true for a Windows path.
[[nodiscard]] inline bool is_dev_fd_path(std::string_view path) {
    constexpr std::string_view kDev = "/dev/";
    if (path.substr(0, kDev.size()) != kDev)
        return false;
    const std::string_view rest = path.substr(kDev.size());
    const std::string_view first = rest.substr(0, rest.find('/'));
    return first == "fd" || first == "stdin" || first == "stdout" || first == "stderr";
}

} // namespace yuzu::filesystem::reserved
