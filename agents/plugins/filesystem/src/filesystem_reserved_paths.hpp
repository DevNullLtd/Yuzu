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
/// must not be described as such. Matching is segment-boundary, never a bare prefix; for a
/// not-yet-existing leaf it is ASCII-case-insensitive on Windows and macOS.

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

/// macOS: the Data volume is reachable both as `/Users/x/f` and, through a firmlink (not a symlink, so
/// no canonicalising call collapses it), as `/System/Volumes/Data/Users/x/f`. The spelling is removed
/// before a not-yet-existing reserved leaf is compared, on both sides. Pure and platform-neutral so it
/// is unit-tested on Linux; the comparison applies it on `__APPLE__` only.
[[nodiscard]] inline std::string strip_apple_data_firmlink(std::string_view p) {
    constexpr std::string_view kPrefix = "/System/Volumes/Data";
    if (p.size() >= kPrefix.size() && p.compare(0, kPrefix.size(), kPrefix) == 0 &&
        (p.size() == kPrefix.size() || p[kPrefix.size()] == '/' || p[kPrefix.size()] == '\\'))
        p.remove_prefix(kPrefix.size());
    return std::string(p);
}

/// Normalise for comparison: '\' -> '/', collapse a trailing '/', fold ASCII case (A-Z only) on Windows
/// and macOS, and on macOS drop a leading `/System/Volumes/Data` firmlink spelling.
[[nodiscard]] inline std::string normalise(std::string_view p_in) {
#ifdef __APPLE__
    const std::string stripped = strip_apple_data_firmlink(p_in);
    const std::string_view p{stripped};
#else
    const std::string_view p = p_in;
#endif
    std::string out;
    out.reserve(p.size());
    for (char c : p) {
        char n = c == '\\' ? '/' : c;
#if defined(_WIN32) || defined(__APPLE__)
        // The default volumes on Windows (NTFS) and macOS (APFS) are case-insensitive, so a not-yet-existing
        // reserved leaf is matched ASCII-case-folded there (an EXISTING reserved file is matched by
        // identity). Non-ASCII letters are NOT folded on either OS (a documented residual).
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
/// Refused as a literal or canonical spelling, BY PATH NAME and not by file identity: on macOS
/// `/dev/fd/N` reports the same inode as the real file but a different st_dev (a synthetic devfs value,
/// measured on macOS 27 arm64), so an identity compare would not match it. Pure; never true for a
/// Windows path.
[[nodiscard]] inline bool is_dev_fd_path(std::string_view path_in) {
    // ASCII case is folded: the default macOS volume is case-insensitive and whether /dev folds case
    // was not measured, so a case variant is refused rather than assumed to be another object
    // (harmless over-refusal on a case-sensitive volume).
    std::string path(path_in);
    for (char& c : path)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    constexpr std::string_view kDev = "/dev/";
    if (std::string_view{path}.substr(0, kDev.size()) != kDev)
        return false;
    const std::string_view rest = std::string_view{path}.substr(kDev.size());
    const std::string_view first = rest.substr(0, rest.find('/'));
    return first == "fd" || first == "stdin" || first == "stdout" || first == "stderr";
}

/// macOS: `/.vol/<dev>/<ino>` opens any file by inode number, so a literal `/.vol/` path names a
/// reserved file without spelling its path. Refused as a literal (ASCII case folded: over-refusal, since
/// `/.VOL` does not exist on the macOS host measured). Pure; the
/// plugin applies it on `__APPLE__` only.
[[nodiscard]] inline bool is_apple_vol_path(std::string_view path_in) {
    std::string path(path_in);
    for (char& c : path)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    return std::string_view{path}.substr(0, 6) == "/.vol/" || path == "/.vol";
}

/// A path containing a NUL byte names no single file: every C-string consumer truncates it, so the
/// decision and the open can disagree. Refused outright.
[[nodiscard]] inline bool contains_nul(std::string_view path) {
    return path.find('\0') != std::string_view::npos;
}

/// Windows: a spelling that Win32 normalises to a DIFFERENT name than the one compared lexically.
/// A not-yet-existing reserved file is compared by string, so `keys\agent.key::$DATA`,
/// `keys\agent.key:ads` (an alternate data stream of the same file) and `keys\agent.key ` (a trailing
/// space, stripped by Win32) would each slip past the string match and then create or reach the
/// reserved file. Refused as a SPELLING, before any reserved comparison: a ':' anywhere after the
/// leading drive designator (`X:`) and the verbatim prefix (`\\?\`), and any component that ends in a
/// space or a '.' (the components "." and ".." are navigation, not names). Pure and
/// platform-neutral so it is unit-tested on Linux; the plugin applies it on `_WIN32` only (on POSIX a
/// ':' or a trailing space is an ordinary file name). Over-refusal is the safe side.
[[nodiscard]] inline bool is_windows_alias_spelling(std::string_view p) {
    auto sep = [](char c) { return c == '\\' || c == '/'; };
    std::size_t i = 0;
    if (p.size() >= 4 && sep(p[0]) && sep(p[1]) && p[2] == '?' && sep(p[3]))
        i = 4;
    if (p.size() >= i + 2 && ((p[i] >= 'A' && p[i] <= 'Z') || (p[i] >= 'a' && p[i] <= 'z')) &&
        p[i + 1] == ':')
        i += 2;
    const std::string_view rest = p.substr(i);
    if (rest.find(':') != std::string_view::npos)
        return true;
    std::size_t start = 0;
    while (start <= rest.size()) {
        std::size_t end = start;
        while (end < rest.size() && !sep(rest[end]))
            ++end;
        const std::string_view comp = rest.substr(start, end - start);
        if (!comp.empty() && comp != "." && comp != ".." && (comp.back() == ' ' || comp.back() == '.'))
            return true;
        start = end + 1;
    }
    return false;
}

} // namespace yuzu::filesystem::reserved
