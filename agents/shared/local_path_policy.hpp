// local_path_policy.hpp -- ONE "may an agent plugin open this operator- or user-supplied path?"
// predicate. Only local paths pass; a network path is never opened.
//
// WHY. The Windows agent runs as LocalSystem. A path handed to CreateFileW / std::ifstream /
// GetDiskFreeSpaceExW / std::filesystem that names a share (`\\host\share\f`, `\\?\UNC\host\...`,
// a mapped network drive) makes the machine account authenticate to that host and can stall the
// calling worker on the SMB round trip; a `\\.\` or `\??\` device spelling or a reserved DOS
// device name (`CON`, `NUL`, `COM1`) reaches a driver. On POSIX a path under an NFS/CIFS/autofs
// mount pins the worker on a dead server (a hard mount can hold it forever) and an automount
// trigger can connect outbound. The same refusal for the image paths Echo reads lives in
// agents/plugins/echo/src/echo_local_image_path.hpp (a different, image-specific contract: it
// also accepts the `\Device\HarddiskVolume<n>` shape); this header is the one every OTHER
// plugin path sink extends. EXTEND it, never copy the checks into a plugin.
//
// WHAT IT DECIDES (before any filesystem call that could reach the target):
//   Windows spelling -- LEXICAL: refuse `\\`/`//` (UNC, `\\?\UNC\`, `\\.\`, `\\?\GLOBALROOT\`),
//     the `\??\` and `\Device\` namespaces, a reserved DOS device name in any component
//     (CON PRN AUX NUL COM1-9 LPT1-9 and the superscript COM/LPT 1-3 spellings), and a drive letter
//     (`X:`, `X:file`, `X:\...`, `\\?\X:\...`) whose drive type (injected; GetDriveTypeW in the OS
//     glue) is not DRIVE_FIXED (a mapped network drive, removable, optical, RAM disk, unknown,
//     no-root all refuse). A path with no drive letter (relative, or rooted at the current drive)
//     is allowed: it resolves against the agent's working directory.
//   POSIX -- RESOLVING: the absolute path is walked component by component (`lstat`/`readlink`, at
//     most 40 symlink hops, never a stat below a network mount: each accumulated prefix is judged
//     against the mount table BEFORE it is stat'ed), so a symlink anywhere in the path, the leaf
//     included, that points under a network mount (network_fstype.hpp; the guard reads the table
//     in its strict form: unlisted FUSE and an overlay over a network mount count) is refused.
//     A `..` that follows a missing component cannot be resolved and fails closed. The resolved
//     path is returned so a caller can apply a further policy to it (ioc refuses /proc /sys /dev
//     for hashing). A caller that OPENS the file uses `posix_open_checked`, which has no window
//     between judging and opening: the path is opened component by component relative to its
//     parent descriptor (O_NOFOLLOW|O_PATH|O_DIRECTORY), and the OPENED file's filesystem type is
//     checked (network, FUSE and pseudo filesystems are refused whatever the path text said).
//
// WHAT IT DOES NOT DECIDE (residuals, stated so no caller or document claims more):
//   * Windows link traversal. A junction or directory symlink to a share is FOLLOWED by a path-
//     resolving open; the Windows decision is lexical and the plugins that re-judge a canonical
//     result do so AFTER the canonicalising call has already touched the link. Only a caller that
//     opens handle-relative with no reparse point (win_no_reparse_open.hpp: ioc, procfetch) never
//     follows one. filesystem (validate_path and its canonical re-check) and disk_space are
//     lexical-refusal-only on Windows; link traversal is a residual there.
//   * POSIX: a stacked filesystem (overlay or ecryptfs over a network mount), a network type the
//     deny-list does not name, a bind-mounted NFS subdirectory whose mount point is not itself in
//     the table, and a mount that appears after the table was read (network_fstype.hpp).
//   * Time of check versus use: the judgement is not an open. A caller that opens the path should
//     still open the leaf no-follow and fstat the descriptor.
//
// Read the mount table ONCE per action: construct a `LocalPathGuard` and judge every path with it
// (the one-shot `local_path_refusal` re-reads /proc/self/mountinfo, up to 16 MiB, per call). The
// pure decision functions run in the unit suite on every host; the OS glue is the one place that
// asks the OS for a drive type or the mount table and FAILS CLOSED
// (`Refusal::mount_table_unreadable`) when the POSIX table cannot be read.
#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "network_fstype.hpp"

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/vfs.h>
#elif defined(__APPLE__)
#include <sys/mount.h>
#include <sys/param.h>
#endif
#include "posix_secure_read.hpp" // yuzu::shared::ScopedFile
#endif

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#elif defined(__linux__)
#include "posix_secure_read.hpp"
#elif defined(__APPLE__)
#include "macos_network_mounts.hpp"
#endif

namespace yuzu::shared::local_path {

// DRIVE_FIXED from <winbase.h>; restated so the pure part needs no <windows.h>.
inline constexpr unsigned kDriveTypeFixed = 3;

enum class Refusal : std::uint8_t {
    none,
    network_or_device,       ///< UNC / device namespace / reserved device name / network mount
    non_fixed_drive,         ///< a drive letter whose type is not DRIVE_FIXED
    mount_table_unreadable,  ///< POSIX only: the mount table could not be read (fail closed)
    unresolvable,            ///< POSIX only: the path could not be resolved, or changed while opened
    pseudo_filesystem,       ///< POSIX only: the opened file lives on proc/sys/debugfs/cgroup/...
};

[[nodiscard]] constexpr bool refused(Refusal r) noexcept { return r != Refusal::none; }

/// Stable token for a result row; never echoes the caller's path.
[[nodiscard]] constexpr std::string_view refusal_token(Refusal r) noexcept {
    switch (r) {
    case Refusal::none:
        return "";
    case Refusal::network_or_device:
        return "path_refused:network_or_device";
    case Refusal::non_fixed_drive:
        return "path_refused:non_fixed_drive";
    case Refusal::mount_table_unreadable:
        return "path_refused:mount_table_unreadable";
    case Refusal::unresolvable:
        return "path_refused:unresolvable";
    case Refusal::pseudo_filesystem:
        return "path_refused:pseudo_filesystem";
    }
    return "path_refused";
}

namespace detail {

[[nodiscard]] constexpr char ascii_lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}
[[nodiscard]] constexpr bool ascii_alpha(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

[[nodiscard]] inline bool istarts_with(std::string_view s, std::string_view prefix) noexcept {
    if (s.size() < prefix.size())
        return false;
    for (std::size_t i = 0; i < prefix.size(); ++i)
        if (ascii_lower(s[i]) != ascii_lower(prefix[i]))
            return false;
    return true;
}

/// A reserved Win32 DOS device name once the extension / trailing dots and spaces are dropped:
/// CON PRN AUX NUL CONIN$ CONOUT$ COM1-9 LPT1-9. Win32 resolves these in ANY directory.
[[nodiscard]] inline bool is_reserved_device_component(std::string_view comp) noexcept {
    const auto dot = comp.find_first_of(".:");
    std::string_view stem = dot == std::string_view::npos ? comp : comp.substr(0, dot);
    while (!stem.empty() && (stem.back() == ' ' || stem.back() == '.'))
        stem.remove_suffix(1);
    constexpr std::string_view kNames[] = {"con", "prn", "aux", "nul", "conin$", "conout$"};
    for (const auto n : kNames) {
        if (stem.size() == n.size() && istarts_with(stem, n))
            return true;
    }
    if (stem.size() == 4 && (istarts_with(stem, "com") || istarts_with(stem, "lpt")) &&
        stem[3] >= '1' && stem[3] <= '9')
        return true;
    // COM1-3 and LPT1-3 are also reserved in their superscript spellings (U+00B9, U+00B2, U+00B3;
    // UTF-8 C2 B9 / C2 B2 / C2 B3) on Windows 10 and later.
    if (stem.size() == 5 && (istarts_with(stem, "com") || istarts_with(stem, "lpt")) &&
        static_cast<unsigned char>(stem[3]) == 0xC2 &&
        (static_cast<unsigned char>(stem[4]) == 0xB9 || static_cast<unsigned char>(stem[4]) == 0xB2 ||
         static_cast<unsigned char>(stem[4]) == 0xB3))
        return true;
    return false;
}

} // namespace detail

/// The drive letter of an `X:` / `X:file` / `X:\...` / `\\?\X:\...` spelling, or 0 for every other shape
/// (relative, rooted-at-current-drive, UNC, device). The Windows glue asks the OS for the type of
/// `X:\`.
[[nodiscard]] inline char win_drive_letter(std::string_view path) noexcept {
    if (path.size() >= 4 && (path[0] == '\\' || path[0] == '/') &&
        (path[1] == '\\' || path[1] == '/') && path[2] == '?' && (path[3] == '\\' || path[3] == '/'))
        path.remove_prefix(4);
    // ANY `X:` prefix names a drive, with or without a separator after it: `Z:file` is relative to
    // the current directory ON DRIVE Z, so it reaches that drive (a mapped network drive included)
    // and must face the same drive-type check as `Z:\x`.
    if (path.size() >= 2 && detail::ascii_alpha(path[0]) && path[1] == ':')
        return path[0];
    return 0;
}

/// A drive-letter Windows path in ONE canonical spelling: the `\\?\` long-path prefix before a drive
/// letter is dropped, `/` becomes `\`, and `.` / `..` segments are collapsed lexically (never above
/// the drive root; empty segments dropped). A path that does not start with a drive letter after the
/// prefix is returned with only the slash conversion (the caller makes a relative path absolute
/// first). Pure: it exists so a handle-relative open (win_no_reparse_open.hpp, which accepts only
/// `X:\a\b`) is not refused for an ordinary spelling.
[[nodiscard]] inline std::string win_normalise_spelling(std::string_view path) {
    std::string n(path);
    for (auto& c : n)
        if (c == '/')
            c = '\\';
    std::string_view v = n;
    if (v.starts_with("\\\\?\\") && win_drive_letter(v.substr(4)) != 0)
        v.remove_prefix(4);
    if (win_drive_letter(v) == 0 || v.size() < 3 || v[2] != '\\')
        return std::string(v);
    std::vector<std::string> keep;
    std::size_t start = 3;
    while (start <= v.size()) {
        const auto sep = v.find('\\', start);
        const auto seg = v.substr(start, sep == std::string_view::npos ? std::string_view::npos : sep - start);
        if (seg == "..") {
            if (!keep.empty())
                keep.pop_back();
        } else if (!seg.empty() && seg != ".") {
            keep.emplace_back(seg);
        }
        if (sep == std::string_view::npos)
            break;
        start = sep + 1;
    }
    std::string out(v.substr(0, 3));
    for (std::size_t i = 0; i < keep.size(); ++i) {
        if (i)
            out += '\\';
        out += keep[i];
    }
    return out;
}

/// The Windows-spelling decision. `drive_type_of_letter(char)` returns the OS drive type of
/// `<letter>:\` and is called at most once, and only for a drive-letter spelling. Pure.
template <class DriveTypeFn>
[[nodiscard]] Refusal win_refusal(std::string_view path, DriveTypeFn&& drive_type_of_letter) {
    if (path.empty())
        return Refusal::none; // the caller owns the empty-path error
    // A leading control character or space: Win32 does not agree with any parser on what that
    // names. Refuse rather than guess.
    if (static_cast<unsigned char>(path.front()) <= 0x20)
        return Refusal::network_or_device;

    std::string n(path);
    for (auto& c : n)
        if (c == '/')
            c = '\\';

    std::string_view body = n;
    if (body.starts_with("\\\\?\\")) {
        body.remove_prefix(4);
        // Only the long-path spelling of a drive-letter path survives; `UNC\`, `GLOBALROOT\`,
        // `Volume{...}\` and every other object name are refused.
        if (win_drive_letter(body) == 0)
            return Refusal::network_or_device;
    } else if (body.starts_with("\\\\")) {
        return Refusal::network_or_device; // UNC, `\\.\`
    } else if (body.starts_with("\\??\\") || detail::istarts_with(body, "\\device\\") ||
               detail::istarts_with(body, "\\systemroot\\")) {
        return Refusal::network_or_device; // NT object namespace spellings
    }

    // The component walk: a reserved device name in any component (`C:\x\NUL`, `NUL.txt`).
    std::size_t start = 0;
    // Skip the `X:` drive designator so it is not read as a component.
    if (win_drive_letter(body) != 0)
        start = 2;
    while (start <= body.size()) {
        const auto sep = body.find('\\', start);
        const auto comp = body.substr(start, sep == std::string_view::npos ? std::string_view::npos
                                                                            : sep - start);
        if (!comp.empty() && detail::is_reserved_device_component(comp))
            return Refusal::network_or_device;
        if (sep == std::string_view::npos)
            break;
        start = sep + 1;
    }

    if (const char letter = win_drive_letter(body); letter != 0) {
        if (static_cast<unsigned>(drive_type_of_letter(letter)) != kDriveTypeFixed)
            return Refusal::non_fixed_drive;
    }
    return Refusal::none;
}

/// True when `abs_norm_path` (absolute, lexically normalised) is a mount point from `mounts` or
/// lies under one, on a path-segment boundary (`/mnt/nfs` matches `/mnt/nfs/a`, not `/mnt/nfs2`).
/// A mount of "/" matches everything (a network root filesystem). Pure.
[[nodiscard]] inline bool posix_under_mount(std::string_view abs_norm_path,
                                            const std::vector<std::string>& mounts) {
    for (std::string_view m : mounts) {
        while (m.size() > 1 && m.back() == '/')
            m.remove_suffix(1);
        if (m.empty())
            continue;
        if (m == "/" || abs_norm_path == m)
            return true;
        if (abs_norm_path.size() > m.size() && abs_norm_path.compare(0, m.size(), m) == 0 &&
            abs_norm_path[m.size()] == '/')
            return true;
    }
    return false;
}

/// The POSIX decision over a mount list the caller already holds. Lexical only: makes the path
/// absolute against the working directory and normalises `.`/`..`/`//` without touching the
/// target, so it never blocks on a dead mount. Fails closed when the path cannot be made absolute.
[[nodiscard]] inline Refusal posix_refusal(std::string_view path,
                                           const std::vector<std::string>& network_mounts) {
    if (path.empty())
        return Refusal::none;
    std::error_code ec;
    const std::filesystem::path abs = std::filesystem::absolute(std::filesystem::path(path), ec);
    if (ec)
        return Refusal::unresolvable;
    const std::string norm = abs.lexically_normal().string();
    return posix_under_mount(norm, network_mounts) ? Refusal::network_or_device : Refusal::none;
}

#ifndef _WIN32

/// A path that lies on or under /proc, /sys or /dev (already resolved). Hashing such a file is not
/// a file read: /proc/kmsg consumes the kernel ring buffer, a /dev node can block or have side
/// effects, /proc and /sys pseudo-files report size 0 and are unbounded. Segment boundary.
[[nodiscard]] inline bool posix_pseudo_fs_path(std::string_view resolved) noexcept {
    for (const std::string_view root : {"/proc", "/sys", "/dev"}) {
        if (resolved == root || (resolved.size() > root.size() && resolved.starts_with(root) &&
                                 resolved[root.size()] == '/'))
            return true;
    }
    return false;
}

struct Judged {
    Refusal refusal{Refusal::none};
    std::string resolved; ///< the fully resolved absolute path (POSIX, only when refusal == none)
    int err{0};           ///< errno of the failing lstat/readlink when refusal == unresolvable (0 otherwise)
};

/// The POSIX decision with symlink resolution (see the banner). `network_mounts` are mount points
/// as physical paths. Never stats a component on or under a network mount: each accumulated prefix
/// is judged before it is lstat'ed. A component that does not exist ends the walk; the remainder
/// is appended lexically and judged once more. Any other lstat/readlink failure, more than 40
/// symlink hops, or an uninterpretable path fails closed (`unresolvable`).
[[nodiscard]] inline Judged posix_judge(std::string_view path,
                                        const std::vector<std::string>& network_mounts) {
    if (path.empty())
        return {};
    constexpr int kMaxHops = 40;
    std::error_code ec;
    const std::filesystem::path abs = std::filesystem::absolute(std::filesystem::path(path), ec);
    if (ec)
        return {Refusal::unresolvable, {}};

    std::deque<std::string> pending;
    for (const auto& part : abs)
        if (const auto c = part.string(); !c.empty() && c != "/")
            pending.push_back(c);

    std::string cur = "/";
    const auto parent_of = [](std::string& p) {
        if (p == "/")
            return;
        const auto slash = p.rfind('/');
        p = slash == 0 ? "/" : p.substr(0, slash);
    };
    int hops = 0;
    while (!pending.empty()) {
        const std::string c = std::move(pending.front());
        pending.pop_front();
        if (c == "." || c.empty())
            continue;
        if (c == "..") {
            parent_of(cur);
            continue;
        }
        std::string next = cur == "/" ? "/" + c : cur + "/" + c;
        if (posix_under_mount(next, network_mounts))
            return {Refusal::network_or_device, {}};
        struct stat st{};
        if (::lstat(next.c_str(), &st) != 0) {
            if (errno != ENOENT && errno != ENOTDIR)
                return {Refusal::unresolvable, {}, errno};
            // Nothing exists from here down: the remainder cannot be a link. Judge it lexically.
            cur = std::move(next);
            while (!pending.empty()) {
                const std::string r = std::move(pending.front());
                pending.pop_front();
                if (r == "." || r.empty())
                    continue;
                // A `..` after a missing component would cancel it and expose components that
                // exist but were never lstat'ed (`d/missing/../lnk/a`): the walk cannot say what
                // that path names, so it fails closed instead of guessing lexically.
                if (r == "..")
                    return {Refusal::unresolvable, {}};
                cur = cur == "/" ? "/" + r : cur + "/" + r;
            }
            if (posix_under_mount(cur, network_mounts))
                return {Refusal::network_or_device, {}};
            return {Refusal::none, std::move(cur)};
        }
        if (S_ISLNK(st.st_mode)) {
            if (++hops > kMaxHops)
                return {Refusal::unresolvable, {}};
            char buf[4096];
            const ssize_t n = ::readlink(next.c_str(), buf, sizeof(buf));
            if (n <= 0 || static_cast<std::size_t>(n) >= sizeof(buf))
                return {Refusal::unresolvable, {}};
            const std::string target(buf, static_cast<std::size_t>(n));
            if (target.front() == '/')
                cur = "/";
            // Splice the target's components in front of what is left, in order.
            std::deque<std::string> parts;
            std::size_t start = 0;
            while (start <= target.size()) {
                const auto slash = target.find('/', start);
                parts.push_back(target.substr(start, slash == std::string::npos ? std::string::npos
                                                                                : slash - start));
                if (slash == std::string::npos)
                    break;
                start = slash + 1;
            }
            for (auto it = parts.rbegin(); it != parts.rend(); ++it)
                pending.push_front(*it);
            continue;
        }
        cur = std::move(next);
    }
    return {Refusal::none, std::move(cur)};
}

/// The file the judged path names, opened WITHOUT a window between judging and opening: every
/// component of the (already resolved, symlink-free) path is opened relative to its parent
/// descriptor with O_NOFOLLOW|O_DIRECTORY|O_PATH, so a component swapped for a symlink or a
/// directory renamed away after the judgement fails the open (`unresolvable`) instead of being
/// followed; the final component is opened with `final_flags | O_NOFOLLOW`; and the OPENED file's
/// filesystem is checked with fstatfs/fstatfs-equivalents: a network, FUSE or pseudo filesystem is
/// refused whatever the path text said (this also catches an unlisted network mount and an
/// overlay the mount table could not name). `absent` distinguishes a clean ENOENT/ENOTDIR (a
/// definitive "not there") from every refusal.
#if defined(O_PATH)
inline constexpr int kPathFlag = O_PATH; // Linux: a directory handle that needs no read permission
#else
inline constexpr int kPathFlag = O_RDONLY; // macOS: no O_PATH; a directory is opened for reading
#endif

struct CheckedOpen {
    yuzu::shared::ScopedFile file;
    Refusal refusal{Refusal::none};
    bool absent{false};
    bool not_regular{false}; ///< `require_regular` was set and the leaf is a FIFO/device/socket/directory
    int err{0};
    [[nodiscard]] bool opened() const noexcept { return file.valid(); }
};

namespace detail {

#if defined(__linux__)
[[nodiscard]] inline Refusal refusal_for_fs_type(unsigned long f_type) noexcept {
    switch (f_type) {
    case 0x6969:     // NFS
    case 0x517B:     // SMB
    case 0xFE534D42: // SMB2
    case 0xFF534D42: // CIFS
    case 0x73757245: // CODA
    case 0x564C:     // NCP
    case 0x5346414F: // AFS
    case 0x01021997: // 9P
    case 0x00C36400: // CEPH
    case 0x65735546: // FUSE (the subtype is not visible here: refused, see the banner)
    case 0x0BD00BD0: // LUSTRE
    case 0x47504653: // GPFS
    case 0x7461636f: // OCFS2
    case 0x01161970: // GFS2
        return Refusal::network_or_device;
    case 0x9fa0:     // PROC
    case 0x62656572: // SYSFS
    case 0x64626720: // DEBUGFS
    case 0x27e0eb:   // CGROUP
    case 0x63677270: // CGROUP2
    case 0x73636673: // SECURITYFS
    case 0x74726163: // TRACEFS
    case 0xcafe4a11: // BPF
        return Refusal::pseudo_filesystem;
    default:
        return Refusal::none;
    }
}
#endif

} // namespace detail

///
/// The LEAF is always opened with O_NONBLOCK added, whatever `path_flag` is: where there is no
/// O_PATH (macOS) the leaf is opened O_RDONLY, and a plain O_RDONLY open of a FIFO with no writer
/// (or a device node) blocks in open(2) before any fstat could refuse it. `require_regular` fstat's
/// the opened descriptor and refuses (closing it, `not_regular`) anything but a regular file, so a
/// FIFO, a device, a socket or a symlink-to-/dev/zero is refused without being read. `path_flag` is a
/// seam: tests pass O_RDONLY to force the non-O_PATH (macOS) code path on Linux.
[[nodiscard]] inline CheckedOpen posix_open_checked(const std::string& resolved, int final_flags,
                                                    bool require_regular = false,
                                                    int path_flag = kPathFlag) {
    CheckedOpen out;
    if (resolved.empty() || resolved.front() != '/') {
        out.refusal = Refusal::unresolvable;
        return out;
    }
    std::vector<std::string> parts;
    for (std::size_t start = 1; start <= resolved.size();) {
        const auto slash = resolved.find('/', start);
        const auto comp = resolved.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
        if (comp == "..") { // a resolved path has none: refuse rather than interpret
            out.refusal = Refusal::unresolvable;
            return out;
        }
        if (!comp.empty() && comp != ".")
            parts.push_back(comp);
        if (slash == std::string::npos)
            break;
        start = slash + 1;
    }
    yuzu::shared::ScopedFile dir{::open("/", path_flag | O_DIRECTORY | O_CLOEXEC)};
    if (!dir.valid()) {
        out.err = errno;
        out.refusal = Refusal::unresolvable;
        return out;
    }
    for (std::size_t i = 0; i < parts.size(); ++i) {
        const bool last = i + 1 == parts.size();
        const int flags = last ? (final_flags | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY | O_NONBLOCK)
                               : (path_flag | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        yuzu::shared::ScopedFile next{::openat(dir.fd(), parts[i].c_str(), flags)};
        if (!next.valid()) {
            out.err = errno;
            if (errno == ENOENT || (errno == ENOTDIR && !last)) {
                // ENOTDIR on a non-final component with O_DIRECTORY|O_NOFOLLOW is also what a
                // component swapped for a symlink reports: tell them apart by looking.
                struct stat lst{};
                if (errno == ENOENT || ::fstatat(dir.fd(), parts[i].c_str(), &lst, AT_SYMLINK_NOFOLLOW) != 0) {
                    out.absent = true;
                    return out;
                }
                out.refusal = Refusal::unresolvable; // exists but is a link / not a directory
                return out;
            }
            out.refusal = (errno == ELOOP || errno == ENOTDIR) ? Refusal::unresolvable : Refusal::none;
            return out; // EACCES/EIO/...: err carries it, refusal none, absent false
        }
        dir = std::move(next);
    }
    out.file = std::move(dir); // the opened leaf (or the root itself for "/")
    if (require_regular) {
        struct stat lst{};
        if (::fstat(out.file.fd(), &lst) != 0 || !S_ISREG(lst.st_mode)) {
            out.err = errno;
            out.file = yuzu::shared::ScopedFile{};
            out.not_regular = true;
            return out;
        }
    }
#if defined(__linux__)
    struct statfs sfs{};
    if (::fstatfs(out.file.fd(), &sfs) != 0) {
        out.err = errno;
        out.file = yuzu::shared::ScopedFile{};
        out.refusal = Refusal::unresolvable;
        return out;
    }
    if (const auto r = detail::refusal_for_fs_type(static_cast<unsigned long>(sfs.f_type)); r != Refusal::none) {
        out.file = yuzu::shared::ScopedFile{};
        out.refusal = r;
    }
#elif defined(__APPLE__)
    struct statfs sfs{};
    if (::fstatfs(out.file.fd(), &sfs) != 0) {
        out.err = errno;
        out.file = yuzu::shared::ScopedFile{};
        out.refusal = Refusal::unresolvable;
        return out;
    }
    if (yuzu::shared::is_network_mount_fstype(sfs.f_fstypename)) {
        out.file = yuzu::shared::ScopedFile{};
        out.refusal = Refusal::network_or_device;
    }
#endif
    return out;
}

#endif // !_WIN32

// -- OS glue ------------------------------------------------------------------------------------
// The one place that asks the OS. Not exercised by the unit suite on Windows/macOS.

/// One judge per ACTION: the mount table (Linux /proc/self/mountinfo, macOS getmntinfo) is read
/// ONCE at construction and every path is judged against that snapshot. Windows has no table; the
/// drive type is asked per drive-letter path (GetDriveTypeW is cheap).
class LocalPathGuard {
public:
    LocalPathGuard() {
#if defined(__linux__)
        // /proc/self/mountinfo reports st_size 0, so the reader streams to the cap (the 16 MiB
        // bound find_by_hash and the runtimes walk use). An unreadable or oversized table is a
        // refusal: a guard that cannot see the mounts must not read as "no network mounts".
        constexpr std::size_t kMountinfoCap = 16 * 1024 * 1024;
        const auto table = yuzu::shared::read_file_no_follow("/proc/self/mountinfo", kMountinfoCap);
        table_ok_ = table.ok();
        if (table_ok_)
            mounts_ = yuzu::shared::network_mount_points(table.data, /*strict=*/true);
#elif defined(__APPLE__)
        const auto mounts = yuzu::shared::read_macos_network_mounts();
        table_ok_ = mounts.has_value();
        if (mounts)
            mounts_ = *mounts;
#endif
    }

#if defined(_WIN32)
    [[nodiscard]] Refusal refusal(std::string_view path) const {
        return win_refusal(path, [](char letter) -> unsigned {
            const wchar_t root[4] = {static_cast<wchar_t>(static_cast<unsigned char>(letter)), L':',
                                     L'\\', L'\0'};
            return ::GetDriveTypeW(root);
        });
    }
#elif defined(__linux__) || defined(__APPLE__)
    [[nodiscard]] Judged judge(std::string_view path) const {
        if (path.empty())
            return {};
        if (!table_ok_)
            return {Refusal::mount_table_unreadable, {}};
        return posix_judge(path, mounts_);
    }
    [[nodiscard]] Refusal refusal(std::string_view path) const { return judge(path).refusal; }
#else
    [[nodiscard]] Refusal refusal(std::string_view) const { return Refusal::none; }
#endif

private:
#if defined(__linux__) || defined(__APPLE__)
    bool table_ok_{false};
    std::vector<std::string> mounts_;
#endif
};

/// One-shot form for a caller that judges exactly one path (reads the table each call).
[[nodiscard]] inline Refusal local_path_refusal(std::string_view path) {
    return LocalPathGuard{}.refusal(path);
}

} // namespace yuzu::shared::local_path
