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
// WHAT IT DECIDES (lexically, before any filesystem call):
//   Windows spelling -- refuse `\\`/`//` (UNC, `\\?\UNC\`, `\\.\`, `\\?\GLOBALROOT\`), the
//     `\??\` and `\Device\` namespaces, a reserved DOS device name in any component, and a drive
//     letter whose drive type (injected, GetDriveTypeW in the OS glue) is not DRIVE_FIXED
//     (a mapped network drive, removable, optical, RAM disk, unknown, no-root all refuse).
//     `\\?\X:\...` is the long-path spelling of a drive-letter path and is judged like `X:\...`.
//     A path with no drive letter (relative, or rooted at the current drive) is allowed: it
//     resolves against the agent's working directory, which is local.
//   POSIX -- the lexically normalised absolute path on or under a network mount named by the
//     mount table the caller read (network_fstype.hpp).
//
// WHAT IT DOES NOT DECIDE. A symlink or a Windows junction/directory symlink inside a local
// tree can still point at a share; a caller that resolves the path (fs::canonical) re-judges the
// RESULT with the same predicate (the plugins do). A stacked filesystem over a dead network
// mount, an unlisted network type and a mount that appears after the table was read are the
// residuals network_fstype.hpp documents. Nothing here replaces an open that does not follow
// reparse points / symlinks where the caller can use one.
//
// The decision functions are pure and run in the unit suite on every host; the OS glue at the
// bottom (`local_path_refusal`) is the one place that asks the OS for a drive type or the mount
// table, and FAILS CLOSED (`Refusal::mount_table_unreadable`) when the POSIX table cannot be read.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "network_fstype.hpp"

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
    unresolvable,            ///< POSIX only: the path could not be made absolute (fail closed)
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

// -- OS glue ------------------------------------------------------------------------------------
// The one place that asks the OS. Not exercised by the unit suite on Windows/macOS.

#if defined(_WIN32)

[[nodiscard]] inline Refusal local_path_refusal(std::string_view path) {
    return win_refusal(path, [](char letter) -> unsigned {
        const wchar_t root[4] = {static_cast<wchar_t>(static_cast<unsigned char>(letter)), L':',
                                 L'\\', L'\0'};
        return ::GetDriveTypeW(root);
    });
}

#elif defined(__linux__)

[[nodiscard]] inline Refusal local_path_refusal(std::string_view path) {
    if (path.empty())
        return Refusal::none;
    // /proc/self/mountinfo reports st_size 0, so the reader streams to the cap (the 16 MiB bound
    // find_by_hash and the runtimes walk use). An unreadable or oversized table is a refusal: a
    // guard that cannot see the mounts must not read as "no network mounts".
    constexpr std::size_t kMountinfoCap = 16 * 1024 * 1024;
    const auto table = yuzu::shared::read_file_no_follow("/proc/self/mountinfo", kMountinfoCap);
    if (!table.ok())
        return Refusal::mount_table_unreadable;
    return posix_refusal(path, yuzu::shared::network_mount_points(table.data));
}

#elif defined(__APPLE__)

[[nodiscard]] inline Refusal local_path_refusal(std::string_view path) {
    if (path.empty())
        return Refusal::none;
    const auto mounts = yuzu::shared::read_macos_network_mounts();
    if (!mounts)
        return Refusal::mount_table_unreadable;
    return posix_refusal(path, *mounts);
}

#else

[[nodiscard]] inline Refusal local_path_refusal(std::string_view) { return Refusal::none; }

#endif

} // namespace yuzu::shared::local_path
