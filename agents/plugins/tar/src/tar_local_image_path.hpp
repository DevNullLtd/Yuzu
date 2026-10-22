/**
 * tar_local_image_path.hpp — pure "may this executable image path be opened?" classifier
 * for the Windows module (image-load) and procperf (file-version) paths. Only local paths
 * pass; network paths are never opened.
 *
 * Both sources hand an image path to an API that OPENS it (GetFileAttributesExW,
 * CryptQueryObject, WinVerifyTrust, GetFileVersionInfoW). The agent runs as LocalSystem,
 * so a path on a network share would make the machine account authenticate to the
 * share's host and could stall the caller on the SMB round trip. The path is taken from
 * an image any standard user can load, so it is attacker-influenced. Callers classify the
 * path FIRST and, when it is refused, open nothing: the row is kept with an unknown
 * signing verdict (module) or an empty version (procperf).
 *
 * Accepted (and nothing else):
 *   - `\Device\HarddiskVolume<digits>\...` (the shape the Kernel-Process IMAGE event
 *     delivers). This is an NT volume path on ANY local volume, removable included: its
 *     drive type is not asked for (procperf's QueryFullProcessImageNameW yields the
 *     Win32 drive-letter form, so this arm is the module source's);
 *   - `X:\...` or `\\?\X:\...` when the caller-supplied drive type of `X:\` is
 *     DRIVE_FIXED (3).
 * Refused: UNC (`\\server\...`, `\\?\UNC\...`), `\Device\Mup`, `\Device\LanmanRedirector`,
 *   `\Device\WebDavRedirector`, any other `\Device\*`, `\SystemRoot\...`, `\??\...`, the
 *   converted `\\?\GLOBALROOT\...` form (callers classify the path as delivered, BEFORE the
 *   NT-to-Win32 conversion), a non-fixed drive letter, and the empty string. `\SystemRoot\`
 *   and `\??\` paths are refused because they match neither accepted shape; the module
 *   source has only ever converted `\Device\...` names for the file APIs (nt_path_to_win32).
 *
 * Residual: the check is lexical and the open happens by name afterwards (a tick later
 * for module, immediately for procperf), so a local-looking path swapped for a symbolic
 * link to a network target in that window is not caught. Creating such a link needs
 * SeCreateSymbolicLinkPrivilege (administrators, or any user when Windows Developer Mode
 * is on) and winning a race against the drain; a directory junction cannot point at a
 * remote share. Closing it fully needs a handle-relative, hop-by-hop open like
 * win_hive_file_guard.hpp, which is a separate change.
 *
 * The drive type is injected (the Windows shell calls GetDriveTypeW on drive_root_of()),
 * so this header needs no Windows API and runs in the unit suites on every host.
 */

#pragma once

#include <string>
#include <string_view>

namespace yuzu::tar {

// DRIVE_FIXED from <winbase.h>; restated so the pure header needs no <windows.h>.
inline constexpr unsigned kDriveTypeFixed = 3;

// The `X:\` root of an `X:\...` / `\\?\X:\...` path; "" for every other shape (including
// UNC, whose `\\?\UNC\` prefix is not a drive letter). The Windows shell asks the OS for
// the type of this root.
[[nodiscard]] inline std::string drive_root_of(std::string_view path) {
    if (path.starts_with("\\\\?\\"))
        path.remove_prefix(4);
    const bool alpha = !path.empty() && ((path[0] >= 'A' && path[0] <= 'Z') ||
                                         (path[0] >= 'a' && path[0] <= 'z'));
    if (alpha && path.size() >= 3 && path[1] == ':' && path[2] == '\\')
        return std::string(path.substr(0, 3));
    return {};
}

// True only for a local image path (see the banner). `drive_type_of_root` is the OS drive
// type of drive_root_of(path); it is consulted only for the drive-letter forms.
[[nodiscard]] inline bool is_local_image_path(std::string_view path,
                                               unsigned drive_type_of_root) noexcept {
    constexpr std::string_view kVolume = "\\Device\\HarddiskVolume";

    if (path.starts_with(kVolume)) {
        path.remove_prefix(kVolume.size());
        const auto end = path.find_first_not_of("0123456789");
        return end != 0 && end != std::string_view::npos && path[end] == '\\';
    }
    return drive_type_of_root == kDriveTypeFixed && !drive_root_of(path).empty();
}

} // namespace yuzu::tar
