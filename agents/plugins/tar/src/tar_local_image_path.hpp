/**
 * tar_local_image_path.hpp — pure "may this executable image path be opened?" classifier
 * for the Windows module (image-load) and procperf (file-version) paths. Only local paths
 * pass; network paths are never opened.
 *
 * Both sources hand an image path to an API that OPENS it (NtCreateFile/WinVerifyTrust for
 * the module source, GetFileVersionInfoW for procperf). The agent runs as LocalSystem,
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
 *   `\\?\GLOBALROOT\...` form (the module source opens the delivered NT path itself, so it
 *   never builds that form, and the classifier still refuses it), a non-fixed drive letter,
 *   and the empty string. `\SystemRoot\` and `\??\` paths are refused because they match
 *   neither accepted shape.
 *
 * Reparse points. module: after this check the drain opens the image ONCE with
 * NtCreateFile and OBJ_DONT_REPARSE (tar_module_etw.cpp open_local_image_no_reparse), so a
 * symbolic link or junction anywhere in the path, including one planted after the ETW
 * event, fails the open and the row keeps an unknown verdict; nothing is opened by name.
 * procperf: GetFileVersionInfoW still opens by name after this check; the image is
 * RUNNING, its ancestors cannot be renamed while it is mapped and a renamed image reports
 * its new name, so a swap cannot redirect it. Measured 2026-10-22 on Windows 11 Pro
 * 26200.9711: a directory junction whose substitute name is `\??\UNC\localhost\C$\Windows\`
 * is accepted by NTFS (FSCTL_SET_REPARSE_POINT returns 0) but traversing it fails with
 * "The data present in the reparse point buffer is invalid"; other mount-point targets
 * were not measured. A symbolic link to a share needs SeCreateSymbolicLinkPrivilege
 * (administrators, Windows Developer Mode, or the "Create symbolic links" policy).
 *
 * The drive type is injected (the Windows shell calls GetDriveTypeW on drive_root_of()),
 * so this header needs no Windows API and runs in the unit suites on every host.
 */

#pragma once

#include <cstdint>
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

// The leaf decision for an image already opened with OBJ_DONT_REPARSE: refuse a NAME SURROGATE
// reparse point (symbolic link, junction); a filter-handled tag (WOF/CompactOS, dedup, cloud
// files) is an ordinary image. Values restated from winnt.h (tar_module_etw.cpp static_asserts
// them) so this stays pure.
inline constexpr std::uint32_t kFileAttributeReparsePoint = 0x400;
inline constexpr std::uint32_t kReparseTagNameSurrogateBit = 0x20000000;

[[nodiscard]] constexpr bool reparse_leaf_refused(std::uint32_t file_attributes,
                                                  std::uint32_t reparse_tag) noexcept {
    return (file_attributes & kFileAttributeReparsePoint) != 0 &&
           (reparse_tag & kReparseTagNameSurrogateBit) != 0;
}

} // namespace yuzu::tar
