/**
 * component_fs_win.cpp -- the Windows leg of the component_inventory filesystem seam (FsOps in
 * component_walk.hpp) and the choice of what to walk (component_legs_win.hpp).
 *
 * A THIN SHELL. Every decision is in component_legs_win.hpp and is tested on every OS: which roots,
 * which exclusions, how a path and a name convert, how a record type is read, how a listing is cut and
 * sorted, how a ranged read loops. This file holds only what needs the Windows API: the handles, one
 * GetFileInformationByHandleEx call, one ReadFile, the known-folder lookup, the drive type. It holds
 * no component logic and is written so that the file-search programme's Windows filesystem layer
 * (plan PR 4) can adopt it or replace it.
 *
 * Read-only: no write, no subprocess, no network, no environment variable. Wide APIs only.
 *
 * NO REPARSE POINT IS FOLLOWED AT ANY COMPONENT. The Program Files trees are writable by installers
 * and, below an application's own directory, often by non-administrators, and the agent reads them as
 * a privileged account, so a junction or symbolic link planted anywhere on a path would make the agent
 * read what the planter cannot, or (for a junction to a UNC path) connect outbound with its identity.
 * Every directory and every file is therefore opened relative to its volume root in ONE kernel name
 * resolution that refuses a reparse point at any component (yuzu::win::open_dir_no_reparse and
 * open_file_no_reparse, agents/shared/win_no_reparse_open.hpp): there is no path-based fallback and no
 * check-then-open window, and a directory swapped for a junction after it was listed is refused when it
 * is listed itself. An entry whose own attributes carry FILE_ATTRIBUTE_REPARSE_POINT is typed `link`
 * (counted by the walk) and never opened, whatever kind of reparse point it is. A file is read through
 * the handle that was opened and checked, never by path again.
 *
 * VOLUMES. Only DRIVE_FIXED volumes are walked: a root on a mapped network drive, a removable or
 * optical drive, or a drive whose type cannot be told is dropped and counted (roots_network_skipped).
 * Nothing below a root can leave its volume, because a volume mount point is a reparse point.
 *
 * RESIDUALS, stated plainly:
 *  - NtCreateFile, GetFileInformationByHandleEx and ReadFile carry no deadline of their own. The 45 s
 *    wall budget in WalkLimits is checked between directories and between files; it is NOT a hard
 *    bound on one call, and a dead fixed volume can park a call, as it can for the runtimes plugin's
 *    read of the same primitive.
 *  - A file the OS stores behind a reparse point (a cloud placeholder, a file compressed with the
 *    Windows Overlay Filter) is counted as a link and not read: the leg never opens a reparse point to
 *    find out what it is.
 *  - A name a Win32 path cannot spell (a segment ending in '.' or ' ') is refused by the no-reparse
 *    open, so such a directory reads as unreadable and such a file as changed under the scan, never as
 *    absent.
 *  - last-write time is compared at 100 ns resolution on the same handle, but a writer that rewrites
 *    a file and restores its size and time cannot be told from no change (the POSIX leg's residual).
 *  - The directory listing reports no directory identity (ListResult::dev and file_id stay 0): the
 *    component walk does not read it.
 */
#include "component_legs_win.hpp"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <shlobj.h> // SHGetKnownFolderPath, FOLDERID_ProgramFilesX64 / X86

#include <win_no_reparse_open.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace yuzu::component_inventory {

namespace {

// The pure layer states these Windows constants and the record layout; the SDK is the authority.
static_assert(sizeof(wchar_t) == sizeof(char16_t), "UTF-16 units are copied between wchar_t and char16_t");
static_assert(kAttrDirectory == FILE_ATTRIBUTE_DIRECTORY);
static_assert(kAttrDevice == FILE_ATTRIBUTE_DEVICE);
static_assert(kAttrReparsePoint == FILE_ATTRIBUTE_REPARSE_POINT);
static_assert(kDirInfoNextEntryOffset == offsetof(FILE_ID_BOTH_DIR_INFO, NextEntryOffset));
static_assert(kDirInfoFileAttributes == offsetof(FILE_ID_BOTH_DIR_INFO, FileAttributes));
static_assert(kDirInfoFileNameLength == offsetof(FILE_ID_BOTH_DIR_INFO, FileNameLength));
static_assert(kDirInfoFileId == offsetof(FILE_ID_BOTH_DIR_INFO, FileId));
static_assert(kDirInfoFileName == offsetof(FILE_ID_BOTH_DIR_INFO, FileName));

constexpr std::size_t kBatchBytes = 64u * 1024; // one GetFileInformationByHandleEx answer

[[nodiscard]] std::wstring to_wstring(const std::u16string& s) {
    return std::wstring(s.begin(), s.end());
}

[[nodiscard]] std::optional<std::string> known_folder_wtf8(const KNOWNFOLDERID& id) {
    PWSTR raw = nullptr;
    const HRESULT hr = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &raw);
    // CoTaskMemFree is the required deallocator, whether or not the call succeeded.
    const std::unique_ptr<std::remove_pointer_t<PWSTR>, decltype(&::CoTaskMemFree)> owned(raw, &::CoTaskMemFree);
    if (FAILED(hr) || raw == nullptr)
        return std::nullopt;
    const std::wstring_view w{raw};
    return wtf8_from_utf16(std::u16string(w.begin(), w.end()));
}

[[nodiscard]] bool is_fixed_drive(char drive) {
    const wchar_t root[] = {static_cast<wchar_t>(drive), L':', L'\\', L'\0'};
    return GetDriveTypeW(root) == DRIVE_FIXED;
}

/// What a handle says about its file right now: the pair unchanged() compares, and the attributes the
/// open checks.
struct Stamp {
    std::uint64_t size{0};
    std::uint64_t last_write{0}; // FILETIME ticks
    DWORD attributes{0};
};

[[nodiscard]] std::optional<Stamp> stamp_of(HANDLE h) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(h, &info))
        return std::nullopt;
    Stamp s;
    s.size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    s.last_write = (static_cast<std::uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) |
                   info.ftLastWriteTime.dwLowDateTime;
    s.attributes = info.dwFileAttributes;
    return s;
}

[[nodiscard]] ListResult list_directory(const std::string& dir, std::size_t cap) {
    if (const auto wide = native_path_from_walk(dir)) {
        const auto opened = yuzu::win::open_dir_no_reparse(to_wstring(*wide));
        if (opened.status == yuzu::win::NoReparseOpen::ok) {
            const HANDLE h = opened.file.get();
            std::vector<std::uint64_t> buffer(kBatchBytes / sizeof(std::uint64_t)); // 8-byte aligned records
            bool restart = true;
            return list_from_batches(
                [&]() -> std::optional<std::span<const std::byte>> {
                    const auto cls = restart ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo;
                    restart = false;
                    if (GetFileInformationByHandleEx(h, cls, buffer.data(), static_cast<DWORD>(kBatchBytes)))
                        return std::span<const std::byte>{reinterpret_cast<const std::byte*>(buffer.data()),
                                                          kBatchBytes};
                    if (GetLastError() == ERROR_NO_MORE_FILES)
                        return std::span<const std::byte>{}; // the end of the directory
                    return std::nullopt;
                },
                cap);
        }
    }
    ListResult out;
    out.error = true; // not opened: missing, a reparse point on the way, refused, or a name it cannot spell
    return out;
}

[[nodiscard]] std::optional<FileView> open_regular_file(const std::string& path) {
    const auto wide = native_path_from_walk(path);
    if (!wide)
        return std::nullopt;
    auto opened = yuzu::win::open_file_no_reparse(to_wstring(*wide));
    if (opened.status != yuzu::win::NoReparseOpen::ok)
        return std::nullopt;
    const auto held = std::make_shared<yuzu::win::NoReparseHandle>(std::move(opened.file));
    const HANDLE h = held->get();

    // The open refuses a directory and a reparse point on the way; a leaf reparse point is opened as
    // itself, so its attributes are checked here, and a device handle fails the disk-type check.
    const auto first = stamp_of(h);
    if (!first || (first->attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0 ||
        GetFileType(h) != FILE_TYPE_DISK)
        return std::nullopt;

    FileView v;
    v.size = first->size;
    v.mtime = unix_seconds_from_filetime(first->last_write);
    v.read_at = [held](std::uint64_t offset, std::size_t len) {
        return read_range(offset, len,
                          [h = held->get()](std::uint64_t at, char* buf, std::size_t n) -> std::optional<std::size_t> {
                              OVERLAPPED where{};
                              where.Offset = static_cast<DWORD>(at & 0xFFFFFFFFu);
                              where.OffsetHigh = static_cast<DWORD>(at >> 32);
                              DWORD got = 0;
                              if (ReadFile(h, buf, static_cast<DWORD>(n), &got, &where))
                                  return static_cast<std::size_t>(got);
                              if (GetLastError() == ERROR_HANDLE_EOF)
                                  return std::size_t{0};
                              return std::nullopt;
                          });
    };
    v.unchanged = [held, size = first->size, last_write = first->last_write] {
        const auto now = stamp_of(held->get());
        return now && now->size == size && now->last_write == last_write;
    };
    return v;
}

} // namespace

Targets scan_targets() {
    // The rule (a failed lookup walks nothing and says so) is windows_targets_from_known_folders'.
    return windows_targets_from_known_folders(known_folder_wtf8(FOLDERID_ProgramFilesX64),
                                              known_folder_wtf8(FOLDERID_ProgramFilesX86), is_fixed_drive);
}

Targets scan_native_targets() {
    return scan_targets();
}

FsOps make_fs_ops(const Targets& /*targets*/) {
    FsOps ops;
    ops.list = [](const std::string& dir, std::size_t cap) { return list_directory(dir, cap); };
    ops.open_file = [](const std::string& path) { return open_regular_file(path); };
    ops.now = [] { return std::chrono::steady_clock::now(); };
    return ops;
}

} // namespace yuzu::component_inventory

#endif // _WIN32
