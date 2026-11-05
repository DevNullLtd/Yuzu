// win_bounded_file_read.hpp -- one bounded read of a small regular file on Windows.
//
// For plugins that read a few KB of metadata from files an installer (not the
// agent) owns, where an unbounded or link-following read would be a hazard:
//   - the leaf is opened with FILE_FLAG_OPEN_REPARSE_POINT, so a symlink or
//     junction in the leaf position is opened as the LINK ITSELF and then refused
//     (attributes carry FILE_ATTRIBUTE_REPARSE_POINT), never followed;
//   - the read also refuses (as `error`) a file with more than one hard link and a file whose
//     resolved path (GetFinalPathNameByHandleW) is not the requested path, so a junction or
//     symlink in ANY parent directory, swapped in after a listing, is not followed (a refusal
//     only ever turns an answer into an `error`, never into data);
//   - a directory is refused as `error` (the leaf is opened with FILE_FLAG_BACKUP_SEMANTICS:
//     without it CreateFileW answers ERROR_ACCESS_DENIED for a directory, which would be
//     misreported as `denied`, an ACL refusal, when it is a wrong-kind path);
//   - at most min(`cap`, kMaxBoundedReadBytes) bytes are returned, by ONE ReadFile.
//     A larger file is read up to that limit and flagged `truncated` (the callers
//     parse a header-sized prefix), so the read is bounded in memory and in time
//     whatever the file size;
//   - share mode is read|write|delete, so an installer rewriting the file does
//     not make the agent's read fail with a sharing violation, and the agent's
//     handle never blocks an uninstall.
//
// No file hashing, no process, no dependency beyond windows.h. Status mapping is
// the caller-facing minimum: absent (file or path not found), denied (access
// denied), error (anything else, a refused reparse point or directory included).
//
// Windows-only by construction (#ifdef _WIN32); the header is empty elsewhere.
#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::win {

/// Hard ceiling on one read, whatever `cap` a caller passes: the single ReadFile takes
/// a DWORD, so this keeps the request far inside it.
inline constexpr std::size_t kMaxBoundedReadBytes = std::size_t{1} << 20;

enum class BoundedReadStatus { ok, absent, denied, error };

struct BoundedRead {
    BoundedReadStatus status = BoundedReadStatus::error;
    std::string bytes;      ///< the file's first min(size, cap) bytes (status ok only)
    bool truncated = false; ///< the file held more than `cap` bytes
};

/// Whether the path the kernel resolved the open handle to is the path that was asked for. The
/// final path of a DOS-volume handle carries a `\\?\` prefix; the comparison is ordinal and
/// case-insensitive, the primitive NTFS itself is defined against. Any failure answers false.
/// `requested` must be a canonical absolute drive-letter path (backslashes, no `\\?\` prefix, no
/// `.` or `..` segments, no 8.3 names, not UNC); anything else reads as a redirected parent and is
/// refused, which turns the answer into an `error`, never into data.
[[nodiscard]] inline bool handle_path_is(HANDLE h, const std::wstring& requested) {
    std::vector<wchar_t> fin(MAX_PATH);
    DWORD n = GetFinalPathNameByHandleW(h, fin.data(), static_cast<DWORD>(fin.size()),
                                        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (n >= fin.size()) {
        fin.assign(static_cast<std::size_t>(n) + 1, L'\0');
        n = GetFinalPathNameByHandleW(h, fin.data(), static_cast<DWORD>(fin.size()),
                                      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    }
    if (n == 0 || n >= fin.size()) return false;
    const std::wstring expected = L"\\\\?\\" + requested;
    return CompareStringOrdinal(expected.c_str(), static_cast<int>(expected.size()), fin.data(),
                                static_cast<int>(n), TRUE) == CSTR_EQUAL;
}

[[nodiscard]] inline BoundedRead read_file_bounded(const std::wstring& path, std::size_t cap) {
    BoundedRead out;
    if (path.empty()) return out; // an empty path would name the current directory's drive root
    const HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                 OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
                                     FILE_FLAG_BACKUP_SEMANTICS,
                                 nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
            out.status = BoundedReadStatus::absent;
        else if (err == ERROR_ACCESS_DENIED)
            out.status = BoundedReadStatus::denied;
        return out;
    }
    struct Closer {
        HANDLE h;
        ~Closer() { CloseHandle(h); }
    } closer{h};

    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(h, &info)) return out;
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0)
        return out; // refused: status stays `error`
    if (info.nNumberOfLinks > 1 || !handle_path_is(h, path))
        return out; // refused: a hard link, or a parent redirected by a junction or symlink
    const std::uint64_t size =
        (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    const std::size_t limit = (std::min)(cap, kMaxBoundedReadBytes);
    const std::size_t want = static_cast<std::size_t>((std::min)(size, static_cast<std::uint64_t>(limit)));
    out.truncated = size > limit;
    out.bytes.resize(want);
    DWORD n = 0;
    if (!ReadFile(h, out.bytes.data(), static_cast<DWORD>(want), &n, nullptr)) {
        out.bytes.clear();
        return out; // status stays `error`
    }
    out.bytes.resize(n); // the file may have shrunk under us: keep what was read
    out.status = BoundedReadStatus::ok;
    return out;
}

} // namespace yuzu::win

#endif // _WIN32
