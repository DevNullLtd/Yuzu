// win_bounded_file_read.hpp -- one bounded read of a small regular file on Windows.
//
// For plugins that read a few KB of metadata from files an installer (not the
// agent) owns, where an unbounded or link-following read would be a hazard:
//   - the leaf is opened with FILE_FLAG_OPEN_REPARSE_POINT, so a symlink or
//     junction in the leaf position is opened as the LINK ITSELF and then refused
//     (attributes carry FILE_ATTRIBUTE_REPARSE_POINT), never followed; parent
//     directories are trusted (the callers read machine-wide, admin-writable
//     trees such as C:\ProgramData);
//   - a directory is refused;
//   - at most `cap` bytes are returned. A larger file is read up to the cap and
//     flagged `truncated` (the callers parse a header-sized prefix), so the read
//     is bounded in memory and in time whatever the file size;
//   - share mode is read|write|delete, so an installer rewriting the file does
//     not make the agent's read fail with a sharing violation, and the agent's
//     handle never blocks an uninstall.
//
// No file hashing, no process, no dependency beyond windows.h. Status mapping is
// the caller-facing minimum: absent (file or path not found), denied (access
// denied), refused (reparse point or directory), error (anything else).
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

namespace yuzu::win {

enum class BoundedReadStatus { ok, absent, denied, refused, error };

struct BoundedRead {
    BoundedReadStatus status = BoundedReadStatus::error;
    std::string bytes;      ///< the file's first min(size, cap) bytes (status ok only)
    bool truncated = false; ///< the file held more than `cap` bytes
};

[[nodiscard]] inline BoundedRead read_file_bounded(const std::wstring& path, std::size_t cap) {
    BoundedRead out;
    if (path.empty()) return out; // an empty path would name the current directory's drive root
    const HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                 OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
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
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        out.status = BoundedReadStatus::refused;
        return out;
    }
    const std::uint64_t size =
        (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    const std::size_t want = static_cast<std::size_t>((std::min)(size, static_cast<std::uint64_t>(cap)));
    out.truncated = size > cap;
    out.bytes.resize(want);
    std::size_t got = 0;
    while (got < want) {
        const DWORD chunk = static_cast<DWORD>((std::min)(want - got, std::size_t{1} << 20));
        DWORD n = 0;
        if (!ReadFile(h, out.bytes.data() + got, chunk, &n, nullptr)) {
            out.bytes.clear();
            return out; // status stays `error`
        }
        if (n == 0) break; // the file shrank under us: keep what was read
        got += n;
    }
    out.bytes.resize(got);
    out.status = BoundedReadStatus::ok;
    return out;
}

} // namespace yuzu::win

#endif // _WIN32
