// win_junction_test_support.hpp -- a privilege-free NTFS junction builder shared by the Windows
// test TUs (test_confined_fs_win.cpp, test_runtimes_win_walk.cpp). Windows only; empty elsewhere.
// Lifted out of test_confined_fs_win.cpp so both TUs share one copy.
#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// AFTER <windows.h>: <winioctl.h> (FSCTL_SET_REPARSE_POINT) depends on the base Windows types.
#include <winioctl.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace yuzu::test {

// Builds a junction (NTFS mount point) at `link` pointing at `target`,
// without administrator privilege. `link` must not already exist.
// Hand-builds the IO_REPARSE_TAG_MOUNT_POINT data buffer -- REPARSE_DATA_BUFFER
// is not declared by the public Windows SDK, only by the (kernel-mode) WDK.
inline bool create_junction(const std::filesystem::path& link, const std::filesystem::path& target) {
    if (!CreateDirectoryW(link.c_str(), nullptr))
        return false;

    const HANDLE raw =
        CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (raw == INVALID_HANDLE_VALUE)
        return false;
    struct Owned {
        HANDLE h;
        ~Owned() { CloseHandle(h); }
    } handle{raw};

    // Mount-point substitute name is an NT device path ("\??\<absolute>");
    // the print name is the plain absolute path shown to Explorer/dir.
    const std::wstring substitute = L"\\??\\" + std::filesystem::absolute(target).wstring();
    const std::wstring print_name = std::filesystem::absolute(target).wstring();

    const std::size_t sub_bytes = (substitute.size() + 1) * sizeof(wchar_t);
    const std::size_t print_bytes = (print_name.size() + 1) * sizeof(wchar_t);
    constexpr std::size_t kFixedHeaderSize = 8; // ReparseTag(4) + ReparseDataLength(2) + Reserved(2)
    constexpr std::size_t kMountFieldsSize = 8; // 4 USHORTs: sub/print offset+length

    std::vector<std::byte> buf(kFixedHeaderSize + kMountFieldsSize + sub_bytes + print_bytes);
    const auto put16 = [&](std::size_t off, std::uint16_t v) {
        std::memcpy(buf.data() + off, &v, sizeof(v));
    };
    const auto put32 = [&](std::size_t off, std::uint32_t v) {
        std::memcpy(buf.data() + off, &v, sizeof(v));
    };

    put32(0, IO_REPARSE_TAG_MOUNT_POINT);
    put16(4, static_cast<std::uint16_t>(kMountFieldsSize + sub_bytes + print_bytes));
    put16(6, 0); // Reserved
    put16(8, 0); // SubstituteNameOffset
    put16(10, static_cast<std::uint16_t>(sub_bytes - sizeof(wchar_t)));
    put16(12, static_cast<std::uint16_t>(sub_bytes)); // PrintNameOffset
    put16(14, static_cast<std::uint16_t>(print_bytes - sizeof(wchar_t)));
    std::memcpy(buf.data() + kFixedHeaderSize + kMountFieldsSize, substitute.c_str(), sub_bytes);
    std::memcpy(buf.data() + kFixedHeaderSize + kMountFieldsSize + sub_bytes, print_name.c_str(),
                print_bytes);

    DWORD bytes_returned = 0;
    return DeviceIoControl(handle.h, FSCTL_SET_REPARSE_POINT, buf.data(),
                            static_cast<DWORD>(buf.size()), nullptr, 0, &bytes_returned,
                            nullptr) != 0;
}

// RemoveDirectory on a reparse-point directory removes the reparse point
// itself, never the target -- so this never touches victim content.
struct JunctionCleanup {
    std::filesystem::path path;
    ~JunctionCleanup() { RemoveDirectoryW(path.c_str()); }
};

} // namespace yuzu::test

#endif // _WIN32
