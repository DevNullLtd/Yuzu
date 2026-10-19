#pragma once

/**
 * win_hive_file_probe.hpp -- the OS side of the offline-hive file guard seam
 * (win_hive_file_guard.hpp).
 *
 * Win32HiveFileProbe is the Win32 sequence behind each HiveFileProbe question, nothing more: every
 * deciding fact comes from a HANDLE opened for that step (FILE_FLAG_OPEN_REPARSE_POINT, so a
 * link is seen, never followed), except the drive type (GetDriveTypeW) and the sidecar listing, which
 * is re-read from the sidecar's own handle. The guard's logic is unit-tested over a fake probe on every
 * host; this header is Windows-only (empty elsewhere) and is driven through the real shell by
 * tests/unit/test_privacy_permissions_win_internals.cpp.
 *
 * UniqueHandle / FindHandle / LocalFreeGuard are the three RAII owners the probe needs;
 * final_path_matches is the ordinal case-insensitive path comparison.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <win_hive_file_guard.hpp>
#include <win_str.hpp>

namespace yuzu::win {

static_assert(kHiveErrorFileNotFound == ERROR_FILE_NOT_FOUND);
static_assert(kDriveFixed == DRIVE_FIXED);
static_assert(kFileAttributeDirectory == FILE_ATTRIBUTE_DIRECTORY);
static_assert(kFileAttributeReparsePoint == FILE_ATTRIBUTE_REPARSE_POINT);
static_assert(kFileAttributeOffline == FILE_ATTRIBUTE_OFFLINE);
static_assert(kFileAttributeRecallOnOpen == FILE_ATTRIBUTE_RECALL_ON_OPEN);
static_assert(kFileAttributeRecallOnDataAccess == FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS);
static_assert(sizeof(FileId::file_id) == sizeof(FILE_ID_128));

// ── offline hive-file guard ───────────────────────────────────────────

/// Owns a CreateFile-family handle: INVALID_HANDLE_VALUE is the empty sentinel (do not wrap an API
/// that fails with NULL), and the owner is neither copyable nor movable.
struct UniqueHandle {
    HANDLE h = INVALID_HANDLE_VALUE;
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE x) noexcept : h(x) {}
    ~UniqueHandle() {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    [[nodiscard]] bool ok() const noexcept { return h != INVALID_HANDLE_VALUE; }
};

/// Owns a FindFirstFileExW search handle: FindClose (not CloseHandle) on every exit path.
struct FindHandle {
    HANDLE h;
    explicit FindHandle(HANDLE x) noexcept : h(x) {}
    ~FindHandle() {
        if (h != INVALID_HANDLE_VALUE) FindClose(h);
    }
    FindHandle(const FindHandle&) = delete;
    FindHandle& operator=(const FindHandle&) = delete;
    [[nodiscard]] bool ok() const noexcept { return h != INVALID_HANDLE_VALUE; }
};

/// Owns an allocation the OS handed back to be released with LocalFree (a security descriptor from
/// GetSecurityInfo, a string from ConvertSidToStringSidW); null is a no-op.
struct LocalFreeGuard {
    HLOCAL p;
    explicit LocalFreeGuard(HLOCAL x) noexcept : p(x) {}
    ~LocalFreeGuard() {
        if (p) LocalFree(p);
    }
    LocalFreeGuard(const LocalFreeGuard&) = delete;
    LocalFreeGuard& operator=(const LocalFreeGuard&) = delete;
};

/// Whether the path the kernel resolved a handle to (`final_path`, GetFinalPathNameByHandleW with
/// VOLUME_NAME_DOS) is the path that was asked for (`requested`, which gets the `\\?\` prefix a
/// DOS-volume final path carries). CompareStringOrdinal is the ordinal case-insensitive primitive
/// the file system itself is defined against, so a non-ASCII case-only difference is the same path.
/// A failed comparison (0) is "not equal": the safe side. Runs of `\` in `requested` collapse to
/// one first (a ProfileImagePath with a trailing separator yields `..\\NTUSER.DAT`; the kernel's
/// final path carries one): `requested` is a drive-letter path here (UNC was refused upstream), so
/// no `\\?\` or UNC prefix can be damaged. Only separator runs: never `.`/`..` or 8.3 names.
[[nodiscard]] inline bool final_path_matches(const std::wstring& requested,
                                             const std::wstring& final_path) {
    std::wstring collapsed = requested;
    collapsed.erase(std::unique(collapsed.begin(), collapsed.end(),
                                [](wchar_t a, wchar_t b) { return a == L'\\' && b == a; }),
                    collapsed.end());
    const std::wstring expected = L"\\\\?\\" + collapsed;
    return CompareStringOrdinal(expected.c_str(), static_cast<int>(expected.size()),
                                final_path.c_str(), static_cast<int>(final_path.size()),
                                TRUE) == CSTR_EQUAL;
}

/// A failing call's code as the seam reports it: never 0 (success), even if the call left no
/// last-error behind.
[[nodiscard]] inline long failure_code(DWORD gle) noexcept {
    return gle != 0 ? static_cast<long>(gle) : static_cast<long>(ERROR_GEN_FAILURE);
}

/// The OS side of the hive-file seam (win_hive_file_guard.hpp): each method is the
/// Win32 sequence for one question the guard asks, nothing more. The unit tests drive HiveFileGuard
/// through a fake probe; the rig tests drive it through this one.
struct Win32HiveFileProbe final : HiveFileProbe {
    UniqueHandle open_attr(const std::wstring& path, DWORD access) {
        ++opens;
        return UniqueHandle{CreateFileW(path.c_str(), access,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr, OPEN_EXISTING,
                                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                                        nullptr)};
    }

    std::uint32_t drive_type(const std::wstring& root) override {
        return GetDriveTypeW(root.c_str());
    }

    long path_attributes(const std::wstring& path, std::uint32_t& attrs) override {
        const UniqueHandle dir = open_attr(path, FILE_READ_ATTRIBUTES);
        if (!dir.ok()) return failure_code(GetLastError());
        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (!GetFileInformationByHandleEx(dir.h, FileAttributeTagInfo, &tag, sizeof tag))
            return failure_code(GetLastError());
        attrs = tag.FileAttributes;
        return 0;
    }

    long leaf_facts(const std::wstring& path, LeafFacts& out) override {
        const UniqueHandle leaf = open_attr(path, FILE_READ_ATTRIBUTES | READ_CONTROL);
        if (!leaf.ok()) return failure_code(GetLastError());

        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (!GetFileInformationByHandleEx(leaf.h, FileAttributeTagInfo, &tag, sizeof tag))
            return failure_code(GetLastError());
        out.attributes = tag.FileAttributes;
        out.is_disk_file = GetFileType(leaf.h) == FILE_TYPE_DISK;

        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(leaf.h, &info)) return failure_code(GetLastError());
        out.size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;

        PSID owner = nullptr;
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (const DWORD rc = GetSecurityInfo(leaf.h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                             &owner, nullptr, nullptr, nullptr, &sd);
            rc != ERROR_SUCCESS)
            return failure_code(rc);
        const LocalFreeGuard sd_guard{sd}; // `owner` points into it: alive until this scope ends
        LPWSTR sid_str = nullptr;
        const BOOL converted = ConvertSidToStringSidW(owner, &sid_str);
        const LocalFreeGuard sid_guard{sid_str};
        // The return value is evaluated before the guards run, so GetLastError is read first.
        if (!converted) return failure_code(GetLastError());
        out.owner_sid = from_wide(sid_str);

        std::wstring fin(MAX_PATH, L'\0');
        DWORD n = GetFinalPathNameByHandleW(leaf.h, fin.data(), static_cast<DWORD>(fin.size()),
                                            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (n >= fin.size()) {
            fin.assign(static_cast<std::size_t>(n) + 1, L'\0');
            n = GetFinalPathNameByHandleW(leaf.h, fin.data(), static_cast<DWORD>(fin.size()),
                                          FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        }
        // n >= size is a sizing result (the path grew between the two calls), not an API failure:
        // GetLastError is stale then, so name the documented "buffer still too small" code.
        if (n == 0 || n >= fin.size())
            return n == 0 ? failure_code(GetLastError()) : static_cast<long>(ERROR_MORE_DATA);
        fin.resize(n);
        out.final_path_matches = final_path_matches(path, fin);

        FILE_ID_INFO id{};
        if (!GetFileInformationByHandleEx(leaf.h, FileIdInfo, &id, sizeof id))
            return failure_code(GetLastError());
        out.id.volume_serial = id.VolumeSerialNumber;
        std::memcpy(out.id.file_id.data(), &id.FileId, sizeof id.FileId);
        return 0;
    }

    long list_sidecars(const std::wstring& dir, const std::wstring& leaf, std::size_t limit,
                       std::vector<SidecarEntry>& out) override {
        const std::wstring base = dir.ends_with(L'\\') ? dir : dir + L"\\";
        WIN32_FIND_DATAW fd{};
        const FindHandle find{FindFirstFileExW((base + leaf + L"*").c_str(), FindExInfoBasic, &fd,
                                               FindExSearchNameMatch, nullptr, 0)};
        if (!find.ok()) {
            const DWORD rc = GetLastError();
            return (rc == ERROR_FILE_NOT_FOUND || rc == ERROR_NO_MORE_FILES) ? 0 : failure_code(rc);
        }
        do {
            const std::wstring name = fd.cFileName;
            if (name == L"." || name == L".." ||
                CompareStringOrdinal(name.c_str(), static_cast<int>(name.size()), leaf.c_str(),
                                     static_cast<int>(leaf.size()), TRUE) == CSTR_EQUAL)
                continue;
            out.push_back({name, fd.dwFileAttributes});
            if (out.size() >= limit) return 0;
        } while (FindNextFileW(find.h, &fd));
        const DWORD rc = GetLastError();
        return rc == ERROR_NO_MORE_FILES ? 0 : failure_code(rc);
    }

    long sidecar_facts(const std::wstring& path, std::uint32_t& links,
                       std::uint32_t& attrs) override {
        const UniqueHandle h = open_attr(path, FILE_READ_ATTRIBUTES);
        if (!h.ok()) return failure_code(GetLastError());
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(h.h, &info)) return failure_code(GetLastError());
        links = info.nNumberOfLinks;
        attrs = info.dwFileAttributes;
        return 0;
    }
};

} // namespace yuzu::win

#endif // _WIN32
