// win_no_reparse_open.hpp -- open ONE local-drive file with no reparse point followed anywhere
// below the drive root, in a single kernel name resolution.
//
// WHY. A path-resolving open (CreateFileW on `X:\a\b\file`) follows a reparse point in any
// ancestor directory, and a separate attribute check of each ancestor first leaves a window in
// which a writer of a user-writable ancestor can swap a junction or symlink in (for a junction
// to a UNC path, the open would then connect outbound with the caller's identity). This header
// closes the window instead of narrowing it.
//
// MECHANISM (binding; the shape of agents/core/src/confined_fs_win.cpp and of echo's
// open_local_image_no_reparse):
//   1. The ONE path-resolving open is `CreateFileW(L"X:\\")` on the volume root. A volume root is
//      never an NTFS reparse point; the handle is checked to be a directory and not a reparse point.
//   2. `NtCreateFile` with OBJECT_ATTRIBUTES.RootDirectory = that handle and ObjectName = the
//      relative remainder, with OBJ_DONT_REPARSE. The kernel resolves every component below the
//      root inside that one call and answers STATUS_REPARSE_POINT_ENCOUNTERED the moment any
//      component is a reparse point, before it is followed, so there is no user-mode window and no
//      outbound connection. The root is opened as a handle first because `\??\X:` is itself an
//      object-manager symbolic link that OBJ_DONT_REPARSE would refuse.
//   3. FILE_OPEN_REPARSE_POINT also opens a leaf reparse point as itself (never its target); the
//      caller's by-handle checks refuse it.
//
// FAIL CLOSED. Never a path-based fallback: a missing `NtCreateFile` symbol, a build that rejects
// OBJ_DONT_REPARSE (STATUS_INVALID_PARAMETER), or any other failure is a refusal.
// `drive_relative_name` refuses every spelling `NtCreateFile` would resolve differently from
// CreateFileW (see below), so such a name reads as refused, never as a false "absent".
//
// STATUS MAPPING: ok (handle owned), absent (object name or path not found), unsupported (no
// NtCreateFile, or STATUS_INVALID_PARAMETER), refused (everything else: a reparse point
// encountered, access denied, a bad name, a root that cannot be verified).
//
// The header never logs (agents/shared headers do not pull spdlog into consumers); a consumer
// that wants the `unsupported` cause in its log reads the status.
//
// The Windows body is `#ifdef _WIN32`; `drive_relative_name` is pure and above the guard so every
// OS tests it.
#pragma once

#include <cstddef>
#include <optional>
#include <string>

namespace yuzu::win {

/// `X:\a\b\file` (or `X:/a/b/file`) -> `a\b\file`. Pure and lexical. nullopt (refuse) for anything
/// the NT open would treat differently from CreateFileW: a name that is not `<drive letter>:` plus a
/// separator (a UNC or relative name, a bare root), an empty segment, a `.` or `..` segment, a
/// component ending in '.' or ' ' (the Win32 layer strips those, the NT open does not), an
/// embedded NUL.
[[nodiscard]] inline std::optional<std::wstring> drive_relative_name(const std::wstring& path) {
    if (path.size() < 4 || path[1] != L':' || (path[2] != L'\\' && path[2] != L'/'))
        return std::nullopt;
    const wchar_t drive = path[0];
    if (!((drive >= L'A' && drive <= L'Z') || (drive >= L'a' && drive <= L'z')))
        return std::nullopt;
    std::wstring out;
    out.reserve(path.size() - 3);
    std::size_t start = 3;
    while (true) {
        const std::size_t sep = path.find_first_of(L"\\/", start);
        const std::wstring seg =
            path.substr(start, sep == std::wstring::npos ? std::wstring::npos : sep - start);
        if (seg.empty() || seg == L"." || seg == L".." || seg.back() == L'.' ||
            seg.back() == L' ' || seg.find(L'\0') != std::wstring::npos)
            return std::nullopt;
        if (!out.empty())
            out += L'\\';
        out += seg;
        if (sep == std::wstring::npos)
            break;
        start = sep + 1;
    }
    return out;
}

} // namespace yuzu::win

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <winternl.h> // UNICODE_STRING, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, NTSTATUS (after windows.h)

#include <limits>

namespace yuzu::win {

/// Owns one HANDLE; closed in the destructor. Move-only.
class NoReparseHandle {
public:
    NoReparseHandle() = default;
    explicit NoReparseHandle(HANDLE h) noexcept : h_(h) {}
    NoReparseHandle(const NoReparseHandle&) = delete;
    NoReparseHandle& operator=(const NoReparseHandle&) = delete;
    NoReparseHandle(NoReparseHandle&& o) noexcept : h_(o.h_) { o.h_ = INVALID_HANDLE_VALUE; }
    NoReparseHandle& operator=(NoReparseHandle&& o) noexcept {
        if (this != &o) {
            reset();
            h_ = o.h_;
            o.h_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    ~NoReparseHandle() { reset(); }
    [[nodiscard]] HANDLE get() const noexcept { return h_; }

private:
    void reset() noexcept {
        if (h_ != INVALID_HANDLE_VALUE && h_ != nullptr)
            CloseHandle(h_);
        h_ = INVALID_HANDLE_VALUE;
    }
    HANDLE h_{INVALID_HANDLE_VALUE};
};

enum class NoReparseOpen { ok, absent, refused, unsupported };

struct NoReparseOpenResult {
    NoReparseOpen status{NoReparseOpen::refused};
    NoReparseHandle file; ///< valid only when status == ok
};

namespace no_reparse_detail {

using NtCreateFileFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                         PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

// Resolved once (thread-safe init). null = the module or symbol is missing.
inline NtCreateFileFn resolve_ntcreatefile() {
    static const NtCreateFileFn resolved = []() -> NtCreateFileFn {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
            return nullptr;
        return reinterpret_cast<NtCreateFileFn>(
            reinterpret_cast<void*>(GetProcAddress(ntdll, "NtCreateFile")));
    }();
    return resolved;
}

// Local NT values: <winternl.h> does not export them reliably and <ntstatus.h> collides with
// <winnt.h>'s STATUS_* macros (confined_fs_win.cpp banner).
constexpr ULONG kObjCaseInsensitive = 0x00000040UL;
constexpr ULONG kObjDontReparse = 0x00001000UL;
constexpr ULONG kFileOpen = 0x00000001UL;
constexpr ULONG kFileNonDirectoryFile = 0x00000040UL;
constexpr ULONG kFileOpenReparsePoint = 0x00200000UL;
constexpr ULONG kFileSynchronousIoNonalert = 0x00000020UL;
constexpr DWORD kFileTraverse = 0x00000020UL;
constexpr NTSTATUS kStatusObjectNameNotFound = static_cast<NTSTATUS>(0xC0000034L);
constexpr NTSTATUS kStatusObjectPathNotFound = static_cast<NTSTATUS>(0xC000003AL);
constexpr NTSTATUS kStatusInvalidParameter = static_cast<NTSTATUS>(0xC000000DL);

/// Open `X:\` as a verified directory handle (not a reparse point). The traverse right is asked
/// for because NT relative-name resolution traverse-checks the root handle, then retried once
/// without it for a root whose ACL grants listing but not traverse (confined_fs_win.cpp open_root).
inline NoReparseHandle open_volume_root(wchar_t drive_letter) {
    const wchar_t root[] = {drive_letter, L':', L'\\', L'\0'};
    HANDLE raw = CreateFileW(root, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | kFileTraverse,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                             OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (raw == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED) {
        raw = CreateFileW(root, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                          OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                          nullptr);
    }
    NoReparseHandle owned(raw); // owned from this statement on
    if (owned.get() == INVALID_HANDLE_VALUE)
        return {};
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(owned.get(), &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        return {};
    return owned;
}

} // namespace no_reparse_detail

/// Open `path` (`X:\...` or `X:/...`) for reading with no reparse point followed below the drive
/// root. See the file banner for the mechanism and the status mapping.
[[nodiscard]] inline NoReparseOpenResult open_file_no_reparse(const std::wstring& path) {
    using namespace no_reparse_detail;
    NoReparseOpenResult result;

    const auto relative = drive_relative_name(path);
    if (!relative)
        return result; // refused: a name the NT open would resolve differently

    const NtCreateFileFn nt_create_file = resolve_ntcreatefile();
    if (nt_create_file == nullptr) {
        result.status = NoReparseOpen::unsupported;
        return result;
    }

    // UNICODE_STRING::Length is a USHORT byte count.
    const std::size_t bytes = relative->size() * sizeof(wchar_t);
    if (bytes > (std::numeric_limits<USHORT>::max)())
        return result;

    const NoReparseHandle root = open_volume_root(path[0]);
    if (root.get() == INVALID_HANDLE_VALUE)
        return result;

    UNICODE_STRING name{};
    name.Length = static_cast<USHORT>(bytes);
    name.MaximumLength = name.Length;
    // const_cast proof (confined_fs_win.cpp make_unicode_string): as OBJECT_ATTRIBUTES::ObjectName
    // the Buffer is an INPUT NtCreateFile never writes through; it BORROWS `*relative`, a local that
    // outlives the call below.
    name.Buffer = const_cast<PWSTR>(relative->c_str());

    OBJECT_ATTRIBUTES attrs{};
    attrs.Length = sizeof(attrs);
    attrs.RootDirectory = root.get();
    attrs.ObjectName = &name;
    attrs.Attributes = kObjCaseInsensitive | kObjDontReparse;

    HANDLE raw = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK iosb{};
    const NTSTATUS status = nt_create_file(
        &raw, FILE_GENERIC_READ, &attrs, &iosb, /*AllocationSize=*/nullptr, /*FileAttributes=*/0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, kFileOpen,
        kFileNonDirectoryFile | kFileSynchronousIoNonalert | kFileOpenReparsePoint,
        /*EaBuffer=*/nullptr, /*EaLength=*/0);
    if (status >= 0) {
        result.file = NoReparseHandle(raw); // owned at the statement it is produced
        result.status = NoReparseOpen::ok;
    } else if (status == kStatusObjectNameNotFound || status == kStatusObjectPathNotFound) {
        result.status = NoReparseOpen::absent;
    } else if (status == kStatusInvalidParameter) {
        result.status = NoReparseOpen::unsupported;
    } // else refused (STATUS_REPARSE_POINT_ENCOUNTERED, access denied, ...)
    return result;
}

} // namespace yuzu::win

#endif // _WIN32
