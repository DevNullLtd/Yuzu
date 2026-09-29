/**
 * confined_fs_win.cpp -- Windows shell for confined recursive delete
 * (agents/core/include/yuzu/agent/confined_fs.hpp's Windows-branch
 * declarations). Entire TU is `#ifdef _WIN32`; compiles as an empty
 * translation unit on every other platform.
 *
 * ── The RootDirectory-relative mechanism (binding) ──────────────────────────
 * After `open_root`, EVERY open in this file goes through `nt_open_relative`,
 * which calls `NtCreateFile` with `OBJECT_ATTRIBUTES.RootDirectory` set to an
 * already-open, already-verified parent HANDLE and `ObjectName` a SINGLE
 * relative path component (never a joined path string). `CreateFileW`
 * appears exactly once in this file, inside `open_root`, which is the only
 * place a path string is ever resolved -- see confined_fs.hpp's header
 * banner for why re-resolving a path anywhere below the root would
 * reintroduce the TOCTOU race this whole design exists to close.
 *
 * ── ntdll resolution / fail-closed ───────────────────────────────────────────
 * `NtCreateFile` is not declared by <windows.h> (WIN32_LEAN_AND_MEAN or not)
 * -- it is resolved ONCE via `GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
 * "NtCreateFile")` behind a function-local static (thread-safe init, C++11
 * [stmt.dcl]p4). If resolution fails, or the `detail::set_ntcreatefile_for_test`
 * seam injects a null function pointer, every operation in this file returns
 * `Reason::Unsupported` and deletes NOTHING -- there is no fallback to a
 * path-based open, which would defeat the parent-handle-relative guarantee.
 *
 * ── NTSTATUS -> os_error mapping ─────────────────────────────────────────────
 * `RtlNtStatusToDosError` is also ntdll and also GetProcAddress-resolved. If
 * IT fails to resolve, the handful of STATUS_* codes this TU can actually
 * produce are mapped by hand (see `map_ntstatus_to_os_error`) using LOCAL
 * constexpr values rather than <ntstatus.h> -- <ntstatus.h>'s STATUS_* macros
 * collide (same names, different intended use) with the exception-code
 * STATUS_* constants <winnt.h> already defines, so including both in one TU
 * is a well-known landmine. Anything outside that short list surfaces as the
 * raw NTSTATUS value truncated into `os_error`; callers only ever log it, as
 * an opaque diagnostic, never branch on it.
 */

#ifdef _WIN32

#include <yuzu/agent/confined_fs.hpp>
#include <yuzu/agent/confined_fs_rules.hpp>
#include <yuzu/agent/confined_fs_walk.hpp>

#include <win_str.hpp> // yuzu::win::to_wide / from_wide (agents/shared/win_str.hpp)

#include <spdlog/spdlog.h>

#include <winternl.h> // UNICODE_STRING, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, NTSTATUS

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent::confined_fs {

namespace {

// ── NtCreateFile plumbing ───────────────────────────────────────────────────

using NtCreateFileFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                         PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG,
                                         ULONG, PVOID, ULONG);

// Test seam state (PLAN-011). Deliberately plain globals, no synchronization:
// the header contract (confined_fs.hpp detail::set_ntcreatefile_for_test) is
// single-threaded/test-only and requires the caller to restore before the
// test ends.
NtCreateFileFn g_test_ntcreatefile = nullptr;
bool g_test_ntcreatefile_enabled = false;

// Resolved once, thread-safe init. A null result (module or symbol missing)
// is a legitimate outcome -- callers treat it as Reason::Unsupported.
NtCreateFileFn resolve_ntcreatefile() {
    static const NtCreateFileFn resolved = []() -> NtCreateFileFn {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
            return nullptr;
        return reinterpret_cast<NtCreateFileFn>(
            reinterpret_cast<void*>(GetProcAddress(ntdll, "NtCreateFile")));
    }();
    return resolved;
}

NtCreateFileFn current_ntcreatefile() {
    return g_test_ntcreatefile_enabled ? g_test_ntcreatefile : resolve_ntcreatefile();
}

using RtlNtStatusToDosErrorFn = ULONG(NTAPI*)(NTSTATUS);

RtlNtStatusToDosErrorFn resolve_rtl_ntstatus_to_doserror() {
    static const RtlNtStatusToDosErrorFn resolved = []() -> RtlNtStatusToDosErrorFn {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
            return nullptr;
        return reinterpret_cast<RtlNtStatusToDosErrorFn>(
            reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlNtStatusToDosError")));
    }();
    return resolved;
}

// Local, distinctly-named NTSTATUS values -- NOT <ntstatus.h> (see file
// banner). Only the codes this TU's own NtCreateFile/SetFileInformationByHandle
// calls can realistically produce.
constexpr NTSTATUS kStatusObjectNameNotFound = static_cast<NTSTATUS>(0xC0000034L);
constexpr NTSTATUS kStatusObjectPathNotFound = static_cast<NTSTATUS>(0xC000003AL);
constexpr NTSTATUS kStatusAccessDenied = static_cast<NTSTATUS>(0xC0000022L);
constexpr NTSTATUS kStatusSharingViolation = static_cast<NTSTATUS>(0xC0000043L);
constexpr NTSTATUS kStatusNotADirectory = static_cast<NTSTATUS>(0xC0000103L);
constexpr NTSTATUS kStatusDirectoryNotEmpty = static_cast<NTSTATUS>(0xC0000101L);

// Local NT CreateDisposition / CreateOptions values, for the same reason as the
// kStatus* block above: <winternl.h> does not reliably export them, and today
// they are supplied ONLY by the hand-written header stand-in this TU is parsed
// against off-Windows -- verified by deleting them from the stand-in, which
// produced 9 "use of undeclared identifier" errors at exactly these call sites.
// Defining them here removes the dependency, so the first real MSVC compile
// cannot fail on their absence. Values are the documented NT constants.
constexpr ULONG kFileOpen = 0x00000001UL;                  // FILE_OPEN
constexpr ULONG kFileDirectoryFile = 0x00000001UL;         // FILE_DIRECTORY_FILE
constexpr ULONG kFileNonDirectoryFile = 0x00000040UL;      // FILE_NON_DIRECTORY_FILE
constexpr ULONG kFileOpenReparsePoint = 0x00200000UL;      // FILE_OPEN_REPARSE_POINT
constexpr ULONG kFileSynchronousIoNonalert = 0x00000020UL; // FILE_SYNCHRONOUS_IO_NONALERT
// Traverse rights on a directory handle used as OBJECT_ATTRIBUTES.RootDirectory:
// NT relative-name resolution traverse-checks the parent. On a default host
// SeChangeNotifyPrivilege (Bypass traverse checking) masks its absence, but on a
// host where that privilege is stripped every child open would fail closed and
// the primitive would delete nothing.
constexpr DWORD kFileTraverse = 0x00000020UL;              // FILE_TRAVERSE

constexpr bool nt_success(NTSTATUS status) noexcept {
    return status >= 0;
}

int map_ntstatus_to_os_error(NTSTATUS status) {
    if (const RtlNtStatusToDosErrorFn fn = resolve_rtl_ntstatus_to_doserror(); fn != nullptr)
        return static_cast<int>(fn(status));
    if (status == kStatusObjectNameNotFound || status == kStatusObjectPathNotFound)
        return ERROR_FILE_NOT_FOUND;
    if (status == kStatusAccessDenied)
        return ERROR_ACCESS_DENIED;
    if (status == kStatusSharingViolation)
        return ERROR_SHARING_VIOLATION;
    if (status == kStatusNotADirectory)
        return ERROR_DIRECTORY;
    if (status == kStatusDirectoryNotEmpty)
        return ERROR_DIR_NOT_EMPTY;
    // Undocumented fallback: the raw NTSTATUS, never branched on by a
    // caller -- diagnostic only.
    return static_cast<int>(status);
}

// ── Name validation (confined_fs.hpp InvalidName rule, PLAN-015/PLAN-007) ──


// Validates `name` BEFORE any syscall touches it and produces its wide form.
// Returns InvalidName (never calls to_wide) for a structurally-invalid name,
// or InvalidName when `to_wide` cannot translate it (win_str.hpp: untranslatable
// input yields an EMPTY wstring -- PLAN-007. An empty ObjectName with a
// RootDirectory set opens the parent itself, so this must never reach
// NtCreateFile). Returns nullopt and fills `out_wide` on success.
// NOTE on the out_wide.empty() branch below: win_str.hpp's to_wide() calls
// MultiByteToWideChar(CP_UTF8, 0, ...) -- flags=0, no MB_ERR_INVALID_CHARS --
// which Microsoft documents as lenient for CP_UTF8: malformed byte sequences
// are substituted (U+FFFD-equivalent), not rejected, so a non-empty `name`
// realistically never yields an empty `out_wide` on a real Windows host (only
// `name.empty()` does, already refused above by structurally_invalid_name).
// The check is kept anyway because it is PLAN-007's explicit contract and is
// a one-line defensive backstop against a `to_wide` behaviour change; it is
// not exercisable with a hand-crafted invalid-UTF-8 test today, which is why
// no such test exists for this specific branch (see confined_fs_win.cpp's
// other InvalidName cases, which ARE exercisable and ARE tested).
std::optional<Reason> validate_name(const std::string& name, std::wstring& out_wide) {
    if (is_invalid_component(name, /*windows_separators=*/true))
        return Reason::InvalidName;
    out_wide = yuzu::win::to_wide(name);
    if (out_wide.empty())
        return Reason::InvalidName;
    return std::nullopt;
}

// Manual UNICODE_STRING construction (no RtlInitUnicodeString): bounds the
// byte length to USHORT, refusing anything longer as InvalidName.
bool make_unicode_string(const std::wstring& wide, UNICODE_STRING& out) {
    const std::size_t byte_len = wide.size() * sizeof(wchar_t);
    if (byte_len > (std::numeric_limits<USHORT>::max)())
        return false;
    out.Length = static_cast<USHORT>(byte_len);
    out.MaximumLength = out.Length;
    // const_cast proof (docs/cpp-conventions.md requires one at a syscall
    // boundary). CONSTNESS: UNICODE_STRING::Buffer is declared PWSTR because
    // the same struct is used for kernel OUT parameters; as an
    // OBJECT_ATTRIBUTES::ObjectName it is strictly an INPUT and NtCreateFile
    // does not write through it, so casting away const cannot produce a
    // mutation of `wide`. OWNERSHIP: this borrows, it does not own -- `out`
    // holds a non-owning view into the caller's `wide`, which every call site
    // keeps alive as a local for the whole duration of the NtCreateFile call
    // (see open_dir_at/unlink_at below); `out` must never outlive it.
    // MaximumLength is set equal to Length precisely so that a kernel path
    // that did attempt to append would have zero spare capacity rather than
    // writing past the string's buffer.
    out.Buffer = const_cast<PWSTR>(wide.c_str());
    return true;
}

// ── Parent-HANDLE-relative NtCreateFile wrapper ─────────────────────────────

struct NtOpenResult {
    WinHandle handle;
    NTSTATUS status{0};
    Reason reason{Reason::None}; // None only when `handle` is valid
};

// `parent` MUST already be an open, verified directory handle (the caller's
// pinned root or a previously opened, volume-checked directory). `wide_name`
// is a SINGLE relative path component -- never a joined path.
NtOpenResult nt_open_relative(HANDLE parent, const std::wstring& wide_name,
                               ACCESS_MASK desired_access, ULONG share_access,
                               ULONG create_disposition, ULONG create_options) {
    NtOpenResult result;

    const NtCreateFileFn fn = current_ntcreatefile();
    if (fn == nullptr) {
        result.reason = Reason::Unsupported;
        return result;
    }

    UNICODE_STRING object_name{};
    if (!make_unicode_string(wide_name, object_name)) {
        result.reason = Reason::InvalidName;
        return result;
    }

    OBJECT_ATTRIBUTES attrs{};
    attrs.Length = sizeof(attrs);
    attrs.RootDirectory = parent;
    attrs.ObjectName = &object_name;
    attrs.Attributes = 0;
    attrs.SecurityDescriptor = nullptr;
    attrs.SecurityQualityOfService = nullptr;

    HANDLE raw = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK iosb{};
    const NTSTATUS status = fn(&raw, desired_access, &attrs, &iosb, /*AllocationSize=*/nullptr,
                                /*FileAttributes=*/0, share_access, create_disposition,
                                create_options, /*EaBuffer=*/nullptr, /*EaLength=*/0);
    result.status = status;
    if (!nt_success(status)) {
        result.reason = Reason::OsError;
        return result;
    }

    // Own it immediately -- no raw HANDLE survives past this statement.
    result.handle = WinHandle(raw);
    result.reason = Reason::None;
    return result;
}

} // namespace

namespace detail {

void set_ntcreatefile_for_test(void* fn, bool enable) noexcept {
    g_test_ntcreatefile = reinterpret_cast<NtCreateFileFn>(fn);
    g_test_ntcreatefile_enabled = enable;
}

} // namespace detail

std::optional<FileIdentity> capture_identity(HANDLE h) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(h, &info))
        return std::nullopt;
    return FileIdentity{
        info.dwVolumeSerialNumber,
        (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow};
}

OpenRootResult open_root(const std::filesystem::path& path) {
    OpenRootResult result;

    // An embedded NUL would be truncated by c_str(), pinning a DIFFERENT
    // directory than the caller named and confining every later operation to
    // the wrong root. Entry names are checked for this (validate_name); the
    // root path is the caller's own string and needs the same check. Sibling of
    // the identical guard in confined_fs_posix.cpp's open_root.
    if (path.native().find(L'\0') != std::wstring::npos) {
        spdlog::warn("confined_fs::open_root: refused root path containing an embedded NUL");
        result.reason = Reason::RootInvalid;
        result.os_error = 0;
        return result;
    }

    // By design, root only: this is the ONE CreateFileW in this file. Every
    // later open is parent-HANDLE-relative via nt_open_relative.
    // FILE_TRAVERSE is requested because NT relative-name resolution
    // traverse-checks the parent handle -- but requesting a right we did not
    // previously ask for can itself turn a working open into ACCESS_DENIED on a
    // root whose ACL grants List but not Traverse. Ask for it, then retry once
    // without it: a static mask cannot serve both the privilege-stripped host
    // and the restrictive-ACL root.
    HANDLE raw =
        CreateFileW(path.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | kFileTraverse,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (raw == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED) {
        raw = CreateFileW(path.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                          OPEN_EXISTING,
                          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    }
    if (raw == INVALID_HANDLE_VALUE) {
        // B004: a root that cannot be opened or identified is RootInvalid on both
        // legs -- the POSIX leg already reports it that way, and a
        // platform-dependent reason gives callers platform-dependent retry and
        // diagnostic semantics. The OS code is preserved in os_error either way.
        result.reason = Reason::RootInvalid;
        result.os_error = static_cast<int>(GetLastError());
        return result;
    }
    WinHandle owned(raw); // transient handle -- owned from this line on

    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(owned.get(), &info)) {
        result.reason = Reason::RootInvalid; // B004: parity with the POSIX leg
        result.os_error = static_cast<int>(GetLastError());
        return result;
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        result.reason = Reason::RootInvalid;
        return result;
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        result.reason = Reason::RootInvalid;
        return result;
    }

    const FileIdentity id{
        info.dwVolumeSerialNumber,
        (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow};

    result.root = ConfinedRoot{std::move(owned), id};
    result.reason = Reason::None;
    return result;
}

OpenDirResult open_dir_at(HANDLE parent, const std::string& name, const FileIdentity& root_id) {
    OpenDirResult result{};

    std::wstring wide;
    if (const auto invalid = validate_name(name, wide)) {
        result.reason = *invalid;
        return result;
    }

    NtOpenResult opened = nt_open_relative(
        parent, wide, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | kFileTraverse | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, kFileOpen,
        kFileDirectoryFile | kFileOpenReparsePoint | kFileSynchronousIoNonalert);

    if (opened.reason == Reason::Unsupported || opened.reason == Reason::InvalidName) {
        result.reason = opened.reason;
        return result;
    }
    if (opened.reason == Reason::OsError) {
        result.reason = Reason::OsError;
        result.os_error = map_ntstatus_to_os_error(opened.status);
        return result;
    }

    // opened.handle is a transient WinHandle: it closes itself on every
    // early return below (reparse / device-boundary refusal), and is moved
    // out ONLY on success.
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(opened.handle.get(), &info)) {
        result.reason = Reason::OsError;
        result.os_error = static_cast<int>(GetLastError());
        return result;
    }
    // A junction/mount-point/symlink swapped in mid-walk is opened RAW by
    // FILE_OPEN_REPARSE_POINT above and rejected here, never traversed.
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        // warn, matching the POSIX leg: this branch fires on a mid-walk junction
        // swap -- the live TOCTOU attack this primitive exists to defeat, not a
        // steady-state reparse entry (which decide_entry handles, unlogged).
        spdlog::warn("confined_fs::open_dir_at: reparse point rejected for '{}'", name);
        result.reason = Reason::ReparseRejected;
        return result;
    }
    if (info.dwVolumeSerialNumber != root_id.volume_serial) {
        spdlog::warn("confined_fs::open_dir_at: volume boundary rejected for '{}'", name);
        result.reason = Reason::DeviceBoundary;
        return result;
    }

    result.h = std::move(opened.handle);
    result.reason = Reason::None;
    return result;
}

// C003: the delete handle deliberately omits FILE_SHARE_WRITE. Measuring the
// size and then setting the delete disposition are separate steps, so admitting
// a concurrent writer would let the file grow past the charged cap between them
// -- the Windows twin of the POSIX swap this primitive already defends against.
// Without FILE_SHARE_WRITE an incompatible existing writer makes the open fail,
// which is the fail-closed outcome a blast-radius cap requires.
UnlinkOutcome unlink_at(HANDLE parent, const std::string& name, UnlinkKind kind,
                        std::uint64_t max_bytes_remaining,
                         const FileIdentity& root_id) {
    UnlinkOutcome result{EntryStatus::Failed, Reason::None, 0};

    std::wstring wide;
    if (const auto invalid = validate_name(name, wide)) {
        result.reason = *invalid;
        return result;
    }

    const ULONG type_option =
        kind == UnlinkKind::EmptyDirectory ? kFileDirectoryFile : kFileNonDirectoryFile;

    NtOpenResult opened = nt_open_relative(
        parent, wide, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE, kFileOpen,
        kFileOpenReparsePoint | kFileSynchronousIoNonalert | type_option);

    if (opened.reason == Reason::Unsupported || opened.reason == Reason::InvalidName) {
        result.reason = opened.reason;
        return result;
    }
    if (opened.reason == Reason::OsError) {
        result.reason = Reason::OsError;
        result.os_error = map_ntstatus_to_os_error(opened.status);
        return result;
    }

    // Volume-verified per PLAN-008 (unlike POSIX unlinkat, this handle is a
    // real open object -- see confined_fs.hpp's asymmetry note above
    // unlink_at's Windows overload). Transient until the delete below.
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(opened.handle.get(), &info)) {
        result.reason = Reason::OsError;
        result.os_error = static_cast<int>(GetLastError());
        return result;
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        result.reason = Reason::ReparseRejected;
        return result;
    }
    if (info.dwVolumeSerialNumber != root_id.volume_serial) {
        result.reason = Reason::DeviceBoundary;
        return result;
    }
    // Byte cap re-measured from the handle we ALREADY hold, so unlike the POSIX
    // leg (whose unlinkat is name-level) there is no residual window here: this
    // is the exact object about to be deleted. A regular file whose live size
    // exceeds the remaining budget is refused, not deleted.
    std::uint64_t live_bytes = 0;
    if (kind == UnlinkKind::File && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        live_bytes = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
        if (live_bytes > max_bytes_remaining) {
            spdlog::warn("confined_fs::unlink_at: '{}' grew past the byte cap since "
                         "enumeration -- refusing", name);
            result.status = EntryStatus::Skipped;
            result.reason = Reason::ByteCap;
            result.bytes = 0;
            return result;
        }
    }

    // updater.cpp:568's delete-by-handle mechanism, on a handle WE opened
    // parent-relative. Aggregate-initialized (never `.DeleteFile = TRUE`):
    // FILE_DISPOSITION_INFO's only field is literally named `DeleteFile`,
    // which collides with the winbase.h macro that renames that same
    // identifier to its wide-string sibling (WIN32_LEAN_AND_MEAN does not
    // suppress it) -- a member-access spelling would macro-expand to a
    // member that does not exist and fail to compile. Positional init
    // sidesteps the identifier entirely.
    FILE_DISPOSITION_INFO disposition{TRUE};
    if (!SetFileInformationByHandle(opened.handle.get(), FileDispositionInfo, &disposition,
                                     sizeof(disposition))) {
        result.reason = Reason::OsError;
        result.os_error = static_cast<int>(GetLastError());
        return result;
    }

    // opened.handle's destructor (CloseHandle) below completes the delete.
    result.status = EntryStatus::Deleted;
    result.bytes = live_bytes;
    result.reason = Reason::None;
    return result;
}

EnumerateResult enumerate_at(HANDLE dir, [[maybe_unused]] const FileIdentity& root_id,
                              const EnumBudget& budget) {
    // root_id is accepted for API symmetry with the walker's Ops contract;
    // the volume boundary is re-verified at every open_dir_at call (the
    // moment a NEW handle could straddle a swapped-in mount point), not
    // here -- `dir`'s volume cannot change between its own open and this
    // enumeration without a fresh open somewhere else.
    EnumerateResult result;

    if (budget.max_entries == 0) {
        result.reason = Reason::EntryCap;
        return result;
    }

    constexpr DWORD kBufferBytes = 64 * 1024;
    std::vector<std::byte> buffer(kBufferBytes);

    bool first_call = true;
    for (;;) {
        if (std::chrono::steady_clock::now() >= budget.deadline) {
            result.reason = Reason::WallTimeCap;
            return result;
        }

        // FileFullDirectoryRestartInfo forces enumeration to (re)start from
        // the beginning on the first call -- a directory HANDLE opened via
        // open_dir_at is fresh, but this is the documented way to guarantee
        // it regardless of any prior query state on the handle.
        const FILE_INFO_BY_HANDLE_CLASS query_class =
            first_call ? FileFullDirectoryRestartInfo : FileFullDirectoryInfo;
        first_call = false;

        if (!GetFileInformationByHandleEx(dir, query_class, buffer.data(),
                                           static_cast<DWORD>(buffer.size()))) {
            const DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_FILES)
                break; // fully enumerated
            result.reason = Reason::OsError;
            result.os_error = static_cast<int>(err);
            return result;
        }

        const std::byte* cursor = buffer.data();
        const std::byte* const buffer_end = buffer.data() + buffer.size();
        for (;;) {
            // Aliasing/alignment proof (docs/cpp-conventions.md requires one at a
        // syscall boundary): `buffer` is a std::vector<std::byte>, whose data()
        // is suitably aligned for any scalar type, and the kernel writes each
        // FILE_FULL_DIR_INFO at an 8-byte-aligned offset -- NextEntryOffset is
        // documented as 8-aligned -- so every `cursor` derived by advancing
        // through those offsets is correctly aligned for this type. The pointee
        // is read-only and owned by `buffer`, which outlives every use here.
        // BOUNDS, before the cast is dereferenced. NextEntryOffset and
        // FileNameLength are values supplied by the filesystem, and a user-mode
        // or redirected filesystem (WinFsp/Dokan/SMB) is exactly the hostile
        // source this primitive's threat model contemplates. The alignment and
        // aliasing proof below says nothing about extent, so it is checked here:
        // a header that does not fit, or a name that runs past the returned
        // bytes, is an OS error -- never a silent break, which would truncate
        // the listing while reporting a complete enumeration.
        if (cursor < buffer.data() || cursor + sizeof(FILE_FULL_DIR_INFO) > buffer_end) {
            spdlog::warn("confined_fs::enumerate_at: directory entry header out of bounds");
            result.reason = Reason::OsError;
            result.os_error = static_cast<int>(ERROR_INVALID_DATA);
            return result;
        }
        const auto* entry = reinterpret_cast<const FILE_FULL_DIR_INFO*>(cursor);
        const std::byte* const name_begin =
            cursor + offsetof(FILE_FULL_DIR_INFO, FileName);
        if (entry->FileNameLength > static_cast<ULONG>(buffer_end - name_begin)) {
            spdlog::warn("confined_fs::enumerate_at: directory entry name out of bounds");
            result.reason = Reason::OsError;
            result.os_error = static_cast<int>(ERROR_INVALID_DATA);
            return result;
        }

            const std::wstring_view wide_name(entry->FileName,
                                               entry->FileNameLength / sizeof(WCHAR));
            const bool dot_entry = wide_name == L"." || wide_name == L"..";

            if (!dot_entry) {
                if (result.entries.size() >= budget.max_entries) {
                    result.reason = Reason::EntryCap;
                    return result;
                }

                DirEntry de;
                de.name = yuzu::win::from_wide(entry->FileName, static_cast<int>(wide_name.size()));
                // Name round-trip check (PLAN-016): a name that cannot
                // survive UTF-8 (e.g. an unpaired surrogate) is flagged --
                // the walker never lets it reach match/deletion. Such names
                // are only creatable deliberately; confinement is unaffected
                // by refusing to act on one.
                de.name_invalid = (yuzu::win::to_wide(de.name) != std::wstring(wide_name));

                EntryType type;
                if ((entry->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    type = EntryType::Reparse; // any tag -- symlink, junction, mount point
                else if ((entry->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                    type = EntryType::Directory;
                else
                    type = EntryType::RegularFile;

                // LastWriteTime is in the SAME FILE_FULL_DIR_INFO record as the
                // EndOfFile already read -- no extra call, and the enumeration
                // itself is handle-relative.
                de.meta = EntryMeta{type, static_cast<std::uint64_t>(entry->EndOfFile.QuadPart),
                                     /*same_device_as_root=*/true,
                                     filetime_to_unix_seconds(entry->LastWriteTime.QuadPart)};
                de.stat_error = 0;
                result.entries.push_back(std::move(de));
            }

            if (entry->NextEntryOffset == 0)
                break;
            // The advance itself must stay in the buffer and must make progress;
            // a zero-but-nonterminal or backward offset would loop forever.
            if (entry->NextEntryOffset < sizeof(FILE_FULL_DIR_INFO) ||
                entry->NextEntryOffset > static_cast<ULONG>(buffer_end - cursor)) {
                spdlog::warn("confined_fs::enumerate_at: directory entry offset out of bounds");
                result.reason = Reason::OsError;
                result.os_error = static_cast<int>(ERROR_INVALID_DATA);
                return result;
            }
            cursor += entry->NextEntryOffset;
        }
    }

    result.reason = Reason::None;
    return result;
}

namespace {

// Thin Ops adapter instantiating P1's walk_delete (PLAN-010): every walk/
// tally/deadline/outcome/lazy-match/exception decision lives in
// confined_fs_walk.hpp -- this struct only forwards to the exported
// primitives above. No raw HANDLE, no file-local handle owner: DirHandle IS
// confined_fs.hpp's WinHandle.
struct WinOps {
    using DirHandle = WinHandle;

    explicit WinOps(const FileIdentity& id) : root_id(id) {}

    OpenDirRes<DirHandle> open_dir(DirHandle& parent, const std::string& name) {
        OpenDirResult r = open_dir_at(parent.get(), name, root_id);
        OpenDirRes<DirHandle> out;
        out.reason = r.reason;
        out.os_error = r.os_error;
        if (r.reason == Reason::None)
            out.handle = std::move(r.h);
        return out;
    }

    EnumerateResult enumerate(DirHandle& dir, const EnumBudget& budget) {
        return enumerate_at(dir.get(), root_id, budget);
    }

    UnlinkOutcome unlink(DirHandle& parent, const std::string& name, UnlinkKind kind,
                         std::uint64_t max_bytes_remaining) {
        return unlink_at(parent.get(), name, kind, max_bytes_remaining, root_id);
    }

    static std::chrono::steady_clock::time_point now() {
        return std::chrono::steady_clock::now();
    }

    FileIdentity root_id; // by value, matching PosixOps -- no borrow to outlive
};

} // namespace

DeleteResult delete_matching(const ConfinedRoot& root, const MatchFn& match,
                              const DeleteLimits& limits) {
    // walk_delete takes its root DirHandle BY VALUE (it owns and eventually
    // closes every frame it pops). `root` is a caller-held const& that must
    // stay open across possibly-repeated delete_matching calls on the same
    // ConfinedRoot (ROOT REUSE), so the walker needs a SEPARATE owned handle,
    // not root's own. DuplicateHandle produces exactly that; the duplicate
    // is wrapped in a WinHandle immediately -- no raw HANDLE survives past
    // this statement.
    HANDLE dup_raw = INVALID_HANDLE_VALUE;
    if (!DuplicateHandle(GetCurrentProcess(), root.h_.get(), GetCurrentProcess(), &dup_raw, 0,
                          FALSE, DUPLICATE_SAME_ACCESS)) {
        // DeleteResult carries no top-level os_error (see confined_fs_rules.hpp:
        // only EntryOutcome::os_error, and the walk never started so there is no
        // entry to attach one to) -- this is a deliberate limit of the shared
        // result type, not a dropped value: log it here so a real occurrence is
        // still diagnosable.
        const DWORD err = GetLastError();
        spdlog::debug("confined_fs::delete_matching: DuplicateHandle failed: {}",
                      static_cast<unsigned long>(err));
        DeleteResult result;
        result.stop_reason = Reason::OsError;
        return result;
    }
    WinHandle root_handle(dup_raw);

    WinOps ops(root.identity());
    return walk_delete<WinOps>(std::move(root_handle), ops, match, limits);
}

} // namespace yuzu::agent::confined_fs

#endif // _WIN32
