#pragma once

// The agent's --enrollment-token-file reader and the token-source rule.
//
// Header-only and free of logging, so the outcome matrix is testable without a
// running agent. resolve_enrollment_token owns the whole decision (read, which
// token wins, whether the configured path stays set for the post-registration
// removal); main() only maps each outcome to a log line.
//
// read_enrollment_token_file opens the LEAF of the path without following a
// link and checks the OPENED object, not the name it was reached by: POSIX goes
// through yuzu::shared::read_file_no_follow (O_NOFOLLOW + fstat regular-file
// check + bounded read, so a FIFO cannot block it); Windows refuses a UNC,
// device or non-fixed-drive path without opening it (an open on an unreachable
// share can outlast the service start deadline), then opens the leaf with
// FILE_FLAG_OPEN_REPARSE_POINT and refuses a reparse point from the handle (the
// plugin_loader.cpp shape). Intermediate path components are followed; an
// ancestor directory that another account can write to is tracked as #5257, and
// the content gate below (only a 64-hex token is accepted) bounds what such a
// path can supply.
//
// OWNER. A token file is accepted only if the opened object was laid down by an
// account that may place a credential for this agent: owned by the superuser
// (uid 0 / SYSTEM), by the account the process runs as (euid / token owner), or
// on Windows by BUILTIN\Administrators; and on POSIX neither group- nor
// other-writable (the sudoers-source predicate in local_security_policy_legs.hpp).
// The point is that a file placed by an account that is not allowed to supply a
// credential for this agent is never used: its content is not parsed and its token
// is not presented to the server. The Windows leg checks the owner before reading a
// byte; the POSIX primitive has read the (capped) bytes by the time the fstat facts
// are checked, and they are discarded unparsed.
// The check runs on the handle/fd that is read, never on the path. Own-user is
// accepted so the unit tests and an interactive run read their own files; the
// LocalSystem service therefore accepts only SYSTEM or Administrators.
// Windows checks the owner only: the installer sets the file's DACL itself, and an
// effective-rights walk over inherited ACEs is surface this reader does not take on.
//
// A file longer than the cap is rejected (too_large), never truncated and
// parsed. Whatever the outcome, `token` holds a value if and only if the
// outcome is ok, and then the value passed enrollment_token_shape_valid.

#include <yuzu/enrollment_token_shape.hpp>

#include <bounded_wait.hpp> // yuzu::shared::bounded_call (agents/shared)

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h> // GetSecurityInfo (the owner check)

#include <vector>

#pragma comment(lib, "advapi32.lib")
#else
#include <cerrno>

#include <posix_secure_read.hpp>
#include <unistd.h>
#endif

namespace yuzu::agent {

/// Upper bound on the token file: a token is 64 bytes, the rest is slack for a
/// newline, a BOM and stray whitespace.
inline constexpr std::size_t kEnrollmentTokenFileCap = 4096;

/// How long main() waits for the token-file read before carrying on without it.
/// The read runs before the Windows SCM hand-off, so an open that never returns (an
/// oplock held on a file another account placed there, a wedged filesystem) must not eat
/// the service's start deadline.
inline constexpr std::chrono::milliseconds kEnrollmentTokenReadDeadline{5000};

enum class TokenFileOutcome {
    ok,              ///< a shape-valid token was read from the file
    absent,          ///< nothing at the path (the normal already-enrolled restart)
    not_regular,     ///< a link, directory or other non-regular object
    too_large,       ///< longer than the cap
    unreadable,      ///< the open or the read failed, or it timed out; `detail` says why
    untrusted_owner, ///< owned by someone else, or (POSIX) group/other-writable; `detail` says
                     ///< which (see OWNER in the file header)
    no_token,        ///< a regular file whose first line is not a token
};

struct EnrollmentTokenFileRead {
    std::optional<std::string> token; ///< set if and only if outcome == ok
    TokenFileOutcome outcome{TokenFileOutcome::absent};
    std::string detail; ///< an OS error description for `unreadable`, else empty
};

namespace detail {

struct RawTokenFile {
    std::string text;
    TokenFileOutcome outcome{TokenFileOutcome::ok}; ///< ok means `text` was read
    std::string detail;
};

/// The drive letter of an absolute Windows path, or nullopt when the path is not
/// rooted at a drive letter: a UNC share (\\host\share, \\?\UNC\host\share), a
/// device or pipe path (\\.\pipe\x), or anything relative. Pure string logic,
/// kept outside the Windows leg so it is unit-tested on every host. A path
/// carrying an extended-length prefix (\\?\ or \\.\) is not a plain drive-letter
/// root and is refused too; the installer writes a plain path.
[[nodiscard]] inline std::optional<wchar_t>
token_file_drive_letter(std::wstring_view path) noexcept {
    if (path.size() < 3 || path[1] != L':' || (path[2] != L'\\' && path[2] != L'/'))
        return std::nullopt;
    const wchar_t c = path[0];
    if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z')))
        return std::nullopt;
    return c;
}

/// The POSIX owner/mode policy over an opened file's fstat facts: owned by the
/// superuser or by `euid`, and not writable by group or other. Pure integer logic
/// (the same predicate shape as local_security_policy_legs.hpp's strict arm), kept
/// outside the POSIX leg so the refuse matrix is unit-tested on every host.
[[nodiscard]] constexpr bool token_file_posix_trusted(std::uint32_t owner_uid, std::uint32_t mode,
                                                      std::uint32_t euid) noexcept {
    return (owner_uid == 0 || owner_uid == euid) && (mode & 0022u) == 0;
}

#ifdef _WIN32

struct TokenFileHandle {
    HANDLE h;
    explicit TokenFileHandle(HANDLE handle) noexcept : h(handle) {}
    TokenFileHandle(const TokenFileHandle&) = delete;
    TokenFileHandle& operator=(const TokenFileHandle&) = delete;
    ~TokenFileHandle() {
        if (h != INVALID_HANDLE_VALUE && h != nullptr)
            CloseHandle(h);
    }
};

/// Owner policy over the OPEN file handle: ok if its owner is SYSTEM,
/// BUILTIN\Administrators or the owner of this process's token; untrusted_owner
/// otherwise; unreadable if the owner cannot be determined (fail closed). The
/// second member says why when the outcome is not ok. The handle carries
/// READ_CONTROL (GENERIC_READ includes it).
[[nodiscard]] inline std::pair<TokenFileOutcome, std::string> token_file_owner_check(HANDLE file) {
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    const DWORD rc = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner,
                                     nullptr, nullptr, nullptr, &sd);
    if (rc != ERROR_SUCCESS)
        return {TokenFileOutcome::unreadable, "GetSecurityInfo error " + std::to_string(rc)};
    struct SdGuard { // owns the GetSecurityInfo-allocated descriptor `owner` points into
        PSECURITY_DESCRIPTOR p;
        explicit SdGuard(PSECURITY_DESCRIPTOR d) noexcept : p(d) {}
        SdGuard(const SdGuard&) = delete;
        SdGuard& operator=(const SdGuard&) = delete;
        ~SdGuard() {
            if (p)
                LocalFree(p);
        }
    } sd_guard{sd};
    if (owner == nullptr || !IsValidSid(owner))
        return {TokenFileOutcome::unreadable, "the file has no valid owner"};
    if (IsWellKnownSid(owner, WinLocalSystemSid) ||
        IsWellKnownSid(owner, WinBuiltinAdministratorsSid))
        return {TokenFileOutcome::ok, {}};

    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token))
        return {TokenFileOutcome::unreadable,
                "OpenProcessToken error " + std::to_string(GetLastError())};
    const TokenFileHandle token{raw_token};
    DWORD needed = 0;
    GetTokenInformation(token.h, TokenOwner, nullptr, 0, &needed);
    std::vector<BYTE> buf(needed);
    if (needed == 0 || !GetTokenInformation(token.h, TokenOwner, buf.data(), needed, &needed))
        return {TokenFileOutcome::unreadable,
                "GetTokenInformation error " + std::to_string(GetLastError())};
    // Lifetime: the PSID points INTO `buf`, which outlives the comparison. Alignment:
    // vector's storage comes from operator new, aligned for any fundamental type, so
    // TOKEN_OWNER is readable at buf.data(). Constness: a read-only view, never written
    // through.
    const PSID self = reinterpret_cast<const TOKEN_OWNER*>(buf.data())->Owner;
    if (EqualSid(owner, self))
        return {TokenFileOutcome::ok, {}};
    return {TokenFileOutcome::untrusted_owner,
            "owned by an account other than SYSTEM, Administrators or this service"};
}

[[nodiscard]] inline RawTokenFile read_token_file_leaf(const std::filesystem::path& p,
                                                       std::size_t cap) {
    RawTokenFile out;
    // Refuse a non-local path BEFORE opening it: CreateFileW on an unreachable UNC
    // share or a disconnected mapped drive blocks long enough to miss the service
    // start deadline (error 1053), and main() calls this ahead of the SCM hand-off.
    // absolute() is lexical (GetFullPathNameW, no network); only a fixed local
    // drive is opened (the privacy_permissions hive guard's order: UNC first,
    // then drive type, both before any open).
    std::error_code abs_ec;
    const auto abs = std::filesystem::absolute(p, abs_ec);
    const auto drive = abs_ec ? std::nullopt : token_file_drive_letter(abs.native());
    const wchar_t root[] = {drive.value_or(L'?'), L':', L'\\', L'\0'};
    if (!drive || GetDriveTypeW(root) != DRIVE_FIXED) {
        out.outcome = TokenFileOutcome::unreadable;
        out.detail = "not a local fixed-drive path";
        return out;
    }
    // Share read/write/delete so a concurrent installer rename or delete (or a
    // scanner holding the file) does not turn this one-shot read into a sharing
    // violation that leaves the agent tokenless (the guardian_state_reader.cpp
    // shape). BACKUP_SEMANTICS lets a directory leaf open, so the attribute check
    // below reports it as not_regular rather than as an open failure.
    const TokenFileHandle guard{CreateFileW(p.c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING,
                                      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                                      nullptr)};
    if (guard.h == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            out.outcome = TokenFileOutcome::absent;
        } else {
            out.outcome = TokenFileOutcome::unreadable;
            out.detail = "CreateFileW error " + std::to_string(err);
        }
        return out;
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(guard.h, &info)) {
        out.outcome = TokenFileOutcome::unreadable;
        out.detail = "GetFileInformationByHandle error " + std::to_string(GetLastError());
        return out;
    }
    if (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) {
        out.outcome = TokenFileOutcome::not_regular;
        return out;
    }
    // The owner of the object that will be read, checked before any byte is.
    if (auto [owner, why] = token_file_owner_check(guard.h); owner != TokenFileOutcome::ok) {
        out.outcome = owner;
        out.detail = std::move(why);
        return out;
    }
    // One byte past the cap tells "exactly the cap" from "longer"; never trust the size field.
    std::string buf(cap + 1, '\0');
    std::size_t total = 0;
    while (total < buf.size()) {
        DWORD n = 0;
        if (!ReadFile(guard.h, buf.data() + total, static_cast<DWORD>(buf.size() - total), &n,
                      nullptr)) {
            out.outcome = TokenFileOutcome::unreadable;
            out.detail = "ReadFile error " + std::to_string(GetLastError());
            return out;
        }
        if (n == 0)
            break;
        total += n;
    }
    if (total > cap) {
        out.outcome = TokenFileOutcome::too_large;
        return out;
    }
    buf.resize(total);
    out.text = std::move(buf);
    return out;
}

#else

[[nodiscard]] inline RawTokenFile read_token_file_leaf(const std::filesystem::path& p,
                                                       std::size_t cap) {
    RawTokenFile out;
    auto fr = yuzu::shared::read_file_no_follow(p.string(), cap);
    switch (fr.error) {
    case yuzu::shared::ReadError::none:
        // The owner/mode of the object that was read (the fstat read_file_no_follow
        // already made), checked before the bytes are used.
        if (!token_file_posix_trusted(static_cast<std::uint32_t>(fr.owner_uid),
                                      static_cast<std::uint32_t>(fr.mode),
                                      static_cast<std::uint32_t>(::geteuid()))) {
            out.outcome = TokenFileOutcome::untrusted_owner;
            out.detail = std::format("owner uid {}, mode {:04o} (must be owned by root or this "
                                     "user and not writable by group or other)",
                                     static_cast<unsigned long>(fr.owner_uid),
                                     static_cast<unsigned>(fr.mode & 07777));
            break;
        }
        out.text = std::move(fr.data);
        break;
    case yuzu::shared::ReadError::symlink_refused:
    case yuzu::shared::ReadError::not_regular:
        out.outcome = TokenFileOutcome::not_regular;
        break;
    case yuzu::shared::ReadError::oversized:
        out.outcome = TokenFileOutcome::too_large;
        break;
    case yuzu::shared::ReadError::io:
        if (fr.err == ENOENT) {
            out.outcome = TokenFileOutcome::absent;
        } else {
            out.outcome = TokenFileOutcome::unreadable;
            out.detail = std::error_code(fr.err, std::generic_category()).message();
        }
        break;
    }
    return out;
}

#endif

} // namespace detail

/// Read the enrollment token from the file at `p`. See the file header for the
/// guarantees; the caller logs by outcome and must not use `p` as a deletion
/// target unless the outcome is ok.
[[nodiscard]] inline EnrollmentTokenFileRead
read_enrollment_token_file(const std::filesystem::path& p,
                           std::size_t cap = kEnrollmentTokenFileCap) {
    EnrollmentTokenFileRead out;
    auto raw = detail::read_token_file_leaf(p, cap);
    out.outcome = raw.outcome;
    out.detail = std::move(raw.detail);
    if (raw.outcome != TokenFileOutcome::ok)
        return out;
    if (auto tok = enrollment_token_from_file_text(raw.text)) {
        out.token = std::move(tok);
    } else {
        out.outcome = TokenFileOutcome::no_token;
    }
    return out;
}

/// What resolve_enrollment_token decided, for main() to log.
struct EnrollmentTokenResolution {
    /// The token-file read's outcome; nullopt when no token file was configured.
    std::optional<TokenFileOutcome> file_outcome;
    std::string file_detail; ///< the reader's `detail` (an OS error description), else empty
    std::string_view source; ///< the winning source: "file", "option" or "none"
};

/// The one place that decides which enrollment token the agent registers with and
/// whether the token file stays a deletion target.
///
/// `token` is the --enrollment-token / YUZU_ENROLLMENT_TOKEN value and
/// `token_file` the --enrollment-token-file path; both are updated in place.
/// When the path is set the file is read once, under `deadline`. A token read from
/// it wins over `token`, and the path is kept so the first accepted registration, or
/// the server's refusal of that token (is_enrollment_token_refusal), can remove the
/// file. On every other outcome (absent, a link or directory, too large, unreadable
/// or timed out, an untrusted owner, no token in it) the path is CLEARED, so the
/// agent never removes a path it did not read a token from (the removal itself is by
/// path, so an object placed there before that accepted registration or refusal is
/// removed), and the option/env value stands (a service whose environment still
/// carries the token keeps starting). With no path configured nothing is read and
/// `token` is left alone.
///
/// The read runs on yuzu::shared::bounded_call's detached worker: past `deadline`
/// the caller carries on tokenless (outcome unreadable, detail "timed out") and
/// the worker is abandoned. That is safe here because the worker owns copies of
/// everything it touches and this header lives in the agent binary, never in a
/// dlclose()'d plugin. `reader` is the injection point for the read (tests pass a
/// reader that blocks or returns a scripted outcome).
template <typename Reader>
[[nodiscard]] EnrollmentTokenResolution
resolve_enrollment_token_with(std::string& token, std::filesystem::path& token_file,
                              Reader reader, std::chrono::milliseconds deadline) {
    EnrollmentTokenResolution out;
    bool from_file = false;
    if (!token_file.empty()) {
        auto read = yuzu::shared::bounded_call(
            deadline, [reader = std::move(reader), path = token_file]() { return reader(path); });
        if (!read) {
            read.emplace();
            read->outcome = TokenFileOutcome::unreadable;
            read->detail = "timed out";
        }
        out.file_outcome = read->outcome;
        out.file_detail = std::move(read->detail);
        from_file = read->outcome == TokenFileOutcome::ok;
        if (from_file)
            token = std::move(*read->token);
        else
            token_file.clear();
    }
    out.source = from_file ? "file" : (token.empty() ? "none" : "option");
    return out;
}

[[nodiscard]] inline EnrollmentTokenResolution
resolve_enrollment_token(std::string& token, std::filesystem::path& token_file) {
    return resolve_enrollment_token_with(
        token, token_file,
        [](const std::filesystem::path& p) { return read_enrollment_token_file(p); },
        kEnrollmentTokenReadDeadline);
}

} // namespace yuzu::agent
