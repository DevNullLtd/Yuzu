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
// A file longer than the cap is rejected (too_large), never truncated and
// parsed. Whatever the outcome, `token` holds a value if and only if the
// outcome is ok, and then the value passed enrollment_token_shape_valid.

#include <yuzu/enrollment_token_shape.hpp>

#include <cstddef>
#include <filesystem>
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
#else
#include <cerrno>

#include <posix_secure_read.hpp>
#endif

namespace yuzu::agent {

/// Upper bound on the token file: a token is 64 bytes, the rest is slack for a
/// newline, a BOM and stray whitespace.
inline constexpr std::size_t kEnrollmentTokenFileCap = 4096;

enum class TokenFileOutcome {
    ok,          ///< a shape-valid token was read from the file
    absent,      ///< nothing at the path (the normal already-enrolled restart)
    not_regular, ///< a link, directory or other non-regular object
    too_large,   ///< longer than the cap
    unreadable,  ///< the open or the read failed; `detail` says why
    no_token,    ///< a regular file whose first line is not a token
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
/// kept outside the Windows leg so it is unit-tested on every host. An
/// extended-length prefix (\\?\ or \\.\) in front of a drive letter is skipped.
[[nodiscard]] inline std::optional<wchar_t>
token_file_drive_letter(std::wstring_view path) noexcept {
    for (const std::wstring_view prefix : {std::wstring_view{LR"(\\?\)"},
                                           std::wstring_view{LR"(\\.\)"}}) {
        if (path.starts_with(prefix)) {
            path.remove_prefix(prefix.size());
            break;
        }
    }
    if (path.size() < 3 || path[1] != L':' || (path[2] != L'\\' && path[2] != L'/'))
        return std::nullopt;
    const wchar_t c = path[0];
    if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z')))
        return std::nullopt;
    return c;
}

#ifdef _WIN32

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
    struct Handle {
        HANDLE h;
        explicit Handle(HANDLE handle) noexcept : h(handle) {}
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
        ~Handle() {
            if (h != INVALID_HANDLE_VALUE)
                CloseHandle(h);
        }
    } guard{CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                        FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
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
/// When the path is set the file is read once. A token read from it wins over
/// `token`, and the path is kept so the first accepted registration can remove
/// the file. On every other outcome (absent, a link or directory, too large,
/// unreadable, no token in it) the path is CLEARED, so the agent can never delete
/// an object it did not consume a token from, and the option/env value stands (a
/// service whose environment still carries the token keeps starting). With no
/// path configured nothing is read and `token` is left alone.
[[nodiscard]] inline EnrollmentTokenResolution
resolve_enrollment_token(std::string& token, std::filesystem::path& token_file,
                         std::size_t cap = kEnrollmentTokenFileCap) {
    EnrollmentTokenResolution out;
    bool from_file = false;
    if (!token_file.empty()) {
        auto read = read_enrollment_token_file(token_file, cap);
        out.file_outcome = read.outcome;
        out.file_detail = std::move(read.detail);
        from_file = read.outcome == TokenFileOutcome::ok;
        if (from_file)
            token = std::move(*read.token);
        else
            token_file.clear();
    }
    out.source = from_file ? "file" : (token.empty() ? "none" : "option");
    return out;
}

} // namespace yuzu::agent
