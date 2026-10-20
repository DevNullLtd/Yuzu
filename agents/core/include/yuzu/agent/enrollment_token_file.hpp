#pragma once

// The agent's --enrollment-token-file reader and the token-source precedence rule.
//
// Header-only and free of logging, so the outcome matrix is testable without a
// running agent; main() maps each outcome to a log line and decides what to do
// with the configured path.
//
// read_enrollment_token_file opens the LEAF of the path without following a
// link and checks the OPENED object, not the name it was reached by: POSIX goes
// through yuzu::shared::read_file_no_follow (O_NOFOLLOW + fstat regular-file
// check + bounded read, so a FIFO cannot block it); Windows opens the leaf with
// FILE_FLAG_OPEN_REPARSE_POINT and refuses a reparse point from the handle (the
// plugin_loader.cpp shape). Intermediate path components are followed; a
// user-controlled ancestor of the token file's directory is the #5257 exposure,
// bounded here by the content gate below (only a 64-hex token is accepted).
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

#ifdef _WIN32

[[nodiscard]] inline RawTokenFile read_token_file_leaf(const std::filesystem::path& p,
                                                       std::size_t cap) {
    RawTokenFile out;
    struct Handle {
        HANDLE h;
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

/// Which token the agent registers with: one read from the file wins; otherwise
/// the --enrollment-token / YUZU_ENROLLMENT_TOKEN value stands (so a service
/// whose environment still carries the token keeps starting). The second member
/// names the winning source for the startup log: "file", "option" or "none".
[[nodiscard]] inline std::pair<std::string, std::string_view>
resolve_enrollment_token_source(std::string cli_or_env, std::optional<std::string> file_token) {
    if (file_token)
        return {std::move(*file_token), "file"};
    const bool have_option = !cli_or_env.empty();
    return {std::move(cli_or_env), have_option ? "option" : "none"};
}

} // namespace yuzu::agent
