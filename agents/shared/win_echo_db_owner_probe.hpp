#pragma once

/**
 * win_echo_db_owner_probe.hpp -- the read-only "is this Echo database file ours?" test, shared by
 * the two code paths that open <data_dir>\echo.db: the echo plugin (echo_db.cpp, which also
 * re-creates a refused sidecar and re-secures the rest) and app_usage, which reads the same file
 * and ships its rows to the server every day.
 *
 * A file is NOT ours on positive evidence only: it is owned by an account other than SYSTEM,
 * BUILTIN\Administrators or the process token's user (a planted file keeps its planter as owner),
 * or it has more than one hard link (a link shares its target's owner and security descriptor, so
 * the owner test cannot see it). A failed owner read, link-count query or open is no evidence: the
 * caller decides what that means. Every look is through a handle opened for it with
 * FILE_FLAG_OPEN_REPARSE_POINT, so a planted link is examined as the link, never its target, and
 * with READ_CONTROL | FILE_READ_ATTRIBUTES only, so no share mode held on the file can refuse it.
 *
 * Windows-only and header-only (empty elsewhere); pure Win32, no dependency on the echo plugin.
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

#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <win_str.hpp>

namespace yuzu::win {

class EchoDbOwnerProbe {
public:
    // Reads the process token's user once; ok() is false when that failed, and then no file is
    // judged foreign (the owner test has nothing to compare against).
    EchoDbOwnerProbe() {
        HANDLE token = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
            error_ = ::GetLastError();
            return;
        }
        const HandlePtr token_guard{token, ::CloseHandle}; // closes on the resize throwing too
        DWORD len = 0;
        ::GetTokenInformation(token, TokenUser, nullptr, 0, &len); // size probe
        user_buf_.resize(len);
        const bool got =
            len != 0 && ::GetTokenInformation(token, TokenUser, user_buf_.data(), len, &len);
        if (!got)
            error_ = ::GetLastError();
        // The PSID points INTO user_buf_ (alive as long as *this, hence no copy or move). The
        // cast is aligned: vector<BYTE>::data() is a heap block aligned to the default new
        // alignment.
        if (got)
            user_sid_ = reinterpret_cast<TOKEN_USER*>(user_buf_.data())->User.Sid;
    }
    EchoDbOwnerProbe(const EchoDbOwnerProbe&) = delete;
    EchoDbOwnerProbe& operator=(const EchoDbOwnerProbe&) = delete;

    [[nodiscard]] bool ok() const noexcept { return user_sid_ != nullptr; }
    [[nodiscard]] DWORD error() const noexcept { return error_; } // set at the failing call
    [[nodiscard]] PSID user_sid() const noexcept { return user_sid_; }

    // Why `file` (an open handle with READ_CONTROL) is owned by a foreign account, else nullopt.
    // `read_error`, when given, receives the owner read's result (ERROR_SUCCESS on success) so the
    // caller can log a failed read: that case returns nullopt, because a filesystem without ACLs
    // (FAT/exFAT) has no owner to compare.
    [[nodiscard]] std::optional<std::string> foreign_owner(HANDLE file,
                                                           DWORD* read_error = nullptr) const {
        PSID owner = nullptr;
        PSECURITY_DESCRIPTOR sd = nullptr;
        const DWORD rc = ::GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                           &owner, nullptr, nullptr, nullptr, &sd);
        const LocalPtr sd_guard{sd, ::LocalFree}; // `owner` points into it
        if (read_error != nullptr)
            *read_error = rc;
        if (rc != ERROR_SUCCESS || owner == nullptr || !ok() || owner_allowed(owner))
            return std::nullopt;
        return std::format("is owned by {}, not SYSTEM, Administrators or the agent account",
                           sid_text(owner));
    }

    // Why `file` (an open handle with FILE_READ_ATTRIBUTES) has other names, else nullopt. A
    // failed query is no evidence.
    [[nodiscard]] static std::optional<std::string> extra_links(HANDLE file) {
        BY_HANDLE_FILE_INFORMATION info{};
        if (::GetFileInformationByHandle(file, &info) && info.nNumberOfLinks > 1)
            return std::format("has {} hard links", info.nNumberOfLinks);
        return std::nullopt;
    }

    // For a caller that only reads the database: look at echo.db and the three files SQLite can
    // read beside it (-wal and -shm are read as database content, a hot -journal is replayed by a
    // writer), and return "<file> <why>" for the first one that is not ours. A file that is
    // absent or cannot be opened for the look yields nothing here -- sqlite3_open_v2 reports it.
    [[nodiscard]] std::optional<std::string> distrust(const std::filesystem::path& db) const {
        for (const char* suffix : {"", "-wal", "-shm", "-journal"}) {
            std::filesystem::path file = db;
            file += suffix;
            const HANDLE h = ::CreateFileW(file.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                           nullptr, OPEN_EXISTING,
                                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                                           nullptr);
            if (h == INVALID_HANDLE_VALUE)
                continue;
            const HandlePtr guard{h, ::CloseHandle};
            std::optional<std::string> why = foreign_owner(h);
            if (!why)
                why = extra_links(h);
            if (why)
                return from_wide(file.filename().c_str()) + " " + *why;
        }
        return std::nullopt;
    }

private:
    using HandlePtr = std::unique_ptr<void, decltype(&::CloseHandle)>;
    using LocalPtr = std::unique_ptr<void, decltype(&::LocalFree)>;

    // SYSTEM, BUILTIN\Administrators or the process token's user.
    [[nodiscard]] bool owner_allowed(PSID owner) const noexcept {
        return ok() && owner != nullptr &&
               (::EqualSid(owner, user_sid_) || ::IsWellKnownSid(owner, WinLocalSystemSid) ||
                ::IsWellKnownSid(owner, WinBuiltinAdministratorsSid));
    }

    static std::string sid_text(PSID sid) {
        LPWSTR raw = nullptr;
        if (!::ConvertSidToStringSidW(sid, &raw))
            return "an unreadable SID";
        const LocalPtr guard{raw, ::LocalFree};
        return from_wide(raw);
    }

    std::vector<BYTE> user_buf_;
    PSID user_sid_ = nullptr;
    DWORD error_ = ERROR_SUCCESS;
};

} // namespace yuzu::win

#endif // _WIN32
