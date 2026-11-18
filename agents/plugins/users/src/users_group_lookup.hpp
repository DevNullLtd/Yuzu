/**
 * users_group_lookup.hpp -- reentrant, value-semantics group/user lookups for the users plugin
 * (F40), with NOT-FOUND kept distinct from ERROR (POSIX). getgrnam()/getpwuid() return pointers
 * into one libc static buffer that any concurrent dispatch-pool thread rewrites, so the record is
 * copied into owned strings before anything else runs. The buffer grows on ERANGE up to a cap.
 *
 * The distinction matters to the caller: "no such group" is a definite answer, while a lookup
 * that failed (an NSS fault, ERANGE past the cap) must be reported as a degraded result, never
 * folded into a silently smaller admin list. The lookup function is a template parameter (same
 * signature as getgrnam_r / getpwuid_r) so each branch is unit-testable without a passwd database.
 */
#pragma once

#ifndef _WIN32

#include <cerrno>
#include <cstddef>
#include <string>
#include <vector>

#include <grp.h>
#include <pwd.h>
#include <sys/types.h>

namespace yuzu::users {

inline constexpr std::size_t kMaxLookupBufferBytes = 1u << 20;

enum class LookupStatus { kOk, kNotFound, kError };

/// ENOENT/ESRCH are glibc's documented "no such entry" spellings (same fold as agent-core's
/// passwd_lookup.hpp); every other nonzero rc, and ERANGE past the cap, is an ERROR.
[[nodiscard]] inline LookupStatus classify_lookup_rc(int rc, bool have_result) {
    if (rc == 0)
        return have_result ? LookupStatus::kOk : LookupStatus::kNotFound;
    if (rc == ENOENT || rc == ESRCH)
        return LookupStatus::kNotFound;
    return LookupStatus::kError;
}

struct GroupCopy {
    unsigned gid = 0;
    std::vector<std::string> members;
};

struct GroupLookup {
    LookupStatus status = LookupStatus::kError;
    GroupCopy group{};
};

template <typename LookupFn>
[[nodiscard]] GroupLookup lookup_group_copy(const char* name, LookupFn&& lookup) {
    std::vector<char> buf(4096);
    for (;;) {
        struct group grp{};
        struct group* res = nullptr;
        const int rc = lookup(name, &grp, buf.data(), buf.size(), &res);
        if (rc == ERANGE) {
            if (buf.size() >= kMaxLookupBufferBytes)
                return {LookupStatus::kError, {}};
            buf.resize(buf.size() * 2);
            continue;
        }
        GroupLookup out;
        out.status = classify_lookup_rc(rc, res != nullptr);
        if (out.status == LookupStatus::kOk) {
            out.group.gid = static_cast<unsigned>(res->gr_gid);
            for (char** m = res->gr_mem; m && *m; ++m)
                out.group.members.emplace_back(*m);
        }
        return out;
    }
}

[[nodiscard]] inline GroupLookup lookup_group_copy(const char* name) {
    return lookup_group_copy(name, ::getgrnam_r);
}

struct UserLookup {
    LookupStatus status = LookupStatus::kError;
    std::string name;
};

template <typename LookupFn>
[[nodiscard]] UserLookup lookup_user_name(uid_t uid, LookupFn&& lookup) {
    std::vector<char> buf(4096);
    for (;;) {
        struct passwd pw{};
        struct passwd* res = nullptr;
        const int rc = lookup(uid, &pw, buf.data(), buf.size(), &res);
        if (rc == ERANGE) {
            if (buf.size() >= kMaxLookupBufferBytes)
                return {LookupStatus::kError, {}};
            buf.resize(buf.size() * 2);
            continue;
        }
        UserLookup out;
        out.status = classify_lookup_rc(rc, res != nullptr);
        if (out.status == LookupStatus::kOk) {
            if (res->pw_name == nullptr)
                return {LookupStatus::kError, {}};
            out.name = res->pw_name;
        }
        return out;
    }
}

[[nodiscard]] inline UserLookup lookup_user_name(uid_t uid) {
    return lookup_user_name(uid, ::getpwuid_r);
}

} // namespace yuzu::users

#endif // !_WIN32
