/**
 * filesystem_posix_names.hpp -- reentrant owner/group name resolution for `get_acl` (F63), POSIX.
 *
 * getpwuid()/getgrgid() return pointers into libc static buffers that concurrent dispatch-pool
 * commands rewrite, so the _r forms run into a local buffer (growing on ERANGE, bounded) and the
 * name is copied out at once. An unresolved id (no such entry, any error, a buffer past the cap)
 * reports the NUMERIC id, never an empty name. The lookup function is a template parameter so the
 * fallback is unit-testable without a passwd database.
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

namespace yuzu::filesystem {

inline constexpr std::size_t kMaxNameLookupBufferBytes = 1u << 20;

template <typename LookupFn>
[[nodiscard]] std::string owner_name_or_numeric(uid_t uid, LookupFn&& lookup) {
    std::vector<char> buf(4096);
    for (;;) {
        passwd pw{};
        passwd* res = nullptr;
        const int rc = lookup(uid, &pw, buf.data(), buf.size(), &res);
        if (rc == ERANGE && buf.size() < kMaxNameLookupBufferBytes) {
            buf.resize(buf.size() * 2);
            continue;
        }
        if (rc == 0 && res != nullptr && res->pw_name != nullptr)
            return res->pw_name;
        return std::to_string(uid);
    }
}

template <typename LookupFn>
[[nodiscard]] std::string group_name_or_numeric(gid_t gid, LookupFn&& lookup) {
    std::vector<char> buf(4096);
    for (;;) {
        group gr{};
        group* res = nullptr;
        const int rc = lookup(gid, &gr, buf.data(), buf.size(), &res);
        if (rc == ERANGE && buf.size() < kMaxNameLookupBufferBytes) {
            buf.resize(buf.size() * 2);
            continue;
        }
        if (rc == 0 && res != nullptr && res->gr_name != nullptr)
            return res->gr_name;
        return std::to_string(gid);
    }
}

[[nodiscard]] inline std::string owner_name_or_numeric(uid_t uid) {
    return owner_name_or_numeric(uid, ::getpwuid_r);
}
[[nodiscard]] inline std::string group_name_or_numeric(gid_t gid) {
    return group_name_or_numeric(gid, ::getgrgid_r);
}

} // namespace yuzu::filesystem

#endif // !_WIN32
