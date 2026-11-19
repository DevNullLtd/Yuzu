/**
 * printing_identity.hpp -- the effective user's name for `printing.clear_queue`'s
 * `requesting-user-name` / `Authorization: PeerCred` identity (#4679). POSIX only.
 *
 * Uses the REENTRANT getpwuid_r into a caller-owned, ERANGE-growing buffer and copies the name
 * out, instead of getpwuid(): its result lives in one libc static buffer that any concurrent
 * dispatch-pool command (users, filesystem.get_acl) rewrites, so a torn name could reach the
 * header. The lookup function is a template parameter so the failure branches are unit-testable
 * without a passwd database. An empty result means "no resolvable identity" (not found, an error,
 * or a buffer past the cap) and the caller must NOT send.
 *
 * Not bounded in TIME: getpwuid_r can still block in NSS on a directory-joined host. agent-core's
 * `passwd_lookup.hpp` bounds a by-NAME lookup with a detached worker that must live in agent-core;
 * it has no by-uid form, so wiring a bounded by-uid lookup is a separate agent-core change.
 */
#pragma once

#ifndef _WIN32

#include <cerrno>
#include <cstddef>
#include <string>
#include <vector>

#include <pwd.h>
#include <sys/types.h>

namespace yuzu::printing {

/// Largest passwd scratch buffer tried before giving up (fail closed: empty).
inline constexpr std::size_t kMaxPasswdBufferBytes = 1u << 20;

/// `lookup` has getpwuid_r's signature. Returns the user name, or "" when it cannot be resolved.
template <typename LookupFn>
[[nodiscard]] std::string username_for_uid(uid_t uid, LookupFn&& lookup) {
    std::vector<char> buf(4096);
    for (;;) {
        struct passwd pw{};
        struct passwd* res = nullptr;
        const int rc = lookup(uid, &pw, buf.data(), buf.size(), &res);
        if (rc == ERANGE && buf.size() < kMaxPasswdBufferBytes) {
            buf.resize(buf.size() * 2);
            continue;
        }
        if (rc != 0 || res == nullptr || res->pw_name == nullptr)
            return {};
        return std::string(res->pw_name);
    }
}

[[nodiscard]] inline std::string username_for_uid(uid_t uid) {
    return username_for_uid(uid, ::getpwuid_r);
}

} // namespace yuzu::printing

#endif // !_WIN32
