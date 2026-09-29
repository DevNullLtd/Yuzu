#pragma once

/**
 * local_security_policy_scratch_identity.hpp -- ownership verification for the
 * Windows leg's scratch directory and the sweep's candidates. PLUGIN-LOCAL COPY
 * of execution_artifacts_scratch_identity.hpp's two functions (only the
 * namespace differs); not lifted into agents/shared until a second consumer
 * justifies it. Both resolve against an OPEN HANDLE, never a path, and compare
 * against the current process token's owner (never a hardcoded SYSTEM pair).
 * Windows-only (#ifdef _WIN32); empty elsewhere.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h> // GetSecurityInfo (the owner check)

#include <yuzu/agent/confined_fs.hpp> // WinHandle -- aliased below as ScopedHandle

#include <vector>

namespace yuzu::local_security_policy::detail {

using ScopedHandle = yuzu::agent::confined_fs::WinHandle;

/// The current process token's owner (TOKEN_OWNER) as an in-process buffer, or
/// an empty vector on any failure. The PSID inside is valid only for the
/// buffer's lifetime.
inline std::vector<BYTE> current_process_token_owner_buf() {
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token))
        return {};
    ScopedHandle token(raw_token);

    DWORD needed = 0;
    GetTokenInformation(token.get(), TokenOwner, nullptr, 0, &needed);
    if (needed == 0)
        return {};
    std::vector<BYTE> buf(needed);
    if (!GetTokenInformation(token.get(), TokenOwner, buf.data(), needed, &needed))
        return {};
    return buf;
}

/// True only when the already-open directory handle is not a reparse point
/// and is owned by the SAME SID as the current process token's owner. A
/// directory owned by any other principal (a planted, look-alike name) is
/// never ours. Takes the HANDLE so every check binds to the open object.
inline bool scratch_dir_is_ours(HANDLE dir_handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(dir_handle, &info))
        return false;
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        return false; // a junction/symlink -- never follow it.

    const auto owner_buf = current_process_token_owner_buf();
    if (owner_buf.empty())
        return false;
    // TOKEN_OWNER over vector<BYTE> storage. Alignment: the vector's storage comes from
    // operator new, aligned for any fundamental type, so a pointer-sized struct at offset 0 is
    // aligned. Bounds: GetTokenInformation sized the buffer itself (`needed`) and wrote the
    // TOKEN_OWNER at its start. Aliasing: TOKEN_OWNER is an implicit-lifetime type and
    // operator-new storage implicitly creates one ([intro.object]). Lifetime: the PSID points
    // INTO this same buffer, valid while owner_buf lives, which spans every use below.
    const PSID token_owner = reinterpret_cast<const TOKEN_OWNER*>(owner_buf.data())->Owner;

    PSECURITY_DESCRIPTOR sd = nullptr;
    PSID dir_owner = nullptr;
    const DWORD rc = GetSecurityInfo(dir_handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                     &dir_owner, nullptr, nullptr, nullptr, &sd);
    if (rc != ERROR_SUCCESS)
        return false;
    struct SdGuard {
        PSECURITY_DESCRIPTOR p;
        ~SdGuard() {
            if (p)
                LocalFree(p);
        }
    } sd_guard{sd};

    return EqualSid(dir_owner, token_owner);
}

} // namespace yuzu::local_security_policy::detail

#endif // defined(_WIN32)
