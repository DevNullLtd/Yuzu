#pragma once

/**
 * execution_artifacts_scratch_identity.hpp — ownership verification for a
 * scratch directory this plugin itself created under agent.data_dir.
 *
 * current_process_token_owner_buf() and scratch_dir_is_ours() below are
 * HOISTED VERBATIM out of execution_artifacts_win.cpp's anonymous namespace
 * (banners included) so this plugin's A1 stale-scratch-dir sweep
 * (execution_artifacts_scratch_sweep_win.cpp) can call the exact same
 * ownership check collect_amcache already relies on, rather than
 * hand-rolling a second copy that could silently drift from it.
 * execution_artifacts_win.cpp keeps calling this same function too
 * (`git diff --color-moved` on that file shows these two functions as
 * MOVED, not rewritten). Marked `inline`: both this header and
 * execution_artifacts_scratch_sweep_win.cpp include it into the same
 * shared_library target, so a plain (non-inline) definition would be an
 * ODR violation at link time.
 *
 * Windows-only by construction (#ifdef _WIN32); the header is empty
 * elsewhere.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h> // GetSecurityInfo (scratch_dir_is_ours's owner check)

#include <yuzu/agent/confined_fs.hpp> // WinHandle -- aliased below as ScopedHandle

#include <vector>

namespace yuzu::execution_artifacts::detail {

// Local alias so the two functions below -- moved verbatim out of
// execution_artifacts_win.cpp's anonymous namespace -- compile completely
// unchanged: they reference `ScopedHandle`, win.cpp's own name for this
// exact move-only-HANDLE-RAII shape. Reusing confined_fs.hpp's already-
// exported WinHandle (identical semantics: closes on destruct/move/reset,
// same `.get()` accessor) rather than hand-rolling a third copy of the same
// wrapper -- confined_fs.hpp's own banner invites exactly this ("if a third
// consumer appears, hoist it and collapse the two"; WinHandle already IS
// that hoist, and this is the third consumer).
using ScopedHandle = yuzu::agent::confined_fs::WinHandle;

/// Returns the current process token's owner (TOKEN_OWNER) as an
/// in-process buffer, or an empty vector on any failure -- the two-call
/// GetTokenInformation idiom already used by process_enum.cpp/
/// tar_proc_etw.cpp, requesting TokenOwner (a PSID) rather than TokenUser.
/// The PSID inside the returned buffer is only valid for the buffer's
/// lifetime.
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

/// Verifies an already-open, freshly-created scratch-directory handle is
/// the object this process itself created: not a reparse point, and owned
/// by the SAME SID as the current process token's owner -- never a
/// hardcoded SYSTEM/Administrators pair, so this holds unchanged under a
/// future least-privilege NT SERVICE\YuzuAgent identity too (#1442/#4450).
///
/// yuzu_create_temp_dir() already gives CREATE_NEW semantics (ANY failure,
/// including ERROR_ALREADY_EXISTS, is treated as a hard failure -- see
/// temp_file.cpp) over a 128-bit crypto-random name, so this check is not
/// what makes the directory safe to use -- a name nobody else can predict
/// and a create that refuses to reuse an existing object already do that.
/// It is a second, independent proof that the specific object this handle
/// refers to really is the one collect_amcache just created, covering the
/// narrow window between that create and this open during which a
/// principal with FILE_DELETE_CHILD on agent.data_dir could in principle
/// have deleted and resubstituted it.
///
/// Takes the HANDLE, not a path: every check below resolves against the
/// OPEN OBJECT, never re-resolving the path -- combined with the caller
/// holding this same handle open (no FILE_SHARE_DELETE) through the
/// subsequent copy, this is what closes the TOCTOU a path-based
/// verify-then-use would otherwise have.
inline bool scratch_dir_is_ours(HANDLE dir_handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(dir_handle, &info))
        return false;
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        return false; // a junction/symlink -- never follow it.

    const auto owner_buf = current_process_token_owner_buf();
    if (owner_buf.empty())
        return false;
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

} // namespace yuzu::execution_artifacts::detail

#endif // defined(_WIN32)
