/**
 * shares_linux.cpp -- Linux leg: configured NFS/SMB shares from /etc/exports, the
 * /etc/exports.d snippets and /etc/samba/smb.conf (rung 1, bounded no-follow reads).
 *
 * Only the path binding lives here: the reads are shares_posix_fs.hpp and every decision
 * (refused != absent, registry/include/usershare tokens, row budget) is `list_linux` in
 * shares_legs.hpp. These are configured shares as written, not live nfsd/smbd state.
 */
#include "shares_legs.hpp"

#if defined(__linux__)

#include "shares_posix_fs.hpp"

namespace yuzu::shares {

int run_linux(yuzu::CommandContext& ctx) {
    // Built per call, inside execute_list's containment, not as a dlopen-time global.
    const Paths paths{"/etc/exports", "/etc/exports.d", "/etc/samba/smb.conf",
                      "/var/lib/samba/usershares"};
    report_list(ctx, list_linux(make_posix_fs(paths)));
    return 0;
}

} // namespace yuzu::shares

#endif // defined(__linux__)
