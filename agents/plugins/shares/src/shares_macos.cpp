/**
 * shares_macos.cpp -- macOS leg: the share points `sharing -l -f json` records (SMB) plus the
 * NFS exports in /etc/exports (rung 2: one read-only argv leaf and one bounded file read).
 *
 * Only the two boundaries are bound here; every decision (read before run, refused != absent,
 * runner outcomes as named tokens, one row/byte budget) is `list_macos` in shares_legs.hpp and
 * the grammars are shares_parsers.hpp. Rows are what the host RECORDS and exports as written,
 * not live smbd/nfsd state. ACLs, permissions and remarks are never read.
 *
 * Bounds, stated precisely. The tool is TIME-bounded (the runner's 5 s deadline SIGKILLs the
 * child's process group) and BYTE-bounded (a 2 MiB output cap). The /etc/exports read is
 * BYTE-bounded (shares_posix_fs.hpp's 256 KiB cap) with no deadline of its own, like the Linux
 * leg's read and every posix_secure_read consumer (#4875); the file lives on the system volume.
 * The dslocal share-point node is never read: the tool is the mechanism.
 */
#include "shares_legs.hpp"

#if defined(__APPLE__)

#include "shares_posix_fs.hpp"

namespace yuzu::shares {

int run_macos(yuzu::CommandContext& ctx) {
    // Built per call, inside execute_list's containment, not as a dlopen-time global.
    MacFs fs;
    fs.exports_path = "/etc/exports";
    fs.read = &read_no_follow;
    fs.run = [](const std::vector<std::string>& argv, const yuzu::agent::SubprocessOptions& opts) {
        // sink: shares/run_macos#1 -- /usr/sbin/sharing -l -f json (rung 2 argv; no public API
        // exposes share-point records and the dslocal sharepoints node is not a permitted read)
        return yuzu::agent::run_bounded_subprocess(argv, opts);
    };
    report_list(ctx, list_macos(fs));
    return 0;
}

} // namespace yuzu::shares

#endif // defined(__APPLE__)
