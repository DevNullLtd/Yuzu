/**
 * shares_macos.cpp -- macOS leg: SMB share points via `/usr/sbin/sharing -l -f json`
 * (rung 2 argv, bounded runner) plus NFS exports from /etc/exports (bounded no-follow read,
 * BSD exports(5) grammar).
 *
 * No public API exposes share-point records and the sharepoints dslocal node is not a
 * permitted read, so the tool is the mechanism. This TU is only the runner/reader binding;
 * the classification is `list_macos` in shares_legs.hpp.
 */
#include "shares_legs.hpp"

#if defined(__APPLE__)

#include "shares_posix_fs.hpp"

namespace yuzu::shares {

int run_macos(yuzu::CommandContext& ctx) {
    const auto fs = make_posix_fs(Paths{"/etc/exports", "", "", ""});
    report_list(ctx, list_macos(
                         [](const auto& argv, const auto& opts) {
                             // sink: shares/run_macos#1 -- /usr/sbin/sharing -l -f json (rung 2 argv; no public API for share-point records, the sharepoints dslocal node is not a permitted read)
                             return yuzu::agent::run_bounded_subprocess(argv, opts);
                         },
                         fs.read, fs.exports_path));
    return 0;
}

} // namespace yuzu::shares

#endif // defined(__APPLE__)
