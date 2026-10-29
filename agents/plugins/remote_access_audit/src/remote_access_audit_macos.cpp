/**
 * remote_access_audit_macos.cpp -- macOS leg: the path binding, the mount-table read and the
 * `launchctl print-disabled system` runner (rung 2; works unprivileged). Every decision is
 * `list_posix`. The mount table is getmntinfo_r_np(MNT_NOWAIT), the kernel's cache, which
 * never calls into a wedged server (agents/shared/macos_network_mounts.hpp, shared with runtimes).
 */
#include "remote_access_audit_legs.hpp"

#if defined(__APPLE__)

#include "remote_access_audit_posix_fs.hpp"

#include <macos_network_mounts.hpp> // yuzu::shared::read_macos_network_mounts (agents/shared)

namespace yuzu::remote_access_audit {

int run_macos(yuzu::CommandContext& ctx) {
    Paths p;
    p.os = "macos";
    p.launchd = true;
    p.config = "/etc/ssh/sshd_config";
    p.home_parents = {"/Users"};
    // canonical spelling: /var is a link to private/var and a home opens hop by hop with no link followed
    p.single_homes = {"/private/var/root"};
    p.min_uid = 500; // an account home, not Shared or a stray entry (autoruns_macos.cpp's rule)
    p.mounts = &yuzu::shared::read_macos_network_mounts;
    p.run = [](const std::vector<std::string>& args, const yuzu::agent::SubprocessOptions& opts) {
        std::vector<std::string> argv{"/bin/launchctl"};
        argv.insert(argv.end(), args.begin(), args.end());
        // sink: remote_access_audit/run_macos#1 -- /bin/launchctl print-disabled system (rung 2 argv; no public API reports launchd override state)
        return yuzu::agent::run_bounded_subprocess(argv, opts);
    };
    report_list(ctx, list_posix(make_posix_fs(p)));
    return 0;
}

} // namespace yuzu::remote_access_audit

#endif // defined(__APPLE__)
