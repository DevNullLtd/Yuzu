/**
 * remote_access_audit_macos.cpp -- macOS leg: sshd_config (Include followed), per-account
 * authorized_keys fingerprints and the sshd launchd override state via
 * `launchctl print-disabled system` (rung 2, a bounded argv runner; it works unprivileged).
 *
 * Only the path binding, the mount-table read and the runner live here; every decision is
 * `list_posix` in remote_access_audit_legs.hpp. The mount table comes from
 * getmntinfo_r_np(MNT_NOWAIT), the kernel's cache, which never calls into a wedged server.
 */
#include "remote_access_audit_legs.hpp"

#if defined(__APPLE__)

#include "remote_access_audit_posix_fs.hpp"

#include <cstdlib>
#include <memory>
#include <sys/mount.h>
#include <sys/param.h>

namespace yuzu::remote_access_audit {

namespace {

std::optional<std::vector<std::string>> macos_network_prefixes() {
    struct statfs* raw = nullptr;
    const int n = ::getmntinfo_r_np(&raw, MNT_NOWAIT);
    const std::unique_ptr<struct statfs, decltype(&::free)> mnt{raw, &::free};
    if (n <= 0 || raw == nullptr)
        return std::nullopt;
    std::vector<std::string> out;
    for (int i = 0; i < n; ++i) {
        if (yuzu::shared::is_network_mount_fstype(mnt.get()[i].f_fstypename))
            out.emplace_back(mnt.get()[i].f_mntonname);
    }
    return out;
}

} // namespace

int run_macos(yuzu::CommandContext& ctx) {
    Paths p;
    p.os = "macos";
    p.launchd = true;
    p.config = "/etc/ssh/sshd_config";
    p.home_parents = {"/Users"};
    // canonical spelling: /var is a link to private/var and a home opens hop by hop with no link followed
    p.single_homes = {"/private/var/root"};
    p.min_uid = 500; // an account home, not Shared or a stray entry (autoruns_macos.cpp's rule)
    p.mounts = &macos_network_prefixes;
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
