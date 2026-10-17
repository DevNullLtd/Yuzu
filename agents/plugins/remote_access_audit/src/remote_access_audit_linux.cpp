/**
 * remote_access_audit_linux.cpp -- Linux leg: sshd_config (Include followed), per-account
 * authorized_keys fingerprints and sshd's enablement via `systemctl is-enabled` (rung 2, a
 * bounded argv runner; chosen over the sd-bus GetUnitFileState API to avoid a system dependency).
 *
 * Only the path binding and the runner live here: the reads are
 * remote_access_audit_posix_fs.hpp and every decision (refused != absent, Include order,
 * network-mount skips, budgets) is `list_posix` in remote_access_audit_legs.hpp.
 */
#include "remote_access_audit_legs.hpp"

#if defined(__linux__)

#include "remote_access_audit_posix_fs.hpp"

namespace yuzu::remote_access_audit {

int run_linux(yuzu::CommandContext& ctx) {
    // Built per call, inside execute_list's containment, not as a dlopen-time global.
    Paths p;
    p.os = "linux";
    p.config = "/etc/ssh/sshd_config";
    p.home_parents = {"/home"};
    p.single_homes = {"/root"};
    p.mounts = [] { return linux_mountinfo_prefixes("/proc/self/mountinfo"); };
    p.run = [](const std::vector<std::string>& args, const yuzu::agent::SubprocessOptions& opts) {
        // The tool path comes from probing the two absolute locations; an unresolvable tool
        // is an EMPTY argv, which the runner answers as spawn_error without spawning.
        const auto tool = yuzu::agent::probe_tool_path({"/usr/bin/systemctl", "/bin/systemctl"});
        std::vector<std::string> argv;
        if (!tool.empty()) {
            argv.push_back(tool);
            argv.insert(argv.end(), args.begin(), args.end());
        }
        // sink: remote_access_audit/run_linux#1 -- systemctl is-enabled <unit> (rung 2 argv; chosen over the sd-bus GetUnitFileState API to avoid a system dependency)
        return yuzu::agent::run_bounded_subprocess(argv, opts);
    };
    report_list(ctx, list_posix(make_posix_fs(p)));
    return 0;
}

} // namespace yuzu::remote_access_audit

#endif // defined(__linux__)
