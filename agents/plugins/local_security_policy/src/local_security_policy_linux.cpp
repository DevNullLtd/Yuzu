/**
 * local_security_policy_linux.cpp -- Linux leg: bounded reads of login.defs,
 * pwquality/faillock config, /etc/pam.d, audit.rules and sudoers through the
 * shared pure collector (local_security_policy_parsers.hpp).
 *
 * Residual gaps (disclosed in the README caveats too):
 *  - CONTAINERS: these are the files this process can see. The shipped
 *    deploy/docker/Dockerfile.agent image runs as unprivileged `yuzu-agent` and mounts
 *    no host /etc, so every row describes the IMAGE (debian:trixie-slim: no sudo, no
 *    auditd, so sudoers and audit.rules read `absent`), not the host it runs on.
 *  - PAM: only /etc/pam.d/{common-password,system-auth,password-auth} (password) and
 *    {common-auth,common-account,system-auth,password-auth} (lockout) are read -- the
 *    Debian and RHEL alternatives. One missing file is silent while a sibling exists;
 *    only all-missing is a `source_state|absent|/etc/pam.d` row. `@include` lines and
 *    include/substack controls are not followed, and a line that is not
 *    `type control module` is dropped without a row.
 *  - A file read successfully that sets none of the reported keys contributes no row
 *    (e.g. Debian's all-commented faillock.conf); login.defs is filtered to a fixed key
 *    list per action; pwquality.conf.d, faillock drop-ins and /etc/audit/rules.d are
 *    not read.
 */
#include "local_security_policy_legs.hpp"

#if defined(__linux__)

namespace yuzu::local_security_policy {

int collect_linux_policy(yuzu::CommandContext& ctx, std::string_view action) {
    const auto which = parse_local_policy_action(action);
    return apply_collected(
        ctx, collect_file_policy(FileFlavor::Linux, which, posix_read_file, posix_list_dir),
        action_row_prefix(which));
}

} // namespace yuzu::local_security_policy

#endif // defined(__linux__)
