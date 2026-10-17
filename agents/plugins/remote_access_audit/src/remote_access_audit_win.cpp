/**
 * remote_access_audit_win.cpp -- Windows leg: PLANNED placeholder.
 *
 * The Windows inbound-access audit (per-profile .ssh\authorized_keys, the
 * %ProgramData%\ssh\administrators_authorized_keys file and sshd_config, with the OpenSSH
 * Server service state) is a follow-up; the descriptor in remote_access_audit_plugin.cpp
 * declares the leg PLANNED. Until then `list` on Windows answers with exactly one status row
 * (`status|list|unsupported|windows:planned`) -- never an empty success. The row is formatted
 * by the portable report_list in remote_access_audit_legs.hpp.
 */
#include "remote_access_audit_legs.hpp"

#if defined(_WIN32)

namespace yuzu::remote_access_audit {

int run_windows(yuzu::CommandContext& ctx) {
    report_list(ctx, Listing{StatusState::unsupported, "windows:planned", {}});
    return 0;
}

} // namespace yuzu::remote_access_audit

#endif // defined(_WIN32)
