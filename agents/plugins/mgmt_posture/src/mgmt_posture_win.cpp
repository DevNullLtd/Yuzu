/**
 * mgmt_posture_win.cpp -- Windows leg: PLANNED placeholder.
 *
 * The join/enrolment read (NetGetJoinInformation plus the HKLM Enrollments and
 * CloudDomainJoin\JoinInfo registry keys) is a follow-up that needs a real-host probe
 * first; the descriptor in mgmt_posture_plugin.cpp declares the leg PLANNED. Until
 * then `posture` on Windows answers with exactly one status row
 * (`status|posture|unsupported|windows:planned`) -- never an empty success. The row is
 * formatted by the portable report_unavailable in mgmt_posture_legs.hpp.
 */
#include "mgmt_posture_legs.hpp"

#if defined(_WIN32)

namespace yuzu::mgmt_posture {

int run_windows(yuzu::CommandContext& ctx) {
    report_unavailable(ctx, kWindowsPlannedToken);
    return 0;
}

} // namespace yuzu::mgmt_posture

#endif // defined(_WIN32)
