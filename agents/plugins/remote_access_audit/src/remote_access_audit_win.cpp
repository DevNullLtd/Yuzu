/**
 * remote_access_audit_win.cpp -- Windows leg: PLANNED placeholder (the descriptor says so).
 * `list` answers with exactly one row, `status|list|unsupported|windows:planned`, never an
 * empty success.
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
