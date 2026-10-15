/**
 * browser_policy_win.cpp — Windows leg entry point.
 *
 * PLANNED — follows as its own PR. The HKLM\SOFTWARE\Policies registry read is
 * not implemented; until it lands the leg reports the honest planned status
 * (one `status` row, UNAVAILABLE, provenance `windows:planned`) rather than an
 * empty success, so a host never reads as "no policy configured" from a leg
 * that did not look.
 */
#include "browser_policy_legs.hpp"

#if defined(_WIN32)

namespace yuzu::browser_policy {

int run_windows(yuzu::CommandContext& ctx) {
    mark_result_planned(ctx, "windows:planned");
    return 0;
}

} // namespace yuzu::browser_policy

#endif // defined(_WIN32)
