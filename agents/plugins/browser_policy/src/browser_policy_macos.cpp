/**
 * browser_policy_macos.cpp — macOS leg entry point.
 *
 * PLANNED — follows as its own PR. The /Library/Managed Preferences plist read
 * is not implemented; until it lands the leg reports the honest planned status
 * (one `status` row, UNAVAILABLE, provenance `macos:planned`) rather than an
 * empty success, so a host never reads as "no policy configured" from a leg
 * that did not look.
 */
#include "browser_policy_legs.hpp"

#if defined(__APPLE__)

namespace yuzu::browser_policy {

int run_macos(yuzu::CommandContext& ctx) {
    mark_result_planned(ctx, "macos:planned");
    return 0;
}

} // namespace yuzu::browser_policy

#endif // defined(__APPLE__)
