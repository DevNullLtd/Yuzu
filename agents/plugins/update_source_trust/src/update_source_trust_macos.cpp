/**
 * update_source_trust_macos.cpp -- macOS leg: PLANNED placeholder.
 *
 * The macOS Software Update policy read (the local and the MDM-managed
 * com.apple.SoftwareUpdate.plist, decoded in-process with CoreFoundation)
 * is not implemented yet; the descriptor in update_source_trust_plugin.cpp
 * declares the leg PLANNED. Until then `sources` on macOS answers with exactly
 * one status row (`status|sources|unsupported|macos:planned`) -- never an empty
 * success. No decision logic lives here, and none is a candidate for a
 * macOS-only code path: the row is formatted by the portable, unit-tested
 * report_unavailable in update_source_trust_legs.hpp.
 */
#include "update_source_trust_legs.hpp"

#if defined(__APPLE__)

namespace yuzu::update_source_trust {

int run_macos(yuzu::CommandContext& ctx) {
    report_unavailable(ctx, kMacosPlannedToken);
    return 0;
}

} // namespace yuzu::update_source_trust

#endif // defined(__APPLE__)
