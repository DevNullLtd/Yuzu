/**
 * shares_macos.cpp -- macOS leg: PLANNED placeholder.
 *
 * Enumerating macOS share points and NFS exports is a follow-up; the descriptor in
 * shares_plugin.cpp declares the leg PLANNED. Until then `list` on macOS answers with exactly
 * one status row (`status|list|unsupported|macos:planned`) -- never an empty success. The row
 * is formatted by the portable report_list in shares_legs.hpp.
 */
#include "shares_legs.hpp"

#if defined(__APPLE__)

namespace yuzu::shares {

int run_macos(yuzu::CommandContext& ctx) {
    report_list(ctx, Listing{StatusState::unsupported, "macos:planned", {}});
    return 0;
}

} // namespace yuzu::shares

#endif // defined(__APPLE__)
