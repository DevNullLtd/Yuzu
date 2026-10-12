/**
 * shares_win.cpp -- Windows leg: PLANNED placeholder.
 *
 * The share enumeration (NetShareEnum level 2 from netapi32, with the administrative
 * STYPE_SPECIAL shares ADMIN$/IPC$/C$ flagged `special`, never hidden) is a follow-up; the
 * descriptor in shares_plugin.cpp declares the leg PLANNED. Until then `list` on Windows
 * answers with exactly one status row (`status|list|unsupported|windows:planned`) -- never
 * an empty success. The row is formatted by the portable report_list in shares_legs.hpp.
 */
#include "shares_legs.hpp"

#if defined(_WIN32)

namespace yuzu::shares {

int run_windows(yuzu::CommandContext& ctx) {
    report_list(ctx, Listing{StatusState::unsupported, "windows:planned", {}});
    return 0;
}

} // namespace yuzu::shares

#endif // defined(_WIN32)
