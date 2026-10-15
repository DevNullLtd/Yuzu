/**
 * update_source_trust_win.cpp -- Windows leg: PLANNED placeholder.
 *
 * The Windows WSUS / Automatic Updates policy read
 * (HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate{,\AU}) is not
 * implemented yet; the descriptor in update_source_trust_plugin.cpp declares the
 * leg PLANNED. Until then `sources` on Windows answers with exactly one status row
 * (`status|sources|unsupported|windows:planned`) -- never an empty success.
 * No decision logic lives here, and none is a candidate for a Windows-only
 * code path: the row is formatted by the portable, unit-tested
 * report_unavailable in update_source_trust_legs.hpp.
 */
#include "update_source_trust_legs.hpp"

#if defined(_WIN32)

namespace yuzu::update_source_trust {

int run_windows(yuzu::CommandContext& ctx) {
    report_unavailable(ctx, kWindowsPlannedToken);
    return 0;
}

} // namespace yuzu::update_source_trust

#endif // defined(_WIN32)
