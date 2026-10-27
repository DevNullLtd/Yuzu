/**
 * hardware_estate_macos.cpp -- macOS leg of chassis/baseboard/swap/machine_id: PLANNED.
 *
 * Every action answers exactly one `status|<action>|unsupported|macos:planned` row until its
 * leg PR lands; none of chassis, baseboard or machine_id has a public source on Apple hardware
 * (S-H1 finding; the hardware UUID from `system` already covers identity), so H.13 moves
 * those three to a typed `unsupported` with a reason. swap will read vm.swapusage.
 */
#include "hardware_estate_legs.hpp"

#include <planned_leg.hpp>

#if defined(__APPLE__)

namespace yuzu::hardware::estate {

int run_macos(yuzu::CommandContext& ctx, Kind k) {
    return yuzu::shared::report_planned(ctx, kind_name(k));
}

} // namespace yuzu::hardware::estate

#endif // defined(__APPLE__)
