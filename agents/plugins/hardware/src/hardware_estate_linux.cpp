/**
 * hardware_estate_linux.cpp -- Linux leg of chassis/baseboard/swap/machine_id: PLANNED.
 *
 * Every action answers exactly one `status|<action>|unsupported|linux:planned` row until its
 * leg PR lands; H.11 reads chassis/baseboard from /sys/class/dmi/id/{chassis_*,board_*}, swap from
 * /proc/swaps, and machine_id as a keyed hash of /etc/machine-id.
 */
#include "hardware_estate_legs.hpp"

#include <planned_leg.hpp>

#if defined(__linux__)

namespace yuzu::hardware::estate {

int run_linux(yuzu::CommandContext& ctx, Kind k) {
    return yuzu::shared::report_planned(ctx, kind_name(k));
}

} // namespace yuzu::hardware::estate

#endif // defined(__linux__)
