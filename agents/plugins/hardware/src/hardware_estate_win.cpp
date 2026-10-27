/**
 * hardware_estate_win.cpp -- Windows leg of chassis/baseboard/swap/machine_id: PLANNED.
 *
 * Every action answers exactly one `status|<action>|unsupported|windows:planned` row until its
 * leg PR lands; H.5 reads chassis/baseboard from SMBIOS types 3 and 2 through the shared walker
 * (GetSystemFirmwareTable('RSMB'), H.1), swap from Win32_PageFileUsage, and machine_id as a
 * keyed hash of the registry MachineGuid.
 */
#include "hardware_estate_legs.hpp"

#include <planned_leg.hpp>

#if defined(_WIN32)

namespace yuzu::hardware::estate {

int run_windows(yuzu::CommandContext& ctx, Kind k) {
    return yuzu::shared::report_planned(ctx, kind_name(k));
}

} // namespace yuzu::hardware::estate

#endif // defined(_WIN32)
