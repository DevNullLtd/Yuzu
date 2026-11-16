/**
 * hardware_estate_win.hpp -- declaration of the Windows leg of the four estate actions.
 *
 * Defined in hardware_estate_win.cpp (Windows builds only); hardware_plugin.cpp calls it from
 * the one dispatch line that used to answer `windows:planned`.
 */
#pragma once

#include "hardware_estate_legs.hpp"

#include <yuzu/plugin.hpp>

namespace yuzu::hardware::estate {

#ifdef _WIN32
/// Reads `kind` on this Windows host and answers it through emit_report. Never throws across the
/// plugin boundary. Returns 0 for every outcome, degraded reads included (a degraded read is a typed
/// result, not a failed command); the ONE exception is rc 1 when the report itself cannot be
/// written, so the device record stores the section as unavailable instead of a false "ok".
int run_windows(yuzu::CommandContext& ctx, Kind kind) noexcept;
#endif

} // namespace yuzu::hardware::estate
