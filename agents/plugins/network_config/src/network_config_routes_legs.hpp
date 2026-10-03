/**
 * network_config_routes_legs.hpp — the seam between the portable plugin TU and
 * the three per-OS `routes` leg TUs (modelled on system_hardening_legs.hpp).
 *
 * Declared unconditionally so every TU sees one signature on every OS; only the
 * DEFINITION is self-gated (each leg TU wraps its whole body in
 * `#if defined(__linux__|__APPLE__|_WIN32)`), and the plugin TU calls only the
 * host leg. Each entry point is a READ that returns 0 for every data-level
 * outcome: an unreadable or incomplete table is reported through
 * set_result_status, never as an empty success; `do_routes` in the plugin TU alone
 * converts an escaped exception into rc 1.
 */
#pragma once

#include <string>
#include <vector>

#include <constraint_accumulator.hpp> // yuzu::shared::ConstraintAccumulator

#include <yuzu/plugin.hpp>

#include "network_config_routes_parsers.hpp"

namespace yuzu::network_config {

int collect_routes_linux(yuzu::CommandContext& ctx);
int collect_routes_macos(yuzu::CommandContext& ctx);
int collect_routes_win(yuzu::CommandContext& ctx);

// Provenance tokens shared by the legs. `network_config:<lower_snake>` is the
// plugin's existing convention (see do_arp()).
inline constexpr const char* kTokRowCap = "network_config:routes_row_cap_reached";

/// Write every row, then the typed status. A table that could not be read at all
/// (`unavailable`) is UNAVAILABLE/PARTIAL; one that was read but is incomplete or
/// reduced (row cap, malformed record, multipath collapsed to its first nexthop,
/// an unresolved nexthop object) is CONSTRAINED/PARTIAL with every accumulated
/// token as the reason; otherwise OK/FULL. An empty row set with OK/FULL is a
/// genuinely empty routing table, never a failed read.
inline void emit_routes(yuzu::CommandContext& ctx, const std::vector<RouteRow>& rows,
                        const yuzu::shared::ConstraintAccumulator& acc, bool unavailable) {
    for (const auto& r : rows)
        ctx.write_output(format_route_row(r));
    if (unavailable) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              acc.reason());
    } else if (acc.any_failure()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              acc.reason());
    } else {
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, {});
    }
}

} // namespace yuzu::network_config
