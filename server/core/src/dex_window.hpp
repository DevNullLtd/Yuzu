#pragma once

/// @file dex_window.hpp
/// PURE window-selector + OS-filter resolvers for the DEX family — the single
/// source of truth for how the dashboard fragments, the `/api/v1/dex/*` REST
/// surface, the MCP DEX tools, and the in-process `DexApi` seam all interpret
/// the `window`/`os` request tokens (ADR-0031 WS-A4).
///
/// This header is store-free and httplib-free BY CONSTRUCTION (only `<string>`).
/// It exists so the CORE `DexApi` implementation (`dex_api.cpp`) can resolve a
/// window/os token WITHOUT including `dex_routes.hpp` or `dex_view_types.hpp`
/// (both of which pull `<httplib.h>`) — a presentation/transport dependency has
/// no place in a core API impl. `dex_routes.hpp` and `dex_view_types.hpp` now
/// `#include` THIS header and keep re-declaring these symbols transitively, so
/// every existing caller is unaffected (ODR-safe relocation, same pattern as
/// `dex_types.hpp`). The definitions live in the core-only `dex_window.cpp`
/// (relocated from the dashboard TU, ADR-0031 WS-A4 PR-1 F1 fix, closing the
/// #4579 link residual's DEX half).

#include <cstdint>
#include <string>

namespace yuzu::server {

/// Maps the window token "24h"/"7d"/"30d"/"all" (anything else → 7d) to a day
/// count (0 = "all"). Pair with `dex_iso_since` to get the ISO-8601 UTC cutoff.
int dex_window_to_days(const std::string& window);

/// ISO-8601 UTC rendering of an absolute epoch-seconds instant — the shared
/// formatter behind `dex_iso_since`, exposed so a caller that cuts one window
/// at a fixed instant (say a UTC midnight) formats it identically.
std::string dex_iso_at(std::int64_t epoch_seconds);

/// A window of whole UTC days ending at the current day's midnight: the one
/// derivation of the cut that events and exposure share.
struct DexDayWindow {
    std::int64_t since_day{0};  ///< epoch seconds of the UTC midnight `days` days back
    std::int64_t end_day{0};    ///< epoch seconds of the UTC midnight at or before `now_epoch`
    std::string since_iso;      ///< `since_day` as an ISO-8601 UTC instant
};

/// PURE given its inputs: the `days`-day window ending at the UTC midnight at or
/// before `now_epoch`.
DexDayWindow dex_day_window(std::int64_t now_epoch, int days);

/// Turns a resolved day count into an ISO-8601 UTC cutoff ("" when days<=0 =
/// "all") — the day-count half of the shared window vocabulary.
std::string dex_iso_since(int days);

/// Normalises a REST/MCP `os` filter param to a store-ready platform token:
/// "windows"/"linux"/"macos" pass through; anything else (including "all" or
/// empty) returns "" = all-OS. The single source of truth so the machine
/// surfaces' DEX OS-scoping stays identical to the dashboard drilldown.
std::string dex_normalize_os_filter(const std::string& os);

} // namespace yuzu::server
