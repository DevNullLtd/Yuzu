#include "dex_window.hpp"

/// @file dex_window.cpp
/// Definitions for the PURE window-selector + OS-filter resolvers declared in
/// `dex_window.hpp` (ADR-0031 WS-A4). Relocated VERBATIM from the presentation
/// TU `dex_routes.cpp`, where they were defined despite being declared in this
/// store-free/httplib-free header (PR-1 F1 fix, Fable review 2026-09-28) —
/// `dex_api.cpp` and `dex_read_model.cpp` (both core) were linking against a
/// presentation TU's object file for `dex_window_to_days`/`dex_iso_since`/
/// `dex_normalize_os_filter`, invisible to the seam gate
/// (`scripts/ci/check-seam-closure.py`), which only checks include closure,
/// not link closure. `dex_routes.cpp` keeps its own file-local
/// `window_to_days`/`iso_days_ago` helper names (used at ~20 call sites across
/// its route handlers) — they now simply forward to the functions defined
/// here, so there is exactly one implementation of each mapping. No logic
/// changes.

#include <chrono>
#include <ctime>

namespace yuzu::server {

// Map the window selector value to a day count (0 = "all").
int dex_window_to_days(const std::string& window) {
    if (window == "24h") return 1;
    if (window == "30d") return 30;
    if (window == "all") return 0;
    return 7; // "7d" / default
}

// ISO-8601 UTC cutoff for "N days ago"; "" for days<=0 (the "all" window, where a
// per-device-days rate is ill-defined). Mirrors guardian_ingest's ts_to_iso8601.
std::string dex_iso_since(int days) {
    if (days <= 0)
        return {};
    const auto t = std::chrono::system_clock::now() - std::chrono::hours(24 * days);
    std::time_t tt = std::chrono::system_clock::to_time_t(t);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

std::string dex_normalize_os_filter(const std::string& os) {
    return (os == "windows" || os == "linux" || os == "macos") ? os : std::string{};
}

} // namespace yuzu::server
