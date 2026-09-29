// tar_cursor_sources.cpp -- assembles the cursor-model sources this agent
// ships. See tar_cursor.hpp for the CursorSource contract.

#include "tar_cursor.hpp"

#include "tar_db.hpp"

namespace yuzu::tar {

// Empty on purpose in this change: the seam ships the contract, the durable
// cursor table and the driver, and each consuming source registers itself here
// when it lands. tar_plugin.cpp already builds cursor_sources_ from this
// function's return value at init(), so a source needs no plugin-side change
// to light up.
std::int64_t lookback_seconds_or_forward_only(TarDatabase& db, const std::string& source,
                                              std::int64_t declared_default) {
    auto stored = db.try_get_config(source + "_lookback_seconds");
    if (!stored)
        return 0; // UNREADABLE -> forward-only. Never inherit the default here.
    if (!stored->has_value())
        return declared_default; // genuinely unset: the documented default applies
    try {
        const auto v = std::stoll(**stored);
        return v < 0 ? 0 : v;
    } catch (...) {
        return 0; // malformed -> forward-only
    }
}

std::vector<std::unique_ptr<CursorSource>> make_cursor_sources() {
    std::vector<std::unique_ptr<CursorSource>> sources;
    sources.push_back(make_power_cursor_source());
    sources.push_back(make_removable_cursor_source());
    return sources;
}

} // namespace yuzu::tar
