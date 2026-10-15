/**
 * browser_inventory_win.cpp — Windows leg, FINAL placeholder this wave.
 *
 * PLANNED per the descriptor in browser_inventory_plugin.cpp: the real
 * implementation (ProfileList walk + %LOCALAPPDATA% User Data; Program
 * Files Application\<semver> dirs) follows as its own PR. No registry
 * read, no subprocess here -- this body is the whole of this package's
 * Windows leg.
 */
#include "browser_inventory_legs.hpp"

#if defined(_WIN32)

namespace yuzu::browser_inventory {

int run_windows(yuzu::CommandContext& ctx, Action a) {
    mark_planned(ctx, a, "windows");
    return 0;
}

} // namespace yuzu::browser_inventory

#endif // _WIN32
