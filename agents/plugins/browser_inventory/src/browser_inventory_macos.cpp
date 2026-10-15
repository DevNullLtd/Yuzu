/**
 * browser_inventory_macos.cpp — macOS leg, FINAL placeholder this wave.
 *
 * PLANNED per the descriptor in browser_inventory_plugin.cpp: the real
 * implementation (/Applications/{Google Chrome,Microsoft Edge}.app
 * Info.plist + ~/Library/Application Support walk; Safari bundle + .appex
 * containers) follows as its own PR. No CFPropertyList copy, no bundle
 * walk here -- this body is the whole of this package's macOS leg.
 */
#include "browser_inventory_legs.hpp"

#if defined(__APPLE__)

namespace yuzu::browser_inventory {

int run_macos(yuzu::CommandContext& ctx, Action a) {
    mark_planned(ctx, a, "macos");
    return 0;
}

} // namespace yuzu::browser_inventory

#endif // __APPLE__
