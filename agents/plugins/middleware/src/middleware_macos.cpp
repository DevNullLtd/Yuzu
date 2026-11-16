/**
 * middleware_macos.cpp -- macOS leg: PLANNED placeholder.
 *
 * No product of the table (agents/shared/middleware_products.hpp) has a macOS read yet. Until one
 * ships every action reports `status|<action>|unsupported|macos:planned`, matching the PLANNED
 * macOS legs the descriptor table in middleware_plugin.cpp declares.
 */
#include "middleware_legs.hpp"

#if defined(__APPLE__)

namespace yuzu::middleware {

int run_macos(yuzu::CommandContext& ctx, const Product& p) {
    emit_planned(ctx, p, "macos:planned");
    return 0;
}

} // namespace yuzu::middleware

#endif // defined(__APPLE__)
