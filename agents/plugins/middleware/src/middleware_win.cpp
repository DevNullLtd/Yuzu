/**
 * middleware_win.cpp -- Windows leg: PLANNED placeholder.
 *
 * The Windows read (the product's registry keys, per the table in
 * agents/shared/middleware_products.hpp) is planned. Until it ships every action reports
 * `status|<action>|unsupported|windows:planned`, matching the PLANNED Windows legs the table
 * declares; the Windows leg replaces this body.
 */
#include "middleware_legs.hpp"

#if defined(_WIN32)

namespace yuzu::middleware {

int run_windows(yuzu::CommandContext& ctx, const Product& p) {
    emit_planned(ctx, p, "windows:planned");
    return 0;
}

} // namespace yuzu::middleware

#endif // defined(_WIN32)
