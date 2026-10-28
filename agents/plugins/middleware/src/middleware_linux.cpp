/**
 * middleware_linux.cpp -- Linux leg entry point.
 *
 * `run_linux` wraps `lnx::run_linux_at` (middleware_linux_parsers.hpp, runtimes_linux.cpp shape):
 * production passes "/" and `lnx::production_config()`; the unit suite drives `run_linux_at` over a
 * materialized tree. Every action is a READ that returns 0: a degraded read rides the status row and
 * set_result_status (emit_read), never a failed command. The body is compiled on __linux__ only.
 */
#include "middleware_legs.hpp"
#include "middleware_linux_parsers.hpp"

#if defined(__linux__)

namespace yuzu::middleware {

int run_linux(yuzu::CommandContext& ctx, const Product& p) {
    return lnx::run_linux_at(ctx, p, "/", lnx::production_config());
}

} // namespace yuzu::middleware

#endif // defined(__linux__)
