/**
 * platform_security_legs.hpp -- the seam between the portable plugin TU and the per-OS
 * leg TUs. Each entry point returns 0 for every data-level outcome (degraded reads go
 * through set_result_status); only execute() converts an exception to rc 1. Declared
 * unconditionally; each leg TU self-gates its definition (*_win: platform_security_win.cpp).
 */
#pragma once

#include "platform_security_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <vector>

namespace yuzu::platform_security {

int collect_secure_boot_linux(yuzu::CommandContext& ctx);
int collect_secure_boot_macos(yuzu::CommandContext& ctx);
int collect_secure_boot_win(yuzu::CommandContext& ctx);

int collect_code_integrity_linux(yuzu::CommandContext& ctx);
int collect_code_integrity_macos(yuzu::CommandContext& ctx);
int collect_code_integrity_win(yuzu::CommandContext& ctx);

/// Writes every row, then the status via select_status; every leg (Windows too) uses it.
inline void emit_rows(yuzu::CommandContext& ctx, const std::vector<PlatformRow>& rows,
                      const yuzu::shared::ConstraintAccumulator& acc) {
    for (const auto& r : rows)
        ctx.write_output(format_row(r));
    const auto s = select_status(acc, any_denied(rows));
    ctx.set_result_status(s.status, s.completeness, s.provenance);
}

} // namespace yuzu::platform_security
