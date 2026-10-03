/**
 * system_hardening_legs.hpp -- the seam between the portable plugin TU and
 * the three per-OS leg TUs (modelled on peripherals_legs.hpp /
 * disk_actions_legs.hpp). Each entry point is a READ that returns 0 for every
 * data-level outcome: an unreadable key is a degraded read reported through
 * set_result_status, an absent key is not a failure at all; the portable
 * `execute()` alone converts an escaped exception into rc 1.
 *
 * Declared unconditionally so every TU sees one signature on every OS; only
 * the DEFINITION is self-gated (each leg TU wraps its whole body in
 * `#if defined(_WIN32|__linux__|__APPLE__)`), and the plugin TU calls only
 * the host leg. collect_posture_win is defined by system_hardening_win.cpp.
 */
#pragma once

#include "system_hardening_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <vector>

namespace yuzu::system_hardening {

int collect_posture_linux(yuzu::CommandContext& ctx);
int collect_posture_macos(yuzu::CommandContext& ctx);
int collect_posture_win(yuzu::CommandContext& ctx);

/// Writes every row, then the CC-07 status via select_status: OK/FULL when acc
/// holds no failure token; PERMISSION_DENIED/PARTIAL when a read was refused
/// (EACCES/EPERM); else CONSTRAINED/PARTIAL, with the accumulated tokens as the
/// reason. Each `unreadable` key adds one `<key>:<cause>` token; an absent optional
/// key adds none and never downgrades the run on its own. The one token that is
/// not a key's is the Linux backstop `proc_sys:not_visible` (all eleven keys ENOENT
/// on a confirmed procfs), which makes the run CONSTRAINED with every row `absent`.
inline void emit_posture(yuzu::CommandContext& ctx, const std::vector<PostureRow>& rows,
                         const yuzu::shared::ConstraintAccumulator& acc) {
    for (const auto& r : rows)
        ctx.write_output(format_posture_row(r));
    const auto s = select_status(acc, any_denied(rows));
    ctx.set_result_status(s.status, s.completeness, s.provenance);
}

} // namespace yuzu::system_hardening
