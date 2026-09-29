/**
 * privacy_permissions_legs.hpp -- the seam between the portable plugin TU and the per-OS
 * leg TUs. Each collect_* is defined by exactly one leg TU (self-#if-gated internally, same
 * shape as platform_security_legs.hpp / firmware_posture); the portable TU declares and calls
 * all three unconditionally.
 *
 * Only the Linux leg reads today; collect_macos_permissions/collect_windows_permissions are
 * PLANNED placeholders (privacy_permissions_macos.cpp / privacy_permissions_win.cpp) that push
 * one whole-source `unsupported` row with `<os>:planned` in `raw` and set the typed result
 * status directly -- UNAVAILABLE/PARTIAL with `<os>:planned` as the provenance -- deliberately
 * bypassing the shared emit_rows()/select_status(), which is scoped to the Linux leg's own
 * "genuinely reachable mechanism, definitively no session" case (UNAVAILABLE/FULL, the fixed
 * generic token portal:unavailable). Same shape as browser_policy_legs.hpp's
 * mark_result_planned; browser_policy has no shared row model to reuse it from, this plugin
 * does, hence no separate helper here.
 *
 * WHEN A LEG LANDS (macOS TCC.db, Windows ConsentStore): replace its placeholder body with the
 * real read, then grep the tree for "planned" and "follows as its own PR" and update every
 * hit -- known sites at the time this was written: the descriptor legs in
 * privacy_permissions_plugin.cpp (support level, mechanism, fallback; the leg-hash changes, so
 * run `plugin_doc_gen.py --stamp` for both samples), the yaml header comment and `platforms`
 * column, the README (How it works, the mermaid diagram, Privileges, Result status, Sample,
 * Caveats), docs/agent-privilege-model.md's row, the capability matrix row and counts, the
 * capability-map cell, docs/enterprise-readiness-soc2-first-customer.md's two hunks, the
 * changelog fragment, and test_privacy_permissions_local_dispatcher.cpp's macOS-only
 * `has("location")` assertion (currently commented out -- the placeholder emits one
 * whole-source row, not a per-category one).
 */
#pragma once

#include "privacy_permissions_parsers.hpp"

#include <yuzu/plugin.hpp>

namespace yuzu::privacy_permissions {

int collect_linux_permissions(yuzu::CommandContext& ctx);
int collect_macos_permissions(yuzu::CommandContext& ctx);
int collect_windows_permissions(yuzu::CommandContext& ctx);

/// Writes every row then the one status the rows collectively imply. Shared by all three legs
/// so the status-selection decision lives in exactly one place.
inline int emit_rows(yuzu::CommandContext& ctx, const std::vector<PermissionRow>& rows,
                     const yuzu::shared::ConstraintAccumulator& acc, bool unavailable) {
    for (const auto& r : rows) ctx.write_output(format_row(r));
    const auto st = select_status(acc, any_denied(rows), unavailable);
    ctx.set_result_status(st.status, st.completeness, st.provenance);
    return 0;
}

} // namespace yuzu::privacy_permissions
