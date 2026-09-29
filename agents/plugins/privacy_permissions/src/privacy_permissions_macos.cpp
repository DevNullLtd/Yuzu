/**
 * privacy_permissions_macos.cpp -- macOS leg entry point.
 *
 * PLANNED -- follows as its own PR (the TCC.db read; privacy_permissions_macos_parsers.hpp
 * doesn't exist yet). Until it lands this leg reports the honest planned state -- one
 * whole-source row (category "-", state `unsupported`, `macos:planned` in `raw`) and typed
 * result status UNAVAILABLE/PARTIAL with `macos:planned` as the provenance -- rather than an
 * empty success, so a host is never read as "no grants" from a leg that did not look.
 *
 * Deliberately bypasses the shared emit_rows()/select_status(): those exist for the Linux
 * leg's "genuinely reachable mechanism, definitively no session" case, which is
 * UNAVAILABLE/FULL with the fixed generic token portal:unavailable -- a real, complete
 * answer about that one mechanism. A PLANNED leg has not looked at all, so it needs its own
 * PARTIAL/<os>:planned typed provenance, exactly the browser_policy precedent
 * (browser_policy_legs.hpp's mark_result_planned) -- routing this through the generic
 * selector would silently erase that distinction (adversarial-review finding, round 3).
 */
#include "privacy_permissions_legs.hpp"

#if defined(__APPLE__)

namespace yuzu::privacy_permissions {

int collect_macos_permissions(yuzu::CommandContext& ctx) {
    const PermissionRow row{"macos", "-", "-", PermissionState::unsupported, "macos:planned",
                            "-", "-", false};
    ctx.write_output(format_row(row));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          "macos:planned");
    return 0;
}

} // namespace yuzu::privacy_permissions

#endif // defined(__APPLE__)
