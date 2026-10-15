/**
 * platform_security_macos.cpp -- macOS leg.
 *
 * secure_boot: an honest UNSUPPORTED leg (no public API for the boot-security
 * policy; bputil is a recovery-environment tool and is not shelled out to).
 * SIP, the closest public posture, is reported under code_integrity.
 *
 * code_integrity: Gatekeeper (`spctl --status`) and SIP (`csrutil status`), declared
 * rung-2 argv leaves (no library API for either state), run through
 * run_bounded_subprocess with a literal absolute argv (no PATH search, no shell), a
 * deadline, stdout only and a byte cap. What a run MEANS is decided by tool_row in the
 * parsers header. vuln_scan runs the same commands via popen (rung 3); not edited here.
 *
 * NOT DONE, decided: the roadmap row also names Security.framework `SecStaticCode*`
 * for "code-signing enforcement". Checked (2026-09-22) and rejected: every
 * `SecStaticCode*` API (`SecStaticCodeCheckValidity` and friends) validates ONE named
 * code object's OWN signature -- there is no machine-wide "is code-signing
 * enforcement on" query in Security.framework, the way `spctl --status` and
 * `csrutil status` report Gatekeeper/SIP policy. Reading it against the agent's own
 * binary would report whether the AGENT is signed, not the host's posture -- a
 * different question this action doesn't ask. Same shape as the Windows leg's WLDP decision (platform_security_win.cpp banner):
 * the roadmap named an API, the API doesn't provide what the row needs, so it stays
 * unshipped rather than wired to answer a question it can't actually answer.
 */
#include "platform_security_legs.hpp"

#if defined(__APPLE__)

#include <yuzu/agent/subprocess_runner.hpp>

#include <chrono>
#include <string>
#include <vector>

namespace yuzu::platform_security {

namespace {

/// Runs one rung-2 site: `which` is the #<n> of the site id (1 = spctl, 2 = csrutil).
/// Both tools answer in well under a second; the deadline only bounds a wedged one.
ToolOutcome do_code_integrity(int which) {
    yuzu::agent::SubprocessOptions opts;
    opts.deadline = std::chrono::milliseconds{5000};
    opts.max_lines = 16;
    opts.output_cap_bytes = 16 * 1024;
    opts.merge_stderr = false;
    const auto outcome = [](const yuzu::agent::SubprocessResult& r) {
        return ToolOutcome{r.tool_ran, r.timed_out, r.output_truncated, r.exit_code, r.spawn_errno, r.output};
    };
    if (which == 1) {
        // sink: platform_security/do_code_integrity#1 -- spctl --status (rung 2 argv; no library API for Gatekeeper enforcement state)
        return outcome(yuzu::agent::run_bounded_subprocess({"/usr/sbin/spctl", "--status"}, opts));
    }
    // sink: platform_security/do_code_integrity#2 -- csrutil status (rung 2 argv; no library API for SIP enforcement state)
    return outcome(yuzu::agent::run_bounded_subprocess({"/usr/bin/csrutil", "status"}, opts));
}

} // namespace

int collect_secure_boot_macos(yuzu::CommandContext& ctx) {
    ctx.write_output(format_row(unsupported_row(kSecureBootAction, "macos", "secure_boot")));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_FULL,
                          "no public API; SIP reported under code_integrity");
    return 0;
}

int collect_code_integrity_macos(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    emit_rows(ctx, code_integrity_rows_macos(do_code_integrity, acc), acc);
    return 0;
}

} // namespace yuzu::platform_security

#endif // defined(__APPLE__)
