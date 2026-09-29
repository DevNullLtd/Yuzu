#pragma once

// subprocess_degradation.hpp -- the single acquisition-health decision shared
// by every plugin that gates a subprocess-backed inventory action on whether
// the run should be treated as DEGRADED (Gate-8 governance remediation,
// Wave 4 PR4.3a).
//
// Extracted here rather than left plugin-local after a Gate-8 finding: an
// earlier revision of msi_packages_plugin.cpp hand-duplicated this decision
// inline, and the duplicate quietly omitted the nonzero-exit branch --
// msi_packages never degraded on a clean exit with a nonzero code, while its
// own comment claimed the two plugins were "kept identical ... so they cannot
// drift". A comment asserting shared logic that does not exist is a truth
// finding regardless of how small it looks, and the actual fix is to share
// the function, not just correct the comment. Pure and header-only so it is
// table-testable on every host without linking the subprocess runner or any
// platform-specific acquisition code -- the plugin's own
// run_bounded_subprocess call is the impure shell; this header only ever
// sees the outcome.

namespace yuzu::shared {

// Whether a completed subprocess run should be treated as a DEGRADED
// acquisition -- the most security-relevant branch in every plugin that
// calls this: it decides whether a possibly-truncated enumeration is
// published as a host's authoritative inventory, or the collection is
// reported as failed instead.
//
// `reason_is_exited` is `termination_reason == TerminationReason::exited`.
// Taking a bool rather than the enum keeps this header free of an
// agent-core include, so a pure-parser unit test can exercise this
// decision without linking the runner.
//
// The rules, and why:
//   - anything other than a clean `exited` is degraded. The enum has six
//     states; testing the individual timed_out/tool_ran/output_truncated
//     flags misses `signaled` (OOM kill), `cancelled` (shutdown) and
//     `line_limit`, all of which leave those flags clear while still
//     truncating the output.
//   - a truncated capture is degraded even on a clean exit.
//   - a nonzero exit is degraded UNLESS the caller opts out. Every
//     top-level enumerator these plugins run exits 0 on a healthy host;
//     the one documented benign nonzero (installed_apps: a per-ID
//     `pkgutil --pkg-info` for a receipt removed between enumeration and
//     lookup) is opted out at that single call site, never blanket-wide.
[[nodiscard]] inline bool is_degraded_run(bool reason_is_exited, int exit_code,
                                          bool output_truncated,
                                          bool tolerate_nonzero_exit) {
    if (!reason_is_exited)
        return true;
    if (output_truncated)
        return true;
    return !tolerate_nonzero_exit && exit_code != 0;
}

} // namespace yuzu::shared
