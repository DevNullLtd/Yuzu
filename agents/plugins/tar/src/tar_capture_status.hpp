#pragma once

// tar_capture_status.hpp -- pure predicate for whether a bounded-subprocess
// capture is complete enough to trust as an authoritative TAR snapshot.
//
// Background: run_bounded_subprocess (agents/core/include/yuzu/agent/
// subprocess_runner.hpp) distinguishes "the child ran to completion" from
// "the deadline/output cap cut it off" via SubprocessResult::{tool_ran,
// timed_out, output_truncated, exit_code}. Several TAR collectors migrated
// from popen to that runner but kept the old popen-era check (only
// `tool_ran`), so a command that hit the deadline or the output cap still
// had its (partial) lines/output parsed and diffed against the previous
// COMPLETE snapshot -- fabricating durable "stopped"/"removed" forensic
// events for every row the partial run happened not to reach, followed by
// compensating false "started"/"appeared" events once a complete run
// replaces the partial one as the new baseline. This header is the single
// place that decision is made, so it is unit-testable without spawning a
// process (tests/unit/test_tar_service.cpp, tests/unit/test_tar_mapdrive.cpp)
// and every collector site applies the identical policy.
//
// zero_exit_required defaults to true because every command this repo wraps
// through the runner today (systemctl list-units, launchctl list, smbstatus
// -b, wevtutil qe, journalctl -u ... -n) is verified or documented to exit 0
// on a normal empty-result run -- see the call sites in
// tar_service_collector.cpp / tar_mapdrive_collector.cpp for what was
// verified on a live host versus assumed from documented behaviour. A future
// command whose *documented* success path is legitimately non-zero (this
// repo has been bitten by exactly that with `dnf check-update` exiting 100)
// must pass zero_exit_required=false at its own call site rather than
// weakening this default for everyone.

#include <cstddef>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace yuzu::tar {

/// The single exception type every TAR collector throws to report an
/// incomplete capture (a failed read, a kernel/parser-reported truncation,
/// or an entry-cap reached before the whole table was consumed) --
/// service/mapdrive's subprocess legs, and every ARP/mapdrive native leg.
/// collect_or_retain() below catches ONLY this type (round 3, B3-003): an
/// earlier cut caught bare `std::exception`, which would also swallow a
/// genuine std::bad_alloc or other programming/allocation failure thrown out
/// of a collector and misreport it as ordinary capture incompleteness --
/// masking, not just retrying, a real bug. A dedicated type also makes the
/// contract self-documenting: catching `IncompleteCaptureError` by name says
/// exactly what is being tolerated, where `std::exception` said nothing.
struct IncompleteCaptureError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

/// Why a capture was (or was not) judged complete -- `complete` is the
/// verdict a caller acts on; `reason` is populated only when `!complete`,
/// for logging (never a fabricated verdict, never silent).
struct CaptureCompleteness {
    bool complete{false};
    std::string reason;
};

/// Whether appending one more row to a size-`size_before_push` collection
/// would exceed `cap` -- the single decision every capped collector loop
/// must apply BEFORE appending the candidate row, never after. Extracted
/// (round 3, B3-004/B3-005) because the Windows ARP and Windows mapdrive
/// (WNet outbound + NetSessionEnum inbound) loops each re-implemented this
/// check inline, AFTER the push, which misclassifies an exact-cap table as
/// truncated: the cap-th row is appended, size becomes == cap, and the
/// post-push check then (wrongly) declares the table truncated even though
/// no row was actually omitted. Every platform's capped loop must call this
/// BEFORE push_back so only a genuine (cap+1)-th candidate establishes
/// truncation. Pure and compiled on every platform (unlike the #ifdef-gated
/// collector loops themselves), so this exact decision is unit-tested
/// directly (tests/unit/test_tar_capture_status.cpp) independent of which
/// OS's loop calls it -- the gap B3-005 identifies: the off-by-one survived
/// two review rounds because nothing exercised the real per-platform cap
/// decision, only a stand-in throw.
inline bool would_exceed_cap(std::size_t size_before_push, std::size_t cap) {
    return size_before_push >= cap;
}

/// True when `status` is NOT one of an enumeration API's documented
/// terminal/exempt codes for the call site it came from -- e.g. {NO_ERROR}
/// for a WNetOpenEnumW open (any other status is a real open failure, not
/// "no connected resources"), {NO_ERROR, ERROR_NO_MORE_ITEMS} for a
/// WNetEnumResourceW page (NO_ERROR means "more rows, keep paging",
/// ERROR_NO_MORE_ITEMS means "table exhausted, stop cleanly" -- any other
/// code is an unexpected provider/transport failure), or {NERR_Success} for
/// a NetSessionEnum result once its own ERROR_MORE_DATA paging and
/// ERROR_ACCESS_DENIED (a documented, constrained-empty outcome handled
/// separately by the caller) are already accounted for.
///
/// BR4-003 (round 4): tar_mapdrive_collector.cpp's Windows legs previously
/// conflated any unexpected WNet/NetSessionEnum status with normal
/// enumeration completion (a bare `if (rc != NO_ERROR) break/return`),
/// so a transient provider error could silently persist a partial
/// outbound/inbound map set as though it were the complete live snapshot.
/// This predicate is the single, shared "is this status one of the
/// documented non-failure outcomes for this call" decision every Windows
/// mapdrive enumeration site now applies before deciding to throw
/// IncompleteCaptureError -- extracted as plain `unsigned long` codes (not
/// the WinAPI DWORD/NET_API_STATUS typedefs) and an initializer_list of
/// acceptable codes so it compiles and is unit-tested on every OS with
/// fixture status codes standing in for real WNet/NetApi results, exactly
/// like classify_subprocess_capture / would_exceed_cap above.
inline bool is_unexpected_enumeration_status(unsigned long status,
                                              std::initializer_list<unsigned long> acceptable) {
    for (auto code : acceptable) {
        if (status == code)
            return false;
    }
    return true;
}

/// Pure completeness check over a bounded-subprocess result's status fields
/// (passed individually rather than as a SubprocessResult so this header
/// stays free of any dependency on agents/core, and so a test can construct
/// every combination directly). A capture is authoritative only when the
/// child actually ran, was not killed at the deadline, was not cut off by
/// the output cap, and -- unless the caller says this command's success is
/// legitimately non-zero -- exited 0.
inline CaptureCompleteness classify_subprocess_capture(bool tool_ran, bool timed_out,
                                                        bool output_truncated, int exit_code,
                                                        bool zero_exit_required = true) {
    if (!tool_ran)
        return CaptureCompleteness{.complete = false, .reason = "spawn failed"};
    if (timed_out)
        // BR-007: `timed_out` is set for BOTH a genuine wall-clock deadline
        // AND an explicit cancel request (SubprocessResult::timed_out's own
        // documented contract, subprocess_runner.hpp) -- this header stays
        // free of any agents/core dependency (see the header comment above)
        // so it cannot take a TerminationReason to disambiguate. "deadline
        // exceeded" alone previously misreported a deliberate shutdown
        // cancellation as a timeout, sending an operator to tune timeouts
        // for a run that was never slow. Honest combined wording until the
        // enum dependency is accepted.
        return CaptureCompleteness{.complete = false, .reason = "deadline/cancelled"};
    if (output_truncated)
        return CaptureCompleteness{.complete = false, .reason = "output capped"};
    if (zero_exit_required && exit_code != 0)
        return CaptureCompleteness{.complete = false,
                                   .reason = "exit code " + std::to_string(exit_code)};
    return CaptureCompleteness{.complete = true, .reason = {}};
}

/// Outcome of an incomplete-capture-aware snapshot collection: either the
/// collector ran to completion (`current` holds the snapshot) or it threw
/// (an incomplete/failed/truncated/capped capture, however the specific
/// collector detected that -- subprocess status via
/// classify_subprocess_capture above, or a platform syscall's own error
/// contract for the native ARP/mapdrive legs), in which case `current` is
/// empty and `skip_reason` carries the thrown what() for logging.
template <typename T>
struct CollectOrRetain {
    std::optional<T> current;
    std::string skip_reason;
};

/// The single collect-or-retain seam every TAR snapshot-diff source applies
/// (service, mapdrive, arp): call `collect`, and on a thrown
/// IncompleteCaptureError -- the shared, dedicated signal a collector uses
/// to report "this capture did not complete" -- return an empty result
/// instead of propagating, so the caller's existing "skip this tick's diff
/// and state advance, retain the previous baseline" branch (`if (current) {
/// ... }` at every tar_plugin.cpp call site) is the ONLY place that decision
/// is made. A free function taking the collector as a parameter (rather
/// than each call site's own inline try/catch) means a test can inject a
/// fixture collector that throws/returns on demand and assert the exact
/// skip/retain/recover behaviour without a live syscall or subprocess
/// (tests/unit/test_tar_capture_status.cpp).
///
/// Catches ONLY IncompleteCaptureError (round 3, B3-003) -- previously this
/// caught bare `std::exception`, so a genuine std::bad_alloc or other
/// allocation/programming failure thrown out of a collector was silently
/// reinterpreted as ordinary capture incompleteness (retained baseline,
/// logged, tick continues) instead of surfacing as the real bug it is. Any
/// other std::exception now propagates out of collect_or_retain, out of
/// collect_fast_impl/collect_slow_impl, and up to agent.cpp's own
/// defence-in-depth catch around plugin execute() (agents/core/src/agent.cpp
/// -- frozen for this branch, read not edited), which is the actual safety
/// net for a plugin's unexpected exception; it is not this seam's job.
template <typename CollectFn>
auto collect_or_retain(CollectFn&& collect) {
    using T = std::invoke_result_t<CollectFn>;
    CollectOrRetain<T> result;
    try {
        result.current = std::forward<CollectFn>(collect)();
    } catch (const IncompleteCaptureError& e) {
        result.skip_reason = e.what();
    }
    return result;
}

/// The `snapshot` action's (do_snapshot, tar_plugin.cpp) single honesty
/// decision (round 3, B3-002): given the names of every enabled source that
/// collect_or_retain skipped this pass (arp/service/mapdrive -- whichever
/// legs threw IncompleteCaptureError), produce the exact response line the
/// action writes. Previously `snapshot` unconditionally reported
/// "tar|snapshot|complete" even when a source was classified incomplete and
/// silently skipped, leaving operator/agentic consumers unable to tell a
/// complete forced snapshot from one that quietly retained stale state.
/// Extracted to a pure function (rather than inlined at the do_snapshot call
/// site) so the exact wording is unit-tested directly
/// (tests/unit/test_tar_capture_status.cpp) without standing up a live
/// TarPlugin/CommandContext/database.
inline std::string snapshot_result_line(const std::vector<std::string>& skipped_sources) {
    if (skipped_sources.empty())
        return "tar|snapshot|complete";
    std::string joined;
    for (std::size_t i = 0; i < skipped_sources.size(); ++i) {
        if (i)
            joined += ',';
        joined += skipped_sources[i];
    }
    return "tar|snapshot|partial|" + joined;
}

/// The `snapshot` action's SECOND honesty decision (BR4-001, round 4):
/// given the three per-phase return codes do_snapshot's own three
/// collect_fast_impl / collect_slow_impl / do_collect_software calls
/// produced, decide which phase names to add to the skipped_sources list
/// snapshot_result_line above renders, and the action's own exit code.
///
/// Previously do_snapshot called all three as bare expression statements
/// and discarded every return value, so an ordinary persistence failure
/// inside any of them (e.g. "error|service insert failed", already written
/// to ctx by the failing phase itself) still produced
/// "tar|snapshot|complete" and a zero return code -- collect_or_retain's
/// IncompleteCaptureError skip path was the ONLY failure snapshot_result_line
/// could ever report; a plain `return 1` from a failed DB write was
/// invisible to it. Extracted as a pure function over three plain `int`s
/// (not a live TarPlugin/CommandContext/database -- TarPlugin is
/// translation-unit-local, so it cannot be constructed from
/// tests/unit/*.cpp) so this exact aggregation is unit-tested with fixture
/// return codes standing in for do_snapshot's three real calls.
struct SnapshotPhaseOutcome {
    std::vector<std::string> failed_phases; // appended to skipped_sources, in call order
    int return_code{0};
};

/// `has_earlier_skips` folds in whatever collect_or_retain already pushed
/// onto skipped_sources BEFORE this call (arp/service/mapdrive -- the legs
/// that throw IncompleteCaptureError and are silently retained rather than
/// returning a nonzero phase rc). Without it, a forced snapshot that
/// retained one of those sources still returned rc 0 here -- the phase
/// integers were all zero -- and a generic/MCP/automation consumer reading
/// only the action's return code (not the "tar|snapshot|partial|<sources>"
/// text line) saw a clean SUCCESS for a snapshot that silently kept stale
/// state (adversarial-review finding, round 5). A partial snapshot must
/// never report success at the return-code level, regardless of which of
/// the two independent mechanisms (a failed phase rc, or an earlier
/// collect_or_retain skip) produced the partial-ness.
inline SnapshotPhaseOutcome snapshot_phase_outcome(int fast_rc, int slow_rc, int software_rc,
                                                   bool has_earlier_skips = false) {
    SnapshotPhaseOutcome out;
    if (fast_rc != 0)
        out.failed_phases.push_back("collect_fast");
    if (slow_rc != 0)
        out.failed_phases.push_back("collect_slow");
    if (software_rc != 0)
        out.failed_phases.push_back("software");
    out.return_code = (out.failed_phases.empty() && !has_earlier_skips) ? 0 : 1;
    return out;
}

} // namespace yuzu::tar
