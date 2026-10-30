#pragma once

/// @file dispatch_record_policy.hpp
/// #4990: the bound on the dispatch-record write for a loop that builds ONE command per target.
///
/// `ServerImpl::build_classified_command` writes the server's record of every dispatch (command id
/// -> plugin, execution id) before the command is sent. The write is best-effort: a failure never
/// refuses the dispatch or holds it beyond a short bound, it only means this command's responses are
/// labelled `~unverified` (response_provenance.hpp, the documented fail-closed outcome) and the
/// failure is counted (`yuzu_exec_correlation_write_degrade_total`).
///
/// A single dispatch pays for that write once, so it keeps the tracker's ordinary lease budget
/// (`ExecutionTracker`'s `kWriteTimeout`, 2 s). A loop that mints one command per agent (today:
/// the operator Guardian rule push, one `__guard__` command id per target) would pay that budget
/// PER AGENT, serialised on one worker thread, ahead of `forward_gateway_pending()`. During a
/// database or pool outage that turns a 5,000-agent push into hours. (The heartbeat reconcile push
/// and the asset-tag push also mint one id per agent, but they are one write per call, not a
/// loop, and keep the ordinary budget; the pool already clamps an acquire on a saturated pool to
/// 500 ms. The quarantine containment reconciler's tick is another per-device loop (up to
/// `kMaxDispatchesPerTick` serial single dispatches) that is NOT latched today: each pays the
/// ordinary budget, so a contended pool delays re-containment, never refuses it (an item of the dispatch-record
/// hardening follow-up, which has no issue number yet). Every other `build_classified_command` caller builds
/// ONE command and fans that same object out, so it is one write per dispatch however many
/// agents it reaches.)
///
/// The fix is CALLER-KEYED, not tracker-wide. A loop declares a `DispatchRecordLatch` and passes
/// its address down to the record write:
///   1. the write uses `kFanOutRecordLeaseTimeout` instead of the tracker's ordinary budget;
///   2. the first failed write TRIPS the latch, and every later write in the SAME loop is skipped
///      (the dispatch still goes out; the skipped record is counted as a degrade exactly like a
///      failed one and its responses are labelled `~unverified`).
/// So an outage costs the loop one short wait, not N. A tracker-wide breaker was rejected on
/// purpose: it would store every ordinary response `~unverified` for as long as it stayed open,
/// including the responses of operator dispatches that never asked for a short wait.
///
/// The key is an EXPLICIT parameter, deliberately not `DispatchCaller::system`: `system` also marks
/// the policy evaluator, the preflight runner, the quarantine reconciler and the scheduled-fire
/// path, which write ONE record per dispatch and must keep the ordinary budget (a shortened lease
/// there would label compliance-check results `~unverified` under ordinary pool contention). The
/// latch is also not a field of `DispatchCaller`, which is identity plumbing.
///
/// SCOPE: one latch per loop, an object local to it. Never a member, never a static, never
/// reused for a second loop: a latch that survives its loop would carry one outage's verdict into
/// the next push. Not thread-safe; the loops that use it are single-threaded by construction.
///
/// RESIDUAL (stated, not hidden): the short lease timeout bounds only the wait for a pooled
/// connection. Once a connection is leased the statement runs under the pool's server-side
/// `lock_timeout` (10 s) and `statement_timeout` (30 s), and a fresh connect can run to the pool's
/// `connect_timeout_s`. The latch makes each of those a once-per-loop cost, not a per-agent one. A
/// per-statement `SET LOCAL` was not added: it needs BEGIN/SET/upsert/COMMIT, four round trips
/// instead of one on the HEALTHY path of every agent in the loop.

#include <chrono>
#include <cstddef>

#include <spdlog/spdlog.h>

namespace yuzu::server {

/// The lease-acquire budget of a dispatch-record write made from a per-target loop.
///
/// Why 250 ms: a healthy pool hands a connection over in well under a millisecond, and the pool
/// itself already clamps a bounded acquire on an already-saturated pool to 500 ms
/// (`PgPool::Options::saturated_fast_fail`); 250 ms sits below that clamp, so it is the effective
/// bound in both the saturated and the merely-slow case, while staying far above scheduler jitter
/// on a loaded host (a spurious trip costs the REST OF ONE LOOP its record labels, so the constant
/// must not be tuned towards zero). The latch means it is paid once per loop: an outage push to
/// 5,000 agents is bounded by this constant, not by 5,000 times the ordinary 2 s budget. Same
/// family as `kContainmentReadSlotWait` (500 ms, server.cpp): a bounded wait that composes with
/// the store's own timeout rather than stacking on it.
inline constexpr std::chrono::milliseconds kFanOutRecordLeaseTimeout{250};

class DispatchRecordLatch {
  public:
    explicit DispatchRecordLatch(const char* loop_label) noexcept : loop_label_(loop_label) {}
    DispatchRecordLatch(const DispatchRecordLatch&) = delete;
    DispatchRecordLatch& operator=(const DispatchRecordLatch&) = delete;

    /// One line when the loop ends, if the latch skipped anything. The per-failure line is
    /// throttled inside the tracker; this one says how much of THIS loop was affected.
    ~DispatchRecordLatch() {
        if (skipped_ > 0)
            spdlog::warn("dispatch record: {} skipped {} record write(s) after the first one "
                         "failed; those commands were still dispatched and their responses will "
                         "be labelled unverified (withheld from readers without the Forensics "
                         "grant)",
                         loop_label_, skipped_);
    }

    /// True once a write in this loop has failed: later writes are skipped.
    [[nodiscard]] bool tripped() const noexcept { return tripped_; }

    /// The loop's first failed write calls this; later writes are skipped.
    void trip() noexcept { tripped_ = true; }

    /// A write that was skipped because the latch was already tripped.
    void note_skipped() noexcept { ++skipped_; }

    [[nodiscard]] std::size_t skipped() const noexcept { return skipped_; }

    /// The lease budget a write made under this latch uses.
    [[nodiscard]] static constexpr std::chrono::milliseconds lease_timeout() noexcept {
        return kFanOutRecordLeaseTimeout;
    }

  private:
    const char* loop_label_;
    bool tripped_{false};
    std::size_t skipped_{0};
};

} // namespace yuzu::server
