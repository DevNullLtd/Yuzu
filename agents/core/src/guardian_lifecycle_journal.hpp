#pragma once

/**
 * guardian_lifecycle_journal.hpp -- the ENGINE-owned durable side of the Guardian
 * lifecycle-audit journal (item 7 PR-Ag; design rev 4.1).
 *
 * Homed on GuardianEngine, NOT GuardianSparkRuntime: the runtime is the
 * detach-survival object (a late SparkEngine handler may run past the engine), so
 * it must own everything it touches and NEVER borrow a KvStore. The engine, by
 * contrast, already borrows the agent-owned KvStore (kv_) with a proven
 * member-destruction-order guarantee - this component makes the same borrow.
 *
 * C2 delivers persist() only; paging + retention (C4/C5) layer on later.
 *
 * CONCURRENCY (updated #2303, #2233 item 4): NOT a general thread-safe object, but
 * it does run under a specific, bounded concurrency in production - persist()
 * executes on the engine mtx_ (heartbeat retry / apply_rules flush / stop-flush)
 * while prune() and page_into_window() run OFF mtx_ on the drain worker's own
 * thread, serialised against each other by paging_mutex_. mark_batch_sent() is a
 * THIRD, independent caller into kv_: it runs wherever the production `send` wrap
 * happens to execute, which since #2233 item 4 is GuardianOutboxSendExecutor's
 * detached worker (guardian_outbox_send_executor.hpp), NOT the drain worker's own
 * thread - so it can now run genuinely concurrently with prune()/page_into_window(),
 * not merely interleaved on one thread as before. That safe overlap rests on: the
 * size gauges being atomic RMW running counters (no lost update across
 * persist-vs-prune-vs-mark_batch_sent), the IJournalStore contract's per-call
 * serialisation (a real KvStore serialises its single connection under one mutex;
 * see kv_store.hpp's IJournalStore doc comment for the contract every implementation
 * must keep - #4153), batch_seq_ being written only by the single persist caller
 * (boot_nonce_ is fixed in the ctor, immutable thereafter), and the seed's absolute
 * store running once in the ctor before publication. mark_batch_sent()'s label is
 * explicitly best-effort (see its own doc comment) - a redundant re-page from a
 * stale-observed label is the worst case, not a correctness break. Do NOT add a
 * second persist caller or a non-RMW gauge write.
 */

#include "guardian_journal_format.hpp"

#include <yuzu/audit_retention_rules.hpp>
#include <yuzu/plugin.h> // YUZU_EXPORT

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>
#include <span>
#include <string>
#include <unordered_set>
#include <type_traits>
#include <utility>

namespace yuzu::agent {

class IJournalStore;
class GuardianSparkRuntime;

/// A token bucket for replay paging (rev-4.1 #8). PROCESS-LIFETIME: it is NOT reset on
/// reconnect, so a flapping agent cannot replay its whole backlog on every reconnect. It
/// DELAYS, never skips - a batch the bucket defers pages on a later pass, and retention (not
/// the bucket) is the only deletion path. That holds only because refill() re-baselines on a
/// BACKWARD clock step rather than waiting the step out; see the note there. now_ms is passed
/// in, so the pacing is deterministic + testable.
class YUZU_EXPORT JournalPagingBucket {
public:
    JournalPagingBucket(double refill_per_sec, double burst)
        : refill_per_sec_(refill_per_sec), burst_(burst), tokens_(burst) {}

    /// Refill for the elapsed time, then report whether at least one token is available.
    bool ready(std::int64_t now_ms) {
        refill(now_ms);
        return tokens_ >= 1.0;
    }
    /// Spend one token - call only after ready() returned true.
    void take() { tokens_ -= 1.0; }
    [[nodiscard]] double tokens() const { return tokens_; } // test introspection

private:
    void refill(std::int64_t now_ms) {
        if (last_ms_ == 0) {
            last_ms_ = now_ms;
            return;
        }
        // Clock stepped BACKWARD: re-baseline instead of waiting for wall time to climb back
        // (#2345 round 7, Sol). Refilling only on now_ms > last_ms_ meant a backward step froze
        // replay for the whole size of the step - hours, after a VM snapshot restore or an NTP
        // correction - while retention's count and byte ceilings, which are clock-free, kept
        // deleting on schedule. Replay stopped with deletion continuing is precisely the unsent
        // loss this journal exists to prevent, and it is the one case the "DELAYS, never skips"
        // note above did not hold for. Re-baselining grants no tokens, so the pacing bound is
        // unchanged; it only stops the deferral from becoming unbounded.
        if (now_ms < last_ms_) {
            last_ms_ = now_ms;
            return;
        }
        if (now_ms > last_ms_) {
            // (std::min), not std::min: MSVC's min() macro would clobber it in a windows.h TU.
            tokens_ = (std::min)(burst_, tokens_ + refill_per_sec_ *
                                                     static_cast<double>(now_ms - last_ms_) / 1000.0);
            last_ms_ = now_ms;
        }
    }
    double refill_per_sec_;
    double burst_;
    double tokens_;
    std::int64_t last_ms_{0};
};

/// One page-into-window pass's outcome.
struct JournalPageStats {
    std::size_t batches_paged{0}; ///< batches that contributed >=1 net-new record this pass
    std::size_t records_paged{0}; ///< records newly enqueued into the send window this pass
    /// A candidate batch could not be placed because the window lacked room FOR THAT BATCH -
    /// which is NOT the same as the window being full: headroom 255 blocks a 256-entry batch.
    /// Distinct from placing nothing because every entry was already a member. Callers must not
    /// conflate the two: the first means "a backlog is waiting on drain progress" and
    /// justifies re-attempting once the drain frees room; the second is an idle steady state
    /// where re-attempting is a full-journal rescan for nothing (#2298 Gate 4 UP-2).
    bool headroom_blocked{false};
    /// The pass did no work because the paging rate-limiter had no token. A FORCED page (a
    /// reconnect kick) that lands on an empty bucket would otherwise be silently swallowed:
    /// the pass returns clean, so the caller's "re-arm if the forced page failed" never fires
    /// and replay waits out a whole cadence interval after the link came back (#2345 Gate 6).
    bool deferred_no_token{false};
    /// Entries the SMALLEST blocked batch needed. A caller must not re-attempt until at least
    /// this much room exists; re-arming on any headroom at all meant a 1-slot opening
    /// retriggered a full journal scan for a batch needing 256 (#2345).
    std::size_t min_blocked_headroom{0};
    /// Candidates skipped because they already carry a durable sent-label - in steady state,
    /// the redundant redelivery that is no longer being generated. PER-PASS and diagnostic:
    /// it is surfaced through GuardianMaintenanceResult for tests and callers, but has no
    /// cumulative counter or heartbeat tag, so do not cite it as fleet-visible evidence.
    std::size_t skipped_already_sent{0};
    /// The sent-label scan failed, so this pass could not skip anything and fell back to
    /// re-offering everything. Counted because that fallback is invisible otherwise: an agent
    /// whose scan fails every pass silently returns to the old redelivery floor (#2345 Gate 8).
    bool sent_scan_failed{false};
    /// This pass could not read/establish replay state: the candidate scan failed, a considered
    /// candidate's VALUE read failed, or the boot-prune barrier's own scan failed (the last
    /// increments prune_failures_, not page_read_failures_, so it carries no counter signal of its
    /// own). Distinct from deferred_no_token (no token) and sent_scan_failed (fell back but could
    /// still page): a read_failed pass did NO verifiable replay work, so the drain worker's page
    /// success stamp must not read it as fresh unless the pass also placed records (#2452).
    bool read_failed{false};
    /// THE authoritative "this pass is healthy replay evidence" signal the page success stamp
    /// gates on (#2452 governance Gate 7). Defaults false and is set true at EXACTLY ONE place -
    /// the successful tail of page_into_window - iff the pass either placed records
    /// (records_paged > 0) OR considered every candidate it reached this pass and found nothing
    /// that needed or could be paged, with nothing left blocked (headroom), quarantined,
    /// read-failed, or sent-scan-degraded. "Considered this pass" is per-SLICE, not whole-backlog:
    /// the consideration loop is capped at kJournalPageMaxBatchesPerPass, so on a large journal a
    /// clean slice reads verified-idle while an unexamined tail could still be blocked/corrupt -
    /// bounded and self-correcting, because the fair-rotation cursor reaches that tail within
    /// ceil(N/cap) passes (whereupon headroom/quarantine flip it stale). Requiring whole-backlog
    /// coverage would instead read a large fully-delivered journal permanently STALE, since no
    /// single pass ever considers more than the cap. Every early return (null-kv, a stopping_ bail,
    /// deferred_no_token, the boot-prune barrier, a candidate scan failure) leaves it false by
    /// construction, so a NEW no-progress exit cannot advance the stamp by forgetting to opt out -
    /// the failure mode the earlier per-cause negative enumeration kept hitting (headroom-blocked,
    /// quarantine-only). This is the page-side mirror of the prune stamp's positive
    /// JournalPruneStats::progress_or_verified.
    bool progress_or_verified_idle{false};
};

/// A batch persist() durably wrote, for back-filling window-entry provenance (review M3): the
/// still-windowed LIVE entries get this batch key so their send writes the sent-label instead
/// of the batch later aging out falsely counted evicted_without_send_evidence. event_ids are in
/// batch order; back() is the batch's last-in-batch record.
struct PersistedBatch {
    std::string key;
    std::vector<std::string> event_ids;
};

/// One prune pass's outcome (also mirrored on the lock-free counters).
struct JournalPruneStats {
    bool read_ok{false};           ///< the initial journal scan succeeded (gates the boot barrier, M5)
    std::size_t evicted{0};        ///< batches removed by retention (age/count/bytes)
    std::size_t quarantined{0};    ///< MALFORMED-KEY / implausibly-sized batches moved
                                   ///< aside this pass. A corrupt VALUE is quarantined by
                                   ///< the REPLAY pass instead (#2299), not counted here.
    std::size_t sent_labels_gc{0}; ///< orphaned/evicted sent-labels removed this pass
    /// THE prune-side gate signal (#2452 Gate 8), mirroring the page stamp's
    /// progress_or_verified_idle. True iff retention was APPLIED (the delete succeeded) or VERIFIED
    /// IDLE (nothing eligible to evict). Default false; set true only after the eviction block, so
    /// a scan failure (read_ok false), a delete failure (returns early, prune_failures), and any
    /// stop BEFORE the delete all leave it false - the drain worker's prune success stamp advances
    /// only on this, closing the "reads fresh while retention did not run" holes (UP-7 delete-fail,
    /// UP8-3 stop-abort) that gating on read_ok alone left open. read_ok is retained separately: it
    /// still gates the boot-prune barrier (M5), which needs only "the scan succeeded".
    bool progress_or_verified{false};
};

class YUZU_EXPORT GuardianLifecycleJournal {
public:
    /// `kv` is BORROWED and must outlive this component (the agent owns it and
    /// destroys it after the engine - agent.cpp member order). May be null (KV
    /// unavailable): persist() then durably writes nothing. Production always passes
    /// a real KvStore; a test may pass any other IJournalStore implementation (#4153)
    /// as long as it keeps that interface's per-call contract.
    explicit GuardianLifecycleJournal(IJournalStore* kv);

    /// Serialise + durably write the FIFO-ordered `pending` records in batches
    /// (each ≤ kMaxJournalEntriesPerBatch entries and ≈ kMaxJournalBatchBytes).
    /// Returns the count of RECORDS durably written - the caller passes it to
    /// GuardianSparkRuntime::erase_persisted_prefix(). A per-push CIRCUIT BREAKER
    /// stops at the first write failure (remaining records stay pending for the
    /// maintenance-tick retry) so one failing write cannot stall a 500-rule
    /// apply_rules for 500 × the 5 s KvStore busy timeout under mtx_.
    ///
    /// `max_batches` / `max_records` bound ONE call; `kJournalPersistUnbounded`
    /// (0) disables either. The circuit breaker above covers write FAILURE; these
    /// cover slow SUCCESS, which the heartbeat's retry-persist had no bound on at
    /// all: a full staging buffer is many autocommit inserts under mtx_, each able
    /// to approach the 5 s KvStore busy timeout under contention, and the heartbeat
    /// thread waits for every one of them. Whichever limit is reached first ends
    /// the call, which is deliberate - batches bound the LATENCY (round trips) and
    /// records bound the THROUGHPUT floor, and with only the former the drain rate
    /// collapses ~21x when large fields make the byte cap split batches. A capped
    /// call returns like a circuit-broken one - the remainder stays staged and the
    /// next tick continues - so the caller needs no new handling.
    ///
    /// NEITHER argument is defaulted, on purpose: every caller must state its
    /// intent, so that a future cadence caller cannot silently inherit unbounded
    /// behaviour. Only the heartbeat passes real bounds; the boot, apply_rules and
    /// both shutdown flushes pass `kJournalPersistUnbounded` because each has to
    /// drain everything it was given.
    [[nodiscard]] std::size_t persist(std::span<const std::shared_ptr<const JournalRecord>> pending,
                                      std::vector<PersistedBatch>* out_batches,
                                      std::size_t max_batches, std::size_t max_records);

    /// Enforce retention + quarantine (design §6, rev-4.1 #9). Evicts the oldest
    /// batches by (ts_ms, key) once they exceed the age (kJournalRetentionDays),
    /// count (kMaxJournalBatches), or byte (kMaxJournalBytes) caps; moves any
    /// malformed-KEY or implausibly-sized batch aside to a bounded quarantine (atomic
/// rename) - a corrupt VALUE is the replay pass's to quarantine since #2299; GCs
    /// sent-labels whose batch no longer survives. `now_ms` is the wall clock in ms
    /// (a parameter so age eviction is testable). Fail-safe: a read error counts
    /// prune_failures and returns, never throws, never fatal. Runs off mtx_ (KvStore
    /// serialises itself); wired into the drain worker's maintenance pass (C0 #2298) + a
    /// boot barrier inside page_into_window. Honors request_stop() early and between the
    /// per-evicted-key reads, so a stop never waits out a full retention pass.
    JournalPruneStats prune(std::int64_t now_ms);

    /// Replay the durable journal into `rt`'s send window (design §5; item 7 PR-Ag C5).
    /// Serialised by the paging mutex; the FIRST call runs a boot prune before returning
    /// any candidate (the prune-before-page barrier). Reads unexpired batches (fallible),
    /// orders them by (ts_ms, key), and for each - rate-limited by a process-lifetime token
    /// bucket charged ONLY for net-new work - reconstructs wire-identical entries (with
    /// replay provenance) and pages them via rt.try_page_batch. A batch carrying a durable
    /// sent-label is SKIPPED unless `replay_sent` - so an ordinary pass no longer re-offers what
    /// has already been delivered, and a labelled batch is permanently skipped until a forced
    /// pass or retention.
    /// Takes KvStore.mu_ then outbox_mu_ SEQUENTIALLY, never nested, never the engine mtx_.
    /// `replay_sent` re-offers batches that already carry a durable sent-label. FALSE on the
    /// ordinary cadence pass and TRUE on a forced one. Forced means every path that sets the
    /// worker's force_page_: boot replay, the reconnect kick, AND the headroom-refill re-arm,
    /// which fires during backlog recovery - enumerating only the first two was wrong in three
    /// places (#2345 Gate 8).
    JournalPageStats page_into_window(GuardianSparkRuntime& rt, std::int64_t now_ms,
                                      bool replay_sent = false);

    /// Write the (best-effort) sent-label for a batch - called from the send path after the
    /// batch's LAST paged entry is delivered. Presence classifies eviction (sent-unacked vs
    /// no-send-evidence) AND, since #2345 round 8, gates re-paging: page_into_window skips a
    /// labelled batch on any non-forced pass. It still never gates deletion.
    void mark_batch_sent(const std::string& batch_key);

    /// Signal that shutdown has begun: a concurrent page_into_window pass observes this
    /// between batches and stops enqueuing, so a late page never mutates the send window
    /// after stop() joins the drain worker (rev-4.1 #7 stop-race gate). Idempotent, lock-free.
    /// C0 (#2298) widened the gate: BOTH prune and page also check it on entry and at each
    /// remaining KvStore-loop boundary, because both now run ON the drain-worker thread that
    /// GuardianEngine::stop() joins - an unchecked full pass would become join latency.
    void request_stop() noexcept { stopping_.store(true, std::memory_order_release); }

    // Integrity counters (design §2 loss table). Lock-free.
    [[nodiscard]] std::uint64_t batches_written() const noexcept {
        return batches_written_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t write_failures() const noexcept {
        return write_failures_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t key_collisions() const noexcept {
        return key_collisions_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t quarantined() const noexcept {
        return quarantined_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t quarantine_failures() const noexcept {
        return quarantine_failures_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t batches_pruned() const noexcept {
        return batches_pruned_.load(std::memory_order_relaxed);
    }
    /// Page-side KvStore READ FAILURES. Two kinds, deliberately on one counter: a failed
    /// candidate SCAN (one per pass, the pass then pages nothing) and, since #2299, a failed
    /// per-candidate VALUE read (up to the per-pass candidate cap, each leaving that one
    /// candidate's disposition unknown). Both mean "replay could not read what it needed",
    /// which is the operator question; without a counter at all a page-side read failure is
    /// invisible and replay silently does nothing (#2345 Gate 6 SRE).
    ///
    /// NOTE the unit is therefore FAILED READS, not failed passes - a single pass can add
    /// more than one. Do not read a rate off this as a pass-failure rate.
    [[nodiscard]] std::uint64_t page_read_failures() const noexcept {
        return page_read_failures_.load(std::memory_order_relaxed);
    }
    /// Passes whose sent-label scan failed, so the pass re-offered already-delivered batches.
    [[nodiscard]] std::uint64_t sent_scan_failures() const noexcept {
        return sent_scan_failures_.load(std::memory_order_relaxed);
    }
    /// Retention passes that skipped age eviction due to an implausible forward clock jump.
    [[nodiscard]] std::uint64_t clock_jump_skips() const noexcept {
        return clock_jump_skips_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t prune_failures() const noexcept {
        return prune_failures_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t pages() const noexcept {
        return pages_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t records_paged() const noexcept {
        return records_paged_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t sent_labels_written() const noexcept {
        return sent_labels_written_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t evicted_sent_unacked() const noexcept {
        return evicted_sent_unacked_.load(std::memory_order_relaxed);
    }
    /// Batches retention removed with NO sent-label - the audit-loss signal. Since #2299 it
    /// also absorbs a batch whose VALUE was corrupt and which the replay rotation never
    /// reached before it aged out (corrupt-value quarantine moved to the replay pass, so
    /// prune no longer intercepts such a row). Both are lost evidence, so the alarm is not
    /// wrong - but on a mass-corruption endpoint it no longer distinguishes "never
    /// delivered" from "never deliverable". Read it with `quarantined` when diagnosing.
    [[nodiscard]] std::uint64_t evicted_without_send_evidence() const noexcept {
        return evicted_without_send_evidence_.load(std::memory_order_relaxed);
    }
    /// Batches retention evicted whose sent/unsent disposition was never determined - the
    /// THIRD, mutually-exclusive eviction outcome that makes the per-pass accounting exact:
    /// batches_pruned == evicted_sent_unacked + evicted_without_send_evidence +
    /// evicted_unclassified (item 3 / sec-M4, #2298 CC7.2). Its existence is what lets an
    /// auditor read evicted_without_send_evidence as a trustworthy FLOOR on lost evidence
    /// rather than a value a mid-pass shutdown could silently shrink.
    ///
    /// THREE causes, all "disposition permanently unknown", not "loss" and not "success":
    ///  - a stop landing after the delete but before/mid classification (the remainder is
    ///    counted here rather than dropped) - at most ONE such bump per process lifetime,
    ///    since stopping_ latches;
    ///  - a sent-label read that returned an error on the scan-failure fallback (an unreadable
    ///    label is unknown, not absence) - paired with a same-pass prune_failures increment
    ///    recorded the instant the read fails, and can climb repeatedly;
    ///  - a throw mid-classification (bad_alloc under memory pressure) - the not-yet-classified
    ///    remainder is accounted here before the rethrow; the throw itself is separately counted
    ///    as a maintenance exception (journal_maint_exceptions) by the drain-worker firewall.
    /// In-memory only, resets on restart, like its two siblings. NOTE the shutdown-skip case
    /// may never reach a final heartbeat before the process exits: this closes IN-PROCESS
    /// accounting, it is not durable evidence that a skip occurred.
    [[nodiscard]] std::uint64_t evicted_unclassified() const noexcept {
        return evicted_unclassified_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t write_capacity_rejected() const noexcept {
        return write_capacity_rejected_.load(std::memory_order_relaxed);
    }
    // A gauge observed NEGATIVE at the write-ceiling check (#2303 UP-2 / Sol). The size is then
    // untrusted, so persist() fails CLOSED (refuses the write, defers to RAM staging) until a
    // prune rebase restores it - and increments this. Correct operation never goes negative, so
    // any non-zero here is a real accounting bug surfacing, not silently admitted on a clamp.
    //
    // NOW WIRED (flip checklist item 5, #2298 / L1): this counter mirrors write_capacity_rejected
    // through GuardianJournalStats + journal_stats() + emit_guardian_journal_heartbeat_tags, and
    // rolls up server-side as yuzu_fleet_guardian_journal_gauge_underflow (#2298 gate 3). Landed
    // PRE-flip on purpose: it stays 0 (and the sparse emit ships no tag) while inert
    // (prefer_spark=false), so the telemetry is already in place when the cutover makes the write
    // path live. Without it the journal_batch_count gauge CLAMPS a negative to 0 - reading as a
    // healthy EMPTY journal - so this is the only signal that de-camouflages the fail-closed
    // state (governance UP-4).
    [[nodiscard]] std::uint64_t gauge_underflow() const noexcept {
        return gauge_underflow_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t quarantine_capacity_evicted() const noexcept {
        return quarantine_capacity_evicted_.load(std::memory_order_relaxed);
    }
    // Current-size GAUGES (not cumulative): maintained as a RUNNING COUNTER - persist
    // fetch_adds on a durable write; prune rebases to the scanned on-disk reality and
    // fetch_subs what it removes (#2303 gauge-race fix). They are signed internally so a
    // rebase can walk a conservative fail-closed boot seed back DOWN, and clamped to >=0 at
    // read so no residual accounting bug can present as a negative or (post-cast) huge size.
    // An operator watches these to see growth BEFORE a chronic prune failure exhausts the
    // shared kv_store.db (sre review). Approximate between prune scans; a restart re-seeds
    // them from the boot size-probe.
    [[nodiscard]] std::uint64_t journal_bytes() const noexcept {
        return clamp_nonneg(journal_bytes_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::uint64_t journal_batch_count() const noexcept {
        return clamp_nonneg(journal_batch_count_.load(std::memory_order_relaxed));
    }
    /// Age in ms of the current headroom-blocked replay-congestion EPISODE (#2364 step-1
    /// telemetry); 0 = no current episode. `now_steady_ms` is the caller's steady_clock
    /// reading (a parameter for testability, and so one heartbeat samples every age off one
    /// `now`). Saturates to 0 if `now` reads at-or-before the stored episode start (a
    /// concurrent new episode between the caller's clock read and this load), so a transient
    /// race can under-report one sample but never wraps unsigned. Lock-free - see the member
    /// comment for the episode's set/clear rules.
    [[nodiscard]] std::uint64_t headroom_blocked_age_ms(std::int64_t now_steady_ms) const noexcept {
        const auto since = headroom_blocked_since_steady_ms_.load(std::memory_order_relaxed);
        if (since < 0 || now_steady_ms <= since)
            return 0;
        return static_cast<std::uint64_t>(now_steady_ms - since);
    }

    /// TEST-ONLY: force the next `n` batch writes to fail (as if KvStore returned
    /// Error), exercising the per-push circuit breaker and the maintenance-tick
    /// retry (Sol BLOCKER-4) without a real disk fault. No production caller.
    void inject_write_failures_for_test(int n, int skip_first = 0) noexcept {
        inject_skip_writes_.store(skip_first, std::memory_order_relaxed);
        inject_fail_writes_.store(n, std::memory_order_relaxed);
    }

    /// TEST-ONLY: shrink the retention caps so count/byte/quarantine eviction is
    /// reachable at unit-test scale (production caps are 1000 batches / 32 MiB / 100
    /// quarantined). Age eviction needs no shrink - pass a future now_ms to prune().
    void set_retention_limits_for_test(int days, std::size_t max_batches, std::size_t max_bytes,
                                       std::size_t max_quarantine) noexcept {
        retention_days_ = days;
        max_batches_ = max_batches;
        max_bytes_ = max_bytes;
        max_quarantine_ = max_quarantine;
    }

    /// TEST-ONLY: shrink the hard WRITE ceiling (the UP-1 anti-runaway bound, default 2x the
    /// production retention caps) so a rejection is reachable at unit-test scale. Independent of
    /// set_retention_limits_for_test - retention is the soft cap prune trims to; this is the hard
    /// cap persist refuses to cross.
    void set_write_ceiling_for_test(std::size_t max_batches, std::size_t max_bytes) noexcept {
        hard_max_batches_ = max_batches;
        hard_max_bytes_ = max_bytes;
    }

    /// TEST-ONLY: the raw #2364 episode stamp (-1 = no episode). Lets a test assert the
    /// set-if-unset / rotation-sticky-clear transitions exactly (e.g. "a second blocked pass
    /// did NOT re-stamp") without racing the real steady_clock the production stamp reads.
    /// No production caller - production reads ages via headroom_blocked_age_ms().
    [[nodiscard]] std::int64_t headroom_blocked_since_for_test() const noexcept {
        return headroom_blocked_since_steady_ms_.load(std::memory_order_relaxed);
    }

    /// TEST-ONLY: invoked by page_into_window once per examined candidate, BEFORE its
    /// disposition. Exists so a test can land request_stop() BETWEEN candidates and drive
    /// the mid-loop stop-truncation path - the branch that protects the episode state from
    /// counting an incomplete pass, which no external sequence can hit deterministically.
    /// Null in production. Set BEFORE any concurrent pass can run (the write is
    /// unsynchronized, same discipline as the pre/post_scan hooks - a set racing a live
    /// drain worker's read would be a TSan-visible data race).
    void set_post_classify_hook_for_test(std::function<void()> hook) {
        post_classify_hook_ = std::move(hook);
    }

    /// TEST-ONLY: invoked by prune's EVICTION classifier - once immediately after the delete
    /// with `classified == 0` (before the shutdown gate), then again after each key is placed
    /// in a disposition bucket with the running count (1, 2, ...). Exists so a test can land
    /// request_stop() at an EXACT classification boundary and drive the mid-pass truncation
    /// remainder-accounting deterministically, and so a hook that THROWS can exercise the
    /// classification firewall's remainder-accounting (the drain worker cannot make this loop
    /// throw from outside). Null in production. Set BEFORE any concurrent pass can run - the
    /// write is unsynchronized, same discipline as the pre/post_scan hooks. The hook fires
    /// UNDER paging_mutex_ (prune_locked_ holds it), which is non-recursive: a hook re-entering
    /// a paging_mutex_-taking journal method self-deadlocks. The delivered tests only call
    /// request_stop() (a bare atomic store) or throw, both safe.
    void set_prune_classify_hook_for_test(std::function<void(std::size_t classified)> hook) {
        prune_classify_hook_ = std::move(hook);
    }

    /// TEST-ONLY: force the next `n` journal SCANS (the keys-only scan at the head of a prune
    /// pass) to fail, exercising the read-error fail-safe: prune_failures increments, read_ok
    /// stays false, and the boot-prune barrier does NOT latch (design §10 "injected list
    /// failure distinguished from empty & retried"). No production caller.
    void inject_read_failures_for_test(int n) noexcept {
        inject_fail_reads_.store(n, std::memory_order_relaxed);
    }

    /// TEST-ONLY: force the next `n` REPLAY scans (the keys-only scan at the head of
    /// page_into_window) to fail. Deliberately a separate counter from the prune-side
    /// injection: the point of page_read_failures() is that the two scans fail independently,
    /// so a test that conflated them could not observe the difference. No production caller.
    /// TEST-ONLY: force the next `n` SENT-LABEL scans to fail. Distinct from
    /// inject_page_read_failures_for_test, which fails the candidate scan and returns before
    /// the label read is ever reached - so without this the fallback branch is unreachable
    /// from any test (#2345 Gate 8 QE).
    void inject_sent_scan_failures_for_test(int n) noexcept {
        inject_fail_sent_scans_.store(n, std::memory_order_relaxed);
    }
    void inject_page_read_failures_for_test(int n) noexcept {
        inject_fail_page_reads_.store(n, std::memory_order_relaxed);
    }

    /// TEST-ONLY: force the next `n` prune-side SENT-LABEL scans to fail, exercising the
    /// eviction classifier's per-key fallback. Separate from the page-side sent-scan
    /// injection: the two passes read the same namespace for different reasons and must fail
    /// independently for either fallback to be testable. No production caller.
    void inject_prune_sent_scan_failures_for_test(int n) noexcept {
        inject_fail_prune_sent_scans_.store(n, std::memory_order_relaxed);
    }

    /// TEST-ONLY: force the next `n` prune-side per-key sent-label POINT reads to fail. Pair
    /// it with the scan injection above to stage the correlated failure that matters - one
    /// broken database, not one broken key - and prove an evicted batch of UNKNOWN
    /// disposition is counted as neither sent nor unsent. No production caller.
    void inject_prune_sent_read_failures_for_test(int n) noexcept {
        inject_fail_prune_sent_reads_.store(n, std::memory_order_relaxed);
    }

    /// TEST-ONLY: force the next `n` per-candidate VALUE reads (the point read a replay pass
    /// issues only for a candidate it actually considers) to fail. Distinct from the two scan
    /// injections above: those fail before any value is read, so without this the point-read
    /// error path - which must NOT be recorded as block-free coverage - is unreachable from a
    /// test. No production caller.
    void inject_value_read_failures_for_test(int n) noexcept {
        inject_fail_value_reads_.store(n, std::memory_order_relaxed);
    }

    /// TEST-ONLY: how many candidate VALUES the replay pass has read from the KvStore. The
    /// O(work) proof: a pass over a journal whose candidates are all sent-labelled, expired or
    /// outside the per-pass cap must read ZERO values, where the pre-#2299 pass read (and
    /// parsed) every row in the namespace. Deliberately NOT a heartbeat/fleet counter - it
    /// pins an implementation property, not an operator signal.
    [[nodiscard]] std::uint64_t candidate_value_fetches_for_test() const noexcept {
        return candidate_value_fetches_.load(std::memory_order_relaxed);
    }

    /// TEST-ONLY: overwrite the size gauges directly, to stage a state the production
    /// paths reach only via a rare boot condition - e.g. the fail-closed boot seed that
    /// pins them at the hard ceiling. Used to prove a later successful prune REBASES them
    /// back to on-disk reality (the failed-boot recovery the rebase-as-delta scheme must
    /// preserve). No production caller.
    void set_size_gauges_for_test(std::int64_t count, std::int64_t bytes) noexcept {
        journal_batch_count_.store(count, std::memory_order_relaxed);
        journal_bytes_.store(bytes, std::memory_order_relaxed);
    }

    /// TEST-ONLY: run `hook` inside prune_locked_ immediately AFTER the scan succeeds and
    /// the gauge is rebased, but BEFORE the removal accounting - the exact window a
    /// concurrent persist() would land in. Lets a single-threaded test drive the
    /// scan/insert/publish interleaving deterministically to prove prune does NOT clobber a
    /// concurrent insert's gauge increment (#2303 gauge-race). No production caller.
    void set_post_scan_hook_for_test(std::function<void()> hook) {
        post_scan_hook_ = std::move(hook);
    }

    /// TEST-ONLY: run `hook` inside prune_locked_ BEFORE the scan (between the pre_count
    /// snapshot and the scan). This is the window where a concurrent persist's row IS seen by
    /// the scan AND carries its own fetch_add - the transient DOUBLE-count. Proves it self-heals
    /// to the true on-disk size (over-count only, ceiling tightens). Complements the post-scan
    /// hook (persist AFTER the rebase). #2303 UP-3. No production caller.
    void set_pre_scan_hook_for_test(std::function<void()> hook) {
        pre_scan_hook_ = std::move(hook);
    }

    /// TEST-ONLY: force the next `n` retention DELETES (del_keys of the evict set) to report a
    /// 0/failure return, exercising the M4 delete-failure fail-safe (prune_failures increments,
    /// survivors' sent-labels are left intact and retried). No production caller.
    void inject_delete_failures_for_test(int n) noexcept {
        inject_fail_deletes_.store(n, std::memory_order_relaxed);
    }

private:
    /// Clamp a signed running-counter gauge to a non-negative size. A correct accounting
    /// never goes negative; this only defends a residual bug from presenting as a huge size
    /// once cast to unsigned (and keeps the ceiling check monotonic).
    static constexpr std::uint64_t clamp_nonneg(std::int64_t v) noexcept {
        return v > 0 ? static_cast<std::uint64_t>(v) : 0;
    }

    /// The retention/quarantine body, serialised by paging_mutex_ against page_into_window
    /// (review round 2 MINOR-1). prune() is the public wrapper that takes the mutex; the
    /// boot-prune barrier inside page_into_window calls this directly (it already holds it).
    JournalPruneStats prune_locked_(std::int64_t now_ms);

    /// Seed the size gauges from the journal already on disk so the write-side ceiling is
    /// honest from this process's FIRST write, not only after a successful prune (#2303 C1).
    /// Called from the ctor; fails CLOSED (assume-at-ceiling) if the journal cannot be sized.
    void seed_size_gauges_();

    IJournalStore* kv_;          ///< BORROWED; outlives this (agent owns it)
    std::string boot_nonce_;     ///< random, fixed at construction - batch-key uniqueness across restarts
    std::uint64_t batch_seq_{0}; ///< per-process monotonic batch-key sequence (persist runs single-threaded under mtx_)
    std::atomic<std::uint64_t> batches_written_{0};
    std::atomic<std::uint64_t> write_failures_{0};
    std::atomic<std::uint64_t> key_collisions_{0};
    std::atomic<std::uint64_t> quarantined_{0};         ///< batches moved aside: malformed key
                                                        ///< or implausible size (prune), corrupt
                                                        ///< value (replay pass, since #2299)
    std::atomic<std::uint64_t> quarantine_failures_{0}; ///< could not even quarantine a corrupt batch
    std::atomic<std::uint64_t> batches_pruned_{0};      ///< batches evicted by retention
    std::atomic<std::uint64_t> prune_failures_{0};      ///< a prune pass could not read the journal
    std::atomic<std::uint64_t> pages_{0};               ///< page_into_window passes
    std::atomic<std::uint64_t> records_paged_{0};       ///< records newly enqueued into the window
    std::atomic<std::uint64_t> sent_labels_written_{0}; ///< sent-labels written (best-effort)
    std::atomic<std::uint64_t> evicted_sent_unacked_{0};          ///< aged out WITH a sent-label
    std::atomic<std::uint64_t> evicted_without_send_evidence_{0}; ///< aged out with NO sent-label (alert)
    std::atomic<std::uint64_t> evicted_unclassified_{0};          ///< aged out, disposition unknown (item 3)
    std::atomic<std::uint64_t> write_capacity_rejected_{0};       ///< new batch refused: journal at cap (UP-1)
    std::atomic<std::uint64_t> quarantine_capacity_evicted_{0};   ///< over-cap quarantined batches shed (UP-7)
    // Size gauges are SIGNED running counters (#2303 gauge-race fix): persist fetch_adds,
    // prune rebases (fetch_add of scanned-actual minus count-at-scan-start) then fetch_subs
    // removals - all RMW so a concurrent persist increment is never lost to an absolute
    // store. Signed so a fail-closed boot seed at the ceiling can be walked back down; read
    // through clamp_nonneg().
    std::atomic<std::int64_t> journal_bytes_{0};                 ///< current live journal size estimate (gauge)
    std::atomic<std::int64_t> journal_batch_count_{0};           ///< current live batch count (gauge)
    std::atomic<std::uint64_t> gauge_underflow_{0};              ///< ceiling check saw a negative gauge (UP-2)
    std::atomic<bool> size_seeded_{false};              ///< seed_size_gauges_ call-once guard (UP-7)
    std::function<void()> post_scan_hook_;              ///< test-only prune interleaving seam (null in prod)
    std::function<void()> pre_scan_hook_;               ///< test-only pre-scan interleaving seam (UP-3)
    std::function<void()> post_classify_hook_;          ///< test-only per-candidate seam (mid-loop stop, null in prod)
    std::function<void(std::size_t)> prune_classify_hook_; ///< test-only eviction-classify seam (indexed; null in prod)
    std::atomic<int> inject_fail_writes_{0};            ///< test-only forced-failure countdown
    std::atomic<int> inject_skip_writes_{0};            ///< test-only: skip this many writes before failing
    std::atomic<int> inject_fail_reads_{0};             ///< test-only: force the next N prune scans to fail
    std::atomic<int> inject_fail_page_reads_{0};        ///< test-only: force the next N replay scans to fail
    std::atomic<int> inject_fail_deletes_{0};           ///< test-only: force the next N retention deletes to fail
    // Paging state - all guarded by paging_mutex_ (paging is single-threaded per pass).
    std::mutex paging_mutex_;
    bool boot_pruned_{false}; ///< the prune-before-first-page barrier has run
    JournalPagingBucket page_bucket_{kJournalPageRefillPerSec, kJournalPageBurst};
    std::atomic<bool> stopping_{false}; ///< set by request_stop(); page_into_window bails on it
    /// Last now_ms a retention pass observed, for the forward-clock-jump guard. Written only
    /// under paging_mutex_ by prune_locked_, the single retention caller.
    std::int64_t last_prune_now_ms_{0};
    /// The age cutoff the last retention pass actually applied, and whether one has run.
    /// page_into_window reuses it rather than deriving its own, so retention and replay can
    /// never disagree about what "expired" means. Written only under paging_mutex_.
    std::int64_t last_age_cutoff_{0};
    bool pruned_cutoff_valid_{false};
    /// The fact set the last decline was reported against (#2573 GJ half). Presence is the
    /// dedup key, not a bool: a bool cannot carry anomaly IDENTITY, so a DIFFERENT anomaly
    /// arriving while a bool latch was still set was neither declined nor counted, and the
    /// pass deleted (measured, same class as #2573's TAR half, PR #3101). Held for as long as
    /// this pass's anomaly backlog is still being worked off (see the `pacing` comment at the
    /// write site), cleared once it drains, at which point a fresh anomaly reports on its own
    /// merits. In-memory only, like `last_prune_now_ms_` above - GJ persists no anchor across
    /// restarts by design (unlike TAR/audit_store), so `Facts::no_anchor` and
    /// `Facts::prev_unusable` are always false here; see the mapping comment in prune_locked_.
    std::optional<yuzu::server::audit_retention::Facts> last_reported_facts_;
    /// Retention passes that declined to age-evict because the clock jumped implausibly far
    /// forward. Nonzero means an endpoint's clock moved; it is NOT an error in itself.
    std::atomic<std::uint64_t> clock_jump_skips_{0};
    std::atomic<std::uint64_t> page_read_failures_{0};
    std::atomic<std::uint64_t> sent_scan_failures_{0};
    std::atomic<int> inject_fail_sent_scans_{0}; ///< test-only: fail the next N label scans
    std::atomic<int> inject_fail_value_reads_{0}; ///< test-only: fail the next N candidate value reads
    std::atomic<int> inject_fail_prune_sent_scans_{0}; ///< test-only: fail the next N prune label scans
    std::atomic<int> inject_fail_prune_sent_reads_{0}; ///< test-only: fail the next N prune label reads
    std::atomic<std::uint64_t> candidate_value_fetches_{0}; ///< test-only O(work) proof counter
    /// One-shot latch for the retired-key-format warn (prune only, under paging_mutex_).
    bool old_format_key_warned_{false};
    /// Fair-rotation cursor (review B2): the last-CONSIDERED (ts_ms, key). Each pass resumes at
    /// the first candidate strictly greater and wraps, so the never-sent tail is reached instead
    /// of the oldest sent-and-popped batches monopolising the bucket. Process-local (NOT
    /// persisted): a restart re-sends the whole unexpired journal, which is correct.
    std::optional<std::pair<std::int64_t, std::string>> page_cursor_;
    /// #2364 episode state: steady_clock ms when headroom blocking was first observed in the
    /// current replay-congestion episode; -1 = no current episode. -1 (not 0) because
    /// steady_clock's epoch is unspecified (commonly boot) and an honest reading near 0 must
    /// not be mistaken for the sentinel. WRITTEN only at the end of page_into_window (single
    /// writer under paging_mutex_); ATOMIC for the lock-free heartbeat read - the heartbeat
    /// must never queue behind an in-flight O(journal) pass. Process-local like the cursor:
    /// a restart starts a fresh episode (documented in the tag's semantics).
    std::atomic<std::int64_t> headroom_blocked_since_steady_ms_{-1};
    /// Batch keys observed block-free since the last blocked observation - the coverage
    /// record that gates CLEARING the episode (see page_into_window's transition-rule
    /// comment). A DISTINCT-KEY set, deliberately not a count: a count compared against the
    /// current set size clears early under shrink-churn (prune evicts already-counted
    /// candidates, the count survives, the bar drops - Fable review, 2026-07-23), which
    /// sawtooths the gauge in exactly the #2364 starvation regime. Populated only while an
    /// episode is active; cleared on every blocked observation and on episode clear. Size
    /// bound is EPOCH-scoped, not the live batch cap: keys of candidates evicted mid-epoch
    /// linger until the next block or clear, so under churn the set can transiently exceed
    /// the live count - still bounded in practice because every blocked pass resets it, and
    /// growth without a re-block requires sustained all-clean batch turnover. Plain member:
    /// only touched under paging_mutex_.
    std::unordered_set<std::string> clean_keys_since_block_;
    // Retention (SOFT) caps - default to the production constants; a test may shrink them.
    int retention_days_{kJournalRetentionDays};
    std::size_t max_batches_{kMaxJournalBatches};
    std::size_t max_bytes_{kMaxJournalBytes};
    std::size_t max_quarantine_{kMaxQuarantineBatches};
    // Hard WRITE ceiling (UP-1 anti-runaway bound) - 2x the retention caps, above normal
    // between-prune overshoot; persist refuses to cross it so a chronically-failing prune cannot
    // grow the shared kv_store.db without bound. Decoupled from the retention caps above.
    std::size_t hard_max_batches_{kMaxJournalBatches * 2};
    std::size_t hard_max_bytes_{kMaxJournalBytes * 2};
};

// Holds a std::mutex + atomics directly, so it is implicitly non-copyable AND non-movable; it
// is only ever owned via a std::unique_ptr on GuardianEngine. Pin that so an accidental by-value
// use (which would try to copy the borrowed kv_ and duplicate paging state) fails to compile.
static_assert(!std::is_copy_constructible_v<GuardianLifecycleJournal> &&
              !std::is_move_constructible_v<GuardianLifecycleJournal>);

} // namespace yuzu::agent
