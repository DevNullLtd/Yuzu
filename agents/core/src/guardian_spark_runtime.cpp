#include "guardian_spark_runtime.hpp"

#include "guardian_scope_guard.hpp" // GuardianRollback (terminate-safe rollback)
#include "spark_key_rule_index.hpp"

#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <limits>
#include <new>
#include <stdexcept>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <variant>

namespace yuzu::agent {

namespace {

/// #2233 item 3: which of GuardianIoExecutor's three bounded-I/O lanes backs a
/// SparkType's arm/disarm, or nullopt for a type whose mechanism is never a
/// blocking OS watch (Interval/Startup/Disk - timer/poll-based, matches
/// GuardianIoExecutor's own kIoClassCount==3 scope). attach_rule/detach_rule_locked
/// use nullopt to mean "keep the call inline under registry_mu_, as before".
[[nodiscard]] constexpr std::optional<IoClass> io_class_for_spark_type(SparkType t) noexcept {
    switch (t) {
    case SparkType::File:     return IoClass::File;
    case SparkType::Registry: return IoClass::Registry;
    case SparkType::Service:  return IoClass::Service;
    case SparkType::Interval:
    case SparkType::Startup:
    case SparkType::Disk:
        return std::nullopt;
    }
    return std::nullopt;
}

/// A random 64-bit hex token fixed once per runtime construction. Folded into
/// every event_id so a restart (which resets event_seq_ and can revisit a wall_ms)
/// cannot reproduce a prior id and have the server's event_id PK drop it.
std::string make_boot_nonce() {
    std::random_device rd;
    const std::uint64_t n = (static_cast<std::uint64_t>(rd()) << 32) | rd();
    static const char* d = "0123456789abcdef";
    std::string s(16, '0');
    std::uint64_t v = n;
    for (int i = 15; i >= 0; --i) {
        s[static_cast<std::size_t>(i)] = d[v & 0xF];
        v >>= 4;
    }
    return s;
}

} // namespace

GuardianSparkRuntime::GuardianSparkRuntime(std::shared_ptr<IStateReader> reader,
                                           std::shared_ptr<ISparkBackend> backend)
    : GuardianSparkRuntime(std::move(reader), std::move(backend), Config{}, RuntimeClock{}) {}

GuardianSparkRuntime::GuardianSparkRuntime(std::shared_ptr<IStateReader> reader,
                                           std::shared_ptr<ISparkBackend> backend, Config cfg,
                                           RuntimeClock clock)
    : reader_(std::move(reader)), backend_(std::move(backend)),
      clock_(clock ? std::move(clock)
                   : RuntimeClock{[] { return std::chrono::steady_clock::now(); }}),
      cfg_(cfg), boot_nonce_(make_boot_nonce()), index_(std::make_unique<SparkKeyRuleIndex>()),
      outbox_(std::max(kMinOutboxCapacity, cfg.outbox_capacity)),
      // The LIFECYCLE window must be able to hold at least one maximum-size journal batch.
      // Paging is all-or-nothing per batch, so a window smaller than kMaxJournalEntriesPerBatch
      // makes large batches permanently unpageable - they are skipped every pass and then
      // silently deleted at retention. That loss channel is SIZE-BIASED: the largest batches
      // are mass arm/disarm bursts, i.e. the most security-relevant audit records, so it is
      // strictly worse than a random one (#2345 Gate 5 CH-4 / Gate 4 UP-5+UP-15).
      lifecycle_log_(std::max({kMinOutboxCapacity, cfg.outbox_capacity,
                               kMaxJournalEntriesPerBatch})) {
    if (cfg.outbox_capacity > 0 && cfg.outbox_capacity < kMaxJournalEntriesPerBatch)
        spdlog::info("Guardian: lifecycle audit window raised from the configured {} to {} - a "
                     "window smaller than one maximum-size journal batch makes large batches "
                     "permanently unpageable",
                     cfg.outbox_capacity, kMaxJournalEntriesPerBatch);
    // Reserve the staging vector ONCE - never from rule count. push_back then never
    // reallocates, which is what makes stage_pending_locked's noexcept contract real.
    pending_journal_.reserve(kMaxPendingJournalRecords);
}

GuardianSparkRuntime::~GuardianSparkRuntime() {
    // No in-flight pass can be running: a pass keeps the runtime alive through the
    // handler's captured shared_ptr, so ~runtime runs only once nothing references
    // it. begin_stop() is a defensive idempotent no-op here.
    begin_stop();
}

namespace {
/// The ONE arm-side map from an executor failure to the reason string a waiter
/// receives (and GuardianEngine logs). Shared by dispatch_arm_off_lock's admission
/// branch and on_arm_complete's worker-failure branch so the two cannot drift
/// (governance consistency c-1); the reader keeps its own read-side strings
/// (guardian_state_reader.cpp). Exhaustive: -Wswitch enforces a new IoFailure here.
[[nodiscard]] const char* arm_failure_reason(IoFailure f) noexcept {
    switch (f) {
    case IoFailure::Timeout:           return "arm timed out";
    case IoFailure::Stopped:           return "stopping";
    case IoFailure::CapacityExhausted: return "arm capacity exhausted";
    case IoFailure::AlreadyRunning:    return "arm already in progress for this key";
    case IoFailure::LaunchFailed:      return "arm worker launch failed";
    case IoFailure::WorkerThrew:       return "arm worker threw";
    case IoFailure::CeilingExhausted:  return "arm rejected at alive-worker ceiling";
    }
    return "arm failed";
}

/// up-3 (#4221): a runtime-level refusal, not an IoFailure - the compensating-
/// disarm reservation pool (compensation_reserved_count_) is exhausted for this
/// claim's IoClass. Deliberately NOT a case in arm_failure_reason's switch above:
/// that map is exhaustively keyed on IoFailure (governance consistency c-1) and
/// this refusal happens BEFORE io_executor_ is ever consulted. Named here so both
/// call sites that report it route through the same string, not an ad-hoc literal.
constexpr const char* kCompensationReservationExhausted =
    "compensating-disarm reservation exhausted";
/// up-2 (#4221, rung 9c PR-5c): a genuinely new claimant (different rule_id) tried
/// to attach onto a key whose head is Wedged - refused immediately rather than
/// queued, matching kCompensationReservationExhausted's own "one named constant,
/// not an ad-hoc literal at the call site" pattern.
constexpr const char* kSparkKeyWedged = "spark key wedged";
} // namespace

std::function<void(const SparkEvent&)>
GuardianSparkRuntime::make_handler(std::shared_ptr<GuardianSparkRuntime> rt) {
    // Capture ONLY the shared_ptr: detach-safe. A late/detached dispatch touches
    // solely runtime-owned state, which this keeps alive.
    return [rt = std::move(rt)](const SparkEvent& ev) { rt->on_event(ev); };
}

bool GuardianSparkRuntime::release_claim_index_locked(KeyClaim& claim) noexcept {
    if (!claim.index_held)
        return true;
    // Adversarial re-review r2 C2: remove FIRST, clear the ownership flag AFTER.
    // remove_rule's one allocation (its key copy) precedes its mutation, so a throw
    // leaves both the index mapping and index_held intact - the next release for this
    // claim (the drain's finished sweep, a later detach) retries and succeeds. The
    // old order cleared the flag first, so a throw left a stale mapping that nothing
    // could ever remove: the key's refcount never reached zero again (no disarm on
    // the real owner's detach - a leaked subscription) and a same-key re-attach of
    // the rule could hit a ghost entry.
    //
    // Adversarial re-review r3 C2/C3: noexcept BY CONSTRUCTION. Callers reach this
    // from on_arm_complete() (noexcept: the finished sweep, publish_locked's fill-in,
    // the refill's fail_all_claims_locked) and from begin_stop() (which runs from the
    // destructor); before this round remove_rule's one allocation - the key copy it
    // RETURNS, which this caller never needed - could cross those noexcept boundaries
    // into std::terminate. SparkKeyRuleIndex::erase_rule is the same walk without that
    // copy: finds on stored strings and erases by iterator, nothing that can throw.
    // The try/catch below exists for the test seam (which throws to prove the
    // containment shape) and as defence in depth: a failure is counted, reported as
    // `false`, and index_held stays true so the next release retries.
    try {
        index_remove_fault_here_for_test(); // seam: "the index removal threw"
        // rung 9c PR-5a (#4221 up-101): pass claim.generation, not just claim.rule_id.
        // `index_held` alone does NOT stop a stale, retried release from clobbering a
        // replacement's mapping - it only stops THIS claim object calling erase twice.
        // A DIFFERENT, older claim's legitimately-retried release (fail_all_claims_locked's
        // "the next same-key event... retries the release" case) can fire after a
        // same-rule re-attach has already installed a new mapping for this rule_id; the
        // generation check inside erase_rule() is what makes that a safe no-op instead of
        // an erroneous erase of the newer owner's entry. (An earlier version of this
        // comment claimed index_held alone was sufficient - it was not; see the header
        // doc comment on SparkKeyRuleIndex::erase_rule.)
        index_->erase_rule(claim.rule_id, claim.generation); // noexcept; idempotent
    } catch (...) {
        claim_index_release_failures_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    claim.index_held = false;
    return true;
}

std::shared_ptr<GuardianSparkRuntime::KeyClaim>
GuardianSparkRuntime::try_dispatch_head_locked(const std::string& key) {
    const auto eit = claims_.find(key);
    if (eit == claims_.end())
        return nullptr;
    sweep_terminal_queued_locked(eit->second); // never dispatch a tombstone (pass-3 sg-3)
    if (eit->second.fifo.empty()) {
        claims_.erase(eit);
        return nullptr;
    }
    auto& head = eit->second.fifo.front();
    if (head->dispatch != ClaimDispatch::Queued)
        return nullptr;
    head->dispatch = ClaimDispatch::Dispatching;
    return head;
}

void GuardianSparkRuntime::sweep_terminal_queued_locked(KeyClaimQueue& entry) noexcept {
    auto& fifo = entry.fifo;
    while (!fifo.empty()) {
        auto& c = fifo.front();
        // A Dispatching/Dispatched head belongs to its drain (which pops it); only a
        // claim that was never dispatched and is already terminal is a tombstone.
        if (c->dispatch != ClaimDispatch::Queued || (!c->outcome && !c->commit_exception))
            return;
        if (!release_claim_index_locked(*c))
            return; // release still failing (seam): keep the tombstone for the next retry
        fifo.pop_front();
    }
}

void GuardianSparkRuntime::fail_all_claims_locked(const std::string& key, const std::string& reason,
                                                  ClaimEnd end) {
    const auto eit = claims_.find(key);
    if (eit == claims_.end())
        return;
    auto& fifo = eit->second.fifo;
    bool all_released = true;
    for (auto& c : fifo) {
        // up-5: a Disarm claim reached here (this function's only Disarm-relevant
        // caller: submit_disarm_off_lock's Stopped branch) never holds index_held
        // (release_claim_index_locked's own no-op check makes its release trivially
        // succeed), so it is unconditionally dropped by this function either via
        // the all_released erase below or the erase_if filter - a genuine terminal
        // removal either way. Harmless no-op for every Arm claim.
        clear_retained_locked(*c);
        // consistency-auditor Gate 4 finding (this governance run, C-1): this
        // function gained a second caller (dispatch_arm_off_lock's reservation-
        // exhaustion path, up-3) that CAN reach an Arm claim holding a
        // compensation_permit. Today that specific caller only ever fires before
        // its own head's reservation succeeds, and a Disarm-only fifo can never
        // hold a live Arm claim (detach_rule_locked's own invariant) - so this was
        // provably a no-op on every reachable path even before this call was added.
        // Added anyway, matching clear_retained_locked's own defensive placement
        // one line above: release_compensation_locked() is idempotent (a no-op if
        // `c` never held a permit), and calling it here means a FUTURE caller or a
        // future up-3 change that violates either invariant above releases the
        // slot immediately rather than only when `c`'s shared_ptr eventually goes
        // out of scope via the RAII backstop (still correct either way, but this is
        // more predictable and directly testable).
        release_compensation_locked(*c);
        // noexcept; a failure (test seam / defence in depth - erase_rule cannot throw)
        // is counted and the claim keeps its index ownership for a retry.
        if (!release_claim_index_locked(*c)) {
            all_released = false;
            c->withdrawn = true; // tombstone: the drain that next runs on this key sweeps
                                 // it (retrying the release) and never commits it
        }
        if (!c->outcome) {
            // Adversarial re-review r3 C2: this copy of `reason` allocates, and this
            // function is reached from on_arm_complete() (noexcept) via the refill's
            // admission-failure branch. Contained per claim: a waiter left without an
            // outcome is still bounded by its own deadline (its abandon path finds no
            // entry and returns "arm timed out"); never a std::terminate.
            try {
                c->outcome = std::unexpected(reason);
            } catch (...) {
                claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
            }
        }
        if (c->end == ClaimEnd::None)
            c->end = end;
    }
    if (all_released) {
        claims_.erase(eit); // noexcept: the key is free for the next same-key event
        return;
    }
    // Keep only the tombstones (Queued, withdrawn, index still held): the next
    // same-key attach queues behind them and its dispatch drives the head; the drain
    // then sweeps the tombstones, retrying their index release, and adopts the arm for
    // the live claim. Erase-by-iterator only: nothing here can throw.
    std::erase_if(fifo, [](const std::shared_ptr<KeyClaim>& c) { return !c->index_held; });
    for (auto& c : fifo)
        c->dispatch = ClaimDispatch::Queued;
}

std::string GuardianSparkRuntime::abandon_claim_locked(const std::string& key,
                                                       const std::shared_ptr<KeyClaim>& claim,
                                                       bool stopping) {
    // The caller-side half of the exactly-once decision, taken under the SAME
    // registry_mu_ acquisition the completion callback will take (#3816's shape, now on
    // the runtime side): either we get here first and the callback sees
    // waiter_abandoned, or the callback published first and the waiter never reaches
    // this. A timeout while the claim is still Dispatching (mid-submit()) is waiter
    // abandonment too - never erase a claim the dispatcher still expects to find.
    const std::string reason = stopping ? "stopping" : "arm timed out";
    if (claim->dispatch == ClaimDispatch::Queued) {
        release_claim_index_locked(*claim);
        // Never dispatched: queue-wait expiry. Erase it outright; nothing is in flight.
        if (const auto eit = claims_.find(key); eit != claims_.end()) {
            auto& fifo = eit->second.fifo;
            for (auto it = fifo.begin(); it != fifo.end(); ++it) {
                if (*it == claim) {
                    fifo.erase(it);
                    break;
                }
            }
            if (fifo.empty())
                claims_.erase(eit);
        }
        claim->end = stopping ? ClaimEnd::Stopped : ClaimEnd::WaiterTimedOutQueued;
    } else {
        // #4508 W0: candidacy never writes a generation owned by rules_.
        // A null rg means ordinary commit was attempted (the by-value argument
        // consumed it), whether that commit succeeded or threw. Nothing remains
        // on this claim that could be adopted.
        // W1: another candidate can only have become desired after this claim
        // was created, through a later attach or re-observation. A timeout is
        // not fresh desire: deactivate this incoming claim, not that candidate.
        // The walk and write cannot allocate; no separate locator can be lost.
        if (!stopping && claim->rg && !generation_committed_locked(*claim) &&
            wedge_candidate_exists_locked(claim->rule_id, claim.get()))
            claim->rg->active = false;
        release_claim_index_locked(*claim);
        claim->waiter_abandoned = true; // the completion callback finishes this episode
        // cpp-safety SHOULD (#4221, rung 9c PR-5c follow-up governance): when
        // `stopping` is true this writes ClaimEnd::Stopped DIRECTLY, bypassing
        // the WaiterTimedOutDispatched staging value that
        // reclassify_dispatching_race_locked()'s guard keys on. A stopping
        // runtime's own admission attempt also reports IoFailure::Stopped (see
        // dispatch_arm_off_lock's `real_end` computation), so this converges to
        // the same real-world value as the guard's own correction would have
        // produced - but that convergence is untested as an explicit
        // interleaving (a caller-side timeout landing here with `stopping`
        // already true, racing dispatch_arm_off_lock's own re-lock, is a
        // distinct 3-way race from the two Dispatching-window race tests this
        // PR already carries - see "the Dispatching-window race, Stopped
        // variant" in test_guardian_spark_runtime.cpp, which instead drives
        // WaiterTimedOutDispatched via expire_overdue_claims() and only THEN
        // calls begin_stop(), exercising the guard's correction path, not this
        // direct-write path). Flagging rather than adding a test: constructing
        // this exact interleaving deterministically needs a caller-side
        // wait_for_claim() timeout to land here with `stopping_` already true,
        // which existing seams (dispatch_entry_hook_for_test_, hang_next_arm)
        // don't currently give direct control over.
        claim->end = stopping ? ClaimEnd::Stopped : ClaimEnd::WaiterTimedOutDispatched;
    }
    if (!claim->outcome)
        claim->outcome = std::unexpected(reason);
    if (!stopping)
        backend_op_timeouts_.fetch_add(1, std::memory_order_relaxed);
    return reason;
}

std::expected<std::uint64_t, std::string>
GuardianSparkRuntime::wait_for_claim(const std::string& key, const std::shared_ptr<KeyClaim>& claim,
                                     std::chrono::steady_clock::time_point deadline) {
    std::unique_lock<std::mutex> lk{registry_mu_};
    claim_cv_.wait_until(lk, deadline, [&] {
        return claim->outcome.has_value() || claim->commit_exception || stopping_;
    });
    if (claim->commit_exception) {
        // The drain already undid this claim's own commit and erased it; the waiter
        // just re-raises on its own thread (existing "attach_rule throws" contract).
        const std::exception_ptr e = claim->commit_exception;
        lk.unlock();
        std::rethrow_exception(e);
    }
    if (claim->outcome)
        return *claim->outcome; // a real outcome wins over a concurrent stop
    // No outcome: the deadline elapsed, or begin_stop() flipped stopping_ while this
    // claim is dispatched (begin_stop drops QUEUED claims with an outcome itself).
    // Never dereference the empty optional - abandon under this same acquisition.
    return std::unexpected(abandon_claim_locked(key, claim, stopping_));
}

void GuardianSparkRuntime::submit_disarm_off_lock(const std::shared_ptr<KeyClaim>& claim) {
    const std::string key = claim->key;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        const auto eit = claims_.find(key);
        if (eit == claims_.end() || eit->second.fifo.empty() || eit->second.fifo.front() != claim)
            return; // completed, dropped, or not yet the head
        if (claim->dispatch != ClaimDispatch::Queued)
            return; // another caller (or a prior admission-refusal retry) is already
                    // driving it, or it already completed
        claim->dispatch = ClaimDispatch::Dispatching;
    }
    // rung 9c PR-2 Unit 3 (Astra opine review Blocker 4): genuinely non-blocking now -
    // submit(), not run(). detach_rule()/detach_all() (this function's only callers
    // besides attach_core()'s own off-lock prior-disarm/retained-head drives) return
    // as soon as this call is ADMITTED, not once the backend call physically
    // finishes; on_disarm_complete() below is the completion callback, invoked by
    // the detached worker whenever the real backend_->disarm() call actually
    // returns or throws - however long that takes. submit() itself has NO deadline
    // (guardian_io_executor.hpp: "there is no waiter to time out"), so the old
    // Timeout branch this function used to have is GONE, not merely moved: nothing
    // can ever pop this claim out from under a still-running backend call anymore
    // (Astra's own finding on the pre-Unit-3 code: "[run()'s] timeout branch pops
    // the claim while the backend call remains running... this is not the stronger
    // R5.2 guarantee that teardown finishes before rearm dispatch" - fixed by
    // construction, not by adding a new check).
    IoResult<void> adm{std::unexpect, IoFailure::LaunchFailed};
    try {
        auto self = shared_from_this();
        adm = io_executor_.submit(
            claim->io_class, key,
            [backend = backend_, sub = claim->subscription]() -> int {
                backend->disarm(sub);
                return 0;
            },
            [self, key, claim](IoResult<int>&& r) {
                self->on_disarm_complete(key, claim, std::move(r));
            });
    } catch (const std::exception& e) {
        try {
            spdlog::error("Guardian spark: building the disarm submission for key '{}' threw ({}) - "
                         "the disarm attempt itself failed, not just the backend call; the claim "
                         "is retained for the next same-key event",
                         ::yuzu::log_key_token(key), e.what());
        } catch (...) {
        }
    }
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        const auto eit = claims_.find(key);
        if (eit == claims_.end() || eit->second.fifo.empty() || eit->second.fifo.front() != claim)
            return; // the callback already ran (a fast completion) and popped/erased
                    // it, or begin_stop() dropped it meanwhile
        if (adm) {
            if (claim->dispatch == ClaimDispatch::Dispatching)
                claim->dispatch = ClaimDispatch::Dispatched;
            return;
        }
        if (adm.error() == IoFailure::Stopped) {
            // The executor refused admission at shutdown. Dropped with a count (R5.5
            // makes this the counted total); everything queued behind it goes with
            // it, since nothing can dispatch any more.
            claims_dropped_at_stop_.fetch_add(1, std::memory_order_relaxed);
            fail_all_claims_locked(key, "stopping", ClaimEnd::Stopped);
        } else {
            // Any OTHER synchronous admission refusal (capacity, key, ceiling,
            // launch, or the throw above): the backend call never ran. Retain the
            // claim at the head - never drop a disarm for capacity reasons (rung 9c
            // R5.2; before it the drop was one that #3415's missing counter egress
            // left invisible - #3415 stays OPEN, it is the egress issue, not this
            // drop) - and count it. The next same-key event (an attach, which then
            // queues its own arm behind this claim) re-drives it, and so does
            // redrive_retained_disarms() below, bounded and on demand.
            claim->dispatch = ClaimDispatch::Queued;
            ++claim->admission_rejections;
            mark_retained_locked(*claim);
        }
    }
    claim_cv_.notify_all();
}

void GuardianSparkRuntime::on_disarm_complete(const std::string& key,
                                              const std::shared_ptr<KeyClaim>& claim,
                                              IoResult<int>&& r) noexcept {
    // Runs on the detached io_executor_ worker (GuardianDetachedWorkerRole marked -
    // nothing here may take GuardianEngine::mtx_; registry_mu_ is fine), exactly
    // like on_arm_complete. A disarm has no commit and no compensation to run - it
    // is best-effort teardown of an OS resource nobody wants any more - so this is
    // far smaller: decide the claim's fate, pop it if it is genuinely done, dispatch
    // whatever queued behind it.
    std::shared_ptr<KeyClaim> refill;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        const auto eit = claims_.find(key);
        if (eit == claims_.end() || eit->second.fifo.empty() || eit->second.fifo.front() != claim)
            return; // cannot happen by construction (only this callback pops the
                    // head) - defensive: never touch a foreign entry
        auto& fifo = eit->second.fifo;
        if (!r) {
            // Only WorkerThrew is reachable here (submit() has no deadline, and
            // Stopped/other admission refusals are handled synchronously in
            // submit_disarm_off_lock above - a completion callback only ever fires
            // for a call that was genuinely admitted). Astra opine review Blocker 4:
            // "Record actual worker failure; retain for bounded retry rather than
            // pretend admission failed" - retained exactly like an admission
            // refusal (not popped, not marked terminal), but logged distinctly so
            // the two causes are never conflated in diagnostics.
            try {
                spdlog::error("Guardian spark: backend_->disarm() itself threw for key '{}' - "
                             "the disarm attempt failed on the worker, not at admission; the "
                             "claim is retained for the next same-key event",
                             ::yuzu::log_key_token(key));
            } catch (...) {
            }
            claim->dispatch = ClaimDispatch::Queued;
            ++claim->admission_rejections;
            mark_retained_locked(*claim);
            return;
        }
        clear_retained_locked(*claim); // up-5: a retained claim's own successful
                                       // completion is exactly the moment it stops
                                       // being "currently retained" - see disarm_
                                       // retained()'s doc comment.
        claim->end = ClaimEnd::DisarmDone;
        claim->outcome = 0;
        fifo.pop_front();
        if (fifo.empty())
            claims_.erase(eit);
        else
            refill = try_dispatch_head_locked(key); // an arm queued behind this disarm
    }
    claim_cv_.notify_all();
    if (refill)
        dispatch_arm_off_lock(key, refill);
}

std::size_t GuardianSparkRuntime::redrive_retained_disarms() {
    // rung 9c PR-2 Unit 3 (Astra opine review Blocker 4): "Provide a bounded, fair
    // maintenance pass for retained disarms. Otherwise rapid non-waiting
    // detach_all() submissions can exhaust capacity and leave deleted keys retained
    // indefinitely because no further same-key attach arrives." One attempted
    // submission per currently-Queued Disarm head, no sleeps/recursion/waiting for
    // quota - submit_disarm_off_lock's own admission-refusal handling re-retains it
    // if capacity is still unavailable, so this is safe to call as often as a
    // future heartbeat tick (Unit 5) likes. Also the general safety net for ANY
    // Queued disarm head nobody currently holds a live handle to (e.g. a caller's
    // own bookkeeping between detach_rule_locked() and submit_disarm_off_lock()
    // throwing) - the claim itself is always safely queued in claims_ regardless
    // of what happens to the caller's local handle, so this pass finds it either
    // way. Collected first, driven second (outside any lock, matching every other
    // off-lock dispatch site) since submit_disarm_off_lock takes registry_mu_
    // itself. Returns the number of claims this call attempted to redrive.
    std::vector<std::shared_ptr<KeyClaim>> retained;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        for (auto& [key, entry] : claims_) {
            if (entry.fifo.empty())
                continue;
            const auto& head = entry.fifo.front();
            if (head->kind == ClaimKind::Disarm && head->dispatch == ClaimDispatch::Queued)
                retained.push_back(head);
        }
    }
    for (const auto& c : retained)
        submit_disarm_off_lock(c);
    return retained.size();
}

void GuardianSparkRuntime::dispatch_arm_off_lock(const std::string& key,
                                                 const std::shared_ptr<KeyClaim>& claim) {
    // The claim is the Dispatching head; nothing else can dispatch it. Build the
    // submit() call: `fn` is the bare backend call (it needs nothing from this
    // runtime - #3816); the completion callback captures self_keepalive, NOT `this`,
    // because it runs on a detached io_executor_ worker that may outlive
    // ~GuardianSparkRuntime() (the class's established off-thread capture pattern).
    // shared_from_this()'s documented bad_weak_ptr, a bad_alloc copying `spec`, or a
    // synchronous admission refusal all land in the same place: the claim never
    // launched, no callback will ever fire, so fail the head and every arm queued
    // behind it here (they were all waiting on this one backend call).
    if (claim->kind != ClaimKind::Arm) {
        // Defensive: only an Arm claim is ever handed here (the FIFO invariant puts a
        // Disarm only at the head of an otherwise-empty entry, and every refill site
        // pops the disarm first). Hand a mis-routed disarm back to the retained state
        // rather than arm a spec it does not carry.
        assert(false && "dispatch_arm_off_lock: not an Arm claim");
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (claim->dispatch == ClaimDispatch::Dispatching)
            claim->dispatch = ClaimDispatch::Queued;
        return;
    }
    // rung 9c PR-5c (#4221) test seam: default-empty, one-shot, fired here at entry -
    // before this function takes registry_mu_ at all, so a hook body is free to call
    // expire_overdue_claims() (or anything else needing that lock) without deadlocking.
    // This is the window a caller-side timeout needs to land in, racing either the
    // reservation check just below or the executor submission further down, to
    // reproduce the Dispatching-window race deterministically.
    {
        std::function<void()> entry_hook;
        {
            std::lock_guard<std::mutex> lk{registry_mu_};
            entry_hook = std::move(dispatch_entry_hook_for_test_);
        }
        if (entry_hook)
            entry_hook();
    }
    // up-3 (#4221): reserve this claim's compensating-disarm slot BEFORE the arm is
    // ever submitted, while no subscription exists yet - see
    // compensation_reserved_count_'s header comment for why this is a separate,
    // runtime-side pool rather than an io_executor_ admission. On exhaustion, fail
    // the same way an ordinary capacity refusal already fails, before any backend
    // arm runs - never leave an undriven Dispatching claim, never dispatch the arm.
    {
        bool refused = false;
        {
            std::lock_guard<std::mutex> lk{registry_mu_};
            const auto eit = claims_.find(key);
            if (eit == claims_.end() || eit->second.fifo.empty() || eit->second.fifo.front() != claim)
                return; // already resolved/replaced before dispatch even began
            if (auto permit = try_reserve_compensation_locked(claim->io_class)) {
                // rung 9c PR-5b hardening (this governance run): the permit now
                // lives on the claim itself (KeyClaim::compensation_permit, an
                // RAII CompensationPermit) rather than a plain bool - see that
                // class's own doc comment for why. Nothing else about this branch
                // changes.
                claim->compensation_permit = std::move(*permit);
            } else {
                refused = true;
                compensation_reservation_refused_.fetch_add(1, std::memory_order_relaxed);
                // Dispatching-window race (rung 9c PR-5c, #4221): this claim may already
                // carry a stale WaiterTimedOutDispatched from a caller timeout that raced
                // this same re-lock - see reclassify_dispatching_race_locked()'s own doc
                // comment. Correct it before fail_all_claims_locked()'s guard would
                // otherwise leave it in place.
                reclassify_dispatching_race_locked(*claim, ClaimEnd::AdmissionRejected);
                try {
                    std::string reason{kCompensationReservationExhausted};
                    fail_all_claims_locked(key, reason, ClaimEnd::AdmissionRejected);
                } catch (...) {
                    claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
                    if (claim->dispatch == ClaimDispatch::Dispatching)
                        claim->dispatch = ClaimDispatch::Queued;
                }
            }
        }
        if (refused) {
            claim_cv_.notify_all();
            return;
        }
    }
    IoResult<void> adm{std::unexpect, IoFailure::LaunchFailed};
    try {
        auto self = shared_from_this();
        adm = io_executor_.submit(
            claim->io_class, key,
            [backend = backend_, spec = claim->spec]() -> std::expected<std::uint64_t, std::string> {
                return backend->arm(spec);
            },
            [self, key, claim](IoResult<std::expected<std::uint64_t, std::string>>&& r) {
                self->on_arm_complete(key, claim, std::move(r));
            });
    } catch (const std::exception& e) {
        try {
            spdlog::error("Guardian spark: building the arm submission for key '{}' threw ({}) - "
                          "the arm was never dispatched",
                          ::yuzu::log_key_token(key), e.what());
        } catch (...) {
        }
    }
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        const auto eit = claims_.find(key);
        if (eit == claims_.end() || eit->second.fifo.empty() || eit->second.fifo.front() != claim) {
            // The callback already ran (before submit() even returned) and erased or
            // replaced it - never touch whatever occupies the key now. If admission
            // itself failed, the callback never fired and never will; nothing else
            // will ever release this claim's reservation, so this call must.
            if (!adm)
                release_compensation_locked(*claim);
            return;
        }
        if (adm) {
            if (claim->dispatch == ClaimDispatch::Dispatching)
                claim->dispatch = ClaimDispatch::Dispatched;
            return;
        }
        // Synchronous submission failure (a throw building the call, or an executor
        // admission refusal): no arm was ever dispatched, so nothing can ever need
        // compensation for this claim - release its reservation now, in the same
        // critical section as the rest of this failure's bookkeeping.
        release_compensation_locked(*claim);
        // Adversarial re-review r3 C2: this branch is reached from on_arm_complete()
        // (noexcept) when a refill's admission is refused, and the reason string
        // allocates. Contained: on a throw the head is handed back to Queued (a
        // nothrow enum write) so the next same-key event - an attach, a detach,
        // begin_stop - re-drives or drops it, the failure is counted, and the
        // claims' waiters stay bounded by their own deadlines. Nothing crosses the
        // noexcept boundary. fail_all_claims_locked itself is contained per claim.
        try {
            const ClaimEnd real_end = adm.error() == IoFailure::Stopped ? ClaimEnd::Stopped
                                                                        : ClaimEnd::AdmissionRejected;
            // Dispatching-window race (rung 9c PR-5c, #4221): see
            // reclassify_dispatching_race_locked()'s own doc comment. Done before the
            // reason-string allocation below so the corrected classification survives
            // even if that allocation throws.
            reclassify_dispatching_race_locked(*claim, real_end);
            // Timeout/WorkerThrew are unreachable at admission (submit() has no
            // deadline; a throw happens on the worker) - the shared map keeps them so
            // the two sites can never drift (governance consistency c-1).
            std::string reason{arm_failure_reason(adm.error())};
            fail_all_claims_locked(key, reason, real_end);
        } catch (...) {
            claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
            if (claim->dispatch == ClaimDispatch::Dispatching)
                claim->dispatch = ClaimDispatch::Queued; // recoverable: re-driven by the next event
        }
    }
    claim_cv_.notify_all();
}

void GuardianSparkRuntime::fault_here_for_test(int point) {
    int expected = point;
    if (drain_fault_point_for_test_.compare_exchange_strong(expected, 0)) {
        // ch-1 (#4221): points 6/7/9 name fill-in-outcome allocations
        // (std::unexpected(std::string{...})) - point 9 is synthesize_fallback_
        // outcome_locked()'s own equivalent line, added this governance run
        // alongside dropping that function's incorrect `noexcept` (consistency-
        // auditor Gate 4 finding: the "mirror" function had no fault seam of its
        // own, unlike the loop it mirrors). Inject the exact exception each
        // allocation would actually throw under real memory pressure, matching
        // point 1's existing precedent, not a generic runtime_error.
        if (point == 1 || point == 6 || point == 7 || point == 8 || point == 9)
            throw std::bad_alloc{};
        throw std::runtime_error("drain fault point " + std::to_string(point) + " (test seam)");
    }
}

bool GuardianSparkRuntime::publish_arm_verdicts_locked(
    const std::string& key, const std::shared_ptr<KeyClaim>& claim,
    const std::vector<std::shared_ptr<KeyClaim>>& finished,
    std::vector<std::pair<std::shared_ptr<KeyClaim>, ArmVerdict>>& verdicts, bool firewall,
    std::shared_ptr<KeyClaim>& refill) {
    // registry_mu_ held (see the declaration's doc comment). PUBLISH the staged
    // verdicts, then pop every claim this drain finished (they are a prefix of the
    // fifo; new claims that queued behind the head meanwhile follow them). A claim
    // that already carries an outcome (a withdrawal published by detach_rule_locked,
    // an abandonment by its waiter) keeps it - the staged verdict fills only an
    // empty slot. Called exactly once per path (on_arm_complete's inline call, or
    // finalize_arm_compensation's deferred one) - neither re-runs it after a throw.
    // What "idempotent" means here: the per-claim `c->outcome || c->commit_exception`
    // guard above is what makes a claim's terminal state stick regardless of which
    // path published it, not repeated invocation of this function.
    const auto eit = claims_.find(key);
    if (eit == claims_.end())
        return true;
    auto& fifo = eit->second.fifo;
    for (auto& [c, v] : verdicts) {
        if (c->outcome || c->commit_exception)
            continue;
        if (v.ex)
            c->commit_exception = v.ex;
        else
            c->outcome = std::move(v.outcome);
        if (c->end == ClaimEnd::None)
            c->end = v.end;
    }
    fault_here_for_test(3); // seam: "the publish threw after the outcomes were written, before the pop"
    for (const auto& c : finished) {
        if (!c->outcome && !c->commit_exception) {
            // No verdict was staged for this claim: the drain threw before it got
            // there. Say what is TRUE: if its commit already ran (rules_ carries its
            // generation) the rule is live and the waiter gets its generation -
            // never "failed" for an armed rule (C2's second window); otherwise
            // it never committed and fails plainly.
            if (c->kind == ClaimKind::Arm && generation_committed_locked(*c)) {
                c->index_held = false; // ownership is rules_/keys_'s
                c->outcome = c->generation;
                c->end = ClaimEnd::Committed;
            } else {
                release_claim_index_locked(*c);
                fault_here_for_test(6); // ch-1 (#4221): "the finished loop's own
                                        // fill-in allocation threw" - downstream of
                                        // point 3, the seam that criterion actually
                                        // names and was missing until now.
                c->outcome = std::unexpected(std::string{"arm drain failed"});
                c->end = ClaimEnd::CommitThrew;
            }
        }
        if (!fifo.empty() && fifo.front() == c)
            fifo.pop_front();
    }
    if (firewall && !fifo.empty() && fifo.front() == claim) {
        // finished was never filled: the head is still here. Drop the entry.
        for (auto& c : fifo) {
            // Governance pass-3 cs-2: a claim whose index release fails (seam /
            // defence in depth) is KEPT as a Queued tombstone holding its mapping,
            // never dropped - dropping it would leave a ghost (key, rule) mapping
            // that makes the next same-key attach take the shared-watcher branch
            // for a key that has no PerKey. The next same-key event sweeps it.
            if (!release_claim_index_locked(*c)) {
                c->withdrawn = true;
                c->dispatch = ClaimDispatch::Queued;
            }
            if (!c->outcome) {
                fault_here_for_test(7); // ch-1: the SIBLING fill-in allocation, in
                                        // the firewall loop - shares this function
                                        // with the one above but has its own catch
                                        // recovery at each of the 3 call sites.
                c->outcome = std::unexpected(std::string{"arm drain failed"});
            }
            if (c->end == ClaimEnd::None)
                c->end = ClaimEnd::CommitThrew;
        }
        std::erase_if(fifo, [](const std::shared_ptr<KeyClaim>& c) { return !c->index_held; });
    }
    if (fifo.empty())
        claims_.erase(eit);
    else
        refill = try_dispatch_head_locked(key);
    return true;
}

void GuardianSparkRuntime::direct_disarm_fallback(const std::string& key, std::uint64_t sub) noexcept {
    try {
        backend_->disarm(sub);
    } catch (const std::exception& e) {
        try {
            spdlog::error("Guardian spark: compensating-disarm direct fallback for key '{}' "
                         "threw ({}) - best-effort teardown only, not retried again",
                         ::yuzu::log_key_token(key), e.what());
        } catch (...) {
        }
    } catch (...) {
    }
}

void GuardianSparkRuntime::finalize_arm_compensation(std::shared_ptr<ArmCompensation> cont) noexcept {
    // Runs on the detached io_executor_ worker that completed the compensating
    // disarm (or, on a synchronous admission refusal, on-the-arm-completion worker
    // that called this directly) - same thread-role guarantees as on_arm_complete
    // itself. Carries on_arm_complete's own former step-3 shape verbatim: a single
    // try wraps the (possibly firewalled) publish, a single catch counts the
    // failure and runs the SAME best-effort recovery (hand the head back to Queued,
    // or pop it if its verdict is already published) so a throw here can never
    // wedge the key until restart.
    std::shared_ptr<KeyClaim> refill;
    try {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (cont->firewalled)
            claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
        publish_arm_verdicts_locked(cont->key, cont->claim, cont->finished, cont->verdicts,
                                    cont->firewalled, refill);
        // up-3: the compensating disarm this continuation carried has now genuinely
        // completed (successfully or best-effort-failed - direct_disarm_fallback's
        // own contract) and its verdict is published. Same critical section as the
        // pop above.
        release_compensation_locked(*cont->claim);
        cont->claim->compensation_finished = true;
    } catch (...) {
        claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
        try {
            std::lock_guard<std::mutex> lk{registry_mu_};
            release_compensation_locked(*cont->claim);
            cont->claim->compensation_finished = true;
            const auto eit = claims_.find(cont->key);
            if (eit != claims_.end() && !eit->second.fifo.empty() &&
                eit->second.fifo.front() == cont->claim) {
                if (cont->claim->outcome || cont->claim->commit_exception) {
                    release_claim_index_locked(*cont->claim);
                    eit->second.fifo.pop_front();
                    if (eit->second.fifo.empty())
                        claims_.erase(eit);
                    else
                        refill = try_dispatch_head_locked(cont->key);
                } else {
                    cont->claim->dispatch = ClaimDispatch::Queued;
                }
            }
        } catch (...) {
        }
    }
    claim_cv_.notify_all();
    try {
        if (cont->waker)
            cont->waker();
        if (cont->outbox_waker)
            cont->outbox_waker();
    } catch (...) {
    }
    if (refill)
        dispatch_arm_off_lock(cont->key, refill);
}

void GuardianSparkRuntime::on_arm_complete(const std::string& key,
                                           const std::shared_ptr<KeyClaim>& claim,
                                           IoResult<std::expected<std::uint64_t, std::string>>&& r) noexcept {
    // Runs on the detached io_executor_ worker (GuardianDetachedWorkerRole marked -
    // nothing here may take GuardianEngine::mtx_; registry_mu_/outbox_mu_ are fine).
    //
    // Shape (rung 9c R5.2, commit-in-callback; rung 9c PR-2 Unit 4 changed step 2/3
    // from a blocking wait to an async hand-off - see below): (1) under registry_mu_,
    // decide the outcome of the head and every sibling and perform the commits. Then
    // ONE of two paths, chosen by whether a live subscription is left that nobody
    // adopted:
    //   - NOTHING TO DISARM (the ordinary adopted commit, or a failure with no live
    //     subscription): the outcomes are PUBLISHED and the finished claims POPPED
    //     inside this same acquisition. There is no instant at which keys_[key] is
    //     written while the head still sits in claims_[key] without an outcome - a
    //     same-key attach arriving after the unlock sees the committed watcher and
    //     joins it (the pre-existing reuse path), and detach_rule_locked sees a plain
    //     rules_ entry, never a "pending" claim (adversarial review C1/K1': that
    //     window let a rearm re-dispatch and mint an untracked second subscription,
    //     and let a detach mark a LIVE rule "withdrawn").
    //   - A COMPENSATING DISARM IS OWED: publication is DEFERRED, and (rung 9c PR-2
    //     Unit 4) so is EVERYTHING ELSE - this function builds an ArmCompensation
    //     continuation and hands it to submit(), then RETURNS. The head stays in the
    //     fifo as the key's marker until finalize_arm_compensation() actually runs
    //     (on the real completion, whenever that is - or synchronously, right here,
    //     on a synchronous admission refusal), so a rearm on the same key queues
    //     behind it exactly as before; nothing pops the claim, publishes an outcome,
    //     or dispatches a refill until the compensating disarm has genuinely
    //     finished (Astra opine review: "An unwanted successful arm is owned
    //     continuously; its replacement cannot dispatch ahead of compensation").
    //     Publishing only after compensation finishes keeps "attach_rule threw =>
    //     the rollback disarm already happened" true for the caller (:2187's
    //     contract) without any notify-order reasoning: no waiter can observe its
    //     outcome while a subscription nobody wants is still live.
    // OWNERSHIP FIRST (adversarial review C2/K5): if the backend armed, the live
    // subscription is owned by `compensating` before ANY fallible work - every vector
    // build, stage(), make_shared and commit below can throw, and the firewall path
    // below can only reclaim what this optional holds. A nothrow assignment; the
    // adopting commit resets it.
    std::optional<std::uint64_t> compensating; // a live subscription nobody adopted
    if (r && r->has_value())
        compensating = **r;
    std::vector<std::shared_ptr<KeyClaim>> finished;
    // Verdicts are STAGED here and written into the claims by publish_arm_verdicts_
    // locked below: a waiter's predicate reads the claim's own outcome/commit_
    // exception, and claim_cv_ is runtime-wide, so on the deferred path any other
    // key's notify (or a spurious wake) would otherwise let a waiter observe its
    // verdict before the compensating disarm has run. Notification is not
    // publication; the field write is.
    std::vector<std::pair<std::shared_ptr<KeyClaim>, ArmVerdict>> verdicts;
    const auto stage = [&](const std::shared_ptr<KeyClaim>& c,
                           std::optional<std::expected<std::uint64_t, std::string>> outcome,
                           std::exception_ptr ex, ClaimEnd end) {
        for (auto& [pc, v] : verdicts)
            if (pc == c)
                return; // first verdict for a claim wins
        verdicts.emplace_back(c, ArmVerdict{std::move(outcome), std::move(ex), end});
    };
    std::function<void()> waker;
    std::function<void()> outbox_waker;
    std::function<void()> gap_hook; // test seam; copied under the lock in (1)
    bool firewalled = false;
    bool published = false;
    std::shared_ptr<KeyClaim> refill;

    try {
        {
            std::unique_lock<std::mutex> lk{registry_mu_};
            gap_hook = drain_gap_hook_for_test_;
            const auto eit = claims_.find(key);
            const bool is_head = eit != claims_.end() && !eit->second.fifo.empty() &&
                                 eit->second.fifo.front() == claim;
            const bool armed_live = r && r->has_value();
            if (!is_head) {
                // Cannot happen by construction (only this callback pops the head) -
                // defensive: never leak the subscription, never touch a foreign entry.
                if (armed_live)
                    compensating = **r;
                stage(claim, std::unexpected(std::string{"arm claim orphaned"}), nullptr,
                      ClaimEnd::AdmissionRejected);
                claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
            } else {
                auto& fifo = eit->second.fifo;
                // Everything currently queued is an Arm claim behind this head (a disarm
                // is only ever created on a key with no live claim - see KeyClaim).
                // Pre-size every staging container NOW, so that after the adopting
                // commit has reset `compensating` no push/emplace below can reallocate
                // and throw (C2's second window: a throw after adoption would have
                // published "arm drain failed" for a rule that is live in rules_).
                fault_here_for_test(1);
                finished.reserve(fifo.size());
                std::vector<std::shared_ptr<KeyClaim>> live;
                live.reserve(fifo.size());
                verdicts.reserve(fifo.size());
                for (const auto& c : fifo)
                    finished.push_back(c);
                for (const auto& c : finished)
                    // Live = an Arm still wanted AND not yet terminal AND still owning
                    // its index mapping. The last two guards (governance pass-3
                    // sg-3/ar-4/cs-5) keep a tombstone or an already-published claim
                    // that survived a double fault from ever being committed twice.
                    if (c->kind == ClaimKind::Arm && !c->withdrawn && !c->waiter_abandoned &&
                        !c->outcome && !c->commit_exception && c->index_held)
                        live.push_back(c);

                // Adversarial-review correction (rung 9c PR-5d follow-up): this
                // comment previously claimed a wedged head is structurally the ONLY
                // claim that can ever be here - false. attach_core()'s up-2
                // immediate-refusal only fires once the head is ALREADY wedged at
                // attach time; a DIFFERENT rule_id that queued behind the head while
                // it was still Dispatching survives the transition to Wedged and
                // remains a live follower (see the up-2 comment elsewhere in this
                // file: "Live followers CAN exist behind a wedged head" - a
                // pre-existing test pins exactly this: an unrelated rule queued
                // before the wedge, still live when the wedge's late success
                // lands). What actually excludes adoption in that case is the
                // `live.empty()` runtime guard just below, not structural
                // uniqueness - when a live follower exists, the ordinary
                // live-siblings commit path handles it and this claim's own wedge
                // is not adopted (still recoverable on the next Reapply).
                // Candidacy ends by commitment or removal from claims_.
                const bool was_wedge = is_retained_wedge(*claim);

                // A still-desired wedge's late success can be adopted. Withdrawal
                // walks claims_ and clears candidacy before ordinary teardown.
                // The subscription is committed exactly
                // like an ordinary live claim's commit below, but `claim->outcome`/
                // `claim->end` are LEFT UNTOUCHED - the sticky-Wedged receipt (this
                // PR's own load-bearing invariant, pinned by test) records a fact
                // about the ORIGINAL episode's own timeout, not the rule's live
                // status; adoption is a second, independent signal entirely (R5.3's
                // "Three separate transitions, never collapsed"). `live` deliberately
                // never includes this claim (waiter_abandoned/outcome already exclude
                // it) - adoption is handled as its own branch, not by loosening that
                // filter, precisely because commit_new_generation_locked()'s siblings-
                // path assumes every `live` claim still owns its index mapping, which
                // a wedged claim does not (abandon_claim_locked released it
                // unconditionally the instant it wedged).
                bool adopted = false;
                // Governance Gate 7 fix (rung 9c PR-5d follow-up round 2,
                // defense-in-depth): a wedged claim's rg->active reading true does
                // NOT by itself prove nothing else has taken ownership of rule_id
                // in the meantime - governance Gate 2-4 found a real bug (fixed
                // at Gate 7, in attach_core's Reobserved-restore branch above)
                // that could violate that assumption on a fault-injection path.
                // Gate 8's OWN re-review then found this branch is ALSO
                // reachable via entirely ordinary desired-state churn, no fault
                // injection needed: rule R wedges on key A; R is redeployed to key
                // B (commits normally, rules_[R] now live on B); R is redeployed
                // BACK to key A while the ORIGINAL key-A arm is still in flight -
                // is_retained_wedge() never consults rg->active (see its own
                // definition), so the still-outstanding claim is genuinely
                // re-observed and its rg->active legitimately restored to true by
                // that Reobserved-restore branch, even though rules_[R] is
                // correctly live on B the whole time. Either way, wedge_may_adopt
                // intentionally does NOT itself check rules_ - that check is the
                // explicit, separately-counted-and-logged guard immediately below,
                // so BOTH the rare invariant-violation case and the ordinary churn
                // case are handled by the SAME code path rather than the latter
                // being assumed away.
                const bool wedge_may_adopt = was_wedge && !stopping_ && armed_live &&
                                             live.empty() && claim->rg && claim->rg->active;
                if (wedge_may_adopt && rules_.contains(claim->rule_id)) {
                    // rules_ already holding an entry for this rule_id while this
                    // claim's own rg->active reads true means SOMETHING else
                    // legitimately owns rule_id right now (an ordinary redeploy
                    // that landed after this claim wedged - the common case,
                    // proven reachable above - or, more rarely, the invariant
                    // violation the fix above closes) - never adopt over it.
                    // Refuse; the claim falls through to the ordinary non-adopt/
                    // compensating-disarm path below exactly as ANY other
                    // unwanted late success does (live.empty() is still true).
                    // Counted AND logged (Gate 8 finding: a bare "should be
                    // impossible" WARN mischaracterised the common redeploy-churn
                    // case as an anomaly) - see wedge_adopt_stale_refused()'s own
                    // doc comment for what a sustained, climbing rate means vs. an
                    // occasional one. INFO, not WARN (Gate 8 unhappy-path NICE
                    // finding): an occasional occurrence is expected operational
                    // noise from ordinary redeploy churn, not a fault - the
                    // counter, not the log level, is the signal a sustained rate
                    // would be worth investigating from, once wired to a fleet
                    // gauge (internal-only today, #3415).
                    wedge_adopt_stale_refused_.fetch_add(1, std::memory_order_relaxed);
                    try {
                        spdlog::info("Guardian spark: a late arm success for rule '{}' "
                                     "generation {} arrived after rules_ already gained "
                                     "a different entry for this rule_id (an ordinary "
                                     "redeploy landing while this claim was still wedged, "
                                     "or - rarely - an invariant violation) - disarming "
                                     "the stale success rather than adopting over the "
                                     "current live generation",
                                     ::yuzu::log_id_token(claim->rule_id), claim->generation);
                    } catch (...) {
                    }
                } else if (wedge_may_adopt) {
                    const std::uint64_t sub = **r;
                    bool index_readded = false;
                    try {
                        // Reacquire the mapping abandonment released. Safe to re-add at
                        // this exact (rule_id, generation): the guard immediately above
                        // has already confirmed rules_ holds NOTHING for rule_id right
                        // now, so nothing else currently owns it - a concurrent
                        // supersession is exactly what that check excludes, whether it
                        // arrived via detach_rule_locked's ordinary deactivation or (see
                        // that guard's own comment) an ordinary ongoing redeploy.
                        index_->add(key, claim->rule_id, claim->generation); // may throw
                        index_readded = true;
                        auto fresh = std::make_shared<PerKey>();
                        fresh->spec = claim->spec;
                        fresh->subscription = sub;
                        if (!keys_.emplace(key, fresh).second)
                            throw std::logic_error(
                                "spark runtime: keys_ already holds a watcher for an adopted key");
                        try {
                            // Pass rg by COPY, not std::move like the ordinary commit
                            // path below - claim keeps its own reference (harmless, one
                            // extra shared_ptr refcount) rather than being left with a
                            // null rg, since nothing here needs to null it out.
                            commit_new_generation_locked(claim->rule_id, claim->generation,
                                                         claim->guard_type, claim->rule_name,
                                                         fresh, claim->rg, claim->attach_now,
                                                         waker, outbox_waker,
                                                         CommitPath::CallbackAdopt);
                        } catch (...) {
                            rules_.erase(claim->rule_id);
                            fresh->pending_initial.erase(claim->rule_id);
                            keys_.erase(key);
                            throw;
                        }
                        compensating.reset(); // adopted - no compensating disarm owed
                        // Explicit, not relied-upon-as-already-false: the ordinary
                        // stuck-index-release fault seam (set_index_remove_fault_for_test)
                        // can leave a wedged claim's index_held stuck true from
                        // abandonment - index_->add() above is still a safe idempotent
                        // no-op against the same (key, rule_id, generation) in that case,
                        // but this claim's OWN bookkeeping must say ownership has passed
                        // to rules_/keys_ regardless of how it arrived here, matching the
                        // ordinary live-commit path's identical line below.
                        claim->index_held = false;
                        adopted = true;
                    } catch (...) {
                        // Adoption failed (index_->add or the commit itself threw):
                        // fall back to the existing safe default below - `compensating`
                        // still holds `sub` (never reset above on this path), so the
                        // deferred compensating-disarm branch runs normally, exactly as
                        // an ordinary not-wanted late success always has. No verdict is
                        // (re-)staged here: claim already carries its original "arm
                        // timed out" outcome / Wedged end from abandonment.
                        if (index_readded)
                            index_->erase_rule(claim->rule_id, claim->generation); // noexcept
                    }
                }

                if (adopted) {
                    // Nothing to stage: publish_arm_verdicts_locked's own per-claim
                    // guard (`if (c->outcome || c->commit_exception) continue;`) leaves
                    // an already-resolved claim's outcome/end untouched regardless -
                    // only the subscription changed hands. `finished`'s normal pop-
                    // from-fifo below still runs unconditionally.
                } else if (stopping_ || live.empty()) {
                    // Nobody is left to adopt the result: withdrawn, abandoned, or the
                    // runtime is stopping (R5.5: a late success is disarmed, never left
                    // live). No "armed" audit - nothing committed.
                    for (const auto& c : finished) {
                        release_claim_index_locked(*c);
                        stage(c, std::unexpected(std::string{stopping_ ? "stopping" : "withdrawn"}),
                              nullptr, stopping_ ? ClaimEnd::Stopped : ClaimEnd::Withdrawn);
                        fault_here_for_test(8); // up-4 (#4221) test seam: fires AFTER
                                                // this claim's own verdict is staged,
                                                // so on a multi-claim batch it leaves
                                                // any LATER sibling un-staged for
                                                // publish_arm_verdicts_locked's own
                                                // fill-in loop (ch-1's seam) to
                                                // backstop.
                    }
                    if (armed_live) {
                        // `compensating` already owns the subscription (entry).
                        if (claim->waiter_abandoned)
                            backend_op_late_arms_.fetch_add(1, std::memory_order_relaxed);
                    }
                } else if (!r) {
                    // The executor's own outer failure. Only WorkerThrew is reachable
                    // here (submit() has no deadline and admission refusals never reach
                    // a callback); the full map is kept for PR-5.
                    std::string reason{arm_failure_reason(r.error())};
                    if (r.error() == IoFailure::Timeout)
                        backend_op_timeouts_.fetch_add(1, std::memory_order_relaxed);
                    for (const auto& c : finished) {
                        release_claim_index_locked(*c);
                        stage(c, std::unexpected(reason), nullptr,
                              r.error() == IoFailure::WorkerThrew ? ClaimEnd::WorkerThrew
                                                                 : ClaimEnd::AdmissionRejected);
                    }
                } else if (!armed_live) {
                    // backend_->arm() itself refused (synchronously, on the worker) - the
                    // key genuinely could not be armed, so every sibling fails with it.
                    for (const auto& c : finished) {
                        release_claim_index_locked(*c);
                        stage(c, std::unexpected(r->error()), nullptr, ClaimEnd::BackendRefused);
                    }
                } else {
                    // Success: commit every live claim, in FIFO order, against the ONE
                    // new subscription. `compensating` has owned it since entry; the
                    // first surviving claim's commit adopts it, so a throw anywhere
                    // before that (make_shared, keys_.emplace, a waker copy, the
                    // lifecycle enqueue) leaves it owned by the disarm step below,
                    // never leaked - the same shape the pre-R5.2 post-wait commit's
                    // rollback had.
                    const std::uint64_t sub = **r;
                    std::shared_ptr<PerKey> pk;
                    for (const auto& c : live) {
                        if (!pk) {
                            // First surviving claim (the head may itself be withdrawn):
                            // its commit is what makes keys_[key] live. Undo on throw:
                            // erase what this claim wrote and leave `compensating` set.
                            try {
                                auto fresh = std::make_shared<PerKey>();
                                fresh->spec = claim->spec; // the spec actually armed
                                fresh->subscription = sub;
                                if (!keys_.emplace(key, fresh).second) {
                                    // A claimed key has no keys_ entry by construction
                                    // (attach_rule queues behind a claim instead of
                                    // writing keys_). Committing against a PerKey that is
                                    // not the one in keys_ would leave `sub` untracked
                                    // forever (adversarial review C1); fail the claim
                                    // and let the compensating disarm reclaim `sub`.
                                    throw std::logic_error(
                                        "spark runtime: keys_ already holds a watcher for a claimed key");
                                }
                                try {
                                    commit_new_generation_locked(c->rule_id, c->generation,
                                                                 c->guard_type, c->rule_name,
                                                                 fresh, std::move(c->rg),
                                                                 c->attach_now, waker, outbox_waker,
                                                                 CommitPath::CallbackArm);
                                } catch (...) {
                                    rules_.erase(c->rule_id);
                                    fresh->pending_initial.erase(c->rule_id);
                                    keys_.erase(key);
                                    throw;
                                }
                                pk = fresh;
                            } catch (...) {
                                release_claim_index_locked(*c);
                                stage(c, std::nullopt, std::current_exception(),
                                      ClaimEnd::CommitThrew);
                                // `compensating` still holds `sub`: the remaining live
                                // claims cannot adopt a subscription whose PerKey does
                                // not exist, so they fail with a plain reason.
                                for (const auto& other : live) {
                                    if (other == c)
                                        continue;
                                    release_claim_index_locked(*other);
                                    stage(other, std::unexpected(std::string{"arm commit failed"}),
                                          nullptr, ClaimEnd::CommitThrew);
                                }
                                break;
                            }
                            compensating.reset(); // adopted
                            c->index_held = false; // ownership passed to rules_/keys_
                            fault_here_for_test(2);
                            stage(c, c->generation, nullptr, ClaimEnd::Committed); // nothrow: reserved
                        } else {
                            // A later sibling joins the existing shared watcher - the
                            // pre-existing reuse path, one commit per claim. A throw here
                            // undoes only THIS claim's own bookkeeping; the drain continues.
                            try {
                                commit_new_generation_locked(c->rule_id, c->generation,
                                                             c->guard_type, c->rule_name, pk,
                                                             std::move(c->rg), c->attach_now,
                                                             waker, outbox_waker,
                                                             CommitPath::CallbackShared);
                                c->index_held = false;
                                stage(c, c->generation, nullptr, ClaimEnd::Committed);
                            } catch (...) {
                                rules_.erase(c->rule_id);
                                pk->pending_initial.erase(c->rule_id);
                                release_claim_index_locked(*c);
                                stage(c, std::nullopt, std::current_exception(),
                                      ClaimEnd::CommitThrew);
                            }
                        }
                    }
                    // Claims that were withdrawn/abandoned while their siblings adopted.
                    for (const auto& c : finished) {
                        release_claim_index_locked(*c);
                        stage(c, std::unexpected(std::string{c->withdrawn ? "withdrawn"
                                                                          : "arm timed out"}),
                              nullptr,
                              c->withdrawn ? ClaimEnd::Withdrawn
                                           : ClaimEnd::WaiterTimedOutDispatched);
                    }
                }
            }
            // Nothing to disarm: publish and pop NOW, under this same acquisition.
            // The deferred path (below, after this try/catch) is taken whenever
            // `compensating` is still set - either because nothing adopted it above,
            // or because staging itself threw AFTER `compensating` was set but before
            // reaching here (the exception unwinds past this call entirely).
            if (!compensating) {
                published = publish_arm_verdicts_locked(key, claim, finished, verdicts, false, refill);
                // up-3: the ordinary, non-faulted happy path (including "nothing was
                // ever owed a disarm" and "commit threw / worker threw / backend
                // refused") - `claim`'s compensation is resolved (never became owed)
                // the instant this call returns without throwing. Same critical
                // section as the pop inside it. The `if (!published)` recovery path
                // below has its own release calls for when THIS call throws instead.
                release_compensation_locked(*claim);
                claim->compensation_finished = true;
            }
        }
    } catch (...) {
        firewalled = true;
    }

    // Test seam: the only gap in which the key's outcome is decided but its claims
    // are still unpublished. Reachable on the deferred (compensating) path alone -
    // an ADOPTED commit published above - so a test that parks here around a plain
    // successful attach pins that the window is gone.
    if (!published && gap_hook)
        gap_hook();

    if (compensating) {
        // rung 9c PR-2 Unit 4 (Astra opine review): reached either because nothing
        // adopted the live subscription in the ordinary case above, OR because
        // staging itself threw AFTER `compensating` was set (the old firewall path -
        // folded into this ONE shared branch instead of a separate post-hoc check,
        // since both need identical treatment: build the continuation, submit the
        // disarm, hand off the rest of the job).
        //
        // Adversarial review C1 (PR #4318, fjarvis): building `cont` is itself
        // fallible (make_shared's allocation, the `key` string copy) - it MUST run
        // under its own try while `sub` is still tracked, because this whole
        // function is noexcept and an uncaught throw here would terminate the
        // process with the OS watcher never disarmed. `sub` is captured into a
        // local FIRST so ownership never depends on `cont` existing; on a throw,
        // `finished`/`verdicts`/`waker`/`outbox_waker` are untouched (the moves
        // into `cont` happen only after the build succeeds), so the failure path
        // falls through to the same "nothing owed" recovery the ordinary
        // no-compensation case already uses below.
        //
        // Gate 8 re-review (cpp-safety + security-guardian, both independent):
        // `cont` MUST NOT become observable (non-null) until BOTH fallible steps
        // (the allocation AND the `key` copy) have succeeded - `make_shared`
        // succeeding while the very next statement (`cont->key = key`) throws
        // left a non-null `cont` behind (std::string::operator= gives the strong
        // guarantee, so `cont->key` stayed "" - not the real key), which made
        // `if (cont)` below run the FULL continuation on top of the direct
        // disarm the catch handler had already issued: a redundant
        // backend->disarm(sub) (harmless only because SparkEngine::disarm() is
        // id-idempotent and ids are never recycled - not a documented contract),
        // and a poisoned `cont->key` that made finalize_arm_compensation()'s
        // claims_.find(cont->key) miss the real key entirely - the head claim,
        // already terminal, was never popped, permanently wedging that key
        // (no arm/disarm possible again on it short of a process restart, a
        // silent enforcement hole in this exact per-rule chokepoint). Built into
        // a local FIRST and moved into `cont` only as the LAST statement of the
        // try, so `cont`'s nullity is atomic with respect to the whole build:
        // any throw anywhere in the try (allocation or the key copy) leaves
        // `cont` null, one direct_disarm_fallback() runs, and the fallthrough
        // below is reached exactly as intended - `if (cont)` is a true single
        // discriminator again.
        // up-3/up-4 (#4221): compensation is now owed for `claim` - mark it not-yet-
        // finished (expire_overdue_claims()'s terminal-recovery pass must never reap
        // a head whose compensation is still outstanding) and establish its ONE
        // absolute observation deadline, set once and never reset by a later
        // fallback retry.
        {
            std::lock_guard<std::mutex> lk{registry_mu_};
            claim->compensation_finished = false;
            if (claim->compensation_deadline == std::chrono::steady_clock::time_point{})
                claim->compensation_deadline = std::chrono::steady_clock::now() + cfg_.backend_op_deadline;
        }
        const std::uint64_t sub = *compensating;
        compensating.reset(); // ownership from here is `cont` (below) or the direct
                               // disarm on the catch path - never this optional again
        std::shared_ptr<ArmCompensation> cont;
        try {
            fault_here_for_test(4); // seam: "the continuation allocation threw"
            auto built = std::make_shared<ArmCompensation>();
            fault_here_for_test(5); // seam: "the key copy threw with `built` already alive"
            built->key = key; // the only other fallible op here (string copy)
            cont = std::move(built); // non-null ONLY once the whole build has succeeded
        } catch (...) {
            try {
                spdlog::error("Guardian spark: building the compensating-disarm continuation "
                             "for key '{}' threw - falling back to a direct disarm on this "
                             "worker", ::yuzu::log_key_token(key));
            } catch (...) {
            }
            direct_disarm_fallback(key, sub);
            firewalled = true;
        }
        if (cont) {
            cont->claim = claim;
            cont->sub = sub;
            cont->finished = std::move(finished);
            cont->verdicts = std::move(verdicts);
            cont->waker = std::move(waker);
            cont->outbox_waker = std::move(outbox_waker);
            cont->firewalled = firewalled;

            IoResult<void> adm{std::unexpect, IoFailure::LaunchFailed};
            try {
                auto self = shared_from_this();
                adm = io_executor_.submit(
                    claim->io_class, key,
                    [backend = backend_, sub]() -> int {
                        backend->disarm(sub);
                        return 0;
                    },
                    [self, cont](IoResult<int>&& res) {
                        // Only WorkerThrew is reachable here (submit() has no deadline) -
                        // Astra opine review: "A disarm exception remains best-effort
                        // teardown failure, not proof that an OS resource disappeared."
                        if (!res.has_value()) {
                            try {
                                spdlog::error("Guardian spark: compensating disarm's own worker "
                                             "threw for key '{}' - retrying once, best-effort",
                                             ::yuzu::log_key_token(cont->key));
                            } catch (...) {
                            }
                            self->direct_disarm_fallback(cont->key, cont->sub);
                        }
                        self->finalize_arm_compensation(cont);
                    });
            } catch (const std::exception& e) {
                try {
                    spdlog::error("Guardian spark: building the compensating-disarm submission for "
                                 "key '{}' threw ({}) - falling back to a direct call on this worker",
                                 ::yuzu::log_key_token(key), e.what());
                } catch (...) {
                }
            }
            if (!adm) {
                // Synchronous admission refusal (including Stopped - Astra opine review:
                // "Stopped cannot silently discard a subscription that the late arm just
                // produced"): no worker will ever call back for this attempt, so finish
                // it right here, off-lock, on this already-detached worker (never the
                // engine caller, never under registry_mu_).
                direct_disarm_fallback(key, sub);
                finalize_arm_compensation(cont);
            }
            return;
        }
        // `cont` never came into being: `sub` was already disarmed directly above,
        // and `finished`/`verdicts`/`waker`/`outbox_waker` are still intact locals -
        // fall through into the ordinary "nothing owed" recovery path below.
    }

    if (!published) {
        // Nothing was ever owed a disarm (an ordinary failure with no live
        // subscription, or staging threw before `compensating` was ever set) - the
        // same double-fault recovery shape finalize_arm_compensation() carries for
        // the deferred path, inline here since there is no continuation to build.
        try {
            std::lock_guard<std::mutex> lk{registry_mu_};
            if (firewalled)
                claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
            published = publish_arm_verdicts_locked(key, claim, finished, verdicts, firewalled, refill);
            // up-3: reached whether `claim` was never owed a disarm at all, or a
            // synchronous direct_disarm_fallback() already resolved it above (the
            // `cont`-never-built fallthrough) - either way its compensation is fully
            // resolved by this point. Same critical section as the pop above.
            release_compensation_locked(*claim);
            claim->compensation_finished = true;
        } catch (...) {
            // A throw here (the lock, or the fill-in allocations, now the only
            // throwing steps left on this path since the index release became
            // noexcept - r3 C2) leaves the entry as-is; the waiters' own deadlines
            // still bound them, and the count records that this path fired.
            // Best-effort recovery so the key is not wedged until restart: if the
            // head is still this claim, hand it back to Queued so the next same-key
            // event re-drives it (its old result was already disarmed or committed
            // above; a re-arm on a committed key fails at the keys_.emplace hard
            // error and is compensated, never leaked). Double-fault only; contained
            // again.
            claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
            try {
                std::lock_guard<std::mutex> lk{registry_mu_};
                // Independent of whatever recovery below achieves: `claim`'s own
                // compensation (if any was ever owed) is already resolved by this
                // point on every path that reaches here - see this catch's own doc
                // comment above.
                release_compensation_locked(*claim);
                claim->compensation_finished = true;
                const auto eit = claims_.find(key);
                if (eit != claims_.end() && !eit->second.fifo.empty() &&
                    eit->second.fifo.front() == claim) {
                    if (claim->outcome || claim->commit_exception) {
                        // Its verdict IS published (the throw came after the write):
                        // the head is terminal, so pop it rather than leave a Dispatched
                        // tombstone nothing pops - a detach would then queue a Disarm
                        // behind it that nothing drives (governance pass-3 sg-3/ar-4/cs-5).
                        release_claim_index_locked(*claim); // noexcept; no-op once committed
                        eit->second.fifo.pop_front();
                        if (eit->second.fifo.empty())
                            claims_.erase(eit);
                        else
                            refill = try_dispatch_head_locked(key); // sweeps finished siblings
                    } else {
                        claim->dispatch = ClaimDispatch::Queued;
                    }
                }
            } catch (...) {
            }
        }
    }
    // Wake + notify. Waiters were unreachable until now.
    claim_cv_.notify_all();
    try {
        if (waker)
            waker();
        if (outbox_waker)
            outbox_waker();
    } catch (...) {
    }
    if (refill)
        dispatch_arm_off_lock(key, refill);
}

std::size_t GuardianSparkRuntime::claim_queue_depth_for_test(const std::string& key) const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    const auto eit = claims_.find(key);
    return eit == claims_.end() ? 0 : eit->second.fifo.size();
}

std::pair<std::uint64_t, std::uint64_t> GuardianSparkRuntime::application_fence_for_test() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    return {detach_epoch_, gen_counter_};
}

void GuardianSparkRuntime::commit_new_generation_locked(
    const std::string& rule_id, std::uint64_t gen, const char* guard_type,
    const std::string& rule_name, const std::shared_ptr<PerKey>& pk,
    std::shared_ptr<RuleGeneration> rg, std::chrono::steady_clock::time_point attach_now,
    std::function<void()>& waker, std::function<void()>& outbox_waker, CommitPath via) {
    rules_.insert_or_assign(rule_id, std::move(rg));
    pk->pending_initial.insert_or_assign(rule_id, PendingState{attach_now, 0, false});
    // Copy the wakers (throwing std::function copies) BEFORE the lifecycle enqueue so
    // a throw here rolls back with NO audit entry yet - see the callers' own rollback
    // guards for the full reasoning.
    waker = pending_initial_waker_;
    outbox_waker = outbox_enqueue_waker_;
    enqueue_lifecycle_locked(rule_id, gen, "armed", guard_type, rule_name);
    // R5.7 T2 (docs/spark-stage2-guardian-consumer-design.md): the runtime's own
    // arm-confirmation commit - the ONLY valid log-side proxy for "this rule is
    // armed" under spark (SparkEngine's own "armed" line fires before the OS
    // watch exists - see spark_engine.cpp). `epoch` is detach_epoch_ read under
    // the registry_mu_ this function already holds - it names which application
    // (full_sync teardown) this commit belongs to; `incarnation` is `gen`, this
    // attach's own gen_counter_ token, NOT the server policy generation. Fully
    // firewalled INCLUDING the clock read and the duration math: this runs after
    // the lifecycle enqueue above, and an escaping throw here would leave an
    // "armed" audit record enqueued while every caller's own rollback (a
    // catch(...) at the callback sites, a GuardianRollback guard at the inline
    // sites) undoes rules_/pending_initial. Same firewall shape as the lifecycle
    // window-raise log above and spark_engine.cpp's own armed-log site.
    // FIELD ORDER IS PINNED by the #3990 driver's own regex
    // (docs/spark-rebuild-baselines/fullsync_blackout_diag.py's T2_RE) - change
    // both together. The line is built by format_arm_committed_line (guardian_spark_timing.cpp),
    // which neutralises the operator-authored rule id so a hostile id cannot forge a second
    // log line.
    try {
        const auto attach_to_commit_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                             clock_() - attach_now).count();
        spdlog::info("{}", format_arm_committed_line(rule_id, detach_epoch_, gen, guard_type,
                                                     commit_path_name(via), attach_to_commit_ms));
    } catch (...) {
    }
}

const char* commit_path_name(GuardianSparkRuntime::CommitPath path) {
    using P = GuardianSparkRuntime::CommitPath;
    switch (path) {
    case P::InlineArm:
        return "inline-arm";
    case P::InlineShared:
        return "inline-shared";
    case P::CallbackArm:
        return "callback-arm";
    case P::CallbackShared:
        return "callback-shared";
    case P::CallbackAdopt:
        return "callback-adopt";
    }
    return "Unknown"; // unreachable if the switch above is kept exhaustive
}

std::expected<std::uint64_t, std::string>
GuardianSparkRuntime::attach_rule(std::string rule_id, SparkSpec spec, RuleAssertion assertion,
                                  bool emit_compliant_edge) {
    const std::string key = spark_key(spec);
    std::shared_ptr<KeyClaim> arm_claim; // written by attach_core() iff it returns Pending

    // #3831 (rung 9c R5.2 shape): this guard protects the claim enqueue inside
    // attach_core()'s locked block, but the work it must ALSO wrap - the off-lock
    // dispatch and the bounded wait below, both still owned by THIS function - runs
    // OFF both locks, in a region after attach_core() has already returned. Function-
    // scoped, one object spanning both regions, .fn assigned HERE before
    // registry_mu_ is even locked, so a throw during the assignment (a multi-capture
    // closure exceeding libstdc++'s std::function SBO heap-allocates) has nothing to
    // roll back yet - the original defect was a guard whose .fn was assigned AFTER
    // the mutation it protected, which left the key's marker orphaned forever on a
    // bad_alloc. arm_claim starts null and is set (a noexcept pointer write, inside
    // attach_core()) immediately after the enqueue succeeds, so fn no-ops until then.
    // Matched on POINTER identity: a same-rule_id retry that has since queued a FRESH
    // claim is a different object, so this guard can never touch it (stronger than
    // the (rule_id, generation) match the InFlightArm shape needed).
    //
    // Lock order: fn takes registry_mu_, yet it is declared while the caller has NOT
    // locked it, and it can fire while attach_core()'s own locked block still holds
    // it. Safe only because that block's own std::unique_lock is a NARROWER scope
    // than this function-scope guard - C++ unwind destructs the narrower scope's
    // locals (releasing registry_mu_) before continuing to unwind this one. Moving
    // this declaration into attach_core() would deadlock on exactly that unwind path
    // (rung 9c PR-2, Unit 1: kept in THIS function for exactly this reason - see
    // attach_core()'s own doc comment).
    GuardianRollback claim_rollback;
    claim_rollback.fn = [this, key, &arm_claim] {
        if (!arm_claim)
            return; // never enqueued (or not yet) - nothing to undo
        std::lock_guard<std::mutex> lk{registry_mu_};
        // Only if the claim is still live in its entry: a completed/erased claim is
        // already terminal and needs no undo.
        const auto eit = claims_.find(key);
        if (eit == claims_.end())
            return;
        bool present = false;
        for (const auto& c : eit->second.fifo)
            if (c == arm_claim) {
                present = true;
                break;
            }
        if (!present || arm_claim->outcome || arm_claim->commit_exception)
            return;
        abandon_claim_locked(key, arm_claim, stopping_);
        claim_cv_.notify_all();
    };

    AttachCoreResult core = attach_core(key, std::move(rule_id), std::move(spec),
                                       std::move(assertion), emit_compliant_edge, arm_claim);
    switch (core.state) {
    case AttachCoreState::Armed:
        return core.generation;
    case AttachCoreState::Failed:
        return std::unexpected(std::move(core.error));
    case AttachCoreState::Pending:
        break; // fall through to the bounded wait below
    case AttachCoreState::Reobserved:
        // up-2 (#4221, rung 9c PR-5c): the existing wedged head's own outcome is
        // already set (abandon_claim_locked wrote it when that claim first timed
        // out) - return it directly. This function's return type has no way to
        // expose a receipt for later polling, so there is nothing to wait on: the
        // wedge is already a known, resolved-shaped fact. Do NOT wait on or
        // re-abandon core.claim - this call owns nothing, it only observed.
        if (core.claim->outcome)
            return *core.claim->outcome;
        return std::unexpected(std::string{kSparkKeyWedged}); // defensive: outcome
                                                               // should always be set
                                                               // for a retained wedge
    }

    // The bounded wait for THIS call's own claim (PR-1's synchronous contract: a
    // caller - GuardianEngine::apply_rules/start_local, still holding mtx_ for its
    // whole body - waits at most cfg_.backend_op_deadline for this rule's arm to
    // resolve, PLUS, if this rule_id had a prior generation on a bounded key, up to
    // another deadline for that generation's disarm, since the two are sequential,
    // not concurrent - a same-key redeploy is therefore up to 2x this deadline, not
    // 1x, and a rule moving onto a key that holds a RETAINED disarm (Gate 4 hp-1) up
    // to 3x: prior-key disarm, target-key disarm, own arm; a non-waiting entry point
    // removes this wait entirely). The deadline is real steady_clock time captured
    // HERE - after attach_core()'s own prior-disarm wait, which runs inside it - never
    // the injected clock_() snapshot attach_core() uses for its own bookkeeping
    // (tests inject fake clocks) and never counted from entry. Every OTHER rule's
    // attach/detach and every evaluate_key proceed freely throughout, since
    // registry_mu_ is not held here at all. The commit itself - keys_/rules_/
    // pending_initial/"armed" audit - runs in on_arm_complete on the executor
    // worker; the wait only collects its recorded outcome (or rethrows its commit
    // exception on this thread). On a deadline or stop the waiter abandons the claim
    // under registry_mu_ (a queued claim is erased, a dispatched one is left for the
    // callback to finish and disarm - #3816's late-success handling, now decided on
    // the runtime's side with the same one-mutex shape). The wakers for a claim
    // commit are fired by the callback, not here.
    const auto deadline = std::chrono::steady_clock::now() + cfg_.backend_op_deadline;
    auto outcome = wait_for_claim(key, arm_claim, deadline);
    claim_rollback.committed = true;
    return outcome;
}

GuardianSparkRuntime::ReceiptStatus
GuardianSparkRuntime::classify_claim_end(ClaimEnd end) noexcept {
    switch (end) {
    case ClaimEnd::None:
        return ReceiptStatus::Pending;
    case ClaimEnd::Committed:
        return ReceiptStatus::Committed;
    case ClaimEnd::Withdrawn:
        return ReceiptStatus::Withdrawn;
    case ClaimEnd::Stopped:
        return ReceiptStatus::Stopped;
    case ClaimEnd::WaiterTimedOutQueued:
        return ReceiptStatus::CongestionExpired;
    case ClaimEnd::WaiterTimedOutDispatched:
        return ReceiptStatus::Wedged;
    case ClaimEnd::BackendRefused:
    case ClaimEnd::WorkerThrew:
    case ClaimEnd::AdmissionRejected:
    case ClaimEnd::CommitThrew:
    case ClaimEnd::DeadSubscription:
        return ReceiptStatus::Failed;
    case ClaimEnd::DisarmDone:
        // Defensive only: an ArmReceipt is constructed solely from attach_rule's own
        // arm_claim (ClaimKind::Arm), so a Disarm claim's own terminal value can
        // never actually reach here - kept as an explicit case (not folded into a
        // default:) so this switch stays exhaustive against ClaimEnd's real set.
        return ReceiptStatus::Failed;
    }
    // unreachable (exhaustive above). No `default:` so a new ClaimEnd enumerator
    // produces a missing-case WARNING here (meson.build's werror=false repo-wide -
    // this is NOT a build failure, correcting an earlier overclaim in this comment).
    return ReceiptStatus::Failed;
}

GuardianSparkRuntime::ReceiptStatus
GuardianSparkRuntime::receipt_status(const ArmReceipt& receipt) const {
    if (!receipt.claim)
        return ReceiptStatus::Failed; // nothing to observe
    std::lock_guard<std::mutex> lk{registry_mu_};
    return classify_claim_end(receipt.claim->end);
}

bool GuardianSparkRuntime::is_terminal(const ArmReceipt& receipt) const {
    return receipt_status(receipt) != ReceiptStatus::Pending;
}

bool GuardianSparkRuntime::generation_committed_locked(const KeyClaim& claim) const noexcept {
    const auto rit = rules_.find(claim.rule_id);
    return rit != rules_.end() && rit->second->generation == claim.generation;
}

bool GuardianSparkRuntime::is_wedge_candidate_locked(const KeyClaim& claim) const noexcept {
    return is_retained_wedge(claim) && claim.rg && claim.rg->active &&
           !generation_committed_locked(claim);
}

void GuardianSparkRuntime::deactivate_wedge_candidates_locked(
    std::optional<std::string_view> rule_id, const KeyClaim* except) noexcept {
    for (const auto& [key, entry] : claims_)
        for (const auto& claim : entry.fifo)
            if (claim.get() != except && is_retained_wedge(*claim) &&
                (!rule_id || claim->rule_id == *rule_id) && is_wedge_candidate_locked(*claim))
                claim->rg->active = false;
}

bool GuardianSparkRuntime::wedge_candidate_exists_locked(
    std::optional<std::string_view> rule_id, const KeyClaim* except) const noexcept {
    for (const auto& [key, entry] : claims_)
        for (const auto& claim : entry.fifo)
            if (claim.get() != except && is_retained_wedge(*claim) &&
                (!rule_id || claim->rule_id == *rule_id) && is_wedge_candidate_locked(*claim))
                return true;
    return false;
}

void GuardianSparkRuntime::log_wedge_withdrawal_postcondition_violation(
    std::optional<std::string_view> rule_id) const noexcept {
    try {
        spdlog::critical(
            "Guardian spark #4508: a wedge candidate survived a withdrawal of rule "
            "'{}' - the sweep was skipped or reordered",
            rule_id ? ::yuzu::log_id_token(*rule_id) : std::string{"<all>"});
    } catch (...) {
    }
}

std::size_t GuardianSparkRuntime::wedge_candidate_count_for_test(const std::string& rule_id) const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    std::size_t count = 0;
    for (const auto& [key, entry] : claims_)
        for (const auto& claim : entry.fifo)
            if (is_retained_wedge(*claim) && claim->rule_id == rule_id &&
                is_wedge_candidate_locked(*claim))
                ++count;
    return count;
}

bool GuardianSparkRuntime::receipt_wedge_candidate_for_test(const ArmReceipt& receipt) const {
    if (!receipt.claim)
        return false;
    std::lock_guard<std::mutex> lk{registry_mu_};
    const auto& claim = receipt.claim;
    const auto eit = claims_.find(claim->key);
    return eit != claims_.end() && !eit->second.fifo.empty() && eit->second.fifo.front() == claim &&
           is_wedge_candidate_locked(*claim);
}

std::optional<bool> GuardianSparkRuntime::rule_active_for_test(const std::string& rule_id) const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    const auto rit = rules_.find(rule_id);
    if (rit == rules_.end())
        return std::nullopt;
    return rit->second->active;
}

bool GuardianSparkRuntime::is_wedge_k_eligible_locked(
    const std::shared_ptr<KeyClaim>& claim) const noexcept {
    if (claim->end != ClaimEnd::WaiterTimedOutDispatched || claim->dispatch != ClaimDispatch::Dispatched)
        return false;
    const auto eit = claims_.find(claim->key);
    return eit != claims_.end() && !eit->second.fifo.empty() && eit->second.fifo.front() == claim;
}

GuardianSparkRuntime::WedgeAwareStatus
GuardianSparkRuntime::receipt_status_wedge_aware(const ArmReceipt& receipt) const {
    if (!receipt.claim)
        return WedgeAwareStatus{}; // Failed, wedge_eligible=false - nothing to observe
    std::lock_guard<std::mutex> lk{registry_mu_};
    const auto& claim = receipt.claim;
    WedgeAwareStatus out;
    out.status = classify_claim_end(claim->end);
    if (out.status == ReceiptStatus::Wedged)
        out.wedge_eligible = is_wedge_k_eligible_locked(claim);
    return out;
}

bool GuardianSparkRuntime::receipt_recovered(const ArmReceipt& receipt) const {
    if (!receipt.claim)
        return false;
    std::lock_guard<std::mutex> lk{registry_mu_};
    return generation_committed_locked(*receipt.claim);
}

bool GuardianSparkRuntime::receipt_wedge_k_eligible(const ArmReceipt& receipt) const {
    if (!receipt.claim)
        return false;
    std::lock_guard<std::mutex> lk{registry_mu_};
    return is_wedge_k_eligible_locked(receipt.claim);
}

GuardianSparkRuntime::RecoveryStatus
GuardianSparkRuntime::receipt_recovery_status(const ArmReceipt& receipt) const {
    if (!receipt.claim)
        return RecoveryStatus::Blocking;
    std::lock_guard<std::mutex> lk{registry_mu_};
    const auto& claim = receipt.claim;
    // Both predicates observe the same instant under this one lock.
    if (generation_committed_locked(*claim))
        return RecoveryStatus::Recovered;
    if (is_wedge_k_eligible_locked(claim))
        return RecoveryStatus::WedgeEligible;
    return RecoveryStatus::Blocking;
}

std::expected<GuardianSparkRuntime::ArmOutcome, GuardianSparkRuntime::ArmError>
GuardianSparkRuntime::attach_rule(NonWaiting, std::string rule_id, SparkSpec spec,
                                  RuleAssertion assertion, bool emit_compliant_edge) {
    const std::string key = spark_key(spec);
    std::shared_ptr<KeyClaim> arm_claim; // written by attach_core() iff it returns Pending

    // Identical #3831 shape to the blocking overload just above - see its own doc
    // comment for the full reasoning (armed before registry_mu_ is even locked,
    // matched on pointer identity, narrower-scope unwind ordering - moving this
    // declaration into attach_core() would deadlock on unwind exactly as it would
    // there). The only difference from here on: this function never calls
    // wait_for_claim(), and on an unresolved claim it must NOT let claim_rollback's
    // fn fire - Accepted means "still wanted", not "abandon on the way out" (Astra
    // opine review Blocker 1/2).
    GuardianRollback claim_rollback;
    claim_rollback.fn = [this, key, &arm_claim] {
        if (!arm_claim)
            return; // never enqueued (or not yet) - nothing to undo
        std::lock_guard<std::mutex> lk{registry_mu_};
        const auto eit = claims_.find(key);
        if (eit == claims_.end())
            return;
        bool present = false;
        for (const auto& c : eit->second.fifo)
            if (c == arm_claim) {
                present = true;
                break;
            }
        if (!present || arm_claim->outcome || arm_claim->commit_exception)
            return;
        abandon_claim_locked(key, arm_claim, stopping_);
        claim_cv_.notify_all();
    };

    AttachCoreResult core = attach_core(key, std::move(rule_id), std::move(spec),
                                       std::move(assertion), emit_compliant_edge, arm_claim);
    switch (core.state) {
    case AttachCoreState::Armed:
        return ArmOutcome{.kind = ArmOutcomeKind::Armed, .generation = core.generation,
                          .receipt = {}};
    case AttachCoreState::Failed:
        // rung 9c PR-5c round 2 (#4221): carry attach_core()'s own
        // prior_state_preserved bit through to the caller - see ArmError's doc
        // comment. GuardianEngine::reconcile_rule_locked() MUST check it before
        // running its own defensive detach_rule() cleanup on this failure.
        return std::unexpected(ArmError{.message = std::move(core.error),
                                        .prior_state_preserved = core.prior_state_preserved});
    case AttachCoreState::Pending:
        break; // fall through: inspect below, without waiting
    case AttachCoreState::Reobserved:
        // up-2 (#4221, rung 9c PR-5c): return the EXISTING head's receipt directly
        // as Accepted - this call created no claim of its own (arm_claim, the
        // local out-param, is still null here), so there is nothing for
        // claim_rollback to undo either way. The caller polls receipt_status() on
        // this receipt exactly as it would for any other Accepted result - but
        // unlike an ordinary unresolved Accepted receipt, this one is already
        // terminal (Wedged) at the moment it's handed back, and STAYS Wedged
        // once *this* claim's own `end` has settled to its final value: every
        // downstream write site only sets a claim's `end` while it is still
        // None, so a Reobserved retry's receipt cannot itself move `end` off
        // Wedged (test-pinned: test_guardian_spark_runtime.cpp's sticky-Wedged-
        // after-late-success case). This is not a blanket claim that `end` can
        // never change after a Reobserved retry reads it -
        // reclassify_dispatching_race_locked() is a deliberate, narrowly-scoped
        // counter-example: for the one interleaving where a Reobserved retry
        // lands inside the Dispatching-window race (after abandon_claim_locked
        // sets the stale WaiterTimedOutDispatched but before
        // dispatch_arm_off_lock's own re-lock corrects it), the SAME shared
        // claim object's `end` is corrected to its real outcome, and both the
        // original waiter and this Reobserved receipt see that corrected value
        // (they share one claim). Don't read "eventually resolves on its own"
        // into this either way - nothing about calling attach_rule again
        // changes an already-settled `end`, short of a genuinely different
        // rule_id/spec reaching this key.
        return ArmOutcome{.kind = ArmOutcomeKind::Accepted, .generation = 0,
                          .receipt = ArmReceipt{core.claim}};
    }

    // Astra opine review, Blocker 1 step 3: "Reacquire registry_mu_ and inspect this
    // claim object, not merely the current entry for its key" - completion can
    // precede this function's own resumption (the detached worker may finish before
    // attach_core()'s off-lock submit() call even returns control here), so a claim
    // reported Pending a moment ago may already be terminal. Mirrors wait_for_claim's
    // own terminal check exactly, minus the cv wait itself - this never blocks.
    std::unique_lock<std::mutex> lk{registry_mu_};
    if (arm_claim->commit_exception) {
        const std::exception_ptr e = arm_claim->commit_exception;
        claim_rollback.committed = true; // terminal result observed
        lk.unlock();
        std::rethrow_exception(e);
    }
    if (arm_claim->outcome) {
        auto outcome = *arm_claim->outcome;
        claim_rollback.committed = true;
        lk.unlock();
        if (outcome)
            return ArmOutcome{.kind = ArmOutcomeKind::Armed, .generation = *outcome,
                              .receipt = {}};
        // This call's own NEW claim (attach_core() already ran
        // detach_rule_locked(rule_id) on rule_id's prior generation to create it)
        // resolved to a failure by the time we re-checked - rule_id has nothing
        // left either way, so prior_state_preserved is false, unchanged from
        // before rung 9c PR-5c round 2 (#4221).
        return std::unexpected(ArmError{.message = std::move(outcome).error(),
                                        .prior_state_preserved = false});
    }
    // Still unresolved: hand off to runtime-owned state, never abandon it. True for
    // every Pending claim reaching here regardless of Queued/Dispatching/Dispatched -
    // only outcome/commit_exception decided the branch above, not dispatch state
    // (Astra opine review Blocker 1: "Queued siblings need this handoff too. They
    // may be accepted without their own executor submission. Setting the flag only
    // when submit() succeeds would still abandon them.").
    claim_rollback.committed = true;
    lk.unlock();
    return ArmOutcome{.kind = ArmOutcomeKind::Accepted, .generation = 0,
                      .receipt = ArmReceipt{arm_claim}};
}

void GuardianSparkRuntime::synthesize_fallback_outcome_locked(KeyClaim& c) {
    // Mirrors publish_arm_verdicts_locked's own fill-in loop (governance
    // consistency: one place decides what an unfilled claim's outcome becomes).
    // NOT noexcept (fixed, this governance run - see this function's own
    // declaration comment in the header for the full story): the std::string
    // allocation below CAN throw, exactly like that loop's own equivalent line -
    // reap_stranded_claims_locked()'s existing try/catch around its call to this
    // now genuinely contains it, degrading a rare allocation failure to "retry next
    // pass" instead of a std::terminate.
    if (c.outcome || c.commit_exception)
        return;
    if (c.kind == ClaimKind::Arm && generation_committed_locked(c)) {
        c.index_held = false;
        c.outcome = c.generation;
        c.end = ClaimEnd::Committed;
    } else {
        release_claim_index_locked(c);
        fault_here_for_test(9); // consistency-auditor Gate 4 finding (this
                                // governance run): the ONE call site of this
                                // function's own allocating line previously had no
                                // fault seam of its own, unlike the fill-in loop it
                                // mirrors (points 6/7) - this closes that gap so the
                                // now-genuinely-contained catch path is directly
                                // testable.
        c.outcome = std::unexpected(std::string{"arm drain failed"});
        c.end = ClaimEnd::CommitThrew;
    }
}

std::size_t GuardianSparkRuntime::reap_stranded_claims_locked(
    std::vector<std::pair<std::string, std::shared_ptr<KeyClaim>>>& refills) {
    const auto now = std::chrono::steady_clock::now();
    std::size_t reaped = 0;
    for (auto it = claims_.begin(); it != claims_.end();) {
        const std::string& key = it->first;
        auto& fifo = it->second.fifo;
        bool key_changed = false;
        while (!fifo.empty()) {
            auto& c = fifo.front();
            if (c->kind != ClaimKind::Arm)
                break; // a Disarm head is redrive_retained_disarms()'s own job
            // up-3's deadline-observation contract: count-only, once, regardless of
            // whether this claim ends up reaped this pass - never release anything.
            if (!c->compensation_finished && !c->compensation_deadline_observed &&
                c->compensation_deadline != std::chrono::steady_clock::time_point{} &&
                now >= c->compensation_deadline) {
                c->compensation_deadline_observed = true;
                compensation_deadline_elapsed_.fetch_add(1, std::memory_order_relaxed);
            }
            // NOTE: deliberately Queued-only, never Dispatched/Dispatching - a
            // Dispatched head can carry an outcome that abandon_claim_locked wrote
            // EARLY (the timeout-while-still-physically-in-flight case: the async
            // arm() call is genuinely still running, its own completion callback
            // has not run yet, and reaping it here would rip the claim out from
            // under that still-pending callback; measured directly (5b's own
            // implementation) as a real regression on "expire_overdue_claims():
            // abandons a non-waiting claim's own overdue arm... the compensating
            // disarm still runs once the late success arrives" - `compensation_
            // finished` defaults true and does not, by itself, distinguish this
            // case from a genuinely stuck Dispatched head, and no cheaper signal
            // was found in this pass to tell them apart safely). A Dispatched-head
            // reap was the kickoff's own literal ask, but neither Astra's nor
            // Fable's review could construct a real reproduction of it either -
            // left as a documented non-fix (see the PLAN doc) rather than risking
            // this exact class of defect again.
            const bool stranded_queued = c->dispatch == ClaimDispatch::Queued && !c->outcome &&
                                         !c->commit_exception &&
                                         (c->withdrawn || c->waiter_abandoned);
            if (!stranded_queued)
                break; // legitimately still in flight, or legitimately awaiting its turn
            if (!c->compensation_finished)
                break; // its own compensating disarm is genuinely still outstanding
            try {
                synthesize_fallback_outcome_locked(*c);
            } catch (...) {
                claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
                break; // leave it for the next pass rather than reap a half-written claim
            }
            if (!release_claim_index_locked(*c))
                break; // release still failing (seam / genuine failure): retry next pass
            fifo.pop_front();
            ++reaped;
            key_changed = true;
        }
        if (fifo.empty()) {
            it = claims_.erase(it);
        } else {
            if (key_changed) {
                if (auto refill = try_dispatch_head_locked(key)) {
                    // Fable review (2026-09-14): try_dispatch_head_locked() already
                    // flipped this head Queued->Dispatching before returning it - if
                    // the collection push below throws (key's std::string copy,
                    // vector growth), nobody will ever drive this claim: it is not
                    // Queued any more (redrive_retained_disarms()/a same-key event
                    // won't touch it) and the NEXT stranded-claims pass skips
                    // non-Queued heads too. Same class of alloc-after-flip wedge this
                    // function exists to fix - contained the same way the rest of
                    // this file handles it (dispatch_arm_off_lock's own refusal path,
                    // above): hand the head back to Queued so the next same-key event
                    // or stranded-claims pass re-drives it, and count the failure.
                    try {
                        refills.emplace_back(key, refill);
                    } catch (...) {
                        claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
                        if (refill->dispatch == ClaimDispatch::Dispatching)
                            refill->dispatch = ClaimDispatch::Queued;
                    }
                }
            }
            ++it;
        }
    }
    return reaped;
}

std::size_t GuardianSparkRuntime::expire_overdue_claims() {
    const auto now = std::chrono::steady_clock::now();
    std::vector<std::pair<std::string, std::shared_ptr<KeyClaim>>> overdue;
    std::vector<std::pair<std::string, std::shared_ptr<KeyClaim>>> refills;
    std::size_t expired_count = 0;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        // Collect first, mutate second: abandon_claim_locked() erases from a key's
        // fifo (and possibly the claims_ entry itself), which must never happen
        // while a range-based for is iterating those same containers. One
        // continuous lock acquisition spans both passes, so no other thread's
        // dispatch/completion can interleave between the scan and the abandon
        // calls below.
        for (auto& [key, entry] : claims_) {
            for (auto& c : entry.fifo) {
                if (c->kind != ClaimKind::Arm)
                    continue; // since Unit 3, a Disarm claim has no caller-side deadline at
                              // all - submit_disarm_off_lock's submit() call has none
                if (c->outcome || c->commit_exception || c->waiter_abandoned)
                    continue; // already terminal or already someone else's abandon
                if (now < c->deadline)
                    continue;
                overdue.emplace_back(key, c);
            }
        }
        for (auto& [key, c] : overdue) {
            if (c->outcome || c->commit_exception || c->waiter_abandoned)
                continue; // a sibling's abandon_claim_locked() call already reached this one
            abandon_claim_locked(key, c, /*stopping=*/false);
            ++expired_count;
        }
        // up-4 (#4221): the terminal-recovery safety net (see this function's own
        // doc comment) - separate from the overdue-live-claim pass above, which
        // deliberately excludes anything already outcome/commit_exception/abandoned.
        reap_stranded_claims_locked(refills);
    }
    if (expired_count || !refills.empty())
        claim_cv_.notify_all();
    for (auto& [key, refill] : refills)
        dispatch_arm_off_lock(key, refill);
    return expired_count;
}

bool GuardianSparkRuntime::is_retained_wedge(const KeyClaim& head) noexcept {
    return head.kind == ClaimKind::Arm &&
           (head.dispatch == ClaimDispatch::Dispatching ||
            head.dispatch == ClaimDispatch::Dispatched) &&
           head.waiter_abandoned && head.end == ClaimEnd::WaiterTimedOutDispatched;
}

GuardianSparkRuntime::AttachCoreResult
GuardianSparkRuntime::attach_core(const std::string& key, std::string rule_id, SparkSpec spec,
                                  RuleAssertion assertion, bool emit_compliant_edge,
                                  std::shared_ptr<KeyClaim>& arm_claim) {
    // #2233 item 3: File/Registry/Service arm off registry_mu_; every other type
    // stays inline (see io_class_for_spark_type's doc).
    const std::optional<IoClass> io_class = io_class_for_spark_type(spec.type);
    std::function<void()> waker;
    std::function<void()> outbox_waker;
    std::uint64_t new_gen = 0;
    std::shared_ptr<KeyClaim> prior_disarm;
    // Snapshot BEFORE taking registry_mu_ (same outside-lock pattern evaluate_key uses
    // for its own now-snapshot): this is PendingState::first_seen, the M1 item (b)
    // elapsed-time demotion clock. A fresh attach always starts un-demoted regardless
    // of how long a PRIOR generation on this rule_id sat pending (detach_rule_locked
    // below drops that generation's PendingState entirely). It comes from the
    // INJECTED clock_() and is never used as the real wait deadline in attach_rule().
    const auto attach_now = clock_();

    // Built once, reused by both the fast (reuse-existing-watcher / inline-type) path
    // and the claim (bounded off-lock arm) path's commit.
    const std::string rule_name = assertion.rule_name;
    const char* guard_type = guard_type_for(assertion.kind);
    auto rg = std::make_shared<RuleGeneration>();
    rg->active = true;
    rg->emit_compliant_edge = emit_compliant_edge;
    rg->assertion = std::move(assertion);
    rg->assertion.rule_id = rule_id; // keep the assertion's own rule_id authoritative

    std::uint64_t gen = 0;
    std::shared_ptr<KeyClaim> to_dispatch;  // set iff this call must dispatch it
    std::shared_ptr<KeyClaim> head_to_drive; // a retained disarm at the head to redrive first

    {
        std::unique_lock<std::mutex> lk{registry_mu_};
        if (stopping_)
            // rung 9c PR-5c round 2 (#4221): before detach_rule_locked(rule_id) ever
            // runs below - rule_id's prior state, if any, is untouched.
            return AttachCoreResult{.state = AttachCoreState::Failed, .generation = 0,
                                    .error = "stopping", .prior_state_preserved = true,
                                    .claim = nullptr};

        // UP-1 fix (#4221, rung 9c PR-5c follow-up governance - confirmed HIGH,
        // newly-reachable by this PR's own Reobserved/immediate-refusal design):
        // if the TARGET key `key`'s FIFO front is a retained wedge belonging to a
        // genuinely DIFFERENT rule_id, refuse right here - BEFORE
        // detach_rule_locked(rule_id) below unconditionally tears down whatever
        // generation `rule_id` itself currently holds (armed, dispatching, or
        // still queued elsewhere). Without this early check, the unconditional
        // detach followed by the immediate refusal further down would leave
        // `rule_id` with ZERO live arms and no automatic recovery path: the
        // sticky-Wedged design means a same-rule retry never un-wedges `key` by
        // itself, and a different-claimant refusal never creates a claim of its
        // own, so nothing is left in `key`'s FIFO to later adopt a late success
        // either. This is a regression from pre-PR-5c behavior, where a retry
        // queued behind a busy key at least had a chance of late-success recovery
        // if the head eventually resolved.
        //
        // Safe to evaluate here, before detach_rule_locked runs: nothing between
        // taking registry_mu_ above and this point mutates claims_, and
        // detach_rule_locked(rule_id) can only ever touch `key`'s own claims_ FIFO
        // via its Case 0 branch, which withdraws only an entry whose OWN rule_id
        // matches the rule being detached - it can never touch or reorder a front
        // claim owned by a DIFFERENT rule_id. So the different-rule_id refusal
        // below fires whenever the FRONT (computed right here, before any detach)
        // belongs to someone else, full stop - independent of whether rule_id's
        // own active generation exists elsewhere in this same FIFO as a queued,
        // non-follower ("Live followers CAN exist behind a wedged head", the up-2
        // comment below); it does not depend on rule_id's own generation being the
        // front, only on someone ELSE's being it.
        //
        // Re-observation precedes ordinary withdrawal: the caller still wants
        // this exact rule/spec, so do not sweep its own candidacy away first.
        // The restore below handles a preceding full-sync sweep and preserves
        // generation ownership if adoption committed before publication failed.
        //
        // Deliberately duplicates part of the original (post-detach) Reobserved
        // branch below rather than removing it: that branch stays as defense-in-
        // depth for any call shape that could reach it with the hoisted check
        // somehow not firing (there is none known today, matching this file's own
        // established pattern of keeping a superseded check as a redundant
        // backstop - see the UP-1 fix's own precedent immediately below).
        if (const auto pre_cit = claims_.find(key);
            io_class && pre_cit != claims_.end() && !pre_cit->second.fifo.empty()) {
            const auto& pre_head = pre_cit->second.fifo.front();
            if (is_retained_wedge(*pre_head) && pre_head->rule_id != rule_id) {
                wedged_refusals_.fetch_add(1, std::memory_order_relaxed);
                // detach_rule_locked(rule_id) has NOT run yet - rule_id's prior
                // state, if any, is untouched (rung 9c PR-5c round 2, #4221).
                return AttachCoreResult{.state = AttachCoreState::Failed, .generation = 0,
                                        .error = std::string{kSparkKeyWedged},
                                        .prior_state_preserved = true, .claim = nullptr};
            }
            if (is_retained_wedge(*pre_head) && pre_head->rule_id == rule_id &&
                pre_head->spec == spec) {
                wedged_reobservations_.fetch_add(1, std::memory_order_relaxed);
                // #4508: re-observation proves this exact rule/spec is desired,
                // including after a full-sync withdrawal. Preserve W1 by sweeping
                // other candidates first, even if this claim is already active.
                // W0 excludes an adopted-but-unpublished claim: its rg aliases
                // the committed generation, whose active bit belongs to rules_.
                // attach_core's stopping gate precedes this branch.
                if (pre_head->rg && !generation_committed_locked(*pre_head)) {
                    deactivate_wedge_candidates_locked(rule_id, pre_head.get());
                    pre_head->rg->active = true;
                }
                return AttachCoreResult{.state = AttachCoreState::Reobserved, .generation = 0,
                                        .error = {}, .claim = pre_head};
            }
        }

        // PR #3821 review (fjarvis, cpp-safety re-review): armed BEFORE
        // prior_disarm is even populated below, not after - fn is a std::function
        // ASSIGNMENT (a separate throwing operation from this guard's own
        // construction; a 3-capture closure exceeds libstdc++'s SBO and heap-
        // allocates), so a guard armed only once prior_disarm already held a real
        // value would itself have a bad_alloc-sized gap where the mutation was
        // real but the guard protecting it did not exist yet. Safe to install
        // this early: fn checks `if (prior_disarm)` at fire-time and correctly
        // no-ops on every exit before the assignment below actually runs.
        // Protects every return/throw between here and this locked block's normal
        // end uniformly: lk.unlock() before the off-lock submission, matching this
        // function's own established discipline. Committed only once that normal
        // end is reached. (rung 9c R5.2: the disarm claim is already queued at the
        // head of the key entry by detach_rule_locked, so a same-key rearm that
        // arrives during this unlock queues BEHIND it by construction.)
        GuardianRollback prior_disarm_rollback;
        prior_disarm_rollback.fn = [this, &prior_disarm, &lk] {
            if (prior_disarm) {
                lk.unlock();
                submit_disarm_off_lock(prior_disarm);
            }
        };

        // Fresh generation: drop any prior mapping for this rule first. This
        // rebuilds eval state from scratch on every push, identical re-push
        // included - there is no diff-skip that preserves it (matches the legacy
        // path's own tear-down-and-rebuild-every-push behavior). If a prior
        // generation existed, this already enqueued its "disarmed" lifecycle entry
        // (and, #2233 item 3, may return a disarm claim driven off-lock either
        // way: prior_disarm_rollback above fires it on an early return/throw,
        // committed=true suppresses it and the explicit call after this locked
        // block fires it instead on the normal path - exit-path-exclusive, never
        // both) - the "armed" entry below covers the new one, so ONE outbox-waker
        // firing at the end of this call covers both. A prior generation whose own
        // arm is still claimed is withdrawn in place (Case 0, generalised).
        prior_disarm = detach_rule_locked(rule_id);

        gen = ++gen_counter_;
        rg->generation = gen;

        // Gate 4 unhappy-path re-review (PR #3821 scoped governance): armed BEFORE
        // index_->add() runs, same reasoning and same fix shape as
        // prior_disarm_rollback above - a guard whose .fn is assigned only AFTER
        // the mutation it protects has a bad_alloc-sized gap during that
        // assignment itself. index_added starts false and is set true immediately
        // after index_->add() returns (a bool assignment, cannot throw), so fn
        // correctly no-ops if the assignment below never runs. Covers index_->add's
        // effect uniformly for every branch below - each branch's OWN rollback
        // (still correctly armed-before-mutation within its own branch) now
        // protects only ITS OWN additional state, not this shared one, so nothing
        // double-removes it. On the claim branches the claim's own index_held flag
        // takes over once the claim is queued (committed below), so the two never
        // both remove the mapping.
        bool index_added = false;
        GuardianRollback index_add_rollback;
        index_add_rollback.fn = [this, rule_id, gen, &index_added] {
            if (index_added)
                // rung 9c PR-5a (#4221 up-101): pass `gen` - this rollback only ever
                // fires within THIS same attach_core() call, before anything else could
                // have transferred ownership elsewhere, so `gen` is always still the
                // recorded owner here; passing it keeps this call symmetric with every
                // other erase_rule() call site now that the parameter is required for
                // safety elsewhere.
                index_->erase_rule(rule_id, gen); // noexcept (adversarial r4 K2/C5): remove_rule's
                                                  // key copy could throw inside ~GuardianRollback,
                                                  // which swallows it and leaves a ghost mapping
        };

        // rung 9c R5.2: a key that already has a claim entry (an arm in flight with
        // or without siblings, a disarm in flight, or a disarm RETAINED after an
        // admission refusal) is checked FIRST - before the 0->1 edge decides
        // anything - so this call queues behind it instead of double-arming or
        // failing fast. The old fail-fast "busy" rejection lived here (#2233 item 3);
        // it was unreachable via GuardianEngine's mtx_-serialised production callers
        // and is replaced, not removed: a second same-key call is now a QUEUED claim
        // that commits against the same subscription when the head's arm lands.
        const auto cit = claims_.find(key);
        const bool key_claimed = io_class && cit != claims_.end() && !cit->second.fifo.empty();

        // up-2 (#4221, rung 9c PR-5c): when the key is already claimed, its FIFO
        // front is always the claim that matters (try_dispatch_head_locked only
        // ever dispatches the front; abandon_claim_locked retains a
        // dispatching/dispatched claim in place rather than removing it - a
        // genuinely unresolved dispatched arm can never have a live claim queued
        // ahead of it). Live followers CAN exist behind a wedged head - irrelevant
        // here, only the front matters. Checked BEFORE index_->add() below and
        // BEFORE any index mutation: re-observation must construct nothing new and
        // touch no index state at all (see the PLAN doc's "Correction to the
        // kickoff" - a fresh index_->add() here would create a ghost mapping
        // nothing ever cleans up, since the abandoned head's own completion
        // already unconditionally releases its index ownership independent of
        // this call).
        if (key_claimed) {
            const auto& head = cit->second.fifo.front();
            // Compare the underlying ClaimEnd/ClaimDispatch fields directly, never
            // the public receipt_status() accessor - it acquires registry_mu_
            // itself, and this locked block already holds it.
            const bool retained_wedge = is_retained_wedge(*head);
            // Do NOT require index_held == false to recognize this state -
            // abandonment releases the index unconditionally in the ordinary case,
            // but the existing fault seam can make that release fail and leave
            // index_held true; that seam must never corrupt this classification.
            if (retained_wedge) {
                if (head->rule_id == rule_id && head->spec == spec) {
                    // Re-observe: return the EXISTING claim's receipt, construct
                    // nothing new. Must not reset outcome, abandonment, dispatch
                    // state, or deadline - re-observation never revives or
                    // restarts anything, it only reports what is already true.
                    wedged_reobservations_.fetch_add(1, std::memory_order_relaxed);
                    return AttachCoreResult{.state = AttachCoreState::Reobserved,
                                            .generation = 0, .error = {}, .claim = head};
                }
                // A genuinely different claimant (different rule_id - the "same
                // rule_id, different spec" case is structurally unreachable:
                // spark_key() canonically encodes the full spec into the key
                // itself, so two different specs on the same rule_id can never
                // reach this branch with the SAME key in the first place).
                //
                // UP-1 fix (#4221): the hoisted pre-check above already refuses
                // (and returns) every call that would land here - it runs the
                // identical condition (now is_retained_wedge(), rung 9c PR-5c
                // round 2 governance fold) on the identical FIFO front BEFORE
                // detach_rule_locked, and detach_rule_locked can never touch a
                // front owned by a rule_id other than the one it was called
                // with. This branch is kept, unchanged, as defense-in-depth
                // rather than removed: it still fires correctly (redundantly)
                // if it were ever reached, and removing it would make the
                // Reobserved branch above stand alone in a way that is easy to
                // accidentally break on a future edit. Unlike the hoisted
                // pre-check, detach_rule_locked(rule_id) already ran earlier in
                // THIS call by the time we reach here - rule_id has nothing left
                // to preserve, so prior_state_preserved is (explicitly) false: a
                // caller's defensive cleanup on this Failed result is a genuine
                // no-op, not a live-arm teardown (rung 9c PR-5c round 2, #4221).
                wedged_refusals_.fetch_add(1, std::memory_order_relaxed);
                return AttachCoreResult{.state = AttachCoreState::Failed, .generation = 0,
                                        .error = std::string{kSparkKeyWedged},
                                        .prior_state_preserved = false, .claim = nullptr};
            }
        }

        const bool arm_edge = index_->add(key, rule_id, gen); // may throw; index_added still false
                                                              // then. rung 9c PR-5a (#4221 up-101):
                                                              // `gen` is this attach's own incarnation
                                                              // token - see erase_rule()'s doc comment.
        index_added = true;
        if (key_claimed || (arm_edge && io_class)) {
            // Claim path: mark and return to the caller below WITHOUT touching
            // keys_/rules_/pending_initial/lifecycle - all deferred to the completion
            // callback's commit, so a same-key racer never sees a half-built PerKey.
            auto c = std::make_shared<KeyClaim>(); // may throw -> index_add_rollback
            c->kind = ClaimKind::Arm;
            c->key = key;
            c->io_class = *io_class;
            c->rule_id = rule_id;
            c->generation = gen;
            c->spec = spec;
            c->rg = std::move(rg);
            c->rule_name = rule_name;
            c->guard_type = guard_type;
            c->attach_now = attach_now;
            // rung 9c PR-2 Unit 2: the real monotonic deadline expire_overdue_claims()
            // consults - std::chrono::steady_clock::now(), NOT the injected clock_()
            // attach_now uses above, matching the blocking wrapper's own
            // wait_for_claim() deadline (computed at the same point, just after this
            // function returns).
            c->deadline = std::chrono::steady_clock::now() + cfg_.backend_op_deadline;
            auto& entry = claims_[key];               // may throw -> index_add_rollback
            entry.fifo.push_back(c);                  // may throw -> index_add_rollback
            c->index_held = true;                     // noexcept; ownership handed over
            arm_claim = c;                            // noexcept; arms claim_rollback (#3831)
            if (key_claimed) {
                backend_op_queued_.fetch_add(1, std::memory_order_relaxed);
                // A retained (Queued, refused-before) disarm at the head is re-driven
                // by THIS call after it unlocks; a Dispatching/Dispatched head needs
                // nothing from us.
                if (entry.fifo.front() != c && entry.fifo.front()->kind == ClaimKind::Disarm &&
                    entry.fifo.front()->dispatch == ClaimDispatch::Queued)
                    head_to_drive = entry.fifo.front();
                // Adversarial re-review r3 C2: a Queued ARM head that is not this call's
                // own claim is one a contained failure handed back (a refill whose
                // admission-failure cleanup threw, a drain whose publish threw) or a
                // withdrawn tombstone still holding its index mapping. Nothing else
                // drives it, so THIS call does, exactly as it would its own head: the
                // drain then adopts the arm for the live claims behind it and sweeps
                // the tombstone (retrying its index release).
                else if (entry.fifo.front() != c && entry.fifo.front()->kind == ClaimKind::Arm &&
                         entry.fifo.front()->dispatch == ClaimDispatch::Queued)
                    to_dispatch = try_dispatch_head_locked(key);
                assert(entry.fifo.front()->kind == ClaimKind::Disarm ||
                       entry.fifo.front()->kind == ClaimKind::Arm);
            } else {
                to_dispatch = try_dispatch_head_locked(key); // it is the head
            }
        } else if (arm_edge) {
            // Inline type (Interval/Startup/Disk): unchanged synchronous arm, still
            // under registry_mu_ - these are never a blocking OS watch.
            std::shared_ptr<PerKey> pk;
            std::uint64_t sub = 0;
            bool armed_here = false;
            GuardianRollback rollback;
            rollback.fn = [this, rule_id, key, &sub, &armed_here, &pk] {
                if (armed_here) {
                    keys_.erase(key);
                    backend_->disarm(sub);
                }
                rules_.erase(rule_id);
                if (pk)
                    pk->pending_initial.erase(rule_id);
            };
            auto armed = backend_->arm(spec); // may THROW -> rollback + index_add_rollback undo it
            if (!armed)
                // rollback + index_add_rollback undo it. detach_rule_locked(rule_id)
                // already ran earlier in this call, and this attempt's own new state
                // is fully rolled back above - rule_id has nothing left either way,
                // so prior_state_preserved stays false (rung 9c PR-5c round 2, #4221).
                return AttachCoreResult{.state = AttachCoreState::Failed, .generation = 0,
                                        .error = armed.error(),
                                        .prior_state_preserved = false, .claim = nullptr};
            sub = *armed;
            armed_here = true;
            pk = std::make_shared<PerKey>();
            pk->spec = spec;
            pk->subscription = sub;
            keys_.emplace(key, pk);

            commit_new_generation_locked(rule_id, gen, guard_type, rule_name, pk, std::move(rg),
                                         attach_now, waker, outbox_waker, CommitPath::InlineArm);
            rollback.committed = true;
        } else {
            // An existing, COMMITTED shared watcher for this key: reaching here with
            // arm_edge==false and no claim entry means keys_ genuinely has it (a key
            // with a claim entry took the branch above, so keys_.at cannot throw here).
            // No backend call, but a throw below (map insert, or a throwing
            // waker/outbox_waker COPY) must still undo the index_->add - mirrors the
            // original unified rollback's armed_here=false shape (never disarms;
            // there is no new watcher to tear down, only this rule's own bookkeeping;
            // index_add_rollback above handles the index_->add undo).
            auto pk = keys_.at(key);
            GuardianRollback rollback;
            rollback.fn = [this, rule_id, pk] {
                rules_.erase(rule_id);
                pk->pending_initial.erase(rule_id);
            };
            commit_new_generation_locked(rule_id, gen, guard_type, rule_name, pk, std::move(rg),
                                         attach_now, waker, outbox_waker,
                                         CommitPath::InlineShared);
            rollback.committed = true;
        }
        new_gen = gen;
        index_add_rollback.committed = true;
        prior_disarm_rollback.committed = true;
    }

    // Off-lock: any watcher a superseded prior generation owed a disarm to. Its claim
    // is already at the head of its key entry, so if this redeploy kept the SAME key
    // our own arm claim is queued behind it by construction (the "disarm completes
    // before its own rearm dispatches" property R5.2 asks for) and driving it here
    // refills straight into our arm; a different key just runs the disarm first, as
    // before, so the two never race their own teardown against their own re-arm.
    if (prior_disarm)
        submit_disarm_off_lock(prior_disarm);
    if (head_to_drive && head_to_drive != prior_disarm)
        submit_disarm_off_lock(head_to_drive); // a retained disarm from an earlier detach on the
                                               // TARGET key. Governance Gate 4 hp-1: a rule moving
                                               // from key A onto key B can owe BOTH (A's prior
                                               // generation, B's retained head); an else-if left
                                               // B's undriven and this call's own arm waited it
                                               // out. Same object on a same-key redeploy -> once.
    if (to_dispatch)
        dispatch_arm_off_lock(key, to_dispatch);

    if (!arm_claim) {
        // Resolved synchronously (inline type, or an existing committed shared
        // watcher was reused) - nothing pending, so fire the wakers here rather than
        // deferring them to a caller that has nothing further to wait for.
        if (waker)
            waker();
        if (outbox_waker)
            outbox_waker();
        return AttachCoreResult{.state = AttachCoreState::Armed, .generation = new_gen,
                                .error = {}, .claim = nullptr};
    }

    // Still pending: `arm_claim` (the caller's own local, written above) is this
    // call's own live claim, already enqueued and (if selected) already dispatched
    // off-lock. The wakers for a claim's eventual commit are fired by
    // on_arm_complete's own callback, not here - unlike the resolved branch above,
    // there is nothing to fire yet. attach_rule() waits on this claim via
    // wait_for_claim(); a future non-waiting entry point would return it as
    // Accepted(claim) instead, without waiting.
    return AttachCoreResult{.state = AttachCoreState::Pending, .generation = 0,
                            .error = {}, .claim = arm_claim};
}

void GuardianSparkRuntime::detach_rule(const std::string& rule_id) {
    std::function<void()> outbox_waker;
    std::shared_ptr<KeyClaim> work;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        work = detach_rule_locked(rule_id);
        outbox_waker = outbox_enqueue_waker_;
    }
    // #2233 item 3: off both locks - the confirmed-state mutation + "disarmed" audit
    // above are already committed regardless of what follows here.
    if (work)
        submit_disarm_off_lock(work);
    if (outbox_waker)
        outbox_waker();
}

void GuardianSparkRuntime::detach_all() {
    std::function<void()> outbox_waker;
    std::vector<std::shared_ptr<KeyClaim>> works;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        // R5.7 application fence (docs/spark-stage2-guardian-consumer-design.md):
        // bumped FIRST, before any of this block's own mutation, so every commit
        // this teardown's own re-arm eventually produces carries an epoch strictly
        // greater than whatever a still-in-flight PRIOR application's callback
        // could log - see the T0d line at the end of this block for the full
        // reasoning (both share registry_mu_, so no commit can interleave between
        // this increment and that line). #4508: a trivial, non-throwing counter
        // bump that touches no wedge-candidacy state, so it's harmless ahead of
        // the postcondition guard below - the guard's own contract only requires
        // it precede the sweep and any wedge-relevant withdrawal work.
        ++detach_epoch_;
        WedgeWithdrawalPostcondition postcondition{*this, std::nullopt};
        deactivate_wedge_candidates_locked(std::nullopt, nullptr);
        // Withdraw pending arms as well as committed rules. Both loops use the
        // pre-swept helper: neither can create a candidate under this lock.
        std::vector<std::string> claimed;
        {
            std::size_t claim_count = 0;
            for (const auto& [k, entry] : claims_)
                claim_count += entry.fifo.size();
            claimed.reserve(claim_count); // Astra opine review Blocker 4: pre-reserve
                                          // where possible - a throw growing this
                                          // vector must not skip a withdrawal
        }
        for (const auto& [k, entry] : claims_)
            for (const auto& c : entry.fifo)
                if (c->kind == ClaimKind::Arm && !c->withdrawn && !c->waiter_abandoned &&
                    !c->outcome)
                    claimed.push_back(c->rule_id);
        for (const auto& rid : claimed)
            (void)withdraw_rule_after_wedge_sweep_locked(rid, "disarmed");
        std::vector<std::string> rule_ids;
        rule_ids.reserve(rules_.size());
        for (const auto& [rid, rg] : rules_)
            rule_ids.push_back(rid);
        works.reserve(rule_ids.size()); // Astra opine review Blocker 4: "detach_all()
                                        // currently accumulates returned claims in a
                                        // vector after individual mutations... If
                                        // those steps throw, queued work must remain
                                        // discoverable by maintenance." Pre-reserving
                                        // is the cheap half of that; the real safety
                                        // net is that a dropped handle still leaves
                                        // the claim safely queued in claims_ itself -
                                        // see redrive_retained_disarms().
        for (const auto& rid : rule_ids)
            if (auto work = withdraw_rule_after_wedge_sweep_locked(rid, "disarmed"))
                works.push_back(std::move(work));
        outbox_waker = outbox_enqueue_waker_;
        // R5.7 T0d (docs/spark-stage2-guardian-consumer-design.md): the runtime's
        // own teardown-complete marker - the #3990 diagnostic's T0d line. Logged
        // LAST in this locked block so its timestamp means "registry cleared for
        // this application" and every commit this application goes on to produce
        // is guaranteed to log AFTER it. `incarnation_floor` is gen_counter_ NOW:
        // every attach this application makes gets an incarnation strictly above
        // it (ordinary paths) or, for a Reobserved wedge adoption specifically,
        // AT OR BELOW it (the diagnostic's own epoch-fence design treats that as
        // the one legal exception - see the design doc's R5.7 section). Firewalled:
        // an escaping throw here is caught by this function's own caller
        // (GuardianEngine's full_sync teardown catch, which counts a reconcile
        // failure and proceeds to re-arm what it can) - a missing T0d line for an
        // epoch that then produces commits anyway is the diagnostic's own signal
        // to void that repeat, not a correctness problem for the engine itself.
        // FIELD ORDER IS PINNED by the #3990 driver's own regex
        // (docs/spark-rebuild-baselines/fullsync_blackout_diag.py's T0D_RE) -
        // change both together.
        try {
            spdlog::info("Guardian spark: detach_all complete (epoch={}, incarnation_floor={}, "
                         "detached_rules={}, withdrawn_claims={})",
                         detach_epoch_, gen_counter_, rule_ids.size(), claimed.size());
        } catch (...) {
        }
    }
    // rung 9c PR-2 Unit 3: submitted sequentially, off-lock, through
    // submit_disarm_off_lock() - each returns as soon as its disarm is ADMITTED, not
    // once the backend call physically finishes (see on_disarm_complete()). No
    // longer bounded by cfg_.backend_op_deadline per call the way the pre-Unit-3
    // run()-based dispatch was; this loop itself is therefore fast regardless of how
    // long any individual backend disarm takes.
    for (const auto& work : works)
        submit_disarm_off_lock(work);
    if (outbox_waker)
        outbox_waker();
}

std::shared_ptr<GuardianSparkRuntime::KeyClaim>
GuardianSparkRuntime::detach_rule_locked(const std::string& rule_id, std::string_view lifecycle_kind) {
    WedgeWithdrawalPostcondition postcondition{*this, rule_id};
    deactivate_wedge_candidates_locked(rule_id, nullptr);
    return withdraw_rule_after_wedge_sweep_locked(rule_id, lifecycle_kind);
}

std::shared_ptr<GuardianSparkRuntime::KeyClaim>
GuardianSparkRuntime::withdraw_rule_after_wedge_sweep_locked(
    const std::string& rule_id, std::string_view lifecycle_kind) {

    // rung 9c R5.2 (Case 0, generalised from #2233 item 3): rule_id belongs to a key
    // whose arm is still CLAIMED - in flight as the head, or queued behind it - so it
    // has no rules_/keys_ entry to withdraw yet. Mark the claim withdrawn and release
    // its index mapping NOW (matches the immediate-index-cleanup semantics the
    // confirmed path below already has). A queued (never dispatched) claim is erased
    // outright and its waiter woken; a dispatched one stays as the key's marker and
    // its completion skips it (a live sibling adopts the subscription, or it is
    // disarmed). No "disarmed" audit - the rule was never actually armed (same
    // "pending arm withdrawn -> no lifecycle entry" contract the confirmed path's
    // `known` gate already encodes). The search excludes withdrawn AND abandoned
    // claims so a retained stale claim can never match ahead of its live replacement
    // (wedged candidates were swept before entering this helper), and a claim
    // already marked Committed. Publication failure can retain a committed head;
    // confirmed-state withdrawal below remains responsible for its generation.
    if (const auto key_opt = index_->key_for_rule(rule_id); key_opt) {
        if (const auto eit = claims_.find(*key_opt); eit != claims_.end()) {
            auto& fifo = eit->second.fifo;
            for (auto it = fifo.begin(); it != fifo.end(); ++it) {
                auto& c = *it;
                if (c->kind != ClaimKind::Arm || c->rule_id != rule_id || c->withdrawn ||
                    c->waiter_abandoned || c->outcome || !c->index_held ||
                    c->end == ClaimEnd::Committed)
                    continue; // a committed claim is a rules_ entry now, never "pending"
                c->withdrawn = true;
                const bool released = release_claim_index_locked(*c); // noexcept
                // The waiter returns "withdrawn" NOW in either state - the rule is no
                // longer wanted, so there is nothing for its caller to wait for. A
                // dispatched claim keeps its place as the key's marker and the drain
                // skips it by the `withdrawn` flag (a live sibling adopts the result, or
                // it is disarmed); a queued one is erased outright - UNLESS its index
                // release failed (r3 C2/C3 containment; only the test seam can make
                // erase_rule fail): then it stays as a withdrawn tombstone so the next
                // drain on this key sweeps it and retries the release, exactly as the
                // pre-containment code left it in the fifo by throwing before the erase.
                c->outcome = std::unexpected(std::string{"withdrawn"});
                c->end = ClaimEnd::Withdrawn;
                if (c->dispatch == ClaimDispatch::Queued && released) {
                    fifo.erase(it);
                    if (fifo.empty())
                        claims_.erase(eit);
                }
                claim_cv_.notify_all(); // under the lock: a _locked helper cannot defer it
                return nullptr; // nothing to disarm yet; the claim's completion handles it
            }
        }
    }

    const auto rit = rules_.find(rule_id);
    const bool known = (rit != rules_.end());
    const std::uint64_t gen = known ? rit->second->generation : 0;
    // Capture the lifecycle metadata before rules_.erase below drops the generation.
    const std::string rule_name = known ? rit->second->assertion.rule_name : std::string{};
    const char* guard_type = known ? guard_type_for(rit->second->assertion.kind) : "";
    const auto key_opt = index_->key_for_rule(rule_id); // capture BEFORE removal
    // #2233 item 3 / rung 9c R5.2: the confirmed-state mutation below (index_/rules_/
    // keys_) and the "disarmed" audit at the end are the durable commit; the actual
    // backend_->disarm() call is the CALLER's job, off-lock, by driving the DISARM
    // CLAIM queued here (submit_disarm_off_lock). Queued in THIS critical section, the
    // same one that erases keys_[key]: a same-key attach that lands in the off-lock
    // gap sees the claim and queues its arm behind it, rather than seeing "no keys_
    // entry, no claim" and dispatching an arm ahead of the teardown. Changes WHERE
    // the call runs, not whether its success is confirmed - disarm() is void and was
    // never awaited for success even in the old inline call.
    //
    // Adversarial re-review r2 C1 (#3831's arm-before-mutation discipline, applied
    // here): EVERY fallible step of building and queueing that claim - the
    // make_shared, the key string copy, the claims_ node, the deque push - runs
    // BEFORE index_->remove_rule / rules_.erase / keys_.erase, while keys_[key] still
    // owns the subscription. A bad_alloc in any of them therefore leaves the
    // confirmed state exactly as it was (the claim, if already pushed, is popped
    // again below). Previously the claim was built AFTER the erases, so a throw there
    // stranded a live subscription in keys_ with no rule, no index entry and no
    // claim - and the next same-key attach then hit the keys_.emplace hard error.
    // The ->0 edge is PREDICTED from the refcount (same lock, nothing can change it
    // between here and remove_rule) instead of learned from remove_rule's return.
    // Adversarial re-review r3 C4: the lifecycle kind is copied HERE, before the durable
    // mutation, not at the enqueue call after it - that copy allocates, and a throw
    // there used to unwind past the claim hand-off with rules_/index_/keys_ already
    // erased (the queued disarm never driven, the audit record lost).
    detach_post_fault_here_for_test(1); // seam: "the lifecycle-kind copy threw" (pre-mutation)
    const std::string kind_str{lifecycle_kind};
    std::shared_ptr<KeyClaim> work;
    bool claim_pushed = false;
    std::optional<std::uint64_t> inline_disarm; // inline type: disarmed synchronously below
    const bool last_on_key = key_opt && index_->refcount(*key_opt) == 1;
    if (last_on_key) {
        if (const auto kit = keys_.find(*key_opt); kit != keys_.end()) {
            if (const auto ioc = io_class_for_spark_type(kit->second->spec.type)) {
                detach_fault_here_for_test(); // seam: "the claim allocation threw"
                auto c = std::make_shared<KeyClaim>();
                c->kind = ClaimKind::Disarm;
                c->key = *key_opt;
                c->io_class = *ioc;
                c->subscription = kit->second->subscription;
                const auto [eit, inserted] = claims_.try_emplace(*key_opt);
                // A disarm is only ever created on a key with no LIVE claim (an arm
                // never writes keys_ until it commits, and commit erases the entry);
                // a never-dispatched terminal tombstone may still sit here after a
                // double fault, and is swept first (governance pass-3 sg-3/ar-4/cs-5).
                //
                // rung 9c PR-5a (#4221 cs-103) reachability note (corrected 2026-09-14,
                // governance S2 - the original (a) below was wrong for a same-rule_id
                // tombstone; see the correction inline): this sweep's ATTACH-path twin
                // (try_dispatch_head_locked, this file's other
                // sweep_terminal_queued_locked call site) has concrete, tested repros
                // (the "adversarial re-review r3 C2" death test and PR-5a's own
                // "up-101/ch-101" test both leave a real tombstone for this call to
                // sweep). This DETACH-path call site does not, and an extensive trace
                // of the actual call graph (attach_core, publish_arm_verdicts_locked,
                // on_arm_complete, Case 0 in this function) did not turn up a
                // producible sequence of public-API calls that reaches here with a
                // non-empty fifo. Two cases, scoped by whose rule_id the tombstone
                // holds - conflating them was the (a) defect:
                // (a) a DIFFERENT rule sharing this key still holds its OWN
                //     index_->add() mapping (its release having failed): by_key_ is a
                //     std::set<rule_id>, so a SECOND, distinct rule_id inflates
                //     index_->refcount() for this key past 1 and blocks `last_on_key`
                //     above from ever gating entry into this branch while that
                //     tombstone persists. This case does NOT apply to a same-rule_id
                //     tombstone from an older generation: by_key_ counts the rule_id
                //     string once regardless of which generation currently owns it in
                //     by_rule_, so refcount stays 1 either way.
                // (b) the SAME rule's own stale tombstone gets opportunistically swept
                //     by try_dispatch_head_locked's OWN call as part of that rule's
                //     next attach - see PR-5a's up-101 test, where the tombstone is
                //     cleared before the new claim ever reaches commit, not left for a
                //     later, separate detach to find. This is the case that actually
                //     covers a same-rule_id tombstone; (a) never needs to.
                // The overall unreachability conclusion rests on (b) alone for the
                // same-rule case and on (a) for the different-rule case - independently
                // traced by two reviewers with no counter-example found, but not
                // exhaustively modeled against every background retry path. This
                // matches the governance finding's own framing (sg-3/ar-4/cs-5 hardened
                // BOTH sweep call sites symmetrically as defence-in-depth) rather than a
                // distinctly reproduced defect at this specific site. Flagging rather
                // than asserting impossibility: a future change to up-5's
                // retained-disarm redrive (5b) or to the claim/index bookkeeping above
                // could open a path this analysis didn't model - re-check this note
                // rather than deleting it if either changes. Because this conclusion is
                // call-graph reasoning, not a compile-time guarantee, the check right
                // below is a REAL runtime guard (counted via
                // detach_sweep_left_residue(), logged, safe fallback) rather than a bare
                // debug-only assert - see its own comment for why.
                sweep_terminal_queued_locked(eit->second);
                // rung 9c PR-5a (#4221 cs-103): a bare assert() here would compile out
                // entirely under NDEBUG, silently proceeding as if the sweep's
                // precondition held even though this investigation only established it
                // via call-graph reasoning, not a compile-time guarantee. Matches this
                // file's own established precedent for a should-never-happen branch
                // (dispatch_arm_off_lock's "not an Arm claim" guard): keep the debug
                // assert for immediate local visibility, but pair it with a REAL,
                // NDEBUG-surviving fallback that never risks inserting this Disarm claim
                // behind (or ahead of) something whose state this code no longer
                // understands.
                //
                // Gate 8 re-review correction (G2, both cpp-expert and cpp-safety):
                // this comment and this commit's own message originally claimed the
                // disarm itself is "deferred to the next same-key event" - that is
                // WRONG. Deliberately not pushing the new Disarm claim here just leaves
                // `claim_pushed` false and `inline_disarm` unset, so control falls
                // through to the PRE-EXISTING (unrelated to this PR) `!claim_pushed`
                // last-resort fallback in the `if (disarm_key)` block later in this
                // function: that fallback runs SYNCHRONOUSLY, in this SAME call, under
                // this SAME lock -
                // it calls backend_->disarm() on the real subscription directly and then
                // unconditionally erases keys_[key]. So the real disarm and the key's
                // teardown both happen immediately, not deferred. The ONLY thing
                // genuinely left for the next same-key event is the unexpected residue
                // still sitting in claims_[key]'s own fifo (this rule's own
                // rules_/index_ cleanup below also runs unconditionally regardless).
                assert(eit->second.fifo.empty());
                if (!eit->second.fifo.empty()) {
                    detach_sweep_left_residue_.fetch_add(1, std::memory_order_relaxed);
                    try {
                        spdlog::error("Guardian spark: key '{}' still has {} queued claim(s) "
                                     "after the last-on-key sweep for rule '{}' - the real "
                                     "disarm still runs synchronously via the existing "
                                     "last-resort fallback, but this leftover fifo residue "
                                     "is left for the next same-key event to sweep (see "
                                     "detach_sweep_left_residue())",
                                     ::yuzu::log_key_token(*key_opt), eit->second.fifo.size(),
                                     ::yuzu::log_id_token(rule_id));
                    } catch (...) {
                    }
                } else {
                    try {
                        eit->second.fifo.push_back(c);
                    } catch (...) {
                        if (inserted)
                            claims_.erase(eit); // never leave an empty entry behind
                        throw;
                    }
                    work = c;
                    claim_pushed = true;
                }
            } else {
                inline_disarm = kit->second->subscription;
            }
        }
    }
    if (known)
        rit->second->active = false; // in-flight evals will not commit
    std::optional<std::string> disarm_key;
    try {
        // remove_rule is strong-guarantee (its one allocation precedes its mutation);
        // on a throw pop the pre-pushed claim so the key is left exactly as found -
        // subscription still owned by keys_, rule still confirmed.
        disarm_key = index_->remove_rule(rule_id);
    } catch (...) {
        if (claim_pushed) {
            if (const auto eit = claims_.find(work->key); eit != claims_.end()) {
                eit->second.fifo.pop_back();
                if (eit->second.fifo.empty())
                    claims_.erase(eit);
            }
        }
        if (known)
            rit->second->active = true;
        detach_claim_failures_.fetch_add(1, std::memory_order_relaxed);
        throw;
    }
    // From here to the claim hand-off (`return work`) the function ALWAYS reaches the
    // hand-off: rules_.erase, keys_.erase, pending_initial.erase and the shared_ptr copy
    // are noexcept; the two remaining allocating steps are CONTAINED, not absent
    // (adversarial re-review r3 C4, which found the earlier "nothing can throw" claim
    // false): outbox_.drop_rule builds an owning Key string per matching entry
    // (guardian_outbox.hpp) and is wrapped below - a throw there is counted and the
    // teardown continues; enqueue_lifecycle_locked's disarm branch is firewalled
    // inside itself (journal_stage_failures_) and its only caller-side allocation, the
    // kind string, was moved ahead of the mutation above. The inline-type synchronous
    // backend_->disarm is pre-existing and unchanged.
    if (known)
        rules_.erase(rule_id);
    try {
        detach_post_fault_here_for_test(2); // seam: "drop_rule's Key allocation threw"
        std::lock_guard<std::mutex> ob{outbox_mu_};
        outbox_.drop_rule(rule_id); // compliance/health only - Lifecycle lives in lifecycle_log_
    } catch (...) {
        // Compliance/health entries for a withdrawn rule may linger in the outbox until
        // its generation-supersede purge or the drain's own staleness check; the
        // durable state and the queued disarm are unaffected. Counted.
        detach_post_commit_failures_.fetch_add(1, std::memory_order_relaxed);
    }
    assert(disarm_key.has_value() == last_on_key); // the prediction and the edge agree
    if (disarm_key) {
        const auto kit = keys_.find(*disarm_key);
        if (kit != keys_.end()) {
            if (inline_disarm) {
                backend_->disarm(*inline_disarm); // inline type: unchanged, synchronous
            } else if (!claim_pushed) {
                // Gate 8 re-review correction (G3): this used to read "cannot happen by
                // construction" - that stopped being true the moment the residue-sweep
                // branch above (rung 9c PR-5a, #4221 cs-103) was added. That branch
                // deliberately leaves `claim_pushed` false whenever the last-on-key sweep
                // finds leftover fifo residue it can't safely reorder past, so THIS
                // fallback is now the real, live disarm+cleanup path for that case, not
                // just an unreachable last resort. It remains the defensive last resort
                // for any other path that leaves `claim_pushed` false; this is the
                // last-resort real disarm, counted so a subscription is NEVER stranded.
                detach_claim_failures_.fetch_add(1, std::memory_order_relaxed);
                try {
                    backend_->disarm(kit->second->subscription);
                } catch (...) {
                }
            }
            keys_.erase(kit); // the in-flight pass (if any) holds its own shared_ptr; safe
        }
    } else if (key_opt) {
        const auto kit = keys_.find(*key_opt);
        if (kit != keys_.end())
            kit->second->pending_initial.erase(rule_id);
    }
    if (known)
        enqueue_lifecycle_locked(rule_id, gen, kind_str, guard_type, rule_name); // disarm
                                                        // branch: firewalled inside
    return work;
}

void GuardianSparkRuntime::on_subscription_lost(const std::string& key,
                                                 std::uint64_t subscription_id,
                                                 const std::string& detail) {
    // #2818: the underlying watch for `key` was torn down entirely - every rule
    // currently on it lost its enforcement, not just withdrew from it. Report each as
    // "errored" (guardian_outbox.hpp's documented vocabulary) rather than "disarmed" -
    // no immediate self-heal in this PR (Dave's call, 2026-09-06: smaller, safer diff,
    // no new blocking-retry policy).
    //
    // RECOVERY PATH, STATED PRECISELY (governance Gate 4 unhappy-path UP-4 - an
    // earlier version of this comment overclaimed "the next server-issued
    // PushRules"): a subscription dying is LOCAL to this agent and never changes the
    // server's policy generation, so server.cpp's heartbeat reconcile gate
    // (`if (agent_gen >= current) ...`, i.e. it re-pushes only when the SERVER's
    // generation has moved past what the agent last reported) is NOT triggered by
    // this event on its own. The two things that DO recover an errored rule are an
    // UNRELATED rule/policy edit bumping the server generation (whatever its cause),
    // or an agent restart (whose boot re-arm calls reconcile_rule_locked for every
    // persisted rule unconditionally). Absent either, an errored rule can sit
    // un-enforced for the life of the deployment with no proactive operator signal
    // beyond the "errored" audit entry itself - a real, undocumented-until-now
    // residual, tracked as a hardening candidate before the prefer_spark_ flip.
    std::function<void()> outbox_waker;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return;
        const auto kit = keys_.find(key);
        // Staleness guard: a fresh re-arm may have already superseded this
        // notification by the time it's dispatched (async queue hop) - subscription_id
        // pins it to the EXACT dead id the engine told us about, mirroring
        // evaluate_key's own shared_ptr-identity re-check for the ordinary Fired case.
        if (kit == keys_.end() || kit->second->subscription != subscription_id)
            return;
        // enterprise-readiness Gate 6: the mechanism's failure reason (SparkEvent::detail)
        // was being silently dropped entirely - unretrievable by engineering or a customer
        // reading their own journal, since the "errored" audit entry itself has no free-text
        // field for it. Logged here rather than added to the wire payload: extending the
        // Lifecycle wire event's schema is a protocol change, deliberately deferred (folded
        // into this doc's pre-PR-5 list) rather than made under a hardening round's time
        // pressure. This log line is the interim "why", for local debugging only.
        const std::vector<std::string> rule_ids = index_->rules_for(key); // copy: mutates below
        try {
            spdlog::warn("Guardian spark: key '{}' subscription {} lost ({}) - detaching {} "
                         "rule(s) as errored",
                         ::yuzu::log_key_token(key), subscription_id,
                         detail.empty() ? "no reason given" : ::yuzu::log_key_token(detail),
                         rule_ids.size());
        } catch (...) {
        }
        for (const auto& rid : rule_ids)
            (void)detach_rule_locked(rid, "errored");
        // The last detach above queued a Disarm claim for the dead id at the key's
        // head (rung 9c R5.2). The guard above already proves that id dead, so driving
        // it would be a guaranteed no-op backend call that the next same-key attach
        // would have to wait out first (governance pass-3 cs-1). Complete it HERE, in
        // the same critical section, and count it: no undriven claim lingers, the key
        // is clean, and the next attach arms straight away.
        if (const auto eit = claims_.find(key); eit != claims_.end() && !eit->second.fifo.empty()) {
            auto& head = eit->second.fifo.front();
            if (head->kind == ClaimKind::Disarm && head->dispatch == ClaimDispatch::Queued &&
                head->subscription == subscription_id) {
                clear_retained_locked(*head); // up-5: terminal removal - this claim
                                              // may have been retained by an
                                              // earlier admission refusal
                head->outcome = std::uint64_t{0};
                head->end = ClaimEnd::DeadSubscription;
                eit->second.fifo.pop_front();
                if (eit->second.fifo.empty())
                    claims_.erase(eit);
                dead_subscription_disarms_skipped_.fetch_add(1, std::memory_order_relaxed);
            }
        }
        outbox_waker = outbox_enqueue_waker_;
    }
    if (outbox_waker)
        outbox_waker();
}

void GuardianSparkRuntime::on_subscription_faulted(const std::string& key,
                                                    std::uint64_t subscription_id, bool faulted,
                                                    const std::string& detail) {
    // #2818: the watch reported itself unhealthy (or recovered) WITHOUT the key being
    // torn down - Armed still exists at the engine level, so unlike Lost this does NOT
    // touch keys_/rules_/index_. Just surfaces a Health-domain entry per active rule.
    std::vector<OutboxEntry> entries;
    std::function<void()> outbox_waker;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return;
        const auto kit = keys_.find(key);
        if (kit == keys_.end() || kit->second->subscription != subscription_id)
            return; // stale - same guard as on_subscription_lost
        const auto now_wall = std::chrono::system_clock::now().time_since_epoch();
        const std::int64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now_wall).count();
        const std::int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(now_wall).count();
        const std::string agent_id = agent_id_fn_ ? agent_id_fn_() : std::string{};
        for (const auto& rid : index_->rules_for(key)) {
            const auto rit = rules_.find(rid);
            if (rit == rules_.end() || !rit->second->active)
                continue;
            const auto& rg = rit->second;
            entries.push_back(OutboxEntry::health(
                rid, rg->generation, make_event_id(rid, ms, agent_id), ns,
                /*healthy=*/!faulted, faulted ? detail : std::string{},
                guard_type_for(rg->assertion.kind), rg->assertion.rule_name));
        }
        if (!entries.empty()) {
            std::lock_guard<std::mutex> ob{outbox_mu_};
            outbox_.enqueue_all(std::move(entries)); // best-effort, same posture as
                                                      // evaluate_key's own enqueue - a
                                                      // rejected (full) enqueue is dropped
            outbox_waker = outbox_enqueue_waker_;
        }
    }
    if (outbox_waker)
        outbox_waker();
}

void GuardianSparkRuntime::revalidate_subscriptions() {
    // Snapshot under registry_mu_, query health with it released (subscription_health()
    // is cheap/lock-only on a DIFFERENT mutex, but this keeps the same
    // snapshot-then-act discipline the rest of this file uses rather than nesting
    // locks). on_subscription_lost re-validates staleness itself before acting, so a
    // fresh re-arm landing between this snapshot and that call is still handled
    // correctly - no duplicated detach logic here.
    std::vector<std::pair<std::string, std::uint64_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return;
        snapshot.reserve(keys_.size());
        for (const auto& [key, pk] : keys_)
            snapshot.emplace_back(key, pk->subscription);
    }
    for (const auto& [key, subscription_id] : snapshot) {
        if (backend_->subscription_health(subscription_id) == SubscriptionHealth::Dead)
            on_subscription_lost(key, subscription_id, "detected dead by the poll backstop "
                                                        "(revalidate_subscriptions) - no push "
                                                        "notification ever confirmed, or one "
                                                        "was silently dropped");
    }
}

void GuardianSparkRuntime::on_event(const SparkEvent& ev) {
    switch (ev.kind) {
    case SparkEventKind::Fired: {
        // The event is an invalidation HINT; evaluate_key re-reads live state.
        // #4606 criterion-10: T_handler (diagnostic) captured here, at queued-handler entry;
        // T_mechanism read from ev.at (already stamped by SparkEngine::emit_event(), no
        // producer change needed — this is purely consuming an existing value).
        const auto handler_wall = std::chrono::system_clock::now();
        const auto handler_mono = std::chrono::steady_clock::now();
        EvalTrigger trigger;
        trigger.mechanism_wall_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                        ev.at.time_since_epoch()).count();
        trigger.handler_wall_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                       handler_wall.time_since_epoch()).count();
        trigger.handler_mono_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                       handler_mono.time_since_epoch()).count();
        trigger.seq = ev.seq;
        evaluate_key(ev.key, EvalReason::Event, trigger);
        return;
    }
    case SparkEventKind::Lost:
        on_subscription_lost(ev.key, ev.subscription_id, ev.detail);
        return;
    case SparkEventKind::Faulted:
        on_subscription_faulted(ev.key, ev.subscription_id, /*faulted=*/true, ev.detail);
        return;
    case SparkEventKind::Recovered:
        on_subscription_faulted(ev.key, ev.subscription_id, /*faulted=*/false, ev.detail);
        return;
    }
}

void GuardianSparkRuntime::evaluate_key(const std::string& key, EvalReason reason,
                                        std::optional<EvalTrigger> trigger) {
    std::shared_ptr<PerKey> pk;
    SparkSpec spec;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return;
        const auto kit = keys_.find(key);
        if (kit == keys_.end())
            return;
        pk = kit->second;
        spec = pk->spec;
    }

    // Serialise the whole pass (plan + read + fan-out + commit) for THIS key, so
    // read order == commit order and the freshest read commits last (no backward
    // compliance). Per-key, so sibling keys run concurrently. unique_lock (not
    // lock_guard) so #4606 criterion-10's deferred log emission below can explicitly
    // release it before doing any I/O.
    std::unique_lock<std::mutex> eval_lk{pk->eval_mu};

    const bool is_file = spec.type == SparkType::File;
    const bool is_reg = spec.type == SparkType::Registry;
    const bool is_svc = spec.type == SparkType::Service;

    // Snapshot the active generations + derive the read plan BEFORE any I/O (under
    // registry_mu_). We evaluate ONLY these generations: a rule that joins during the
    // read is not in the plan, so its value_name / hash cap was not read - evaluating
    // it against a snapshot that lacks its data would be wrong. It stays dirty in
    // pending_initial and the priority lane re-runs the key for it.
    std::vector<std::shared_ptr<RuleGeneration>> planned;
    FileReadPlan fplan;
    RegistryReadPlan rplan;
    std::string agent_id;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return;
        const auto kit = keys_.find(key);
        if (kit == keys_.end() || kit->second.get() != pk.get())
            return;
        std::set<std::string> reg_values; // distinct value_names (the plan's contract)
        for (const std::string& rid : index_->rules_for(key)) {
            const auto rrit = rules_.find(rid);
            if (rrit == rules_.end() || !rrit->second->active)
                continue;
            const auto& rg = rrit->second;
            planned.push_back(rg);
            if (is_file && rg->assertion.kind == AssertionKind::FileHashEquals)
                fplan.hash_cap = std::max(fplan.hash_cap, rg->assertion.max_bytes);
            if (is_reg)
                reg_values.insert(rg->assertion.value_name);
        }
        rplan.value_names.assign(reg_values.begin(), reg_values.end());
        agent_id = agent_id_fn_ ? agent_id_fn_() : std::string{}; // snapshot here, not post-read
    }
    if (planned.empty())
        return;

    // #4606 criterion-10: T_detect/T_fire staging for this pass, emitted as a
    // best-effort deferred log line after both registry_mu_ and eval_lk release
    // (see the end of this function). Purely diagnostic — read by nothing else here.
    // BEST-EFFORT means it may never change what is enqueued: every allocation this
    // bookkeeping does is inside a try, and a failure drops the timing, not the event.
    std::vector<EvalTimingRecord> staged;
    try {
        if (fail_timing_reserve_for_test_.exchange(false, std::memory_order_relaxed))
            throw std::bad_alloc{}; // test seam: as if the reserve below failed
        staged.reserve(planned.size() * 2); // most rules produce 0-1 entries; recovery+compliance
                                             // pairs produce 2 sharing one detect stamp
    } catch (...) { // diagnostic only; the staging loop below re-guards its own allocations
    }

    // Snapshot the debounce clock BEFORE the blocking read too, so neither the clock
    // nor the agent-id provider is invoked on the detached-post-read path (a provider
    // that borrowed agent state would UAF if shutdown destroyed it during the read).
    const auto now = clock_();

    // The one blocking I/O, OUTSIDE registry_mu_, driven by the plan. Every event is
    // a hint: re-read live state rather than trust a queued payload.
    ReadResult<FileSnapshot> file_read;
    RegistryRead reg_read;
    ReadResult<ServiceRunState> svc_read;
    if (is_file)
        file_read = reader_->read_file(std::get<FileSparkParams>(spec.params), fplan);
    else if (is_reg)
        reg_read = reader_->read_registry(std::get<RegistrySparkParams>(spec.params), rplan);
    else if (is_svc)
        svc_read = reader_->read_service(std::get<ServiceSparkParams>(spec.params));
    else
        return; // non-event-driven type is never armed here

    // Commit section: IO-free, under registry_mu_ so a concurrent detach cannot
    // interleave between the eval and the enqueue (which would re-add a purged
    // entry). Commit ONLY the planned generations, and re-check each is STILL the
    // active current generation for its rule - one withdrawn or re-attached during
    // the read must drop here (its new generation gets its own pass).
    bool enqueued_any = false;
    std::function<void()> outbox_waker;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return;
        const auto kit = keys_.find(key);
        if (kit == keys_.end() || kit->second.get() != pk.get())
            return; // key withdrawn or re-armed under a new PerKey during the read

        for (const std::shared_ptr<RuleGeneration>& rg : planned) {
            const auto rrit = rules_.find(rg->assertion.rule_id);
            if (rrit == rules_.end() || rrit->second.get() != rg.get() || !rg->active)
                continue; // withdrawn or superseded during the read

            // copy-eval-enqueue-commit: eval mutates a COPY; commit only if what we
            // needed to buffer was accepted, else leave the eval pending for retry.
            RuleEvalState scratch = rg->eval;
            const EvalOutcome out =
                eval_rule(spec, rg->assertion, scratch, now, rg->emit_compliant_edge,
                          is_file ? &file_read : nullptr, is_reg ? &reg_read : nullptr,
                          is_svc ? &svc_read : nullptr);
            // #4606 criterion-10: T_detect — the REAL clock, never clock_() (that's the
            // injected eval-window seam for debounce logic, not a latency measurement).
            const auto detect_wall = std::chrono::system_clock::now();
            const auto detect_mono = std::chrono::steady_clock::now();

            // M1 item (a): a committed repeat Unknown (edge already fired earlier in this
            // errored episode) is due a REFRESH once errored_refresh_ms has elapsed since
            // the last emission (edge or refresh) - a lost/coalesced edge must not leave
            // the server's errored view stale forever now that the edge is the sole
            // primary emission. `scratch.last_unhealthy_emit` reflects the LAST COMMITTED
            // emission (untouched by eval_rule); errored_refresh_ms == 0 disables refresh
            // entirely (edge-only, pre-F5 behaviour).
            const bool refresh_due = out.status == EvalStatus::Unhealthy && !out.unhealthy_edge &&
                                     cfg_.errored_refresh_ms > 0 &&
                                     (now - scratch.last_unhealthy_emit) >=
                                         std::chrono::milliseconds(cfg_.errored_refresh_ms);

            // M1 item (b), decided on the READ outcome (this pass observed Unknown),
            // independent of the WIRE-side accept/reject check below (#2992). A
            // rejected enqueue still consumed a read - a rule whose first edge is
            // perpetually rejected at the outbox cap must still eventually leave the
            // 5s priority lane, not retry the identical read forever - and the
            // elapsed-time arm is a clock, not a sweep count, so it is checked on
            // EVERY Unknown pass regardless of reason. Only the sweep COUNTER stays
            // Convergence-only: an Event-reason eval (an OS-level change notification,
            // not a poll) must not fast-demote a rule that is merely noisy.
            if (out.status == EvalStatus::Unhealthy) {
                const auto pit = pk->pending_initial.find(rg->assertion.rule_id);
                if (pit != pk->pending_initial.end() && !pit->second.demoted) {
                    if (reason == EvalReason::Convergence)
                        ++pit->second.unknown_sweeps;
                    const bool sweep_due = cfg_.pending_demote_sweeps > 0 &&
                                          pit->second.unknown_sweeps >= cfg_.pending_demote_sweeps;
                    const bool time_due = cfg_.pending_demote_ms > 0 &&
                                          (now - pit->second.first_seen) >=
                                              std::chrono::milliseconds(cfg_.pending_demote_ms);
                    if (sweep_due || time_due) {
                        pit->second.demoted = true;
                        priority_demoted_.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

            std::vector<OutboxEntry> entries = build_entries(*rg, out, agent_id, refresh_due);
            const bool had_entries = !entries.empty(); // captured BEFORE the move below

            // #4606 criterion-10: stage one EvalTimingRecord per entry (event_id/domain
            // already final, minted by build_entries above) BEFORE entries moves into
            // enqueue_all below.
            const std::size_t staged_begin = staged.size();
            try {
                const int fail_at = fail_timing_stage_at_for_test_.load(std::memory_order_relaxed);
                for (const OutboxEntry& e : entries) {
                    if (fail_at >= 0 && staged.size() == static_cast<std::size_t>(fail_at)) {
                        // One-shot: the erase below restores staged.size(), so a seam left armed
                        // would fire again on the next rule.
                        fail_timing_stage_at_for_test_.store(-1, std::memory_order_relaxed);
                        throw std::bad_alloc{}; // test seam: as if the copy below failed
                    }
                    EvalTimingRecord r;
                    r.event_id = e.event_id; // the only allocating copy: a throw here must not
                                             // prevent the enqueue below
                    r.domain = e.domain;
                    r.detect_wall_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                           detect_wall.time_since_epoch()).count();
                    r.detect_mono_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                           detect_mono.time_since_epoch()).count();
                    r.trigger = trigger; // copied as-is; absent stays absent
                    staged.push_back(std::move(r));
                }
            } catch (...) {
                // Best-effort: drop THIS rule's timing (including any of its entries already staged
                // before the failure), never its event, and keep earlier rules' records. erase() of a
                // tail range does not allocate, so this handler cannot itself throw.
                staged.erase(staged.begin() + static_cast<std::ptrdiff_t>(staged_begin),
                             staged.end());
            }

            bool accepted = true;
            if (had_entries) {
                std::lock_guard<std::mutex> ob{outbox_mu_};
                accepted = outbox_.enqueue_all(std::move(entries)); // both-or-neither
            }

            // #4606 criterion-10: backfill T_fire (or accepted=false) into the records
            // just staged for this rule. MUST run regardless of `accepted` — placed
            // before the `continue` below so a rejected batch's records still get
            // accepted=false written, not silently left at their struct defaults. On a
            // rejection fire_wall_ns/fire_mono_ns are deliberately left at their -1
            // "never fired" sentinel defaults (guardian_spark_timing.hpp), never a
            // fabricated 0. noexcept field writes only; nothing here may throw.
            {
                const auto fire_wall = accepted ? std::chrono::system_clock::now()
                                                 : std::chrono::system_clock::time_point{};
                const auto fire_mono = accepted ? std::chrono::steady_clock::now()
                                                 : std::chrono::steady_clock::time_point{};
                for (std::size_t i = staged_begin; i < staged.size(); ++i) {
                    staged[i].accepted = accepted;
                    if (accepted) {
                        staged[i].fire_wall_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                     fire_wall.time_since_epoch()).count();
                        staged[i].fire_mono_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                     fire_mono.time_since_epoch()).count();
                    }
                }
            }

            if (!accepted)
                continue; // outbox full: RuleEvalState scratch stays uncommitted (nothing
                          // written to rg->eval/last_unhealthy_emit), so eval retries the
                          // identical read next pass. The M1 demotion bookkeeping above
                          // already ran on this same read, unaffected by the rejection (#2992).
            if (had_entries)
                enqueued_any = true;

            // Stamp the emission clock in the SAME scratch that is about to commit, so a
            // rejected enqueue (continue above) leaves it untouched and the refresh is
            // retried, not lost, on the next sweep - the same transactional guarantee
            // copy-eval-enqueue-commit already gives every other field here.
            if (out.status == EvalStatus::Unhealthy && (out.unhealthy_edge || refresh_due))
                scratch.last_unhealthy_emit = now;

            rg->eval = std::move(scratch); // COMMIT
            // M1: every committed repeat Unknown is counted on exactly one of these two
            // channels - REFRESHED (put on the wire) or SUPPRESSED (not) - so the
            // edge/refresh split is observable, never silent (Option-A: every loss/
            // suppression/resource-shedding channel is a counted metric).
            if (out.status == EvalStatus::Unhealthy && !out.unhealthy_edge) {
                if (refresh_due)
                    unhealthy_refreshed_.fetch_add(1, std::memory_order_relaxed);
                else
                    unhealthy_suppressed_.fetch_add(1, std::memory_order_relaxed);
            }
            // A Known verdict (Emit or steady-Silent) satisfies the initial eval; an
            // Unknown does not (it still owes a real verdict). The demotion bookkeeping
            // for the Unknown case already ran above, on the read outcome.
            if (out.status != EvalStatus::Unhealthy) {
                pk->pending_initial.erase(rg->assertion.rule_id);
            }
        }
        if (enqueued_any)
            outbox_waker = outbox_enqueue_waker_; // copy; call after releasing registry_mu_
    }
    // Fire once for the whole pass (not per-rule/per-key concurrently - this
    // local is per-call, no cross-thread sharing) - the drain worker (rung 7.5)
    // drains everything pending regardless of how many entries accumulated.
    if (outbox_waker)
        outbox_waker();

    // #4606 criterion-10: release eval_lk (this key's serialisation) BEFORE any I/O
    // below, so a slow log write does not extend the window in which OTHER threads wait
    // on this key, and the waker above has already fired, so nothing below delays the
    // ENQUEUE or the drain worker's wake. That is the whole extent of the decoupling:
    // the T_detect line is written synchronously on THIS thread (the Spark consumer
    // thread for an Event pass, a convergence lane or the priority thread otherwise) and
    // the T_wire line on a send worker, so a log sink that blocks stalls whichever thread
    // is writing, including the next Event evaluation queued behind it on the consumer
    // thread (see guardian_spark_timing.hpp). The waker also means a T_wire line can
    // reach the log before its own T_detect line - correlate by event_id and the
    // embedded *_wall_ns fields, never file order.
    eval_lk.unlock();
    if (!staged.empty()) {
        try {
            for (const EvalTimingRecord& r : staged)
                spdlog::info("{}", format_eval_timing_line(r));
        } catch (...) { // best-effort diagnostic; never propagate out of evaluate_key
        }
    }
    {
        // Test accessor only. Assigned AFTER the emission so it adds no allocation between the
        // waker and the log line; the move is noexcept and `staged` is not used again.
        std::lock_guard<std::mutex> lt{last_eval_timings_mu_};
        last_eval_timings_ = std::move(staged);
    }
}

EvalOutcome GuardianSparkRuntime::eval_rule(const SparkSpec& /*spec*/, const RuleAssertion& a,
                                            RuleEvalState& state,
                                            std::chrono::steady_clock::time_point now, bool edge,
                                            const ReadResult<FileSnapshot>* file,
                                            const RegistryRead* reg,
                                            const ReadResult<ServiceRunState>* svc) {
    if (file)
        return eval_file(a, *file, state, now, edge);
    if (reg) {
        // Pick THIS rule's value from the per-value_name map (the plan requested it).
        const auto it = reg->values.find(a.value_name);
        if (it == reg->values.end())
            return eval_registry(a, read_unknown<RegistrySnapshot>("value not in read plan"), state,
                                 reg->latency_us, now, edge);
        return eval_registry(a, it->second, state, reg->latency_us, now, edge);
    }
    if (svc)
        return eval_service(a, *svc, state, now, edge);
    return EvalOutcome{}; // Silent (unreachable for an armed event-driven key)
}

std::vector<OutboxEntry> GuardianSparkRuntime::build_entries(const RuleGeneration& gen,
                                                            const EvalOutcome& out,
                                                            const std::string& agent_id,
                                                            bool refresh) {
    // Wall clock for the wire timestamp + id (the steady clock used for debounce has
    // an arbitrary epoch and is not a valid observation time; system_clock::now
    // captures nothing, so it is detach-safe). registry_mu_ is held. agent_id was
    // snapshotted at pass start.
    const auto wall = std::chrono::system_clock::now().time_since_epoch();
    const std::int64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(wall).count();
    const std::int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(wall).count();
    const std::string& rid = gen.assertion.rule_id;
    // Health entries carry guard_type/rule_name explicitly (the compliance path carries
    // both inside out.drift). Derived from the assertion, not a spec (#2237 item 4).
    const char* gtype = guard_type_for(gen.assertion.kind);
    const std::string& rname = gen.assertion.rule_name;
    std::vector<OutboxEntry> v;
    if (out.recovered) // Unknown -> Known: clear the health stream's errored state first
        v.push_back(OutboxEntry::health(rid, gen.generation, make_event_id(rid, ms, agent_id), ns,
                                        /*healthy=*/true, {}, gtype, rname));
    if (out.status == EvalStatus::Emit)
        v.push_back(OutboxEntry::compliance(rid, gen.generation, make_event_id(rid, ms, agent_id),
                                            ns, out.drift));
    else if (out.status == EvalStatus::Unhealthy && (out.unhealthy_edge || refresh))
        // EDGE + REFRESH (M1): the first Unknown of an errored episode mints one
        // guard.unhealthy; the caller (evaluate_key) additionally sets `refresh` at
        // errored_refresh_ms cadence so a lost/coalesced edge cannot leave the server's
        // errored view stale forever - the edge is the primary emission, refresh is the
        // backstop. A repeat Unknown that is NEITHER produces NO entry here (the caller
        // counts it via unhealthy_suppressed_ instead of unhealthy_refreshed_).
        // out.health_detail is this eval's CURRENT read-error string (eval_rule refreshes
        // it on every Unknown, not just the edge), so a refresh - unlike a merely-
        // suppressed tick - re-surfaces a changed reason (EACCES -> ENODEV) on the wire at
        // errored_refresh_ms cadence, retiring the prior edge-only staleness trade.
        v.push_back(OutboxEntry::health(rid, gen.generation, make_event_id(rid, ms, agent_id), ns,
                                        /*healthy=*/false, out.health_detail, gtype, rname));
    // Silent, a suppressed repeat-Unknown, + !recovered -> empty (nothing to publish).
    return v;
}

std::string GuardianSparkRuntime::make_event_id(const std::string& rule_id, std::int64_t wall_ms,
                                                const std::string& agent_id) {
    // registry_mu_ is held by the caller; event_seq_ is guarded by it. boot_nonce_
    // makes the id restart-unique (wall_ms + seq alone are not); agent_id was
    // snapshotted at pass start (not called on the detached-post-read path).
    return agent_id + "-" + boot_nonce_ + "-" + rule_id + "-" + std::to_string(wall_ms) + "-" +
           std::to_string(++event_seq_);
}

bool GuardianSparkRuntime::enqueue_lifecycle_locked(const std::string& rule_id,
                                                    std::uint64_t generation,
                                                    const std::string& kind,
                                                    const std::string& guard_type,
                                                    const std::string& rule_name) {
    // Called under registry_mu_ from attach_rule's inline paths, detach_rule_locked
    // AND - since rung 9c R5.2 (commit-in-callback) - from on_arm_complete on a
    // detached GuardianIoExecutor worker. Calling agent_id_fn_() directly (not
    // pre-snapshotted) is safe ONLY because set_agent_id_provider requires a
    // provider callable from any thread that never takes GuardianEngine::mtx_ (the
    // production provider is a value-capturing lambda); an earlier version of this
    // comment claimed "never on the detached path" (governance pass-3 sg-2/ar-6).
    const auto wall = std::chrono::system_clock::now().time_since_epoch(); // noexcept arithmetic
    const std::int64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(wall).count();
    const std::int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(wall).count();

    if (kind == "armed") {
        // ARM: every throwing op here PROPAGATES, so attach_rule's GuardianRollback undoes the
        // arm and nothing is staged (no phantom). The event_id is minted ONCE and shared by the
        // window entry + the durable record (rev-4.1 #4). The window enqueue is the LAST throwing
        // op before the caller's noexcept commit; the journal push after it is noexcept.
        const std::string agent_id = agent_id_fn_ ? agent_id_fn_() : std::string{};
        const std::string event_id = make_event_id(rule_id, ms, agent_id);
        auto entry =
            OutboxEntry::lifecycle(rule_id, generation, event_id, ns, kind, guard_type, rule_name);
        std::shared_ptr<JournalRecord> record =
            build_journal_record(rule_id, generation, event_id, ns, kind, guard_type, rule_name);
        std::lock_guard<std::mutex> ob{outbox_mu_};
        const bool accepted = lifecycle_log_.enqueue(std::move(entry)); // throwing, rolls back arm
        // #2233 item 7: a capacity-rejected lifecycle entry previously counted
        // (lifecycle_backpressure_drops(), fleet-visible via the journal heartbeat) but
        // was never itself logged - "loudly observable" per this log's own doc comment
        // meant an aggregate a human had to go check, not a line an operator would see
        // at the moment it happened. Log-once-then-count-only (n==1), mirroring
        // drain_log_unlocked's identical shape for send-side losses just below - the
        // counter, not a latch, still tracks every occurrence.
        // Firewalled: this whole line is documented (a few lines above) as the LAST
        // throwing op before the caller's noexcept commit, but spdlog::warn's own fmt
        // formatting can allocate and throw. A throw here still rolls back cleanly
        // (stage_pending_locked hasn't run yet, so attach_rule's rollback/
        // index_add_rollback undo the arm with no phantom staged record) - firewalled
        // anyway so a logging-only failure can never surprise a future reader of the
        // "last throwing op" comment above.
        if (!accepted && lifecycle_log_.backpressure_drops() == 1) {
            lifecycle_backpressure_log_fires_.fetch_add(1, std::memory_order_relaxed);
            try {
                spdlog::warn("Guardian spark: lifecycle audit log at capacity - '{}' entry for "
                            "rule '{}' dropped (further occurrences counted, not logged)",
                            kind, ::yuzu::log_id_token(rule_id));
            } catch (...) {
            }
        }
        stage_pending_locked(std::move(record));                        // noexcept
        return accepted;
    }

    // DISARM: the teardown already happened, so NO throw may propagate (it would break the
    // caller mid-teardown). Firewall the WHOLE construction: agent_id, the event_id mint, the
    // OutboxEntry, and the record all allocate, and a bad_alloc in ANY of them post-teardown is
    // the reachable journal_stage_failures loss channel (rev-4.1 #5 / review B3). Then stage the
    // durable record FIRST so a best-effort window-enqueue throw cannot lose a real disarm.
    OutboxEntry entry;
    std::shared_ptr<JournalRecord> record;
    try {
        const std::string agent_id = agent_id_fn_ ? agent_id_fn_() : std::string{};
        const std::string event_id = make_event_id(rule_id, ms, agent_id);
        entry =
            OutboxEntry::lifecycle(rule_id, generation, event_id, ns, kind, guard_type, rule_name);
        record = build_journal_record(rule_id, generation, event_id, ns, kind, guard_type, rule_name);
    } catch (...) {
        journal_stage_failures_.fetch_add(1, std::memory_order_relaxed);
        return false; // nothing built, nothing to stage or enqueue
    }
    std::lock_guard<std::mutex> ob{outbox_mu_};
    stage_pending_locked(std::move(record)); // durable disarm staged first (noexcept)
    try {
        const bool accepted = lifecycle_log_.enqueue(std::move(entry)); // best-effort live window
        // #2233 item 7 (see the ARM-side twin above for the full rationale). Distinct
        // from THIS try's own catch just below: that one covers enqueue() itself
        // throwing (not a capacity rejection, which enqueue() reports via its return
        // value) - a genuinely different failure, so it must not double-log here. The
        // separate construction try/catch above (agent_id/event_id/OutboxEntry/record
        // build) already returned early on its own throw and never reaches this line.
        if (!accepted && lifecycle_log_.backpressure_drops() == 1) {
            lifecycle_backpressure_log_fires_.fetch_add(1, std::memory_order_relaxed);
            // Firewalled (see ARM-side twin): a throw here must not fall into this
            // try's own catch, which returns false and would misreport `accepted`
            // (already true) as an enqueue rejection.
            try {
                spdlog::warn("Guardian spark: lifecycle audit log at capacity - '{}' entry for "
                            "rule '{}' dropped (further occurrences counted, not logged)",
                            kind, ::yuzu::log_id_token(rule_id));
            } catch (...) {
            }
        }
        return accepted;
    } catch (...) {
        return false; // window enqueue failed post-teardown; the durable record already stands
    }
}

std::shared_ptr<JournalRecord> GuardianSparkRuntime::build_journal_record(
    const std::string& rule_id, std::uint64_t generation, const std::string& event_id,
    std::int64_t enqueued_ns, const std::string& kind, const std::string& guard_type,
    const std::string& rule_name) {
    auto jr = std::make_shared<JournalRecord>(
        JournalRecord{.rule_id = rule_id, .generation = generation, .event_id = event_id,
                      .enqueued_ns = enqueued_ns, .kind = kind, .guard_type = guard_type,
                      .rule_name = rule_name});
    switch (validate_record(*jr)) {
    case JournalReject::None:
        return jr;
    case JournalReject::SkewedClock:
        journal_clock_rejected_.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    default: // EmbeddedNul / Oversized / InvalidUtf8 - a field the journal cannot carry byte-exact
        journal_field_rejected_.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
}

void GuardianSparkRuntime::stage_pending_locked(std::shared_ptr<JournalRecord> record) noexcept {
    // #2303 K6. The noexcept below is only real because the ctor's reserve() means push_back
    // never reallocates. That is an invariant of a DIFFERENT function, so assert it here where
    // it is relied on - if a future edit drops or shrinks the reserve, a debug build trips
    // immediately instead of a release build calling std::terminate on an OOM realloc.
    assert(pending_journal_.capacity() >= kMaxPendingJournalRecords &&
           "pending_journal_ reserve is what makes stage_pending_locked's noexcept real");
    if (!record)
        return; // rejected at build - sent live, never journaled
    if (pending_journal_.size() >= kMaxPendingJournalRecords) {
        pending_journal_.erase(pending_journal_.begin()); // drop oldest; O(n) only under sustained failure
        journal_stage_dropped_.fetch_add(1, std::memory_order_relaxed);
    }
    // Reserve is fixed at construction, so this never reallocates and shared_ptr move is
    // noexcept - the push cannot throw (the enclosing noexcept documents + enforces it).
    pending_journal_.push_back(std::move(record));
}

GuardianSparkRuntime::PendingSnapshot GuardianSparkRuntime::snapshot_pending() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    // The drop counter is read HERE, under the same lock as the snapshot. Reading it from the
    // caller just before this call left a gap in which a drop could land: it would then be
    // attributed to "after the snapshot", the erase would come up short, and a durably-written
    // record would stay staged to be persisted again under a second key. That is the safe
    // direction (a duplicate, which the server de-dupes) rather than loss - but it is the same
    // read-outside-the-lock mistake this whole mechanism exists to fix (#2345 focused review).
    return PendingSnapshot{{pending_journal_.begin(), pending_journal_.end()},
                          journal_stage_dropped_.load(std::memory_order_relaxed)};
}

void GuardianSparkRuntime::erase_persisted_prefix(std::size_t n, std::uint64_t drops_at_snapshot) {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    // The prefix must be identified by IDENTITY, not by position (#2345 Gate 8b). The caller
    // snapshots under this lock, RELEASES it to do KvStore I/O, then comes back to erase what
    // it wrote. In that window stage_pending_locked can hit kMaxPendingJournalRecords and
    // drop from the FRONT - so slot 0 is no longer the record slot 0 was when the snapshot was
    // taken, and erasing n positions deletes n records of which the last few were never
    // written. That is silent, uncounted destruction of audit records, and it is worst exactly
    // when it matters most: staging only fills when persist is failing or the link is dead.
    //
    // Front-drops remove a PREFIX of the same ordered sequence, so the count of drops since the
    // snapshot is all that is needed to realign: those records are already gone, and they were
    // the oldest - i.e. the front of what was just persisted.
    const std::uint64_t dropped_since =
        journal_stage_dropped_.load(std::memory_order_relaxed) - drops_at_snapshot;
    if (dropped_since >= n)
        return; // every record we persisted has already been dropped from staging
    n -= static_cast<std::size_t>(dropped_since);
    n = std::min(n, pending_journal_.size());
    pending_journal_.erase(pending_journal_.begin(),
                           pending_journal_.begin() + static_cast<std::ptrdiff_t>(n));
}

std::size_t GuardianSparkRuntime::pending_journal_depth() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return pending_journal_.size();
}

GuardianSparkRuntime::PageOutcome
GuardianSparkRuntime::try_page_batch(std::vector<OutboxEntry> entries) {
    PageOutcome out;
    if (entries.empty())
        return out;
    std::lock_guard<std::mutex> ob{outbox_mu_};
    // Build the window membership set ONCE (O(window)) rather than re-scanning the window per
    // record (O(records x window)); the latter runs on the heartbeat/run-loop thread and can
    // starve heartbeats under a large backlog (review UP-12 / perf P-2).
    // Scoped: `present` holds string_views borrowed from the window's own entries. They are
    // valid here (the log's nodes are stable and nothing is erased under this lock), but the
    // enqueue loop below moves entries, so keeping a borrowed view alive across it is one edit
    // away from a use-after-free for no benefit (#2345 Gate 8 cpp-safety).
    std::unordered_set<std::string> want;
    {
    const auto present = lifecycle_log_.event_id_set();

    // Required headroom is the count of NET-NEW event_ids, not the raw batch size (#2345
    // Gate 5 CH-7). Charging the raw size is not merely pessimistic, it can wedge replay:
    // a 256-entry batch with 255 entries already in the window needs ONE slot, but reporting
    // 256 makes the worker's refill re-arm wait for 256 free slots - room the window may
    // never have while those same 255 entries are what is occupying it. The batch then never
    // pages and its one unsent record is eventually pruned: a permanent, silent audit gap
    // produced by the accounting rather than by any real shortage.
    //
    // Deduplicated, so a batch that repeats an event_id (a torn or hand-edited journal row)
    // cannot inflate the requirement past what enqueue would actually consume, nor enqueue
    // the same record twice against a membership set built before the loop.
    want.reserve(entries.size());
    for (const auto& e : entries)
        if (!present.count(e.event_id))
            want.insert(e.event_id);
    }
    if (want.empty())
        return out; // every entry is already windowed: nothing to do, and nothing is blocked

    // Headroom gate (design §5): page the batch only if its net-new records fit whole; else
    // leave it for a later pass once the window drains (never a partial page that splits a
    // batch).
    //
    // Reporting WHY nothing was added has to happen here, under the lock. A caller's own
    // pre-check can be stale by the time it gets here - a concurrent arm can consume the room
    // in between - and if that case is misread as "already a member" the caller never learns a
    // backlog is waiting and replay stalls for a whole cadence interval (#2345 Gate 3).
    if (lifecycle_log_.headroom() < want.size()) {
        out.blocked_for_headroom = true;
        out.required = want.size();
        return out;
    }
    for (auto& e : entries) {
        if (want.erase(e.event_id) == 0) // already windowed, or an intra-batch duplicate
            continue;
        if (lifecycle_log_.enqueue(std::move(e)))
            ++out.added;
    }
    return out;
}

void GuardianSparkRuntime::backfill_batch_provenance(const std::string& batch_key,
                                                     const std::vector<std::string>& event_ids,
                                                     const std::string& last_event_id) {
    if (event_ids.empty())
        return;
    const std::unordered_set<std::string> ids(event_ids.begin(), event_ids.end());
    std::lock_guard<std::mutex> ob{outbox_mu_};
    lifecycle_log_.stamp_provenance(batch_key, ids, last_event_id);
}

namespace {
// Drain one log with outbox_mu_ RELEASED across each send: copy the head under the
// lock, unlock, send (the gRPC Write - previously run UNDER outbox_mu_, so a stalled
// write blocked every evaluate_key emit / arm-disarm enqueue / heartbeat behind it -
// item 4), then re-lock and pop the head ONLY if it is still the entry we sent. A
// coalesce/drop during the unlocked window replaces or removes it; pop_front_if(event_id)
// then no-ops and the current head is handled on the next pass.
struct DrainPassLimits {
    std::size_t budget{0};                            ///< decremented per successful send
    std::chrono::steady_clock::time_point deadline{}; ///< zero-valued when unbounded
    bool has_deadline{false};
    const std::function<bool()>* should_stop{nullptr};
    /// Sends allowed to proceed even past `deadline`. The wall slice alone guarantees only
    /// that compliance gets to START, and only if the in-flight lifecycle send returns in
    /// time - so a single send slower than the whole pass budget left compliance's restored
    /// deadline permanently in the past and it shipped NOTHING, every pass, forever
    /// (#2345 Gate 4 UP-3). This converts that into a hard floor. It does NOT bypass
    /// should_stop: shutdown still wins immediately.
    std::size_t guaranteed_attempts{0};
};

template <typename Log>
std::size_t drain_log_unlocked(Log& log, std::mutex& mu,
                               const std::function<SendResult(const OutboxEntry&)>& send,
                               std::atomic<std::uint64_t>& send_exceptions,
                               DrainPassLimits& lim, bool& truncated) {
    std::size_t sent = 0;
    while (true) {
        OutboxEntry entry;
        {
            std::lock_guard<std::mutex> ob{mu};
            std::optional<OutboxEntry> front = log.front_copy();
            if (!front)
                return sent; // drained - NOT truncated, whatever the budget says
            entry = std::move(*front);
        }
        // Limits are evaluated only once an entry is known to exist, and always BEFORE the
        // send: the point is to avoid STARTING work, since an in-flight send cannot be
        // interrupted and the caller may be holding a lock across a thread join
        // (#2298 Sol review). Checking them earlier would report a drained log as truncated.
        // A guaranteed attempt overrides the DEADLINE only - never the budget, and never the
        // stop predicate.
        const bool guaranteed = lim.guaranteed_attempts > 0;
        if (lim.should_stop && *lim.should_stop && (*lim.should_stop)()) {
            truncated = true;
            return sent;
        }
        if (lim.budget == 0 ||
            (!guaranteed && lim.has_deadline &&
             std::chrono::steady_clock::now() >= lim.deadline)) {
            truncated = true;
            return sent;
        }
        if (guaranteed)
            --lim.guaranteed_attempts;
        SendResult r = SendResult::Retain;
        try {
            r = send(entry); // outbox_mu_ RELEASED here
        } catch (...) {
            // A send throw is treated as stream-down (keep the head, stop), BUT unlike a
            // Retain it can be entry-specific (an un-serializable entry jamming the head
            // forever). Count it + log the first so a permanent jam is visible, not
            // silent (Fable). The head is retained either way.
            const auto n = send_exceptions.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n == 1) {
                try {
                    spdlog::error("Guardian drain: send threw (head retained; may be a "
                                  "permanently-unsendable entry). Further occurrences counted only.");
                } catch (...) {
                }
            }
            return sent;
        }
        if (r != SendResult::Sent)
            return sent; // Retain: keep the head, stop
        {
            std::lock_guard<std::mutex> ob{mu};
            log.pop_front_if(entry.event_id); // remove IFF unchanged during the unlocked send
        }
        ++sent;
        --lim.budget;
    }
}
} // namespace

std::size_t GuardianSparkRuntime::lifecycle_headroom() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return lifecycle_log_.headroom();
}

std::unordered_set<std::string> GuardianSparkRuntime::lifecycle_event_ids() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    const auto present = lifecycle_log_.event_id_set(); // borrowed views, valid under the lock
    // Materialise element-by-element rather than via the iterator-range ctor (#2484).
    // The range ctor routes through libstdc++'s `_Hashtable::_S_forward_key`, which on
    // libstdc++ 13 forwards the source key type instead of converting it — so building an
    // unordered_set<string> from string_view iterators is a hard compile error there
    // (hashtable.h:890, "could not convert ... basic_string_view<char> ... to
    // basic_string<char>"). GCC 14+ accepts it, which is why only the ubuntu-24.04 canary
    // leg — the sole leg on the distro's system GCC 13 — caught it. CLAUDE.md declares
    // GCC 13+ as a supported compiler, so this must build there. Same explicit-emplace
    // idiom the sibling `want` set above already uses.
    std::unordered_set<std::string> out;
    out.reserve(present.size());
    for (const std::string_view sv : present)
        out.emplace(sv);
    return out;
}

std::size_t GuardianSparkRuntime::drain(const std::function<SendResult(const OutboxEntry&)>& send) {
    // Drain lifecycle (audit) BEFORE compliance/health so a rule's "armed" precedes its
    // first drift on the wire in the common case (stream up, both drain fully). This is
    // BEST-EFFORT ordering, NOT a hard gate: an earlier version gated compliance on the
    // lifecycle log being empty, but that let a lifecycle head that could not send (a
    // persistent send throw) block ALL compliance/health for the agent indefinitely - a
    // detection blackout, far worse than the narrow ordering blip it prevented (Gate 4
    // UP-3). Both logs now drain every pass; failure isolation beats strict ordering.
    // Residual (documented NICE): a reconnect flap between the two phases, or a concurrent
    // arm during the compliance phase, can still send a drift a pass ahead of its "armed".
    // THIS residual is sequential/next-pass in shape (phase N+1 relative to phase N) - a
    // DIFFERENT, same-pass residual exists too, see drain_bounded()'s own note below;
    // #3972 tracks the watertight fix (merge-drain by global sequence) for both.
    DrainLimits unbounded;
    return drain_bounded(send, unbounded).sent;
}

GuardianSparkRuntime::DrainOutcome
GuardianSparkRuntime::drain_bounded(const std::function<SendResult(const OutboxEntry&)>& send,
                                    const DrainLimits& limits) {
    // Production caller: GuardianOutboxDrainWorker::drain_bounded() (#3847/#3961), which
    // routes `send` through TWO INDEPENDENTLY SCHEDULED GuardianOutboxSendExecutor
    // instances (one per lane), each on its own bounded per-attempt wait and its own
    // detached worker thread. This makes a SAME-PASS cross-lane wire reordering reachable
    // that the prior single shared executor structurally prevented: a compliance/health
    // event can land on the wire between two lifecycle entries within this one call, if
    // the lifecycle lane's send is still detached past its own bounded wait while the
    // compliance/health lane's completes. Distinct from drain()'s own disclosed residual
    // above, which is sequential/next-pass, not same-pass - #3972 tracks the fix for both.
    std::lock_guard<std::mutex> dg{drain_mu_};
    DrainOutcome out;

    const bool unbounded = limits.max_entries == 0;
    const std::size_t total =
        unbounded ? std::numeric_limits<std::size_t>::max() : limits.max_entries;

    // Reserve a share for compliance/health BEFORE lifecycle runs. Draining lifecycle first
    // out of one shared budget means a busy lifecycle log can consume the entire pass and
    // compliance never runs at all - which is the detection blackout the comment above says
    // was removed for exactly that reason (Gate 4 UP-3), reintroduced in bounded form.
    // Unused lifecycle allowance rolls over below, so this costs nothing when lifecycle is
    // quiet, and the overall cap is still `total`.
    // Normalise the reserve ratio ONCE, defensively: den == 0 (disabled), num > den
    // (nonsensical), and the wall-only case where max_entries == 0 all have to land somewhere
    // explicit rather than dividing by zero or over-reserving (Sol review).
    // A ratio denominator beyond this is nonsense and only invites overflow in the wall
    // arithmetic below; treat it as "no reserve" rather than trusting the cast.
    constexpr std::size_t kMaxReserveRatio = 1'000'000;
    const std::size_t reserve_den =
        (limits.compliance_reserve_den > kMaxReserveRatio) ? 0 : limits.compliance_reserve_den;
    const std::size_t reserve_num =
        (reserve_den == 0) ? 0 : std::min(limits.compliance_reserve_num, reserve_den);

    std::size_t reserve = 0;
    if (!unbounded && reserve_den > 0) {
        reserve = total / reserve_den * reserve_num;
        if (reserve > total)
            reserve = total;
        // Integer division floors to 0 whenever total < den, which silently removes the
        // reserve and reopens the starvation this exists to prevent - with no diagnostic
        // (#2298 Gate 4 UP-8). Guarantee at least one slot whenever there is more than one
        // to give; at total == 1 there is nothing to split and lifecycle keeps first claim.
        if (reserve == 0 && total > 1 && reserve_num > 0)
            reserve = 1;
    }

    DrainPassLimits lim;
    lim.budget = total - reserve;
    lim.should_stop = limits.should_stop ? &limits.should_stop : nullptr;

    // Slice the WALL the same way the count is sliced. A single shared deadline made the
    // count reserve dead on arrival under time pressure: drain_log_unlocked checks the
    // deadline BEFORE the budget, so once lifecycle consumed the wall, compliance returned on
    // entry without ever spending a reserved slot - the Gate-4 UP-3 detection blackout reached
    // through the other limit (#2345 important-1).
    //
    // GUARANTEE, stated precisely: compliance gets an opportunity to START, provided the
    // in-flight lifecycle send returns before the full-pass deadline. It is NOT "compliance
    // gets time" - a lifecycle send begun just inside its slice can return after the full
    // deadline, and no bound here can interrupt it. You cannot have both a hard pass deadline
    // and a guaranteed compliance attempt while sends are uninterruptible (Sol review).
    const auto pass_start = std::chrono::steady_clock::now();
    if (limits.max_wall.count() > 0) {
        lim.has_deadline = true;
        // CLAMP BEFORE THE CAST. The count path clamps (min(num,den), reserve <= total) and an
        // unclamped wall path recreated the very asymmetry this round exists to remove: with a
        // pathological denominator the size_t->int64_t cast could yield a lifecycle slice
        // LONGER than the whole pass, leaving compliance's restored deadline already in the
        // past - zero compliance sends, i.e. the UP-3 detection blackout reached through a
        // sign flip. Unreachable from the sole production caller (1/2), which is exactly why
        // it needed a bound rather than an argument (#2345 Gate 2 sec-MEDIUM-1).
        std::chrono::milliseconds lifecycle_wall = limits.max_wall;
        // Gated on the WALL, not on max_entries: a {max_entries = 0, max_wall = X} config looks
        // bounded but previously received neither the count reserve (skipped by !unbounded) nor
        // a wall slice, i.e. the UP-3 blackout reachable purely by configuration
        // (#2345 Gate 3 cpp-safety).
        if (reserve_den > 0 && reserve_den <= kMaxReserveRatio) {
            // DIVIDE FIRST. Multiplying max_wall by (den - num) before dividing overflows a
            // signed 64-bit millisecond count for a large max_wall with a large denominator -
            // undefined behaviour, not merely a wrong slice. Unreachable from the sole
            // production caller, but the comment above claims a bound, so it needs to be one
            // (#2345 Gate 8 security). Dividing first costs at most (den - 1) ms of slice.
            lifecycle_wall = std::chrono::milliseconds{
                limits.max_wall.count() / static_cast<std::int64_t>(reserve_den) *
                static_cast<std::int64_t>(reserve_den - reserve_num)};
        }
        // Never longer than the pass itself, whatever the ratio said.
        // FLOOR the slice, mirroring the count reserve's floor. Without it a small max_wall
        // truncates lifecycle_wall to 0, lifecycle gets a deadline equal to pass_start and
        // ships NOTHING - the same starve-a-lane bug this round fixed for compliance, simply
        // pointed the other way (#2345 Gate 4 consistency S5). One millisecond is enough to
        // guarantee an attempt; the count budget still bounds the work.
        if (lifecycle_wall < std::chrono::milliseconds{1})
            lifecycle_wall = std::chrono::milliseconds{1};
        lim.deadline = pass_start + std::min(lifecycle_wall, limits.max_wall);
    }

    bool lifecycle_truncated = false;
    out.sent = drain_log_unlocked(lifecycle_log_, outbox_mu_, send, send_exceptions_, lim,
                                 lifecycle_truncated);
    // Hand the compliance pass its reserve PLUS whatever lifecycle did not use, and restore
    // the FULL pass deadline - lifecycle only ever held a slice of it.
    lim.budget += reserve;
    if (limits.max_wall.count() > 0)
        lim.deadline = pass_start + limits.max_wall;
    // Guarantee compliance at least one attempt even if lifecycle already overran the pass.
    // Without this the "compliance gets to start" property is conditional on the in-flight
    // lifecycle send returning in time, and a persistently slow send makes it never true.
    lim.guaranteed_attempts = (reserve > 0) ? 1 : 0;
    bool compliance_truncated = false;
    out.sent += drain_log_unlocked(outbox_, outbox_mu_, send, send_exceptions_, lim,
                                  compliance_truncated);

    // Give any STILL-unused allowance back to lifecycle. Without this the transfer is
    // one-directional and the reserve becomes a hard cap on lifecycle even when compliance
    // is completely idle - which at a small budget throttles audit delivery for no benefit.
    // Spend or drop the guaranteed attempt HERE. If the compliance log was empty the token is
    // never consumed, and carrying it into the lifecycle retry below lets lifecycle start one
    // send past the whole pass deadline - the deadline this exception exists to relax for
    // COMPLIANCE only (#2345 Gate 8 security). should_stop still bounds shutdown either way.
    lim.guaranteed_attempts = 0;
    bool lifecycle_retry_truncated = false;
    const bool retried = lifecycle_truncated && lim.budget > 0;
    if (retried)
        out.sent += drain_log_unlocked(lifecycle_log_, outbox_mu_, send, send_exceptions_, lim,
                                      lifecycle_retry_truncated);

    out.truncated =
        compliance_truncated || (retried ? lifecycle_retry_truncated : lifecycle_truncated);
    return out;
}

void GuardianSparkRuntime::begin_stop() {
    std::shared_ptr<IStateReader> reader;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        stopping_ = true;
        for (auto& [rid, rg] : rules_)
            rg->active = false;
        // rung 9c R5.2: every QUEUED (never dispatched) claim is dropped here with a
        // counted "stopping" outcome so its waiter wakes now rather than riding out
        // its deadline; a Dispatching/Dispatched head is left in place - its
        // completion callback finishes it (a late success is disarmed, R5.5). A
        // retained disarm dropped here leaks its watcher exactly as the old
        // silent Stopped drop did, now counted.
        for (auto eit = claims_.begin(); eit != claims_.end();) {
            auto& fifo = eit->second.fifo;
            for (auto it = fifo.begin(); it != fifo.end();) {
                auto& c = *it;
                if (c->dispatch == ClaimDispatch::Queued) {
                    // Adversarial re-review r3 C3: begin_stop() runs from the destructor
                    // (implicitly noexcept) and from GuardianEngine::stop() AHEAD of the
                    // executor/scheduler/worker shutdown, so nothing in this walk may
                    // propagate. The index release is noexcept (counted on failure,
                    // ownership kept - moot after stop); the outcome copy is contained,
                    // and a waiter that never sees one still wakes on stopping_
                    // (wait_for_claim's predicate) and returns "stopping".
                    clear_retained_locked(*c); // up-5: terminal removal (erased below)
                    release_claim_index_locked(*c);
                    try {
                        if (!c->outcome)
                            c->outcome = std::unexpected(std::string{"stopping"});
                    } catch (...) {
                    }
                    if (c->end == ClaimEnd::None)
                        c->end = ClaimEnd::Stopped;
                    claims_dropped_at_stop_.fetch_add(1, std::memory_order_relaxed);
                    it = fifo.erase(it);
                } else {
                    ++it;
                }
            }
            if (fifo.empty())
                eit = claims_.erase(eit);
            else
                ++eit;
        }
        reader = reader_; // copy under the lock; call request_stop() outside it
    }
    claim_cv_.notify_all(); // after the lock: wake every claim waiter
    // request_stop() is an extensible virtual - never invoke it under registry_mu_
    // (the runtime already avoids calling copied wakers under its central lock). It
    // is contractually noexcept + nonblocking, so it is safe here even though
    // begin_stop() also runs from ~GuardianSparkRuntime().
    if (reader)
        reader->request_stop();
    // #2233 item 3: wake any attach_rule/detach_rule currently parked in a bounded
    // backend wait immediately, rather than making it ride out cfg_.backend_op_deadline.
    // rung 9c PR-2 Unit 6 removed the only production caller of that blocking wait:
    // GuardianEngine::reconcile_rule_locked() now calls attach_rule(NonWaiting{}, ...)
    // (guardian_engine.cpp), which never calls wait_for_claim(). The blocking
    // attach_rule(rule_id, spec, deadline) overload above still exists and this wake
    // still applies to it, but nothing in production calls it today - only test code
    // does.
    // NOTE this does NOT make GuardianEngine::stop() itself prompt (§R5.5): stop()
    // takes GuardianEngine::mtx_ BEFORE calling begin_stop() (guardian_engine.cpp), and
    // apply_rules() still does real synchronous work under that lock regardless of this
    // change: a full_sync's KV sweep and detach_all() (scales with the rule count being
    // torn down), the per-rule reconcile loop, and an unbounded lifecycle-journal persist
    // on scope exit. It is not the only mtx_ holder that can delay stop() this way - the
    // boot-time start_local()/wire_spark_engine() calls do their own synchronous work
    // under the same lock unconditionally, and journal_maintenance_tick() (every
    // heartbeat) does too, but ONLY when prefer_spark_ is true - it no-ops immediately
    // after taking mtx_ otherwise (guardian_engine.cpp:767), which is production's
    // default today. None of that is a *backend* wait this wake-up reaches - stop()
    // is decoupled from backend-arm latency, not from any mtx_ holder's own
    // duration. This DOES matter for a caller that
    // already holds mtx_ across a DIFFERENT blocking section calling begin_stop()
    // directly, and for the runtime's own destructor path.
    //
    // Contained in try/catch (adversarial review C4/k2): idempotent and DOCUMENTED
    // as nonblocking, but its internal std::lock_guard is, per the standard, permitted
    // to throw std::system_error - not "non-throwing" as an earlier version of this
    // comment claimed. begin_stop() runs from ~GuardianSparkRuntime(), implicitly
    // noexcept; an escaping exception there would std::terminate the agent. Mirrors
    // GuardianStateReader::request_stop()'s identical containment of the same
    // executor's stop() call, just above.
    try {
        io_executor_.stop();
    } catch (...) {
    }
}

std::size_t GuardianSparkRuntime::armed_key_count() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    return keys_.size();
}
std::size_t GuardianSparkRuntime::rule_count() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    return rules_.size();
}
std::size_t GuardianSparkRuntime::outbox_size() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return outbox_.size();
}
std::uint64_t GuardianSparkRuntime::outbox_backpressure_drops() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return outbox_.backpressure_drops();
}
std::uint64_t GuardianSparkRuntime::io_ceiling_rejections() const {
    // GuardianIoExecutor::stats() is self-locking (state_->mu) - no additional lock
    // needed at this level, matching io_executor_stats_for_test()'s own shape.
    std::uint64_t total = 0;
    for (const auto& c : io_executor_.stats().counters)
        total += c.rejected_ceiling;
    return total;
}
std::uint64_t GuardianSparkRuntime::lifecycle_backpressure_drops() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return lifecycle_log_.backpressure_drops();
}
std::optional<GuardianSparkRuntime::RuleStatusSnapshot>
GuardianSparkRuntime::status_for_rule(const std::string& rule_id) const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    const auto it = rules_.find(rule_id);
    if (it == rules_.end())
        return std::nullopt;
    RuleStatusSnapshot snap;
    snap.in_unknown = it->second->eval.in_unknown;
    snap.last_compliant = it->second->eval.emit.last_compliant;
    return snap;
}
std::vector<std::string> GuardianSparkRuntime::pending_initial(const std::string& key) const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    const auto kit = keys_.find(key);
    if (kit == keys_.end())
        return {};
    std::vector<std::string> out;
    out.reserve(kit->second->pending_initial.size());
    for (const auto& [rule_id, state] : kit->second->pending_initial)
        out.push_back(rule_id); // membership means "never Known" - includes demoted rules
    return out;
}

std::vector<std::string>
GuardianSparkRuntime::pending_demoted_for_test(const std::string& key) const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    const auto kit = keys_.find(key);
    if (kit == keys_.end())
        return {};
    std::vector<std::string> out;
    for (const auto& [rule_id, state] : kit->second->pending_initial)
        if (state.demoted)
            out.push_back(rule_id);
    return out;
}

std::vector<EvalTimingRecord> GuardianSparkRuntime::last_eval_timings_for_test() const {
    std::lock_guard<std::mutex> lk{last_eval_timings_mu_};
    return last_eval_timings_;
}

bool GuardianSparkRuntime::stopping() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    return stopping_;
}

std::vector<std::string> GuardianSparkRuntime::keys_for_type(SparkType type) const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    std::vector<std::string> out;
    for (const auto& [key, pk] : keys_)
        if (pk->spec.type == type)
            out.push_back(key);
    return out;
}

std::vector<std::string> GuardianSparkRuntime::keys_with_pending_initial() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    std::vector<std::string> out;
    for (const auto& [key, pk] : keys_) {
        // M1 item (b): a key leaves the priority worklist only once EVERY pending rule
        // on it is demoted - a key with a mixed demoted/non-demoted pending set already
        // pays the per-key read cost for its non-demoted sibling, so excluding it would
        // silently starve that sibling's priority-lane cadence for free.
        const bool has_active_pending =
            std::any_of(pk->pending_initial.begin(), pk->pending_initial.end(),
                       [](const auto& entry) { return !entry.second.demoted; });
        if (has_active_pending)
            out.push_back(key);
    }
    return out;
}

void GuardianSparkRuntime::set_drain_fault_point_for_test(int point) noexcept {
    drain_fault_point_for_test_.store(point);
}

void GuardianSparkRuntime::set_detach_post_fault_point_for_test(int point) noexcept {
    detach_post_fault_point_for_test_.store(point);
}

void GuardianSparkRuntime::set_index_remove_fault_for_test(bool on) noexcept {
    index_remove_fault_for_test_.store(on);
}

void GuardianSparkRuntime::set_detach_fault_for_test(bool on) noexcept {
    detach_fault_for_test_.store(on);
}

void GuardianSparkRuntime::set_drain_gap_hook_for_test(std::function<void()> hook) {
    std::lock_guard<std::mutex> lk{registry_mu_};
    drain_gap_hook_for_test_ = std::move(hook);
}

void GuardianSparkRuntime::set_dispatch_entry_hook_for_test(std::function<void()> hook) {
    std::lock_guard<std::mutex> lk{registry_mu_};
    dispatch_entry_hook_for_test_ = std::move(hook);
}

void GuardianSparkRuntime::set_pending_initial_waker(std::function<void()> waker) {
    std::lock_guard<std::mutex> lk{registry_mu_};
    pending_initial_waker_ = std::move(waker);
}

std::function<void()> GuardianSparkRuntime::pending_initial_waker_for_test() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    return pending_initial_waker_;
}

void GuardianSparkRuntime::set_outbox_enqueue_waker(std::function<void()> waker) {
    std::lock_guard<std::mutex> lk{registry_mu_};
    outbox_enqueue_waker_ = std::move(waker);
}

std::function<void()> GuardianSparkRuntime::outbox_enqueue_waker_for_test() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    return outbox_enqueue_waker_;
}

void GuardianSparkRuntime::set_agent_id_provider(std::function<std::string()> provider) {
    std::lock_guard<std::mutex> lk{registry_mu_};
    agent_id_fn_ = std::move(provider);
}

} // namespace yuzu::agent
