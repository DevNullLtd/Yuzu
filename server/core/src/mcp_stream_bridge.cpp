#include "mcp_stream_bridge.hpp"

#include "background_jobs.hpp"

#include "mcp_jsonrpc.hpp"
#include "mcp_session.hpp"
#include "mcp_stream.hpp"
#include "rest_a4_envelope.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <new>
#include <system_error>
#include <utility>
#include <vector>

namespace yuzu::server::mcp {

namespace {
constexpr const char* kMetricRecordsActive = "yuzu_mcp_bridge_records_active";
constexpr const char* kMetricRejects = "yuzu_mcp_bridge_reject_total";
constexpr const char* kMetricListenerFailures = "yuzu_mcp_bridge_listener_failures_total";
// #2438: H1's suppress-non-strictly-increasing-progress rule fires silently -
// nothing counted a suppression, so a regression that stopped suppressing
// (re-admitting equal/decreasing progress onto the wire) was only catchable by
// unit tests, never production alerting. WIDENED by #2412: also counts a
// progress snapshot the listener overwrote (latest-wins) before the projector
// ever saw it - see the field comment on BridgeRecord::progress_suppressed_delta.
constexpr const char* kMetricProgressSuppressed = "yuzu_mcp_bridge_progress_suppressed_total";
constexpr const char* kMetricProjectorCycles = "yuzu_mcp_bridge_projector_cycles_total";
constexpr const char* kMetricProjectionDegraded = "yuzu_mcp_bridge_projection_degraded_total";
constexpr const char* kMetricStreamingBackstop = "yuzu_mcp_bridge_streaming_backstop_total";
// #2487: a teardown_claimed step that could not complete on the bare maintenance
// thread. `stage` is a CLOSED literal set (unsubscribe | release_charge | erase),
// pre-seeded in server.cpp. Any nonzero value means a record, its streamed charge,
// or its bus subscription outlived its teardown and now waits for shutdown() -
// alert on > 0.
constexpr const char* kMetricTeardownIncomplete = "yuzu_mcp_bridge_teardown_incomplete_total";
// #2513: a retry pass's re-entry into a previously-incomplete teardown, by the
// CLOSED `outcome` set (recovered | exhausted), pre-seeded in server.cpp.
// `teardown_incomplete` fires once per failed step per ATTEMPT (so it moves
// again on a retry that fails again); this family reports the record's final
// disposition once retry either settles it or gives up. Alert on `exhausted`;
// `recovered` is success-shaped movement, same as forced_expire.
constexpr const char* kMetricTeardownRetry = "yuzu_mcp_bridge_teardown_retry_total";
// sre-N1 (#2489): one ring-only PRESSURE forced expiry, by the disposition the
// visitor decided. `disposition` is a CLOSED set derived from TeardownFinal
// (none | synthesize_unavailable | fallback_final), pre-seeded in server.cpp.
// Without it the only forced-expire series was a FAILURE counter, so a fleet
// silently degrading clients to the fallback final and one synthesizing -32014
// looked identical on a dashboard; the split existed only in audit, which is not
// scraped. Success-shaped by design: any movement at all means the cap is being
// enforced, and `synthesize_unavailable` is the one to alert on.
constexpr const char* kMetricForcedExpire = "yuzu_mcp_bridge_forced_expire_total";
// #2489 review: the ring-only pressure pass stopped on its per-invocation victim
// budget with the cap STILL exceeded. The budget exists because a defer now
// advances instead of ending the pass, so without it a sustained park rate could
// keep one maintenance tick expiring records indefinitely. Movement here is
// therefore not an error - it is the hatch saying arrivals are keeping pace with
// expiries, and the remaining victims roll to the next tick.
constexpr const char* kMetricPressureBudgetExhausted =
    "yuzu_mcp_bridge_pressure_budget_exhausted_total";
// #2529: a streamed admission charge that could not be released at its natural
// release point (arm()'s cancel-degrade) and is therefore RETAINED on the record
// until its teardown reclaims it. Distinct from kMetricTeardownIncomplete, which
// is teardown_claimed's own steps on the maintenance thread; this one fires on a
// request thread. Both-or-neither holds either way - the record and the ledger
// still agree - so a nonzero value is a deferred release, never a stranded slot.
constexpr const char* kMetricChargeReleaseDeferred =
    "yuzu_mcp_bridge_charge_release_deferred_total";
// Streamed admissions refused for want of a slot, labelled by WHICH half of the
// admission sum was holding them. Measured at the reject site, using the same
// expression admission evaluates, because the first attempt at this diagnostic was
// a periodic gauge that counted only the charge ledger - and a wedged session is
// precisely the case where the charges are gone and the PINS are held, so it read
// zero exactly when it mattered and non-zero on healthy concurrency (governance
// Gate 8). A signal computed anywhere other than the decision it describes can
// drift from it; this one cannot.
//   held="charges" - calls genuinely in flight; clears as they finish.
//   held="pins"    - finals already committed whose pins were never released. After
//                    the rule-(a) unpin this should be rare; a sustained rate is the
//                    wedge signature.
constexpr const char* kMetricPinSlotsReject = "yuzu_mcp_bridge_pin_slots_reject_total";
// #2740: a new streamed call reclaimed a slot from an already-committed final that
// no wire took delivery of. This is the EXPECTED, healthy response to disconnecting
// clients, so it is deliberately its own counter rather than a label on the ring's
// yuzu_mcp_stream_pin_displaced_total - that family is the corroborate-before-filing
// signal, and folding a routine event into it would destroy that alarm.
constexpr const char* kMetricPinDisplacedForAdmission =
    "yuzu_mcp_bridge_pin_displaced_for_admission_total";
// #2740 / governance: the admission reclaim's release threw and was contained. The
// record is already committed at that point, so letting it escape would leave a slot
// nothing reclaims until the arming reaper. "Should never happen" - it needs a broken
// platform mutex - so any nonzero value is a signal, not a rate.
constexpr const char* kMetricPinReleaseFailed = "yuzu_mcp_bridge_pin_release_failed_total";
// #2740 / #2795: the reclaim's release lost a race - it returned false without
// throwing, so another route had already cleared the slot. Unlike the throw above this
// is REACHABLE by an ordinary client (racing its own GET resume against a streamed
// POST admission), and unlike the throw it moves neither of the other two counters.
// Without this the residual is unobservable, which is what made the "check both
// counters" rule-out unsound.
constexpr const char* kMetricPinReleaseRaced = "yuzu_mcp_bridge_pin_release_raced_total";
// Produced ONLY by the bridge's publish_final -> fallback -> poison ladder
// (below); named in the yuzu_mcp_stream_* family because it describes stream-
// terminal delivery, not because mcp_stream.cpp increments it - poison_terminal()
// increments its OWN family instead (yuzu_mcp_stream_poison_close_failures_total,
// #2531), which counts a close failure, not a publish-ladder failure.
constexpr const char* kMetricTerminalPublishFailures =
    "yuzu_mcp_stream_terminal_publish_failures_total";

/// Parse the two monotone counters out of an execution-progress payload.
/// Throws on malformed JSON - the caller catches per batch (C4).
struct ProgressCounts {
    std::uint64_t responded = 0;
    std::uint64_t targeted = 0;
};
ProgressCounts parse_progress(const std::string& data) {
    const auto j = nlohmann::json::parse(data);
    ProgressCounts c;
    c.responded = j.value("agents_responded", std::uint64_t{0});
    c.targeted = j.value("agents_targeted", std::uint64_t{0});
    return c;
}
}  // namespace

// ── Construction / shutdown ────────────────────────────────────────────────

McpStreamBridge::McpStreamBridge(ExecutionEventBus* bus, McpSessionRegistry* sessions,
                                 yuzu::MetricsRegistry* metrics, AuditFn audit)
    : McpStreamBridge(bus, sessions, metrics, std::move(audit), Config{}) {}

McpStreamBridge::McpStreamBridge(ExecutionEventBus* bus, McpSessionRegistry* sessions,
                                 yuzu::MetricsRegistry* metrics, AuditFn audit, Config cfg)
    : bus_(bus), sessions_(sessions), metrics_(metrics), audit_(std::move(audit)), cfg_(cfg) {
    YUZU_ASSERT_BACKGROUND_JOB("mcp_stream_bridge.run_projector"); // WS-10 ReplicaSafe (per-replica)
    projector_ = std::thread([this] { run_projector(); });
}

McpStreamBridge::~McpStreamBridge() { shutdown(); }

void McpStreamBridge::shutdown() {
    if (shutdown_called_.exchange(true)) {
        return;  // idempotent - dtor after an explicit stop() is a no-op
    }
    {
        // Gate every public mutator first (C6): anything arriving after this
        // observes the flag while resolving its record under bridge_mu_ and
        // returns shutdown/not-found without waking the (soon dead) projector.
        std::lock_guard<std::mutex> lk(bridge_mu_);
        shutdown_started_ = true;
    }
    {
        // Stop the projector BEFORE touching records, and never while holding
        // bridge_mu_ - the projector snapshots under it (C6 join ordering).
        std::lock_guard<std::mutex> lk(core_->mu);
        core_->stop = true;
    }
    core_->cv.notify_all();
    if (projector_.joinable()) {
        projector_.join();
    }
    // The critical shutdown guarantees are already met above (mutators gated,
    // projector joined) BEFORE any allocation. The teardown below allocates a
    // reaped vector; a bad_alloc there must not propagate through the noexcept
    // ServerImpl::stop() or the destructor (→ std::terminate) and must not leave
    // the idempotence flag consumed with the work half-done in a way a retry
    // could resume - so the whole best-effort cleanup is contained. On OOM at
    // shutdown some subscriptions may linger, but the process is already tearing
    // down and no projector remains to touch them.
    try {
        std::vector<std::shared_ptr<BridgeRecord>> reaped;
        {
            std::lock_guard<std::mutex> lk(bridge_mu_);
            reaped.reserve(records_.size());
            for (auto& [key, rec] : records_) {
                if (rec->subscribed && bus_ != nullptr) {
                    // bridge_mu_ → Channel::mu is a declared edge; unsubscribe waits
                    // out in-flight listeners (they take record mu + WakeCore::mu
                    // only, never bridge_mu_ - no cycle).
                    bus_->unsubscribe(rec->execution_id, rec->sub_id);
                }
                rec->subscribed = false;
                reaped.push_back(rec);
            }
            records_.clear();
            streamed_unpinned_.clear();
        }
        std::size_t poisoned_unresolved = 0;
        for (const auto& rec : reaped) {
            bool should_poison = false;
            {
                // Settle charge bookkeeping for consistency (the ledger map is
                // already gone; the flag must not read as "held" to a late observer).
                std::lock_guard<std::mutex> lk(rec->mu);
                rec->streamed_charge_held = false;
                // A pressure-visitor claim (torn_down set under Channel::mu) can be
                // abandoned mid-teardown: the claim commits inside the bus visitor,
                // WITHOUT bridge_mu_, so shutdown() can start meanwhile - the
                // CALLER (sweep's pressure-relief loop, not teardown_claimed
                // itself) re-checks shutdown_started_ right after and returns
                // before teardown_claimed is ever invoked, so this walk is the
                // only reclaimer left. It still never PUBLISHES against
                // a torn-down record - that would race a possibly-still-running
                // teardown_claimed and break the exactly-once arbitration
                // teardown_claimed's own comment describes - but it CAN poison one
                // whose terminal was never resolved (teardown_terminal_handled
                // false), so a client still connected learns its stream is gone
                // instead of heart-beating past process exit (#2517). A concurrent
                // sweep() mid-teardown_claimed (not joined here, only the projector
                // is) can race this and cause a spurious poison of a record that
                // actually published - harmless: poisoning is idempotent and the
                // client's remediation is the same fetch-by-execution_id either way.
                should_poison = rec->torn_down && !rec->teardown_terminal_handled &&
                                !rec->terminal_projected.load(std::memory_order_acquire) &&
                                !rec->final_written;
            }
            if (should_poison) {
                rec->stream->poison_terminal();  // noexcept (#2531); idempotent
                ++poisoned_unresolved;
            }
            flush_record_obs(*rec);
        }
        if (poisoned_unresolved > 0) {
            // ONE aggregate row, not one per record: a closed campaign of shutdown
            // reaps is not evidence-silent (#2489 comp-S1), but per-record teardown
            // evidence is exactly what the abandoned records never got and cannot
            // get now (publishing against them here would be the arbitration
            // violation the poison-only design above avoids). No metric: the
            // process is exiting and the series would never be scraped - this
            // audit row is the durable evidence.
            audit_contained("mcp.bridge.shutdown_reap", /*execution_id=*/"", /*stage=*/"",
                            "poisoned " + std::to_string(poisoned_unresolved) +
                                " claimed-but-unpublished record(s) at shutdown; every "
                                "result remains fetchable by execution_id");
            try {
                spdlog::info("MCP bridge shutdown: poisoned {} claimed-but-unpublished "
                            "record(s); every result remains fetchable by execution_id",
                            poisoned_unresolved);
            } catch (...) {  // NOLINT(bugprone-empty-catch) - nothing left we could safely do
            }
        }
        flush_core_obs();
        publish_records_gauge(0);
    } catch (...) {  // NOLINT(bugprone-empty-catch) - see the note above
    }
}

// ── Key / lookup ───────────────────────────────────────────────────────────

std::string McpStreamBridge::make_key(const std::string& session_id,
                                      const nlohmann::json& jsonrpc_id) {
    // Session ids are 32 lowercase hex chars (mint), so '\n' cannot collide;
    // dump() keeps string "1" (\"1\") distinct from integer 1 (1).
    return session_id + '\n' + jsonrpc_id.dump();
}

std::shared_ptr<McpStreamBridge::BridgeRecord>
McpStreamBridge::find_locked(const std::string& key) const {
    auto it = records_.find(key);
    return it == records_.end() ? nullptr : it->second;
}

// ── Wake path ──────────────────────────────────────────────────────────────

void McpStreamBridge::mark_dirty(WakeCore& core, const std::string& key) noexcept {
    // #2411: replaces the old bare wake(core). The projector used to rescan
    // EVERY live record on every wake, regardless of which one had new work;
    // it now scans only the keys pushed here.
    //
    // LOST-WAKEUP PROOF (do not weaken this without re-deriving it - it is
    // what a TSan run and an adversarial review are meant to catch). The
    // insert and `work_pending = true` happen in ONE `core.mu` critical
    // section here; the projector clears `work_pending` and swaps `dirty` out
    // empty in ONE `core.mu` section of its own (run_projector). Three cases:
    //   - This insert lands BEFORE the projector's swap: `key` is in the set
    //     the swap takes, so this cycle visits it.
    //   - This insert lands AFTER the swap: `dirty` was empty at the swap, so
    //     insert() returns true here, notify_one() fires, and `work_pending`
    //     is set true in the SAME critical section as the insert - even if
    //     the notify races the projector's re-entry into cv.wait, the
    //     predicate (`stop || work_pending`) is already satisfied by the time
    //     it re-checks.
    //   - insert() returns FALSE: `key` was already in the CURRENT `dirty`
    //     set, so the set was non-empty when this insert ran, so (by the
    //     invariant stated on WakeCore::dirty) `work_pending` was already
    //     true - a cycle that will visit `key` is already owed, and skipping
    //     the redundant notify is correct, not a lost wakeup.
    // This IS "wake only on a real edge" (the issue's phrasing, from when the
    // progress mailbox that #2412 later replaced still existed), expressed at drain
    // granularity (per dirty-set-empty→non-empty transition) rather than per
    // mailbox-empty→non-empty transition - provable here, and equivalent for
    // the projector's purposes, since the projector only ever cares whether a
    // cycle is owed, not how many events landed.
    try {
        bool signal = false;
        {
            // The flag flips under the SAME mutex the projector's wait predicate
            // reads - a notify can never slot between predicate-check and sleep
            // (the lost-wakeup killer). WakeCore::mu is a strict leaf.
            std::lock_guard<std::mutex> lk(core.mu);
            try {
                signal = core.dirty.insert(key).second;
            } catch (...) {
                // Allocation failure growing the set: degrade to a full scan
                // next cycle rather than lose track of which records have
                // pending work - see WakeCore::scan_all.
                core.scan_all.store(true, std::memory_order_relaxed);
                signal = true;
            }
            core.work_pending = true;  // UNCONDITIONAL - see the invariant above
        }
        if (signal) {
            core.cv.notify_one();
        }
    } catch (...) {
        // The outer try wraps the `lock_guard` CONSTRUCTION, not just the
        // block inside it, and the inner try/catch above is exhaustive (it
        // never rethrows) - so the only realistic path here is `core.mu`
        // itself failing to lock. `work_pending` is unreachable in that case
        // (it is only ever set under `mu`), so there is no mu-held section
        // left to record intent in - hence the lock-free write below (see
        // WakeCore::scan_all's comment). A wake must never escape a listener.
        core.scan_all.store(true, std::memory_order_relaxed);
    }
}

// ── Listener (free factory, C7/D5: captures record + wake core ONLY) ──────

ExecutionEventBus::Listener McpStreamBridge::make_listener(std::shared_ptr<BridgeRecord> rec,
                                                           std::shared_ptr<WakeCore> core) {
    return [rec = std::move(rec), core = std::move(core)](const ExecutionEvent& ev) noexcept {
        // Hard constraint 7: strictly copy-only + notify, catch-and-count.
        // Runs under Channel::mu; touches record mu + WakeCore::mu only.
        try {
            if (core->listener_fault.exchange(false, std::memory_order_acq_rel)) {
                throw std::bad_alloc{};  // inject_listener_fault_for_test
            }
            const bool is_terminal = ev.event_type == "execution-completed";
            const bool is_progress = ev.event_type == "execution-progress";
            if (!is_terminal && !is_progress) {
                return;  // agent-transition et al: not projected (documented)
            }
            {
                std::lock_guard<std::mutex> lk(rec->mu);
                if (rec->terminal_accepted) {
                    // D2: the final is last. A committed publisher really can emit
                    // post-terminal progress (refresh_counts after mark_cancelled)
                    // and duplicate terminals - all dropped once a terminal is
                    // secured.
                    return;
                }
                if (is_terminal) {
                    // Construct fully OUTSIDE the slot, then commit with a
                    // noexcept move: a payload-copy throw leaves the slot
                    // untouched and terminal_accepted unset.
                    MailboxEntry tmp{ev.id, ev.data};
                    rec->terminal_slot = std::move(tmp);
                    rec->terminal_accepted = true;  // sticky from here on
                } else {
                    // #2412: latest-wins - assign the newest snapshot into the
                    // spare buffer (may throw on allocation growth; a throw here
                    // leaves progress_slot untouched - strong guarantee, better
                    // than the old ring's drop-oldest under the same fault),
                    // then commit with a noexcept swap (MailboxEntry's nothrow
                    // move, see the static_assert above). The slot and spare
                    // flip-flop between listener and projector, so once each
                    // has grown to its steady-state payload size neither swap
                    // allocates again.
                    rec->listener_spare.data.assign(ev.data);
                    rec->listener_spare.bus_id = ev.id;
                    std::swap(rec->progress_slot, rec->listener_spare);
                    if (rec->progress_pending) {
                        // A prior snapshot was still unprojected - it is the one
                        // just overwritten by the swap above. Counted AFTER the
                        // swap commits, so a throw from `assign` (caught below)
                        // never double-counts a supersede that didn't happen.
                        rec->progress_suppressed_delta.fetch_add(1, std::memory_order_relaxed);
                    }
                    rec->progress_pending = true;
                }
            }
            mark_dirty(*core, rec->key);
        } catch (...) {
            // Counted record-locally; the projector flushes it to the registry.
            // #2411: mark dirty too - without this, a dirty-set drain that
            // never otherwise visits this record (its OWN wake is what just
            // failed) would strand this delta until some other event on the
            // same record eventually marks it.
            rec->listener_failure_delta.fetch_add(1, std::memory_order_relaxed);
            mark_dirty(*core, rec->key);
        }
    };
}

// ── reserve / subscribe / arm / cancel / abandon / park ────────────────────

McpStreamBridge::ReserveResult McpStreamBridge::reserve(const std::string& session_id,
                                                        const std::string& principal,
                                                        const nlohmann::json& jsonrpc_id,
                                                        std::optional<nlohmann::json> progress_token,
                                                        bool streamed_intent) {
    if (bus_ == nullptr) {
        count_reject("disabled");
        return {false, "disabled"};
    }
    {
        // D4: check shutdown BEFORE the registry call (and re-check after) so
        // the isolated-registry-lock rule holds without racing the gate.
        bool shutting_down = false;
        {
            std::lock_guard<std::mutex> lk(bridge_mu_);
            shutting_down = shutdown_started_;
        }
        if (shutting_down) {
            count_reject("shutdown");  // L2: count here too, like the post-registry branch
            return {false, "shutdown"};
        }
    }
    // Registry leaf - never called under bridge_mu_. stream_for touches
    // last_seen, which is correct here: reserve runs on a client request that
    // already slid the TTL at session-validate. Nothing on the PARKED path
    // touches it again (retention honesty).
    auto stream = sessions_ != nullptr ? sessions_->stream_for(session_id, principal) : nullptr;
    if (!stream) {
        count_reject("unknown_session");
        return {false, "unknown_session"};
    }
    if (reserve_fault_.exchange(false, std::memory_order_acq_rel)) {
        throw std::bad_alloc{};  // test seam: model an allocation failure post-admission
    }
    // Allocate outside bridge_mu_ (the mint precedent - construction is cheap
    // to discard on a reject and must not serialize against the map).
    auto rec = std::make_shared<BridgeRecord>();
    rec->session_id = session_id;
    rec->principal = principal;
    rec->jsonrpc_id = jsonrpc_id;
    rec->key = make_key(session_id, jsonrpc_id);
    rec->streamed_intent = streamed_intent;
    rec->created = now();
    rec->stream = std::move(stream);
    rec->progress_token = std::move(progress_token);

    const char* reject = nullptr;
    std::size_t active = 0;
    std::size_t pin_reject_pinned = 0;
    std::size_t pin_reject_unpinned = 0;
    auto pin_slots_held = PinSlotsHeld::kNotApplicable;
    std::optional<DisplacedPin> displaced;
    bool release_failed = false;  // latched under bridge_mu_, emitted after it releases
    bool release_raced = false;  // latched under bridge_mu_, emitted after it releases
    // Reserved for the reclaim audit detail, filled after selection and BEFORE the
    // commit block, so the only allocation that could throw on the reclaim path
    // happens while a throw still costs nothing (see the audit_contained call).
    std::string displaced_detail;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            reject = "shutdown";
        } else if (records_.contains(rec->key)) {
            reject = "duplicate_request_id";
        } else if (records_.size() >= cfg_.global_record_cap) {
            reject = "global_cap";
        } else if (streamed_intent) {
            // A5: live pins + streamed records that have not pinned yet. Orphan
            // pins (pressure/pin-ack teardown) are counted via pinned_count()
            // until the ring releases them; a transient over-count between a pin
            // commit and its ledger decrement rejects fail-closed.
            auto it = streamed_unpinned_.find(session_id);
            const std::size_t unpinned = it == streamed_unpinned_.end() ? 0 : it->second;
            const std::size_t pinned = rec->stream->pinned_count();
            if (pinned + unpinned >= kMaxStreamedPostsPerSession) {
                // #2740: before refusing, NAME a slot held by a final that no wire
                // took delivery of. Four client disconnects before their finals
                // landed would otherwise lock this session out of streamed POST
                // for good - every remaining release route (a GET resume acking
                // past the pinned id, or session death) needs a channel a
                // POST-only client does not have, and the refusal told the client
                // to wait for calls that had already ended.
                //
                // SELECTION ONLY here; the release happens after the admission
                // COMMITS, below. Unpinning at this point would destroy an
                // eviction exemption on any pass that still ends up rejecting, or
                // that throws on the ledger/map commit - and an unpin has no
                // inverse, so there would be nothing for LedgerRollback to undo.
                displaced = select_displaceable_pin_locked(session_id, rec->stream);
                if (displaced.has_value()) {
                    // Built HERE - after selection, before the ledger bump and the
                    // map insert. Selection has mutated nothing yet, so a throw
                    // from this allocation unwinds with the session exactly as it
                    // was. Building it at the emission site instead put a throwing
                    // allocation after the commit AND after the release.
                    displaced_detail =
                        displaced->orphan
                            ? "no record referenced it - its owning record was already torn "
                              "down; the result stays fetchable by execution_id; released ring "
                              "event_id=" + std::to_string(displaced->event_id)
                            : std::string("final undelivered as far as the bridge can see; still "
                                          "fetchable by execution_id and in the ring until "
                                          "ordinary eviction");
                }
            }
            // The reclaimed slot counts as free for THIS decision: it is released
            // below on the same `bridge_mu_` hold, so no concurrent reserve can
            // observe the interim state and over-admit.
            //
            // `pinned` is RE-READ rather than reused from above: `teardown_claimed`
            // publishes (and so can pin) WITHOUT `bridge_mu_`, so a pin can appear
            // between the first count and the selection snapshot. Subtracting from
            // the stale figure would then credit a slot that was never counted and
            // admit one call over the per-session cap. The clamp is belt-and-braces
            // for the same reason the re-read exists - `pinned` is unsigned, and a
            // count that reads 0 here must not wrap to SIZE_MAX and reject for the
            // wrong reason.
            //
            // The re-read alone is NOT sufficient, which is why the release below
            // is what finally decides: a count measures SLOTS, not the identity of
            // the one selected. A resume ack or a delivered final can release the
            // selected id (neither takes `bridge_mu_`) while an unrelated pin
            // appears, leaving the count full. So this decision is provisional and
            // is confirmed by `unpin` reporting that it really cleared the slot.
            const std::size_t pinned_now = rec->stream->pinned_count();
            const std::size_t reclaimed = displaced.has_value() && pinned_now > 0 ? 1U : 0U;
            const std::size_t effective_pinned = pinned_now - reclaimed;
            if (effective_pinned + unpinned >= kMaxStreamedPostsPerSession) {
                reject = "pin_slots";
                displaced.reset();  // rejecting: nothing is released, nothing to report
                // Charges outstanding means calls that reserved and have not
                // settled a terminal - ordinarily in flight, so a wait is true
                // advice. Pins alone means every slot is a committed final
                // awaiting delivery AND the reclaim above found none of them
                // takeable; two of the three states that produces clear on a
                // retry, so that arm advises retrying rather than waiting. The
                // remediation differs by that much, so the caller is told which
                // - see PinSlotsHeld's contract for the full state list.
                pin_slots_held = unpinned > 0 ? PinSlotsHeld::kCharges : PinSlotsHeld::kPins;
                // Captured, NOT emitted here: the metrics registry has its own mutex
                // and the label map allocates, and this is inside bridge_mu_ - the
                // global admission lock. Taking a slower shared lock under a broad
                // one is the shape this very round removed from the pump; the
                // sibling count_reject already defers for the same reason.
                // `pinned_now`, NOT the pre-selection `pinned`: the label must be
                // derived from the same reading the refusal was decided on, or the
                // wedge alert and the client's remediation describe different
                // states (the counter's own comment says it lives at the reject
                // site so it cannot drift from the admission expression).
                pin_reject_pinned = pinned_now;
                pin_reject_unpinned = unpinned;
            }
        }
        if (reject == nullptr) {
            rec->seq = next_seq_++;
            // C6a: the ledger bump and the map insert must commit TOGETHER. Both
            // allocate - `operator[]` inserts a node, `emplace` allocates a node
            // and copies the key - so either can throw with the other already
            // applied. A ledger bump that survives a failed insert is a PHANTOM
            // charge: no record exists that will ever release it, so this
            // session's `pinned_count() + unpinned` stays permanently inflated
            // and every later streamed reserve on it rejects pin_slots for the
            // life of the process. Reordering to "emplace first" does NOT fix
            // this - it only swaps which mutation is left orphaned.
            struct LedgerRollback {
                McpStreamBridge* self;
                const std::string& session;
                BridgeRecord& rec;
                bool armed = false;
                bool committed = false;
                ~LedgerRollback() noexcept {
                    if (armed && !committed) {
                        // Runs while bridge_mu_ is still held (declared after the
                        // lock_guard, so it destructs first). find/decrement/erase
                        // allocates nothing, so it cannot throw out of here.
                        self->decrement_streamed_locked(session);
                        rec.streamed_charge_held = false;
                    }
                }
            } rollback{this, session_id, *rec};

            if (streamed_intent) {
                ++streamed_unpinned_[session_id];
                rollback.armed = true;
                rec->streamed_charge_held = true;
            }
            if (reserve_commit_fault_.exchange(false, std::memory_order_acq_rel)) {
                // Test seam: an allocation failure in the window BETWEEN the
                // ledger bump and the insert. The post-admission seam above fires
                // before the record is even constructed, so it cannot model this.
                throw std::bad_alloc{};
            }
            records_.emplace(rec->key, rec);
            rollback.committed = true;
            active = records_.size();
            // #2740: the admission is COMMITTED, so now — and only now — release
            // the slot it was granted from. Placed after every throwing step so a
            // failed reserve cannot cost a parked final its eviction exemption,
            // and still inside `bridge_mu_` so no concurrent reserve can see the
            // slot double-counted. `unpin` is id-targeted and idempotent: if a
            // resume ack or on_final_written released the same id in between, this
            // is a no-op and the admission stands either way. Allocation-free.
            if (displaced.has_value()) {
                bool released = false;
                try {
                    released = rec->stream->unpin(displaced->event_id);
                } catch (...) {
                    // CONTAINED, and the containment is the point. The record is
                    // ALREADY committed at this line, so an escaping throw unwinds
                    // past the handler's degrade-to-plain catch with the admission
                    // counted and no record the caller believes in - a slot nothing
                    // reclaims until the arming reaper fires. A mutex acquisition
                    // is the one throw site this file's fault model treats as real
                    // (it injects resource_deadlock_would_occur elsewhere), and
                    // `unpin`'s first act is one. Same shape as the pump's
                    // contained credit step at on_final_written's call site.
                    //
                    // LATCHED, not emitted: we are inside `bridge_mu_`, and the
                    // metrics registry takes its own mutex and allocates for the
                    // name. Taking a slower leaf lock under the global admission
                    // lock is the shape this file removes everywhere else - the
                    // sibling reject counter defers for exactly this reason.
                    release_failed = true;
                }
                if (!released) {
                    // Either another route (a resume ack, or a final that reached
                    // the wire) released this id between selection and here, or the
                    // release above was contained. The admission still stands: the
                    // count it was decided on was provisional either way, and on
                    // the raced path the slot this pin held did open - though an
                    // unrelated pin can have taken it since, so this is not a proof
                    // that a slot is free right now (#2795). The residual is
                    // bounded by the 4-wide pin array. What does NOT stand is the
                    // report: no exemption was released by US, so nothing is
                    // counted, audited or logged as a DISPLACEMENT. Reporting one
                    // would attribute a loss that did not happen to the admitting
                    // principal.
                    //
                    // The raced arm still gets its OWN counter (#2795), because
                    // "nothing to report" was read as "nothing to observe" and it is
                    // not: this arm leaves the session transiently one call over its
                    // cap while moving neither of the other two counters, so an
                    // operator ruling the residual out by checking them found both
                    // flat in exactly the case they were checking for.
                    release_raced = !release_failed;
                    displaced.reset();
                }
            }
        }
    }
    // #2740: emitted HERE, outside bridge_mu_ - the metrics registry has its own
    // mutex and the audit sink is caller-supplied, and neither may run under the
    // global admission lock (the same rule the pin-slot reject counter follows).
    if (release_failed) {
        count_pin_release_failed();
    }
    if (release_raced) {
        count_pin_release_raced();
    }
    if (displaced.has_value()) {
        count_pin_displaced_for_admission();
        // ACTOR, not "system": this runs synchronously on the admitting client's
        // own request thread, and server.cpp's audit sink documents an EMPTY actor
        // as meaning the bridge's own background work. Stamping that here would
        // put a client-caused release beyond non-repudiation (Decision 15(j)) and
        // hide it from any SIEM rule keyed on `principal != "system"`.
        // An ORPHAN has no surviving record, so `target_id` is necessarily empty
        // and the ring event id is the only handle the row can carry - it is what
        // joins this row to the ring frame and to the later reap. Carried in the
        // detail rather than leaving the row naming nothing at all.
        // The detail is built into `disposition` BEFORE this point (above the
        // `bridge_mu_` block), NOT inline here. Inline, the conditional's composite
        // type is `std::string`, so BOTH arms allocate in reserve's own frame - at
        // a point where the record is already committed and the pin already
        // released. A bad_alloc there escaped into the handler's degrade-to-plain
        // catch, leaving a committed kArming record and an unreleased charge until
        // the 300s arming reaper, with the counter above already claiming a
        // displacement no audit row would ever corroborate. That is precisely the
        // hazard audit_contained's string_view parameter exists to avoid.
        audit_contained("mcp.bridge.pin_displaced_for_admission", displaced->execution_id,
                        displaced->orphan
                            ? "orphan pin released to admit a new streamed call on this session"
                            : "pin released to admit a new streamed call on this session",
                        displaced_detail, AuditResult::kSuccess, principal);
        // Evidence floor, matching this file's teardown convention: the counter
        // and the audit row both route through swallowing guards, so a log line is
        // the one trace that survives an obs/audit sink failure. The release
        // itself has already committed by the time we get here.
        // The session prefix needs no sanitising here (unlike the reject path in
        // mcp_stream.cpp, which logs an id straight off an unvalidated header):
        // this one is the server-minted id, already validated by the time reserve
        // is reached.
        try {
            spdlog::info("MCP bridge: released {} pin (event_id={}) to admit a streamed call "
                         "on session {}",
                         displaced->orphan ? "an orphan" : "a parked", displaced->event_id,
                         session_id.substr(0, 8));
        } catch (...) {  // NOLINT(bugprone-empty-catch) - logging is best-effort
        }
    }
    if (reject != nullptr) {
        count_reject(reject);
        if (std::string_view(reject) == "pin_slots") {
            count_pin_slots_reject(pin_reject_pinned, pin_reject_unpinned);
        }
        return {false, reject, pin_slots_held};
    }
    publish_records_gauge(active);
    return {true, nullptr};
}

std::optional<McpStreamBridge::DisplacedPin>
McpStreamBridge::select_displaceable_pin_locked(const std::string& session_id,
                                                const std::shared_ptr<McpStreamState>& stream) {
    if (!stream) {
        return std::nullopt;
    }
    // ONE walk of records_, collecting three things at once: whether any of this
    // session's records is mid-projection (the decline condition), which pinned
    // ids are still REFERENCED by a record (so the rest are orphans), and the
    // best record-backed candidate.
    //
    // Record-backed candidate clauses, each excluding a state that must survive:
    //  - kRingOnly: a kStreaming record still has a live pump that may be about to
    //    write its final.
    //  - !final_written: excludes the stale-arm backstop case, where a record was
    //    flipped kStreaming -> kRingOnly out from under a pump that then delivered
    //    the final anyway (on_final_written accepts kRingOnly for exactly that).
    //    NOTE this does NOT exclude the OPEN window of that case - a record whose
    //    pump is still mid-write reads the same as one whose peer died. Releasing
    //    the exemption there is safe (the final is on the wire or about to be, and
    //    on_final_written's unpin is idempotent) but it is why the audit detail
    //    says the final was undelivered "as far as the bridge can see", not that
    //    delivery did not happen.
    //  - !torn_down: a record mid-teardown is somebody else's; skip to the next.
    // Oldest parked_seq wins: the longest-undelivered final is the one whose
    // resume window has most likely already passed.
    std::shared_ptr<BridgeRecord> victim;
    std::uint64_t victim_seq = 0;
    bool projection_in_flight = false;
    // The pin array is the fixed side (at most kMaxStreamedPostsPerSession ids);
    // the RECORD side is not - a session can hold more records than pins, because
    // a record keeps `pinned_event_id` set after its pin has been released and
    // until it is torn down. So the membership test is driven from the PINS and
    // marked off by the records. Collecting referenced ids into a fixed array
    // sized to the pin count instead would silently overflow and mark a live
    // call's pin as an orphan - which is exactly the way this released a pinned
    // final out from under a live record the first time it was written.
    std::array<bool, kMaxStreamedPostsPerSession> pin_referenced{};
    // ONE acquisition of the stream mutex for the whole scan, taken up front:
    // every record of a session shares this ring, so polling per candidate would
    // take the same mutex once per record while the global admission lock is held.
    const auto pinned_ids = stream->pinned_ids_snapshot();
    for (const auto& [key, rec] : records_) {
        if (rec->session_id != session_id) {
            continue;  // pins belong to a session's own ring; make that explicit
        }
        // MEASURED (this change's own regression test, 14 failures in 40 runs
        // before this guard): the admission sum TRANSIENTLY over-counts a single
        // record as two slots, because the terminal ladder commits the pin before
        // the block that clears the streamed charge - and both happen inside one
        // projection claim. reserve() has always noted that over-count and
        // deliberately fails CLOSED on it (the client retries and the window has
        // passed). A reclaim must inherit that: acting on a transient reading
        // would release a live session's final for a slot that was never actually
        // occupied. The claim flag is an exact discriminator - the whole
        // double-count window lies inside it, AND so does the window where the
        // ladder has pinned a final the bridge has not yet stamped, which is
        // exactly when a live call's pin is indistinguishable from an orphan.
        if (rec->projection_in_flight.load(std::memory_order_acquire)) {
            projection_in_flight = true;
            continue;
        }
        std::lock_guard<std::mutex> rlk(rec->mu);
        if (rec->projection_in_flight.load(std::memory_order_acquire)) {
            projection_in_flight = true;  // claimed between the check above and this hold
            continue;
        }
        bool still_pinned = false;
        if (rec->pinned_event_id != 0) {
            for (std::size_t i = 0; i < pinned_ids.size(); ++i) {
                if (pinned_ids[i] == rec->pinned_event_id) {
                    pin_referenced[i] = true;
                    still_pinned = true;
                }
            }
        }
        if (rec->torn_down || rec->phase.load(std::memory_order_acquire) != Phase::kRingOnly) {
            continue;
        }
        if (!rec->final_published || rec->final_written || rec->pinned_event_id == 0 ||
            !rec->stream) {
            continue;
        }
        if (!still_pinned) {
            // Its pin is already gone - acked by a resume, or released by an
            // earlier admission. Tested HERE, against the snapshot, rather than
            // once on the winner at the end: a record that keeps `pinned_event_id`
            // after its pin was released is usually the OLDEST, so checking only
            // the winner let it beat every live candidate and then abort the whole
            // selection, which put the lockout straight back.
            continue;
        }
        if (!victim || rec->parked_seq < victim_seq) {
            victim = rec;
            victim_seq = rec->parked_seq;
        }
    }
    if (projection_in_flight) {
        return std::nullopt;
    }
    // ORPHANS FIRST. A pinned id no surviving record references has no route a
    // POST-ONLY client can reach: the pin-ack sweep needs a record, on_final_written
    // needs a record, and the teardown that erased the record did not unpin. It is
    // NOT unreachable in general - attach_and_replay's cursor ack walks pinned_ids_
    // directly with no record lookup and clears every slot at or below the cursor,
    // orphans included - but that needs a GET channel, which is exactly what the
    // locked-out client in #2740 does not have. Left
    // alone, four of these lock the session out of streamed POST permanently - the
    // exact defect #2740 is about, in the one shape a record scan cannot see.
    // Safe only because `projection_in_flight` is false above: that is what rules
    // out a live call whose pin is committed but not yet stamped.
    std::uint64_t orphan = 0;
    for (std::size_t i = 0; i < pinned_ids.size(); ++i) {
        const auto id = pinned_ids[i];
        if (id == 0 || pin_referenced[i]) {
            continue;
        }
        if (orphan == 0 || id < orphan) {
            orphan = id;  // lowest id = oldest frame
        }
    }
    if (orphan != 0) {
        return DisplacedPin{std::string{}, orphan, /*orphan=*/true};
    }
    if (!victim) {
        return std::nullopt;
    }
    std::lock_guard<std::mutex> rlk(victim->mu);
    return DisplacedPin{victim->execution_id, victim->pinned_event_id, /*orphan=*/false};
}

bool McpStreamBridge::subscribe(const std::string& session_id, const nlohmann::json& jsonrpc_id,
                                const std::string& execution_id) {
    if (bus_ == nullptr) {
        return false;
    }
    // A3: the WHOLE install runs under bridge_mu_ - installation and the
    // sub-token store are serialized against shutdown/teardown, so a listener
    // can never exist without a token a teardown can see. bridge_mu_ →
    // Channel::mu is the declared edge; the replay runs the listener inline
    // (record mu + WakeCore::mu - no cycle).
    std::lock_guard<std::mutex> lk(bridge_mu_);
    if (shutdown_started_) {
        return false;
    }
    auto rec = find_locked(make_key(session_id, jsonrpc_id));
    if (!rec) {
        return false;
    }
    if (subscribe_fault_.exchange(false, std::memory_order_acq_rel)) {
        throw std::bad_alloc{};  // test seam: model a subscribe allocation failure
    }
    // Prebuilt HERE, before the record-mu hold, for the same reason arm() does it
    // (H2): the throwing work happens while nothing has changed, and the commit
    // below is a noexcept move. Load-bearing for park_after_dispatch_failure - a
    // record parked before arm() ran has no other source for a fallback final, and
    // every fallback publisher (the projector ladder and teardown's kFallbackFinal
    // arm) reads this field. Without it such a record would publish an EMPTY frame.
    std::string fallback = build_fallback_final(jsonrpc_id, execution_id);
    {
        // EXACTLY-ONCE, STATE-CHECKED (#2487 review). The "written before any
        // listener exists, immutable afterwards" contract is what lets
        // teardown_claimed BORROW execution_id instead of copying it, and what
        // stops a second listener being installed on a record a sweep has already
        // claimed. It used to be a comment; now it is a gate.
        //
        // The window that made it load-bearing: a sweep claimant sets torn_down
        // and releases both locks before teardown_claimed runs, and the record is
        // erased from records_ only at the very END of teardown. A subscribe()
        // arriving in between still resolves the record, would reassign the string
        // out from under teardown's borrowed reference (a reallocating assignment
        // = a genuine data race on the read), and would install a fresh listener
        // that the imminent erase then strands forever - recreating precisely the
        // orphan-listener leak this change exists to prevent. Reachable via the
        // kArming reaper, which cannot distinguish a dead handler from a very slow
        // one.
        std::lock_guard<std::mutex> rlk(rec->mu);
        // `torn_down` is REDUNDANT today and kept deliberately: every claim path
        // moves the phase out of kArming in the same critical section that sets
        // torn_down, so the phase check below always catches a claimed record first.
        // Verified by mutation - deleting this clause alone leaves the suite green,
        // whereas deleting either of the other two reddens it. It is retained as
        // defence in depth so that a future claim path which forgets to move the
        // phase still cannot admit a subscribe; it is NOT independently covered.
        if (rec->subscribed || rec->torn_down ||
            rec->phase.load(std::memory_order_acquire) != Phase::kArming) {
            return false;
        }
        rec->execution_id = execution_id;
        rec->fallback_final = std::move(fallback);
    }
    // ORDERING INVARIANT (governance performance/UP-5): the caller MUST invoke
    // subscribe() BEFORE dispatch / the first refresh_counts, so the bus channel
    // has no buffered events yet and this inline replay-under-bridge_mu_ is O(0).
    // If a future refactor moved subscribe() after progress began, this would
    // hold bridge_mu_ across an O(buffer, up to kBufferCap=1000) replay, stalling
    // every reserve/arm/abandon/sweep behind it.
    const auto sub_id = bus_->subscribe_and_replay(execution_id, 0, make_listener(rec, core_));
    rec->sub_id = sub_id;
    rec->subscribed = true;
    return true;
}

McpStreamBridge::ArmOutcome McpStreamBridge::arm(const std::string& session_id,
                                                 const nlohmann::json& jsonrpc_id, ArmMode mode,
                                                 std::string result_base) {
    std::shared_ptr<BridgeRecord> rec;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return ArmOutcome::kNotFound;
        }
        rec = find_locked(make_key(session_id, jsonrpc_id));
    }
    if (!rec) {
        return ArmOutcome::kNotFound;  // abandon won and erased - equally valid
    }
    if (arm_fault_.exchange(false, std::memory_order_acq_rel)) {
        throw std::bad_alloc{};  // test seam: model a pre-flip allocation failure
    }
    // Prebuild the minimal fallback final BEFORE the flip (H2): all throwing
    // work happens while nothing has changed. subscribe() already stored an
    // identical string (so a park before arm has one); this rebuild keeps arm
    // self-sufficient, and both go through build_fallback_final so the bytes have
    // exactly one derivation.
    std::string exec_id;
    std::string rec_principal;
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        exec_id = rec->execution_id;
        // The cancel this may consume came from an authenticated client too, so the
        // row it produces is attributable like the streamed detach is. The session
        // gate guarantees this equals the canceller.
        rec_principal = rec->principal;
    }
    std::string fallback = build_fallback_final(jsonrpc_id, exec_id);

    bool consumed_cancel = false;
    bool degraded = false;
    ArmOutcome outcome = ArmOutcome::kArmed;  // defensively initialised; assigned below
    {
        // The ONE record-mutex hold (H2): noexcept moves, arbitration, flip,
        // handoff wake. A concurrent listener append lands pre-flip (drained by
        // this wake) or post-flip (drained by its own unconditional wake).
        std::lock_guard<std::mutex> rlk(rec->mu);
        // C6 re-check under the flip hold: shutdown() sets shutdown_called_
        // (atomic) at its very start, BEFORE it stops+joins the projector and
        // clears the map. A caller that passed the top-of-arm shutdown gate but
        // released bridge_mu_ before reaching here could otherwise flip a
        // detached record and wake a joined projector. Bailing keeps the C6
        // gating contract true independent of the (masking) server wiring order.
        if (shutdown_called_.load(std::memory_order_acquire)) {
            return ArmOutcome::kNotFound;
        }
        const Phase cur = rec->phase.load(std::memory_order_acquire);
        if (cur == Phase::kAborted) {
            return ArmOutcome::kAborted;
        }
        if (cur != Phase::kArming) {
            return ArmOutcome::kAlreadyArmed;
        }
        rec->fallback_final = std::move(fallback);
        rec->result_base = std::move(result_base);
        consumed_cancel = rec->cancel_pending;
        rec->cancel_pending = false;
        degraded = consumed_cancel && mode == ArmMode::kStreaming;
        const Phase target =
            (mode == ArmMode::kStreaming && !degraded) ? Phase::kStreaming : Phase::kArmedGetOnly;
        rec->phase.store(target, std::memory_order_release);
        outcome = degraded ? ArmOutcome::kDegradedGetOnly : ArmOutcome::kArmed;
        mark_dirty(*core_, rec->key);  // the handoff - same hold
    }
    if (degraded) {
        // #2529: the degraded record follows the GET-only lifecycle and can never
        // pin, so its admission charge is owed back. This USED TO clear
        // streamed_charge_held inside the flip hold above and take bridge_mu_ here
        // afterwards - the split that broke release_charge and project_record, with
        // the same consequence: a throw at the second acquisition left the record
        // reading "not held" while streamed_unpinned_[session] still counted it, so
        // that entry never reached 0, never got erased, and the session accumulated
        // forever. Routing through release_charge - which takes BOTH locks in
        // hierarchy order and re-reads the flag under them - makes it both-or-
        // neither, and keeps ONE implementation of the release rather than a third
        // copy. Exactly-once survives the move: the flag is the interlock, so a
        // concurrent teardown racing this simply wins and this call no-ops.
        //
        // CONTAINED, and the outcome is still returned. A failure here leaves a
        // CONSISTENT record (charge held, ledger counts it) that its own teardown
        // repairs, whereas throwing would lose a flip that already succeeded and
        // hand the caller an error response for a request whose plain result is
        // perfectly good. This is also what makes the H2 property above literally
        // true: after the flip, arm() cannot throw. Same posture as teardown step 3,
        // which contains and counts a release_charge failure rather than abandoning
        // the teardown.
        try {
            release_charge(rec);
        } catch (...) {
            count_charge_release_deferred();
        }
    }
    if (consumed_cancel) {
        // C1: audit only AFTER winning the arbitration, outside every lock.
        audit_contained("mcp.bridge.cancel", exec_id,
                        outcome == ArmOutcome::kDegradedGetOnly
                            ? "consumed_by_arm: streamed intent degraded to get-only"
                            : "consumed_by_arm: get-only request, nothing to detach",
                        {}, AuditResult::kSuccess, rec_principal);
    }
    return outcome;
}

McpStreamBridge::CancelOutcome McpStreamBridge::request_cancel(const std::string& session_id,
                                                               const nlohmann::json& jsonrpc_id,
                                                               std::string_view principal) {
    std::shared_ptr<BridgeRecord> rec;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return CancelOutcome::kNoOp;
        }
        rec = find_locked(make_key(session_id, jsonrpc_id));
    }
    if (!rec) {
        return CancelOutcome::kNoOp;  // no oracle: unknown == not cancellable
    }
    std::string exec_id;
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        const Phase ph = rec->phase.load(std::memory_order_acquire);
        if (ph == Phase::kStreaming) {
            // 3b: the record HAS a live streamed response, so there is nothing for
            // a later arbiter to decide - the cancel applies NOW. Closing the sink
            // is the whole action: the pump wakes, sees `closed`, and finishes with
            // kCancelled, which writes the close frame carrying execution_id and
            // partial:true; its releaser then parks the record.
            //
            // The EXECUTION is deliberately untouched - not unsubscribed, not
            // abandoned, never marked cancelled. MCP cancellation withdraws the
            // client's interest in a RESPONSE; the dispatched command keeps running
            // on real agents and its result stays fetchable by execution_id.
            // Cancelling the work here would let a client believe it had stopped a
            // fleet-wide change it had not.
            if (!rec->post_sink) {
                return CancelOutcome::kNoOp;  // never bound, or already parked
            }
            // COPIED BEFORE THE MUTATION, deliberately: this is the only allocation
            // on the path, and doing it after the close would let a bad_alloc
            // propagate out of a cancel that had ALREADY ended the response - the
            // caller catches, reports kNoOp, and a cancel that genuinely took effect
            // goes unaudited and uncounted. Same discipline as arm(), which
            // prebuilds its fallback before the flip.
            exec_id = rec->execution_id;
            // The close TRANSITION is the interlock, not the phase. `post_sink` is
            // not cleared until on_post_closed_keyed, which runs later from the
            // pump's releaser, so two cancels arriving before that BOTH see
            // kStreaming with a live sink - a retried notification is ordinary
            // client behaviour, not a race anyone has to engineer. Only the caller
            // that actually flipped `closed` may claim the detach; a duplicate is
            // kNoOp, which is also the honest answer once there is no live response
            // left to detach. A close that could not be delivered returns false
            // too, so the audit below can never assert something that did not
            // happen.
            if (!close_post_sink(rec->post_sink)) {
                return CancelOutcome::kNoOp;
            }
        } else if (ph == Phase::kArming && !rec->cancel_pending) {
            // Pre-arm: intent ONLY - no audit, no transition (C1). A later
            // pre-dispatch failure (abandon) invalidates the cancel/degrade
            // outcome, so the win is arm()'s and the audit belongs there.
            rec->cancel_pending = true;
            return CancelOutcome::kAcceptedPending;
        } else {
            return CancelOutcome::kNoOp;
        }
    }
    // Outside every lock (C1 discipline). Unlike the kArming path there is no later
    // arbiter to audit this one, so it is audited HERE, exactly once - CH-12
    // requires a cancellation to be auditable, and this is the only site that knows
    // it took effect.
    audit_contained("mcp.bridge.cancel", exec_id,
                    "detached the streamed response; the execution continues", {},
                    AuditResult::kSuccess, principal);
    return CancelOutcome::kDetached;
}

bool McpStreamBridge::close_post_sink(
    const std::shared_ptr<sse_bus::SseSinkState>& sink) noexcept {
    if (!sink) {
        return false;
    }
    try {
        // `closed` is stored UNDER the sink mutex rather than as a bare atomic
        // write, for the same reason poke_post_sink takes it: the pump evaluates
        // its wait predicate under this mutex, so a store outside it can land
        // between that evaluation and the wait and leave the pump asleep on a
        // stream the client has already given up on - a lost wakeup that costs a
        // full tick and keeps an HTTP worker pinned meanwhile.
        //
        // Callers hold the record mutex, which the declared hierarchy places ABOVE
        // this one (BridgeRecord::mu -> McpStreamState::mu_ -> SseSinkState::mu),
        // so this nesting is the sanctioned direction.
        bool was_open = false;
        {
            std::lock_guard<std::mutex> lk(sink->mu);
            // exchange, not store: the RETURN VALUE is what makes the caller's
            // action exactly-once. Under the mutex so it cannot interleave with
            // the pump's predicate evaluation.
            was_open = !sink->closed.exchange(true, std::memory_order_acq_rel);
        }
        sink->cv.notify_all();
        return was_open;
    } catch (...) { // NOLINT(bugprone-empty-catch)
        // A cancel we could not deliver is not worth propagating out of a noexcept
        // seam on a request thread: the response still ends at its cap, and the
        // execution was never at risk either way. Reported as "not closed by me"
        // so the caller cannot audit a detach that did not occur.
    }
    return false;
}

bool McpStreamBridge::abandon(const std::string& session_id, const nlohmann::json& jsonrpc_id) {
    std::shared_ptr<BridgeRecord> rec;
    std::size_t active = 0;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return false;  // shutdown owns global teardown
        }
        const auto key = make_key(session_id, jsonrpc_id);
        rec = find_locked(key);
        if (!rec) {
            return false;
        }
        {
            std::lock_guard<std::mutex> rlk(rec->mu);
            if (rec->phase.load(std::memory_order_acquire) != Phase::kArming) {
                return false;  // arm won - the caller lost the arbitration (C1)
            }
            rec->phase.store(Phase::kAborted, std::memory_order_release);
            rec->cancel_pending = false;  // discarded, never audited (C1)
            rec->progress_pending = false;
            rec->terminal_slot.reset();
            if (rec->streamed_charge_held) {
                rec->streamed_charge_held = false;
                decrement_streamed_locked(session_id);  // already under bridge_mu_
            }
        }
        if (rec->subscribed && bus_ != nullptr) {
            // Waits out in-flight listeners; after this returns no thread can
            // append (they take record mu + WakeCore::mu only - no cycle).
            bus_->unsubscribe(rec->execution_id, rec->sub_id);
        }
        rec->subscribed = false;
        records_.erase(key);
        active = records_.size();
    }
    flush_record_obs(*rec);
    publish_records_gauge(active);
    return true;
}

bool McpStreamBridge::park_after_dispatch_failure(const std::string& session_id,
                                                  const nlohmann::json& jsonrpc_id,
                                                  std::string_view principal) {
    std::shared_ptr<BridgeRecord> rec;
    std::uint64_t parked_seq = 0;
    std::string exec_id;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return false;  // shutdown owns global teardown
        }
        rec = find_locked(make_key(session_id, jsonrpc_id));
        if (!rec) {
            return false;  // abandon or a sweep claim won - equally valid
        }
        parked_seq = next_parked_seq_++;
    }
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        // C6 re-check under the transition hold (same rationale as arm() and
        // on_post_closed): a shutdown that raced past the top gate must not have
        // this transition wake a joined projector on a detached record.
        if (shutdown_called_.load(std::memory_order_acquire)) {
            return false;
        }
        Phase expected = Phase::kArming;
        if (!rec->phase.compare_exchange_strong(expected, Phase::kRingOnly,
                                                std::memory_order_acq_rel)) {
            return false;  // arm() or abandon() already arbitrated this record
        }
        // Discarded without audit, exactly as abandon does (C1): the cancel was
        // intent against a stream that now will never exist. The streamed charge
        // is deliberately RETAINED - a parked record can still pin its final, and
        // the pin-ack / teardown paths release it exactly once.
        rec->cancel_pending = false;
        rec->parked_seq = parked_seq;
        exec_id = rec->execution_id;
    }
    // The progress slot and any latched terminal survived the transition, so
    // hand the record to the projector now rather than waiting for the next bus
    // event.
    mark_dirty(*core_, rec->key);
    audit_contained("mcp.bridge.dispatch_failure", exec_id,
                    "parked after a post-dispatch failure: the execution continues and its "
                    "result stays fetchable by execution_id",
                    {}, AuditResult::kSuccess, principal);
    return true;
}

std::optional<std::string> McpStreamBridge::record_key(const std::string& session_id,
                                                       const nlohmann::json& jsonrpc_id) {
    auto key = make_key(session_id, jsonrpc_id);  // allocates HERE, which is the point
    std::lock_guard<std::mutex> lk(bridge_mu_);
    if (shutdown_started_ || !find_locked(key)) {
        return std::nullopt;
    }
    return key;
}

bool McpStreamBridge::on_post_closed(const std::string& session_id,
                                     const nlohmann::json& jsonrpc_id) {
    // ONE implementation; this overload just pays the key allocation. Keeping a
    // second copy of the transition here is how the two would drift.
    return on_post_closed_keyed(make_key(session_id, jsonrpc_id));
}

bool McpStreamBridge::on_post_closed_keyed(const std::string& key) {
    std::shared_ptr<BridgeRecord> rec;
    std::uint64_t parked_seq = 0;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return false;
        }
        rec = find_locked(key);
        if (!rec) {
            return false;
        }
        parked_seq = next_parked_seq_++;
    }
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        // C6 re-check under the transition hold (same rationale as arm()): a
        // shutdown that raced past the top gate must not have this transition
        // wake a joined projector on a detached record.
        if (shutdown_called_.load(std::memory_order_acquire)) {
            return false;
        }
        // A delivered final means the client already holds its answer, so there
        // is nothing left to resume: settle kDone and let sweep reap it. Without
        // a final, park for GET resume. Both are the same CAS out of kStreaming,
        // so a record can only ever take one of them.
        const Phase target = rec->final_written ? Phase::kDone : Phase::kRingOnly;
        Phase expected = Phase::kStreaming;
        if (!rec->phase.compare_exchange_strong(expected, target, std::memory_order_acq_rel)) {
            return false;
        }
        rec->parked_seq = parked_seq;
        // The wire is gone; holding its sink would pin a dead connection's state
        // for as long as the record parks.
        rec->post_sink.reset();
    }
    // A1: a terminal latched while the pump was dying must not wait for the next
    // bus event or sweep - hand the record to the projector now.
    mark_dirty(*core_, rec->key);
    return true;
}

bool McpStreamBridge::on_final_written(const std::string& key) {
    std::shared_ptr<BridgeRecord> rec;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return false;
        }
        rec = find_locked(key);
        if (!rec) {
            return false;
        }
    }
    std::lock_guard<std::mutex> rlk(rec->mu);
    // kRingOnly is accepted alongside kStreaming: the sweep's stale-arm backstop
    // can flip a record kStreaming -> kRingOnly while its pump still holds a final
    // to write. Rejecting a final here after that flip leaks the pin of a result
    // that reached the client.
    const auto ph = rec->phase.load(std::memory_order_acquire);
    if (ph != Phase::kStreaming && ph != Phase::kRingOnly) {
        return false;  // no wire could have written a final in any other phase
    }
    rec->final_written = true;
    // UNPIN RULE (a), the streamed-POST half: "the final was written on the POST
    // wire" (mcp_stream.hpp). This is the rung that makes that event exist, and
    // until now nothing called unpin() at all - so a COMPLETED streamed call left
    // its pin behind forever, admission counted it against
    // kMaxStreamedPostsPerSession, and four successful calls locked a session out
    // permanently while the 429 told the client to wait for calls that had already
    // finished. Rule (b) (a GET resume acking past the id) only ever covered the
    // resume case; a client that received its final on the POST wire never resumes.
    //
    // Safe precisely here: the pump calls this ONLY after write_all succeeded, so a
    // dead peer returns kClientGone without reaching it and correctly keeps the pin
    // for a resuming client. Lock order holds - BridgeRecord::mu is above
    // McpStreamState::mu_.
    if (rec->pinned_event_id != 0 && rec->stream) {
        // Deliberately discarded: this release is best-effort. A false here means
        // the id was already released (a resume ack, or the admission reclaim), and
        // nothing downstream branches on which of those happened.
        (void)rec->stream->unpin(rec->pinned_event_id);
    }
    return true;
}

std::optional<std::string> McpStreamBridge::bind_post_sink(
    const std::string& session_id, const nlohmann::json& jsonrpc_id,
    std::shared_ptr<sse_bus::SseSinkState> sink) {
    if (!sink) {
        return std::nullopt;
    }
    auto key = make_key(session_id, jsonrpc_id);  // allocates HERE, before any state changes
    std::shared_ptr<BridgeRecord> rec;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return std::nullopt;
        }
        rec = find_locked(key);
        if (!rec) {
            return std::nullopt;
        }
    }
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        if (rec->phase.load(std::memory_order_acquire) != Phase::kStreaming) {
            return std::nullopt;  // only a live streamed record has a POST wire
        }
        rec->post_sink = std::move(sink);
        // BIND-TIME HANDSHAKE: evaluate the pending-work predicate inside the SAME
        // hold that stores the sink. Work can latch between arm() and this call -
        // a terminal, most consequentially - and the projector only forwards wakes
        // to a sink it can already see, so anything latched before the bind would
        // otherwise cost the pump a full tick.
        if (has_pending_work_locked(*rec)) {
            poke_post_sink(rec->post_sink);
        }
    }
    return key;
}

McpStreamBridge::PostBatch McpStreamBridge::take_post_batch(const std::string& key,
                                                            bool cap_expired) {
    PostBatch out;
    std::shared_ptr<BridgeRecord> rec;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            // Shutdown owns teardown, but the pump must be told there is nothing
            // left to wait for.
            out.record_gone = true;
            return out;
        }
        rec = find_locked(key);
        if (!rec) {
            // Erased under us — swept, reaped, or torn down. Nothing will ever
            // arrive for this key again.
            out.record_gone = true;
            return out;
        }
    }
    // ONE projection implementation - see the header note. project_record accepts
    // kStreaming only when handed a batch, and fills it with the frames it just
    // committed to the ring.
    project_record(rec, &out, cap_expired);
    flush_record_obs(*rec);
    // PARK-VS-CLAIM FENCE. A close can flip kStreaming -> kRingOnly while this
    // pump holds the projection claim. That transition wakes the projector once,
    // but the projector finds the claim set and returns; by the time the claim
    // clears (project_record's guard, just above) nothing wakes it again, and a
    // parked record holding a latched terminal stalls until the next sweep tick.
    // Re-waking here closes that window. A spurious wake costs one projector pass
    // over a record with no work; a missed one costs a stalled result.
    if (rec->phase.load(std::memory_order_acquire) != Phase::kStreaming) {
        mark_dirty(*core_, rec->key);
    }
    // COMMIT THE ENDING HERE, at the DECISION, not later at the close. Once the
    // bridge has handed back a final or settled the cap, this response IS ending -
    // the pump will write and EOF - so a cancel arriving from now on has nothing
    // left to detach and must answer kNoOp.
    //
    // Doing it at finish() instead (the previous attempt) left the whole rest of
    // the tick exposed: revalidate is a store round trip, then session_alive, then
    // every progress write and the final write. A cancel landing anywhere in there
    // still found closed==false, won close_post_sink's exchange, and audited
    // "detached the streamed response" for an exchange the client completed
    // normally - two contradictory compliance rows for one request. The window is
    // now the batch handover alone.
    //
    // Safe against the pump's own flow: `closed` is read at the TOP of a tick, and
    // this tick will not reach another one. Taking sink-mu under rec-mu is the
    // sanctioned order.
    if (out.final_frame.has_value() || out.cap_settled) {
        std::lock_guard<std::mutex> rlk(rec->mu);
        if (rec->post_sink) {
            (void)close_post_sink(rec->post_sink);
        }
    }
    return out;
}

bool McpStreamBridge::has_pending_work_locked(const BridgeRecord& rec) {
    // "Latched work worth waking the pump for". This was the SAME predicate
    // project_record uses to decide there is a batch worth claiming until #2739
    // made the pump path context-dependent (cap_expired + cap_progress_drained);
    // the divergence is deliberate - a progress snapshot deliberately held back
    // by the cap drain must STILL count as pending here, because that wake is
    // what lets the settle pass run immediately instead of a tick later.
    const bool progress = rec.progress_pending && !rec.pressure_requested;
    const bool terminal = rec.terminal_accepted &&
                          !rec.terminal_projected.load(std::memory_order_acquire) &&
                          rec.terminal_slot.has_value();
    return progress || terminal;
}

void McpStreamBridge::poke_post_sink(
    const std::shared_ptr<sse_bus::SseSinkState>& sink) noexcept {
    if (!sink) {
        return;
    }
    try {
        // Taking the sink mutex before notifying is what makes this a HANDOFF
        // rather than a lost wakeup. The pump evaluates its predicate under this
        // mutex, so a bare notify could land in the window between that
        // evaluation and the wait, and the pump would then sleep through work
        // that was already there. The `poked` flag set below IS what the predicate
        // reads, and holding the mutex across that store is what orders it against
        // the pump's wait - the same discipline as storing `closed` under it. (This
        // comment used to say nothing was mutated here, which was true and was
        // exactly the bug: a notify with no state change cannot satisfy a
        // predicated wait_for, so the whole wake path was inert.)
        //
        // NOT INDEPENDENTLY COVERED, and deliberately so: removing this
        // acquisition leaves the suite green, because the poke reaches here only
        // after the bus listener, the projector wake and a thread switch, by
        // which time any waiting pump is already inside wait_for. Forcing the
        // window would need a test hook inside this function, which would prove
        // the hook rather than the discipline. Verified by mutation and recorded
        // as uncovered rather than given a test that passes for the wrong reason.
        //
        // Callers hold the record mutex, which the declared hierarchy places
        // ABOVE this one (BridgeRecord::mu -> McpStreamState::mu_ ->
        // SseSinkState::mu), so this nesting is the sanctioned direction; the
        // pump holds the sink mutex only to evaluate a predicate, never across
        // a write.
        {
            std::lock_guard<std::mutex> slk(sink->mu);
            // SET something the pump's predicate READS. Taking the mutex alone is
            // not a wake: the pump waits on a predicated wait_for, so a bare notify
            // makes it re-evaluate, find nothing, and sleep out the rest of the
            // tick. Without this flag the whole wake path - this function and
            // bind_post_sink's handshake - is inert, and progress arrives on a
            // fixed grid rather than as it happens.
            sink->poked.store(true, std::memory_order_release);
        }
        sink->cv.notify_one();
    } catch (...) {  // NOLINT(bugprone-empty-catch) - the pump's tick timeout is the backstop
    }
}

// ── Projector ──────────────────────────────────────────────────────────────

void McpStreamBridge::run_projector() {
    // #2411: keys with possibly-unprojected work, swapped out of core_->dirty
    // each cycle. Declared OUTSIDE the loop and `clear()`ed (not
    // reconstructed) per cycle so its bucket storage is reused across the
    // projector's whole lifetime rather than reallocated on every wake.
    std::unordered_set<std::string> keys;
    for (;;) {
        // MUST run before the swap below, unconditionally - not after using
        // `keys`, and not only on the no-throw path. `keys` needs to be
        // GUARANTEED empty at the swap regardless of how the PREVIOUS
        // iteration ended, including via the outer catch below (whose throw
        // sites - snap.reserve/push_back - run before the post-extraction
        // clear this replaced). A stale non-empty `keys` swapped into
        // core_->dirty here would corrupt it with keys no mark_dirty call
        // ever inserted: a LATER mark_dirty on one of those keys would then
        // see insert() return false (already present) and skip its notify,
        // stranding that record's next event with no live source left to
        // wake the projector - the very lost-wakeup mark_dirty's own proof
        // depends on `dirty` only ever holding what a real mark put there.
        // Harmless no-op when the previous iteration exits normally, since
        // the swap below already leaves `keys` empty for next time.
        keys.clear();
        bool full_scan = false;
        {
            std::unique_lock<std::mutex> lk(core_->mu);
            core_->cv.wait(lk, [&] { return core_->stop || core_->work_pending; });
            if (core_->stop) {
                return;  // listeners are unsubscribed by shutdown; residual
                         // progress frames of a dying process are not a delivery
                         // obligation (terminals are durable-fetchable)
            }
            core_->work_pending = false;
            keys.swap(core_->dirty);  // `keys` is guaranteed empty here (the
                                      // clear above), so this ALSO empties
                                      // core_->dirty unconditionally
            // A separate load+store here would race the ONE writer that does
            // not hold core_->mu (mark_dirty's outer catch, above) - its
            // store(true) could land between the two and get silently
            // clobbered by the store(false), losing the only recorded trace
            // of the wake it was standing in for. exchange() closes that
            // window: whichever side the race lands on, the flag is atomic
            // as a single read-clear, not two.
            full_scan = core_->scan_all.exchange(false, std::memory_order_relaxed);
        }
        // BARE-THREAD BOUNDARY: run_projector is a std::thread entry with no
        // caller try/catch, so ANY escaped exception is std::terminate (#2037
        // class). The record snapshot ALLOCATES (snap.reserve / push_back) - a
        // bad_alloc there would escape past the per-record guard below, which is
        // why the whole cycle body is contained. A transient allocation failure
        // drops this cycle; the next wake retries, and a latched terminal stays
        // durably fetchable in the meantime (Decision 15(f)).
        try {
            std::vector<std::shared_ptr<BridgeRecord>> snap;
            {
                std::lock_guard<std::mutex> lk(bridge_mu_);
                if (full_scan) {
                    // Degraded-cycle fallback (WakeCore::scan_all): a dirty-key
                    // insert hit an allocation failure in mark_dirty, a PRIOR
                    // cycle's body threw after its keys were already swapped
                    // out (see the outer catch below), or mark_dirty could not
                    // even acquire WakeCore::mu (its own outer catch) - any of
                    // these leaves `keys` untrustworthy as the full set of
                    // records with pending work, so fall back to the
                    // pre-#2411 full-table scan for this one cycle.
                    snap.reserve(records_.size());
                    for (const auto& [key, rec] : records_) {
                        snap.push_back(rec);
                    }
                } else {
                    // #2411: O(dirty) per cycle, not O(records_). A key that no
                    // longer resolves (erased since it was marked) is simply
                    // skipped, and a key that resolves to a DIFFERENT, freshly
                    // reserved record at the same key (keys are reused after
                    // erase - see BridgeRecord::key's contract) is visited
                    // anyway: a spurious project_record visit on a fresh
                    // same-key record is benign, because every action inside
                    // it self-gates under rec->mu (the phase check, the
                    // projection_in_flight claim, the want_progress/
                    // want_terminal gates) - unlike the CLAIM paths (Pass R
                    // and its siblings), which compare map-slot IDENTITY
                    // because acting on the wrong record there would corrupt
                    // exactly-once teardown arbitration. Projection has no
                    // such hazard, so a plain key lookup is sufficient here.
                    snap.reserve(keys.size());
                    for (const auto& key : keys) {
                        auto it = records_.find(key);
                        if (it != records_.end()) {
                            snap.push_back(it->second);
                        }
                    }
                }
            }
            for (const auto& rec : snap) {
                try {
                    project_record(rec);
                } catch (...) {
                    // project_record's claim guard restored any unsettled terminal;
                    // this is a true should-not-happen backstop (all interior throw
                    // sites are individually caught). Pre-#2411, this record was
                    // retried for free on the next full-table scan; under dirty-set
                    // gating its key was already consumed from this cycle's `keys`,
                    // so without a re-mark a record whose OWN listener will never
                    // fire again (e.g. one already past D2's terminal_accepted
                    // short-circuit) would strand here until an unrelated scan_all
                    // degrade rescued it. Re-mark, mirroring the listener catch
                    // site above. Under a PERSISTENT fault this spins
                    // visit->throw->re-mark - the same accepted risk class as the
                    // outer catch's re-arm below and the listener catch site
                    // (tracked, with this site added, at #3331). Re-mark BEFORE
                    // logging, matching the listener catch site's ordering: the
                    // mark_dirty call itself is verified noexcept end-to-end,
                    // but spdlog's format/sink path is not, so this ordering
                    // means the recovery action never depends on a third-party
                    // library's internal exception containment holding across
                    // a future spdlog upgrade. execution_id, not rec->key, in
                    // the log line - key embeds a literal '\n' plus
                    // client-supplied jsonrpc_id (see make_key()).
                    mark_dirty(*core_, rec->key);
                    spdlog::warn(
                        "MCP bridge projector: projection pass failed (contained) "
                        "[execution_id={}]",
                        rec->execution_id);
                }
                flush_record_obs(*rec);
            }
            flush_core_obs();
            // Event-driven liveness signal (governance sre): a flat rate here
            // while records_active > 0 means the projector is wedged.
            if (metrics_ != nullptr) {
                obs_guard([&] { metrics_->counter(kMetricProjectorCycles).increment(); });
            }
        } catch (...) {  // NOLINT(bugprone-empty-catch) - see the boundary note above
            // #2411: this cycle's dirty keys were already swapped out of
            // core_->dirty above and its snapshot never got visited, so the
            // pre-#2411 guarantee ("the next wake retries") would otherwise
            // silently narrow to only whichever records happen to get freshly
            // marked afterward. Re-arm a full scan instead, restoring it.
            try {
                std::lock_guard<std::mutex> lk(core_->mu);
                core_->scan_all.store(true, std::memory_order_relaxed);
                core_->work_pending = true;
            } catch (...) {  // NOLINT(bugprone-empty-catch)
            }
            core_->cv.notify_one();
        }
    }
}

void McpStreamBridge::project_record(const std::shared_ptr<BridgeRecord>& rec, PostBatch* out,
                                     bool cap_expired) {
    Phase ph;
    bool have_progress = false;  ///< #2412: rec->projection_spare holds a latched snapshot
    std::optional<MailboxEntry> term;
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        ph = rec->phase.load(std::memory_order_acquire);
        // kStreaming is PUMP-owned: only take_post_batch (which passes `out`) may
        // project it. The projector still visits such records, but its whole job
        // there is to FORWARD THE WAKE - a streamed record's frames are ring-only
        // (deliver_live=false), so the publish path never notifies the POST sink
        // and the pump would otherwise sleep out its tick on work already latched.
        if (ph == Phase::kStreaming && out == nullptr) {
            if (has_pending_work_locked(*rec)) {
                poke_post_sink(rec->post_sink);
            }
            return;
        }
        if (ph != Phase::kArmedGetOnly && ph != Phase::kRingOnly && ph != Phase::kStreaming) {
            // kArming latches; kDone/kAborted dead. A sweep claim can reach this
            // point (phase already flipped, record not yet erased) while a pump
            // still holds this key: without record_gone, the pump reads an
            // untouched default batch and heartbeats on a record nothing will
            // ever update again.
            if (out != nullptr) {
                out->record_gone = true;
            }
            return;
        }
        if (rec->projection_in_flight.load(std::memory_order_acquire)) {
            if (out != nullptr) {
                out->deferred = true;  // the pump retries next tick; nothing is owed
            }
            return;  // the claim fences sweep and the other projector (B2)
        }
        // E1: while a pressure sweep is waiting on this record, no NEW progress
        // batch may start - only an already-latched terminal settles.
        const bool want_terminal = rec->terminal_accepted &&
                                   !rec->terminal_projected.load(std::memory_order_acquire) &&
                                   rec->terminal_slot.has_value();
        // #2739: once the one post-expiry drain pass has run, a cap-expired pump
        // pass starts no further progress batch - otherwise a progress slot that
        // refills every tick keeps the response open for the whole execution. A
        // pending terminal bypasses the suppression: that pass ends the response anyway,
        // and it must carry the intervening progress ahead of the final
        // (progress-before-final ordering) rather than strand it in a record about
        // to settle kDone.
        const bool settling_cap =
            out != nullptr && cap_expired && rec->cap_progress_drained && !want_terminal;
        const bool want_progress =
            rec->progress_pending && !rec->pressure_requested && !settling_cap;
        if (!want_progress && !want_terminal) {
            // CAP ARBITRATION, decided INSIDE the record lock alongside the
            // terminal check rather than by the pump beforehand: a terminal that
            // latched in the same instant wins, and ordinary progress is never
            // ring-committed merely to probe for one.
            if (out != nullptr && cap_expired) {
                out->cap_settled = true;
            }
            return;
        }
        // The claim - everything below is noexcept. Relaxed: this critical
        // section IS the mutual exclusion, and every consumer reads under the
        // same `mu`; the acquire/release pair matters only for ~ClaimGuard's
        // lock-free clear (#2528 protocol, stated on the field).
        rec->projection_in_flight.store(true, std::memory_order_relaxed);
        if (want_progress) {
            // #2412: extraction is a swap, not a copy-out - allocation-free once
            // both buffers have grown to their steady-state payload size (see
            // the field comment on progress_slot).
            std::swap(rec->progress_slot, rec->projection_spare);
            rec->progress_pending = false;
            have_progress = true;
            if (out != nullptr && cap_expired) {
                // #2739: this IS the drain pass. Marked before the publish loop
                // (see the field comment for why a mid-pass throw must leave it
                // set), and the sink is poked NOW so the settle pass rides an
                // immediate wake instead of sleeping out a full pump tick when
                // the execution happens to go quiet at cap expiry. Sink-mu under
                // rec-mu is the sanctioned lock order (bind_post_sink does the
                // same); a failed poke just falls back to the next tick.
                rec->cap_progress_drained = true;
                poke_post_sink(rec->post_sink);
            }
        }
        if (want_terminal) {
            term = std::move(rec->terminal_slot);
            rec->terminal_slot.reset();  // explicit - never trust moved-from state (C4)
        }
    }

    // Settle-or-restore guard (B4/C4): whatever exits this scope, an unsettled
    // terminal payload goes BACK into the slot (terminal_accepted is sticky and
    // never cleared, so no listener can have refilled it) and the claim clears.
    //
    // ORDERING (load-bearing, governance cpp-expert): `guard` is declared HERE,
    // OUTSIDE the per-branch `lock_guard(rec->mu)` scopes below. Destructors run
    // in reverse order, so on any branch exit the inner lock_guard releases
    // rec->mu FIRST, then ~ClaimGuard re-locks it - never a same-thread double
    // lock. Do not move this declaration inside a locked scope.
    struct ClaimGuard {
        const std::shared_ptr<BridgeRecord>& rec;
        std::optional<MailboxEntry>& term;
        std::atomic<int>& lock_fault;
        bool terminal_settled = false;
        ~ClaimGuard() noexcept {
            // Contained: this destructor is implicitly noexcept and its FIRST act is a
            // mutex acquisition - the one throw site this file's own fault model treats
            // as real (it injects resource_deadlock_would_occur elsewhere). Unguarded,
            // a lock failure here is std::terminate on the projector thread, and
            // guaranteed so if the destructor runs during unwinding.
            try {
                if (lock_fault.load(std::memory_order_relaxed) > 0 &&
                    lock_fault.fetch_sub(1, std::memory_order_acq_rel) > 0) {
                    // inject_claim_lock_fault_for_test - the modelled mutex failure
                    throw std::system_error(
                        std::make_error_code(std::errc::resource_deadlock_would_occur));
                }
                std::lock_guard<std::mutex> rlk(rec->mu);
                if (term.has_value() && !terminal_settled) {
                    rec->terminal_slot = std::move(term);
                } else if (terminal_settled) {
                // The terminal was committed to the wire but the bookkeeping below
                // may not have run - it is the one thing between the commit and the
                // flag that can throw (two mutex acquisitions). Without this, such a
                // record has terminal_accepted set and terminal_projected clear, and
                // the pressure visitor's "latched but unprojected -> defer" arm then
                // defers it FOREVER - and while the pass now advances past a defer
                // (UP-5, #2489) rather than ending, a record that defers on every
                // sweep is never expired at all. Setting
                // it here is safe precisely because terminal_settled means the frame
                // is already published - it cannot cause a republish.
                    rec->terminal_projected.store(true, std::memory_order_release);
                }
                rec->projection_in_flight.store(false, std::memory_order_release);
                return;
            } catch (...) {  // NOLINT(bugprone-empty-catch) - degraded settle below
            }

            // DEGRADED SETTLE (#2528). `mu` is unavailable, so none of the above
            // ran. The claim must be released anyway - leaving it set wedges the
            // record out of all four consumers - and under the defer-ends-the-pass
            // behaviour that predated UP-5 (#2489), one such record stalled ring-only
            // pressure relief bridge-wide; it now costs that record alone, which is a
            // smaller blast radius and still a wedge. This is the ONE statement of what the skipped
            // bookkeeping means; the field comments point here rather than
            // restate it.
            //
            //  (a) progress-only batch (no terminal extracted): nothing was owed.
            //      Releasing the claim is a COMPLETE recovery.
            //  (b) terminal_settled: the frame is already committed to the ring;
            //      the only lost write is terminal_projected. Storing it here is
            //      honest - settled means published, so it cannot cause a
            //      republish - and it lets the pressure visitor claim with kNone
            //      instead of deferring on "latched but unprojected" forever.
            //  (c) extracted but NOT settled (the restore-and-retry path): the
            //      payload cannot go back into terminal_slot, and no listener will
            //      refill it, so the retry is gone. Mark it lost. The consumer
            //      contract - success-shaped fallback final, never kNone, never
            //      -32014 - is stated on terminal_payload_lost and honoured in the
            //      pressure visitor.
            //
            // Ordering is load-bearing: the bookkeeping stores are released BEFORE
            // the claim, so no consumer can observe a released claim over stale
            // bookkeeping. A consumer that races and reads the pre-store values
            // merely defers one sweep tick and re-reads - bounded, not wedged.
            if (terminal_settled) {
                rec->terminal_projected.store(true, std::memory_order_release);
            } else if (term.has_value()) {
                rec->terminal_payload_lost.store(true, std::memory_order_release);
            }
            rec->projection_degraded_delta.fetch_add(1, std::memory_order_relaxed);
            rec->projection_in_flight.store(false, std::memory_order_release);
        }
    } guard{rec, term, claim_lock_fault_};

    // Phase observed under the mutex ⇒ arm() completed ⇒ the immutable-after-arm
    // fields (progress_token, execution_id, fallback_final, result_base, stream,
    // jsonrpc_id) are safe to read lock-free from here.
    const bool get_only = ph == Phase::kArmedGetOnly;

    // Progress first - the final must be last on the wire. #2412: at most one
    // latched snapshot now (latest-wins in the listener), so there is nothing
    // left to iterate - this stays a `do { } while (false)` so every early
    // exit (`break`) reads the same as the old per-entry loop's `continue`/
    // `break`: "nothing more to do with this snapshot", not "stop the loop".
    if (have_progress && rec->progress_token.has_value()) {
        do {
            std::uint64_t responded = 0;
            std::uint64_t targeted = 0;
            try {
                const auto counts = parse_progress(rec->projection_spare.data);
                // UP-4: skip a frame with no meaningful denominator. An
                // execution-progress event published BEFORE set_agents_targeted
                // (an agent responding during dispatch) carries agents_targeted=0;
                // latched during kArming, it would otherwise drain into a
                // `total:0` progress notification, which a strict MCP client can
                // reject. `total` is monotone-meaningful only once targeted>0.
                if (counts.targeted == 0) {
                    break;
                }
                targeted = counts.targeted;
                // Defensive clamp: responded must never exceed targeted on the
                // wire (a transient count skew between the two COUNT(*) subqueries
                // must not surface as progress>total).
                responded = std::min(counts.responded, counts.targeted);
            } catch (...) {
                // C4: a malformed/unbuildable progress delta is fire-and-forget
                // by contract - drop it, keep going to terminal settlement.
                spdlog::warn("MCP bridge: progress frame build failed; dropping latched snapshot");
                break;
            }
            // H1 (governance adversarial review): both supported MCP revisions say
            // notifications/progress `progress` MUST INCREASE with each frame.
            // The bus publishes a fresh refresh_counts snapshot on EVERY agent
            // response (and the S4.5 fix makes duplicate snapshots more likely),
            // and snapshot-and-release publishing outside the tracker mutex can
            // even momentarily decrease the count - so forwarding every snapshot
            // verbatim would emit equal/decreasing progress. Suppress any
            // candidate not strictly greater than the last value already
            // committed to the wire for this record (the first frame is always
            // allowed, so an initial 0/N is fine as the starting point). Same
            // "a strict client can reject" rationale as the UP-4 total:0 skip.
            // #2412: this now ALSO catches a snapshot the listener superseded
            // before the projector ever saw it (see progress_suppressed_delta's
            // field comment) - both are "a candidate that never reached the
            // wire", so they share one counter.
            if (rec->progress_sent_any && responded <= rec->last_progress_sent) {
                rec->progress_suppressed_delta.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            std::string frame;
            try {
                const std::string msg = std::to_string(responded) + "/" +
                                        std::to_string(targeted) + " agents responded";
                frame = progress_notification(*rec->progress_token, responded, targeted,
                                              msg, rec->execution_id);
            } catch (...) {
                spdlog::warn("MCP bridge: progress frame build failed; dropping latched snapshot");
                break;
            }
            const std::uint64_t id = get_only
                                         ? rec->stream->publish("message", frame)  // live GET + ring
                                         : rec->stream->publish_ring_only("message", frame);  // replay
            // Advance the watermark ONLY after the frame actually committed
            // (id != 0); a pre-commit publish failure leaves the value un-sent so
            // a later equal-value snapshot can still carry it.
            if (id != 0) {
                rec->last_progress_sent = responded;
                rec->progress_sent_any = true;
                if (out != nullptr) {
                    // Only COMMITTED frames reach the live POST wire. A frame the
                    // ring rejected pre-commit has no replayable counterpart, so
                    // sending it live would leave a resuming client with a gap it
                    // can never fill - and the watermark above deliberately did
                    // not advance for it either.
                    try {
                        out->progress.push_back(PostBatch::PostFrame{std::move(frame), id});
                    } catch (...) {  // NOLINT(bugprone-empty-catch)
                        // The ring copy is durable; losing the live copy costs
                        // this client a frame it can still fetch by resume.
                    }
                }
            }
        } while (false);
    }

    if (!term.has_value()) {
        return;  // guard clears the claim
    }

    if (get_only) {
        // GET-only mode: NO final frame, NO pin - the plain JSON response
        // already answered this request. Settle and finish the lifecycle.
        guard.terminal_settled = true;
        std::lock_guard<std::mutex> rlk(rec->mu);
        rec->terminal_projected.store(true, std::memory_order_release);
        Phase expected = Phase::kArmedGetOnly;
        rec->phase.compare_exchange_strong(expected, Phase::kDone, std::memory_order_acq_rel);
        return;  // sweep reaps kDone
    }

    // kRingOnly: real final via the pinned ladder.
    std::string frame;
    bool built = false;
    try {
        if (projection_build_fault_.load(std::memory_order_acquire) > 0 &&
            projection_build_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
            throw std::bad_alloc{};  // inject_projection_build_fault_for_test
        }
        frame = build_real_final(*rec, term->data);
        built = true;
    } catch (...) {
        try {
            if (projection_fallback_fault_.load(std::memory_order_acquire) > 0 &&
                projection_fallback_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
                throw std::bad_alloc{};  // inject_projection_fallback_fault_for_test
            }
            frame = rec->fallback_final;  // prebuilt at subscribe/arm; copy can only OOM
            built = true;
        } catch (...) {  // NOLINT(bugprone-empty-catch)
        }
    }
    if (!built) {
        // Allocation death even for the prebuilt fallback. Restore (guard) and
        // let the NEXT wake retry - deliberately no self-wake here, so a
        // persistent OOM cannot hot-loop the projector (B4/A6c: sweep cadence
        // and any later bus/arm activity bound the retry latency instead).
        return;
    }
    if (out != nullptr) {
        // Copied BEFORE the ladder consumes it, and before anything is published:
        // if this allocation fails, the guard restores the terminal, the claim
        // clears and the pump retries - nothing has been committed or delivered
        // twice. Doing it after the publish would risk a ring commit the pump
        // never learns about.
        out->final_frame = PostBatch::PostFrame{frame, 0};
    }
    const auto fid = publish_terminal_ladder(rec, std::move(frame)).id;
    if (out != nullptr && out->final_frame.has_value()) {
        // #2785: the ring id exists only now, after the ladder committed the
        // frame - stamped in place rather than moving the copy below the
        // publish, which would re-open the restore-safety hole the comment
        // above closes. Stays 0 on a poisoned/pinless settle: that final has no
        // ring counterpart to resume from, so the wire honestly carries no id.
        // On the FALLBACK rung it is non-zero but names the FALLBACK frame the
        // ladder committed, while the bytes on the wire are the real final built
        // before it - the id identifies the RING entry, not the payload delivered.
        // Nothing is published after a final, so a resume cursor built from it is
        // still correct; it just does not round-trip to the same bytes.
        out->final_frame->event_id = fid;
    }
    // #2791 test seam: exactly the window select_displaceable_pin_locked's
    // projection_in_flight guard exists to mask - the frame is already
    // committed to the ring (a live pin), but rec->pinned_event_id below is not
    // yet stamped, so a scan right now cannot tell this pin from an orphan.
    // Neither bridge_mu_ nor rec->mu is held here. Zero-cost when unarmed (one
    // acquire atomic load).
    if (projection_stall_armed_for_test_.load(std::memory_order_acquire)) {
        std::unique_lock<std::mutex> stall_lk(projection_stall_mu_);
        projection_stall_armed_for_test_.store(false, std::memory_order_release);  // one-shot
        projection_stall_reached_for_test_ = true;
        projection_stall_cv_.notify_all();
        // The 10s backstop MUST exceed wait_projection_stall_reached_for_test's
        // 5s default: a backstop shorter than the harness's own wait would let an
        // armed stall self-release mid-test into a confusing partial state
        // instead of a clean REQUIRE failure on the harness side.
        const bool released = projection_stall_cv_.wait_for(
            stall_lk, std::chrono::seconds(10), [&] { return projection_stall_release_for_test_; });
        if (!released) {
            spdlog::warn("MCP bridge: #2791 test stall hit its 10s backstop without an "
                         "explicit release - likely a forgotten release_projection_stall_for_test() "
                         "call after a failed REQUIRE");
        }
    }
    // Settle IMMEDIATELY after the commit/poison decision (C4): no later
    // bookkeeping failure may restore + republish.
    guard.terminal_settled = true;
    {
        // Locks in hierarchy order and held ACROSS the flag clear and the ledger
        // decrement. This used to clear the flag under rec->mu, release, and only
        // then take bridge_mu_ - the same split that broke release_charge, with the
        // same consequence: a throw at the second acquisition leaves the record
        // reading "not held" while streamed_unpinned_[session] still counts it, so
        // that entry never reaches 0, never gets erased, and the session accumulates
        // forever. run_projector's per-record catch swallows it, so nothing retries.
        // Fixing release_charge alone would have fixed the instance and left the sink.
        // This WAS the second of three; arm()'s cancel-degrade path was the third and
        // is now routed through release_charge itself (#2529), so every clear of
        // streamed_charge_held in this file now happens under BOTH locks or under
        // bridge_mu_ with the ledger mutated in the same hold. Verified by sweep:
        // shutdown clears the whole ledger map wholesale, reserve's LedgerRollback
        // unwinds both while bridge_mu_ is still held, and abandon holds both. Keep it
        // that way - a new split here is not a local style choice, it is a permanent
        // per-session leak.
        std::lock_guard<std::mutex> lk(bridge_mu_);
        std::lock_guard<std::mutex> rlk(rec->mu);
        rec->terminal_projected.store(true, std::memory_order_release);
        if (fid != 0) {
            rec->final_published = true;
            rec->pinned_event_id = fid;
        }
        if (rec->streamed_charge_held) {
            // C3: settled - either the final is pinned (admission now counts it
            // via pinned_count()) or it settled pinless/poisoned (no pin will
            // ever come). Exactly-once: cleared and decremented together.
            rec->streamed_charge_held = false;
            decrement_streamed_locked(rec->session_id);
        }
    }
    // D4: the guard clears projection_in_flight only now, AFTER the deferred
    // charge decrement - sweep can never observe a half-settled record.
}

std::string McpStreamBridge::build_fallback_final(const nlohmann::json& jsonrpc_id,
                                                  const std::string& execution_id) {
    return success_response(
        jsonrpc_id, std::string(R"({"execution_id":)") + detail::json_quoted(execution_id) +
                        R"(,"status":"unknown","detail":)" +
                        detail::json_quoted("terminal counts unavailable - fetch by execution_id "
                                            "(get_execution_status / query_responses)") +
                        "}");
}

std::string McpStreamBridge::build_real_final(const BridgeRecord& rec,
                                              const std::string& terminal_data) {
    // B5: result_base is the serialized JSON-RPC *result object* exactly as
    // today's plain path built it; the additive fields are TOP-LEVEL result
    // keys, never folded into content[0].text.
    //
    // This is the one place the bridge uses nlohmann for OUTPUT (parse-merge-
    // reserialize), against the MCP surface's usual JObj/JArr-build convention
    // (governance security-LOW): a genuine three-way merge of an opaque
    // caller-shaped result object + two additive keys needs a real JSON DOM, and
    // dump() escapes correctly, so there is no injection risk. Reached ONLY on
    // the kRingOnly path, which is 3b-dead in production today.
    nlohmann::json base = rec.result_base.empty() ? nlohmann::json::object()
                                                  : nlohmann::json::parse(rec.result_base);
    if (!base.is_object()) {
        base = nlohmann::json::object();
    }
    const auto t = nlohmann::json::parse(terminal_data);
    base["status"] = t.value("status", "unknown");
    if (t.contains("agents_success")) {
        base["agents_success"] = t["agents_success"];
    }
    if (t.contains("agents_failure")) {
        base["agents_failure"] = t["agents_failure"];
    }
    if (!base.contains("execution_id")) {
        base["execution_id"] = rec.execution_id;  // the durable fetch handle, always present
    }
    return success_response(rec.jsonrpc_id, base.dump());
}

// A future throw source added here would std::terminate at this boundary rather than
// silently vanish - teardown_claimed is itself noexcept (so a throw there was ALREADY
// a terminate), and project_record's caller has no ladder-level catch at all (a throw
// would previously escape to run_projector's per-record catch and be swallowed
// silently, mis-settling that record). Binding this to McpStreamState's noexcept-ness
// makes that guarantee a compile-time fact instead of a comment nobody re-checks: if
// either call below becomes throwing again, this line fails to compile rather than
// quietly reopening kPublishThrew's dead-enum problem (#2531/#2523).
static_assert(noexcept(std::declval<McpStreamState&>().publish_final(
                  std::string_view{}, std::string_view{})) &&
             noexcept(std::declval<McpStreamState&>().poison_terminal()),
             "publish_terminal_ladder assumes both calls are noexcept");

McpStreamBridge::LadderResult
McpStreamBridge::publish_terminal_ladder(const std::shared_ptr<BridgeRecord>& rec,
                                         std::string&& frame) noexcept {
    auto fid = rec->stream->publish_final("message", frame);
    if (fid != 0) {
        return {fid, TerminalRung::kPrimary};
    }
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
    }
    // Retry once with the prebuilt per-record fallback (immutable member - the
    // string_view stays alive across the call).
    fid = rec->stream->publish_final("message", rec->fallback_final);
    if (fid != 0) {
        return {fid, TerminalRung::kFallback};
    }
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
    }
    // Double failure: sticky session poison - every future attach 410s and the
    // durable execution_id fetch is the recovery path (Decision 15(f) wiring of
    // the mcp_stream caller obligation).
    rec->stream->poison_terminal();
    return {0, TerminalRung::kPoisoned};
}

// ── Sweep ──────────────────────────────────────────────────────────────────

void McpStreamBridge::sweep() {
    std::vector<std::shared_ptr<BridgeRecord>> snap;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return;
        }
        snap.reserve(records_.size());
        for (const auto& [key, rec] : records_) {
            snap.push_back(rec);
        }
    }

    // Pass R (#2513): retry a teardown a PRIOR sweep could not complete. Runs
    // FIRST, ahead of every other pass, so a failure from THIS sweep's own
    // passes 0-3 is only retried on the NEXT tick - real spacing, never
    // same-tick re-entry. Distinct from `torn_down`, which every other pass
    // below treats as permanent exclusion: `torn_down` is set once and NEVER
    // cleared (shutdown()'s should_poison at #2517 depends on that), so retry
    // eligibility lives on its own `teardown_retry_claimable` flag instead of
    // reopening that gate.
    for (const auto& rec : snap) {
        // Lock-free prefilter: every claimed record settles into kDone or
        // kAborted (see the claim block passes 0-2 use below), so anything
        // else cannot be retry-eligible yet.
        const Phase ph = rec->phase.load(std::memory_order_acquire);
        if (ph != Phase::kDone && ph != Phase::kAborted) {
            continue;
        }
        TeardownFinal stored_decision = TeardownFinal::kNone;
        const char* retry_action = nullptr;
        {
            std::lock_guard<std::mutex> lk(bridge_mu_);
            if (shutdown_started_) {
                return;
            }
            auto it = records_.find(rec->key);
            if (it == records_.end() || it->second != rec) {
                continue;  // reclaimed by shutdown() or a prior retry already
            }
            std::lock_guard<std::mutex> rlk(rec->mu);
            if (!rec->torn_down || !rec->teardown_retry_claimable ||
                rec->projection_in_flight.load(std::memory_order_acquire)) {
                continue;
            }
            rec->teardown_retry_claimable = false;
            stored_decision = rec->teardown_decision;
            retry_action = "mcp.bridge.teardown_retry";
        }
        teardown_claimed(rec, stored_decision, retry_action);
    }

    // Passes 0-2: kDone reap, pin-ack, session death. Classification evidence
    // is gathered without bridge_mu_, but the CLAIM re-validates everything
    // under bridge_mu_ → record mu (B2/D4 - classification IS the claim).
    for (const auto& rec : snap) {
        const Phase ph = rec->phase.load(std::memory_order_acquire);
        bool claim = false;
        const char* action = nullptr;
        if (ph == Phase::kDone) {
            claim = true;
            action = "mcp.bridge.done_reap";
        } else if (ph == Phase::kArming) {
            // A record still kArming long past its synchronous handler's return
            // is orphaned: the double-bad_alloc corner (arm's fallback build
            // threw, then abandon's make_key ALSO threw under OOM) leaves it
            // stranded, and sweep otherwise never reclaims kArming. Reap it to
            // stop a monotonic global-slot leak (governance cpp-safety SHOULD).
            // `created` is write-once (immutable after reserve, before the record
            // is shared), so a lock-free read is safe; a concurrent arm() that
            // moves the phase off kArming makes the claim re-check below fail and
            // defer to the live handler.
            if (now() - rec->created > cfg_.arming_reap_after) {
                claim = true;
                action = "mcp.bridge.arming_reaped";
            }
        } else if (ph == Phase::kStreaming) {
            // BACKSTOP for the streamed-POST leak. Every pass below claims only
            // kDone / kArming / kArmedGetOnly / kRingOnly, so a record stranded
            // in kStreaming - its releaser swallowed the close, or the process
            // lost the connection without running one - is invisible to ALL of
            // them, INCLUDING session death, and leaks for the life of the
            // process. The primary defence is that the releaser's close path
            // allocates nothing (on_post_closed_keyed); this is the second one.
            //
            // It PARKS, never reaps. A reap would unsubscribe, unpin and erase,
            // destroying resume state and possibly a real latched terminal that
            // the client can still legitimately collect. It also deliberately
            // does NOT set `claim` and go through the block below: that block
            // sets torn_down, which means "permanently excluded from reclaim",
            // so a merely-parked record would never be swept again. A transition
            // is not a teardown.
            //
            // Routed through the SAME transition the releaser uses rather than a
            // second copy of it - including its final_written branch, so a record
            // whose final reached the wire still settles kDone rather than
            // parking for a resume nobody needs.
            const bool session_alive =
                sessions_ != nullptr && sessions_->exists(rec->session_id, rec->principal);
            // `created` and `key` are write-once (immutable after reserve, before
            // the record is shared), so both are safe to read lock-free here.
            const bool stale = now() - rec->created > cfg_.streaming_park_after;
            if ((!session_alive || stale) && on_post_closed_keyed(rec->key) && metrics_ != nullptr) {
                obs_guard([&] { metrics_->counter(kMetricStreamingBackstop).increment(); });
            }
        } else if (ph == Phase::kArmedGetOnly || ph == Phase::kRingOnly) {
            // Registry leaf, no locks held. Non-touching: a parked record must
            // never extend session life.
            const bool session_alive =
                sessions_ != nullptr && sessions_->exists(rec->session_id, rec->principal);
            if (!session_alive) {
                claim = true;
                action = "mcp.bridge.session_dead";
            } else if (ph == Phase::kRingOnly) {
                std::lock_guard<std::mutex> rlk(rec->mu);
                // H4: const pin poll - a released pin is the reap trigger; no
                // stream→bridge callback edge. It is NOT proof the client consumed
                // anything: since #2740 an admission reclaim releases pins too, so
                // a record reaped here may never have been resumed. The action
                // name (`mcp.bridge.pin_acked`) predates that and is kept for
                // taxonomy stability - the preceding
                // `mcp.bridge.pin_displaced_for_admission` row is what distinguishes
                // the two causes for anyone reading the trail.
                if (rec->final_published && rec->pinned_event_id != 0 &&
                    !rec->projection_in_flight.load(std::memory_order_acquire) &&
                    !rec->stream->is_pinned(rec->pinned_event_id)) {
                    claim = true;
                    action = "mcp.bridge.pin_acked";
                }
            }
        }
        if (!claim) {
            continue;
        }
        bool claimed = false;
        {
            std::lock_guard<std::mutex> lk(bridge_mu_);
            if (shutdown_started_) {
                return;
            }
            auto it = records_.find(rec->key);
            if (it == records_.end() || it->second != rec) {
                continue;  // map identity: somebody else already tore it down
            }
            std::lock_guard<std::mutex> rlk(rec->mu);
            const Phase cur = rec->phase.load(std::memory_order_acquire);
            if (rec->projection_in_flight.load(std::memory_order_acquire) || rec->torn_down) {
                continue;  // B2: never claim mid-projection; teardown is exactly-once
            }
            if (cur != ph && cur != Phase::kDone) {
                // Moved on since the evidence was gathered (a kDone settle in
                // between is still reapable; a kArming record a concurrent arm()
                // just flipped falls here and is skipped - the live handler owns
                // it); anything else waits for the next sweep with fresh evidence.
                continue;
            }
            // A reaped kArming record ends in kAborted (pre-dispatch failure
            // class); every other claim ends in kDone. teardown_claimed does not
            // inspect the phase value - only the torn_down/erase bookkeeping.
            rec->phase.store(ph == Phase::kArming ? Phase::kAborted : Phase::kDone,
                             std::memory_order_release);
            rec->torn_down = true;
            claimed = true;
        }
        if (claimed) {
            teardown_claimed(rec, TeardownFinal::kNone, action);
        }
    }

    // Pass 3: ring-only pressure (E1 two-stage, multi-victim, oldest-first).
    //
    // UP-5 (#2489): each victim is visited AT MOST ONCE per sweep, so an oldest
    // victim caught perpetually mid-projection cannot deny relief to every newer
    // victim behind it. Originally enforced by a `parked_seq` monotonic floor
    // re-checked on every rescan; a candidate list built ONCE and iterated ONCE
    // (below) subsumes that property structurally - there is no rescan to
    // re-check it against.
    //
    // Doomgoose (PR #2781 review) + Fable plan review: the previous shape
    // rescanned the FULL `records_` map, taking every record's own lock, on
    // EVERY victim visited - O(records x victims) mutex traffic (confirmed
    // introduced by a4809554, not present on origin/dev), ungated by
    // --mcp-enable-streamed-post since this pass already serves the pre-existing
    // GET-only bridge. Fixed by scanning ONCE to build a parked_seq-sorted
    // candidate list, then iterating it with per-visit re-validation instead of
    // per-visit re-scanning.
    // ONE scan: ring_only count, mark count, and the full candidate list, sorted
    // oldest-first. Every kRingOnly record is a candidate - no floor to apply,
    // since each is visited at most once by construction below.
    std::size_t ring_only = 0;
    std::size_t marked = 0;
    std::vector<std::pair<std::uint64_t, std::shared_ptr<BridgeRecord>>> candidates;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return;
        }
        candidates.reserve(records_.size());
        for (const auto& [key, rec] : records_) {
            if (rec->phase.load(std::memory_order_acquire) != Phase::kRingOnly) {
                continue;
            }
            ++ring_only;
            std::lock_guard<std::mutex> rlk(rec->mu);
            if (rec->pressure_requested) {
                ++marked;
            }
            candidates.emplace_back(rec->parked_seq, rec);
        }
    }
    std::sort(candidates.begin(), candidates.end(),
             [](const auto& a, const auto& b) { return a.first < b.first; });

    // VICTIM BUDGET, captured at entry (#2489 review), unchanged: the pass may
    // visit at most the number of parked records it observed on its FIRST count.
    // A record that parks mid-pass is not in `candidates` and is not visited this
    // pass - relief that arrives late is the NEXT tick's job, which is the same
    // answer the cap itself gives, and is now true by construction rather than by
    // a floor comparison.
    std::size_t visit_budget = ring_only;
    // PASS-LOCAL LIVE COUNT (Doomgoose + Fable plan review): decremented only for
    // teardowns THIS PASS commits, so the down-to-cap early exit - visit exactly
    // enough victims to bring the population back under cap, never more - stays
    // O(1) per visit instead of the O(records) rescan it replaces. The ONLY way
    // this can diverge from a fresh recount is a teardown performed by something
    // OTHER than this pass in the same window (a concurrent sweep, which does not
    // happen in production - one maintenance thread - or shutdown(), which this
    // loop already checks for on every lock re-entry and returns on). That
    // residue is bounded by `visit_budget` either way.
    std::size_t live = ring_only;

    std::size_t idx = 0;
    while (idx < candidates.size() && visit_budget > 0 && live > cfg_.ring_only_pressure_cap) {
        auto oldest = candidates[idx].second;
        ++idx;
        --visit_budget;
        // Re-validate map identity before the visit (the candidate was collected
        // in the entry scan; a concurrent teardown may have moved it), and mark it
        // in the SAME hold - stage 1. The mark tells the projector to start no NEW
        // progress batch (project_record gates on pressure_requested); ALL
        // disposition logic lives in the atomic visit below, one source of truth
        // (CORE-2). Marking under bridge_mu_ -> mu rather than mu alone is what
        // makes it mutually exclusive with the clearing walk below, and it also
        // stops us marking a record that has already been torn down.
        {
            std::lock_guard<std::mutex> lk(bridge_mu_);
            if (shutdown_started_) {
                return;
            }
            auto it = records_.find(oldest->key);
            if (it == records_.end() || it->second != oldest) {
                continue;  // torn down by something else - move to the next candidate
            }
            std::lock_guard<std::mutex> rlk(oldest->mu);
            oldest->pressure_requested = true;
        }
        // Stage 2: the atomic visit that closes #2409 (was the KNOWN GAP here).
        // Under a SINGLE hold of the bus channel mutex, `f` computes the
        // disposition from record state (the bus verdict arbitrates ONLY a record
        // with no secured terminal) and claims kDone via a torn_down CAS under
        // record mu; the bus erases the listener ONLY on that committed claim.
        // bridge_mu_ is NOT held across the visit (it takes Channel::mu → record
        // mu, a valid suffix of the declared hierarchy; `f` must not take
        // bridge_mu_ or call a bus method). Every DEFER keeps the listener, so a
        // deferred terminal channel can never be GC'd out from under the record.
        bool claimed_by_me = false;
        TeardownFinal decision = TeardownFinal::kNone;
        ExecutionEventBus::VisitStatus status = ExecutionEventBus::VisitStatus::kAbsentChannel;
        if (bus_ != nullptr) {
            // NOT noexcept ON PURPOSE: the ONE uncontained throw here is the
            // record-lock acquisition below (before any mutation). Letting it
            // propagate lets unsubscribe_and_visit_terminal's try/catch convert it
            // to kInternalError (fail-closed), which a noexcept lambda would instead
            // turn into std::terminate before that catch can see it. Everything
            // after the lock is noexcept stores + an internally-contained payload
            // copy, so a propagated throw means "record untouched" == "f did not
            // run" - the kInternalError invariant holds.
            auto f = [&](ExecutionEventBus::TerminalVisit verdict,
                         const ExecutionEvent* ev) -> bool {
                std::lock_guard<std::mutex> rlk(oldest->mu);
                const Phase ph = oldest->phase.load(std::memory_order_acquire);
                if (oldest->torn_down || ph != Phase::kRingOnly) {
                    return false;  // stale: a competing claimant already owns it
                }
                // Record-side state dominates the bus verdict (CORE-2).
                if (oldest->terminal_accepted &&
                    oldest->terminal_projected.load(std::memory_order_acquire)) {
                    // Settled real final already pinned: claim, publish nothing.
                    oldest->phase.store(Phase::kDone, std::memory_order_release);
                    oldest->torn_down = true;
                    claimed_by_me = true;
                    decision = TeardownFinal::kNone;
                    return true;
                }
                if (oldest->terminal_accepted &&
                    !oldest->terminal_projected.load(std::memory_order_acquire)) {
                    if (oldest->terminal_payload_lost.load(std::memory_order_acquire)) {
                        // #2528 degraded settle: a real terminal existed, but its
                        // payload was extracted and then lost when ~ClaimGuard could
                        // not retake mu. terminal_slot is empty and sticky
                        // terminal_accepted stops any listener refill, so NO projector
                        // retry exists and deferring here would defer forever. Same
                        // disposition as kTerminalKnownLost: the success-shaped
                        // fallback, never -32014 (a terminal did happen) and never
                        // kNone (which would answer the client nothing).
                        oldest->phase.store(Phase::kDone, std::memory_order_release);
                        oldest->torn_down = true;
                        claimed_by_me = true;
                        decision = TeardownFinal::kFallbackFinal;
                        return true;
                    }
                    return false;  // latched, not pinned: defer; projector settles
                }
                if (oldest->projection_in_flight.load(std::memory_order_acquire)) {
                    return false;  // a progress projection is mid-flight: defer
                }
                // No secured terminal: the bus verdict arbitrates. Secure any
                // terminal record-side BEFORE the (claim-driven) erase.
                switch (verdict) {
                    case ExecutionEventBus::TerminalVisit::kTerminalBuffered:
                        // `ev` is the FIRST terminal-flagged event, which in the
                        // refresh_counts split is a terminal-flagged execution-progress
                        // (NOT execution-completed). build_real_final consumes it
                        // correctly ONLY because refresh_counts stamps status +
                        // agents_success/failure onto that terminal progress payload
                        // (execution_tracker.cpp ~:477-482) - a load-bearing coupling
                        // (#2409 cons-S5/UP-3): if that stamping is ever removed, the
                        // final would silently degrade to status:"unknown".
                        if (ev != nullptr) {
                            try {
                                if (visit_copy_fault_.load(std::memory_order_relaxed) > 0 &&
                                    visit_copy_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
                                    throw std::bad_alloc{};  // inject_visit_copy_fault_for_test
                                }
                                // Construct fully OUTSIDE the slot, then commit with
                                // a noexcept move - a copy OOM leaves the slot and
                                // terminal_accepted untouched (mirror the listener).
                                MailboxEntry tmp{ev->id, ev->data};
                                oldest->terminal_slot = std::move(tmp);
                                oldest->terminal_accepted = true;
                            } catch (...) {  // NOLINT(bugprone-empty-catch) - deliberate
                                // Copy OOM: nothing secured. Defer, keep the
                                // listener (a retry latches next sweep).
                            }
                        }
                        return false;  // defer; the projector publishes the real final
                    case ExecutionEventBus::TerminalVisit::kTerminalKnownLost:
                        // Terminal existed but its payload aged out of the bus buffer:
                        // claim + publish the success-shaped fallback, never -32014.
                        oldest->phase.store(Phase::kDone, std::memory_order_release);
                        oldest->torn_down = true;
                        claimed_by_me = true;
                        decision = TeardownFinal::kFallbackFinal;
                        return true;
                    case ExecutionEventBus::TerminalVisit::kNeverTerminal:
                    default:
                        oldest->phase.store(Phase::kDone, std::memory_order_release);
                        oldest->torn_down = true;
                        claimed_by_me = true;
                        decision = TeardownFinal::kSynthesizeUnavailable;
                        return true;
                }
            };
            status = bus_->unsubscribe_and_visit_terminal(oldest->execution_id,
                                                          oldest->sub_id, f);
        }
        if (claimed_by_me) {
            // f won the claim under Channel::mu (FA-1: the captured flag, NOT
            // record-state inference - a concurrent sweep's winner leaves the record
            // kDone-in-map until its teardown erases it). Re-acquire the shutdown
            // gate the pre-visit block released: the claim commits WITHOUT bridge_mu_
            // (inside f, under Channel::mu), so shutdown() can have started meanwhile.
            // If it has, DO NOT publish/audit against a torn-down record - shutdown()'s
            // own walk covers every record (all phases), releasing the charge and
            // unsubscribing, so the claimed record is still cleaned up.
            {
                std::lock_guard<std::mutex> lk(bridge_mu_);
                if (shutdown_started_) {
                    return;
                }
                auto it = records_.find(oldest->key);
                if (it == records_.end() || it->second != oldest) {
                    continue;  // shutdown/another sweep already removed it
                }
            }
            // sre-N1: counted BEFORE the teardown, and unconditionally. The
            // disposition is already decided and its terminal is published by
            // teardown step 0, so a later step failing must not lose the reading -
            // that failure has its own family (teardown_incomplete).
            count_forced_expire(decision);
            teardown_claimed(oldest, decision, "mcp.bridge.forced_expire");
            --live;  // a teardown THIS PASS committed - keeps the O(1) exit check honest
            continue;
        }
        if (status == ExecutionEventBus::VisitStatus::kAbsentChannel ||
            status == ExecutionEventBus::VisitStatus::kInternalError) {
            // f did NOT run (no channel / a lock threw). CF-2: claim from record
            // state ONLY when unambiguous (settled real final, or a secured
            // terminal-known-lost with no projection in flight); else defer +
            // retry. NEVER infer kNeverTerminal from a missing channel (#2409).
            // Near-unreachable under erase-only-on-claim (a deferred record keeps
            // its listener, so its channel never GCs), but kept for robustness.
            bool guard_claim = false;
            TeardownFinal guard_decision = TeardownFinal::kNone;
            {
                std::lock_guard<std::mutex> lk(bridge_mu_);
                if (shutdown_started_) {
                    return;
                }
                auto it = records_.find(oldest->key);
                if (it == records_.end() || it->second != oldest) {
                    continue;
                }
                std::lock_guard<std::mutex> rlk(oldest->mu);
                // Defensive only (near-unreachable: a non-claimed kRingOnly record
                // keeps its listener, so its channel is never GC'd -> f runs, no
                // kAbsentChannel). Claim ONLY an unambiguous settled real final; a
                // record that never secured a terminal defers (NEVER synthesize
                // -32014 from an absent channel - that would re-open #2409).
                // NOTE (#2528): a terminal_payload_lost record is NOT claimed here.
                // Its honest disposition is kFallbackFinal, and this block is
                // deliberately kNone-only - every publishing disposition must stay
                // reachable solely from the visitor above, where the bus has already
                // removed the listener. Such a record defers on this near-unreachable
                // path and is reclaimed by shutdown(); widening the guard block would
                // trade a bounded defer for a publish over a live listener.
                if (!oldest->torn_down &&
                    oldest->phase.load(std::memory_order_acquire) == Phase::kRingOnly &&
                    oldest->terminal_accepted &&
                    oldest->terminal_projected.load(std::memory_order_acquire)) {
                    guard_claim = true;
                    guard_decision = TeardownFinal::kNone;
                    oldest->phase.store(Phase::kDone, std::memory_order_release);
                    oldest->torn_down = true;
                }
            }
            if (guard_claim) {
                count_forced_expire(guard_decision);  // sre-N1; kNone-only by construction
                teardown_claimed(oldest, guard_decision, "mcp.bridge.forced_expire");
                --live;  // a teardown THIS PASS committed
                continue;
            }
        }
        // Deferred (not claimed, or a bus-less build). ADVANCE past this victim
        // rather than ending the pass (UP-5, #2489): iterating the pre-sorted list
        // once, never revisiting an entry, is what now carries FA-4's
        // no-tight-re-visit property, so a defer costs this victim its turn this
        // sweep instead of costing every newer victim theirs. #2411: mark THIS
        // victim dirty - a defer means work was left for it (a secured terminal
        // to settle), and mark_dirty's own dedupe (see its lost-wakeup proof)
        // means marking every deferral costs nothing extra over the old single
        // end-of-pass wake.
        mark_dirty(*core_, oldest->key);
    }

    // FRESH final scan (Doomgoose + Fable plan review): both the mark-clearing
    // gate and the budget-exhausted telemetry need the CURRENT picture, not the
    // entry-scan snapshot the visiting loop above used - a record parking in the
    // gap between entry and now must not be undercounted by either check, exactly
    // the #2489 reasoning that already governed the single-scan version of this
    // gate. This is the only rescan in the whole pass, and it runs once
    // regardless of how many victims were visited above.
    if (marked > 0 || ring_only > cfg_.ring_only_pressure_cap) {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return;
        }
        std::size_t still_parked = 0;
        std::size_t still_marked = 0;
        for (const auto& [key, rec] : records_) {
            if (rec->phase.load(std::memory_order_acquire) != Phase::kRingOnly) {
                continue;
            }
            ++still_parked;
            std::lock_guard<std::mutex> rlk(rec->mu);
            if (rec->pressure_requested) {
                ++still_marked;
            }
        }
        // UP-4 (#2489): `pressure_requested` is a request to QUIESCE a victim for a
        // reap that is coming, and project_record gates `want_progress` on it - so
        // a mark that outlives the pressure freezes progress on a record nothing
        // is reaping any more, for the rest of what may be a long-running
        // execution (the terminal still settles; `want_terminal` is ungated).
        // Clear every mark HERE, where the escape hatch actually disengages, and
        // ONLY here, gated on the FRESH still_parked so clearing never strips a
        // live quiesce this same pass just placed.
        if (still_marked > 0 && still_parked <= cfg_.ring_only_pressure_cap) {
            for (const auto& [key, rec] : records_) {
                if (rec->phase.load(std::memory_order_acquire) != Phase::kRingOnly) {
                    continue;
                }
                bool was_marked = false;
                {
                    std::lock_guard<std::mutex> rlk(rec->mu);
                    was_marked = rec->pressure_requested;
                    rec->pressure_requested = false;
                }
                if (was_marked) {
                    // #2411: only a record that WAS quiesced needs re-waking -
                    // progress may have been frozen mid-execution on it, and
                    // that freeze just lifted. An already-unmarked record has
                    // nothing new for this walk to have unfrozen.
                    mark_dirty(*core_, key);
                }
            }
        }
        if (still_parked > cfg_.ring_only_pressure_cap) {
            // NOT a silent cap: the hatch disengaged with the cap still exceeded
            // (whether from exhausting visit_budget, the candidate list, or
            // finding live already satisfied while a concurrent arrival kept the
            // fresh count high), so say so. Sustained movement here means records
            // are parking at least as fast as they are being expired.
            count_pressure_budget_exhausted();
        }
    }
}

void McpStreamBridge::teardown_claimed(std::shared_ptr<BridgeRecord> rec, TeardownFinal decision,
                                       const char* audit_action) noexcept {
    // Claimant owns the record: the phase (kDone / kAborted) AND `torn_down` were
    // both stored under record mu before we got here. `torn_down` PERMANENTLY
    // excludes this record from every later sweep claim - it is never cleared,
    // never re-arbitrated. What CAN retry (#2513) is a bail this function itself
    // leaves behind: a bail site marks the record `teardown_retry_claimable`
    // (bounded by Config::teardown_retry_max), and a LATER sweep's retry pass
    // claims that flag and calls this function again, on the SAME `torn_down`
    // record. Declared noexcept so nothing about that re-entry can escape either.
    //
    // `rec` is taken BY VALUE, not by const&. The borrow below is a reference INTO
    // the record, and the erase step drops one strong reference to it - so the
    // keep-alive must be structural here, not an unenforced obligation on all three
    // call sites to hold their own copy.
    //
    // #2487 SCOPE, STATED HONESTLY: this narrows the crash surface, it does not
    // close it. The two allocations that made this function abort the process (an
    // execution-id copy and a const char* -> std::string audit temporary) are GONE -
    // that is the actual fix. The per-step containment below is defence in depth
    // against a fault that is currently near-unreachable: unsubscribe, the charge
    // decrement and the map erase are find/erase and node operations that allocate
    // nothing, so only a std::mutex::lock failure can reach these branches. It earns
    // its place because the day anyone adds an allocating call (say
    // gc_terminal_channels(), which publish() already does) to
    // ExecutionEventBus::unsubscribe, that branch becomes live under exactly the
    // memory pressure it was written for. The maintenance thread as a whole is NOT
    // exception-safe: sibling blocks on that thread remain unguarded.
    //
    // Ownership here is THREE things, not two: the records_ entry, the streamed
    // charge, and the BUS SUBSCRIPTION. Erasing the map entry while the subscription
    // survives is the worst available outcome - make_listener captures a shared_ptr
    // to this record, so erasing destroys nothing; the listener stays installed and
    // keeps waking a record nothing can find, shutdown() can no longer reach it (it
    // walks records_), and channel GC refuses to reap the channel because it
    // requires listeners.empty().
    //
    // `execution_id` is immutable after subscribe(), which ENFORCES that with a
    // state gate, so bind it - never copy.
    const std::string& exec_id = rec->execution_id;

    // Contained step runner. Declaring the wrapper noexcept is safe (and NOT the
    // "noexcept defeats an outer catch" trap) because the catch that contains the
    // work lives INSIDE it.
    const auto contained = [](auto&& f) noexcept -> bool {
        try {
            f();
            return true;
        } catch (...) {
            return false;
        }
    };
    // Last-resort evidence. The metric and the audit row both route through guards
    // that swallow, and under the OOM this function exists for BOTH can fail - which
    // would leave a stranded record with no evidence of any kind. This log line is
    // the floor; it is itself contained because formatting allocates.
    const auto log_incomplete = [&](const char* stage, bool retry_eligible) noexcept {
        (void)contained([&] {
            // "reason=" matches the metric label so an operator can correlate the log
            // line with yuzu_mcp_bridge_teardown_incomplete_total{reason} directly.
            // It said "stage=" while the label was renamed, which meant grepping the
            // journal for the label value found nothing.
            // #2513: "until shutdown" is only true once the retry budget is spent -
            // on any earlier attempt the record is retry-eligible and typically
            // resolves within a few sweep ticks, which is exactly the runbook's own
            // "wait for the next few sweep ticks before treating this as an incident"
            // guidance. This is the floor evidence under severe pressure (both the
            // metric and the audit row can also be lost, per the comment above), so
            // it must not overclaim permanence on the common, self-healing path.
            spdlog::error("MCP bridge teardown incomplete [reason={} execution_id={}]: "
                          "{}",
                          stage, exec_id,
                          retry_eligible ? "resource retained (retry-eligible on a later sweep)"
                                         : "resource retained until shutdown");
        });
    };

    // #2513: attempt bookkeeping + Step 1 idempotence check, one lock hold. First
    // entry: attempts 0→1, terminal_already_handled false (Step 1 has never run).
    // A retry entry: attempts N→N+1; terminal_already_handled true iff a PRIOR
    // attempt's Step 1 already resolved the terminal (published, poisoned, or
    // decision was kNone to begin with) - in which case `stored_rung` is that
    // attempt's result, replayed below instead of re-publishing.
    bool terminal_already_handled = false;
    TerminalRung stored_rung = TerminalRung::kNotAttempted;
    const bool entry_ok = contained([&] {
        if (record_entry_lock_fault_.load(std::memory_order_relaxed) > 0 &&
            record_entry_lock_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
            // inject_record_entry_lock_fault_for_test - the modelled mutex
            // failure, thrown before the lock so it models the acquisition
            // itself failing, same shape as the claim/charge seams.
            throw std::system_error(std::make_error_code(std::errc::resource_deadlock_would_occur),
                                    "injected teardown entry lock failure");
        }
        std::lock_guard<std::mutex> rlk(rec->mu);
        ++rec->teardown_attempts;
        terminal_already_handled = rec->teardown_terminal_handled;
        stored_rung = rec->teardown_last_rung;
    });
    if (!entry_ok) {
        // rec->mu itself failed to lock - every later site in this call locks the
        // SAME mutex, so nothing past this point can be trusted to succeed either.
        // Bail without touching bookkeeping: attempts is NOT incremented (the
        // lock_guard construction throws before entering its own body, so none of
        // the three statements above ran), so this call never happened as far as
        // the record's own state is concerned. The record stays torn_down,
        // unresolved, and un-reclaimed by any later retry pass (its
        // teardown_retry_claimable, if this was itself a retry, is already false -
        // Pass R cleared it before calling in) - degraded until shutdown() reaps
        // it, but the alternative is std::terminate() on the maintenance thread.
        // Reaches the IDENTICAL permanent-retention end state as an exhausted
        // retry budget (retained until shutdown, no further attempts) even on a
        // FIRST attempt, so it counts the same way - YuzuMcpBridgeTeardownRetryExhausted
        // is documented as THE complete signal for that state; a silent bypass
        // here would be an undercount review found and confirmed empirically.
        count_teardown_retry(TeardownRetryOutcome::kExhausted);
        (void)contained([&] {
            spdlog::error("MCP bridge teardown entry lock failed [execution_id={}]: "
                          "resource retained, this attempt did not run",
                          exec_id);
        });
        return;
    }

    // ── Step 1: PUBLISH the decided disposition ────────────────────────────────
    // BEFORE the unsubscribe, deliberately. A later step failing must never lose a
    // terminal the pressure visitor already decided on: the previous order returned
    // early on an unsubscribe failure and silently dropped the frame, leaving the
    // client with no terminal, no poison and no retrier. Safe to reorder because the
    // only dispositions that publish anything are reached from the pressure pass,
    // where unsubscribe_and_visit_terminal has ALREADY removed the listener - so for
    // every publishing case there is no live listener to race, and for kNone there
    // is nothing to publish. SKIPPED on a retry whose terminal a prior attempt
    // already resolved (`terminal_already_handled`) - never re-publish, re-poison,
    // or re-synthesize -32014 for the same record.
    TerminalRung rung = terminal_already_handled ? stored_rung : TerminalRung::kNotAttempted;
    if (!terminal_already_handled) {
        switch (decision) {
            case TeardownFinal::kSynthesizeUnavailable: {
                // Pressure victim that genuinely NEVER saw a terminal (verified at claim
                // under Channel::mu): pin a machine-readable terminal-unavailable so a
                // later resume still finds truth in the ring.
                std::string frame;
                bool built = false;
                try {
                    if (terminal_build_fault_.load(std::memory_order_acquire) > 0 &&
                        terminal_build_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
                        throw std::bad_alloc{};  // inject_terminal_build_fault_for_test
                    }
                    // #3344: retry_after_ms stays null — the ring dropped this
                    // terminal, so retrying THIS resume can never succeed
                    // (there is nothing left here to find). The honest
                    // recovery path is the redirect below to get_execution_status
                    // / query_responses, both of which now carry their own
                    // success-shaped retry_after_ms hint while not-ready.
                    std::string data =
                        std::string(R"({"execution_id":)") + detail::json_quoted(exec_id) +
                        R"(,"correlation_id":)" +
                        detail::json_quoted(yuzu::server::detail::make_correlation_id()) +
                        R"(,"retry_after_ms":null,"remediation":)" +
                        detail::json_quoted("result no longer buffered - fetch it by "
                                            "execution_id (get_execution_status / "
                                            "query_responses)") +
                        "}";
                    frame = error_response(rec->jsonrpc_id, kMcpTerminalUnavailable,
                                           "streamed result forced-expired under memory pressure",
                                           data);
                    built = true;
                } catch (...) {  // NOLINT(bugprone-empty-catch)
                }
                if (built) {
                    // The ladder itself is noexcept (#2531/#2523) - nothing left to catch.
                    rung = publish_terminal_ladder(rec, std::move(frame)).rung;
                } else {
                    // rung stays kNotAttempted: the frame was never built, so the ladder
                    // was never called.
                    if (metrics_ != nullptr) {
                        obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
                    }
                }
                break;
            }
            case TeardownFinal::kFallbackFinal: {
                // Terminal existed but its payload aged out of the bus buffer: publish
                // the prebuilt SUCCESS-shaped final, NEVER -32014.
                std::string frame;
                bool built = false;
                try {
                    if (terminal_build_fault_.load(std::memory_order_acquire) > 0 &&
                        terminal_build_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
                        throw std::bad_alloc{};  // models the fallback_final copy failing
                    }
                    frame = rec->fallback_final;
                    built = true;
                } catch (...) {  // NOLINT(bugprone-empty-catch)
                }
                if (built) {
                    rung = publish_terminal_ladder(rec, std::move(frame)).rung;
                } else {
                    if (metrics_ != nullptr) {
                        obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
                    }
                }
                break;
            }
            case TeardownFinal::kNone:
                break;  // real final already pinned, or nothing to publish
        }
    }  // !terminal_already_handled

    // Record whether Step 1 resolved this record's terminal disposition, so
    // shutdown()'s walk can tell "nothing was ever owed / the ladder ran" apart
    // from "the frame build failed and nothing happened" - the latter is the one
    // state shutdown must poison rather than silently abandon (#2517). Set here,
    // under the record lock, regardless of what Steps 2-4 below do next. Also
    // persists `decision`/`rung` (#2513) so a LATER retry whose terminal is
    // already handled can replay this exact disposition without re-running Step
    // 1 - skipped when terminal_already_handled, since nothing changed this time.
    if (!terminal_already_handled) {
        const bool persist_ok = contained([&] {
            std::lock_guard<std::mutex> rlk(rec->mu);
            rec->teardown_terminal_handled =
                decision == TeardownFinal::kNone || rung != TerminalRung::kNotAttempted;
            rec->teardown_decision = decision;
            rec->teardown_last_rung = rung;
        });
        // On failure the write above never happened, so rec->teardown_terminal_handled
        // stays at its prior value - false, since terminal_already_handled was false
        // to reach this branch. That is exactly the safe fallback: a later retry
        // reads it as unhandled and re-runs Step 1 rather than wrongly skipping a
        // terminal this attempt may or may not have actually delivered. No corrective
        // action needed beyond containment; the rest of THIS call still uses the
        // local `decision`/`rung` below, not the (possibly unpersisted) fields.
        //
        // Gate 8 review (post-merge): this is a deliberate AT-LEAST-ONCE choice,
        // not an accident. If Step 1 above genuinely published/poisoned AND this
        // persist then fails AND a later step (2-4) in this SAME attempt ALSO
        // fails (making the record retry-eligible), a later retry's Step 1 will
        // re-run and can re-publish a second terminal frame or re-poison an
        // already-served session. publish_final has no dedup guard, so this is
        // real, not theoretical - but it needs TWO independent instances of the
        // same near-unreachable mutex fault to land in one attempt, and the
        // consequence (a stale duplicate frame a resuming client may see, or a
        // spurious extra poison of a session that already has its real answer)
        // matches the SAME "spurious poison is harmless, idempotent, remediated
        // by the durable execution_id fetch" tradeoff #2517 already accepts
        // elsewhere in this file. The alternative - bailing this whole attempt
        // the way the entry lock above does - would make the FAR more common
        // single-fault case (persist fails, nothing else does) strictly worse:
        // it would give up on steps 2-4 even when they would have succeeded,
        // for no benefit against a risk that requires a second fault to matter.

        if (!persist_ok) {
            (void)contained([&] {
                spdlog::error("MCP bridge teardown terminal-state persist failed "
                              "[execution_id={}]: a later retry will re-attempt Step 1",
                              exec_id);
            });
        }
    }

    // Derived ONCE and passed to every audit site below, bail or not. See
    // disposition_phrase(); nothing here re-derives the terminal's fate.
    const char* const disposition = disposition_phrase(decision, rung);
    const bool terminal_delivered = decision == TeardownFinal::kNone ||
                                    rung == TerminalRung::kPrimary ||
                                    rung == TerminalRung::kFallback;

    // #2513: called from every bail site below, AFTER that site's own
    // count_teardown_incomplete but BEFORE its log_incomplete - log_incomplete's
    // wording depends on this call's result (retry-eligible vs. exhausted), so it
    // needs the answer, not just the fact that a bail happened.
    // Marks the record retry-eligible for a later sweep under
    // Config::teardown_retry_max, or - once that bound is hit - counts and logs
    // the exhausted disposition instead. Returns whether the record is STILL
    // eligible, so callers select between two STATIC audit-detail literals of
    // their own rather than this building one: #2487's whole point is that the
    // audit string on a bail path must not itself be a fresh allocation this
    // function cannot contain (the caller's `contained` steps are already done
    // by the time any of this runs - a throw here has nothing left to catch it).
    const auto mark_retry_or_exhausted = [&]() noexcept -> bool {
        std::size_t attempts = 0;
        bool eligible = false;
        const bool lock_ok = contained([&] {
            std::lock_guard<std::mutex> rlk(rec->mu);
            attempts = rec->teardown_attempts;
            eligible = attempts <= cfg_.teardown_retry_max;
            if (eligible) {
                rec->teardown_retry_claimable = true;
            }
        });
        // A lock failure here is treated exactly like exhaustion: we cannot safely
        // COMMIT teardown_retry_claimable=true without knowing the write actually
        // landed, so the conservative choice is to fall through to the already-
        // written !eligible branch below (count+log exhausted, retained-until-
        // shutdown) rather than risk marking a record retryable when the flag may
        // never have been set. A healthy record spuriously exhausted by a rare
        // lock hiccup is a graceful degradation; retrying a mutation that silently
        // failed to commit would not be.
        if (!lock_ok) {
            eligible = false;
        }
        if (!eligible) {
            count_teardown_retry(TeardownRetryOutcome::kExhausted);
            // Contained (not the bare noexcept boundary alone): formatting
            // allocates, same reasoning as log_incomplete above.
            // Gate 8 review: `attempts` reads as its zero-init default when
            // !lock_ok (the read that would set it never ran) - printing that
            // as though it were the real count would misreport, so the two
            // cases get distinct static-literal formats rather than sharing
            // one that silently lies on the lock-failure path.
            (void)contained([&] {
                if (lock_ok) {
                    spdlog::error(
                        "MCP bridge teardown retry exhausted [execution_id={} attempts={}]: "
                        "resource retained until shutdown",
                        exec_id, attempts);
                } else {
                    spdlog::error(
                        "MCP bridge teardown retry exhausted [execution_id={} attempts=unknown "
                        "(exhaustion check itself lock-faulted)]: resource retained until shutdown",
                        exec_id);
                }
            });
        }
        return eligible;
    };

    // ── Step 2: unsubscribe ────────────────────────────────────────────────────
    // #2519/#3095: the probe brackets the step OUTSIDE its own lock (contained's
    // lambda takes bridge_mu_ internally; the probe calls sit before/after the
    // whole contained(...) call), so a test can measure the step's allocation
    // footprint in isolation or pause the teardown thread at a known point
    // without risking a deadlock against bridge_mu_/rec->mu.
    if (teardown_step_probe_for_test_) {
        teardown_step_probe_for_test_(TeardownStage::kUnsubscribe, /*entering=*/true);
    }
    const bool step2_ok = contained([&] {
        if (take_step_fault(TeardownStage::kUnsubscribe)) {
            // system_error, not bad_alloc: a mutex failure is the only thing these
            // steps actually admit, and the seam should model the real fault.
            throw std::system_error(
                std::make_error_code(std::errc::resource_deadlock_would_occur),
                "injected teardown unsubscribe failure");
        }
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (rec->subscribed && bus_ != nullptr) {
            bus_->unsubscribe(exec_id, rec->sub_id);
        }
        rec->subscribed = false;
    });
    if (teardown_step_probe_for_test_) {
        teardown_step_probe_for_test_(TeardownStage::kUnsubscribe, /*entering=*/false);
    }
    if (!step2_ok) {
        // Bail with the record still in records_, still charged: internally
        // consistent, never an orphan listener, and reclaimed by either a later
        // retry pass (#2513, while under Config::teardown_retry_max) or - once
        // that bound is hit - by shutdown(). torn_down is NEVER cleared here:
        // re-entering this function is a fresh CALL, not a re-opened claim.
        count_teardown_incomplete(TeardownStage::kUnsubscribe);
        // Called ONCE per bail (it mutates retry state / counts the exhausted
        // outcome), and its result is shared by the log line and the audit detail
        // below rather than re-derived - re-calling it here would double-count.
        const bool retry_eligible = mark_retry_or_exhausted();
        log_incomplete(stage_name(TeardownStage::kUnsubscribe), retry_eligible);
        // The detail must not assert a delivery that did not happen. There are three
        // teardown_claimed call sites; the pin-ack / session-death / arming-reap one
        // passes kNone literally and publishes nothing, and the two pressure sites
        // pass a decision that still delivers nothing on kPoisoned / kNotAttempted -
        // so "the terminal was published" is only true when the ladder actually
        // committed. The disposition below is derived, not assumed.
        audit_contained(audit_action, exec_id,
                        retry_eligible
                            ? "teardown incomplete: bus unsubscribe failed; the record, its "
                              "streamed charge and its bus subscription are all retained "
                              "(retry-eligible on a later sweep)"
                            : "teardown incomplete: bus unsubscribe failed; the record, its "
                              "streamed charge and its bus subscription are all retained "
                              "(retry budget exhausted; retained until shutdown)",
                        disposition, AuditResult::kFailure);
        return;
    }

    // ── Step 3: release the streamed charge ────────────────────────────────────
    // #2513: a failure here now BAILS, like step 2, instead of falling through to
    // erase. Erasing on a charge failure was the pre-#2513 posture and made sense
    // ONLY when nothing could retry: the record bought nothing by surviving, so
    // freeing its global slot was the better trade, and the leaked per-session
    // charge had no surviving handle to reclaim it by. Under retry the record IS
    // the handle - erasing it here would strand the charge with nothing left to
    // find it on a later sweep.
    if (teardown_step_probe_for_test_) {
        teardown_step_probe_for_test_(TeardownStage::kReleaseCharge, /*entering=*/true);
    }
    const bool step3_ok = contained([&] {
        if (take_step_fault(TeardownStage::kReleaseCharge)) {
            throw std::system_error(std::make_error_code(std::errc::resource_deadlock_would_occur),
                                    "injected teardown release_charge failure");
        }
        release_charge(rec);
    });
    if (teardown_step_probe_for_test_) {
        teardown_step_probe_for_test_(TeardownStage::kReleaseCharge, /*entering=*/false);
    }
    if (!step3_ok) {
        count_teardown_incomplete(TeardownStage::kReleaseCharge);
        const bool retry_eligible = mark_retry_or_exhausted();
        log_incomplete(stage_name(TeardownStage::kReleaseCharge), retry_eligible);
        audit_contained(audit_action, exec_id,
                        retry_eligible
                            ? "teardown incomplete: streamed charge release failed; the record "
                              "and its one per-session admission slot are both retained "
                              "(retry-eligible on a later sweep)"
                            : "teardown incomplete: streamed charge release failed; the record "
                              "and its one per-session admission slot are both retained "
                              "(retry budget exhausted; retained until shutdown)",
                        disposition, AuditResult::kFailure);
        return;
    }
    flush_record_obs(*rec);  // already noexcept - deltas flushed before a possible erase below

    // ── Step 4: erase the map entry ────────────────────────────────────────────
    std::size_t active = 0;
    if (teardown_step_probe_for_test_) {
        teardown_step_probe_for_test_(TeardownStage::kErase, /*entering=*/true);
    }
    const bool step4_ok = contained([&] {
        if (take_step_fault(TeardownStage::kErase)) {
            throw std::system_error(
                std::make_error_code(std::errc::resource_deadlock_would_occur),
                "injected teardown erase failure");
        }
        std::lock_guard<std::mutex> lk(bridge_mu_);
        auto it = records_.find(rec->key);
        if (it != records_.end() && it->second == rec) {
            records_.erase(it);
        }
        active = records_.size();
    });
    if (teardown_step_probe_for_test_) {
        teardown_step_probe_for_test_(TeardownStage::kErase, /*entering=*/false);
    }
    if (!step4_ok) {
        // The gauge would be a lie, but the row must NOT be skipped: an erase
        // failure previously produced no audit evidence at all, which is the same
        // "no row" gap this work closes for the sibling step.
        count_teardown_incomplete(TeardownStage::kErase);
        const bool retry_eligible = mark_retry_or_exhausted();
        log_incomplete(stage_name(TeardownStage::kErase), retry_eligible);
        // No charge_released branch needed here (#2513): step 3 now bails on its
        // own failure instead of falling through, so reaching this point means
        // the subscription and the streamed charge were BOTH already settled -
        // only the map entry remains. Takes the disposition like every other
        // bail site, so a teardown that poisoned the session and then failed to
        // erase still evidences the poisoning, not just the mechanical failure.
        audit_contained(audit_action, exec_id,
                        retry_eligible
                            ? "teardown incomplete: record erase failed; the subscription and "
                              "the streamed charge were settled, the record is retained "
                              "(retry-eligible on a later sweep)"
                            : "teardown incomplete: record erase failed; the subscription and "
                              "the streamed charge were settled, the record is retained "
                              "(retry budget exhausted; retained until shutdown)",
                        disposition, AuditResult::kFailure);
        return;
    }
    publish_records_gauge(active);

    // ── Step 5: audit the real outcome ─────────────────────────────────────────
    // The terminal's fate comes from disposition_phrase, the SAME source the bail
    // sites use - this block used to hand-roll its own per-rung wording, which is
    // how two of its literals were left asserting "the stream was NOT poisoned"
    // after that claim had been corrected one function over. One source, no drift.
    //
    // #2513: no leaked-charge branch needed here - step 3 now bails on its own
    // failure (see above), so reaching Step 5 means unsubscribe, the charge
    // release AND the erase all settled. Reaching it via a retry pass (attempts
    // > 1) means a fault that survived one or more prior attempts finally
    // cleared; count that as recovered - it is evidence the retry design is
    // doing its job, not just that a first attempt happened to succeed.
    std::size_t attempts = 0;
    const bool attempts_read_ok = contained([&] {
        std::lock_guard<std::mutex> rlk(rec->mu);
        attempts = rec->teardown_attempts;
    });
    // Purely observability: steps 1-4 have already succeeded by this point (the
    // record IS settling correctly regardless), so a lock failure here just means
    // skipping the "recovered" metric bump rather than risking anything on an
    // unknown attempts count.
    if (attempts_read_ok && attempts > 1) {
        count_teardown_retry(TeardownRetryOutcome::kRecovered);
    }
    // kNone contributes no disposition at all, so a clean pin-ack / session-death
    // reap still emits a byte-identical empty-detail row on a FIRST attempt; a
    // retry that recovered says so explicitly (a STATIC literal, not the attempt
    // count - this whole function is noexcept, so nothing on this path may
    // allocate outside a `contained`/`obs_guard` boundary), since a bare
    // "success" row would otherwise look identical to one that never needed
    // retrying at all.
    const bool clean_kNone = decision == TeardownFinal::kNone;
    // Reuses `attempts` without re-checking `attempts_read_ok` (Gate 8 review) -
    // deliberately safe by construction, not an oversight: on a lock failure
    // `attempts` stays at its zero-init default, and 0 > 1 is false, which is
    // the exact same outcome an explicit guard would produce. Kept unguarded
    // rather than adding a redundant check that can never change this branch.
    const char* const stage_detail = attempts > 1 ? "recovered on a retry attempt" : "";
    audit_contained(audit_action, exec_id, stage_detail,
                    clean_kNone ? std::string_view{} : std::string_view{disposition},
                    terminal_delivered ? AuditResult::kSuccess : AuditResult::kFailure);
}

void McpStreamBridge::release_charge(const std::shared_ptr<BridgeRecord>& rec) {
    if (charge_lock_fault_.load(std::memory_order_relaxed) > 0 &&
        charge_lock_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
        // inject_charge_lock_fault_for_test - the modelled mutex failure, thrown
        // BEFORE either lock so it models the acquisition itself failing. It sits
        // here, in the shared primitive, rather than at a call site: this is the
        // one place that owns the both-or-neither property both callers depend on.
        throw std::system_error(std::make_error_code(std::errc::resource_deadlock_would_occur),
                                "injected release_charge lock failure");
    }
    // BOTH halves under BOTH locks, in hierarchy order. The split version cleared
    // the flag under rec->mu and only THEN took bridge_mu_ - and that acquisition is
    // the sole throw site, so a failure left the record reading "not held" while
    // streamed_unpinned_[session] still counted it. That entry could then never
    // reach 0, so decrement_streamed_locked's erase never ran and the
    // no-historical-session-accumulation invariant was permanently broken for that
    // session - a far larger blast radius than the one admission slot it looks like.
    // Locking first means a throw happens before any mutation: both commit, or
    // neither does.
    std::lock_guard<std::mutex> lk(bridge_mu_);
    std::lock_guard<std::mutex> rlk(rec->mu);
    if (rec->streamed_charge_held) {
        rec->streamed_charge_held = false;
        decrement_streamed_locked(rec->session_id);
    }
}

void McpStreamBridge::decrement_streamed_locked(const std::string& session_id) {
    auto it = streamed_unpinned_.find(session_id);
    if (it == streamed_unpinned_.end()) {
        return;  // defensive - exactly-once release should make this unreachable
    }
    if (it->second > 0) {
        --it->second;
    }
    if (it->second == 0) {
        streamed_unpinned_.erase(it);  // C3: no historical-session accumulation
    }
}

// ── Observability (C5: contained, never under bridge_mu_/listener) ────────

template <typename F> bool McpStreamBridge::obs_guard(F&& f) noexcept {
    if (obs_fault_remaining_.load(std::memory_order_relaxed) > 0 &&
        obs_fault_remaining_.fetch_sub(1, std::memory_order_relaxed) > 0) {
        return false;  // injected observability failure (C5 fault seam)
    }
    try {
        f();
        return true;
    } catch (...) {
        return false;
    }
}

void McpStreamBridge::count_reject(const char* reason) noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricRejects, {{"reason", reason}}).increment(); });
    }
}

void McpStreamBridge::count_charge_release_deferred() noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricChargeReleaseDeferred).increment(); });
    }
}

void McpStreamBridge::count_forced_expire(TeardownFinal decision) noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] {
            metrics_
                ->counter(kMetricForcedExpire,
                          {{"disposition", forced_expire_disposition(decision)}})
                .increment();
        });
    }
}

void McpStreamBridge::count_pressure_budget_exhausted() noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricPressureBudgetExhausted).increment(); });
    }
}

void McpStreamBridge::count_teardown_incomplete(TeardownStage stage) noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] {
            metrics_->counter(kMetricTeardownIncomplete, {{"reason", stage_name(stage)}})
                .increment();
        });
    }
}

void McpStreamBridge::count_teardown_retry(TeardownRetryOutcome outcome) noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] {
            metrics_->counter(kMetricTeardownRetry, {{"outcome", retry_outcome_name(outcome)}})
                .increment();
        });
    }
}

bool McpStreamBridge::take_step_fault(TeardownStage stage) noexcept {
    const auto idx = static_cast<std::size_t>(stage);
    if (idx >= kTeardownStageCount) {
        return false;
    }
    auto& slot = teardown_step_fault_[idx];
    return slot.load(std::memory_order_relaxed) > 0 &&
           slot.fetch_sub(1, std::memory_order_acq_rel) > 0;
}

void McpStreamBridge::publish_records_gauge(std::size_t n) noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->gauge(kMetricRecordsActive).set(static_cast<double>(n)); });
    }
}

void McpStreamBridge::count_pin_displaced_for_admission() noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricPinDisplacedForAdmission).increment(); });
    }
}

void McpStreamBridge::count_pin_release_failed() noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricPinReleaseFailed).increment(); });
    }
}

void McpStreamBridge::count_pin_release_raced() noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricPinReleaseRaced).increment(); });
    }
}

void McpStreamBridge::count_pin_slots_reject(std::size_t pinned, std::size_t unpinned) noexcept {
    if (metrics_ == nullptr) {
        return;
    }
    // "pins" only when NO charge is outstanding. That is the wedge SHAPE, but on its
    // own it is NOT proof of a wedge: the charge-to-pin handover happens at terminal
    // projection while the unpin happens only once the final reaches the wire, so
    // every HEALTHY session passes through pinned>0/unpinned==0 during that flush
    // window. Only persistence separates the two, which is why the alert on this
    // counter carries a `for` and why that `for` is load-bearing rather than tuning.
    // A mixed state still has work in flight that will clear, so it reads "charges"
    // rather than overstating a wedge - at the cost of bucketing a PARTIAL wedge
    // (some pins stuck, one call genuinely live) as ordinary saturation, where
    // neither the alert nor the operator-facing text will see it. A simple
    // `pinned > unpinned` would have mislabelled ties and hidden partial wedges
    // behind the wrong bucket either way.
    const char* held = (pinned > 0 && unpinned == 0) ? "pins" : "charges";
    obs_guard([&] { metrics_->counter(kMetricPinSlotsReject, {{"held", held}}).increment(); });
}

void McpStreamBridge::flush_record_obs(BridgeRecord& rec) noexcept {
    // D3: exchange-then-restore. A transiently failing registry never loses the
    // accumulated delta - it is put back (or parked on the shared core) for a
    // later flush; only final process shutdown may drop it.
    const auto fails = rec.listener_failure_delta.exchange(0, std::memory_order_relaxed);
    if (fails != 0) {
        if (metrics_ == nullptr ||
            !obs_guard([&] {
                metrics_->counter(kMetricListenerFailures).increment(static_cast<double>(fails));
            })) {
            core_->pending_listener_failures.fetch_add(fails, std::memory_order_relaxed);
        }
    }
    const auto degraded = rec.projection_degraded_delta.exchange(0, std::memory_order_relaxed);
    if (degraded != 0) {
        if (metrics_ == nullptr ||
            !obs_guard([&] {
                metrics_->counter(kMetricProjectionDegraded)
                    .increment(static_cast<double>(degraded));
            })) {
            core_->pending_projection_degraded.fetch_add(degraded, std::memory_order_relaxed);
        }
    }
    const auto suppressed = rec.progress_suppressed_delta.exchange(0, std::memory_order_relaxed);
    if (suppressed != 0) {
        if (metrics_ == nullptr ||
            !obs_guard([&] {
                metrics_->counter(kMetricProgressSuppressed)
                    .increment(static_cast<double>(suppressed));
            })) {
            core_->pending_progress_suppressed.fetch_add(suppressed, std::memory_order_relaxed);
        }
    }
}

void McpStreamBridge::flush_core_obs() noexcept {
    if (metrics_ == nullptr) {
        return;  // keep pending - a registry may never appear, but losing the
                 // count is worse than holding an int
    }
    const auto fails = core_->pending_listener_failures.exchange(0, std::memory_order_relaxed);
    if (fails != 0 &&
        !obs_guard([&] {
            metrics_->counter(kMetricListenerFailures).increment(static_cast<double>(fails));
        })) {
        core_->pending_listener_failures.fetch_add(fails, std::memory_order_relaxed);
    }
    const auto degraded = core_->pending_projection_degraded.exchange(0, std::memory_order_relaxed);
    if (degraded != 0 &&
        !obs_guard([&] {
            metrics_->counter(kMetricProjectionDegraded).increment(static_cast<double>(degraded));
        })) {
        core_->pending_projection_degraded.fetch_add(degraded, std::memory_order_relaxed);
    }
    const auto suppressed = core_->pending_progress_suppressed.exchange(0, std::memory_order_relaxed);
    if (suppressed != 0 &&
        !obs_guard([&] {
            metrics_->counter(kMetricProgressSuppressed)
                .increment(static_cast<double>(suppressed));
        })) {
        core_->pending_progress_suppressed.fetch_add(suppressed, std::memory_order_relaxed);
    }
}

const char* McpStreamBridge::disposition_phrase(TeardownFinal decision,
                                               TerminalRung rung) noexcept {
    // ONE source for every teardown bail site. The recurring defect on this function
    // was a bail site that described the mechanical failure and stayed silent about
    // the terminal - most consequentially about a POISONED session, which is
    // session-wide (every later attach 410s). Three separate rounds fixed one site
    // and left another; deriving it once removes the opportunity.
    if (decision == TeardownFinal::kNone) {
        return "this teardown published nothing (any earlier final is unaffected)";
    }
    switch (rung) {
        case TerminalRung::kPrimary:
            return decision == TeardownFinal::kSynthesizeUnavailable
                       ? "the terminal-unavailable frame was published"
                       : "the fallback final was published";
        case TerminalRung::kFallback:
            return "the intended terminal failed and the prebuilt fallback final was "
                   "published instead";
        case TerminalRung::kPoisoned:
            return "the terminal publish POISONED the session - every later attach 410s and "
                   "the client must re-initialize; recover the result by execution_id";
        case TerminalRung::kNotAttempted:
            break;
    }
    return "the terminal frame could not be built; nothing was published and THIS teardown did "
           "not poison the session - recover the result by execution_id";
}

void McpStreamBridge::audit_contained(const char* action, const std::string& execution_id,
                                      std::string_view stage, std::string_view disposition,
                                      AuditResult result, std::string_view actor) noexcept {
    if (audit_) {
        // Every owned string the AuditFn signature needs - action from a const char*,
        // and the joined detail from the two views - is constructed HERE, inside the
        // guard, so the join cannot allocate on an uncontained path (#2487).
        obs_guard([&] {
            std::string detail(stage);
            if (!detail.empty() && !disposition.empty()) {
                detail += "; ";
            }
            detail.append(disposition);
            audit_(action, execution_id, std::move(detail), result, std::string(actor));
        });
    }
}

// ── Accessors / test seams ─────────────────────────────────────────────────

std::size_t McpStreamBridge::record_count() const {
    std::lock_guard<std::mutex> lk(bridge_mu_);
    return records_.size();
}

std::optional<bool> McpStreamBridge::post_sink_closed_for_test(
    const std::string& session_id, const nlohmann::json& jsonrpc_id) const {
    std::shared_ptr<BridgeRecord> rec;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        auto it = records_.find(make_key(session_id, jsonrpc_id));
        if (it == records_.end()) {
            return std::nullopt;
        }
        rec = it->second;
    }
    std::lock_guard<std::mutex> rlk(rec->mu);
    if (!rec->post_sink) {
        return std::nullopt;
    }
    return rec->post_sink->closed.load(std::memory_order_acquire);
}

std::size_t McpStreamBridge::ring_only_count() const {
    std::lock_guard<std::mutex> lk(bridge_mu_);
    std::size_t n = 0;
    for (const auto& [key, rec] : records_) {
        if (rec->phase.load(std::memory_order_acquire) == Phase::kRingOnly) {
            ++n;
        }
    }
    return n;
}

std::optional<McpStreamBridge::Phase>
McpStreamBridge::phase_for(const std::string& session_id, const nlohmann::json& jsonrpc_id) const {
    std::lock_guard<std::mutex> lk(bridge_mu_);
    auto rec = find_locked(make_key(session_id, jsonrpc_id));
    if (!rec) {
        return std::nullopt;
    }
    return rec->phase.load(std::memory_order_acquire);
}

void McpStreamBridge::inject_listener_fault_for_test() {
    core_->listener_fault.store(true, std::memory_order_release);
}

void McpStreamBridge::inject_observability_fault_for_test(int times) {
    obs_fault_remaining_.store(times, std::memory_order_relaxed);
}

void McpStreamBridge::inject_arm_fault_for_test() {
    arm_fault_.store(true, std::memory_order_release);
}

void McpStreamBridge::inject_reserve_fault_for_test() {
    reserve_fault_.store(true, std::memory_order_release);
}

void McpStreamBridge::inject_subscribe_fault_for_test() {
    subscribe_fault_.store(true, std::memory_order_release);
}

void McpStreamBridge::inject_visit_copy_fault_for_test(int times) {
    visit_copy_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::inject_reserve_commit_fault_for_test() {
    reserve_commit_fault_.store(true, std::memory_order_release);
}

void McpStreamBridge::inject_claim_lock_fault_for_test(int times) {
    claim_lock_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::inject_projection_build_fault_for_test(int times) {
    projection_build_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::inject_projection_fallback_fault_for_test(int times) {
    projection_fallback_fault_.store(times, std::memory_order_release);
}

bool McpStreamBridge::inject_teardown_step_fault_for_test(TeardownStage stage, int times) {
    const auto idx = static_cast<std::size_t>(stage);
    if (idx >= kTeardownStageCount) {
        return false;  // public method: an out-of-range cast must not become an OOB write
    }
    teardown_step_fault_[idx].store(times, std::memory_order_release);
    return true;
}

void McpStreamBridge::set_teardown_step_probe_for_test(
    std::function<void(TeardownStage, bool)> probe) {
    teardown_step_probe_for_test_ = std::move(probe);
}

void McpStreamBridge::inject_terminal_build_fault_for_test(int times) {
    terminal_build_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::inject_charge_lock_fault_for_test(int times) {
    charge_lock_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::inject_record_entry_lock_fault_for_test(int times) {
    record_entry_lock_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::set_clock_for_test(ClockFn clock) { clock_ = std::move(clock); }

McpStreamBridge::AccountingSnapshot McpStreamBridge::accounting_snapshot_for_test(
    const std::string& session_id, const std::shared_ptr<McpStreamState>& stream) {
    std::lock_guard<std::mutex> lk(bridge_mu_);
    AccountingSnapshot snap;
    snap.pinned = stream ? stream->pinned_count() : 0;
    auto it = streamed_unpinned_.find(session_id);
    snap.unpinned = it == streamed_unpinned_.end() ? 0 : it->second;
    return snap;
}

void McpStreamBridge::arm_projection_stall_for_test() {
    std::lock_guard<std::mutex> lk(projection_stall_mu_);
    projection_stall_reached_for_test_ = false;
    projection_stall_release_for_test_ = false;
    projection_stall_armed_for_test_.store(true, std::memory_order_release);
}

bool McpStreamBridge::wait_projection_stall_reached_for_test(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(projection_stall_mu_);
    return projection_stall_cv_.wait_for(lk, timeout,
                                         [&] { return projection_stall_reached_for_test_; });
}

void McpStreamBridge::release_projection_stall_for_test() {
    std::lock_guard<std::mutex> lk(projection_stall_mu_);
    projection_stall_release_for_test_ = true;
    projection_stall_cv_.notify_all();
}

}  // namespace yuzu::server::mcp
