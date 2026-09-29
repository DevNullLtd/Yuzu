#pragma once

/**
 * guardian_outbox.hpp - the Guardian spark consumer's in-memory, lifetime-safe
 * emit buffer (ADR-0021 Stage 2 rung 2). PURE and caller-serialized: no I/O, no
 * threads, no clock, no proto. The runtime drives it under its registry mutex and
 * injects a send function at drain time, so every branch is unit-tested standalone.
 *
 * Why it exists (the pre-network / A3 gap it closes): GuardianEngine arms and does
 * its initial eval BEFORE the server sink is published (start_local runs before
 * Subscribe-open). Emitting straight to the sink there DROPS the event, yet
 * decide_emit has already committed last_compliant - so the compliant edge is lost
 * forever and steady-compliant stays silent, and the server never learns
 * compliance. The consumer instead enqueues here and drains when the sink is live.
 * This is an in-memory buffer plus a boot re-eval, NOT durable event delivery: a
 * process restart re-arms and re-evaluates from scratch rather than replaying.
 *
 * Contract the runtime MUST honour (enforced structurally here where possible):
 *   - enqueue BEFORE commit. Run the eval against a COPY of RuleEvalState, enqueue
 *     the outcome, and commit the copy back ONLY if enqueue() returned true. If it
 *     returned false (at cap), discard the copy so the eval stays pending and
 *     convergence retries - never advance decider state for an event we could not
 *     buffer. (decide_emit mutates state mid-eval, hence copy-eval-enqueue-commit.)
 *   - peek / send / remove-on-success. drain() sends in FIFO order and removes an
 *     entry only when the send reports success; a false return OR a throw retains
 *     the entry and STOPS the drain (the stream is down - do not burn N syscalls).
 *   - SEPARATE coalescing domains. compliance / health each coalesce to the latest
 *     per rule independently; a health event never overwrites a pending compliance
 *     event for the same rule. Lifecycle is NOT a domain this class accepts - see
 *     GuardianLifecycleLog below and enqueue()'s rejection of it.
 *   - generation-tagged, purged on rule update/disable. A stale entry from a
 *     superseded generation is dropped, never sent.
 *   - event_id + timestamp fixed at ENQUEUE (the caller sets them; this stays free
 *     of clock/randomness). Coalescing replaces with the latest observation's id+ts.
 *   - full-cap => reject (caller leaves the eval pending) + bump the backpressure
 *     counter. NEVER silently evict a buffered entry to make room.
 *
 * The drain trigger (sink publication + every reconnect, not sync_with_server) and
 * the boot re-arm/re-eval are the runtime's wiring, not this structure's concern.
 */

#include <yuzu/agent/guard.hpp> // GuardDrift

#include <cstddef>
#include <cstdint>
#include <list>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::agent {

/// Independent coalescing channels. Two entries coalesce (latest wins) only when
/// BOTH domain and rule_id match, so a rule can have one pending entry per domain.
/// Lifecycle is the odd one out: GuardianOutbox::enqueue()/enqueue_all() REJECT
/// it (see there for why - coalescing is the wrong semantics for an audit trail).
/// It exists on this shared enum/struct only because GuardianLifecycleLog reuses
/// OutboxEntry as its payload type; production code only ever routes it there.
enum class OutboxDomain {
    Compliance, ///< guard.compliant / guard.drift (payload: GuardDrift)
    Health,     ///< guard.unhealthy / guard.healthy (payload: healthy + detail)
    Lifecycle,  ///< guard.armed / guard.disarmed / guard.errored (payload: kind) - GuardianLifecycleLog only
};

/// One buffered emit. Which payload fields are meaningful is fixed by `domain`.
struct OutboxEntry {
    OutboxDomain domain{OutboxDomain::Compliance};
    std::string rule_id;
    std::uint64_t generation{0}; ///< the rule generation this was produced under; dropped once superseded
    std::string event_id;        ///< fixed at enqueue (wire idempotency)
    std::int64_t enqueued_ns{0}; ///< timestamp fixed at enqueue

    GuardDrift drift{};          ///< Compliance payload

    bool healthy{true};          ///< Health payload: true = recovered, false = unhealthy
    std::string health_detail;   ///< Health payload: read-error detail (unhealthy)

    std::string lifecycle_kind;  ///< Lifecycle payload: "armed" | "disarmed" | "errored"

    // Health + Lifecycle carry the guard identity explicitly (the Compliance domain
    // carries both inside `drift`). Empty on Compliance entries. Without these the
    // wire event's guard_type/rule_name were blank on every health/lifecycle event.
    std::string guard_type;      ///< Health/Lifecycle: "file" | "registry" | "service"
    std::string rule_name;       ///< Health/Lifecycle: human-readable rule name

    // Journal-replay provenance (item 7 PR-Ag): set ONLY on Lifecycle entries PAGED back
    // from the durable journal, so the send path can write the batch's sent-label after its
    // LAST entry sends. Empty/false on live + compliance/health entries. NOT wire fields -
    // guardian_outbox_entry_to_event ignores them, so they never change the server compare.
    std::string journal_batch_key;     ///< the durable batch this replayed entry came from ("" if live)
    bool journal_last_in_batch{false}; ///< this is that batch's LAST entry - write sent:<key> on send

    static OutboxEntry compliance(std::string rule_id, std::uint64_t generation,
                                  std::string event_id, std::int64_t enqueued_ns, GuardDrift drift) {
        OutboxEntry e;
        e.domain = OutboxDomain::Compliance;
        e.rule_id = std::move(rule_id);
        e.generation = generation;
        e.event_id = std::move(event_id);
        e.enqueued_ns = enqueued_ns;
        e.drift = std::move(drift);
        return e;
    }
    static OutboxEntry health(std::string rule_id, std::uint64_t generation, std::string event_id,
                              std::int64_t enqueued_ns, bool healthy, std::string detail,
                              std::string guard_type = {}, std::string rule_name = {}) {
        OutboxEntry e;
        e.domain = OutboxDomain::Health;
        e.rule_id = std::move(rule_id);
        e.generation = generation;
        e.event_id = std::move(event_id);
        e.enqueued_ns = enqueued_ns;
        e.healthy = healthy;
        e.health_detail = std::move(detail);
        e.guard_type = std::move(guard_type);
        e.rule_name = std::move(rule_name);
        return e;
    }
    static OutboxEntry lifecycle(std::string rule_id, std::uint64_t generation, std::string event_id,
                                 std::int64_t enqueued_ns, std::string kind,
                                 std::string guard_type = {}, std::string rule_name = {}) {
        OutboxEntry e;
        e.domain = OutboxDomain::Lifecycle;
        e.rule_id = std::move(rule_id);
        e.generation = generation;
        e.event_id = std::move(event_id);
        e.enqueued_ns = enqueued_ns;
        e.lifecycle_kind = std::move(kind);
        e.guard_type = std::move(guard_type);
        e.rule_name = std::move(rule_name);
        return e;
    }
};

/// What a send attempt reported. Retain and Failed are equivalent to the drain
/// (both stop it and keep the entry); they read differently at the call site.
enum class SendResult {
    Sent,   ///< delivered; remove the entry
    Retain, ///< stream down / Write()==false; keep the entry and stop draining
};

/// FIFO, per-(domain,rule_id)-coalesced, capacity-bounded emit buffer.
/// Non-thread-safe by design: the runtime serialises access under its registry
/// mutex. A std::list preserves enqueue order with O(1) coalesce-in-place (the
/// index maps a key to the node, whose iterator stays valid across other edits)
/// and O(1) pop of a drained head.
class GuardianOutbox {
public:
    explicit GuardianOutbox(std::size_t capacity) : capacity_(capacity) {}

    /// Buffer `e`, coalescing to the latest for its (domain, rule_id). Returns
    /// false iff a NEW key would exceed capacity - the caller then leaves the eval
    /// pending (does NOT commit its decider copy) and this bumps the backpressure
    /// counter. Coalescing an existing key never grows the buffer, so it always
    /// succeeds and replaces the payload/id/timestamp/generation in place.
    ///
    /// Also returns false (no counter bump - this is a caller bug, not a capacity
    /// condition) for a Lifecycle-domain entry: this class's coalescing semantics
    /// would silently lose armed/disarmed/errored audit evidence, which is exactly
    /// what GuardianLifecycleLog exists to prevent. Route Lifecycle entries to
    /// GuardianLifecycleLog::enqueue() instead.
    bool enqueue(OutboxEntry e) {
        if (e.domain == OutboxDomain::Lifecycle)
            return false;
        const Key k{e.domain, e.rule_id};
        const auto it = index_.find(k);
        if (it != index_.end()) {
            *it->second = std::move(e); // coalesce: latest observation wins, keep position
            return true;
        }
        if (pending_.size() >= capacity_) {
            ++backpressure_drops_;
            return false; // never evict a buffered entry
        }
        pending_.push_back(std::move(e));
        index_.emplace(k, std::prev(pending_.end()));
        return true;
    }

    /// Atomically buffer a SET of entries: both-or-neither. Returns false iff the
    /// NEW keys among them would exceed capacity, in which case NONE are buffered
    /// (and the backpressure counter bumps once) so the caller leaves the whole eval
    /// pending. Used for the health-recovery pair (guard.healthy + the verdict) which
    /// must land together or not at all - a partial commit would advance decider state
    /// for an event the server never receives. Coalescing entries never count as growth.
    bool enqueue_all(std::vector<OutboxEntry> entries) {
        for (const auto& e : entries) {
            if (e.domain == OutboxDomain::Lifecycle) // see enqueue()'s rejection note
                return false;
        }
        std::size_t new_keys = 0;
        std::unordered_set<Key, KeyHash> adding;
        for (const auto& e : entries) {
            const Key k{e.domain, e.rule_id};
            if (index_.find(k) == index_.end() && adding.insert(k).second)
                ++new_keys;
        }
        if (pending_.size() + new_keys > capacity_) {
            ++backpressure_drops_;
            return false;
        }
        for (auto& e : entries)
            enqueue(std::move(e)); // each fits now (a coalesce, or within the reserved room)
        return true;
    }

    /// TEST-ONLY (unit tests of the coalesce/FIFO/purge semantics with an inline send).
    /// Production drains via GuardianSparkRuntime::drain, which uses front_copy/
    /// pop_front_if with outbox_mu_ RELEASED across the send - do NOT call this from the
    /// runtime under outbox_mu_, it reintroduces the head-of-line stall item 4 removed.
    /// Send buffered entries in FIFO order; a Sent entry is removed, a Retain (or a
    /// thrown exception) is kept and stops the drain. Returns the number sent.
    template <typename SendFn>
    std::size_t drain(SendFn&& send) {
        std::size_t sent = 0;
        while (!pending_.empty()) {
            const OutboxEntry& front = pending_.front();
            SendResult r = SendResult::Retain;
            try {
                r = send(front);
            } catch (...) {
                break; // treat a throw as a down stream: retain the head, stop
            }
            if (r != SendResult::Sent)
                break;
            index_.erase(Key{front.domain, front.rule_id});
            pending_.pop_front();
            ++sent;
        }
        return sent;
    }

    /// Peek a COPY of the head (nullopt if empty). For the runtime's unlock-during-send
    /// drain: copy the head under outbox_mu_, RELEASE it, send (network I/O off-lock),
    /// re-acquire, then pop_front_if(). Keeps a stalled gRPC Write() off outbox_mu_ so it
    /// cannot block evaluate_key's emit / arm-disarm enqueue / heartbeat (item 4).
    [[nodiscard]] std::optional<OutboxEntry> front_copy() const {
        if (pending_.empty())
            return std::nullopt;
        return pending_.front();
    }

    /// Pop the head IFF it is STILL the entry with `event_id` - i.e. a coalesce (which
    /// replaces the node in place with a fresh event_id) or a drop_rule/purge_stale
    /// during the unlocked send did not replace/remove it. Returns true iff popped.
    /// event_id is globally unique per enqueue, so it pins the exact sent entry.
    bool pop_front_if(std::string_view event_id) {
        if (pending_.empty() || pending_.front().event_id != event_id)
            return false;
        index_.erase(Key{pending_.front().domain, pending_.front().rule_id});
        pending_.pop_front();
        return true;
    }

    /// Drop every pending entry for a rule (used on disable / withdraw).
    void drop_rule(const std::string& rule_id) {
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (it->rule_id == rule_id) {
                index_.erase(Key{it->domain, it->rule_id});
                it = pending_.erase(it);
            } else {
                ++it;
            }
        }
    }

    /// Drop pending entries for a rule that predate `active_generation` (a
    /// superseded generation must never send). Entries at or above it are kept.
    void purge_stale(const std::string& rule_id, std::uint64_t active_generation) {
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (it->rule_id == rule_id && it->generation < active_generation) {
                index_.erase(Key{it->domain, it->rule_id});
                it = pending_.erase(it);
            } else {
                ++it;
            }
        }
    }

    [[nodiscard]] std::size_t size() const { return pending_.size(); }
    [[nodiscard]] bool empty() const { return pending_.empty(); }
    [[nodiscard]] std::size_t capacity() const { return capacity_; }
    /// Count of rejected enqueues (never-evicted backpressure), for telemetry.
    [[nodiscard]] std::uint64_t backpressure_drops() const { return backpressure_drops_; }

private:
    struct Key {
        OutboxDomain domain;
        std::string rule_id;
        bool operator==(const Key& o) const { return domain == o.domain && rule_id == o.rule_id; }
    };
    struct KeyHash {
        std::size_t operator()(const Key& k) const {
            return std::hash<std::string>{}(k.rule_id) ^
                   (static_cast<std::size_t>(k.domain) * 0x9e3779b97f4a7c15ull);
        }
    };

    std::size_t capacity_;
    std::list<OutboxEntry> pending_;
    std::unordered_map<Key, std::list<OutboxEntry>::iterator, KeyHash> index_;
    std::uint64_t backpressure_drops_{0};
};

/// APPEND-ONLY audit log for Lifecycle (guard.armed / guard.disarmed / guard.errored)
/// entries (ADR-0021 Stage 2 rung 7, audit-on-arm). Deliberately NOT the same
/// structure as GuardianOutbox: that class coalesces per (domain, rule_id) -
/// latest wins - and its drop_rule()/purge_stale() erase every domain for a
/// rule, INCLUDING Lifecycle. Both are correct and desired for a live
/// compliance/health verdict (only the latest matters, and a withdrawn rule's
/// stale verdict must not send) but WRONG for an audit trail: a rule armed then
/// quickly disabled must not have its "armed" evidence silently coalesced away
/// or purged by the disable's own withdrawal - the trail is the point. This
/// class enqueues FIFO, sends FIFO, coalesces nothing, and is never purged by
/// rule_id or generation - an entry leaves only when successfully sent.
/// Capacity-bounded like its sibling (reject-new + count on full; never evict).
class GuardianLifecycleLog {
public:
    explicit GuardianLifecycleLog(std::size_t capacity) : capacity_(capacity) {}

    /// Buffer `e`. Returns false iff at capacity - the caller's arm/disarm still
    /// succeeds (the audit trail is not allowed to block or unwind a real
    /// detection-capability change); the caller should count/log this loudly
    /// rather than swallow it (see the header note on outbox-full-on-arm).
    ///
    /// Also returns false (no counter bump - this is a caller bug, not a capacity
    /// condition) for a non-Lifecycle entry (#3953 item 4): production only ever
    /// routes Lifecycle here (GuardianOutbox::enqueue's own mirror-image check
    /// above rejects Lifecycle FOR compliance/health reasons), but the invariant
    /// was previously enforced only by convention - three construction sites, no
    /// assertion. Checked BEFORE the capacity check, deliberately: a wrong-domain
    /// entry offered while this log happens to be at capacity must not increment
    /// backpressure_drops_, since that counter means "a correct-domain entry was
    /// rejected for capacity", not "a caller bug occurred".
    bool enqueue(OutboxEntry e) {
        if (e.domain != OutboxDomain::Lifecycle)
            return false;
        if (pending_.size() >= capacity_) {
            ++backpressure_drops_;
            return false;
        }
        pending_.push_back(std::move(e));
        return true;
    }

    /// TEST-ONLY (see GuardianOutbox::drain's note): production drains via
    /// GuardianSparkRuntime::drain with outbox_mu_ released across the send.
    /// Send in FIFO order; a Sent entry is removed, a Retain (or a throw) stops
    /// the drain and keeps the head - identical send contract to GuardianOutbox.
    template <typename SendFn>
    std::size_t drain(SendFn&& send) {
        std::size_t sent = 0;
        while (!pending_.empty()) {
            const OutboxEntry& front = pending_.front();
            SendResult r = SendResult::Retain;
            try {
                r = send(front);
            } catch (...) {
                break;
            }
            if (r != SendResult::Sent)
                break;
            pending_.pop_front();
            ++sent;
        }
        return sent;
    }

    /// Peek/pop primitives for the runtime's unlock-during-send drain (see
    /// GuardianOutbox::front_copy/pop_front_if). This log coalesces nothing, so a
    /// pop_front_if mismatch here means only a successful send already removed the head.
    [[nodiscard]] std::optional<OutboxEntry> front_copy() const {
        if (pending_.empty())
            return std::nullopt;
        return pending_.front();
    }
    bool pop_front_if(std::string_view event_id) {
        if (pending_.empty() || pending_.front().event_id != event_id)
            return false;
        pending_.pop_front();
        return true;
    }

    [[nodiscard]] std::size_t size() const { return pending_.size(); }
    [[nodiscard]] bool empty() const { return pending_.empty(); }
    [[nodiscard]] std::uint64_t backpressure_drops() const { return backpressure_drops_; }

    /// Journal-replay support (item 7 PR-Ag): is `event_id` already buffered? The loader
    /// scans the window to skip re-paging an entry already present (membership = window
    /// scan, no allocating set). O(size); the window is bounded.
    [[nodiscard]] bool contains(std::string_view event_id) const {
        for (const auto& e : pending_)
            if (e.event_id == event_id)
                return true;
        return false;
    }
    /// Journal-replay support (item 7 PR-Ag): build a membership set of the currently-buffered
    /// event_ids in ONE O(size) pass, so the loader can test a whole batch's records in O(1)
    /// each instead of re-scanning the window per record - which is O(records x window) and, on
    /// the heartbeat/run-loop thread, can starve heartbeats under a large backlog (review
    /// UP-12 / perf P-2). The returned views ALIAS this log's entries: valid only while the
    /// caller holds the runtime's outbox_mu_ and does not erase from the log. enqueue()/push_back
    /// keeps std::list nodes (and their string storage) stable, so pages appended after this
    /// call do not invalidate the views - they simply are not in the (pre-batch) set, which is
    /// correct because a batch's own records carry distinct event_ids.
    [[nodiscard]] std::unordered_set<std::string_view> event_id_set() const {
        std::unordered_set<std::string_view> ids;
        ids.reserve(pending_.size());
        for (const auto& e : pending_)
            ids.insert(e.event_id);
        return ids;
    }
    /// Free slots before the capacity cap - the loader pages a batch only when the window
    /// has >= the batch's size of headroom (else it defers the batch to a later pass).
    [[nodiscard]] std::size_t headroom() const {
        return capacity_ > pending_.size() ? capacity_ - pending_.size() : 0;
    }

    /// Back-fill journal provenance onto still-buffered LIVE entries (item 7 PR-Ag M3): for each
    /// entry whose event_id belongs to a just-persisted batch, stamp the batch key and mark ONLY
    /// the batch's LAST record last-in-batch, so a live send writes the sent-label instead of the
    /// batch later ageing out counted evicted_without_send_evidence. The window drains FIFO, so
    /// the last-in-batch entry sends after the earlier ones and the label is never premature.
    ///
    /// The last-in-batch mark is withheld unless EVERY record of the batch is present in the
    /// window (#2345 Gate 8 F1). A record can be journalled but never windowed - the arm path
    /// stages to the journal unconditionally while `enqueue` may refuse on backpressure - and
    /// marking the last entry regardless meant its send wrote a sent-label for a batch one of
    /// whose records had never been sent at all. That was survivable while replay re-offered
    /// every batch on every pass, because the missing record was simply placed next time round;
    /// once the sent-label began to SUPPRESS replay it became silent, permanent loss of exactly
    /// the record that was already unlucky. Withholding the mark keeps the batch unlabelled, so
    /// it stays a replay candidate until a pass does place the whole thing - self-healing, and
    /// it costs only a delayed label.
    void stamp_provenance(const std::string& batch_key,
                          const std::unordered_set<std::string>& event_ids,
                          const std::string& last_event_id) {
        std::size_t matched = 0;
        for (const auto& e : pending_)
            if (event_ids.count(e.event_id))
                ++matched;
        const bool whole_batch_windowed = matched == event_ids.size();
        for (auto& e : pending_) {
            if (event_ids.count(e.event_id)) {
                e.journal_batch_key = batch_key;
                e.journal_last_in_batch = whole_batch_windowed && (e.event_id == last_event_id);
            }
        }
    }

private:
    std::size_t capacity_;
    std::list<OutboxEntry> pending_;
    std::uint64_t backpressure_drops_{0};
};

} // namespace yuzu::agent
