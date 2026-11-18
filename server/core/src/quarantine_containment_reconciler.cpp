#include "quarantine_containment_reconciler.hpp"

#include "agent_registry.hpp"
#include "audit_store.hpp"
#include "quarantine_reapply.hpp"
#include "quarantine_store.hpp"
#include "response_store.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <expected>
#include <iterator>

namespace yuzu::server {

namespace {
std::int64_t default_now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::chrono::milliseconds next_backoff(std::chrono::milliseconds cur, std::chrono::milliseconds cap) {
    const auto doubled = cur * 2;
    return doubled > cap ? cap : doubled;
}

} // namespace

QuarantineContainmentReconciler::QuarantineContainmentReconciler(Deps deps) : d_(std::move(deps)) {}

std::int64_t QuarantineContainmentReconciler::now_epoch() const {
    return d_.now_fn ? d_.now_fn() : default_now_epoch();
}

std::chrono::milliseconds QuarantineContainmentReconciler::min_reapply_interval() const {
    return d_.min_reapply_interval_override.count() > 0 ? d_.min_reapply_interval_override
                                                        : kMinReapplyInterval;
}

std::chrono::milliseconds QuarantineContainmentReconciler::response_wait() const {
    return d_.response_wait_override.count() > 0 ? d_.response_wait_override : kResponseWait;
}

std::chrono::milliseconds QuarantineContainmentReconciler::verify_grace() const {
    return d_.verify_grace_override.count() > 0 ? d_.verify_grace_override : kVerifyGrace;
}

std::chrono::milliseconds QuarantineContainmentReconciler::reverify_interval() const {
    return d_.reverify_interval_override.count() > 0 ? d_.reverify_interval_override
                                                     : kReverifyInterval;
}

std::chrono::milliseconds QuarantineContainmentReconciler::max_backoff() const {
    return d_.max_backoff_override.count() > 0 ? d_.max_backoff_override : kMaxBackoff;
}

std::chrono::steady_clock::time_point QuarantineContainmentReconciler::steady_now() const {
    return d_.steady_now_fn ? d_.steady_now_fn() : std::chrono::steady_clock::now();
}

void QuarantineContainmentReconciler::reset_for(AgentState& st, Kind kind, std::int64_t record_id) {
    // An apply's claim outlives the entry's own state: the apply may not have run yet.
    auto held = std::move(st.held_claim);
    st = AgentState{};
    st.held_claim = std::move(held);
    st.kind = kind;
    st.record_id = record_id;
    // A releasing or owed entry reads status before it dispatches anything.
    st.verify_first = kind != Kind::active;
}

QuarantineContainmentReconciler::AgentState*
QuarantineContainmentReconciler::entry_for(const std::string& agent_id, const AgentState& c) {
    const auto it = state_.find(agent_id);
    if (it == state_.end() || it->second.kind != c.kind || it->second.record_id != c.record_id)
        return nullptr;
    return &it->second;
}

std::optional<std::vector<StoredResponse>>
QuarantineContainmentReconciler::poll_command(const std::string& pending_command_id,
                                              const std::string& agent_id) const {
    if (!d_.response_store)
        return std::nullopt;
    // #4990: internal consumer. Polls the reply to the reconciler's own firewall dispatch (the
    // closed protective set), never an operator read surface. The frozen site key in
    // test_response_store_read_tripwire.py is spelled `query(pending_command_id)`, and this is the
    // only such call: every poll of a command of ours goes through here.
    return d_.response_store->query(pending_command_id,
                                    ResponseTierFilter::unrestricted_internal_consumer(),
                                    ResponseQuery{.agent_id = agent_id});
}

void QuarantineContainmentReconciler::release_held_claim(const std::string& agent_id,
                                                         const AgentState& c) {
    if (c.held_claim.gen == 0 || !d_.quarantine_store)
        return;
    try {
        if (auto rel = d_.quarantine_store->release_apply_claim(agent_id, c.held_claim.record_id,
                                                                c.held_claim.gen);
            !rel)
            spdlog::warn("QuarantineContainmentReconciler: could not release the apply claim for "
                         "record {}: {}",
                         c.held_claim.record_id, rel.error());
    } catch (...) {
        spdlog::warn("QuarantineContainmentReconciler: releasing the apply claim for record {} "
                     "threw; it expires with the claim window",
                     c.held_claim.record_id);
    }
    std::lock_guard<std::mutex> lk(mu_);
    if (auto* st = entry_for(agent_id, c))
        st->held_claim = {};
}

void QuarantineContainmentReconciler::back_off(const std::string& agent_id, const AgentState& c,
                                               std::chrono::steady_clock::time_point now_steady,
                                               bool reverify) {
    std::lock_guard<std::mutex> lk(mu_);
    if (auto* st = entry_for(agent_id, c)) {
        st->backoff = next_backoff(st->backoff, max_backoff());
        st->next_eligible_at = now_steady + st->backoff;
        if (reverify)
            st->verify_first = true;
    }
}

void QuarantineContainmentReconciler::erase_if_current(const std::string& agent_id,
                                                       const AgentState& c) {
    std::lock_guard<std::mutex> lk(mu_);
    if (entry_for(agent_id, c))
        state_.erase(agent_id);
}

void QuarantineContainmentReconciler::seed_metrics(yuzu::MetricsRegistry& metrics) {
    // #3425: the reconciler's outcome series, seeded across its whole closed label set so that
    // `absent()` on any value can never be confused with "the reconciler has never run".
    for (const auto result : kQuarantineReapplyResults)
        metrics.counter("yuzu_server_quarantine_reapply_total", {{"result", std::string(result)}});
    // Per-replica gauges (never sum() across instances: each replica only sees the sessions its
    // own gRPC listener holds). Seeded at 0 for both label values so a healthy fleet with nothing
    // unconfirmed renders as an explicit 0, not an absent series.
    for (const char* reachability : {"connected", "offline"}) {
        metrics.gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", reachability}})
            .set(0);
        // Releasing records (a release asked for, the device not yet confirmed) and records an
        // operator ended by force whose device still owes a release.
        metrics.gauge("yuzu_server_quarantine_release_pending", {{"reachability", reachability}})
            .set(0);
        metrics.gauge("yuzu_server_quarantine_forced_release_owed", {{"reachability", reachability}})
            .set(0);
    }
    // Freshness signal for the gauges above (#3425 review, Doomgoose #3567): pre-seeded optimistic
    // (1) since the reconciler's thread starts within a boot-time window measured in seconds, not
    // minutes: a brief false-healthy read before the first real tick is a negligible tradeoff
    // against a 0 (falsely degraded) or an absent default.
    metrics.gauge("yuzu_server_quarantine_reconciler_tick_healthy").set(1);
    // #7623: when tick() last finished, so a thread that stopped ticking is visible. Seeded with
    // the boot time, so the stall alert does not fire before the first tick.
    metrics.gauge("yuzu_server_quarantine_reconciler_last_tick_unixtime")
        .set(static_cast<double>(default_now_epoch()));
}

void QuarantineContainmentReconciler::count(const char* result) const {
    if (d_.metrics)
        d_.metrics->counter("yuzu_server_quarantine_reapply_total", {{"result", result}})
            .increment();
}

void QuarantineContainmentReconciler::stamp_last_tick() const {
    // #7623: stamped on each of tick()'s three exits (no store, a degraded read, the end), never
    // from on_tick_exception: a tick that threw did not finish, and a stalled thread stamps nothing.
    if (d_.metrics)
        d_.metrics->gauge("yuzu_server_quarantine_reconciler_last_tick_unixtime")
            .set(static_cast<double>(now_epoch()));
}

void QuarantineContainmentReconciler::publish_tick_health(bool healthy) const {
    // #3425 review (Doomgoose, #3567): the freshness signal for
    // `yuzu_server_quarantine_endpoint_unconfirmed`, which otherwise
    // silently freezes at its last value on either early-return path in
    // tick() below.
    // 1 only on a tick that reached the real publish; 0 on either early
    // return. Not per-label — one series, tick()-only (notify_agent_heartbeat's
    // fast path never calls this: a cache-hit heartbeat says nothing about
    // whether the LAST tick's own read succeeded).
    if (d_.metrics)
        d_.metrics->gauge("yuzu_server_quarantine_reconciler_tick_healthy").set(healthy ? 1 : 0);
}

void QuarantineContainmentReconciler::audit_event(const std::string& agent_id,
                                                   const std::string& detail, const char* result,
                                                   const char* action) const {
    if (!d_.audit_store || !d_.audit_store->is_open())
        return;
    AuditEvent ev;
    ev.timestamp = default_now_epoch();
    ev.principal = "system";
    ev.action = action;
    ev.target_type = "Security";
    ev.target_id = agent_id;
    ev.detail = detail;
    ev.result = result;
    // #3425 governance re-review (unhappy-path, Finding UP-4): every call
    // site into this function exists specifically because a containment-
    // affecting system fact must not vanish with no trail (see
    // audit_unstamped's rationale) — a failed audit WRITE itself must not
    // be silent either, or the exact failure this function guards against
    // (store outage swallowing evidence) reproduces one layer up.
    if (!d_.audit_store->log(ev))
        spdlog::error("QuarantineContainmentReconciler: audit write failed for agent={} "
                     "action={} result={} detail={}",
                     agent_id, action, result, detail);
}

void QuarantineContainmentReconciler::audit_reapply(const std::string& agent_id,
                                                     std::int64_t record_id,
                                                     const std::string& command_id,
                                                     std::string_view trigger) const {
    audit_event(agent_id,
               "record_id=" + std::to_string(record_id) + " command_id=" + command_id +
                   " trigger=" + std::string(trigger),
               "success");
}

void QuarantineContainmentReconciler::audit_confirmed(const std::string& agent_id,
                                                       std::int64_t record_id,
                                                       const std::string& command_id) const {
    audit_event(agent_id,
               "CONFIRMED record_id=" + std::to_string(record_id) + " command_id=" + command_id,
               "success");
}

void QuarantineContainmentReconciler::audit_unstamped(const std::string& agent_id,
                                                       std::int64_t record_id,
                                                       const std::string& command_id,
                                                       std::string_view what,
                                                       const std::string& store_error,
                                                       const char* action) const {
    // #3425 governance Gate 2 (security-guardian): the observable, agent-
    // facing action described by `what` already happened by the time this
    // is called (a dispatch was accepted, or a status read confirmed
    // status|active) — that is a real containment-affecting system fact and
    // must leave an audit trail even though the durable stamp write failed,
    // or a transient store outage creates a silent gap in exactly the
    // evidence this verb exists to provide. `result="failure"` (not
    // "success") because the DURABLE record disagrees — audit and store
    // must never both claim more than what actually landed.
    audit_event(agent_id,
               std::string(what) + " record_id=" + std::to_string(record_id) +
                   " command_id=" + command_id + " but the durable stamp failed: " + store_error,
               "failure", action);
}

void QuarantineContainmentReconciler::tick() {
    if (!d_.quarantine_store) {
        // #3425 review (Doomgoose, #3567): both early returns below skip the
        // `yuzu_server_quarantine_endpoint_unconfirmed` publish entirely, so
        // that gauge silently FREEZES at its last value for the whole
        // duration of an outage rather than reflecting current (unknown)
        // state — exactly during the outage window an operator most needs
        // to distinguish "genuinely 0 unconfirmed" from "haven't been able
        // to check." `yuzu_server_quarantine_reconciler_tick_healthy` is
        // that freshness signal: 1 only on a tick that actually reached the
        // publish below, 0 on either early return.
        publish_tick_health(false);
        count("degraded");
        stamp_last_tick();
        return;
    }
    auto rows = d_.quarantine_store->list_quarantined();
    if (!rows) {
        // Fail closed: a degraded read is NEVER treated as "nothing active"
        // — that would silently stop reconciling every currently-contained
        // device for as long as the read stays degraded.
        publish_tick_health(false);
        count("degraded");
        stamp_last_tick();
        return;
    }
    // Records ended by force that still owe their device a release. A failed read here is not
    // fatal to the active work: it counts `degraded`, skips owed work for this tick and keeps
    // the owed entries (never reads as "nothing owed").
    auto owed_rows = d_.quarantine_store->list_release_owed();
    if (!owed_rows)
        count("degraded");

    std::unordered_set<std::string> active_ids;
    active_ids.reserve(rows->size());
    for (const auto& r : *rows)
        active_ids.insert(r.agent_id);
    std::unordered_set<std::string> owed_ids;
    if (owed_rows)
        for (const auto& r : *owed_rows)
            if (!active_ids.contains(r.agent_id)) // a device quarantined again is governed by its new record
                owed_ids.insert(r.agent_id);

    std::vector<std::string> to_reconcile;
    double unconfirmed_connected = 0;
    double unconfirmed_offline = 0;
    double releasing_connected = 0;
    double releasing_offline = 0;
    double owed_connected = 0;
    double owed_offline = 0;
    const auto now_steady = steady_now();
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = state_.begin(); it != state_.end();) {
            const bool keep = active_ids.contains(it->first) || owed_ids.contains(it->first) ||
                              (!owed_rows && it->second.kind == Kind::owed);
            if (!keep)
                it = state_.erase(it); // ended since the last tick
            else
                ++it;
        }
        for (const auto& r : *rows) {
            const auto& agent_id = r.agent_id;
            const Kind row_kind = r.release_requested_at != 0 ? Kind::releasing : Kind::active;
            auto [entry, inserted] = state_.try_emplace(agent_id); // a new entry reads unconfirmed
            auto& st = entry->second;
            // A different kind (a release was requested) or a different record (released, then
            // requarantined, possibly with another whitelist, while the agent stayed connected on
            // the same session) means nothing this entry learned is about this row: start over. A
            // releasing entry reads status before it dispatches anything.
            if (inserted || st.kind != row_kind || st.record_id != r.id)
                reset_for(st, row_kind, r.id);
            auto sess = d_.registry ? d_.registry->get_session(agent_id) : nullptr;
            const bool connected = sess != nullptr;
            if (row_kind == Kind::active && st.confirmed && connected) {
                // Session churn: a reconnect after a reboot wipes the endpoint's firewall rules
                // even though the record never changed — a stale "confirmed" would be a false
                // assurance. Verify via `status` first, not a blind re-apply, so a
                // still-genuinely-contained reconnect doesn't needlessly contend with the
                // agent-side mutation gate for no reason.
                // #5684: compared under the registry lock; an absent session is not churn.
                if (!d_.registry->session_is(agent_id, st.confirmed_session_id)) {
                    st.confirmed = false;
                    st.verify_first = true;
                } else if (st.pending == Pending::none &&
                           now_steady - st.confirmed_at >= reverify_interval()) {
                    // Re-verify without clearing `confirmed`, so the unconfirmed gauge and its
                    // alert do not blink on a healthy device. Not while a command is in flight:
                    // its reply is read first (a confirm then moves confirmed_at forward).
                    st.verify_first = true;
                }
            }
            // A confirmed entry is also revisited while a command of its own is in flight, so the
            // reply to a re-verify is read.
            const bool needs_work = !st.confirmed || st.verify_first || st.pending != Pending::none;
            if (row_kind == Kind::releasing) {
                (connected ? releasing_connected : releasing_offline) += 1;
                to_reconcile.push_back(agent_id);
            } else {
                if (!st.confirmed)
                    (connected ? unconfirmed_connected : unconfirmed_offline) += 1;
                if (needs_work)
                    to_reconcile.push_back(agent_id);
            }
        }
        if (owed_rows) {
            for (const auto& r : *owed_rows) {
                const auto& agent_id = r.agent_id;
                if (!owed_ids.contains(agent_id))
                    continue;
                auto [entry, inserted] = state_.try_emplace(agent_id);
                auto& st = entry->second;
                if (inserted || st.kind != Kind::owed || st.record_id != r.id)
                    reset_for(st, Kind::owed, r.id); // status before any release dispatch
                auto sess = d_.registry ? d_.registry->get_session(agent_id) : nullptr;
                if (!sess) {
                    owed_offline += 1; // nothing is sent to an offline device
                    continue;
                }
                owed_connected += 1;
                // A device whose release was sent (or that is parked after it) is sent a new
                // release only on a NEW session (a full cycle again); otherwise a parked one
                // gets a status-only read every max_backoff().
                if ((st.owed_release_sent || st.owed_parked) && d_.registry &&
                    !d_.registry->session_is(agent_id, st.owed_tried_session_id)) {
                    st.owed_release_sent = false;
                    st.owed_parked = false;
                    st.verify_first = true;
                }
                if (!st.owed_parked || now_steady >= st.next_eligible_at)
                    to_reconcile.push_back(agent_id);
            }
        }
    }
    {
        // The heartbeat fast path's view (#7619). Built first and swapped in AFTER mu_ is
        // released: the two mutexes are never held together, and cache_mu_ (taken by every
        // heartbeat) is held for a swap, not for building a set of every unconfirmed device. The
        // old set is freed outside it.
        IdSet unconfirmed(to_reconcile.begin(), to_reconcile.end());
        {
            std::lock_guard<std::mutex> lk(cache_mu_);
            unconfirmed_cache_.swap(unconfirmed);
        }
    }

    // Per-replica view — never sum() this series across server instances,
    // each replica only sees the sessions its own gRPC listener holds.
    if (d_.metrics) {
        d_.metrics
            ->gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
            .set(unconfirmed_connected);
        d_.metrics
            ->gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "offline"}})
            .set(unconfirmed_offline);
        d_.metrics->gauge("yuzu_server_quarantine_release_pending", {{"reachability", "connected"}})
            .set(releasing_connected);
        d_.metrics->gauge("yuzu_server_quarantine_release_pending", {{"reachability", "offline"}})
            .set(releasing_offline);
        // Not updated while the owed read is degraded: the last value stands, and the degraded
        // count above is the signal.
        if (owed_rows) {
            d_.metrics
                ->gauge("yuzu_server_quarantine_forced_release_owed", {{"reachability", "connected"}})
                .set(owed_connected);
            d_.metrics
                ->gauge("yuzu_server_quarantine_forced_release_owed", {{"reachability", "offline"}})
                .set(owed_offline);
        }
    }
    publish_tick_health(true);

    std::size_t dispatched = 0;
    for (std::size_t i = 0; i < to_reconcile.size(); ++i) {
        // governance Gate 5 (chaos-injector, Finding 4b): checked once per
        // iteration so a shutdown request can stop the loop from starting
        // ANOTHER agent's I/O sequence, rather than the loop being
        // uninterruptible for the whole tick — the in-flight reconcile_one
        // call itself still runs to completion, this only bounds how many
        // MORE of them one tick() call can start after a stop is requested.
        if (d_.should_stop && d_.should_stop()) {
            spdlog::info("QuarantineContainmentReconciler: tick stopping early on shutdown — "
                        "{} record(s) deferred",
                        to_reconcile.size() - i);
            break;
        }
        if (dispatched >= kMaxDispatchesPerTick) {
            spdlog::warn("QuarantineContainmentReconciler: tick hit kMaxDispatchesPerTick ({}) — "
                        "{} record(s) deferred to the next tick",
                        kMaxDispatchesPerTick, to_reconcile.size() - i);
            break;
        }
        if (reconcile_one(to_reconcile[i], "tick"))
            ++dispatched;
    }
    stamp_last_tick();
}

void QuarantineContainmentReconciler::on_tick_exception() const {
    // Gate 8 re-review (cpp-safety SHOULD + cpp-expert INFO, independently
    // converged): this runs from inside server.cpp's outer catch, where
    // nothing else catches — publish_tick_health()/count() are not noexcept
    // (both take a lock and touch an unordered_map), so a genuinely
    // pathological failure here (OOM, lock corruption) must not itself
    // escape and terminate the process on top of the tick() exception
    // already being handled.
    try {
        publish_tick_health(false);
        count("degraded");
    } catch (...) {
    }
}

void QuarantineContainmentReconciler::notify_agent_heartbeat(std::string_view agent_id_sv) {
    // A mark and nothing else (#7619): this runs on the heartbeat ingest path, so it must never
    // wait on a store read, a dispatch, or the lock reconcile work holds. The cache is looked up
    // by view, so a heartbeat from a device that is not under an unconfirmed record (nearly all of
    // them) allocates nothing; only a hit builds the string that is stored.
    std::lock_guard<std::mutex> lk(cache_mu_);
    if (unconfirmed_cache_.contains(agent_id_sv))
        heartbeat_due_.emplace(agent_id_sv);
}

std::size_t QuarantineContainmentReconciler::drain_heartbeat_due() {
    std::unordered_set<std::string> due;
    {
        std::lock_guard<std::mutex> lk(cache_mu_);
        due.swap(heartbeat_due_);
    }
    // A pass is bounded in TIME as well as in dispatches (UP-3). A degraded store read returns
    // false after up to a store read timeout and is not a dispatch, so with the pool stalled a
    // count alone lets one pass cost a timeout per marked device and holds the next tick off.
    // Counting every attempt instead would break the fair-cap rule (reconcile_one's note: a
    // skip-only device must not use up the budget). The budget is checked before each device, so
    // a device already started finishes.
    const auto deadline = steady_now() + kDrainTimeBudget;
    std::size_t dispatched = 0;
    // The marks this pass has not reached go back whether the pass ends on its budget or on an
    // exception, so a throw partway through delays them only until the next heartbeat or the next
    // periodic pass instead of dropping them.
    const auto merge_back = [this, &due]() {
        std::lock_guard<std::mutex> lk(cache_mu_);
        heartbeat_due_.merge(due);
    };
    try {
        while (!due.empty()) {
            if (d_.should_stop && d_.should_stop())
                break; // shutting down: a device still marked is reconciled by the next heartbeat
            if (dispatched >= kMaxDispatchesPerTick || steady_now() >= deadline) {
                merge_back(); // the pass is spent: the rest stay marked for the next drain
                break;
            }
            const auto agent = due.extract(due.begin());
            if (reconcile_one(agent.value(), "heartbeat"))
                ++dispatched;
        }
    } catch (...) {
        try {
            merge_back();
        } catch (...) {
        }
        throw;
    }
    return dispatched;
}

// ── An in-flight reply, by what was pending ──────────────────────────────────

void QuarantineContainmentReconciler::handle_mutation_reply(
    const std::string& agent_id, const AgentState& c, const ContainmentReply& reply,
    std::chrono::steady_clock::time_point now_steady) {
    // The reply to `firewall.quarantine` or `firewall.release`. Neither ends anything: no answer to
    // a release ends a record (only the device's `inactive` on a status read does), and dispatch
    // acceptance (agents_reached>0, already known when the command was issued) is not proof of
    // containment. So whatever it said, read status next, with the exceptions in
    // `decide_mutation_reply`.
    const auto action = decide_mutation_reply(MutationReplyFacts{
        .kind = c.kind,
        .was_apply = c.pending == Pending::apply,
        .apply_for_unconfirmed = c.apply_for_unconfirmed,
        .allow_set_unchanged = reply.allow_set_unchanged,
        .state = reply.state,
    });

    // An apply for a record that was never confirmed, answered with the device's note that it kept
    // other operator exceptions: the device is contained, but not under this record's whitelist, so
    // a status read would only confirm the wrong containment. Leave the record unconfirmed.
    if (action == MutationReplyAction::allow_set_kept && !c.allow_set_reported)
        audit_event(agent_id,
                    "allow_set_not_applied record_id=" + std::to_string(c.pending_record_id) +
                        " command_id=" + c.pending_command_id,
                    "failure");

    {
        std::lock_guard<std::mutex> lk(mu_);
        if (auto* st = entry_for(agent_id, c)) {
            st->pending = Pending::none;
            switch (action) {
            case MutationReplyAction::allow_set_kept:
                st->allow_set_reported = true;
                st->backoff = next_backoff(st->backoff, max_backoff());
                st->next_eligible_at = now_steady + st->backoff;
                break;
            case MutationReplyAction::owed_release_unspent:
                // The device did not run the owed release at all, so this session's one release is
                // not spent: send it again, status first, after an escalated backoff. Reading
                // status next with the release marked spent would park the device with a failure
                // row and no further release for the session.
                st->owed_release_sent = false;
                st->verify_first = true;
                st->backoff = next_backoff(st->backoff, max_backoff());
                st->next_eligible_at = now_steady + st->backoff;
                break;
            case MutationReplyAction::wait_claim_interval:
                // The plugin's mutation gate blocked the command: not a failure, just "already
                // busy". The entry waits for the normal claim interval before trying again.
                break;
            case MutationReplyAction::verify_next:
                // Verify soon, overriding the big claim-time interval so the follow-up isn't
                // delayed a full backoff cycle.
                st->verify_first = true;
                st->next_eligible_at = now_steady + verify_grace();
                break;
            }
        }
    }
    switch (action) {
    case MutationReplyAction::allow_set_kept:
        count("unconfirmed");
        break;
    case MutationReplyAction::owed_release_unspent:
    case MutationReplyAction::wait_claim_interval:
        count("busy");
        break;
    case MutationReplyAction::verify_next:
        break;
    }
}

void QuarantineContainmentReconciler::handle_status_reply(
    const std::string& agent_id, const AgentState& claimed, const ContainmentReply& reply,
    std::chrono::steady_clock::time_point now_steady) {
    // `c` starts as the copy the pass claimed; it becomes a releasing view of the entry if the
    // fresh read below finds a release was requested while the status command was in flight.
    AgentState c = claimed;
    const auto record = std::to_string(c.pending_record_id);
    const auto cmd = "command_id=" + c.pending_command_id;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (auto* st = entry_for(agent_id, c))
            st->pending = Pending::none;
    }

    // #7621: a confirmed record whose re-verify no longer confirms is not called drift on the
    // reply alone. The reply may describe a record that ended or began releasing while the status
    // command was in flight, so the row is read again first.
    if (c.kind == Kind::active && c.confirmed && !reply_confirms_containment(reply)) {
        auto fresh = d_.quarantine_store->get_status(agent_id);
        if (!fresh) {
            // Cannot tell drift from a release: no row, re-verify on the next cycle.
            back_off(agent_id, c, now_steady, /*reverify=*/true);
            count("degraded");
            return;
        }
        if (!fresh->has_value() || fresh->value().id != c.pending_record_id) {
            // Ended, or superseded by another record: nothing left to judge.
            erase_if_current(agent_id, c);
            return;
        }
        if (fresh->value().release_requested_at != 0) {
            // A release was requested after the status command was sent: handle the reply as the
            // releasing reply it now is. An `inactive` answer ends the record through the same
            // fenced write, with the token read before this command was dispatched.
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (auto* st = entry_for(agent_id, c))
                    reset_for(*st, Kind::releasing, c.pending_record_id);
            }
            c.kind = Kind::releasing;
            c.record_id = c.pending_record_id;
        }
    }

    const auto action = decide_status_reply(StatusReplyFacts{
        .kind = c.kind,
        .state = reply.state,
        .confirms = reply_confirms_containment(reply),
        .was_confirmed = c.confirmed,
        .owed_parked = c.owed_parked,
        .owed_release_sent = c.owed_release_sent,
    });

    // #7627: this reply is read every cycle for as long as a record lives. Only the four that
    // changed what the server holds about the device are kept at the default lifetime; the rest
    // are shortened. A failure to shorten is ignored: the row simply keeps the default lifetime.
    if (d_.response_store && !status_reply_is_evidence(action, c.confirmed))
        (void)d_.response_store->shorten_ttl(c.pending_command_id, agent_id, std::chrono::hours(24));

    const auto state_count = [&] {
        count(reply.state == QuarantineEndpointState::busy ? "busy" : "unconfirmed");
    };

    // The device answered `inactive` and `res` is the store write that settles the entry (the
    // caller made it, outside `mu_`, with the fence token read before the status command went
    // out). `kQuarantineNotQuarantined` means the record was ended elsewhere first: the entry goes.
    // `kQuarantineApplyInFlight` means an apply followed the observation: the end is refused,
    // nothing happened to the record, so there is no row and no counter, and the next cycle's
    // status read takes a fresh token. Any other failure backs off. Either way a refused or failed
    // observation is audited as unstamped; on success it is audited and the entry goes.
    const auto on_inactive = [&](const std::expected<void, std::string>& res,
                                 std::string_view unstamped_what, const std::string& ok_detail) {
        switch (classify_quarantine_write(res)) {
        case QuarantineWrite::ok:
            audit_event(agent_id, ok_detail, "success", "quarantine.disable");
            erase_if_current(agent_id, c);
            count("released");
            return;
        case QuarantineWrite::apply_in_flight:
            back_off(agent_id, c, now_steady, /*reverify=*/true);
            return;
        case QuarantineWrite::not_quarantined:
            erase_if_current(agent_id, c); // ended elsewhere first
            break;
        case QuarantineWrite::store_error:
            back_off(agent_id, c, now_steady);
            break;
        }
        audit_unstamped(agent_id, c.pending_record_id, c.pending_command_id, unstamped_what,
                        res.error(), "quarantine.disable");
        count("degraded");
    };

    switch (action) {
    // ── A record being released: only the device's `inactive` ends it ──
    case StatusReplyAction::end_record:
        on_inactive(d_.quarantine_store->mark_released(agent_id, c.pending_record_id,
                                                       ReleaseEnd::device_confirmed, c.pending_fence),
                    "status read confirmed the release",
                    "confirmed record_id=" + record + " " + cmd);
        return;
    case StatusReplyAction::release_next:
        // Still contained (or the device could not say): the next cycle dispatches release.
        back_off(agent_id, c, now_steady);
        state_count();
        return;

    // ── A record ended by force: the device still owes a release ──
    case StatusReplyAction::clear_owed:
        on_inactive(d_.quarantine_store->clear_release_owed(agent_id, c.pending_record_id,
                                                            c.pending_fence),
                    "status read confirmed the owed release",
                    "forced_release_confirmed record_id=" + record + " " + cmd);
        return;
    case StatusReplyAction::owed_keep_parked: {
        // A status-only read of a parked device that still is not inactive: nothing new to say.
        std::lock_guard<std::mutex> lk(mu_);
        if (auto* st = entry_for(agent_id, c)) {
            st->backoff = max_backoff();
            st->next_eligible_at = now_steady + st->backoff;
        }
        break;
    }
    case StatusReplyAction::owed_park: {
        // The release this session sent did not take: say so once, then park (a connected
        // device that cannot release is not sent one forever).
        audit_event(agent_id,
                    std::string("forced_release_unconfirmed status=") +
                        endpoint_state_name(reply.state) + " record_id=" + record,
                    "failure", "quarantine.disable");
        std::lock_guard<std::mutex> lk(mu_);
        if (auto* st = entry_for(agent_id, c)) {
            st->owed_parked = true;
            st->backoff = max_backoff();
            st->next_eligible_at = now_steady + st->backoff;
        }
        break;
    }
    case StatusReplyAction::owed_release_next:
        back_off(agent_id, c, now_steady); // the next cycle sends this session's release
        break;

    // ── An active record ──
    case StatusReplyAction::confirm: {
        // #3425 review K1/CDX-P1-02: the guarded UPDATE (WHERE status='active') affects zero rows
        // if the record was released concurrently, and can fail on a genuine store error — never
        // trust the in-memory "confirmed" transition on an unchecked write, or the reconciler can
        // believe a released/never-stamped device is confirmed for the rest of the process
        // lifetime. Also OUTSIDE mu_ (K10/CDX-P1-04): this is a blocking Postgres write + an
        // AuditStore write, and the class header promises no store/audit I/O runs while the lock
        // is held — multiple short lock/unlock cycles for the SAME agent within one reconcile_one
        // call are safe here because the claim already excludes any concurrent reconcile_one for
        // this agent_id.
        // #3425 governance re-review (unhappy-path, Finding UP-2): checked BEFORE the durable stamp
        // write, not after. The status response just parsed describes the session that was live
        // when the STATUS dispatch was SENT (`pending_session_id`) — a reboot landing between
        // dispatch and here would otherwise let evidence about a gone session get attributed to
        // the new one.
        const std::string confirmed_session_id =
            d_.registry ? d_.registry->session_id_of(agent_id) : std::string{};
        // Plain equality, not an empty-string special case: some deployment paths (and this
        // component's own test harness) never populate `AgentSession::session_id` at all, so
        // "both empty" must read as a match — only a genuine CHANGE is the signal.
        if (confirmed_session_id != c.pending_session_id) {
            back_off(agent_id, c, now_steady);
            audit_event(agent_id,
                        "status read confirmed containment but the session churned "
                        "between dispatch and confirm (dispatch_session=" +
                            c.pending_session_id + " confirm_session=" + confirmed_session_id +
                            ") record_id=" + record + " " + cmd,
                        "failure");
            count("unconfirmed");
            return;
        }
        auto mark_res =
            d_.quarantine_store->mark_endpoint_confirmed(agent_id, c.pending_record_id, now_epoch());
        if (!mark_res) {
            if (classify_quarantine_write(mark_res) == QuarantineWrite::not_quarantined)
                erase_if_current(agent_id, c); // released concurrently — nothing left to confirm
            else
                back_off(agent_id, c, now_steady);
            // The status read DID confirm — that observation is a real fact regardless of whether
            // the stamp landed, and must not vanish with no audit trail.
            audit_unstamped(agent_id, c.pending_record_id, c.pending_command_id,
                            "status read confirmed containment", mark_res.error());
            count("degraded");
            return;
        }
        // One CONFIRMED row per transition: a re-verify that confirms again stamps the store and
        // stays silent, so a contained device does not add an audit row every 5 minutes.
        if (!c.confirmed)
            audit_confirmed(agent_id, c.pending_record_id, c.pending_command_id);
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (auto* st = entry_for(agent_id, c)) {
                st->confirmed = true;
                st->confirmed_at = now_steady;
                st->confirmed_session_id = confirmed_session_id;
                st->backoff = min_reapply_interval();
            }
        }
        if (!c.confirmed)
            count("confirmed");
        return;
    }
    case StatusReplyAction::drift: {
        // DRIFT: a record that read confirmed no longer does, and a fresh read still shows it
        // active (`inactive` included: only a release ends a record, never a device's own state).
        // One audit row (the enumerator's name, never device text), then unconfirmed: the next
        // cycle re-applies through the chokepoint.
        audit_event(agent_id,
                    std::string("drift status=") + endpoint_state_name(reply.state) +
                        " record_id=" + record + " " + cmd,
                    "failure");
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (auto* st = entry_for(agent_id, c))
                st->confirmed = false;
        }
        back_off(agent_id, c, now_steady); // K9/CDX-P1-03: enforce the doubled wait on THIS claim's deadline
        count("drift");
        return;
    }
    case StatusReplyAction::stay_unconfirmed:
        back_off(agent_id, c, now_steady); // K9/CDX-P1-03: enforce the doubled wait on THIS claim's deadline
        state_count();
        return;
    }
    // The owed arms that only adjust the entry share this tail count.
    state_count();
}

// ── Sending ─────────────────────────────────────────────────────────────────

std::optional<std::string>
QuarantineContainmentReconciler::dispatch_bare(const std::string& agent_id,
                                               std::string_view action) {
    std::string command_id;
    int agents_reached = 0;
    bool threw = false;
    try {
        const auto outcome =
            d_.dispatch_fn(std::string(kContainmentPlugin), std::string(action), {agent_id},
                           /*scope_expr=*/"", /*parameters=*/{}, /*execution_id=*/"");
        command_id = outcome.command_id;
        agents_reached = outcome.sent;
    } catch (const std::exception&) {
        threw = true;
    }
    if (threw) {
        count("dispatch_error");
        return std::nullopt;
    }
    if (agents_reached == 0) {
        count("not_reached");
        return std::nullopt;
    }
    return command_id;
}

bool QuarantineContainmentReconciler::send_status(const std::string& agent_id,
                                                  const AgentState& c) {
    // Confirm the row is still what the entry thinks it is before dispatching (a read-only
    // status action has no whitelist to validate, so this doesn't go through
    // redispatch_stored_containment).
    auto status_res = d_.quarantine_store->get_status(agent_id);
    if (!status_res) {
        count("degraded");
        return false;
    }
    std::int64_t record_id = 0;
    if (c.kind == Kind::owed) {
        // An owed row has no active record: one that shows now means the device was quarantined
        // again, and its new record governs.
        if (status_res->has_value()) {
            erase_if_current(agent_id, c);
            return false;
        }
        record_id = c.record_id;
    } else {
        if (!status_res->has_value()) {
            erase_if_current(agent_id, c); // released since verify_first was set
            return false;
        }
        const auto& row = status_res->value();
        const Kind row_kind = row.release_requested_at != 0 ? Kind::releasing : Kind::active;
        if (row_kind != c.kind) {
            // A release was requested since the claim: this entry's view of the row is stale.
            std::lock_guard<std::mutex> lk(mu_);
            if (auto* st = entry_for(agent_id, c))
                reset_for(*st, row_kind, row.id);
            return false;
        }
        // #3425 governance Gate 4 (unhappy-path, Finding A), residual window:
        // `pending_record_id != 0` here means this verify follows a completed apply for a SPECIFIC
        // record. If the currently-active record's id no longer matches, the record was
        // released-and-requarantined since — dispatching a status check now and confirming it
        // against the CURRENT record would attribute "confirmed" to a record whose whitelist this
        // reconciler never actually applied. Bail; the new record re-enters fresh via the normal
        // apply path on the next tick/heartbeat.
        if (c.pending_record_id != 0 && row.id != c.pending_record_id) {
            erase_if_current(agent_id, c);
            return false;
        }
        record_id = row.id;
    }

    // #7613: the apply generation, read BEFORE the status command goes out, so the `inactive`
    // answer to it can only end the record if no apply was claimed after this point. Empty while an
    // apply's claim is live (the end is then refused and re-read). A failed read dispatches nothing:
    // a status command sent without a token could never end a record anyway.
    const auto fence = d_.quarantine_store->apply_fence_token(agent_id, record_id);
    if (!fence) {
        count("degraded");
        return false;
    }

    // #5684: read under the registry lock, BEFORE the dispatch, so a session swapped during the
    // dispatch call still mismatches at confirm time.
    const std::string dispatch_session_id = d_.registry->session_id_of(agent_id);
    const auto command_id = dispatch_bare(agent_id, kContainmentStatusAction);
    if (!command_id)
        return true; // a dispatch WAS attempted (it threw, or the registry reached nobody)
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (auto* st = entry_for(agent_id, c)) {
            st->pending = Pending::status;
            st->pending_command_id = *command_id;
            st->pending_fence = *fence;
            // The record this status dispatch is ABOUT is the one just read — carried forward so
            // the eventual stamp or end is scoped to it, not to whatever happens to be active by
            // then.
            st->pending_record_id = record_id;
            // The session live right now, at the moment this status dispatch is actually sent —
            // compared at confirm time against whatever session is live THEN.
            st->pending_session_id = dispatch_session_id;
            st->pending_since = steady_now();
            st->verify_first = false;
        }
    }
    count("reapplied");
    return true;
}

bool QuarantineContainmentReconciler::send_release(const std::string& agent_id,
                                                   const AgentState& c) {
    // A release is sent only for a row a FRESH read still shows as owing one: a releasing row
    // (same record, release requested) or an owed record with no active record for the device (a
    // device quarantined again is never sent a release; its new record governs).
    auto status_res = d_.quarantine_store->get_status(agent_id);
    if (!status_res) {
        count("degraded");
        return false;
    }
    std::int64_t record_id = c.record_id;
    if (c.kind == Kind::owed) {
        if (status_res->has_value() || record_id == 0) {
            erase_if_current(agent_id, c);
            return false;
        }
    } else {
        if (!status_res->has_value() || status_res->value().release_requested_at == 0 ||
            (record_id != 0 && status_res->value().id != record_id)) {
            // Not (or no longer) a releasing record: never dispatch a release.
            erase_if_current(agent_id, c);
            return false;
        }
        record_id = status_res->value().id;
    }

    const std::string dispatch_session_id = d_.registry->session_id_of(agent_id);
    const auto command_id = dispatch_bare(agent_id, kContainmentReleaseAction);
    if (!command_id)
        return true; // a dispatch WAS attempted (it threw, or the registry reached nobody)
    // #7625: the row is written for the first release of an agent session, not for every cycle of
    // a device that keeps refusing it (the counter below still counts every dispatch). An owed
    // entry's own state machine already sends one release per session.
    const bool owed = c.kind == Kind::owed;
    if (owed || !(c.release_audited && c.release_audited_session_id == dispatch_session_id))
        audit_event(agent_id,
                    std::string(owed ? "forced_release_sent" : "release_sent") +
                        " record_id=" + std::to_string(record_id) + " command_id=" + *command_id,
                    "pending", "quarantine.disable");
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (auto* st = entry_for(agent_id, c)) {
            st->pending = Pending::release;
            st->pending_command_id = *command_id;
            st->pending_record_id = record_id;
            st->pending_session_id = dispatch_session_id;
            st->pending_since = steady_now();
            if (owed) {
                st->owed_tried_session_id = dispatch_session_id; // this session's one release cycle
                st->owed_release_sent = true;
            } else {
                st->release_audited = true;
                st->release_audited_session_id = dispatch_session_id;
            }
        }
    }
    count("release_sent");
    return true;
}

bool QuarantineContainmentReconciler::send_apply(const std::string& agent_id, const AgentState& c,
                                                 std::string_view trigger) {
    // Re-drive the STORED whitelist via the one shared recipe (quarantine_reapply.hpp) — the same
    // chokepoint MCP's already_active retry path uses, so the stored-whitelist-only invariant
    // lives in exactly one function. The chokepoint also claims the apply (#7613).
    //
    // An apply of ours that timed out unanswered still holds its claim (it may not have run), so a
    // retry inside the claim window is refused by the chokepoint (no_active_record) and the claim
    // expires on its own; it is deliberately not dropped here, because that apply may still be
    // waiting to run.
    QuarantineRecord stored{};
    auto reapply_res = redispatch_stored_containment(
        *d_.quarantine_store, agent_id,
        [&](const std::unordered_map<std::string, std::string>& params)
            -> std::pair<std::string, int> {
            // ReapplyDispatchFn's narrower pair shape is deliberate here — see
            // that typedef's own doc comment; #3424/#3511's richer discriminators
            // are for a caller that decides retry semantics from THIS call's
            // result, which this reconciler tick does not (it already treats
            // agents_reached==0 uniformly as "not reached" below).
            const auto outcome = d_.dispatch_fn(std::string(kContainmentPlugin),
                                                std::string(kContainmentApplyAction), {agent_id},
                                                /*scope_expr=*/"", params, /*execution_id=*/"");
            return {outcome.command_id, outcome.sent};
        },
        stored);
    if (!reapply_res) {
        switch (reapply_res.error().kind) {
        case ContainmentReapplyErrorKind::store_error:
            count("degraded");
            break;
        case ContainmentReapplyErrorKind::no_active_record: {
            // Released between the tick snapshot and this call, or the apply claim was refused
            // (the record changed, or another apply is in flight): the entry goes and the next
            // tick re-derives it.
            erase_if_current(agent_id, c);
            break;
        }
        case ContainmentReapplyErrorKind::release_pending: {
            // A release was requested since the tick snapshot: containment is not re-applied under
            // it. Start over as a releasing entry (status first); nothing was dispatched.
            std::lock_guard<std::mutex> lk(mu_);
            if (auto* st = entry_for(agent_id, c))
                reset_for(*st, Kind::releasing, stored.id);
            break;
        }
        case ContainmentReapplyErrorKind::whitelist_invalid:
            count("validation_failed");
            back_off(agent_id, c, steady_now());
            // The value is never echoed: it is what the mapper refused.
            audit_event(agent_id,
                        "stored whitelist cannot be expressed as firewall exceptions record_id=" +
                            std::to_string(stored.id),
                        "failure");
            break;
        }
        return false; // no dispatch_fn call was ever made on any of these branches
    }
    if (reapply_res->dispatch_threw) {
        count("dispatch_error");
        return true; // a dispatch WAS attempted
    }
    if (reapply_res->agents_reached == 0) {
        count("not_reached");
        return true; // dispatch attempted; registry just didn't reach anyone
    }
    // #3425 review K2/CDX-P1-02: same discipline as the confirm branch — a failed guarded UPDATE
    // (released concurrently, superseded by a requarantine, or a genuine store error) must not
    // leave the reconciler believing an apply is durably recorded and polling ResponseStore for a
    // command whose record is gone. `stored.id` (governance Gate 4, unhappy-path Finding A) scopes
    // the write to the record this dispatch was actually built from.
    auto mark_res = d_.quarantine_store->mark_endpoint_applied(agent_id, stored.id, now_epoch());
    if (!mark_res) {
        if (classify_quarantine_write(mark_res) == QuarantineWrite::not_quarantined) {
            // Released, OR superseded by a requarantine, concurrently: the dispatch already fired
            // but there is nothing left here to track as pending; the current active record (if
            // any) re-enters fresh via the normal apply path on the next tick/heartbeat. The
            // apply claim made the record's generation move, so a release that was waiting on an
            // older observation could not end it on that observation (#7613).
            erase_if_current(agent_id, c);
        } else {
            // #3425 governance Gate 3 (cpp-safety, finding C): mirror the confirm branch's backoff
            // escalation — without this, a sustained QuarantineStore write outage re-dispatches a
            // fresh apply every fixed kMinReapplyInterval instead of backing off like every other
            // repeated-failure path in this state machine.
            back_off(agent_id, c, steady_now());
        }
        // #3425 governance Gate 2 (security-guardian): the dispatch WAS accepted
        // (agents_reached>0, checked above) — a real containment-affecting system action already
        // happened and must not vanish with no audit trail just because the store stamp failed.
        audit_unstamped(agent_id, stored.id, reapply_res->command_id, "dispatch accepted",
                        mark_res.error());
        count("degraded");
        return true; // the dispatch itself was still attempted
    }
    audit_reapply(agent_id, stored.id, reapply_res->command_id, trigger);
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (auto* st = entry_for(agent_id, c)) {
            st->pending = Pending::apply;
            st->pending_command_id = reapply_res->command_id;
            // #3425 governance Gate 4 (unhappy-path, Finding A): carried forward into the eventual
            // verify -> mark_endpoint_confirmed call too (the confirm is ABOUT the record whose
            // whitelist was just applied).
            st->pending_record_id = stored.id;
            st->held_claim = {reapply_res->held_claim_gen, stored.id, reapply_res->command_id};
            st->apply_for_unconfirmed = stored.last_confirmed_at == 0;
            st->pending_since = steady_now();
        }
    }
    count("reapplied");
    return true;
}

bool QuarantineContainmentReconciler::reconcile_one(const std::string& agent_id,
                                                     std::string_view trigger) {
    if (!d_.quarantine_store || !d_.dispatch_fn)
        return false;

    // Claim-then-act (Guardian heartbeat reconcile precedent, server.cpp):
    // the rate-limit slot is claimed UNDER THE LOCK before any I/O, so a
    // tick and a heartbeat racing for the same agent cannot both dispatch —
    // the second caller sees the already-claimed `next_eligible_at` and
    // bails immediately. This is the concrete mechanism behind "a busy gate
    // does not spin". An agent with no entry has nothing to reconcile (only
    // tick() creates entries), so nothing is created here.
    AgentState c;
    {
        std::lock_guard<std::mutex> lk(mu_);
        const auto it = state_.find(agent_id);
        if (it == state_.end())
            return false;
        auto& st = it->second;
        const auto now_steady = steady_now();
        if (now_steady < st.next_eligible_at) {
            count("rate_limited");
            return false;
        }
        if (st.backoff.count() == 0)
            st.backoff = min_reapply_interval(); // first-ever claim for this agent
        st.next_eligible_at = now_steady + st.backoff;
        // What reconcile_one reads about the entry from here on: nothing is read under a lock
        // again after the claim, and every write back goes through entry_for(agent_id, c).
        c = st;
    }
    // A parked owed device is only ever read, never sent another release in the same session.
    if (c.kind == Kind::owed && c.owed_parked)
        c.verify_first = true;

    // An apply of ours still holds its claim, and the entry is no longer waiting on it (a release
    // request turned the entry into a releasing one before the reply was read): drop the claim
    // once that apply's answer is in. The answer is the device's `status|` line; a stored row
    // without one (progress text for a redelivered command that is still in flight) is not proof
    // the apply ran. Until then no token is issued and no end is accepted, which is the point of
    // holding it. Nothing is dispatched or decided here.
    if (c.held_claim.gen != 0 && d_.response_store &&
        !(c.pending == Pending::apply && c.pending_command_id == c.held_claim.command_id)) {
        const auto held = poll_command(c.held_claim.command_id, agent_id);
        if (held && !held->empty() && parse_containment_reply(combined_output(*held)).status_seen)
            release_held_claim(agent_id, c);
    }

    // ── An in-flight command: poll for its response, dispatch nothing new ──
    if (c.pending != Pending::none) {
        const auto resp = poll_command(c.pending_command_id, agent_id);
        if (!resp) {
            // #3425 review, sharpened at Gate 5 (gate4-response-store-degradation-freezes-timeout):
            // pending_since is deliberately NOT touched here — the moment response_store recovers,
            // `timed_out` below is computed against the ORIGINAL pending_since and resolves in one
            // shot, so this is not an indefinite stall. What WAS missing: every other repeated-
            // failure path in this state machine escalates backoff so a SUSTAINED failure retries
            // less often over time — a sustained response_store outage instead retried at a flat
            // ~60s cadence forever. `st.pending` stays untouched (the command genuinely is still
            // pending; this round simply couldn't check its status).
            back_off(agent_id, c, steady_now());
            count("degraded");
            return false;
        }
        const auto now_steady = steady_now();
        const bool timed_out = (now_steady - c.pending_since) >= response_wait();
        if (resp->empty()) {
            if (!timed_out) {
                count("pending"); // no re-dispatch — the no-spin contract
                return false;
            }
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (auto* st = entry_for(agent_id, c)) {
                    st->pending = Pending::none;
                    st->verify_first = false;
                    st->backoff = next_backoff(st->backoff, max_backoff());
                    // #3425 review K9/CDX-P1-03: enforce the just-doubled wait on THIS claim's
                    // deadline now, not only on some future claim — otherwise the very next
                    // heartbeat/tick retries immediately.
                    st->next_eligible_at = now_steady + st->backoff;
                }
            }
            count("not_reached");
            return false;
        }

        const auto reply = parse_containment_reply(combined_output(*resp));
        // The device's answer to the apply is in hand (a `status|` line, even a refusal): it ran,
        // or was refused before it could, so its claim can go and a confirmed end is possible
        // again. A row without one is not proof, so the claim stays. (A timed-out apply keeps the
        // claim until it expires: it may not have run.)
        if (c.pending == Pending::apply && c.pending_command_id == c.held_claim.command_id &&
            reply.status_seen)
            release_held_claim(agent_id, c);
        switch (c.pending) {
        case Pending::apply:
        case Pending::release:
            handle_mutation_reply(agent_id, c, reply, now_steady);
            break;
        case Pending::status:
            handle_status_reply(agent_id, c, reply, now_steady);
            break;
        case Pending::none:
            break;
        }
        return false;
    }

    // ── No in-flight command: reachability first, no store I/O if offline ──
    auto session = d_.registry ? d_.registry->get_session(agent_id) : nullptr;
    if (!session) {
        // #3425 governance Gate 4 (happy-path): an offline skip never actually attempted anything
        // (same K11/CDX-P1-05 reasoning already applied to the per-tick dispatch cap, now applied
        // to the per-agent CLAIM) — release it immediately rather than let it hold the full claim
        // window, or the FIRST heartbeat after a genuine reconnect can inherit a stale offline
        // tick's window and sit rate_limited for up to that long. Safe: offline agents don't
        // heartbeat, so nothing re-drives this before the next ~20s tick; backoff itself is
        // untouched, so a flapping device still can't spin faster than its own reconnect cadence.
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (auto* st = entry_for(agent_id, c))
                st->next_eligible_at = steady_now();
        }
        count("offline");
        return false;
    }

    if (c.verify_first)
        return send_status(agent_id, c);
    if (c.kind == Kind::active)
        return send_apply(agent_id, c, trigger);
    return send_release(agent_id, c);
}

} // namespace yuzu::server
