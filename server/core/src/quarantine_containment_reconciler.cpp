#include "quarantine_containment_reconciler.hpp"

#include "agent_registry.hpp"
#include "audit_store.hpp"
#include "quarantine_reapply.hpp"
#include "quarantine_store.hpp"
#include "response_store.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <chrono>

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

// Concatenates every returned response row's `output` in oldest-first order
// (the store returns newest-first) so a multi-frame status response reads as
// one payload for `parse_containment_reply`.
std::string combined_output(const std::vector<StoredResponse>& rows) {
    std::string out;
    for (auto it = rows.rbegin(); it != rows.rend(); ++it) {
        if (!out.empty())
            out += '\n';
        out += it->output;
    }
    return out;
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

void QuarantineContainmentReconciler::back_off(const std::string& agent_id,
                                               std::chrono::steady_clock::time_point steady_now) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& st = state_[agent_id];
    st.backoff = next_backoff(st.backoff, max_backoff());
    st.next_eligible_at = steady_now + st.backoff;
}

void QuarantineContainmentReconciler::count(const char* result) const {
    if (d_.metrics)
        d_.metrics->counter("yuzu_server_quarantine_reapply_total", {{"result", result}})
            .increment();
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
        return;
    }
    auto rows = d_.quarantine_store->list_quarantined();
    if (!rows) {
        // Fail closed: a degraded read is NEVER treated as "nothing active"
        // — that would silently stop reconciling every currently-contained
        // device for as long as the read stays degraded.
        publish_tick_health(false);
        count("degraded");
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
    const auto steady_now = std::chrono::steady_clock::now();
    const auto epoch_now = now_epoch();
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
            auto& st = state_[agent_id]; // default-constructs an unconfirmed entry
            // A different kind (a release was requested) or a different record (released, then
            // requarantined, possibly with another whitelist, while the agent stayed connected on
            // the same session) means nothing this entry learned is about this row: start over. A
            // releasing entry reads status before it dispatches anything.
            if (st.kind != row_kind || (st.record_id != 0 && st.record_id != r.id)) {
                st = AgentState{};
                st.kind = row_kind;
                st.verify_first = row_kind == Kind::releasing;
            }
            st.record_id = r.id;
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
                           steady_now - st.confirmed_at >= reverify_interval()) {
                    // Re-verify without clearing `confirmed`, so the unconfirmed gauge and its
                    // alert do not blink on a healthy device. Not while a command is in flight:
                    // its reply is read first (a confirm then moves confirmed_at forward).
                    st.verify_first = true;
                }
            }
            // A stored device time limit that has run out: read status once before anything is
            // re-applied (a restarted server has `confirmed=false` and would otherwise re-apply
            // straight away to a device whose limit has passed). Offline: nothing to read yet.
            if (row_kind == Kind::active && !st.lapse_checked && connected &&
                st.pending == Pending::none && device_limit_lapsed(r.endpoint_ttl_expires, epoch_now))
                st.verify_first = true;
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
                auto& st = state_[agent_id];
                if (st.kind != Kind::owed || st.record_id != r.id) {
                    st = AgentState{};
                    st.kind = Kind::owed;
                    st.record_id = r.id;
                    st.verify_first = true; // status before any release dispatch
                }
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
                if (!st.owed_parked || steady_now >= st.next_eligible_at)
                    to_reconcile.push_back(agent_id);
            }
        }
        unconfirmed_cache_ =
            std::unordered_set<std::string>(to_reconcile.begin(), to_reconcile.end());
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
    const std::string agent_id(agent_id_sv);
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!unconfirmed_cache_.contains(agent_id))
            return; // fast path: no record needing work — no store read
    }
    (void)reconcile_one(agent_id, "heartbeat"); // no per-tick budget to track on this path
}

// ── An in-flight reply, by what was pending ──────────────────────────────────

void QuarantineContainmentReconciler::handle_apply_reply(
    const std::string& agent_id, const ContainmentReply& reply,
    std::chrono::steady_clock::time_point steady_now) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& st = state_[agent_id];
    st.pending = Pending::none;
    if (reply.state == QuarantineEndpointState::busy) {
        // The plugin's mutation gate blocked the apply — not a failure, just "already busy being
        // quarantined". Wait for the normal claim interval before trying again.
        count("busy");
        return;
    }
    // Dispatch acceptance (agents_reached>0, already known when this command was issued) is not
    // proof of containment — verify soon, overriding the big claim-time interval so the
    // follow-up isn't delayed a full backoff cycle.
    st.verify_first = true;
    st.next_eligible_at = steady_now + verify_grace();
}

void QuarantineContainmentReconciler::handle_release_reply(
    const std::string& agent_id, const ContainmentReply& reply,
    std::chrono::steady_clock::time_point steady_now) {
    // No answer to `firewall.release` ends anything: only the device's `inactive` on a status
    // read does. So whatever it said, read status next.
    std::lock_guard<std::mutex> lk(mu_);
    auto& st = state_[agent_id];
    st.pending = Pending::none;
    if (reply.state == QuarantineEndpointState::busy) {
        count("busy");
        return;
    }
    st.verify_first = true;
    st.next_eligible_at = steady_now + verify_grace();
}

void QuarantineContainmentReconciler::handle_status_reply(
    const std::string& agent_id, const Claim& c, const ContainmentReply& reply,
    std::chrono::steady_clock::time_point steady_now) {
    const auto record = std::to_string(c.pending_record_id);
    const auto cmd = "command_id=" + c.pending_command_id;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto& st = state_[agent_id];
        st.pending = Pending::none;
        if (c.kind == Kind::active)
            st.lapse_checked = true;
    }

    // ── A record being released: only the device's `inactive` ends it ──
    if (c.kind == Kind::releasing) {
        if (reply.state == QuarantineEndpointState::inactive) {
            auto res = d_.quarantine_store->mark_released(agent_id, c.pending_record_id,
                                                          ReleaseEnd::device_confirmed);
            if (!res) {
                if (res.error() == "device is not quarantined") {
                    std::lock_guard<std::mutex> lk(mu_);
                    state_.erase(agent_id); // ended elsewhere first
                } else {
                    back_off(agent_id, steady_now);
                }
                audit_unstamped(agent_id, c.pending_record_id, c.pending_command_id,
                                "status read confirmed the release", res.error(),
                                "quarantine.disable");
                count("degraded");
                return;
            }
            audit_event(agent_id, "confirmed record_id=" + record + " " + cmd, "success",
                        "quarantine.disable");
            {
                std::lock_guard<std::mutex> lk(mu_);
                state_.erase(agent_id);
            }
            count("released");
            return;
        }
        // Still contained (or the device could not say): the next cycle dispatches release.
        back_off(agent_id, steady_now);
        count(reply.state == QuarantineEndpointState::busy ? "busy" : "unconfirmed");
        return;
    }

    // ── A record ended by force: the device still owes a release ──
    if (c.kind == Kind::owed) {
        if (reply.state == QuarantineEndpointState::inactive) {
            auto res = d_.quarantine_store->clear_release_owed(agent_id, c.pending_record_id);
            if (!res) {
                if (res.error() == "device is not quarantined") {
                    std::lock_guard<std::mutex> lk(mu_);
                    state_.erase(agent_id);
                } else {
                    back_off(agent_id, steady_now);
                }
                audit_unstamped(agent_id, c.pending_record_id, c.pending_command_id,
                                "status read confirmed the owed release", res.error(),
                                "quarantine.disable");
                count("degraded");
                return;
            }
            audit_event(agent_id, "forced_release_confirmed record_id=" + record + " " + cmd,
                        "success", "quarantine.disable");
            {
                std::lock_guard<std::mutex> lk(mu_);
                state_.erase(agent_id);
            }
            count("released");
            return;
        }
        if (c.owed_parked) {
            // A status-only read of a parked device that still is not inactive: nothing new to say.
            std::lock_guard<std::mutex> lk(mu_);
            auto& st = state_[agent_id];
            st.backoff = max_backoff();
            st.next_eligible_at = steady_now + st.backoff;
        } else if (c.owed_release_sent) {
            // The release this session sent did not take: say so once, then park (a connected
            // device that cannot release is not sent one forever).
            audit_event(agent_id,
                        std::string("forced_release_unconfirmed status=") + endpoint_state_name(reply.state) +
                            " record_id=" + record,
                        "failure", "quarantine.disable");
            std::lock_guard<std::mutex> lk(mu_);
            auto& st = state_[agent_id];
            st.owed_parked = true;
            st.backoff = max_backoff();
            st.next_eligible_at = steady_now + st.backoff;
        } else {
            back_off(agent_id, steady_now); // the next cycle sends this session's release
        }
        count(reply.state == QuarantineEndpointState::busy ? "busy" : "unconfirmed");
        return;
    }

    // ── An active record ──
    if (reply_confirms_containment(reply)) {
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
            back_off(agent_id, steady_now);
            audit_event(agent_id,
                        "status read confirmed containment but the session churned "
                        "between dispatch and confirm (dispatch_session=" +
                            c.pending_session_id + " confirm_session=" + confirmed_session_id +
                            ") record_id=" + record + " " + cmd,
                        "failure");
            count("unconfirmed");
            return;
        }
        auto mark_res = d_.quarantine_store->mark_endpoint_confirmed(
            agent_id, c.pending_record_id, now_epoch(), reply.ttl_expires);
        if (!mark_res) {
            if (mark_res.error() == "device is not quarantined") {
                std::lock_guard<std::mutex> lk(mu_);
                state_.erase(agent_id); // released concurrently — nothing left to confirm
            } else {
                back_off(agent_id, steady_now);
            }
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
            auto& st = state_[agent_id];
            st.confirmed = true;
            st.confirmed_at = steady_now;
            st.confirmed_session_id = confirmed_session_id;
            st.backoff = min_reapply_interval();
        }
        if (!c.confirmed)
            count("confirmed");
        return;
    }

    if (reply.state == QuarantineEndpointState::inactive &&
        device_limit_lapsed(c.pending_ttl_expires, now_epoch())) {
        // The device's own time limit ran out (a stored limit proves an earlier confirm, so this
        // holds whether or not the entry was confirmed in memory): the record ends, audited as the
        // system, and nothing is re-applied.
        auto res = d_.quarantine_store->mark_released(agent_id, c.pending_record_id,
                                                      ReleaseEnd::device_confirmed);
        if (!res) {
            if (res.error() == "device is not quarantined") {
                std::lock_guard<std::mutex> lk(mu_);
                state_.erase(agent_id);
            } else {
                back_off(agent_id, steady_now);
            }
            audit_unstamped(agent_id, c.pending_record_id, c.pending_command_id,
                            "status read found the device time limit run out", res.error(),
                            "quarantine.disable");
            count("degraded");
            return;
        }
        audit_event(agent_id,
                    "ttl_expired ttl_expires=" + std::to_string(c.pending_ttl_expires) +
                        " record_id=" + record + " " + cmd,
                    "success", "quarantine.disable");
        {
            std::lock_guard<std::mutex> lk(mu_);
            state_.erase(agent_id);
        }
        count("released");
        return;
    }

    if (c.confirmed) {
        // DRIFT: a record that read confirmed no longer does. One audit row (the enumerator's
        // name, never device text), then unconfirmed: the next cycle re-applies through the
        // chokepoint.
        audit_event(agent_id,
                    std::string("drift status=") + endpoint_state_name(reply.state) + " record_id=" + record +
                        " " + cmd,
                    "failure");
        {
            std::lock_guard<std::mutex> lk(mu_);
            state_[agent_id].confirmed = false;
        }
    }
    back_off(agent_id, steady_now); // K9/CDX-P1-03: enforce the doubled wait on THIS claim's deadline
    count(reply.state == QuarantineEndpointState::busy ? "busy" : "unconfirmed");
}

// ── Sending ─────────────────────────────────────────────────────────────────

bool QuarantineContainmentReconciler::send_status(const std::string& agent_id, const Claim& c) {
    // Confirm the row is still what the entry thinks it is before dispatching (a read-only
    // status action has no whitelist to validate, so this doesn't go through
    // redispatch_stored_containment).
    auto status_res = d_.quarantine_store->get_status(agent_id);
    if (!status_res) {
        count("degraded");
        return false;
    }
    std::int64_t record_id = 0;
    std::int64_t ttl_expires = 0;
    if (c.kind == Kind::owed) {
        // An owed row has no active record: one that shows now means the device was quarantined
        // again, and its new record governs.
        if (status_res->has_value()) {
            std::lock_guard<std::mutex> lk(mu_);
            state_.erase(agent_id);
            return false;
        }
        record_id = c.record_id;
    } else {
        if (!status_res->has_value()) {
            std::lock_guard<std::mutex> lk(mu_);
            state_.erase(agent_id); // released since verify_first was set
            return false;
        }
        const auto& row = status_res->value();
        const Kind row_kind = row.release_requested_at != 0 ? Kind::releasing : Kind::active;
        if (row_kind != c.kind) {
            // A release was requested since the claim: this entry's view of the row is stale.
            std::lock_guard<std::mutex> lk(mu_);
            auto& st = state_[agent_id];
            st = AgentState{};
            st.kind = row_kind;
            st.record_id = row.id;
            st.verify_first = row_kind == Kind::releasing;
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
            std::lock_guard<std::mutex> lk(mu_);
            state_.erase(agent_id);
            return false;
        }
        record_id = row.id;
        ttl_expires = row.endpoint_ttl_expires;
    }

    std::string command_id;
    int agents_reached = 0;
    bool threw = false;
    // #5684: read under the registry lock, BEFORE the dispatch, so a session swapped during the
    // dispatch call still mismatches at confirm time.
    const std::string dispatch_session_id = d_.registry->session_id_of(agent_id);
    try {
        const auto outcome = d_.dispatch_fn(std::string(kContainmentPlugin),
                                            std::string(kContainmentStatusAction), {agent_id},
                                            /*scope_expr=*/"", /*parameters=*/{}, /*execution_id=*/"");
        command_id = outcome.command_id;
        agents_reached = outcome.sent;
    } catch (const std::exception&) {
        threw = true;
    }
    if (threw) {
        count("dispatch_error");
        return true; // a dispatch WAS attempted, even though it threw
    }
    if (agents_reached == 0) {
        count("not_reached");
        return true; // dispatch attempted; registry just didn't reach anyone
    }
    std::lock_guard<std::mutex> lk(mu_);
    auto& st = state_[agent_id];
    st.pending = Pending::status;
    st.pending_command_id = command_id;
    // The record this status dispatch is ABOUT is the one just read — carried forward so the
    // eventual stamp or end is scoped to it, not to whatever happens to be active by then.
    st.pending_record_id = record_id;
    st.pending_ttl_expires = ttl_expires;
    // The session live right now, at the moment this status dispatch is actually sent — compared
    // at confirm time against whatever session is live THEN.
    st.pending_session_id = dispatch_session_id;
    st.pending_since = std::chrono::steady_clock::now();
    st.verify_first = false;
    count("reapplied");
    return true;
}

bool QuarantineContainmentReconciler::send_release(const std::string& agent_id, const Claim& c) {
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
            std::lock_guard<std::mutex> lk(mu_);
            state_.erase(agent_id);
            return false;
        }
    } else {
        if (!status_res->has_value() || status_res->value().release_requested_at == 0 ||
            (record_id != 0 && status_res->value().id != record_id)) {
            std::lock_guard<std::mutex> lk(mu_);
            state_.erase(agent_id); // not (or no longer) a releasing record: never dispatch a release
            return false;
        }
        record_id = status_res->value().id;
    }

    std::string command_id;
    int agents_reached = 0;
    bool threw = false;
    const std::string dispatch_session_id = d_.registry->session_id_of(agent_id);
    try {
        const auto outcome = d_.dispatch_fn(std::string(kContainmentPlugin),
                                            std::string(kContainmentReleaseAction), {agent_id},
                                            /*scope_expr=*/"", /*parameters=*/{}, /*execution_id=*/"");
        command_id = outcome.command_id;
        agents_reached = outcome.sent;
    } catch (const std::exception&) {
        threw = true;
    }
    if (threw) {
        count("dispatch_error");
        return true;
    }
    if (agents_reached == 0) {
        count("not_reached");
        return true;
    }
    audit_event(agent_id,
                std::string(c.kind == Kind::owed ? "forced_release_sent" : "release_sent") +
                    " record_id=" + std::to_string(record_id) + " command_id=" + command_id,
                "pending", "quarantine.disable");
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto& st = state_[agent_id];
        st.pending = Pending::release;
        st.pending_command_id = command_id;
        st.pending_record_id = record_id;
        st.pending_session_id = dispatch_session_id;
        st.pending_since = std::chrono::steady_clock::now();
        if (c.kind == Kind::owed) {
            st.owed_tried_session_id = dispatch_session_id; // this session's one release cycle
            st.owed_release_sent = true;
        }
    }
    count("release_sent");
    return true;
}

bool QuarantineContainmentReconciler::send_apply(const std::string& agent_id, const Claim&,
                                                 std::string_view trigger) {
    // Re-drive the STORED whitelist via the one shared recipe (quarantine_reapply.hpp) — the same
    // chokepoint MCP's already_active retry path uses, so the stored-whitelist-only invariant
    // lives in exactly one function.
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
            std::lock_guard<std::mutex> lk(mu_);
            state_.erase(agent_id); // released between the tick snapshot and this call
            break;
        }
        case ContainmentReapplyErrorKind::release_pending: {
            // A release was requested since the tick snapshot: containment is not re-applied under
            // it. Start over as a releasing entry (status first); nothing was dispatched.
            std::lock_guard<std::mutex> lk(mu_);
            auto& st = state_[agent_id];
            st = AgentState{};
            st.kind = Kind::releasing;
            st.record_id = stored.id;
            st.verify_first = true;
            break;
        }
        case ContainmentReapplyErrorKind::whitelist_invalid:
            count("validation_failed");
            back_off(agent_id, std::chrono::steady_clock::now());
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
        if (mark_res.error() == "device is not quarantined") {
            std::lock_guard<std::mutex> lk(mu_);
            state_.erase(agent_id); // released, OR superseded by a requarantine, concurrently
                                     // — the dispatch already fired (K8/CDX-P1-01, the
                                     // disclosed residual TOCTOU — see the "KNOWN RESIDUAL
                                     // RACE" note in the header) but there is nothing left
                                     // here to track as pending; the current active record
                                     // (if any) re-enters fresh via the normal apply path on
                                     // the next tick/heartbeat.
        } else {
            // #3425 governance Gate 3 (cpp-safety, finding C): mirror the confirm branch's backoff
            // escalation — without this, a sustained QuarantineStore write outage re-dispatches a
            // fresh apply every fixed kMinReapplyInterval instead of backing off like every other
            // repeated-failure path in this state machine.
            back_off(agent_id, std::chrono::steady_clock::now());
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
        auto& st = state_[agent_id];
        st.pending = Pending::apply;
        st.pending_command_id = reapply_res->command_id;
        // #3425 governance Gate 4 (unhappy-path, Finding A): carried forward into the eventual
        // verify -> mark_endpoint_confirmed call too (the confirm is ABOUT the record whose
        // whitelist was just applied).
        st.pending_record_id = stored.id;
        st.pending_since = std::chrono::steady_clock::now();
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
    // does not spin".
    Claim c;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto& st = state_[agent_id];
        const auto now_steady = std::chrono::steady_clock::now();
        if (now_steady < st.next_eligible_at) {
            count("rate_limited");
            return false;
        }
        if (st.backoff.count() == 0)
            st.backoff = min_reapply_interval(); // first-ever claim for this agent
        st.next_eligible_at = now_steady + st.backoff;
        c.kind = st.kind;
        c.record_id = st.record_id;
        c.confirmed = st.confirmed;
        c.verify_first = st.verify_first;
        c.pending = st.pending;
        c.pending_command_id = st.pending_command_id;
        c.pending_record_id = st.pending_record_id;
        c.pending_ttl_expires = st.pending_ttl_expires;
        c.pending_session_id = st.pending_session_id;
        c.pending_since = st.pending_since;
        c.owed_tried_session_id = st.owed_tried_session_id;
        c.owed_release_sent = st.owed_release_sent;
        c.owed_parked = st.owed_parked;
    }
    // A parked owed device is only ever read, never sent another release in the same session.
    if (c.kind == Kind::owed && c.owed_parked)
        c.verify_first = true;

    // ── An in-flight command: poll for its response, dispatch nothing new ──
    if (c.pending != Pending::none) {
        std::optional<std::vector<StoredResponse>> resp;
        const std::string& pending_command_id = c.pending_command_id;
        if (d_.response_store)
            // #4990: internal consumer. Polls the reply to the reconciler's own firewall
            // dispatch (the closed protective set), never an operator read surface. The frozen
            // site key in test_response_store_read_tripwire.py is spelled `query(pending_command_id)`.
            resp = d_.response_store->query(pending_command_id,
                                            ResponseTierFilter::unrestricted_internal_consumer(),
                                            ResponseQuery{.agent_id = agent_id});
        if (!resp) {
            // #3425 review, sharpened at Gate 5 (gate4-response-store-degradation-freezes-timeout):
            // pending_since is deliberately NOT touched here — the moment response_store recovers,
            // `timed_out` below is computed against the ORIGINAL pending_since and resolves in one
            // shot, so this is not an indefinite stall. What WAS missing: every other repeated-
            // failure path in this state machine escalates backoff so a SUSTAINED failure retries
            // less often over time — a sustained response_store outage instead retried at a flat
            // ~60s cadence forever. `st.pending` stays untouched (the command genuinely is still
            // pending; this round simply couldn't check its status).
            back_off(agent_id, std::chrono::steady_clock::now());
            count("degraded");
            return false;
        }
        const auto steady_now = std::chrono::steady_clock::now();
        const bool timed_out = (steady_now - c.pending_since) >= response_wait();
        if (resp->empty()) {
            if (!timed_out) {
                count("pending"); // no re-dispatch — the no-spin contract
                return false;
            }
            std::lock_guard<std::mutex> lk(mu_);
            auto& st = state_[agent_id];
            st.pending = Pending::none;
            st.verify_first = false;
            st.backoff = next_backoff(st.backoff, max_backoff());
            // #3425 review K9/CDX-P1-03: enforce the just-doubled wait on THIS claim's deadline
            // now, not only on some future claim — otherwise the very next heartbeat/tick retries
            // immediately.
            st.next_eligible_at = steady_now + st.backoff;
            count("not_reached");
            return false;
        }

        const auto reply = parse_containment_reply(combined_output(*resp));
        switch (c.pending) {
        case Pending::apply:
            handle_apply_reply(agent_id, reply, steady_now);
            break;
        case Pending::release:
            handle_release_reply(agent_id, reply, steady_now);
            break;
        case Pending::status:
            handle_status_reply(agent_id, c, reply, steady_now);
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
            state_[agent_id].next_eligible_at = std::chrono::steady_clock::now();
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
