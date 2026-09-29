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
// (the store returns newest-first) so a multi-frame status response (the
// plugin's `do_status` can emit a `state|` line followed by a separate
// `whitelist|` line) reads as one payload for
// `parse_quarantine_endpoint_state`.
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
                                                   const std::string& detail,
                                                   const char* result) const {
    if (!d_.audit_store || !d_.audit_store->is_open())
        return;
    AuditEvent ev;
    ev.timestamp = default_now_epoch();
    ev.principal = "system";
    ev.action = "quarantine.reapply";
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
                     "action=quarantine.reapply result={} detail={}",
                     agent_id, result, detail);
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
                                                       const std::string& store_error) const {
    // #3425 governance Gate 2 (security-guardian): the observable, agent-
    // facing action described by `what` already happened by the time this
    // is called (a dispatch was accepted, or a status read confirmed
    // state|active) — that is a real containment-affecting system fact and
    // must leave an audit trail even though the durable stamp write failed,
    // or a transient store outage creates a silent gap in exactly the
    // evidence this verb exists to provide. `result="failure"` (not
    // "success") because the DURABLE record disagrees — audit and store
    // must never both claim more than what actually landed.
    audit_event(agent_id,
               std::string(what) + " record_id=" + std::to_string(record_id) +
                   " command_id=" + command_id + " but the durable stamp failed: " + store_error,
               "failure");
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

    std::unordered_set<std::string> active_ids;
    std::unordered_map<std::string, std::int64_t> active_record_ids;
    active_ids.reserve(rows->size());
    active_record_ids.reserve(rows->size());
    for (const auto& r : *rows) {
        active_ids.insert(r.agent_id);
        active_record_ids.emplace(r.agent_id, r.id);
    }

    std::vector<std::string> to_reconcile;
    double unconfirmed_connected = 0;
    double unconfirmed_offline = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = state_.begin(); it != state_.end();) {
            if (!active_ids.contains(it->first))
                it = state_.erase(it); // released since the last tick
            else
                ++it;
        }
        for (const auto& agent_id : active_ids) {
            auto& st = state_[agent_id]; // default-constructs an unconfirmed entry
            if (st.confirmed) {
                // #3425 governance re-review (unhappy-path, Finding UP-1):
                // record churn — the active row for this agent_id is not the
                // one `confirmed` was earned against (released, then
                // requarantined, possibly with a different whitelist, all
                // while the agent stayed connected on the same session so
                // the churn check below never fires). A status re-check
                // against the CURRENT record would prove nothing about
                // whether ITS whitelist was ever applied, so this resets to
                // fresh rather than routing through verify_first's
                // status-only recheck — the new record re-enters via the
                // normal apply path below, this same tick.
                if (st.confirmed_record_id != active_record_ids.at(agent_id)) {
                    st = AgentState{};
                } else {
                    // Session churn: a reconnect after a reboot wipes the
                    // endpoint's firewall rules even though the record never
                    // changed — a stale "confirmed" would be a false
                    // assurance. Verify via `status` first, not a blind
                    // re-apply, so a still-genuinely-contained reconnect
                    // doesn't needlessly contend with the agent-side
                    // mutation gate for no reason.
                    auto sess = d_.registry ? d_.registry->get_session(agent_id) : nullptr;
                    if (sess && sess->session_id != st.confirmed_session_id) {
                        st.confirmed = false;
                        st.verify_first = true;
                    }
                }
            }
            if (!st.confirmed) {
                to_reconcile.push_back(agent_id);
                auto sess = d_.registry ? d_.registry->get_session(agent_id) : nullptr;
                if (sess)
                    unconfirmed_connected += 1;
                else
                    unconfirmed_offline += 1;
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
                        "{} unconfirmed record(s) deferred",
                        to_reconcile.size() - i);
            break;
        }
        if (dispatched >= kMaxDispatchesPerTick) {
            spdlog::warn("QuarantineContainmentReconciler: tick hit kMaxDispatchesPerTick ({}) — "
                        "{} unconfirmed record(s) deferred to the next tick",
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
            return; // fast path: no active unconfirmed record — no store read
    }
    (void)reconcile_one(agent_id, "heartbeat"); // no per-tick budget to track on this path
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
    Pending pending_at_entry = Pending::none;
    std::string pending_command_id;
    std::int64_t pending_record_id = 0;
    std::string pending_session_id;
    std::chrono::steady_clock::time_point pending_since{};
    bool verify_first = false;
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
        pending_at_entry = st.pending;
        pending_command_id = st.pending_command_id;
        pending_record_id = st.pending_record_id;
        pending_session_id = st.pending_session_id;
        pending_since = st.pending_since;
        verify_first = st.verify_first;
    }

    // ── An in-flight command: poll for its response, dispatch nothing new ──
    if (pending_at_entry != Pending::none) {
        std::optional<std::vector<StoredResponse>> resp;
        if (d_.response_store)
            resp = d_.response_store->query(pending_command_id, ResponseQuery{.agent_id = agent_id});
        if (!resp) {
            // #3425 review, sharpened at Gate 5 (gate4-response-store-
            // degradation-freezes-timeout): pending_since is deliberately
            // NOT touched here — the moment response_store recovers,
            // `timed_out` below is computed against the ORIGINAL
            // pending_since and resolves in one shot, so this is not an
            // indefinite stall. What WAS missing: every other repeated-
            // failure path in this state machine (not_reached, busy,
            // unconfirmed, degraded on the confirm/apply store writes)
            // escalates backoff so a SUSTAINED failure retries less often
            // over time — a sustained response_store outage instead retried
            // at a flat ~60s cadence forever. `st.pending` stays untouched
            // (the command genuinely is still pending; this round simply
            // couldn't check its status), matching the "still waiting"
            // shape rather than the "attempt concluded" shape below.
            {
                std::lock_guard<std::mutex> lk(mu_);
                auto& st = state_[agent_id];
                st.backoff = next_backoff(st.backoff, kMaxBackoff);
                st.next_eligible_at = std::chrono::steady_clock::now() + st.backoff;
            }
            count("degraded");
            return false;
        }
        const auto steady_now = std::chrono::steady_clock::now();
        const bool timed_out = (steady_now - pending_since) >= response_wait();
        if (resp->empty()) {
            if (!timed_out) {
                count("pending"); // no re-dispatch — the no-spin contract
                return false;
            }
            std::lock_guard<std::mutex> lk(mu_);
            auto& st = state_[agent_id];
            st.pending = Pending::none;
            st.verify_first = false;
            st.backoff = next_backoff(st.backoff, kMaxBackoff);
            // #3425 review K9/CDX-P1-03: enforce the just-doubled wait on
            // THIS claim's deadline now, not only on some future claim —
            // otherwise the very next heartbeat/tick retries immediately
            // (the prior claim's now-stale next_eligible_at already elapsed
            // by the time a timed-out poll gets here).
            st.next_eligible_at = steady_now + st.backoff;
            count("not_reached");
            return false;
        }

        const auto parsed = parse_quarantine_endpoint_state(combined_output(*resp));
        if (pending_at_entry == Pending::apply) {
            std::lock_guard<std::mutex> lk(mu_);
            auto& st = state_[agent_id];
            st.pending = Pending::none;
            if (parsed == QuarantineEndpointState::busy) {
                // #3429's mutation gate blocked the apply — not a failure,
                // just "already busy being quarantined". Wait for the
                // normal claim interval before trying again.
                count("busy");
                return false;
            }
            // Dispatch acceptance (agents_reached>0, already known when this
            // command was issued) is not proof of containment — verify soon,
            // overriding the big claim-time interval so the follow-up isn't
            // delayed a full backoff cycle.
            st.verify_first = true;
            st.next_eligible_at = steady_now + verify_grace();
            return false;
        }

        // pending_at_entry == Pending::status
        if (endpoint_state_confirms_containment(parsed)) {
            // #3425 review K1/CDX-P1-02: the guarded UPDATE (WHERE
            // status='active') affects zero rows if the record was released
            // concurrently, and can fail on a genuine store error — never
            // trust the in-memory "confirmed" transition on an unchecked
            // write, or the reconciler can believe a released/never-stamped
            // device is confirmed for the rest of the process lifetime
            // (excluded from to_reconcile forever, since only tick()'s GC
            // sweep against list_quarantined() would catch it, and that GC
            // only fires when the agent drops out of the active set — a
            // plain store-error, with the record still active, never
            // triggers it). Also moved OUTSIDE mu_ (K10/CDX-P1-04): this is
            // a blocking Postgres write + an AuditStore write, and the
            // class header promises no store/audit I/O runs while the lock
            // is held — multiple short lock/unlock cycles for the SAME
            // agent within one reconcile_one call are safe here because the
            // claim above already excludes any concurrent reconcile_one for
            // this agent_id.
            // #3425 governance re-review (unhappy-path, Finding UP-2): checked
            // BEFORE the durable stamp write, not after. The status response
            // just parsed above describes the session that was live when the
            // STATUS dispatch was SENT (`pending_session_id`) — a reboot
            // landing between dispatch and here (the response was generated,
            // or sat in ResponseStore, before the new session existed) would
            // otherwise let evidence about a gone session get attributed to
            // the new one. Checking first avoids writing a misleading
            // `last_confirmed_at` for a session that was never actually
            // verified.
            auto sess = d_.registry ? d_.registry->get_session(agent_id) : nullptr;
            const std::string confirmed_session_id = sess ? sess->session_id : std::string{};
            // Plain equality, not an empty-string special case: some
            // deployment paths (and this component's own test harness) never
            // populate `AgentSession::session_id` at all, so "both empty"
            // must read as a match, exactly as the pre-existing churn check
            // in tick() already treats it — only a genuine CHANGE (session
            // gone, or a different session live now) is the signal.
            if (confirmed_session_id != pending_session_id) {
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    auto& st = state_[agent_id];
                    st.pending = Pending::none;
                    st.backoff = next_backoff(st.backoff, kMaxBackoff);
                    st.next_eligible_at = steady_now + st.backoff;
                }
                audit_event(agent_id,
                           "status read confirmed state|active but the session churned "
                           "between dispatch and confirm (dispatch_session=" +
                               pending_session_id + " confirm_session=" + confirmed_session_id +
                               ") record_id=" + std::to_string(pending_record_id) +
                               " command_id=" + pending_command_id,
                           "failure");
                count("unconfirmed");
                return false;
            }
            auto mark_res = d_.quarantine_store->mark_endpoint_confirmed(agent_id, pending_record_id,
                                                                         now_epoch());
            if (!mark_res) {
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    auto& st = state_[agent_id];
                    st.pending = Pending::none;
                    if (mark_res.error() == "device is not quarantined") {
                        state_.erase(agent_id); // released concurrently — nothing left to confirm
                    } else {
                        st.backoff = next_backoff(st.backoff, kMaxBackoff);
                        st.next_eligible_at = steady_now + st.backoff;
                    }
                }
                // #3425 governance Gate 2 (security-guardian): the status
                // read DID confirm state|active — that observation is a
                // real fact regardless of whether the stamp landed, and
                // must not vanish with no audit trail just because the
                // store write failed. Outside the lock, matching K10.
                audit_unstamped(agent_id, pending_record_id, pending_command_id,
                                "status read confirmed state|active", mark_res.error());
                count("degraded");
                return false;
            }
            audit_confirmed(agent_id, pending_record_id, pending_command_id);
            {
                std::lock_guard<std::mutex> lk(mu_);
                auto& st = state_[agent_id];
                st.pending = Pending::none;
                st.confirmed = true;
                st.confirmed_session_id = confirmed_session_id;
                st.confirmed_record_id = pending_record_id;
                st.backoff = min_reapply_interval();
            }
            count("confirmed");
            return false;
        }
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto& st = state_[agent_id];
            st.pending = Pending::none;
            st.backoff = next_backoff(st.backoff, kMaxBackoff);
            st.next_eligible_at = steady_now + st.backoff; // K9/CDX-P1-03, same fix as above
        }
        count(parsed == QuarantineEndpointState::busy ? "busy" : "unconfirmed");
        return false;
    }

    // ── No in-flight command: reachability first, no store I/O if offline ──
    auto session = d_.registry ? d_.registry->get_session(agent_id) : nullptr;
    if (!session) {
        // #3425 governance Gate 4 (happy-path): an offline skip never
        // actually attempted anything (same K11/CDX-P1-05 reasoning already
        // applied to the per-tick dispatch cap, now applied to the per-agent
        // CLAIM) — release it immediately rather than let it hold the full
        // claim window. Without this, the claim taken at the top of this
        // call (before reachability was even checked) persists at its full
        // duration regardless of how many times the device is found
        // offline, so the FIRST heartbeat after a genuine reconnect can
        // inherit a stale offline-tick's window and sit rate_limited for up
        // to that long — directly undermining the "fires within one
        // heartbeat interval of reconnect" design intent for the device
        // class this feature exists to fix. Safe: offline agents don't
        // heartbeat, so nothing re-drives this before the next ~20s tick;
        // backoff itself is untouched, so a flapping device still can't spin
        // faster than its own reconnect cadence.
        {
            std::lock_guard<std::mutex> lk(mu_);
            state_[agent_id].next_eligible_at = std::chrono::steady_clock::now();
        }
        count("offline");
        return false;
    }

    if (verify_first) {
        // Session churn on a previously-confirmed agent: confirm the record
        // is still active before dispatching (no whitelist to validate on a
        // read-only status action, so this doesn't go through
        // redispatch_stored_containment).
        auto status_res = d_.quarantine_store->get_status(agent_id);
        if (!status_res) {
            count("degraded");
            return false;
        }
        if (!status_res->has_value()) {
            std::lock_guard<std::mutex> lk(mu_);
            state_.erase(agent_id); // released since verify_first was set
            return false;
        }
        // #3425 governance Gate 4 (unhappy-path, Finding A), residual window:
        // `pending_record_id != 0` here means this verify follows a completed
        // apply for a SPECIFIC record (see the apply-poll transition above,
        // and the pure-churn path below where it carries the last-confirmed
        // record's id). If the currently-active record's id no longer
        // matches, the record was released-and-requarantined (or otherwise
        // replaced) since that apply/confirm — dispatching a status check
        // now and confirming it against the CURRENT record would attribute
        // "confirmed" to a record whose whitelist this reconciler never
        // actually applied. Bail like the "no active record" case above; the
        // new current record has its own last_applied_at==0 and re-enters
        // fresh via the normal apply path on the next tick/heartbeat.
        if (pending_record_id != 0 && status_res->value().id != pending_record_id) {
            std::lock_guard<std::mutex> lk(mu_);
            state_.erase(agent_id);
            return false;
        }
        std::string command_id;
        int agents_reached = 0;
        bool threw = false;
        try {
            const auto outcome =
                d_.dispatch_fn(std::string(kQuarantinePluginName), std::string(kQuarantineStatusAction),
                              {agent_id}, /*scope_expr=*/"", /*parameters=*/{}, /*execution_id=*/"");
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
        // #3425 governance Gate 4 (unhappy-path, Finding A): the record this
        // status dispatch is ABOUT is the one `status_res` just read — carry
        // its id forward so the eventual mark_endpoint_confirmed call is
        // scoped to it, not to whatever happens to be active by then.
        st.pending_record_id = status_res->value().id;
        // #3425 governance re-review (unhappy-path, Finding UP-2): the
        // session live right now, at the moment this status dispatch is
        // actually sent — compared at confirm time against whatever session
        // is live THEN, so a reboot in between is caught rather than
        // silently attributing a stale response to the new session.
        st.pending_session_id = session->session_id;
        st.pending_since = std::chrono::steady_clock::now();
        st.verify_first = false;
        count("reapplied");
        return true;
    }

    // Normal path: re-drive the STORED whitelist via the one shared recipe
    // (quarantine_reapply.hpp) — the same chokepoint MCP's already_active
    // retry path uses, so the stored-whitelist-only invariant lives in
    // exactly one function.
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
            const auto outcome =
                d_.dispatch_fn(std::string(kQuarantinePluginName),
                               std::string(kQuarantineApplyAction), {agent_id},
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
        case ContainmentReapplyErrorKind::whitelist_invalid:
            count("validation_failed");
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
    // #3425 review K2/CDX-P1-02: same discipline as the confirm branch above
    // — a failed guarded UPDATE (released concurrently, superseded by a
    // requarantine, or a genuine store error) must not leave the reconciler
    // believing an apply is durably recorded and polling ResponseStore for a
    // command whose record is gone. `stored.id` (governance Gate 4,
    // unhappy-path Finding A) scopes the write to the record this dispatch
    // was actually built from — a release-then-requarantine race that swaps
    // in a NEW active row for `agent_id` between the read and this write now
    // affects zero rows here (falls into the same branch below) instead of
    // silently stamping the new, never-actually-dispatched record.
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
            // #3425 governance Gate 3 (cpp-safety, finding C): mirror the
            // confirm branch's backoff escalation below — without this, a
            // sustained QuarantineStore write outage re-dispatches a fresh
            // "quarantine apply" command every fixed kMinReapplyInterval
            // (~60s prod) instead of backing off exponentially like every
            // other repeated-failure path in this state machine.
            const auto steady_now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lk(mu_);
            auto& st = state_[agent_id];
            st.backoff = next_backoff(st.backoff, kMaxBackoff);
            st.next_eligible_at = steady_now + st.backoff;
        }
        // #3425 governance Gate 2 (security-guardian): the dispatch WAS
        // accepted (agents_reached>0, checked above) — a real containment-
        // affecting system action already happened and must not vanish
        // with no audit trail just because the store stamp failed.
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
        // #3425 governance Gate 4 (unhappy-path, Finding A): carried forward
        // into the eventual verify -> mark_endpoint_confirmed call too (the
        // confirm is ABOUT the record whose whitelist was just applied).
        st.pending_record_id = stored.id;
        st.pending_since = std::chrono::steady_clock::now();
    }
    count("reapplied");
    return true;
}

} // namespace yuzu::server
