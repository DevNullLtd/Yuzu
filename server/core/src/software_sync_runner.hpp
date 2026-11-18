#pragma once

/// @file software_sync_runner.hpp
/// One "Sync now" run, shared by every surface that offers it: `POST /api/v1/hardware/sync` and
/// the MCP tool `sync_hardware_software`. The sequence, and the per-process state it needs (the
/// pacing ledger, the per-key run state and cooldown stamps), live here so that a second surface
/// cannot be used to dodge any bound.
///
///   fleet 403 -> confirm 400 -> run key -> key state (join 202 / 409 / 429) -> resolve ->
///   last_synced_before filter -> partition -> ONE critical section (re-read key state, live-send
///   bound, admit against the pacing ledger, reserve) -> fail-closed audit -> execution record ->
///   dispatch (paced) -> settle
///
/// What it does NOT own: the response BODY shaping (`Outcome` carries the HTTP status for REST and
/// a `Status` for MCP; the caller writes the envelope), authorization of the CALLER (the
/// surface's type-level Execution:Execute gate and, for a browser, the same-site gate run first),
/// and WHO IS REACHED. Reach is decided in `dispatch_confined_arms` (the `dispatch` seam below is
/// wired to its system-reserved arm, which intersects the id list with the caller's visible set at
/// send time). `resolve` still narrows the candidates to the caller's visible set so the counts and
/// the audit row never describe devices the caller may not see; that narrowing is count accuracy,
/// the seam is the authority.
///
/// The pacing budget, the run state and the cooldown stamps are per server PROCESS, not
/// cluster-wide, and in memory: replicas multiply them and a restart forgets them (agents keep
/// the delays they already armed; execution rows persist).
///
/// No lock is held across resolve, a store read, an audit write, the execution record or the send.
/// The only state shared with those callbacks is `mu_`, taken for short, non-blocking sections, so a
/// callback may re-enter `run` (the tests drive overlapping runs that way, never with threads).

#include "hardware_list_model.hpp" // agent_supports_sync_now
#include "software_sync_decision.hpp"
#include "software_sync_pacing.hpp"

#include <yuzu/server/auth.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::server::software_sync {

/// The most send loops that may be alive at once in this process (a run counts from the moment
/// it is admitted until its send returns). A connected agent that has stopped reading blocks its
/// own write, and a blocked send cannot be cancelled, so without a bound a persistent stall would
/// strand one request worker per run. A run past this is refused with 409 and nothing is left
/// behind.
inline constexpr int kMaxLiveRuns = 3;

/// The seams a run needs. The server wires them; a test fakes them.
struct Env {
    /// Selector -> the caller's candidate ids (already narrowed to their visible set) and
    /// whether that set is unfiltered.
    std::function<Resolved(const auth::Session&, const Selector&)> resolve;
    /// `__sync__.now` to each id. In production this is the `dispatch_confined_arms`
    /// system-reserved arm; the id list is intersected with the caller's visible set there.
    /// `delay_max_s` is the spread window the agents are asked to fire inside (0 = immediately)
    /// and `execution_id` the tracker row the replies are recorded against (empty = untracked).
    /// A throw out of this seam is handled: see `Runner::run`.
    std::function<DispatchResult(const auth::Session&, const std::vector<std::string>&,
                                 std::int64_t delay_max_s, const std::string& execution_id)>
        dispatch;
    /// Cheap: does the caller hold an unfiltered Execution:Execute? No fleet read. Decides the
    /// run key's caller class and the fleet-administrator half of the whole-fleet rule.
    std::function<bool(const auth::Session&)> caller_unfiltered;
    /// Does the caller hold the global ManagementGroup:Write grant (with the same rule the
    /// permission gate applies while RBAC enforcement is off)? An answer that cannot be determined
    /// is false. Empty = nobody may name the whole fleet.
    std::function<bool(const auth::Session&)> fleet_admin;
    /// The agent version of a session on THIS process, or nullopt.
    std::function<std::optional<std::string>(const std::string&)> agent_version;
    /// device -> server-receipt epoch seconds of its last accepted installed-software report, for
    /// `last_synced_before`. A device with no row is absent from the map. nullopt = the read
    /// degraded (the run is refused 503, never treated as "everything is stale"). Empty = refused.
    std::function<std::optional<std::unordered_map<std::string, std::int64_t>>(const std::vector<std::string>&)>
        last_seen;
    /// The execution record the status route reads. All three are optional; without `create` a run
    /// is untracked (its 202 carries `execution_id: null`).
    struct Tracking {
        /// Create the row BEFORE dispatch. Empty id = it could not be created (the run goes on,
        /// untracked).
        std::function<std::string(const auth::Session&, const Selector&, std::int64_t delay_max_s)> create;
        /// Frames the registry actually accepted.
        std::function<void(const std::string& execution_id, std::size_t targeted)> set_targeted;
        /// Close the row of a run that sent nothing (or whose send threw).
        std::function<void(const std::string& execution_id, const auth::Session&)> cancel;
    } track;
    /// Epoch seconds for the cooldown, the pacing ledger and `requested_at`. Empty = system clock.
    std::function<std::int64_t()> now;
    /// Told when a run is refused by the live-send bound (kMaxLiveRuns sends already alive).
    std::function<void()> on_live_bound_refused;
    /// Told once per `run` with the closed `result_label` of its outcome (a metric label).
    std::function<void(std::string_view)> on_result;
    /// Gap between two runs of one run key, in seconds (0 = none). `--inventory-sync-cooldown`.
    std::int64_t cooldown_s{kDefaultCooldownSecs};
};

/// Where a run writes its audit rows. `note` is best-effort (refusals, failures, joins);
/// `persist` is the fail-closed write BEFORE dispatch and returns false when the row was not
/// stored. `persist_fleet_wide`, when bound, takes that write for a whole-fleet run instead (REST
/// and MCP both bind it, to the verb software_estate.sync.fleet_wide). Arguments:
/// result, target_type, target_id, detail.
struct Audit {
    std::function<void(std::string_view, std::string_view, const std::string&, const std::string&)> note;
    std::function<bool(std::string_view, std::string_view, const std::string&, const std::string&)>
        persist;
    std::function<bool(std::string_view, std::string_view, const std::string&, const std::string&)>
        persist_fleet_wide;
};

enum class Status {
    Accepted,
    BadScope,          // 400: a malformed selector or a missing confirmation
    FleetWideRequired, // 403
    Cooldown,          // 429
    InFlight,          // 409
    ScopeUnresolved,   // 503
    TooMany,           // 413: cannot be spread inside kMaxSpreadSecs at the capacity free
    AuditUnavailable,  // 503
    NoneReachable,     // 503
    BudgetBusy,        // 429: the pacing budget is held by runs still spreading
};

struct Outcome {
    Status status{Status::Accepted};
    int http{202};
    std::string message;                // the error text (non-Accepted)
    std::optional<std::int64_t> retry_after_ms; // unset = no hint
    nlohmann::json summary;             // Accepted: summary_json(...) (+ joined)
};

/// Every `result_label` value, for a metric pre-seed that cannot fall out of step with the mapping.
inline constexpr std::array<std::string_view, 11> kRunResults = {
    "accepted",  "joined",      "bad_request",   "fleet_denied", "cooldown",   "in_flight",
    "unresolved", "too_large",  "audit_failed",  "none_reachable", "budget_busy"};

/// The closed label of one outcome. A switch with no `default:` so a new `Status` fails to compile
/// here rather than silently counting as something else.
[[nodiscard]] inline std::string_view result_label(const Outcome& o) {
    switch (o.status) {
    case Status::Accepted:
        return o.summary.value("joined", false) ? "joined" : "accepted";
    case Status::BadScope: return "bad_request";
    case Status::FleetWideRequired: return "fleet_denied";
    case Status::Cooldown: return "cooldown";
    case Status::InFlight: return "in_flight";
    case Status::ScopeUnresolved: return "unresolved";
    case Status::TooMany: return "too_large";
    case Status::AuditUnavailable: return "audit_failed";
    case Status::NoneReachable: return "none_reachable";
    case Status::BudgetBusy: return "budget_busy";
    }
    return "none_reachable"; // unreachable while the switch stays exhaustive
}

class Runner {
public:
    explicit Runner(Env env) : env_(std::move(env)) {}
    Runner(const Runner&) = delete;
    Runner& operator=(const Runner&) = delete;

    [[nodiscard]] Outcome run(const auth::Session& session, const Selector& sel, const Audit& audit) {
        Outcome out = run_impl(session, sel, audit);
        if (env_.on_result)
            env_.on_result(result_label(out));
        return out;
    }

    /// How many run keys the runner is tracking (live runs and cooldown stamps); bounded by
    /// kCooldownStateCap. For tests and diagnostics.
    [[nodiscard]] std::size_t tracked_keys() {
        std::lock_guard<std::mutex> lk(mu_);
        return keys_.size();
    }

private:
    [[nodiscard]] Outcome run_impl(const auth::Session& session, const Selector& sel, const Audit& audit) {
        Outcome out;
        const std::string_view type = sel.arm == DispatchArm::Ids ? "Agent" : "Scope";
        const std::string target_id = target_label(sel);
        const auto refuse = [&](Status st, int http, std::string message, const std::string& why,
                                std::optional<std::int64_t> retry_ms = std::nullopt) {
            audit.note("denied", type, target_id, why + " scope=" + audit_token(sel.expr));
            out.status = st;
            out.http = http;
            out.message = std::move(message);
            out.retry_after_ms = retry_ms;
            return out;
        };
        const auto unresolved = [&](const std::string& reason) {
            // A degraded store or a failed owner check: never "no matches". Nothing was sent.
            audit.note("failure", type, target_id, "scope_unresolved reason=" + audit_token(reason));
            out.status = Status::ScopeUnresolved;
            out.http = 503;
            out.message = "the scope could not be evaluated; no device was contacted";
            out.retry_after_ms = 5000;
            return out;
        };
        // The answer for a request that found its key busy or cooling down.
        const auto answer_gate = [&](const Gate& g) {
            switch (g.kind) {
            case Gate::Kind::Join:
                audit.note("joined", type, target_id,
                           "scope=" + audit_token(sel.expr) + " execution_id=" +
                               (g.execution_id.empty() ? std::string("none") : audit_token(g.execution_id)));
                out.status = Status::Accepted;
                out.http = 202;
                out.summary = g.summary;
                out.summary["joined"] = true;
                return out;
            case Gate::Kind::InFlight:
                return refuse(Status::InFlight, 409, g.message, "run_in_flight", g.retry_ms);
            case Gate::Kind::Cooldown:
                break;
            }
            return refuse(Status::Cooldown, 429,
                          "a sync run for this scope was requested a moment ago; wait " +
                              std::to_string(g.wait_s) + "s",
                          "rate_limited cooldown=" + std::to_string(g.wait_s) + "s", g.wait_s * 1000);
        };

        // Who may name the fleet, and what a whole group or the fleet must confirm, are decided
        // BEFORE anything is read or reserved. `unfiltered` is also the run key's caller class.
        const bool guarded = needs_run_guard(sel.arm);
        const bool unfiltered = guarded && env_.caller_unfiltered(session);
        if (sel.arm == DispatchArm::Broadcast) {
            const bool admin = env_.fleet_admin && env_.fleet_admin(session);
            if (fleet_wide_denied(sel.arm, unfiltered, admin))
                return refuse(Status::FleetWideRequired, 403,
                              "syncing the whole fleet needs a fleet-wide Execution:Execute grant and the "
                              "global ManagementGroup:Write grant",
                              "fleet_wide_required");
        }
        if (confirmation_required(sel.arm, sel.confirm))
            return refuse(Status::BadScope, 400,
                          "a whole group or the whole fleet needs \"confirm\": true in the request",
                          "confirmation_required");

        // The key's state is read BEFORE the fleet is: a repeat of a running request joins it, a
        // busy or cooling key is refused, and none of that costs a resolve.
        const std::string key = guarded ? run_key(sel, session.username, unfiltered) : std::string();
        if (guarded) {
            const auto at = now();
            std::optional<Gate> gate;
            {
                std::lock_guard<std::mutex> lk(mu_);
                gate = key_gate_locked(key, sel.last_synced_before, at);
            }
            if (gate)
                return answer_gate(*gate);
        }

        const auto resolved = env_.resolve(session, sel);
        if (resolved.status == Resolved::Status::InvalidScope)
            return refuse(Status::BadScope, 400, "invalid scope: " + resolved.detail, "invalid_scope");
        if (resolved.status != Resolved::Status::Ok)
            return unresolved(resolved.detail);
        // The key was built for one caller class. A resolver that disagrees (the grants changed
        // between the two reads) cannot be told apart from a scope that was not evaluable.
        if (guarded && resolved.caller_unfiltered != unfiltered)
            return unresolved("caller_class_changed");

        // last_synced_before: ask only the devices whose last accepted report is older. A read that
        // degrades refuses the run; it is never read as "everything is stale".
        std::size_t fresh = 0;
        std::vector<std::string> stale_ids;
        const std::vector<std::string>* candidates = &resolved.ids;
        if (sel.last_synced_before && !resolved.ids.empty()) {
            std::optional<std::unordered_map<std::string, std::int64_t>> seen;
            if (env_.last_seen)
                seen = env_.last_seen(resolved.ids);
            if (!seen)
                return unresolved("last_seen_degraded");
            auto split = split_fresh(resolved.ids, *seen, *sel.last_synced_before);
            fresh = split.fresh;
            stale_ids = std::move(split.stale);
            candidates = &stale_ids;
        }

        auto plan = partition(*candidates, env_.agent_version,
                              [](std::string_view v) { return agent_supports_sync_now(v); });
        plan.counts.requested = resolved.ids.size();
        plan.counts.skipped_fresh = fresh;

        // Audit BEFORE dispatch and fail closed - same contract as the per-device route. The
        // whole-fleet row goes through its own writer when the surface bound one.
        const auto persist_row = [&](std::int64_t delay_max_s) {
            const auto& writer =
                (sel.arm == DispatchArm::Broadcast && audit.persist_fleet_wide) ? audit.persist_fleet_wide
                                                                                : audit.persist;
            return writer(audit_result(plan.counts), type, target_id, audit_detail(sel, plan.counts, delay_max_s));
        };
        const auto audit_failed = [&] {
            out.status = Status::AuditUnavailable;
            out.http = 503;
            out.message = "audit subsystem unavailable - request not served";
            out.retry_after_ms = 5000;
            return out;
        };

        if (plan.targets.empty()) {
            // Nothing live to ask. The resolve and the lookups were paid for, so a repeat of the
            // key waits out its cooldown, but nothing was reserved and nothing is sent.
            if (!persist_row(0))
                return audit_failed();
            const auto at = now();
            if (guarded) {
                std::lock_guard<std::mutex> lk(mu_);
                stamp_locked(key, at);
            }
            out.status = Status::Accepted;
            out.http = 202;
            out.summary = summary_json(plan.counts, "", at, "", 0);
            return out;
        }

        // ONE critical section: re-read the key (a same-key race gets the join / 409 / 429 answer
        // above), apply the live-send bound, admit against the ledger and reserve. Admission and
        // reservation are atomic, so two different keys can never both be admitted against the same
        // free budget. A single named device is never paced, counted or keyed.
        Reservation reservation(*this);
        std::int64_t delay_max_s = 0;
        std::int64_t started_at = now();
        if (guarded) {
            enum class Verdict { Reserved, Gate, LiveBound, Busy, TooLarge } verdict = Verdict::Reserved;
            std::optional<Gate> gate;
            Admission adm;
            {
                std::lock_guard<std::mutex> lk(mu_);
                prune_ledger_locked(started_at);
                gate = key_gate_locked(key, sel.last_synced_before, started_at);
                if (gate) {
                    verdict = Verdict::Gate;
                } else if (live_sends_ >= kMaxLiveRuns) {
                    verdict = Verdict::LiveBound;
                } else {
                    adm = admit(ledger_, plan.targets.size(), started_at);
                    if (adm.kind == Admission::Kind::Busy)
                        verdict = Verdict::Busy;
                    else if (adm.kind == Admission::Kind::TooLarge)
                        verdict = Verdict::TooLarge;
                    else
                        reservation.take_locked(key, adm, sel.last_synced_before, started_at);
                }
            }
            switch (verdict) {
            case Verdict::Reserved: break;
            case Verdict::Gate: return answer_gate(*gate);
            case Verdict::LiveBound:
                if (env_.on_live_bound_refused)
                    env_.on_live_bound_refused();
                return refuse(Status::InFlight, 409,
                              "too many sync runs are sending right now; try again in a moment",
                              "live_sends_exhausted", 5000);
            case Verdict::Busy:
                return refuse(Status::BudgetBusy, 429,
                              "the capacity for sync runs is in use by runs still spreading; retry in " +
                                  std::to_string(adm.retry_after_s) + "s",
                              "budget_busy retry=" + std::to_string(adm.retry_after_s) + "s",
                              adm.retry_after_s * 1000);
            case Verdict::TooLarge:
                return refuse(Status::TooMany, 413,
                              "this run cannot be spread inside " + std::to_string(kMaxSpreadSecs) +
                                  " s at the capacity free right now; narrow the scope, or retry when other "
                                  "runs have ended",
                              "unspreadable max_spread=" + std::to_string(kMaxSpreadSecs) + "s");
            }
            delay_max_s = adm.delay_max_s;
        }

        if (!persist_row(delay_max_s)) {
            reservation.release_all(); // nothing was sent: the next admission sees the full budget
            return audit_failed();
        }

        // The execution record exists BEFORE the send, so a fast reply cannot beat it. A record that
        // cannot be created leaves the run untracked, not refused: the audit row is the evidence.
        std::string execution_id;
        if (env_.track.create)
            execution_id = env_.track.create(session, sel, delay_max_s);
        const auto close_record = [&] {
            if (!execution_id.empty() && env_.track.cancel)
                env_.track.cancel(execution_id, session);
        };
        started_at = now();

        const auto none_reachable = [&] {
            close_record();
            out.status = Status::NoneReachable;
            out.http = 503;
            out.message = "no selected device is reachable right now";
            out.retry_after_ms = 30000;
            return out;
        };

        DispatchResult sent;
        try {
            sent = env_.dispatch(session, plan.targets, delay_max_s, execution_id);
        } catch (...) {
            // Any throw, not only std::exception: one that skipped this branch would unwind through
            // the Reservation's defaults, releasing the ledger entry with no audit row and the
            // execution record left open.
            // The audit row is already stored. The runner cannot prove nothing was sent, so the
            // pacing reservation stays until its spread ends; the key is neither joinable nor in
            // cooldown (it was not accepted), and the answer is the retryable "nothing reachable".
            audit.note("failure", type, target_id, "dispatch_threw");
            if (guarded)
                reservation.forget_key(); // keep the ledger entry, drop the key's run state
            return none_reachable();
        }
        if (sent.sent == 0) {
            // Every frame was refused: nothing will spread, so the whole reservation goes back and
            // the cooldown stays unspent.
            reservation.release_all();
            return none_reachable();
        }

        // Frames the registry accepted are the run; a frame that was not accepted keeps its share
        // of the reservation until the spread ends (the budget bounds what was ASKED). That holds
        // from here whatever follows: a throw before the settle below must not give the entry back.
        reservation.forget_key();
        if (!execution_id.empty() && env_.track.set_targeted)
            env_.track.set_targeted(execution_id, sent.sent);
        const auto final_counts = finalize(plan.counts, sent.sent);
        const auto summary = summary_json(final_counts, sent.command_id, started_at, execution_id, delay_max_s);
        if (guarded) {
            std::lock_guard<std::mutex> lk(mu_);
            reservation.settle_locked(summary, sent.command_id, execution_id, started_at);
        }
        out.status = Status::Accepted;
        out.http = 202;
        out.summary = summary;
        return out;
    }

    /// What a request that finds its key occupied is told.
    struct Gate {
        enum class Kind { Join, InFlight, Cooldown } kind{Kind::InFlight};
        nlohmann::json summary;     // Join: the running run's summary
        std::string execution_id;   // Join
        std::string message;        // InFlight
        std::int64_t retry_ms{0};   // InFlight
        std::int64_t wait_s{0};     // Cooldown
    };

    /// One key's run state plus its cooldown stamp. An entry with `phase == Idle` is only a stamp.
    /// Pending: admitted and not settled yet (the audit write, the execution record, the send
    /// loop). It cannot expire (a stalled send must not let a second run of the same key start) and
    /// is never joined, so a join only ever reports a run whose frames were accepted. Running:
    /// sent, and spreading until `ends_at`.
    struct KeyState {
        enum class Phase { Idle, Pending, Running } phase{Phase::Idle};
        std::uint64_t ledger_id{0};
        std::string command_id;
        std::string execution_id;
        std::int64_t started_at{0};
        std::int64_t ends_at{0};
        std::optional<std::int64_t> last_synced_before;
        nlohmann::json summary;
        std::optional<std::int64_t> cooldown_from;
    };

    [[nodiscard]] std::int64_t now() const {
        if (env_.now)
            return env_.now();
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    // -- everything below runs with `mu_` held ----------------------------------------------

    void prune_ledger_locked(std::int64_t at) {
        std::erase_if(ledger_, [at](const ActiveRun& e) { return e.ends_at <= at; });
    }

    /// Is the key's run still a run? Pending is; Running is until its spread has ended.
    [[nodiscard]] static bool live_locked(const KeyState& k, std::int64_t at) {
        return k.phase == KeyState::Phase::Pending ||
               (k.phase == KeyState::Phase::Running && k.ends_at > at);
    }

    /// A finished run stops being a run: only its cooldown stamp stays.
    static void expire_locked(KeyState& k, std::int64_t at) {
        if (!live_locked(k, at))
            k.phase = KeyState::Phase::Idle;
    }

    [[nodiscard]] std::optional<Gate> key_gate_locked(const std::string& key,
                                                      std::optional<std::int64_t> requested_before,
                                                      std::int64_t at) {
        const auto it = keys_.find(key);
        if (it == keys_.end())
            return std::nullopt;
        KeyState& k = it->second;
        expire_locked(k, at);
        Gate g;
        switch (k.phase) {
        case KeyState::Phase::Pending:
            g.message = "a sync run for this scope is being started; try again in a moment";
            g.retry_ms = 1000;
            return g;
        case KeyState::Phase::Running:
            if (join_covers(k.last_synced_before, requested_before)) {
                g.kind = Gate::Kind::Join;
                g.summary = k.summary;
                g.execution_id = k.execution_id;
                return g;
            }
            g.message = "a sync run for this scope is already in progress and does not cover this request";
            g.retry_ms = std::clamp<std::int64_t>((k.ends_at - at) * 1000, 1000, kMaxSpreadSecs * 1000);
            return g;
        case KeyState::Phase::Idle:
            break;
        }
        if (const auto wait = cooldown_remaining(k.cooldown_from, at, env_.cooldown_s); wait > 0) {
            g.kind = Gate::Kind::Cooldown;
            g.wait_s = wait;
            return g;
        }
        return std::nullopt;
    }

    [[nodiscard]] bool evictable_locked(const KeyState& k, std::int64_t at) const {
        return !live_locked(k, at) && cooldown_remaining(k.cooldown_from, at, env_.cooldown_s) == 0;
    }

    /// Keep the map at kCooldownStateCap: expired entries go first; if every entry is still cooling
    /// down, the one with the oldest stamp goes (a live run is never dropped).
    void make_room_locked(const std::string& key, std::int64_t at) {
        if (keys_.size() < kCooldownStateCap || keys_.contains(key))
            return;
        std::erase_if(keys_, [&](const auto& kv) { return evictable_locked(kv.second, at); });
        if (keys_.size() < kCooldownStateCap)
            return;
        auto oldest = keys_.end();
        for (auto it = keys_.begin(); it != keys_.end(); ++it) {
            if (live_locked(it->second, at))
                continue;
            if (oldest == keys_.end() ||
                it->second.cooldown_from.value_or(0) < oldest->second.cooldown_from.value_or(0))
                oldest = it;
        }
        if (oldest != keys_.end())
            keys_.erase(oldest);
    }

    /// Record a run that reserved nothing (no live target) as the key's last run. A run of the same
    /// key that was admitted meanwhile keeps its state: only its stamp is touched.
    void stamp_locked(const std::string& key, std::int64_t at) {
        make_room_locked(key, at);
        KeyState& k = keys_[key];
        if (!live_locked(k, at))
            k.phase = KeyState::Phase::Idle;
        k.cooldown_from = at;
    }

    /// The reservation of one admitted run: its ledger entry, its key state and its live-send
    /// count. RAII: whatever the exit path (an exception out of the audit write or the execution
    /// record included), the live count goes back; the ledger entry and the key state go back too
    /// unless the run settled or its send is known to have started.
    class Reservation {
    public:
        explicit Reservation(Runner& r) : r_(r) {}
        Reservation(const Reservation&) = delete;
        Reservation& operator=(const Reservation&) = delete;
        ~Reservation() {
            if (!live_)
                return;
            std::lock_guard<std::mutex> lk(r_.mu_);
            if (give_back_ledger_)
                r_.erase_ledger_locked(id_);
            if (give_back_key_)
                r_.erase_key_if_mine_locked(key_, id_);
            --r_.live_sends_;
        }

        /// Called with `mu_` held, once admission said yes: the ledger entry, the Pending key state
        /// and the live count are taken together.
        void take_locked(const std::string& key, const Admission& adm,
                         std::optional<std::int64_t> before, std::int64_t at) {
            key_ = key;
            id_ = ++r_.next_ledger_id_;
            r_.ledger_.push_back({adm.rate, adm.ends_at, id_});
            r_.make_room_locked(key, at);
            KeyState& k = r_.keys_[key];
            const auto stamp = k.cooldown_from; // a returning key keeps nothing but its stamp, replaced at settle
            k = KeyState{};
            k.cooldown_from = stamp;
            k.phase = KeyState::Phase::Pending;
            k.ledger_id = id_;
            k.started_at = at;
            k.ends_at = adm.ends_at;
            k.last_synced_before = before;
            ++r_.live_sends_;
            live_ = true;
        }
        /// Called with `mu_` held after a send that accepted at least one frame: the key becomes
        /// Running (joinable, with the counts of what was accepted) and starts its cooldown.
        void settle_locked(const nlohmann::json& summary, const std::string& command_id,
                           const std::string& execution_id, std::int64_t started) {
            give_back_ledger_ = false; // the reservation stands until its spread ends
            give_back_key_ = false;
            auto it = r_.keys_.find(key_);
            if (it == r_.keys_.end() || it->second.ledger_id != id_)
                return;
            it->second.phase = KeyState::Phase::Running;
            it->second.summary = summary;
            it->second.command_id = command_id;
            it->second.execution_id = execution_id;
            it->second.cooldown_from = started;
        }
        /// A send that threw, or anything that throws after frames were accepted: the ledger entry
        /// stays until its spread ends, the key's state goes.
        void forget_key() {
            give_back_ledger_ = false;
            give_back_key_ = true;
        }
        /// Nothing was or will be sent: the whole reservation goes back now.
        void release_all() {
            give_back_ledger_ = true;
            give_back_key_ = true;
        }

    private:
        Runner& r_;
        std::string key_;
        std::uint64_t id_{0};
        bool live_{false};
        bool give_back_ledger_{true};
        bool give_back_key_{true};
    };

    void erase_ledger_locked(std::uint64_t id) {
        std::erase_if(ledger_, [id](const ActiveRun& e) { return e.id == id; });
    }
    void erase_key_if_mine_locked(const std::string& key, std::uint64_t id) {
        const auto it = keys_.find(key);
        if (it != keys_.end() && it->second.ledger_id == id && it->second.phase != KeyState::Phase::Idle)
            keys_.erase(it);
    }

    Env env_;
    std::mutex mu_;
    /// The pacing ledger: runs admitted and still spreading (dropped when their spread ends).
    std::vector<ActiveRun> ledger_;
    /// run key -> its run state and cooldown stamp, bounded at kCooldownStateCap.
    std::unordered_map<std::string, KeyState> keys_;
    std::uint64_t next_ledger_id_{0};
    /// Runs admitted whose send has not returned (kMaxLiveRuns bound).
    int live_sends_{0};
};

} // namespace yuzu::server::software_sync
