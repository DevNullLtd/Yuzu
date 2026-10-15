#pragma once

/// @file software_sync_runner.hpp
/// One "Sync now" fleet run, shared by every surface that offers it: `POST /api/v1/hardware/sync`
/// and the MCP tool `sync_hardware_software`. The sequence, and the two pieces of per-process
/// state it needs (the per-operator cooldown and the single in-flight slot), live here so that a
/// second surface cannot be used to dodge either bound.
///
///   preflight 403 -> cooldown 429 -> slot 409 -> resolve -> partition + cap 413 -> decide ->
///   audit (fail closed) -> dispatch -> stamp
///
/// What it does NOT own: HTTP / JSON-RPC shaping (the caller maps an `Outcome`), authorization
/// of the CALLER (the surface's type-level Execution:Execute gate and, for a browser, the
/// same-site gate run first), and WHO IS REACHED. Reach is decided in `dispatch_confined_arms`
/// (the `dispatch` seam below is wired to its system-reserved arm, which intersects the id list
/// with the caller's visible set at send time). `resolve` still narrows the candidates to the
/// caller's visible set so the counts, the 413 cap and the audit row never describe devices the
/// caller may not see; that narrowing is count accuracy, the seam is the authority.
///
/// Both bounds are per server PROCESS, not cluster-wide.

#include "hardware_list_model.hpp" // agent_supports_sync_now
#include "software_sync_decision.hpp"

#include <yuzu/server/auth.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::server::software_sync {

/// How long one run may hold the in-flight slot before another run may take it over. The send
/// loop is sequential and a connected agent that has stopped reading blocks its own write, so
/// without a lease one stalled stream would hold the slot (and answer every other run 409)
/// until that agent reads or disconnects. The stalled run keeps going; it is bounded by the
/// 500-target cap, and a takeover only ever lets a second bounded run start.
inline constexpr std::int64_t kSlotLeaseMs = 120'000;

/// The seams a run needs. The server wires them; a test fakes them.
struct Env {
    /// Selector -> the caller's candidate ids (already narrowed to their visible set) and
    /// whether that set is unfiltered.
    std::function<Resolved(const auth::Session&, const Selector&)> resolve;
    /// `__sync__.now` to each id. In production this is the `dispatch_confined_arms`
    /// system-reserved arm; the id list is intersected with the caller's visible set there.
    std::function<DispatchResult(const auth::Session&, const std::vector<std::string>&)> dispatch;
    /// Cheap: does the caller hold an unfiltered Execution:Execute? No fleet read.
    std::function<bool(const auth::Session&)> caller_unfiltered;
    /// The agent version of a session on THIS process, or nullopt.
    std::function<std::optional<std::string>(const std::string&)> agent_version;
    /// Epoch seconds for the cooldown and `requested_at`. Empty = system clock.
    std::function<std::int64_t()> now;
    /// Monotonic milliseconds for the slot lease. Empty = steady_clock.
    std::function<std::int64_t()> mono_ms;
};

/// Where a run writes its audit rows. `note` is best-effort (refusals and failures);
/// `persist` is the fail-closed write BEFORE dispatch and returns false when the row was not
/// stored. Arguments: result, target_type, target_id, detail.
struct Audit {
    std::function<void(std::string_view, std::string_view, const std::string&, const std::string&)> note;
    std::function<bool(std::string_view, std::string_view, const std::string&, const std::string&)>
        persist;
};

enum class Status {
    Accepted,
    BadScope,          // 400
    FleetWideRequired, // 403
    Cooldown,          // 429
    InFlight,          // 409
    ScopeUnresolved,   // 503
    TooMany,           // 413
    AuditUnavailable,  // 503
    NoneReachable,     // 503
};

struct Outcome {
    Status status{Status::Accepted};
    int http{202};
    std::string message;                // the error text (non-Accepted)
    std::int64_t retry_after_ms{-1};    // -1 = no hint
    std::int64_t retry_after_secs{0};   // for a Retry-After header (Cooldown)
    nlohmann::json summary;             // Accepted: summary_json(...)
};

class Runner {
public:
    explicit Runner(Env env) : env_(std::move(env)) {}
    Runner(const Runner&) = delete;
    Runner& operator=(const Runner&) = delete;

    [[nodiscard]] Outcome run(const auth::Session& session, const Selector& sel, const Audit& audit) {
        Outcome out;
        const std::string_view type = sel.arm == DispatchArm::Ids ? "Agent" : "Scope";
        const std::string target_id = target_label(sel);
        const auto refuse = [&](Status st, int http, std::string message, const std::string& why,
                                std::int64_t retry_ms = -1, std::int64_t retry_secs = 0) {
            audit.note("denied", type, target_id, why + " scope=" + audit_token(sel.expr));
            out.status = st;
            out.http = http;
            out.message = std::move(message);
            out.retry_after_ms = retry_ms;
            out.retry_after_secs = retry_secs;
            return out;
        };
        const auto refuse_fleet_wide = [&] {
            return refuse(Status::FleetWideRequired, 403,
                          "syncing the whole fleet needs a fleet-wide Execution:Execute grant",
                          "fleet_wide_required");
        };

        // A confined caller naming the whole fleet is refused HERE: before it can take the
        // in-flight slot and before the resolver reads the fleet. `decide` applies the same rule
        // again to the resolver's own answer (defence in depth).
        if (sel.arm == DispatchArm::Broadcast && fleet_wide_denied(sel.arm, env_.caller_unfiltered(session)))
            return refuse_fleet_wide();

        // Ordering: preflight 403 -> cooldown 429 -> slot 409 -> resolve -> decide -> audit ->
        // dispatch. One multi-device run at a time and one per operator per minute. The
        // cooldown is read BEFORE the slot so a 429 never occupies it, and the slot is held to
        // the end of the run, so the stamp after dispatch cannot interleave with another run.
        const bool guarded = needs_run_guard(sel.arm);
        Slot slot(*this);
        const auto cooldown_wait = [&] {
            std::optional<std::int64_t> last;
            {
                std::lock_guard<std::mutex> lk(mu_);
                last = last_run_of(last_run_, session.username);
            }
            return cooldown_remaining(last, now()); // the clock is read outside the lock
        };
        const auto refuse_cooldown = [&](std::int64_t wait) {
            return refuse(Status::Cooldown, 429,
                          "a sync run was requested a moment ago; wait " + std::to_string(wait) + "s",
                          "rate_limited cooldown=" + std::to_string(wait) + "s", wait * 1000, wait);
        };
        if (guarded) {
            if (const auto wait = cooldown_wait(); wait > 0)
                return refuse_cooldown(wait);
            if (!slot.take()) {
                const auto remaining = slot_remaining_ms();
                return refuse(Status::InFlight, 409,
                              "another sync run is already in progress; try again in a moment",
                              "run_in_flight", remaining);
            }
            // This operator's previous run may have stamped between the check above and taking
            // the slot. Release the slot before the refusal's audit write.
            if (const auto wait = cooldown_wait(); wait > 0) {
                slot.release();
                return refuse_cooldown(wait);
            }
        }

        const auto resolved = env_.resolve(session, sel);
        if (resolved.status == Resolved::Status::InvalidScope)
            return refuse(Status::BadScope, 400, "invalid scope: " + resolved.detail, "invalid_scope");
        if (resolved.status != Resolved::Status::Ok) {
            // A degraded store or a failed owner check: never "no matches". Nothing was sent.
            audit.note("failure", type, target_id,
                       "scope_unresolved reason=" + audit_token(resolved.detail));
            out.status = Status::ScopeUnresolved;
            out.http = 503;
            out.message = "the scope could not be evaluated; no device was contacted";
            out.retry_after_ms = 5000;
            return out;
        }

        // Partition, stopping as soon as the reachable count passes the cap: past the cap the
        // answer is 413 whatever the rest holds, so a huge `__all__` costs at most kMaxTargets+1
        // session lookups, not one per device in the fleet.
        Plan plan;
        plan.counts.requested = resolved.ids.size();
        bool over_cap = false;
        for (const auto& id : resolved.ids) {
            const auto version = env_.agent_version(id); // a session on THIS process, or nullopt
            if (!version) {
                ++plan.counts.skipped_offline;
            } else if (!agent_supports_sync_now(*version)) {
                ++plan.counts.skipped_version;
            } else {
                plan.targets.push_back(id);
                if (plan.targets.size() > kMaxTargets) {
                    over_cap = true;
                    break;
                }
            }
        }
        plan.counts.reached = plan.targets.size();

        const auto verdict = decide(sel.arm, resolved.caller_unfiltered, plan.counts);
        if (over_cap || verdict == Verdict::TooMany)
            return refuse(Status::TooMany, 413,
                          "this would reach more than " + std::to_string(kMaxTargets) +
                              " devices; the limit is " + std::to_string(kMaxTargets) +
                              " per request - narrow the scope",
                          "over_cap cap=" + std::to_string(kMaxTargets));
        if (verdict == Verdict::FleetWideRequired)
            return refuse_fleet_wide();

        // Audit BEFORE dispatch and fail closed - same contract as the per-device route.
        if (!audit.persist(audit_result(plan.counts), type, target_id, audit_detail(sel, plan.counts))) {
            out.status = Status::AuditUnavailable;
            out.http = 503;
            out.message = "audit subsystem unavailable - request not served";
            out.retry_after_ms = 5000;
            return out;
        }

        DispatchResult sent;
        if (!plan.targets.empty())
            sent = env_.dispatch(session, plan.targets);
        if (!plan.targets.empty() && sent.sent == 0) {
            out.status = Status::NoneReachable;
            out.http = 503;
            out.message = "no selected device is reachable right now";
            out.retry_after_ms = 30000;
            return out;
        }
        if (guarded && sent.sent > 0) {
            const auto stamp_at = now(); // the clock is read outside the lock
            std::lock_guard<std::mutex> lk(mu_);
            stamp(last_run_, session.username, stamp_at);
        }
        out.status = Status::Accepted;
        out.http = 202;
        out.summary = summary_json(finalize(plan.counts, sent.sent), sent.command_id, now());
        return out;
    }

private:
    [[nodiscard]] std::int64_t now() const {
        if (env_.now)
            return env_.now();
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }
    [[nodiscard]] std::int64_t mono_ms() const {
        if (env_.mono_ms)
            return env_.mono_ms();
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }
    /// Milliseconds until the holder's lease lapses, never less than one second so a hint is
    /// always actionable.
    [[nodiscard]] std::int64_t slot_remaining_ms() const {
        const auto until = slot_until_ms_.load();
        const auto left = until - mono_ms();
        return left < 1000 ? 1000 : left;
    }

    /// The in-flight slot, as a lease. RAII: a guard that was not taken, or was released, does
    /// nothing; one whose lease was taken over cannot clear the new holder's lease (the release
    /// is a compare-exchange on its own deadline).
    struct Slot {
        explicit Slot(Runner& r) : r_(r) {}
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;
        ~Slot() { release(); }
        bool take() {
            const auto now_ms = r_.mono_ms();
            auto cur = r_.slot_until_ms_.load();
            if (cur != 0 && now_ms < cur)
                return false; // held and the lease has not lapsed
            const auto mine = now_ms + kSlotLeaseMs;
            if (!r_.slot_until_ms_.compare_exchange_strong(cur, mine))
                return false; // lost a race
            deadline_ = mine;
            return true;
        }
        void release() {
            if (deadline_ == 0)
                return;
            auto expected = deadline_;
            r_.slot_until_ms_.compare_exchange_strong(expected, 0);
            deadline_ = 0;
        }

    private:
        Runner& r_;
        std::int64_t deadline_{0};
    };

    Env env_;
    std::mutex mu_;
    std::unordered_map<std::string, std::int64_t> last_run_;
    /// 0 = free; otherwise the monotonic deadline of the holder's lease.
    std::atomic<std::int64_t> slot_until_ms_{0};
};

} // namespace yuzu::server::software_sync
