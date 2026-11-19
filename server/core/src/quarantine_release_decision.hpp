#pragma once

/// @file quarantine_release_decision.hpp
/// Pure decision core for the release half of device containment: what the reconciler does with a
/// device's reply to a status read or a mutation, what `DELETE /api/v1/quarantine/{agent_id}` does
/// with the outcome of its confirming write, how long the route waits for a reply, and which
/// status replies are worth keeping at the default lifetime.
///
/// PURE ON PURPOSE: standard library plus `quarantine_types.hpp` (the `QuarantineWrite` enum) and
/// `quarantine_reapply.hpp` (the `ContainmentReply` types), nothing that touches a store, a clock, a
/// socket or a lock. Every function is total over closed enums, with exhaustive switches and no
/// `default:` (the `quarantine_dispatch_decision.hpp` idiom), so a new enumerator fails to compile
/// here instead of falling through. The callers (`quarantine_containment_reconciler.cpp`,
/// `rest_api_v1.cpp`) own every effect: the store writes, the audit rows, the counters and the
/// mutex. The tables lived inline in those two files; extracting them lets one test exhaust every
/// branch without Postgres (#7585b), and gives the DELETE route's reply wait a loop a test can run
/// without sleeping (#7584a).
///
/// WHAT THE TABLES DO NOT DECIDE: whether an `inactive` answer may END a record. That is the apply
/// fence (`QuarantineStore::apply_fence_token`, `quarantine_reapply.hpp`): the caller presents the
/// generation it read before it sent the observing command, and the store refuses the end when an
/// apply was claimed since. A refusal arrives here as `QuarantineWrite::apply_in_flight`.

#include "quarantine_reapply.hpp"
#include "quarantine_types.hpp"

#include <optional>
#include <string>
#include <utility>

namespace yuzu::server {

/// What the row behind a reconciler entry is: an active record, one with a release requested (the
/// store reads it "releasing"), or one ended by force that still owes the device a release.
enum class ReconcileKind { active, releasing, owed };

// ── The reconciler's reply to a status read ─────────────────────────────────

struct StatusReplyFacts {
    ReconcileKind kind{ReconcileKind::active};
    QuarantineEndpointState state{QuarantineEndpointState::unconfirmed};
    bool confirms{false};        ///< `reply_confirms_containment(reply)`
    bool was_confirmed{false};   ///< the entry had confirmed this record before this read
    bool owed_parked{false};     ///< owed entry: parked after a release that did not take
    bool owed_release_sent{false}; ///< owed entry: this session's release has been sent
};

enum class StatusReplyAction {
    end_record,        ///< releasing + inactive: the device's word ends the record
    release_next,      ///< releasing + anything else: the next cycle dispatches a release
    clear_owed,        ///< owed + inactive: the device confirmed the owed release
    owed_keep_parked,  ///< owed, parked: a status-only read that still is not inactive
    owed_park,         ///< owed, release sent this session, still not inactive: say so once, park
    owed_release_next, ///< owed, nothing sent yet this session: the next cycle sends the release
    confirm,           ///< active + the device reports its rules in force
    drift,             ///< active, previously confirmed, no longer confirms
    stay_unconfirmed,  ///< active, never confirmed, does not confirm
};

[[nodiscard]] constexpr StatusReplyAction decide_status_reply(const StatusReplyFacts& f) {
    switch (f.kind) {
    case ReconcileKind::releasing:
        return f.state == QuarantineEndpointState::inactive ? StatusReplyAction::end_record
                                                            : StatusReplyAction::release_next;
    case ReconcileKind::owed:
        if (f.state == QuarantineEndpointState::inactive)
            return StatusReplyAction::clear_owed;
        if (f.owed_parked)
            return StatusReplyAction::owed_keep_parked;
        if (f.owed_release_sent)
            return StatusReplyAction::owed_park;
        return StatusReplyAction::owed_release_next;
    case ReconcileKind::active:
        if (f.confirms)
            return StatusReplyAction::confirm;
        return f.was_confirmed ? StatusReplyAction::drift : StatusReplyAction::stay_unconfirmed;
    }
    return StatusReplyAction::stay_unconfirmed; // unreachable while the switch stays exhaustive
}

/// Whether a status reply is evidence worth keeping at the response store's default lifetime
/// (#7627). True only for the four replies that changed what the server holds about the device: one
/// that ended a record, one that cleared an owed release, the first one that confirmed containment,
/// and one that showed drift. Every other status reply the reconciler reads (a repeat confirm, a
/// still-contained reply on a releasing record, a parked owed read, an unconfirmed reply) is
/// recurring and gets the short lifetime.
[[nodiscard]] constexpr bool status_reply_is_evidence(StatusReplyAction action, bool was_confirmed) {
    switch (action) {
    case StatusReplyAction::end_record:
    case StatusReplyAction::clear_owed:
    case StatusReplyAction::drift:
        return true;
    case StatusReplyAction::confirm:
        return !was_confirmed;
    case StatusReplyAction::release_next:
    case StatusReplyAction::owed_keep_parked:
    case StatusReplyAction::owed_park:
    case StatusReplyAction::owed_release_next:
    case StatusReplyAction::stay_unconfirmed:
        return false;
    }
    return false;
}

// ── The reconciler's reply to an apply or a release ─────────────────────────

struct MutationReplyFacts {
    ReconcileKind kind{ReconcileKind::active};
    bool was_apply{false};             ///< the pending command was an apply (else a release)
    bool apply_for_unconfirmed{false}; ///< the apply was for a record never confirmed
    bool allow_set_unchanged{false};   ///< the reply carried `kAllowSetUnchangedNote`
    QuarantineEndpointState state{QuarantineEndpointState::unconfirmed};
};

enum class MutationReplyAction {
    allow_set_kept,       ///< the device kept other exceptions: no status read, leave unconfirmed
    owed_release_unspent, ///< owed release answered busy: not spent, status first, send again
    wait_claim_interval,  ///< busy on anything else: wait the normal claim interval
    verify_next,          ///< whatever it said, read status next
};

/// No answer to `firewall.quarantine` or `firewall.release` ends anything, and dispatch acceptance is
/// not proof of containment, so the default is to read status next. The exceptions: an apply for a
/// never-confirmed record that the device answered by keeping other operator exceptions (a status
/// read would only confirm the wrong containment), and `busy`, which says the plugin's mutation gate
/// refused the command.
[[nodiscard]] constexpr MutationReplyAction decide_mutation_reply(const MutationReplyFacts& f) {
    if (f.was_apply && f.apply_for_unconfirmed && f.allow_set_unchanged)
        return MutationReplyAction::allow_set_kept;
    switch (f.state) {
    case QuarantineEndpointState::busy:
        // An owed release the device did not run at all leaves the session's one release unspent.
        return f.kind == ReconcileKind::owed && !f.was_apply
                   ? MutationReplyAction::owed_release_unspent
                   : MutationReplyAction::wait_claim_interval;
    case QuarantineEndpointState::active:
    case QuarantineEndpointState::active_unproven:
    case QuarantineEndpointState::inactive:
    case QuarantineEndpointState::unconfirmed:
        return MutationReplyAction::verify_next;
    }
    return MutationReplyAction::verify_next;
}

// ── DELETE /api/v1/quarantine/{agent_id} ────────────────────────────────────

enum class ReleaseNext {
    answer_released,                ///< the device's word ended the record: 200, device_confirmed
    answer_already_ended_confirmed, ///< another writer ended it first; this device did answer inactive
    mark_forced,                    ///< the operator forced it: end the record without the device
    answer_releasing,               ///< 202: the reconciler finishes it
};

/// What DELETE does after the device's reply. `confirmed_mark` is the outcome of the confirming
/// `mark_released(device_confirmed, fence)`, or empty when the device did not answer `inactive` (so
/// no mark was attempted). A refused mark (`apply_in_flight`: an apply followed the observation, or
/// the fence could not be read) and a store failure are not a confirmation: the plain call leaves
/// the record releasing, the forced call ends it by force.
[[nodiscard]] constexpr ReleaseNext release_next(std::optional<QuarantineWrite> confirmed_mark,
                                                 bool force) {
    if (confirmed_mark) {
        switch (*confirmed_mark) {
        case QuarantineWrite::ok:
            return ReleaseNext::answer_released;
        case QuarantineWrite::not_quarantined:
            return ReleaseNext::answer_already_ended_confirmed;
        case QuarantineWrite::apply_in_flight:
        case QuarantineWrite::store_error:
            break;
        }
    }
    return force ? ReleaseNext::mark_forced : ReleaseNext::answer_releasing;
}

enum class ForcedAnswer {
    forced,            ///< the record ended by force: 200, released:false
    already_ended,     ///< another writer ended it first
    store_unavailable, ///< retryable 503; the record stays releasing, never a 202 that hides it
};

/// The outcome of the forced `mark_released`. `apply_in_flight` cannot come from a forced end (it
/// takes no fence) and fails closed if it ever did.
[[nodiscard]] constexpr ForcedAnswer forced_answer(QuarantineWrite forced) {
    switch (forced) {
    case QuarantineWrite::ok:
        return ForcedAnswer::forced;
    case QuarantineWrite::not_quarantined:
        return ForcedAnswer::already_ended;
    case QuarantineWrite::store_error:
    case QuarantineWrite::apply_in_flight:
        return ForcedAnswer::store_unavailable;
    }
    return ForcedAnswer::store_unavailable;
}

/// The bounded wait for the device's reply to a command the route dispatched itself: `poll` first,
/// `pause` before each later poll (never before the first, so a reply that is already there costs no
/// pause), at most `max_polls` polls. `poll` returns the stored reply payload, or empty for a
/// degraded or empty read. The first payload with a `status|` line ends the wait; one without keeps
/// polling. The route injects `poll` and `pause`, so a test supplies the reply between two polls
/// without sleeping (#7584a).
template <typename Poll, typename Pause>
[[nodiscard]] std::optional<ContainmentReply> await_status_reply(int max_polls, Poll&& poll,
                                                                 Pause&& pause) {
    for (int i = 0; i < max_polls; ++i) {
        if (i > 0)
            pause();
        const std::optional<std::string> payload = poll();
        if (!payload)
            continue;
        auto parsed = parse_containment_reply(*payload);
        if (parsed.status_seen)
            return parsed;
    }
    return std::nullopt;
}

} // namespace yuzu::server
