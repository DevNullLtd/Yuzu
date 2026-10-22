#include "guardian_arm_ack.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <vector>

#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>

#include "guaranteed_state.pb.h"
#include "sync_canonical.hpp" // sha256_hex

namespace yuzu::agent {

namespace {

namespace gpb = ::yuzu::guardian::v1;

/// Length-prefixed field append ("<byte-length>:<bytes>"), NOT a bare separator
/// byte - a field's own content can legitimately contain any byte a param value
/// might (spark params are free-form strings), so a fixed separator alone is
/// injective only if no field can ever contain it. sync_canonical.hpp's own
/// clamp_field strips exactly this class of framing byte from ITS fields before
/// they cross the wire for the same reason this file has to canonicalize
/// without assuming its own inputs are pre-scrubbed. Length-prefixing makes the
/// encoding injective regardless of what a value contains.
void append_field(std::string& out, std::string_view s) {
    out += std::to_string(s.size());
    out.push_back(':');
    out += s;
}

std::string canonicalize_spec_block(const gpb::GuardianSpecBlock& block) {
    std::string out;
    append_field(out, block.type());
    // proto's map<string,string> iterates in an UNSPECIFIED (hash-map) order -
    // copying into std::map sorts it by key so two byte-identical blocks
    // always canonicalize identically, regardless of process or restart.
    const std::map<std::string, std::string> sorted(block.params().begin(), block.params().end());
    for (const auto& [k, v] : sorted) {
        append_field(out, k);
        append_field(out, v);
    }
    return out;
}

/// True iff `s` has the exact shape of a real `guardian_push_content_id()` output
/// (lowercase-or-uppercase hex, 64 chars - a SHA-256 digest). Governance finding
/// sec-1/arch-1 gate-review (rung 9c PR-2 hardening): decide_retry() must never
/// trust a content_id comparison where EITHER side is a sentinel rather than a
/// real hash - the empty string GuardianEngine::start_local()'s boot placeholder
/// uses, and the empty string guardian_push_content_id()'s own throw fallback
/// uses below, both fail this check trivially (wrong length), so two DIFFERENT
/// pushes that both hit the throw fallback (or one that collides with the boot
/// placeholder) can never be misread as "the same content" merely because their
/// sentinels are byte-identical to each other.
bool is_sha256_hex(std::string_view s) {
    if (s.size() != 64)
        return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

} // namespace

/// Governance finding SHOULD-1 (Gate 4, consistency-auditor): drain_locked()'s own
/// async-failure warn previously logged no reason at all, unlike the sync-refusal
/// warn in reconcile_rule_locked() which always names one. Exhaustive switch, no
/// `default`, mirroring GuardianSparkRuntime::receipt_status()'s own convention -
/// a future ReceiptStatus addition produces a missing-case WARNING here (this
/// repo's meson.build sets werror=false repo-wide, so it is not a build failure -
/// correcting an earlier overclaim in this comment), not a silent catch-all.
/// Exported (see the header declaration's own comment) so its mapping stays
/// directly unit-testable without LogCapture's cross-image hazard.
const char* receipt_status_name(GuardianSparkRuntime::ReceiptStatus status) {
    using S = GuardianSparkRuntime::ReceiptStatus;
    switch (status) {
    case S::Pending:
        return "Pending";
    case S::Committed:
        return "Committed";
    case S::Failed:
        return "Failed";
    case S::CongestionExpired:
        return "CongestionExpired";
    case S::Wedged:
        return "Wedged";
    case S::Withdrawn:
        return "Withdrawn";
    case S::Stopped:
        return "Stopped";
    }
    return "Unknown"; // unreachable if the switch above is kept exhaustive
}

std::string guardian_push_content_id(const gpb::GuaranteedStatePush& push) {
    std::vector<const gpb::GuaranteedStateRule*> sorted_rules;
    sorted_rules.reserve(static_cast<std::size_t>(push.rules_size()));
    for (const auto& r : push.rules())
        sorted_rules.push_back(&r);
    std::sort(sorted_rules.begin(), sorted_rules.end(),
             [](const gpb::GuaranteedStateRule* a, const gpb::GuaranteedStateRule* b) {
                 return a->rule_id() < b->rule_id();
             });

    std::string canon = push.full_sync() ? "F1" : "F0";
    for (const auto* r : sorted_rules) {
        append_field(canon, r->rule_id());
        append_field(canon, r->enabled() ? "1" : "0");
        append_field(canon, r->enforcement_mode());
        append_field(canon, std::to_string(r->version()));
        // Governance finding cae-1 (Gate 3, cpp-expert, verified with a hand-constructed
        // collision): concatenating each block's own already-field-injective output
        // directly is NOT block-boundary-injective - nothing marks where one block's
        // fields end and the next begins, so two rules with different (spark,
        // assertion) splits of the same flat field sequence canonicalize identically.
        // append_field() on the whole block output restores injectivity the same way
        // it already does for individual fields, by length-prefixing the boundary.
        append_field(canon, canonicalize_spec_block(r->spark()));
        append_field(canon, canonicalize_spec_block(r->assertion()));
        append_field(canon, canonicalize_spec_block(r->remediation()));
    }
    return sha256_hex(canon);
}

GuardianArmAckLedger::GuardianArmAckLedger() = default;
GuardianArmAckLedger::~GuardianArmAckLedger() = default;

void GuardianArmAckLedger::begin_application(std::uint64_t generation, std::string content_id,
                                             bool full_sync, std::size_t applied) {
    // Unconditionally replaces whatever was open - Astra opine review: "New
    // application: stale receipts cannot acknowledge it." The old Application's
    // pending map (if any) is simply destroyed here; its receipts' claims stay
    // owned by the runtime's own claims_ registry regardless (ArmReceipt is an
    // observation handle - see the header). Built LOCALLY and published only at the
    // end (rung 9c PR-5e, governance finding UP-1's own precedent applied here too):
    // a make_unique/allocation throw here leaves current_ completely untouched,
    // matching apply_rules()'s own firewall around this call. A fresh Application also
    // starts wedge_suppress_count at 0 (#5459): the safety valve's budget is reset by this
    // overload, by begin_full_application()/begin_delta_application() and in retire().
    // Replacing the open application wholesale also drops the retry obligation of any rule
    // a partial (delta) push omits: a known limit, see the design doc R5.3 known limits
    // and flip-gate AC-11. This overload is kept unchanged in #5547 C1 and carries nothing;
    // begin_delta_application() is the entry point that carries (see the header).
    auto next = std::make_unique<Application>();
    next->generation = generation;
    next->content_id = std::move(content_id);
    next->full_sync = full_sync;
    next->applied = applied;
    current_ = std::move(next);
}

void GuardianArmAckLedger::begin_full_application(std::uint64_t generation, std::string content_id,
                                                  std::size_t applied) {
    // Built LOCALLY and published last, like begin_application(): a throw anywhere below
    // (including the test hook) leaves current_, its obligations and its suppress budget
    // exactly as they were.
    auto next = std::make_unique<Application>();
    next->generation = generation;
    next->content_id = std::move(content_id);
    next->full_sync = true;
    next->applied = applied;
    if (current_) {
        // The only OBLIGATION a full sync carries is the unattributed legacy debt; every
        // per-rule outcome is dropped (the full sync re-arms its named rules and detaches
        // the rest). boot_claims is claim IDENTITY, not an obligation.
        next->inherited_latch = current_->inherited_latch || current_->latched_failure;
        next->boot_claims = current_->boot_claims;
    }
    if (begin_fault_hook_)
        begin_fault_hook_(BeginFaultSite::BeforePublish);
    current_ = std::move(next);
}

void GuardianArmAckLedger::begin_delta_application(
    std::uint64_t generation, std::string content_id, std::size_t applied,
    const std::set<std::string, std::less<>>& named_rules) {
    auto next = std::make_unique<Application>();
    next->generation = generation;
    next->content_id = std::move(content_id);
    next->full_sync = false;
    next->applied = applied;
    if (current_) {
        const Application& old = *current_;
        const auto omitted = [&named_rules](const std::string& id) {
            return !named_rules.contains(id);
        };
        // One source per id (a drain that threw between its insert and its erase leaves an id
        // in two of the old application's sets). Priority sync_failed_ids > failed_ids >
        // failed_receipts > pending: the most conservative, never-silently-dropped record wins.
        // The groups below are ordered so the MidCarry hook sits between the copies.
        for (const auto& id : old.failed_ids) {
            if (omitted(id) && !old.sync_failed_ids.contains(id))
                next->failed_ids.insert(id);
        }
        for (const auto& [id, receipt] : old.failed_receipts) {
            if (omitted(id) && !old.sync_failed_ids.contains(id) && !old.failed_ids.contains(id))
                next->failed_receipts.emplace(id, receipt);
        }
        for (const auto& [id, receipt] : old.pending) {
            if (omitted(id) && !old.sync_failed_ids.contains(id) && !old.failed_ids.contains(id) &&
                !old.failed_receipts.contains(id))
                next->pending.emplace(id, receipt);
        }
        if (begin_fault_hook_)
            begin_fault_hook_(BeginFaultSite::MidCarry);
        for (const auto& id : old.sync_failed_ids) {
            if (omitted(id))
                next->sync_failed_ids.insert(id);
        }
        // Set from what was actually carried, so the counter agrees with the sets by
        // construction (never copied from the old application).
        next->resolved_failed = next->failed_receipts.size() + next->failed_ids.size();
        // A boot tag rides only with an obligation that was carried.
        for (const auto& id : old.boot_origin_ids) {
            if (next->sync_failed_ids.contains(id) || next->failed_ids.contains(id) ||
                next->failed_receipts.contains(id) || next->pending.contains(id))
                next->boot_origin_ids.insert(id);
        }
        // Claim identity for named AND omitted rules: it is not an obligation, and a named
        // rule's re-observation of the same claim must keep its boot tag.
        next->boot_claims = old.boot_claims;
        next->inherited_latch = old.inherited_latch || old.latched_failure;
        // latched_failure stays false: this application has raised nothing yet.
        // wedge_suppress_count stays 0 (Ruling 22 (c)).
    }
    if (begin_fault_hook_)
        begin_fault_hook_(BeginFaultSite::BeforePublish);
    current_ = std::move(next);
}

void GuardianArmAckLedger::note_sync_failure(const std::string& rule_id, bool boot_origin) {
    if (!current_)
        return;
    Application& app = *current_;
    // The tag first, undone if the failure itself cannot be recorded: a boot tag must never
    // outlive (or exist without) the obligation it describes.
    const bool tag_added = boot_origin && app.boot_origin_ids.insert(rule_id).second;
    try {
        app.sync_failed_ids.insert(rule_id);
    } catch (...) {
        if (tag_added)
            app.boot_origin_ids.erase(rule_id);
        throw;
    }
}

void GuardianArmAckLedger::discharge_inherited_latch() noexcept {
    if (current_)
        current_->inherited_latch = false;
}

void GuardianArmAckLedger::set_begin_fault_hook_for_test(std::function<void(BeginFaultSite)> hook) {
    begin_fault_hook_ = std::move(hook);
}

void GuardianArmAckLedger::set_drain_fault_hook_for_test(
    std::function<void(DrainFaultSite, std::string_view)> hook) {
    drain_fault_hook_ = std::move(hook);
}

GuardianArmAckLedger::ObligationForTest
GuardianArmAckLedger::obligation_for_test(const std::string& rule_id) const {
    if (!current_)
        return ObligationForTest::None;
    if (current_->sync_failed_ids.contains(rule_id))
        return ObligationForTest::SyncFailed;
    if (current_->failed_ids.contains(rule_id))
        return ObligationForTest::FailedId;
    if (current_->failed_receipts.contains(rule_id))
        return ObligationForTest::FailedReceipt;
    if (current_->pending.contains(rule_id))
        return ObligationForTest::Pending;
    return ObligationForTest::None;
}
std::size_t GuardianArmAckLedger::failed_id_count_for_test() const {
    return current_ ? current_->failed_ids.size() : 0;
}
std::size_t GuardianArmAckLedger::sync_failed_count_for_test() const {
    return current_ ? current_->sync_failed_ids.size() : 0;
}
std::size_t GuardianArmAckLedger::boot_origin_count_for_test() const {
    return current_ ? current_->boot_origin_ids.size() : 0;
}
std::size_t GuardianArmAckLedger::boot_claim_count_for_test() const {
    return current_ ? current_->boot_claims.size() : 0;
}
bool GuardianArmAckLedger::boot_origin_for_test(const std::string& rule_id) const {
    return current_ && current_->boot_origin_ids.contains(rule_id);
}
bool GuardianArmAckLedger::latched_failure_for_test() const {
    return current_ && current_->latched_failure;
}
bool GuardianArmAckLedger::inherited_latch_for_test() const {
    return current_ && current_->inherited_latch;
}
std::size_t GuardianArmAckLedger::wedge_suppress_count_for_test() const {
    return current_ ? current_->wedge_suppress_count : 0;
}

void GuardianArmAckLedger::add_pending(std::string rule_id,
                                       GuardianSparkRuntime::ArmReceipt receipt, bool boot_origin) {
    if (!current_) {
        try {
            spdlog::error("Guardian: add_pending('{}') with no open application - dropped",
                         rule_id);
        } catch (...) {
        }
        return;
    }
    Application& app = *current_;
    // Effective boot tag: the caller's say-so, or a re-observation of the SAME claim an
    // earlier application registered as boot-origin (compared by claim pointer; boot_claims
    // holds a receipt, so the claim is alive and its address cannot be reused). A different
    // claim for the same rule id is a genuinely new attempt: not tagged, stale entry dropped.
    bool tag = boot_origin;
    if (!tag) {
        if (const auto it = app.boot_claims.find(rule_id); it != app.boot_claims.end()) {
            if (it->second.claim == receipt.claim)
                tag = true;
            else
                app.boot_claims.erase(it);
        }
    }
    bool tag_added = false;
    if (tag) {
        app.boot_claims.insert_or_assign(rule_id, receipt);
        tag_added = app.boot_origin_ids.insert(rule_id).second;
    }
    try {
        app.pending.insert_or_assign(rule_id, std::move(receipt));
    } catch (...) {
        if (tag_added)
            app.boot_origin_ids.erase(rule_id);
        throw;
    }
}

void GuardianArmAckLedger::latch_failure() noexcept {
    if (current_)
        current_->latched_failure = true;
}

std::size_t GuardianArmAckLedger::drain_locked(GuardianSparkRuntime& runtime,
                                               std::size_t max_per_tick, std::size_t* failed_out,
                                               bool* boot_origin_failed) {
    // Runtime-wide sweep, not scoped to this application's own pending set -
    // rung 9c PR-2 Unit 2's expire_overdue_claims() abandons any Arm claim
    // whose real deadline has passed regardless of which (if any) ledger is
    // watching it. Always run, even with no current application: a stray
    // overdue claim from a superseded application still needs to resolve.
    runtime.expire_overdue_claims();

    if (!current_)
        return 0;

    // rung 9c PR-5d (concern 2, arm-recovery): before scanning `pending`, check
    // whether any retained Wedged failure from an earlier drain has since been
    // ADOPTED by the runtime (concern 1's late-adoption path in on_arm_complete)
    // - i.e. its exact (rule_id, generation) incarnation is now the one
    // committed. `end`/receipt_status() never change on adoption (the receipt
    // stays Wedged by design), which is exactly why this needs its own signal -
    // GuardianSparkRuntime::receipt_recovery_status() - rather than re-draining
    // `pending` again. Deliberately unbounded (no max_per_tick cap, no cursor):
    // failed_receipts only ever holds rules that actually wedged, a naturally
    // small, rare population compared to a full ruleset - a bounded pass with a
    // resume cursor would be over-built for that shape here.
    //
    // rung 9c PR-5e (#4221 - adversarial review finding, Kimi K3 +
    // Codex Sol independently converging): this MUST be the combined
    // receipt_recovery_status() accessor, one registry_mu_ acquisition per entry -
    // NOT two sequential calls to receipt_recovered() then receipt_wedge_k_eligible()
    // (an earlier version of this loop did exactly that). Each standalone accessor
    // takes and releases registry_mu_ independently, so a genuine adoption landing in
    // the GAP between them - the first call correctly observing "not yet recovered",
    // then on_arm_complete() adopting and popping the claim before the second call
    // runs - reads as "not eligible either" and gets silently dropped from
    // failed_receipts WITHOUT decrementing resolved_failed, permanently losing a
    // genuine recovery this application would otherwise have recorded. Combining both
    // questions under the SAME lock acquisition closes that window entirely.
    for (auto it = current_->failed_receipts.begin(); it != current_->failed_receipts.end();) {
        switch (runtime.receipt_recovery_status(it->second)) {
        case GuardianSparkRuntime::RecoveryStatus::Recovered:
            // Clears THIS application's own resolved_failed contribution only -
            // never failed_out/arm_failures_, which is a cumulative counter (read only by
            // tests today, not fleet-visible, #4062) and must never decrement (this file's own
            // header treats "how many arm failures have ever happened" and "can the
            // CURRENT application's generation advance" as distinct questions;
            // only the latter recovers here).
            // #5547: the boot tag goes with the last obligation holding the id. Nothing
            // fallible sits between the counter and the erase (the tag erase is noexcept and
            // comes first), so an exception can never leave resolved_failed one low with the
            // entry still retained.
            if (!current_->pending.contains(it->first) &&
                !current_->failed_ids.contains(it->first) &&
                !current_->sync_failed_ids.contains(it->first))
                current_->boot_origin_ids.erase(it->first);
            if (current_->resolved_failed > 0)
                --current_->resolved_failed;
            it = current_->failed_receipts.erase(it);
            break;
        case GuardianSparkRuntime::RecoveryStatus::WedgeEligible:
        case GuardianSparkRuntime::RecoveryStatus::CompensationPending:
            // #5459 (option D): both are OUTSTANDING wedges and both stay retained, so
            // decide_retry() keeps a handle on them. CompensationPending (#4472: the
            // late result has returned and its compensating teardown is outstanding)
            // used to be erased here as Blocking, which destroyed the only handle the
            // ledger had and made every held push pay a full teardown. Retaining it
            // never acknowledges anything: resolved_failed stays counted, so
            // can_advance() stays false until the teardown pops the claim.
            ++it;
            break;
        case GuardianSparkRuntime::RecoveryStatus::Blocking: {
            // This entry has settled to a genuine, non-outstanding failure since it
            // was retained - a Dispatching-window race corrected to a genuine
            // Failed/Stopped/AdmissionRejected outcome, or the claim was popped from
            // its key's FIFO by a real completion nobody adopted (a late failure, or a
            // compensating teardown that finished). It is an ORDINARY failure now, so it
            // leaves the outstanding-wedge set, but it is still a genuine, counted failure:
            // #5547 keeps its rule id in failed_ids (resolved_failed is unchanged when the
            // id is new there), so a replacing delta that omits the rule still carries the
            // obligation. failed_ids != empty is what forces decide_retry() to Reapply
            // (the rule must be re-armed) and what keeps can_advance() false. The runtime
            // invariant this depends on (#4472): compensation_finished=true is always
            // written in the same critical section as the pop of the claim (or the
            // dispatch -> Queued double-fault hand-back), so a Blocking reading never
            // races a claim that is finished but still the Dispatched head.
            //
            // Ordering: the fallible insertion comes BEFORE the erase, so a throwing insert
            // leaves the entry exactly where it was (still counted, still retained).
            if (drain_fault_hook_)
                drain_fault_hook_(DrainFaultSite::BeforeBlockingInsert, it->first);
            const bool added = current_->failed_ids.insert(it->first).second;
            // The id already being in failed_ids means this entry was a second record of
            // one failure; dropping it must take its count with it to keep
            // resolved_failed == failed_receipts.size() + failed_ids.size().
            if (!added && current_->resolved_failed > 0)
                --current_->resolved_failed;
            it = current_->failed_receipts.erase(it);
            break;
        }
        }
    }

    std::size_t resolved = 0;
    for (auto it = current_->pending.begin();
        it != current_->pending.end() && resolved < max_per_tick;) {
        // rung 9c PR-5e (#4221 - cpp-safety governance finding):
        // MUST be the combined receipt_status_wedge_aware() atomic read, one
        // registry_mu_ acquisition - NOT receipt_status() followed by a separate
        // receipt_wedge_k_eligible() call on the Wedged case (an earlier version
        // of this loop did exactly that). A genuine adoption landing in the gap
        // between two separate calls could read Wedged here, then read
        // not-eligible moments later after on_arm_complete() already adopted and
        // popped the claim - the receipt would be counted as an ordinary failure
        // below (the fallthrough is unconditional on `status` alone) while never
        // being retained in failed_receipts, permanently desyncing
        // resolved_failed from failed_receipts.size() for this application (which
        // decide_retry() reads as a non-wedge failure and answers with a Reapply, so it
        // self-heals on the next identical retry). Same TOCTOU class the
        // adversarial review already found and fixed in the recovery-scan loop
        // above (receipt_recovery_status()'s own doc comment), reachable here too
        // until this single-read fix.
        const auto wedge_aware = runtime.receipt_status_wedge_aware(it->second);
        const auto status = wedge_aware.status;
        // Exhaustive switch, no `default` - SHOULD-1's own fix (see the
        // receipt_status_name() helper above): a future ReceiptStatus value
        // produces a missing-case WARNING here (werror=false repo-wide - not a
        // build failure), rather than silently landing in a catch-all "failed"
        // bucket the way the old if/else-if/else chain would have.
        //
        // rung 9c PR-5c (#4221): CongestionExpired and Wedged both fold into
        // resolved_failed exactly like the pre-split Expired did - neither
        // represents a committed arm. A Wedged receipt counts as an ordinary
        // resolved failure - once per rule id within an application (#5547: a
        // re-drain of the same id is not counted again), while a repeated
        // application can still count the same wedge again - nothing about up-2's
        // re-observation changes that (re-observation exists so a TYPED Wedged
        // status reaches this ledger at all, not to change what it means once it
        // arrives). #5459 (option D) removed the K-bound acknowledgment entirely: a
        // counted wedge holds the generation until recovered or replaced.
        using S = GuardianSparkRuntime::ReceiptStatus;
        switch (status) {
        case S::Pending:
            ++it;
            continue;
        case S::Committed:
            ++current_->resolved_armed;
            // Committed: the rule has no obligation left, so its boot tag goes with it. The
            // id is still in `pending` here, hence the explicit exclusion.
            if (!current_->failed_receipts.contains(it->first) &&
                !current_->failed_ids.contains(it->first) &&
                !current_->sync_failed_ids.contains(it->first))
                current_->boot_origin_ids.erase(it->first);
            break;
        case S::Wedged:
        case S::Failed:
        case S::CongestionExpired:
        case S::Withdrawn:
        case S::Stopped: {
            // Every non-Committed, non-Pending status is a counted failure.
            //
            // #5547: TRANSACTIONAL and idempotent. The fallible set insertion comes FIRST;
            // resolved_failed, *failed_out and *boot_origin_failed move only when it added a
            // new element, so a receipt a throw left behind in `pending` is not counted a
            // second time by the next drain. Everything after the insertion is noexcept or
            // contained (the log and the test diagnostic), and the receipt is erased from
            // `pending` last.
            //
            // Which set records it: a Wedged receipt that is wedge-eligible or compensation-
            // pending is RETAINED (failed_receipts; rung 9c PR-5d concern 2 - the only status
            // a later runtime adoption can retroactively recover). Retention is gated on the
            // flags of the SAME atomic read that produced status == Wedged (rung 9c PR-5e,
            // #4221; see the comment above the read): expire_overdue_claims() just above can
            // mint WaiterTimedOutDispatched for a claim still mid-dispatch, and inserting that
            // provisional classification would open a one-tick gap. Every other failure
            // (Failed, CongestionExpired, Withdrawn, Stopped, and a Wedged receipt that is
            // neither flag) keeps only its rule id, in failed_ids; the receipt is discarded.
            // Only a Wedged receipt can later be adopted by the runtime, and a Wedged one that
            // reaches here with neither flag stays an ordinary failure (flip-gate AC-15,
            // unchanged by #5547; retaining it is FU-14, #5548).
            const std::string& id = it->first;
            bool added = false;
            if (status == S::Wedged &&
                (wedge_aware.wedge_eligible || wedge_aware.compensation_pending)) {
                const auto [kept, inserted] = current_->failed_receipts.try_emplace(id, it->second);
                if (!inserted)
                    kept->second = it->second; // refresh the handle; already counted
                added = inserted;
            } else {
                added = current_->failed_ids.insert(id).second;
            }
            if (added) {
                ++current_->resolved_failed;
                if (failed_out)
                    ++*failed_out; // UP-3: feeds GuardianEngine::arm_failures_ (see caller)
                if (boot_origin_failed && current_->boot_origin_ids.contains(id))
                    *boot_origin_failed = true;
                // rung 9c PR-2 Unit 6: the only place this can be logged - reconcile_rule_locked's
                // own "spark arm failed" warn fires only for a SYNCHRONOUS refusal now; an
                // Accepted rule that later resolves to anything but Committed would otherwise be
                // silent on a Guaranteed State product. Heartbeat thread: contained, like every
                // other log call on this path. Names `status` per governance finding SHOULD-1
                // (Gate 4, consistency-auditor) - the sync-refusal warn in
                // reconcile_rule_locked() already names its own failure reason, and this one
                // silently didn't. Logged once per distinct failure (not on a re-drain).
                try {
                    spdlog::warn("Guardian: spark arm failed for rule '{}' (accepted, resolved "
                                 "asynchronously, status={})",
                                 log_id_token(id), receipt_status_name(status));
                } catch (...) {}
                // Test diagnostic only: best-effort, never allowed to fail the drain.
                try {
                    current_->resolved_statuses_for_test.push_back(status);
                } catch (...) {}
            }
            if (drain_fault_hook_)
                drain_fault_hook_(DrainFaultSite::AfterAccounting, id);
            break;
        }
        }
        it = current_->pending.erase(it);
        ++resolved;
    }
    return resolved;
}

bool GuardianArmAckLedger::can_advance() const {
    // #5459 (option D): the conservative branch ONLY. There is no wedge escape: an
    // outstanding wedge, a compensation-pending wedge, and every ordinary failure keep
    // resolved_failed > 0, which holds the generation until a genuine recovery
    // (drain_locked() decrements it for an adopted late success) or a fresh successful
    // application replaces this one. Holding the generation is what keeps the server's
    // full_sync re-push alive; decide_retry() is what stops each held re-push from
    // costing a teardown.
    return current_ && current_->pending.empty() && !current_->latched_failure &&
           !current_->inherited_latch && current_->resolved_failed == 0 &&
           current_->sync_failed_ids.empty();
}

std::size_t GuardianArmAckLedger::applied_count() const {
    return current_ ? current_->applied : 0;
}

std::size_t GuardianArmAckLedger::pending_count_for_test() const {
    return current_ ? current_->pending.size() : 0;
}

std::size_t GuardianArmAckLedger::failed_receipt_count_for_test() const {
    return current_ ? current_->failed_receipts.size() : 0;
}

std::vector<GuardianSparkRuntime::ReceiptStatus>
GuardianArmAckLedger::resolved_statuses_for_test() const {
    return current_ ? current_->resolved_statuses_for_test
                    : std::vector<GuardianSparkRuntime::ReceiptStatus>{};
}

std::optional<GuardianArmStats> GuardianArmAckLedger::arm_stats() const {
    if (!current_)
        return std::nullopt;
    GuardianArmStats s;
    s.pending = static_cast<std::uint64_t>(current_->pending.size());
    s.failed = static_cast<std::uint64_t>(current_->resolved_failed);
    return s;
}

void GuardianArmAckLedger::set_applied(std::size_t applied) {
    if (current_)
        current_->applied = applied;
}

std::uint64_t GuardianArmAckLedger::pending_generation() const {
    return current_ ? current_->generation : 0;
}

GuardianArmAckLedger::RetryDecision GuardianArmAckLedger::decide_retry(
    std::uint64_t generation, const std::string& content_id, bool full_sync,
    const GuardianSparkRuntime& runtime) {
    using S = GuardianSparkRuntime::ReceiptStatus;
    if (!current_)
        return RetryDecision::Reapply; // nothing open to suppress against
    auto& app = *current_;
    // Identity checks come FIRST (#5459: they used to sit behind an early empty-pending
    // Reapply, which an outstanding wedge in an application with nothing left pending
    // could never get past).
    if (app.generation != generation)
        return RetryDecision::Reapply; // a different generation is not a retry at all
    // Governance finding UP-2/SHOULD-2 (Gate 4, converged independently from two
    // reviewers): a content_id that is not an actual SHA-256 digest is a SENTINEL,
    // never a real content identity - GuardianEngine::start_local()'s boot
    // placeholder and guardian_push_content_id()'s own throw fallback both use the
    // empty string today. Two DIFFERENT pushes that both hit the throw fallback (or
    // a real post-boot push landing at the same generation the boot placeholder
    // opened) must never be read as "identical content" merely because their
    // sentinels happen to be byte-identical to each other - that comparison was
    // never meaningful in the first place.
    if (!is_sha256_hex(app.content_id) || !is_sha256_hex(content_id))
        return RetryDecision::Reapply;
    if (app.content_id != content_id || app.full_sync != full_sync)
        return RetryDecision::Reapply; // same generation number, changed content underneath it
    if (app.latched_failure || app.inherited_latch)
        return RetryDecision::Reapply; // an apply_rules() generation-hold failure (its own, or
                                       // inherited from an earlier application, #5547) - a real
                                       // re-apply is owed
    // #5547: a drained non-wedge failure (failed_ids) or a synchronous per-rule failure
    // (sync_failed_ids) is a failure the rule must be re-armed for. Checked BEFORE the
    // count test below because a sync failure is not in resolved_failed at all, so with a
    // co-held live wedge the counts would be equal and the wedge would Suppress the retry.
    if (!app.failed_ids.empty() || !app.sync_failed_ids.empty())
        return RetryDecision::Reapply;
    // Every COUNTED failure must have a retained outstanding-wedge candidate (see
    // Application::failed_receipts). A count with no retained receipt is a genuine
    // non-wedge failure (an ordinary Failed/Congestion/Withdrawn/Stopped, or a wedge
    // whose claim has since popped) - the rule must be re-armed. Since #5547 such a
    // failure is recorded in failed_ids and already answered Reapply above; this test
    // stays as a second check against a counter that disagrees with the sets.
    // Necessary, not sufficient: each retained candidate is re-read LIVE below, never
    // trusted from the map (it can be stale between drains).
    if (app.resolved_failed != app.failed_receipts.size())
        return RetryDecision::Reapply;

    bool outstanding_wedge = false;
    for (const auto& entry : app.failed_receipts) {
        // ONE combined accessor, one registry_mu_ acquisition per entry (the same TOCTOU
        // reasoning as drain_locked()'s recovery scan: never assemble this from
        // receipt_status_wedge_aware() plus a second call).
        switch (runtime.receipt_recovery_status(entry.second)) {
        case GuardianSparkRuntime::RecoveryStatus::WedgeEligible:
        case GuardianSparkRuntime::RecoveryStatus::CompensationPending:
            outstanding_wedge = true;
            break;
        case GuardianSparkRuntime::RecoveryStatus::Recovered:
            // #5459 (Fable review finding): a retained wedge whose late success was ADOPTED
            // since the last drain reads sticky Wedged but is no longer the FIFO front
            // (adoption and the pop are ONE registry_mu_ critical section), so the old
            // "still Wedged and eligible/compensating" test called it a settled failure
            // and answered Reapply - a teardown of the rule that had JUST armed. It is
            // OUTSTANDING WORK instead: it never acknowledges (resolved_failed is still
            // counted until the next tick's recovery scan decrements it, after which
            // can_advance() acks), and this push is suppressed until then. It counts toward
            // the safety valve like any other Suppress below (deliberate: the window is one
            // heartbeat tick, so the valve is usually not the binding bound for it; if the
            // budget is already spent, a forced Reapply re-arms the just-recovered rule
            // (safe direction: one wasted teardown, never an acknowledgment); an uncounted
            // Suppress would be a second unbounded path).
            outstanding_wedge = true;
            break;
        case GuardianSparkRuntime::RecoveryStatus::Blocking:
            return RetryDecision::Reapply; // popped / settled since the last drain: a real failure now
        }
    }
    // drain_locked() is BOUNDED - a receipt past one tick's cap can still sit in
    // `pending` long after it actually resolved. Suppress means every pending receipt is
    // STILL genuinely Pending (or Committed), or a live outstanding wedge the bounded
    // drain has not reached yet (otherwise the bound alone would cause avoidable
    // Reapplies) - so consult the runtime directly rather than trust resolved_failed
    // alone (which only counts what drain_locked has actually retired so far).
    for (const auto& entry : app.pending) {
        const auto s = runtime.receipt_status_wedge_aware(entry.second);
        if (s.status == S::Pending || s.status == S::Committed)
            continue;
        if (s.status == S::Wedged && (s.wedge_eligible || s.compensation_pending)) {
            outstanding_wedge = true;
            continue;
        }
        return RetryDecision::Reapply;
    }

    if (!outstanding_wedge) {
        // Governance finding sec-1/arch-1 (Gates 2-4, 5x independently confirmed - the
        // production-live wedge): the whole reason this dedup exists is to protect a
        // claim that is genuinely still in flight from a spurious re-teardown+re-arm on
        // an identical retry. With nothing pending and no outstanding wedge there is
        // NOTHING to protect, and Suppressing here would swallow the one thing
        // apply_rules()'s own tail gate still needs to do on a repeat push: retry a
        // policy-generation persist that failed last time (an empty `pending` used to
        // fall through to a vacuous Suppress and silently, permanently wedge the
        // reported generation below the server's value until restart). Reapply restores
        // a full re-run of apply_rules. Since #4415 that re-run no longer tears down a rule
        // that is healthy and unchanged (attach_core() skips it), but it still rebuilds one
        // that is not, so it is not free for those; what it restores is that the retry runs
        // AT ALL. With pending non-empty and
        // every receipt Pending/Committed, an identical retry is a pure Suppress.
        return app.pending.empty() ? RetryDecision::Reapply : RetryDecision::Suppress;
    }

    // Safety valve (#5459): a decision-count bound on wedge/compensation suppression.
    // See kWedgeSuppressMaxDecisions for what it does and does not buy. The counter is
    // incremented ONLY here, and reset only by begin_application()/begin_*_application()/retire().
    if (app.wedge_suppress_count >= kWedgeSuppressMaxDecisions)
        return RetryDecision::Reapply;
    ++app.wedge_suppress_count;
    return RetryDecision::Suppress;
}

void GuardianArmAckLedger::retire() {
    current_.reset(); // §R5.5: in-flight workers finish on their own schedule; this just
                      // stops watching them, exactly as begin_application() already does
                      // for a superseded application.
}

} // namespace yuzu::agent
