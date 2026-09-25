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
    // rung 9c PR-5e (#4221, K-bound closeout, decision 1): decide the incoming
    // application's reapply_count BEFORE current_ is touched - an exact identity
    // match against the OUTGOING application (same comparison decide_retry() already
    // uses: both digests real SHA-256, not a sentinel) inherits its saturated count;
    // anything else - a distinct generation/content_id/full_sync, an invalid digest
    // on either side, or no prior application at all - starts fresh at 0. Read-only
    // string/int comparisons only, nothing here can throw.
    std::size_t reapply_count = 0;
    if (current_ && current_->generation == generation && current_->full_sync == full_sync &&
        is_sha256_hex(current_->content_id) && is_sha256_hex(content_id) &&
        current_->content_id == content_id) {
        reapply_count = std::min(current_->reapply_count + 1, kReapplyWaiverThreshold);
    }
    // Unconditionally replaces whatever was open - Astra opine review: "New
    // application: stale receipts cannot acknowledge it." The old Application's
    // pending map (if any) is simply destroyed here; its receipts' claims stay
    // owned by the runtime's own claims_ registry regardless (ArmReceipt is an
    // observation handle - see the header). Built LOCALLY and published only at the
    // end (rung 9c PR-5e, governance finding UP-1's own precedent applied here too):
    // a make_unique/allocation throw here leaves current_ - and its reapply_count -
    // completely untouched, matching apply_rules()'s own firewall around this call.
    auto next = std::make_unique<Application>();
    next->generation = generation;
    next->content_id = std::move(content_id);
    next->full_sync = full_sync;
    next->applied = applied;
    next->reapply_count = reapply_count;
    current_ = std::move(next);
}

void GuardianArmAckLedger::add_pending(std::string rule_id,
                                       GuardianSparkRuntime::ArmReceipt receipt) {
    if (!current_) {
        try {
            spdlog::error("Guardian: add_pending('{}') with no open application - dropped",
                         rule_id);
        } catch (...) {
        }
        return;
    }
    current_->pending.insert_or_assign(std::move(rule_id), std::move(receipt));
}

void GuardianArmAckLedger::latch_failure() {
    if (current_)
        current_->latched_failure = true;
}

std::size_t GuardianArmAckLedger::drain_locked(GuardianSparkRuntime& runtime,
                                               std::size_t max_per_tick,
                                               std::size_t* failed_out) {
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
    // rung 9c PR-5e (#4221, K-bound closeout - adversarial review finding, Kimi K3 +
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
            // never failed_out/arm_failures_, which is a cumulative fleet-visible
            // audit counter and must never decrement (this file's own header
            // treats "how many arm failures have ever happened" and "can the
            // CURRENT application's generation advance" as distinct questions;
            // only the latter recovers here).
            if (current_->resolved_failed > 0)
                --current_->resolved_failed;
            it = current_->failed_receipts.erase(it);
            break;
        case GuardianSparkRuntime::RecoveryStatus::WedgeEligible:
            ++it;
            break;
        case GuardianSparkRuntime::RecoveryStatus::Blocking:
            // rung 9c PR-5e (#4221, K-bound closeout): this entry's K-eligibility has
            // settled to false since it was retained - a Dispatching-window race
            // corrected to a genuine Failed/Stopped/AdmissionRejected outcome, or the
            // claim was popped from its key's FIFO by a real completion (the
            // "still-claimed" requirement; see receipt_wedge_k_eligible()'s own doc
            // comment). It is now an ORDINARY blocking failure - never K-waivable -
            // so it is dropped from the waiver-eligible set here, but resolved_failed
            // is deliberately left UNTOUCHED: this is still a genuine, counted
            // failure, only its membership in the Wedged-only carve-out changes. This
            // is what keeps can_advance()'s `resolved_failed == failed_receipts.size()`
            // check a SAFE predicate rather than a stale one.
            it = current_->failed_receipts.erase(it);
            break;
        }
    }

    std::size_t resolved = 0;
    for (auto it = current_->pending.begin();
        it != current_->pending.end() && resolved < max_per_tick;) {
        // rung 9c PR-5e (#4221, K-bound closeout - cpp-safety governance finding):
        // MUST be the combined receipt_status_wedge_aware() atomic read, one
        // registry_mu_ acquisition - NOT receipt_status() followed by a separate
        // receipt_wedge_k_eligible() call on the Wedged case (an earlier version
        // of this loop did exactly that). A genuine adoption landing in the gap
        // between two separate calls could read Wedged here, then read
        // not-eligible moments later after on_arm_complete() already adopted and
        // popped the claim - the receipt would be counted as an ordinary failure
        // below (the fallthrough is unconditional on `status` alone) while never
        // being retained in failed_receipts, permanently desyncing
        // resolved_failed from failed_receipts.size() for this application (self-
        // heals only on the next identical retry). Same TOCTOU class the
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
        // represents a committed arm. This PR adds classification only, not the
        // later K-bound acknowledgement policy (5e): a Wedged receipt still
        // counts as an ordinary resolved failure on every drain, and a repeated
        // application can still count the same wedge again - nothing about up-2's
        // re-observation changes that (re-observation exists so a TYPED Wedged
        // status reaches this ledger at all, not to change what it means once it
        // arrives).
        using S = GuardianSparkRuntime::ReceiptStatus;
        switch (status) {
        case S::Pending:
            ++it;
            continue;
        case S::Committed:
            ++current_->resolved_armed;
            break;
        case S::Wedged:
            // rung 9c PR-5d (concern 2): retain the receipt itself (not just the
            // rule_id) BEFORE the shared accounting below erases it from
            // `pending` - this is the only failure status a later runtime
            // adoption can retroactively recover (see failed_receipts' own doc
            // comment on Application). A copy, not a move: `it->second` is read
            // again below by nothing else in this loop, but keeping the copy
            // explicit here avoids coupling this case's own lifetime to the
            // shared fallthrough body's unrelated edits.
            //
            // rung 9c PR-5e (#4221, K-bound closeout): retain it into the
            // K-eligible set ONLY if `wedge_aware.wedge_eligible` ALSO read true
            // in the SAME atomic read that produced `status == Wedged` above -
            // NOT unconditionally on every Wedged status, and NOT via a second,
            // separately-locked call (see this loop's own comment above the
            // switch for why a second call would reintroduce a TOCTOU).
            // expire_overdue_claims() just above (this same drain_locked() call)
            // can itself mint end==WaiterTimedOutDispatched for a claim still
            // mid-dispatch (the Dispatching-window race's own unsettled window,
            // dispatch still Dispatching, not yet Dispatched) - without this
            // check, THIS SAME call would insert a provisional, not-yet-settled
            // classification straight into failed_receipts, and the recovery-
            // scan loop above only re-validates EXISTING entries from a PRIOR
            // drain, so the gap would stand open for one full tick. resolved_failed
            // still increments below regardless (it is still counted as an
            // ordinary failure - only its K-eligible-set MEMBERSHIP is gated).
            if (wedge_aware.wedge_eligible)
                current_->failed_receipts.insert_or_assign(it->first, it->second);
            [[fallthrough]];
        case S::Failed:
        case S::CongestionExpired:
        case S::Withdrawn:
        case S::Stopped:
            ++current_->resolved_failed;
            if (failed_out)
                ++*failed_out; // UP-3: feeds GuardianEngine::arm_failures_ (see caller)
            // rung 9c PR-2 Unit 6: the only place this can be logged - reconcile_rule_locked's
            // own "spark arm failed" warn fires only for a SYNCHRONOUS refusal now; an
            // Accepted rule that later resolves to anything but Committed would otherwise be
            // silent on a Guaranteed State product. Heartbeat thread: contained, like every
            // other log call on this path. Names `status` per governance finding SHOULD-1
            // (Gate 4, consistency-auditor) - the sync-refusal warn in
            // reconcile_rule_locked() already names its own failure reason, and this one
            // silently didn't.
            try {
                spdlog::warn("Guardian: spark arm failed for rule '{}' (accepted, resolved "
                             "asynchronously, status={})",
                             log_id_token(it->first), receipt_status_name(status));
            } catch (...) {
            }
            // Governance follow-up (Gate 3, cpp-safety + cpp-expert; Gate 4,
            // unhappy-path, 2026-09-16): pushed LAST in this branch, after
            // resolved_failed/failed_out are already consistent with each other -
            // a push_back bad_alloc here leaves this receipt un-erased (still in
            // `pending`, re-drained and re-counted together next tick) rather than
            // desyncing resolved_failed from failed_out the way an earlier-ordered
            // push_back could have.
            current_->resolved_statuses_for_test.push_back(status);
            break;
        }
        it = current_->pending.erase(it);
        ++resolved;
    }
    return resolved;
}

bool GuardianArmAckLedger::can_advance() const {
    if (!current_)
        return false; // nothing to advance FOR - not the same question as "may advance"
    if (!current_->pending.empty() || current_->latched_failure)
        return false;
    if (current_->resolved_failed == 0)
        return true;
    // rung 9c PR-5e (#4221, K-bound closeout, decision 1): every remaining resolved
    // failure is a currently-eligible Wedged entry - failed_receipts is kept pruned
    // to exactly that set every drain_locked() tick (see its own recovery-loop
    // comment), so this equality is a safe predicate, not a stale snapshot - AND this
    // application-sequence has been identically re-applied at least
    // kReapplyWaiverThreshold times. A non-Wedged failure, or a Wedged entry whose
    // eligibility has since settled to false, is never part of failed_receipts, so it
    // always breaks this equality and blocks the waiver, no matter how high
    // reapply_count climbs.
    return current_->resolved_failed == current_->failed_receipts.size() &&
          current_->reapply_count >= kReapplyWaiverThreshold;
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

std::size_t GuardianArmAckLedger::reapply_count_for_test() const {
    return current_ ? current_->reapply_count : 0;
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
    const GuardianSparkRuntime& runtime) const {
    if (!current_)
        return RetryDecision::Reapply; // nothing open to suppress against
    // Governance finding sec-1/arch-1 (Gates 2-4, 5x independently confirmed - the
    // production-live wedge): the WHOLE reason this dedup exists is to protect a
    // claim that is genuinely still in flight from a spurious re-teardown+re-arm on
    // an identical retry (see this file's header). With nothing pending there is
    // NOTHING to protect - either no rule was ever Accepted this application (the
    // ordinary case at prefer_spark_=false, where Accepted never occurs at all) or
    // everything already resolved - so Suppressing here served no purpose except to
    // ALSO swallow the one thing apply_rules()'s own tail gate still needed to do on
    // a repeat push: retry a policy-generation persist that failed last time. Before
    // this fix, an empty `pending` map fell all the way through to a vacuous
    // Suppress, and the retry that would have re-attempted the failed persist never
    // ran - silently and permanently wedging the reported generation below the
    // server's value until restart. Reapply here restores exact pre-PR behavior for
    // this case: a full re-run, matching what a retry always did before this ledger
    // existed - NOT free (governance finding, Gate 8: consistency-auditor, happy-
    // path and security-guardian each independently caught an earlier draft of this
    // comment overclaiming "costs nothing"). A full_sync retry still pays the same
    // real teardown+re-arm cycle (attach_core() rebuilds eval state from scratch on
    // every push, identical re-push included - there is no diff-skip) it always
    // paid pre-ledger; what this fix restores is that the retry runs AT ALL, not
    // that it becomes cheap.
    if (current_->pending.empty())
        return RetryDecision::Reapply;
    if (current_->generation != generation)
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
    if (!is_sha256_hex(current_->content_id) || !is_sha256_hex(content_id))
        return RetryDecision::Reapply;
    if (current_->content_id != content_id || current_->full_sync != full_sync)
        return RetryDecision::Reapply; // same generation number, changed content underneath it
    if (current_->latched_failure || current_->resolved_failed > 0)
        return RetryDecision::Reapply; // something already failed - a real re-apply is owed
    // drain_locked() is BOUNDED - a receipt past one tick's cap can still sit in
    // `pending` long after it actually resolved. Suppress means every pending
    // receipt is STILL genuinely Pending, not merely "not yet drained" - so consult
    // the runtime directly rather than trust resolved_failed alone (which only
    // counts what drain_locked has actually retired so far).
    for (const auto& entry : current_->pending) {
        const auto status = runtime.receipt_status(entry.second);
        if (status != GuardianSparkRuntime::ReceiptStatus::Pending &&
            status != GuardianSparkRuntime::ReceiptStatus::Committed)
            return RetryDecision::Reapply;
    }
    return RetryDecision::Suppress; // identical content, nothing failed yet, rest still pending
}

void GuardianArmAckLedger::retire() {
    current_.reset(); // §R5.5: in-flight workers finish on their own schedule; this just
                      // stops watching them, exactly as begin_application() already does
                      // for a superseded application.
}

} // namespace yuzu::agent
