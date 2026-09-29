#pragma once

/**
 * spark_key_rule_index.hpp - the consumer-side spark_key -> {rule_id} index
 * (ADR-0021 Stage 2 rung 2, slice 2a).
 *
 * The SparkEngine dedups arming by spark_key: N subscriptions with an equal
 * (type, params) spec share ONE watcher, and a SparkEvent carries only its
 * `key`, never a rule_id or SubscriptionId (spark.hpp). So a Guardian-style
 * consumer that must map each event back to the rules it should evaluate owns
 * this reverse mapping itself; the rule-agnostic engine cannot.
 *
 * Two roles in one small value type:
 *   1. Fan-out register-of-record. rules_for(key) answers "which rules must I
 *      evaluate for this event" when a single shared watcher fires ONE event
 *      for MANY rules (governance UP-11 / happy-path Issue 2).
 *   2. Shared-watcher refcount. add() reports the 0->1 edge (arm the watcher)
 *      and remove_rule() reports the ->0 edge (disarm it), so withdrawing rule
 *      A never blinds rule B that shares the same key.
 *
 * Proto-free and lock-free by design: plain state owned by one consumer and
 * mutated only under that consumer's own serialisation. Each rule maps to
 * exactly one key at a time (its current spec); a redeploy that changes the
 * spec is a remove-then-add, which add() handles internally.
 *
 * Slice 2a builds and unit-tests this INERT: nothing arms yet, so at agent
 * runtime it is never populated and stays empty. Slice 2b populates it at arm
 * time and drives SparkEngine::arm()/disarm() off the 0->1 / ->0 edges.
 */

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

class SparkKeyRuleIndex {
public:
    /// Associate `rule_id` with `spark_key`, owned by `generation` (rung 9c PR-5a,
    /// #4221 up-101). If the rule is already mapped to a DIFFERENT key (a redeploy
    /// that changed the spec), it is first removed from that key. An identical
    /// (key, rule) pair is NOT a pure no-op when `generation` differs from the
    /// stored owner: ownership transfers to the NEW generation (the caller with the
    /// most recent `add()` call is always the recorded owner), but the fan-out/
    /// refcount state itself is unchanged - still an idempotent no-op from
    /// `rules_for`/`refcount`'s point of view. This ownership transfer is what makes
    /// erase_rule() safe against a stale, retried release from an OLDER incarnation
    /// of the same rule (see erase_rule()'s doc comment) - without it, a same-rule
    /// re-attach behind a not-yet-released tombstone would leave both the old and
    /// new claim believing they owned the one stored mapping, and whichever
    /// released last would win by accident rather than by design.
    /// `generation` defaults to 0 for callers that don't need incarnation tracking
    /// (the existing unit tests below, and any future caller with only one
    /// incarnation per rule ever) - matching add/erase generations of 0 behaves
    /// exactly as this class did before this parameter existed.
    /// @return true iff `spark_key` went from zero rules to one - the 0->1 edge
    ///         a caller turns into a single SparkEngine::arm(). Note: a redeploy
    ///         that vacated the rule's OLD key does not surface that key's ->0
    ///         edge here; the caller drives disarm off remove_rule() instead, so
    ///         the redeploy sequence is remove_rule(old) then add(new).
    bool add(std::string_view spark_key, std::string_view rule_id, std::uint64_t generation = 0);

    /// Remove `rule_id` from whatever key it is under (withdraw or the first
    /// half of a redeploy), UNCONDITIONALLY - regardless of which generation
    /// currently owns the mapping. Used only by the CONFIRMED-rule detach path
    /// (an armed rule being withdrawn), which runs as one straight-line call with
    /// no retry, so it is never exposed to the stale-release race erase_rule()
    /// guards against - deliberately NOT incarnation-aware; do not add a
    /// generation parameter here without re-auditing that assumption first.
    /// Idempotent - a no-op for an unknown rule.
    /// @return the key `rule_id` was under IFF that key now has zero rules - the
    ///         ->0 edge a caller turns into a single SparkEngine::disarm().
    ///         nullopt when the rule was unknown OR the key still has siblings.
    std::optional<std::string> remove_rule(std::string_view rule_id);

    /// remove_rule() without the returned key copy - the ONE allocation remove_rule
    /// performs - so it is genuinely noexcept: every step is a find on stored strings
    /// or an erase by iterator. For callers that only need to drop a mapping and
    /// already know (or do not need) the key: GuardianSparkRuntime's claim-index
    /// release, which runs on noexcept and destructor paths (rung 9c R5.2,
    /// adversarial re-review r3 C2/C3). Idempotent - a no-op for an unknown rule.
    ///
    /// **Incarnation-aware (rung 9c PR-5a, #4221 up-101).** Only actually erases the
    /// mapping if `generation` still matches the recorded owner (the generation
    /// passed to the `add()` call that most recently won ownership of `rule_id`).
    /// A mismatch is a SAFE NO-OP, not a failure: it means a newer incarnation
    /// already took over this rule_id (a same-rule re-attach behind this claim's
    /// own not-yet-released tombstone), and that newer incarnation's own mapping
    /// must not be touched by this older, merely-delayed release. This is the fix
    /// for the defect an earlier version of this comment overclaimed as already
    /// handled by `index_held` alone: `index_held` (GuardianSparkRuntime's own
    /// per-claim flag) only stops the SAME claim object from calling this twice: it
    /// does nothing to stop a DIFFERENT, older claim's legitimately-retried release
    /// (fail_all_claims_locked's own "the next same-key event... retries the
    /// release" case) from firing after a same-rule re-attach installed a new
    /// mapping - which, without this generation check, this call would erase.
    /// `generation` defaults to 0, matching a default-0 `add()` - a caller that
    /// never uses generations gets the old unconditional-by-rule_id behavior.
    /// @return true IFF the rule's key now has zero rules AND this call actually
    ///         performed the erase (the ->0 edge); false when the rule was unknown,
    ///         siblings remain, or `generation` did not match the current owner.
    bool erase_rule(std::string_view rule_id, std::uint64_t generation = 0) noexcept;

    /// Rules currently mapped to `spark_key`, in deterministic (sorted) order;
    /// empty for an unknown key. This is the fan-out set an event resolves to.
    [[nodiscard]] std::vector<std::string> rules_for(std::string_view spark_key) const;

    /// Number of rules sharing `spark_key` (0 for unknown) - the watcher refcount.
    [[nodiscard]] std::size_t refcount(std::string_view spark_key) const;

    /// The key `rule_id` is currently mapped to, or nullopt if unknown.
    [[nodiscard]] std::optional<std::string> key_for_rule(std::string_view rule_id) const;

    [[nodiscard]] bool empty() const noexcept { return by_rule_.empty(); }
    [[nodiscard]] std::size_t key_count() const noexcept { return by_key_.size(); }
    [[nodiscard]] std::size_t rule_count() const noexcept { return by_rule_.size(); }

private:
    // key -> set of rule_ids sharing it (sorted, deduped). A key entry never
    // lives empty: remove_rule() erases it on the ->0 edge, so key_count()
    // equals the live shared-watcher count.
    std::map<std::string, std::set<std::string>, std::less<>> by_key_;
    // rule_id -> its single current key PLUS the generation that currently owns
    // that mapping (rung 9c PR-5a, #4221 up-101). The reverse index that lets
    // remove_rule()/erase_rule() work from a rule_id alone and lets add() detect
    // a key move; the generation is what lets erase_rule() refuse a stale,
    // retried release from an incarnation that no longer owns the mapping.
    struct RuleOwner {
        std::string key;
        std::uint64_t generation{0};
    };
    std::map<std::string, RuleOwner, std::less<>> by_rule_;
};

inline bool SparkKeyRuleIndex::erase_rule(std::string_view rule_id, std::uint64_t generation) noexcept {
    // Same walk as remove_rule, minus its key copy: rit->second.key (the stored key)
    // and rit->first (the stored rule_id) drive both lookups directly, and every
    // erase is by iterator. Nothing here can allocate, so nothing here can throw.
    auto rit = by_rule_.find(rule_id);
    if (rit == by_rule_.end()) return false;
    // Incarnation check (#4221 up-101): a generation mismatch means a NEWER
    // add() already took ownership of this rule_id (a same-rule re-attach behind
    // this still-not-yet-released claim's own tombstone) - this call is a stale,
    // merely-delayed release and must be a safe no-op, never touch the newer
    // owner's mapping. Not found in by_rule_ at all (handled above) and "found
    // but owned by someone else" are both "nothing for THIS call to do."
    if (rit->second.generation != generation) return false;
    const auto kit = by_key_.find(rit->second.key);
    const bool have_node = kit != by_key_.end();
    auto sit = have_node ? kit->second.find(rit->first) : std::set<std::string>::iterator{};
    const bool have_sit = have_node && sit != kit->second.end();
    by_rule_.erase(rit); // invalidates rit; kit/sit already captured
    if (have_sit)
        kit->second.erase(sit);
    if (have_node && kit->second.empty()) {
        by_key_.erase(kit);
        return true; // ->0 edge
    }
    return false;
}

inline bool SparkKeyRuleIndex::add(std::string_view spark_key, std::string_view rule_id,
                                   std::uint64_t generation) {
    if (auto rit = by_rule_.find(rule_id); rit != by_rule_.end()) {
        if (rit->second.key == spark_key) {
            // Identical (key, rule): the fan-out/refcount state is an idempotent
            // no-op, exactly as before this parameter existed - BUT ownership
            // transfers to `generation` unconditionally (#4221 up-101). The most
            // recent add() call is always the recorded owner; this is what makes a
            // same-rule re-attach behind an older, not-yet-released claim safe -
            // the older claim's eventual erase_rule() call will see a generation
            // mismatch and correctly no-op instead of erasing this mapping.
            rit->second.generation = generation; // bool assignment on a live node: cannot throw
            return false;
        }
        // A rule already mapped to a DIFFERENT key (a spec change). This is a supported
        // move, but it is NOT strong-guarantee: remove_rule mutates before the new-key
        // allocation below, so a bad_alloc after this point leaves the rule on NEITHER
        // key. Production never hits it - attach_rule always detach_rule_locked()s first,
        // so a redeploy is remove_rule(old) then add(new) - and it also does not surface
        // the OLD key's ->0 disarm edge here (the caller drives disarm off remove_rule).
        // The strong guarantee below covers only the common not-already-mapped path.
        remove_rule(rule_id);
    }
    // Strong exception guarantee (for a rule not already mapped elsewhere): either BOTH
    // indexes gain the mapping, or a throw from any allocation leaves the index exactly
    // as on entry - no EMPTY by_key_ set (which would make a later add's set.empty()
    // mis-report the 0->1 edge and DOUBLE-ARM) and no forward/reverse desync. Every
    // rollback erase is BY ITERATOR (allocation-free, noexcept), so cleanup can never
    // itself throw and leave a forward-only mapping (Sol/Fable rung-7.7b review).
    std::string key{spark_key};
    const auto kit = by_key_.find(key);
    if (kit == by_key_.end()) {
        // New key (0->1 edge). Create the node, then populate it + the reverse index;
        // erase the whole node by iterator on any throw.
        const auto [new_kit, _] = by_key_.emplace(key, std::set<std::string>{}); // may throw: nothing else mutated
        try {
            new_kit->second.emplace(rule_id);                       // may throw
            by_rule_.emplace(std::string{rule_id},
                             RuleOwner{new_kit->first, generation}); // may throw
        } catch (...) {
            by_key_.erase(new_kit); // by-iterator: noexcept
            throw;
        }
        return true;
    }
    // Existing key: add to the live set (keep the returned iterator for an alloc-free
    // undo), then the reverse index; roll the set insert back by iterator if it throws.
    const auto [sit, inserted] = kit->second.emplace(rule_id);      // strong: set unchanged on throw
    try {
        by_rule_.emplace(std::string{rule_id}, RuleOwner{kit->first, generation}); // may throw
    } catch (...) {
        if (inserted)
            kit->second.erase(sit); // by-iterator: noexcept, no temporary string
        throw;
    }
    return false;
}

inline std::optional<std::string> SparkKeyRuleIndex::remove_rule(std::string_view rule_id) {
    auto rit = by_rule_.find(rule_id);
    if (rit == by_rule_.end()) return std::nullopt;
    // The ONLY allocation is this key copy, taken BEFORE any mutation, so a throw here
    // leaves the index untouched. Locate the inner-set node up front using the STORED
    // rule_id string (rit->first) so the find needs no temporary; then every erase is
    // by-iterator/node = noexcept. The old code erased by_rule_ first and then did
    // `set.erase(std::string{rule_id})`, whose temporary could throw and leave a
    // forward-only mapping with a leaked watcher (Sol/Fable rung-7.7b review).
    // Deliberately UNCONDITIONAL on generation - see the header doc comment.
    std::string key = rit->second.key;
    const auto kit = by_key_.find(key);
    const bool have_node = kit != by_key_.end();
    auto sit = have_node ? kit->second.find(rit->first) : std::set<std::string>::iterator{};
    const bool have_sit = have_node && sit != kit->second.end();
    by_rule_.erase(rit); // invalidates rit; key/sit already captured
    if (have_sit)
        kit->second.erase(sit);
    if (have_node && kit->second.empty()) {
        by_key_.erase(kit);
        return key; // ->0 edge: caller disarms the shared watcher
    }
    return std::nullopt; // siblings remain (or unknown key): the watcher stays armed
}

inline std::vector<std::string> SparkKeyRuleIndex::rules_for(std::string_view spark_key) const {
    std::vector<std::string> out;
    if (auto it = by_key_.find(spark_key); it != by_key_.end())
        out.assign(it->second.begin(), it->second.end());
    return out;
}

inline std::size_t SparkKeyRuleIndex::refcount(std::string_view spark_key) const {
    auto it = by_key_.find(spark_key);
    return it == by_key_.end() ? 0U : it->second.size();
}

inline std::optional<std::string> SparkKeyRuleIndex::key_for_rule(std::string_view rule_id) const {
    auto it = by_rule_.find(rule_id);
    if (it == by_rule_.end()) return std::nullopt;
    return it->second.key;
}

} // namespace yuzu::agent
