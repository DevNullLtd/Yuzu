// test_spark_key_rule_index.cpp - SparkKeyRuleIndex (ADR-0021 rung 2 slice 2a).
//
// The index is the consumer-side register-of-record that (1) resolves a shared
// watcher's event back to every rule that fans out from it and (2) reports the
// 0->1 / ->0 refcount edges a caller turns into a single arm()/disarm(). These
// tests pin both roles plus the redeploy (key-move) path, without arming
// anything - the index is pure state.

#include "spark_key_rule_index.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <vector>

using yuzu::agent::SparkKeyRuleIndex;

TEST_CASE("SparkKeyRuleIndex: add reports the 0->1 edge exactly once per key", "[spark][index]") {
    SparkKeyRuleIndex idx;
    REQUIRE(idx.empty());

    // First rule for a key is the arm edge.
    REQUIRE(idx.add("service|5:sshd", "rule-a") == true);
    // A second rule sharing the SAME key is NOT an arm edge (the watcher exists).
    REQUIRE(idx.add("service|5:sshd", "rule-b") == false);
    // Re-adding an identical (key, rule) pair is an idempotent no-op.
    REQUIRE(idx.add("service|5:sshd", "rule-a") == false);

    REQUIRE(idx.refcount("service|5:sshd") == 2);
    REQUIRE(idx.key_count() == 1);
    REQUIRE(idx.rule_count() == 2);
    REQUIRE_FALSE(idx.empty());
}

TEST_CASE("SparkKeyRuleIndex: rules_for is the sorted fan-out set", "[spark][index]") {
    SparkKeyRuleIndex idx;
    idx.add("file|4:/etc", "rule-z");
    idx.add("file|4:/etc", "rule-a");
    idx.add("file|4:/etc", "rule-m");

    // One shared watcher -> three rules, deterministic (sorted) order.
    REQUIRE(idx.rules_for("file|4:/etc") == std::vector<std::string>{"rule-a", "rule-m", "rule-z"});
    // An unmapped key resolves to nothing.
    REQUIRE(idx.rules_for("file|9:/nowhere").empty());
    REQUIRE(idx.refcount("file|9:/nowhere") == 0);
}

TEST_CASE("SparkKeyRuleIndex: remove_rule reports ->0 only on the last sibling", "[spark][index]") {
    SparkKeyRuleIndex idx;
    idx.add("registry|4:HKLM", "rule-a");
    idx.add("registry|4:HKLM", "rule-b");

    // Removing a rule that still has a sibling is NOT a disarm edge.
    REQUIRE(idx.remove_rule("rule-a") == std::nullopt);
    REQUIRE(idx.refcount("registry|4:HKLM") == 1);
    REQUIRE(idx.rules_for("registry|4:HKLM") == std::vector<std::string>{"rule-b"});

    // Removing the LAST rule surfaces the key so the caller disarms it.
    REQUIRE(idx.remove_rule("rule-b") == std::optional<std::string>{"registry|4:HKLM"});
    REQUIRE(idx.refcount("registry|4:HKLM") == 0);
    REQUIRE(idx.key_count() == 0);
    REQUIRE(idx.empty());
}

TEST_CASE("SparkKeyRuleIndex: remove_rule is idempotent for an unknown rule", "[spark][index]") {
    SparkKeyRuleIndex idx;
    REQUIRE(idx.remove_rule("never-added") == std::nullopt);
    idx.add("service|5:nginx", "rule-a");
    REQUIRE(idx.remove_rule("some-other-rule") == std::nullopt);
    REQUIRE(idx.refcount("service|5:nginx") == 1);
}

TEST_CASE("SparkKeyRuleIndex: a redeploy that moves a rule to a new key", "[spark][index]") {
    SparkKeyRuleIndex idx;
    REQUIRE(idx.add("service|5:sshd", "rule-a") == true);
    REQUIRE(idx.key_for_rule("rule-a") == std::optional<std::string>{"service|5:sshd"});

    // Re-add the SAME rule under a different key (its spec changed). add() drops
    // the stale association and reports the new key's 0->1 edge; the old key is
    // vacated (refcount 0) so it no longer resolves or holds the rule.
    REQUIRE(idx.add("service|5:nginx", "rule-a") == true);
    REQUIRE(idx.key_for_rule("rule-a") == std::optional<std::string>{"service|5:nginx"});
    REQUIRE(idx.refcount("service|5:sshd") == 0);
    REQUIRE(idx.refcount("service|5:nginx") == 1);
    REQUIRE(idx.rules_for("service|5:sshd").empty());
    // Exactly one rule, one key: no orphaned empty key entry left behind.
    REQUIRE(idx.rule_count() == 1);
    REQUIRE(idx.key_count() == 1);
}

TEST_CASE("SparkKeyRuleIndex: key_for_rule tracks the current mapping", "[spark][index]") {
    SparkKeyRuleIndex idx;
    REQUIRE(idx.key_for_rule("rule-a") == std::nullopt);
    idx.add("disk|1:/", "rule-a");
    REQUIRE(idx.key_for_rule("rule-a") == std::optional<std::string>{"disk|1:/"});
    idx.remove_rule("rule-a");
    REQUIRE(idx.key_for_rule("rule-a") == std::nullopt);
}

// rung 9c PR-5a (#4221 up-101): a stale, retried erase_rule() from a superseded
// incarnation must never clobber a newer incarnation's mapping for the same rule_id.
// Mutation-verify: drop the `if (rit->second.generation != generation) return false;`
// guard in erase_rule() (or pass generation 0 unconditionally from callers) and this
// test goes RED - the old generation's erase would wrongly succeed, and the newer
// claim's mapping (and its key's refcount) would be destroyed out from under it.
TEST_CASE("SparkKeyRuleIndex: a stale generation's erase_rule is a safe no-op once a "
          "newer generation owns the same rule_id (#4221 up-101)",
          "[spark][index]") {
    SparkKeyRuleIndex idx;

    // Generation 1 claims "rule-a" on key K.
    REQUIRE(idx.add("service|5:sshd", "rule-a", /*generation=*/1) == true);
    REQUIRE(idx.key_for_rule("rule-a") == std::optional<std::string>{"service|5:sshd"});

    // Generation 2 re-attaches the SAME rule_id on the SAME key before generation 1's
    // own release has run - exactly the same-rule-behind-a-not-yet-released-tombstone
    // shape #4221 up-101 describes. Ownership transfers to generation 2; the fan-out
    // state itself (one rule, one key) is unaffected - an idempotent no-op from
    // refcount()/rules_for()'s point of view, matching add()'s pre-existing contract
    // for an identical (key, rule) pair.
    REQUIRE(idx.add("service|5:sshd", "rule-a", /*generation=*/2) == false);
    REQUIRE(idx.refcount("service|5:sshd") == 1);
    REQUIRE(idx.key_for_rule("rule-a") == std::optional<std::string>{"service|5:sshd"});

    // Generation 1's release finally runs (its own first attempt failed and this is the
    // retry `fail_all_claims_locked`'s comment describes) - STALE now. Must be a
    // complete no-op: the mapping generation 2 owns survives untouched.
    REQUIRE(idx.erase_rule("rule-a", /*generation=*/1) == false);
    REQUIRE(idx.key_for_rule("rule-a") == std::optional<std::string>{"service|5:sshd"});
    REQUIRE(idx.refcount("service|5:sshd") == 1);
    REQUIRE_FALSE(idx.empty());

    // Generation 2's OWN eventual release is the real one: it matches the recorded
    // owner, so the erase actually happens and the key's refcount reaches zero (the
    // ->0 edge the caller turns into a real disarm).
    REQUIRE(idx.erase_rule("rule-a", /*generation=*/2) == true);
    REQUIRE(idx.key_for_rule("rule-a") == std::nullopt);
    REQUIRE(idx.refcount("service|5:sshd") == 0);
    REQUIRE(idx.empty());
}

TEST_CASE("SparkKeyRuleIndex: erase_rule for an unknown rule_id is a no-op regardless of "
          "generation",
          "[spark][index]") {
    SparkKeyRuleIndex idx;
    REQUIRE(idx.erase_rule("never-added", 0) == false);
    REQUIRE(idx.erase_rule("never-added", 42) == false);
}

// remove_rule() (the CONFIRMED-rule detach path) is deliberately NOT incarnation-aware
// - it removes whatever is currently mapped regardless of any generation, matching its
// pre-#4221 behavior exactly (see its header doc comment for why: no retry path
// exposes it to the same stale-release race erase_rule() guards against).
TEST_CASE("SparkKeyRuleIndex: remove_rule stays unconditional on generation", "[spark][index]") {
    SparkKeyRuleIndex idx;
    idx.add("registry|4:HKLM", "rule-a", /*generation=*/7);
    REQUIRE(idx.remove_rule("rule-a") == std::optional<std::string>{"registry|4:HKLM"});
    REQUIRE(idx.key_for_rule("rule-a") == std::nullopt);
}
