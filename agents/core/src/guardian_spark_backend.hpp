#pragma once

/**
 * guardian_spark_backend.hpp - binds GuardianSparkRuntime's abstract
 * ISparkBackend to the real SparkEngine (ADR-0021 Stage 2 rung 7).
 *
 * BREAKS A CONSTRUCTION CYCLE: GuardianSparkRuntime needs an ISparkBackend at
 * construction; this adapter needs a SparkEngine::ConsumerId to forward
 * arm()/disarm() to; the ConsumerId comes from SparkEngine::register_consumer(),
 * whose handler argument is GuardianSparkRuntime::make_handler(shared_ptr<
 * GuardianSparkRuntime>) - which needs the runtime to ALREADY exist. Two-phase
 * construction breaks it: build the adapter UNBOUND, build the runtime around
 * it, register the consumer (now possible - the runtime exists), THEN
 * bind_consumer() with the real id. No caller can reach attach_rule() (and
 * therefore arm()) before the whole wiring sequence - owned by
 * GuardianEngine::wire_spark_engine() - returns, so an unbound arm() call is
 * unreachable in production; it is guarded here anyway with a typed error
 * rather than silently forwarding a sentinel ConsumerId (SparkEngine's own
 * arm() would itself reject an unregistered id with "unknown consumer id", but
 * that reads as a mystery bug rather than a caller-sequencing one).
 *
 * LIFETIME: engine_ is BORROWED, never owned. This is safe ONLY because of
 * agent.cpp's member declaration order: spark_engine_ is declared BEFORE
 * guardian_ (which owns this adapter, transitively via GuardianSparkRuntime's
 * shared_ptr<ISparkBackend>). Members destroy in REVERSE declaration order -
 * the LAST-declared member is destroyed FIRST - so guardian_ (declared later)
 * is destroyed BEFORE spark_engine_ (declared earlier): spark_engine_ always
 * outlives this adapter's lifetime. (Landed as a governance Gate 2/3 fix, this
 * PR - a first attempt at this fix got the declaration order BACKWARDS
 * [guardian_ before spark_engine_, which destroys spark_engine_ first - the
 * exact bug being fixed], caught by an independent Gate 8 re-review and
 * verified empirically with a standalone destructor-order reproducer before
 * landing this corrected version. Do not reorder agent.cpp's guardian_/
 * spark_engine_ declarations without re-verifying this invariant the same
 * way - prose review alone was not enough to catch the inversion.)
 */

#include <yuzu/agent/spark.hpp> // SparkSpec

#include "guardian_spark_runtime.hpp" // ISparkBackend
#include "spark_engine.hpp"           // SparkEngine, SparkEngine::ConsumerId

#include <cstdint>
#include <expected>
#include <string>

namespace yuzu::agent {

class GuardianSparkEngineBackend : public ISparkBackend {
public:
    explicit GuardianSparkEngineBackend(SparkEngine& engine) noexcept : engine_(&engine) {}
    GuardianSparkEngineBackend(const GuardianSparkEngineBackend&) = delete;
    GuardianSparkEngineBackend& operator=(const GuardianSparkEngineBackend&) = delete;

    /// Complete the bind, once, after SparkEngine::register_consumer() succeeds.
    /// Called exactly once by the wiring sequence in
    /// GuardianEngine::wire_spark_engine() - never re-bound (a rebind would let
    /// rules armed under the old ConsumerId silently reroute to a new one).
    void bind_consumer(SparkEngine::ConsumerId id) noexcept {
        consumer_ = id;
        bound_ = true;
    }

    std::expected<std::uint64_t, std::string> arm(const SparkSpec& spec) override {
        if (!bound_)
            return std::unexpected(
                "GuardianSparkEngineBackend: arm() called before bind_consumer() completed "
                "wiring - this is a caller-sequencing bug, not a runtime condition");
        // Deliberately NOT firewalled: a throwing SparkEngine::arm (a bad_alloc inside
        // arm_impl) must PROPAGATE so GuardianEngine::apply_rules's per-rule firewall
        // counts it and HOLDS the policy generation (transient arm failures must retry
        // via the heartbeat). Converting it to a returned error here routed the throw
        // around that firewall (reconcile treats a returned attach error as a plain
        // `return false`, which apply_rules does not count -> generation advanced ->
        // silent enforcement hole; Fable B4->B1 finding). The propagating throw is
        // terminate-safe (GuardianRollback), cannot corrupt the index (strong-guarantee
        // add), and since #2270 leaves no partial arm_impl state in the engine either.
        // Precisely: a bad_alloc can escape arm_impl only from its pre-commit/in-lock
        // phase, whose rollback restores armed_/sub_keys_ exactly, because past the
        // commit every allocating statement left is inside a catch-all. The residuals
        // are enumerated in arm_impl and deliberately not restated here. That is a
        // statement about engine state, NOT a
        // claim that the arm succeeded or that siblings are unaffected: a watch that
        // fails to arm still fails for everyone sharing the key (#2270 UP-9, pre-existing).
        // STILL OPEN (#2797): the returned-error arm of that same sentence. apply_rules
        // discards reconcile_rule_locked's bool, so the generation-hold described above
        // fires ONLY on a throw - a returned arm failure still advances the generation
        // and strands the rule. Fixing it needs a transient-vs-permanent classification,
        // which this std::string error channel cannot carry.
        return engine_->arm(consumer_, spec);
    }

    void disarm(std::uint64_t subscription) override {
        if (!bound_)
            return; // nothing was ever armed through an unbound adapter
        engine_->disarm(subscription);
    }

    SubscriptionHealth subscription_health(std::uint64_t subscription) override {
        if (!bound_)
            return SubscriptionHealth::Dead; // unbound adapter never armed anything
        return engine_->subscription_health(subscription);
    }

private:
    SparkEngine* engine_; // BORROWED - see the lifetime note above
    SparkEngine::ConsumerId consumer_{0};
    bool bound_{false};
};

} // namespace yuzu::agent
