#pragma once

/// @file guardian_backend.hpp
/// Which detection backend a Guardian rule is actually enforced by, given the
/// agent's constructor-time spark preference and its runtime spark availability
/// (F7, #2298 rung 2). NOT named `*_heartbeat.hpp`: this is used for boot-log
/// correctness too (agent.cpp, guardian_engine.cpp's wire_spark_engine()), not
/// only heartbeat tag emission - a single derivation shared by every site keeps
/// them from drifting apart again the way the pre-F7 boot log did (it hardcoded
/// "prefer_spark=false; detection backend = legacy IGuard" regardless of the
/// actual prefer_spark_ value, because no accessor existed to query it).

#include <utility> // std::unreachable (C++23; precedented in this codebase, mcp_server.cpp)

#include <yuzu/agent/guardian_engine.hpp> // GuardianEngine::SparkAvailability

namespace yuzu::agent {

enum class GuardianBackend { Legacy, Spark, Unwired, SparkFailed };

/// prefer_spark_ == false makes try_spark false unconditionally in
/// reconcile_rule_locked regardless of spark_availability_'s value - every rule
/// reaches legacy. So Legacy is returned whenever !prefer_spark, before
/// availability is even consulted. Mechanically exhaustive: no default/fallback
/// branch, so a future SparkAvailability enumerator not handled here is a
/// compile-time -Wswitch warning rather than a silently-wrong runtime value -
/// returning Legacy for an unhandled case would be a reassuring lie about
/// enforcement state.
[[nodiscard]] inline GuardianBackend guardian_backend_from_state(
    bool prefer_spark, GuardianEngine::SparkAvailability availability) noexcept {
    if (!prefer_spark)
        return GuardianBackend::Legacy;
    switch (availability) {
    case GuardianEngine::SparkAvailability::Available:
        return GuardianBackend::Spark;
    case GuardianEngine::SparkAvailability::SparkDisabled:
        return GuardianBackend::Legacy;
    case GuardianEngine::SparkAvailability::SparkFailed:
        return GuardianBackend::SparkFailed;
    case GuardianEngine::SparkAvailability::Unwired:
        return GuardianBackend::Unwired;
    }
    std::unreachable();
}

[[nodiscard]] inline const char* guardian_backend_label(GuardianBackend backend) noexcept {
    switch (backend) {
    case GuardianBackend::Legacy:
        return "legacy";
    case GuardianBackend::Spark:
        return "spark";
    case GuardianBackend::Unwired:
        return "unwired";
    case GuardianBackend::SparkFailed:
        return "spark_failed";
    }
    std::unreachable();
}

inline constexpr char kGuardianBackendTag[] = "yuzu.guardian_backend";

/// Always emitted (not sparse) - a categorical value with no "zero" state, unlike
/// the sparse counter families elsewhere in this file group. `TagMap` is any map
/// with a string `operator[]` - the protobuf status_tags map in production,
/// std::map in tests.
template <typename TagMap>
void emit_guardian_backend_heartbeat_tag(TagMap& tags, bool prefer_spark,
                                         GuardianEngine::SparkAvailability availability) {
    tags[kGuardianBackendTag] =
        guardian_backend_label(guardian_backend_from_state(prefer_spark, availability));
}

} // namespace yuzu::agent
