#pragma once

/// @file guardian_unsupported_heartbeat.hpp
/// Writer side of the per-type mech_unsupported_total fleet gauge (F7, #2298 rung 2 /
/// design doc §Platform-rejection, §Fleet metrics). Wire key is
/// yuzu.spark_<mechanism>_unsupported - a sibling of spark_heartbeat.hpp's existing
/// yuzu.spark_<mechanism>_<metric> family, even though this count comes from
/// GuardianEngine::unsupported_counts_by_type(), not SparkEngine: the design doc
/// places it in the same yuzu_fleet_spark_* Prometheus family. Mirrors
/// server/core/src/spark_fleet_tags.hpp's spark_type_metric_tag() composition
/// byte-for-byte; kept in sync by a writer/reader pin test (agent code cannot include
/// that server-side header).
///
/// CURRENT GAUGE, not a cumulative counter (despite the "_total" name inherited from
/// the design doc) - GuardianEngine::unsupported_counts_by_type() aggregates a live
/// map fresh on every call, so it can legally decrease. The server must gauge.set()
/// this value directly, never delta-accumulate it.
///
/// SPARSE: a mechanism with 0 currently-unsupported rules omits its tag. Note for
/// tests: this function APPENDS into the supplied map, it does not clear stale keys -
/// simulating a 2 -> 1 -> 0 sequence needs a FRESH map per call (production always
/// constructs a fresh heartbeat tag map per cycle; the same map reused across calls
/// would keep a key this function never re-wrote).
///
/// `TagMap` is any map with a string `operator[]` - the protobuf status_tags map in
/// production, std::map in tests.

#include <cstdint>
#include <map>
#include <string>

#include <yuzu/agent/spark.hpp> // SparkType, spark_type_token

namespace yuzu::agent {

template <typename TagMap>
void emit_guardian_unsupported_heartbeat_tags(TagMap& tags,
                                              const std::map<SparkType, std::uint64_t>& counts) {
    for (const auto& [type, n] : counts) {
        if (n == 0)
            continue;
        tags[std::string("yuzu.spark_") + spark_type_token(type) + "_unsupported"] =
            std::to_string(n);
    }
}

} // namespace yuzu::agent
