#pragma once

/// @file guardian_backend_fleet_tags.hpp
/// Reader side of the agent's `yuzu.guardian_backend` heartbeat tag (#2240): which detection
/// backend the agent reports its Guardian enforcing with (`legacy`, `spark`, `spark_failed`,
/// `unwired`). The writer is agents/core/src/guardian_backend.hpp
/// (`emit_guardian_backend_heartbeat_tag`, called from agent.cpp's per-beat Guardian tag group).
/// AgentHealthStore::recompute_metrics consumes this header for the `yuzu_fleet_guardian_backend`
/// gauge, and the AgentHealthStore device accessors consume it for the per-device
/// `guardian_backend` field, so the two surfaces share ONE table and ONE parse.
///
/// The key and the four labels are duplicated here rather than `#include`d from the agent ON
/// PURPOSE - the same rationale as guardian_health_fleet_tags.hpp: server production code
/// including an agent private header would add an upward server -> agent dependency edge the
/// build graph does not have and must not gain (tests/meson.build, server test include-path
/// comment). tests/unit/server/test_guardian_backend_fleet_tags.cpp binds the sides: it drives
/// the agent's REAL emitter over every backend and asserts the key and the label set equal this
/// table, so a rename on either side without the other is a red test, not a silently-dead gauge.
///
/// SHAPE: a categorical PARTITION COUNT. Each recognised agent lands in exactly one
/// `{os,backend}` series per sweep (the tag has no "zero" state, unlike the sparse counter
/// families), so the series sum to `yuzu_fleet_guardian_backend_reporting`. Series are cleared
/// and rebuilt every sweep and are ABSENT when no agent is in them, never pre-seeded at 0. The
/// two unlabelled meta gauges are published every sweep including 0.
///
/// A MISSING tag means NotReported, never `legacy`: an agent older than the tag, an agent with
/// no Guardian, an agent whose Guardian tag group faulted this beat (the emit is the LAST call
/// in that group's try, so a fault skips it), and an agent that is stopping all read the same.
/// An EMPTY value is also NotReported (skipped, not counted as rejected). A NON-EMPTY value
/// outside the closed table is REJECTED: it contributes to no bucket, is counted once in
/// `yuzu_fleet_guardian_backend_tag_rejected`, and is never read as `legacy` or `spark_failed`
/// (a forged value must not move a published number, and a newer agent's future token is
/// rejected on purpose until the server learns it).
///
/// CLOCK: the tag rides every beat today (agent.cpp, per-beat Guardian tag group), so `last_seen`
/// and kAgentHealthStaleness are the right clock (owner Ruling 26, 2026-11-06: the status-beat
/// split, H4a / ADR-0073, lands after the Spark flip and this reader stays pre-freeze). When a
/// status-beat split lands, this family and the device accessors must move to the status-beat
/// timestamp together, or both flap at the status cadence. AgentHealthStore::upsert also REPLACES
/// status_tags on every beat, so a beat that omits this tag erases it: that replace-semantics must
/// change in the same slice, or the field reads null (and the gauge drops the agent) on every
/// lean beat even with the clock moved.
///
/// POPULATION AND SCOPE: the agents with a heartbeat in the last kAgentHealthStaleness; the
/// health store is per core replica, so each replica exports only the agents attached to it.
///
/// TWIN: the per-device twin is the `guardian_backend` field on `GET /api/v1/devices[/{id}]`,
/// `list_agents` and `get_agent_details`, fed by AgentHealthStore::guardian_backend_for /
/// guardian_backend_of from this same table and parse. (This replaces the ADR-1005 class
/// exception the sibling fleet-tag headers carry: this family HAS a REST/MCP twin.)
///
/// HELP text is 7-bit ASCII (scripts/ci/check-metrics-help-ascii.sh, help_tables).

#include <cassert>
#include <cstddef>
#include <iterator> // std::size
#include <optional>
#include <string_view>

namespace yuzu::server::detail {

/// The heartbeat status tag the agent writes. Duplicated from the agent header on purpose
/// (see the file comment); pinned by test_guardian_backend_fleet_tags.cpp.
inline constexpr const char* kGuardianBackendTag = "yuzu.guardian_backend";

/// The closed token table. Order is the index space of every accumulator and bucket array.
/// Case-sensitive exact match; the label value and the device field string are always one of
/// these constants, never the raw agent-supplied bytes.
inline constexpr const char* kGuardianBackendTokens[] = {"legacy", "spark", "spark_failed",
                                                         "unwired"};
inline constexpr std::size_t kNGuardianBackendTokens = std::size(kGuardianBackendTokens);

/// Named indices so a reordered table is a compile error, not a silently swapped bucket.
inline constexpr std::size_t kGuardianBackendIdxLegacy = 0;
inline constexpr std::size_t kGuardianBackendIdxSpark = 1;
inline constexpr std::size_t kGuardianBackendIdxSparkFailed = 2;
inline constexpr std::size_t kGuardianBackendIdxUnwired = 3;
static_assert(std::string_view{kGuardianBackendTokens[kGuardianBackendIdxLegacy]} == "legacy");
static_assert(std::string_view{kGuardianBackendTokens[kGuardianBackendIdxSpark]} == "spark");
static_assert(std::string_view{kGuardianBackendTokens[kGuardianBackendIdxSparkFailed]} ==
              "spark_failed");
static_assert(std::string_view{kGuardianBackendTokens[kGuardianBackendIdxUnwired]} == "unwired");
static_assert(kNGuardianBackendTokens == 4,
              "a 5th backend token needs a named index above, an HELP update, the OpenAPI "
              "DevicesListRow enum, the list_agents / get_agent_details output-schema enums "
              "(mcp_server.cpp) and the pin test matrix");

/// Longest accepted value. Any longer value is rejected after one size compare, so a forged
/// multi-megabyte tag costs O(1), never a scan.
inline constexpr std::size_t kMaxGuardianBackendTokenBytes = 12;
namespace guardian_backend_detail {
constexpr bool all_tokens_fit() noexcept {
    for (const char* t : kGuardianBackendTokens)
        if (std::string_view{t}.size() > kMaxGuardianBackendTokenBytes)
            return false;
    return true;
}
} // namespace guardian_backend_detail
static_assert(guardian_backend_detail::all_tokens_fit(),
              "kMaxGuardianBackendTokenBytes is shorter than a table token");

/// Metric names. The gauge name and HELP are constants (not literals at each site) so
/// describe(), the clear and the publisher cannot drift (the dedup_fleet_tags.hpp rule).
inline constexpr const char* kGuardianBackendGauge = "yuzu_fleet_guardian_backend";
inline constexpr const char* kGuardianBackendLabelOs = "os";
inline constexpr const char* kGuardianBackendLabelBackend = "backend";
inline constexpr const char* kGuardianBackendReportingGauge =
    "yuzu_fleet_guardian_backend_reporting";
inline constexpr const char* kGuardianBackendTagRejectedGauge =
    "yuzu_fleet_guardian_backend_tag_rejected";

inline constexpr const char* kGuardianBackendHelp =
    "Agents by Guardian detection backend and OS, from the yuzu.guardian_backend heartbeat tag. "
    "backend is one of legacy, spark, spark_failed, unwired. Each recognised agent is in exactly "
    "one series per sweep (a partition count: the series sum to "
    "yuzu_fleet_guardian_backend_reporting). Series nobody is in are ABSENT, never 0, and an "
    "agent with no tag, an empty tag or a rejected value is in NO series (a missing tag is never "
    "read as legacy; see the _reporting and _tag_rejected gauges). READ legacy CAREFULLY: it is "
    "every reporting agent until prefer_spark is enabled, and afterwards it also covers "
    "--spark-disable (yuzu_fleet_spark_disabled{os} tells the two apart). The backend value "
    "spark_failed is what an agent with prefer_spark on and a failed SparkEngine boot reports; "
    "it is NOT yuzu_fleet_spark_failed{os}, which counts spark_running=0 without spark_disabled "
    "and can fire before the flip. The os label is the agent's self-reported yuzu.os, "
    "allowlisted to windows, linux, darwin, other or unknown. Population: agents with a heartbeat "
    "in the last 90 seconds, per core replica, so an agent that has just disconnected is counted "
    "until it ages out. "
    "The per-device reading is the guardian_backend field on GET /api/v1/devices and the "
    "list_agents and get_agent_details MCP tools, null when this gauge would not count the "
    "agent; the field covers only connected devices and is read live, so it can differ from this "
    "gauge for up to about 105 seconds after a disconnect (90 second window plus one 15 second "
    "sweep)";

inline constexpr const char* kGuardianBackendReportingHelp =
    "Agents whose latest heartbeat carried a valid yuzu.guardian_backend tag this sweep - the "
    "coverage denominator for yuzu_fleet_guardian_backend, which sums to it. Published every "
    "sweep INCLUDING 0. Compare it with yuzu_fleet_agents_by_os: the gap is agents that are "
    "older than the tag, have no Guardian, faulted the Guardian heartbeat tag group this beat, "
    "or sent an empty or rejected value";

inline constexpr const char* kGuardianBackendTagRejectedHelp =
    "yuzu.guardian_backend tags PRESENT and non-empty on a heartbeat this sweep but rejected by "
    "the closed-set parse (not exactly legacy, spark, spark_failed or unwired; case-sensitive; "
    "over 12 bytes). An EMPTY value is skipped before the parse and is NOT counted here. "
    "Published every sweep INCLUDING 0. A rejected value lands in no yuzu_fleet_guardian_backend "
    "series and reads null on the device field, so this gauge is the only fleet signal for it. "
    "> 0 means a forged or malformed tag, or a newer agent shipping a backend this server does "
    "not know yet (a rolling upgrade): investigate the agent, or upgrade the server";

/// Closed-set, case-sensitive parse of an agent-supplied value into a table index.
///
/// Caller semantics (both the gauge publisher and the device accessors follow them):
///   - EMPTY view            -> nullopt, but NotReported: skip it, do NOT count it as rejected
///                              (an absent key and a present-empty value both read as an empty
///                              view through AgentHealthStore's get_view).
///   - non-empty, nullopt    -> REJECTED: count it in the tag_rejected gauge, contribute to no
///                              bucket, never substitute `legacy` or any other token.
///   - Some(i)               -> the label value and the device field are
///                              kGuardianBackendTokens[i], never the raw view.
/// The empty check is the caller's, so a rejected count cannot absorb an absent tag.
[[nodiscard]] inline std::optional<std::size_t>
parse_guardian_backend_token(std::string_view s) noexcept {
    if (s.empty() || s.size() > kMaxGuardianBackendTokenBytes)
        return std::nullopt;
    for (std::size_t i = 0; i < kNGuardianBackendTokens; ++i)
        if (s == std::string_view{kGuardianBackendTokens[i]})
            return i;
    return std::nullopt;
}

/// The one conversion from a parsed index to a string: a view into the constexpr table above
/// (static storage), safe to hold after the health store's mutex is released. `i` must be a
/// value parse_guardian_backend_token returned.
[[nodiscard]] inline std::string_view guardian_backend_token_view(std::size_t i) noexcept {
    assert(i < kNGuardianBackendTokens && "index must come from parse_guardian_backend_token");
    return std::string_view{kGuardianBackendTokens[i]};
}

} // namespace yuzu::server::detail
