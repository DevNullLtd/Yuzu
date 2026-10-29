#pragma once

/**
 * echo_software_core.hpp -- Pure orchestration core for the `software` source.
 *
 * The platform shell (echo_software_collector.cpp) does the registry I/O and the
 * plugin (echo_plugin.cpp do_collect_software) does the lock / source-enabled gate
 * / DB read+write. Everything in between — classifying the prior state
 * (cold-start vs corrupt vs steady) and computing the diff — is the PURE logic
 * here, so it is unit-testable off-Windows where the registry collector returns
 * empty (#1620). Machine scope only: there is no per-user assembly.
 */

#include "echo_collectors.hpp" // SoftwareInfo, SoftwareEvent, compute/assemble

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::echo {

/// Serialise an installed-software snapshot to the JSON array persisted in the
/// `software` KV state. Shared by the collector orchestration and the tests.
std::string software_state_to_json(const std::vector<SoftwareInfo>& apps);

/// Parse a `software` KV-state blob back into entries (tolerant of missing
/// fields / non-object elements). Returns empty for an empty/blank or non-array
/// blob.
std::vector<SoftwareInfo> software_state_from_json(const std::string& s);

/// Outcome of one collect_software tick's PURE logic.
struct SoftwareCollectResult {
    enum class Kind : std::uint8_t {
        kColdStartSeed, // no prior state — seed the baseline, emit NO events
        kCorruptSkip,   // prior state is not a JSON array — skip, preserve baseline
        kSteady,        // diffed against the prior baseline
    };
    Kind kind{Kind::kSteady};
    std::vector<SoftwareEvent> events; // populated for Steady only
    std::string new_state_json;        // ColdStartSeed + Steady; empty on CorruptSkip
};

/**
 * Pure core of do_collect_software (#1620).
 *
 * @param prev_json      The prior `software` KV state ("" ⇒ cold start).
 * @param enumerated     The machine-scope installed software read THIS tick
 *                       (also the full baseline on a first run). It IS the
 *                       current snapshot — machine scope has nothing to carry
 *                       forward.
 */
SoftwareCollectResult software_collect_core(const std::string& prev_json,
                                            std::vector<SoftwareInfo> enumerated,
                                            int64_t timestamp, int64_t snapshot_id);

} // namespace yuzu::echo
