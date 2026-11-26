#pragma once

/**
 * win_vss_snapshots.hpp -- bounded enumeration of the Windows Volume Shadow Copy snapshots.
 *
 * WHY THIS LIVES IN AGENT-CORE
 * ----------------------------
 * The VSS requester calls are synchronous cross-process COM with no deadline. Bounding the wait
 * needs a detached worker, whose code must not live in a plugin the agent can unload (see
 * bounded_single_flight.hpp). Plugins call the exported functions only.
 *
 * One read is in flight process-wide. A second caller waits for a healthy read inside its own
 * deadline; after a deadline hit, callers are answered Abandoned until the blocked worker returns.
 * Every other field of the result is meaningful only when status == Completed.
 */

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <yuzu/agent/bounded_status.hpp>
#include <yuzu/plugin.h> // YUZU_EXPORT

namespace yuzu::agent::win {

/// One shadow copy. Text is UTF-8.
struct VssSnapshot {
    std::string snapshot_id;     ///< braced GUID text; "-" when it could not be formatted
    std::string original_volume; ///< volume GUID path; empty when VSS gave none
    std::string device_object;   ///< shadow-copy device path; "-" when VSS gave none
};

/// The step of the walk that failed.
enum class VssStep { none, com_init, create, initialize, query, next };

struct VssSnapshotsRead {
    BoundedStatus status = BoundedStatus::Rejected;
    bool api_available = true; ///< false: no VSS in this build (not Windows, or no vsbackup.h)
    VssStep failed_step = VssStep::none;
    std::int32_t hr = 0;             ///< HRESULT of the failed step; 0 for com_init
    bool context_narrowed = false;   ///< SetContext(VSS_CTX_ALL) failed; default context only
    bool skipped_wrong_type = false; ///< the provider returned a non-snapshot object
    bool truncated = false;          ///< the walk stopped at kMaxVssSnapshots turns
    std::vector<VssSnapshot> snapshots; ///< what was read, also when a later step failed
};

inline constexpr std::chrono::milliseconds kVssDeadline{15000};
inline constexpr std::size_t kMaxVssSnapshots = 1024;

/// Every shadow copy on the machine, in ONE bounded call. Non-Windows builds answer Completed
/// with api_available = false. Out-of-line (agent-core only).
YUZU_EXPORT VssSnapshotsRead read_vss_snapshots(std::chrono::milliseconds deadline);

/// Test seam: same driver and process-wide slot, injected reader. The reader must own everything
/// it touches. No default arguments (see keychain_read.hpp).
YUZU_EXPORT VssSnapshotsRead read_vss_snapshots_for_test(
    std::chrono::milliseconds deadline, const std::function<VssSnapshotsRead()>& reader);

} // namespace yuzu::agent::win
