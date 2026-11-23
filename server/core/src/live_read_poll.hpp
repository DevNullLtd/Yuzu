#pragma once

/// @file live_read_poll.hpp
/// The shared poll that reads a per-device live command's output back from the response store:
/// one implementation behind `GET /api/v1/devices/{id}/live/{kind}` and the MCP tool
/// `get_device_live`, so the two surfaces answer the same rows the same way.
///
/// What this unit is NOT: it makes no permission or scope decision (no gate calls) and never
/// reads outside the fixed-plugin tier filter. The caller has already authorised, audited and
/// dispatched; this only waits for the answer.
///
/// Reads are scoped AT THE STORE SEAM: `ResponseQuery{.agent_id = ...}` pushes the target
/// agent into the SQL, with an explicit row bound, and the filter is
/// `ResponseTierFilter::for_fixed_plugin_poll` (a null plugin set refuses every row; it is never
/// an unfiltered read). The per-row `agent_id` comparison inside `reduce_rows` stays as a
/// second, defence-in-depth check.
///
/// The poll rule (`reduce_rows`):
///   - rows are ordered ascending by (timestamp, id), and every non-empty `output` is joined in
///     that order (a device that streams its answer in several rows is read whole);
///   - ANY row with status >= 2 is a failure, even when partial output is also present (a failed
///     command must not answer a false success);
///   - an `error|` prefix on the joined output is a device-reported error;
///   - a poll decides as soon as output exists and no row in it failed;
///   - a success terminal (status 1) with no output is an empty success, not a timeout;
///   - otherwise nothing is decided yet: the loop sleeps and reads again.

#include "live_outcome.hpp"
#include "response_store.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::live {

/// Device failure and device error text is cut to this many bytes before it is returned.
inline constexpr std::size_t kLiveDetailMaxBytes = 200;

/// Rows read per poll. A live command produces a handful of rows for one agent; the bound only
/// stops a misbehaving agent from making the poll read an unbounded set.
inline constexpr int kLivePollRowLimit = 64;

/// What `reduce_rows` decided from one poll's rows. `outcome` is kOk (use `output`, which may
/// be empty for a success terminal with no output), kDeviceFailed, kDeviceError, or kTimeout,
/// which here means "nothing decided yet" (no usable rows); the poll loop reads again.
struct LiveRowsVerdict {
    LiveOutcome outcome = LiveOutcome::kTimeout;
    std::string output;  ///< joined output when kOk
    std::string detail;  ///< kDeviceFailed / kDeviceError: device text, at most kLiveDetailMaxBytes
};

/// Pure reduction of one poll's rows (no store, no clock). Rows whose `agent_id` is not
/// `agent_id` are ignored. `rows` need not be sorted.
[[nodiscard]] LiveRowsVerdict reduce_rows(std::span<const StoredResponse> rows,
                                          std::string_view agent_id);

/// What to do with joined output over `max_output_bytes`.
enum class OverCapPolicy {
    kRefuse,            ///< answer kOutputTooLarge (REST)
    kTruncateAtNewline, ///< cut at the last newline inside the cap and set `truncated` (MCP)
};

struct LivePollLimits {
    int max_polls = 40;
    std::chrono::milliseconds interval{500};
    std::size_t max_output_bytes = 4u * 1024u * 1024u;
    OverCapPolicy over_cap = OverCapPolicy::kRefuse;
};

/// How a poll ended. `outcome` is one of: kOk, kDeviceFailed, kDeviceError, kOutputTooLarge,
/// kTimeout, kStoreDegraded.
struct LivePollOutcome {
    LiveOutcome outcome = LiveOutcome::kTimeout;
    std::string output;         ///< kOk: the joined device output (possibly empty)
    std::string detail;         ///< kDeviceFailed / kDeviceError: bounded device text
    bool truncated = false;     ///< kOk under kTruncateAtNewline: the output was cut
};

/// One poll's read: the rows, or `std::nullopt` when the store degraded.
using LiveRowsFn = std::function<std::optional<std::vector<StoredResponse>>()>;
/// Sleep seam; an empty function sleeps the calling thread. Tests pass a no-op.
using LiveSleepFn = std::function<void(std::chrono::milliseconds)>;

/// The poll loop over an injected read (the store overload below is the production wiring).
/// Sleeps `limits.interval` BEFORE every read but the first. When every read degraded the answer
/// is kStoreDegraded (retryable), not kTimeout; a single successful read that found nothing
/// makes it a kTimeout.
[[nodiscard]] LivePollOutcome poll_live_output(const LiveRowsFn& read_rows, std::string_view agent_id,
                                               const LivePollLimits& limits,
                                               const LiveSleepFn& sleep_fn = {});

/// Production wiring: reads `command_id`'s rows for `agent_id` from `store`, scoped in SQL, under
/// `ResponseTierFilter::for_fixed_plugin_poll(forensics_plugins)`.
[[nodiscard]] LivePollOutcome poll_live_output(const ResponseStore& store, const std::string& command_id,
                                               std::string_view agent_id,
                                               const ForensicsPluginSet* forensics_plugins,
                                               const LivePollLimits& limits,
                                               const LiveSleepFn& sleep_fn = {});

} // namespace yuzu::server::live
