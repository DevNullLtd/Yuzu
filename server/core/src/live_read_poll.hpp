#pragma once

/// @file live_read_poll.hpp
/// The shared poll that reads a per-device live command's output back from the response store:
/// one implementation behind `POST /api/v1/dex/devices/{id}/live` and the MCP tool
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
/// second, defence-in-depth check. The read is `ResponseStore::query_bounded`, which also bounds
/// the bytes a single read materialises (the byte cap is `max_output_bytes`).
///
/// The poll rule (`reduce_rows`):
///   - this agent's rows are ordered ascending by row id alone. The id is a Postgres identity
///     column assigned at insert, so it follows ingest order; the row `timestamp` is epoch
///     SECONDS stamped from the server wall clock, so it ties for chunks that land in the same
///     second and goes backwards when the clock is stepped, and is never used to order;
///   - every non-empty `output` is joined in that order, with a single '\n' between two chunks
///     when the text so far does not already end in one (a plugin writes whole lines, and the
///     agent flushes a long answer as several frames, so a chunk boundary is a line boundary);
///   - ANY row with status >= 2 is a failure, even when partial output is also present (a failed
///     command must not answer a false success). The production read supplies decision facts
///     computed over all stored rows before the row limit and the byte cut, so a failing row that
///     later chunks pushed out of the bounded read still answers the failure;
///   - an answer is decided ONLY once a terminal row exists, meaning ANY stored row with
///     status >= 1. Output that has arrived without a terminal row is a partial answer and is
///     NOT decided: the loop reads again. Two ingest shapes both end in a terminal row: the
///     direct Subscribe path inserts a separate (possibly empty) terminal row, and the
///     gateway/proxy path updates the existing RUNNING rows in place when the terminal frame
///     carries no output, so the stored rows then show status 1 with no extra row;
///   - once a terminal row exists, an `error|` prefix on the joined output is a device-reported
///     error, and a terminal row with no output at all is an empty success;
///   - otherwise nothing is decided yet.
///
/// How a poll ends without an answer: nothing at all by the deadline is `timeout`; output but no
/// terminal row by the deadline is `incomplete` (the partial output is discarded, never returned);
/// every read degraded is `store_degraded`; the stop predicate firing is `shutting_down`.
///
/// A device `error|` answer is recognised from the first non-empty chunk: when the bounded read
/// left the oldest rows out, from the head chunk the facts carry, not from the first survivor.
///
/// Known limit (response-store ingest, not this unit): if the server fails to store one MIDDLE
/// chunk of a multi-chunk answer, the remaining rows still look complete here, so the answer can
/// be returned with a hole in it. The poll cannot see a dropped frame.

#include "live_outcome.hpp"
#include "mcp_retry.hpp" // kLiveReadIncompleteRetryMs, pinned to LivePollLimits::deadline below
#include "response_store.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server::live {

/// Device failure and device error text is cut to this many bytes (at a UTF-8 boundary) before
/// it is returned.
inline constexpr std::size_t kLiveDetailMaxBytes = 200;

/// The detail text that goes with the `incomplete` outcome.
inline constexpr std::string_view kLiveIncompleteDetail = "the device began to answer but did not finish";

/// Rows read per poll. A live command produces a handful of rows for one agent; the bound only
/// stops a misbehaving agent from making the poll read an unbounded set.
inline constexpr int kLivePollRowLimit = 64;

// The store cuts the decision-fact texts to `kBoundedFactsTextChars` characters, at least one byte
// each, so the cut text always holds the `error|` prefix plus every byte of the detail we return.
static_assert(static_cast<std::size_t>(kBoundedFactsTextChars) >= kLiveDetailMaxBytes + 6,
              "the fact text must hold the error| prefix and the whole returned detail");

/// What `reduce_rows` decided from one poll's rows. `outcome` is kOk (use `output`, which may
/// be empty for a success terminal with no output), kDeviceFailed, kDeviceError, or kTimeout,
/// which here means "nothing decided yet"; the poll loop reads again.
struct LiveRowsVerdict {
    LiveOutcome outcome = LiveOutcome::kTimeout;
    /// kOk: the joined output. Undecided with `partial`: the joined output so far (so the loop can
    /// stop early over the byte cap); the loop never returns it.
    std::string output;
    std::string detail;  ///< kDeviceFailed / kDeviceError: device text, at most kLiveDetailMaxBytes
    /// Undecided because output has arrived but no terminal row has: a partial answer.
    bool partial = false;
};

/// Pure reduction of one poll's rows (no store, no clock). Rows whose `agent_id` is not
/// `agent_id` are ignored. `rows` need not be sorted.
///
/// `facts`, when the store supplied them, are decision facts over EVERY permitted row of the
/// command, not only the rows in `rows` (which the row limit and the byte cut may have thinned):
///   - a failure anywhere (`any_failed`) is a failure, and its text is `failed_detail`, the newest
///     failing row's, so a failing row the cut dropped still answers;
///   - a terminal row anywhere (`any_terminal`) is a terminal row;
///   - when `rows_cut` (the store left the OLDEST rows out), the `error|` test reads the true head
///     chunk (`head_output`) instead of the first chunk that survived the cut.
/// With no facts (`nullptr`) the reduction is over `rows` alone, as before.
[[nodiscard]] LiveRowsVerdict reduce_rows(std::span<const StoredResponse> rows,
                                          std::string_view agent_id,
                                          const BoundedFacts* facts = nullptr, bool rows_cut = false);

/// What to do with joined output over `max_output_bytes`.
enum class OverCapPolicy {
    kRefuse,            ///< answer kOutputTooLarge (REST)
    kTruncateAtNewline, ///< cut at the last newline inside the cap and set `truncated` (MCP)
};

struct LivePollLimits {
    int max_polls = 40;
    std::chrono::milliseconds interval{500};
    /// Wall-clock budget for the whole poll, measured on a steady clock and checked every
    /// iteration (the first read always happens). It covers slow store reads, which the
    /// iteration count alone does not: the poll never holds its worker past this deadline plus
    /// one interval and one read.
    std::chrono::milliseconds deadline{25000};
    std::size_t max_output_bytes = 4u * 1024u * 1024u;
    OverCapPolicy over_cap = OverCapPolicy::kRefuse;
};

// The quick-kind `incomplete` retry hint is the poll's own wall deadline (see mcp_retry.hpp): a
// caller told to retry sooner could land inside a first run that is still hashing. `processes` has
// its own, longer price (`live_read_incomplete_retry_ms`).
static_assert(std::chrono::milliseconds{yuzu::server::mcp::kLiveReadIncompleteRetryMs} ==
                  LivePollLimits{}.deadline,
              "the incomplete retry hint must equal the poll's wall deadline");

/// How a poll ended. `outcome` is one of: kOk, kDeviceFailed, kDeviceError, kOutputTooLarge,
/// kTimeout, kIncomplete, kStoreDegraded, kShuttingDown.
struct LivePollOutcome {
    LiveOutcome outcome = LiveOutcome::kTimeout;
    std::string output;         ///< kOk: the joined device output (possibly empty)
    std::string detail;         ///< kDeviceFailed / kDeviceError: bounded device text; kIncomplete: kLiveIncompleteDetail
    bool truncated = false;     ///< kOk under kTruncateAtNewline: the output was cut or incomplete
};

/// One poll's read: this agent's rows, plus whether the store left rows out (the row limit or the
/// byte cap was hit). The rows it left out are the OLDEST, so the head of the answer is missing:
/// the poll treats that as over the byte cap.
struct LiveRowsRead {
    std::vector<StoredResponse> rows;
    bool capped = false;
    /// Decision facts over all permitted rows (see `reduce_rows`); empty when the read has none.
    std::optional<BoundedFacts> facts;

    LiveRowsRead() = default;
    // Implicit on purpose: a read that has no cap to report returns its rows directly.
    LiveRowsRead(std::vector<StoredResponse> r, bool was_capped = false)
        : rows(std::move(r)), capped(was_capped) {}
};

/// One poll's read: the rows, or `std::nullopt` when the store degraded.
using LiveRowsFn = std::function<std::optional<LiveRowsRead>()>;
/// Sleep seam; an empty function sleeps the calling thread. Tests pass a no-op.
using LiveSleepFn = std::function<void(std::chrono::milliseconds)>;
/// Stop predicate: true when the poll must abandon the read (server shutdown). Checked at the top
/// of each iteration and after each sleep. An empty function never stops.
using LiveStopFn = std::function<bool()>;
/// Steady-clock seam for the deadline; an empty function reads `std::chrono::steady_clock`.
using LiveClockFn = std::function<std::chrono::steady_clock::time_point()>;

/// The poll loop over an injected read (the store overload below is the production wiring).
/// Sleeps `limits.interval` BEFORE every read but the first. Ends with the first of: a decided
/// answer; `should_stop` (kShuttingDown); the iteration count or `limits.deadline`, when the
/// answer is kStoreDegraded (every read degraded, retryable), kIncomplete (some read saw output
/// but no terminal row) or kTimeout (nothing).
///
/// Early exits over `limits.max_output_bytes`: output already past the cap, with or without a
/// terminal row, is refused at once under kRefuse (kOutputTooLarge) and cut at a newline and
/// flagged `truncated` at once under kTruncateAtNewline. A failure row still wins over both.
[[nodiscard]] LivePollOutcome poll_live_output(const LiveRowsFn& read_rows, std::string_view agent_id,
                                               const LivePollLimits& limits,
                                               const LiveSleepFn& sleep_fn = {},
                                               const LiveStopFn& should_stop = {},
                                               const LiveClockFn& now_fn = {});

/// Production wiring: reads `command_id`'s rows for `agent_id` from `store`, scoped in SQL, under
/// `ResponseTierFilter::for_fixed_plugin_poll(forensics_plugins)`.
[[nodiscard]] LivePollOutcome poll_live_output(const ResponseStore& store, const std::string& command_id,
                                               std::string_view agent_id,
                                               const ForensicsPluginSet* forensics_plugins,
                                               const LivePollLimits& limits,
                                               const LiveSleepFn& sleep_fn = {},
                                               const LiveStopFn& should_stop = {},
                                               const LiveClockFn& now_fn = {});

} // namespace yuzu::server::live
