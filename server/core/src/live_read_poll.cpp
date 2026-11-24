#include "live_read_poll.hpp"

#include "utf8_clamp.hpp"

#include <algorithm>
#include <thread>
#include <utility>

namespace yuzu::server::live {

namespace {

/// Append one chunk to the joined text. A chunk boundary is a line boundary, so a '\n' is added
/// between two non-empty chunks unless the text so far already ends in one. An empty chunk adds
/// nothing, and the first chunk is never prefixed.
void append_chunk(std::string& joined, const std::string& chunk) {
    if (chunk.empty())
        return;
    if (!joined.empty() && joined.back() != '\n')
        joined.push_back('\n');
    joined += chunk;
}

/// `text` cut to at most kLiveDetailMaxBytes at a UTF-8 character boundary.
std::string detail_of(std::string_view text) {
    return std::string(utf8_clamp_prefix(text, kLiveDetailMaxBytes));
}

} // namespace

LiveRowsVerdict reduce_rows(std::span<const StoredResponse> rows, std::string_view agent_id) {
    // Only this agent's rows, ordered ascending by row id alone: the id is assigned at insert, so
    // it is ingest order, which the second-resolution timestamp is not (see the header).
    std::vector<const StoredResponse*> mine;
    mine.reserve(rows.size());
    for (const auto& r : rows) {
        if (r.agent_id == agent_id)
            mine.push_back(&r);
    }
    std::ranges::sort(mine, [](const StoredResponse* a, const StoredResponse* b) { return a->id < b->id; });

    LiveRowsVerdict v;
    bool failed = false;
    bool terminal = false; // ANY row with status >= 1 (a success or a failure)
    std::string failure_text;
    for (const auto* r : mine) {
        if (r->status >= 2) {
            failed = true;
            failure_text = r->error_detail; // the latest failing row speaks last
        }
        if (r->status >= 1)
            terminal = true;
    }

    // FAILURE WINS: a failed row answers a failure even when partial output is also present, and
    // before any joining work is spent on output that will be discarded.
    if (failed) {
        v.outcome = LiveOutcome::kDeviceFailed;
        v.detail = detail_of(failure_text);
        return v;
    }

    std::string joined;
    for (const auto* r : mine)
        append_chunk(joined, r->output);

    if (!terminal) {
        // Nothing decided: output may be on its way (a RUNNING chunk landed before the terminal
        // frame). The joined text is handed back only so the loop can stop early over the cap.
        v.partial = !joined.empty();
        v.output = std::move(joined);
        return v; // outcome stays kTimeout (undecided)
    }
    if (joined.rfind("error|", 0) == 0) {
        v.outcome = LiveOutcome::kDeviceError;
        v.detail = detail_of(std::string_view(joined).substr(6));
        return v;
    }
    v.outcome = LiveOutcome::kOk; // a terminal row, with or without output (empty success)
    v.output = std::move(joined);
    return v;
}

namespace {

/// Apply the byte cap to a joined answer. `head_lost` means the store left the oldest rows out,
/// so the answer is over the cap whatever its length. Returns false when the answer must be
/// refused (kRefuse); under kTruncateAtNewline it cuts and flags instead and returns true.
bool apply_output_cap(LivePollOutcome& out, const LivePollLimits& limits, bool head_lost) {
    const bool over = head_lost || out.output.size() > limits.max_output_bytes;
    if (!over)
        return true;
    if (limits.over_cap == OverCapPolicy::kRefuse)
        return false;
    out.truncated = true;
    if (out.output.size() <= limits.max_output_bytes)
        return true; // only the head was lost: what is left fits
    // Cut at the last newline inside the cap so no row is split; with no newline inside the cap
    // nothing whole fits and the answer is empty and truncated. A CRLF line keeps no '\r'.
    const std::string_view head(out.output.data(), limits.max_output_bytes);
    const auto nl = head.rfind('\n');
    std::size_t keep = nl == std::string_view::npos ? 0 : nl;
    if (keep > 0 && out.output[keep - 1] == '\r')
        --keep;
    out.output.resize(keep);
    return true;
}

/// An answer over the cap that must be refused.
LivePollOutcome too_large() {
    LivePollOutcome out;
    out.outcome = LiveOutcome::kOutputTooLarge;
    return out;
}

} // namespace

LivePollOutcome poll_live_output(const LiveRowsFn& read_rows, std::string_view agent_id,
                                 const LivePollLimits& limits, const LiveSleepFn& sleep_fn,
                                 const LiveStopFn& should_stop, const LiveClockFn& now_fn) {
    const auto now = [&]() { return now_fn ? now_fn() : std::chrono::steady_clock::now(); };
    const auto stopping = [&]() { return should_stop && should_stop(); };
    const auto deadline = now() + limits.deadline;

    int degraded = 0;
    int polls = 0;
    bool saw_partial = false;
    for (int i = 0; i < limits.max_polls; ++i) {
        if (stopping()) {
            LivePollOutcome out;
            out.outcome = LiveOutcome::kShuttingDown;
            return out;
        }
        if (i > 0) { // read first; back off only after a miss
            if (now() >= deadline)
                break; // the wall budget is spent (slow reads count against it)
            if (sleep_fn)
                sleep_fn(limits.interval);
            else
                std::this_thread::sleep_for(limits.interval);
            if (stopping()) {
                LivePollOutcome out;
                out.outcome = LiveOutcome::kShuttingDown;
                return out;
            }
        }
        ++polls;
        // A degraded read is empty for this iteration; the bounded loop retries (deny-or-benign).
        const auto read = read_rows ? read_rows() : std::nullopt;
        if (!read) {
            ++degraded;
            continue;
        }
        auto verdict = reduce_rows(read->rows, agent_id);
        LivePollOutcome out;
        switch (verdict.outcome) {
        case LiveOutcome::kOk:
            out.outcome = LiveOutcome::kOk;
            out.output = std::move(verdict.output);
            if (!apply_output_cap(out, limits, read->capped))
                return too_large();
            return out;
        case LiveOutcome::kDeviceFailed:
        case LiveOutcome::kDeviceError:
            out.outcome = verdict.outcome;
            out.detail = std::move(verdict.detail);
            return out;
        default: // kTimeout: undecided, read again unless the output is already over the cap
            break;
        }
        if (verdict.partial) {
            saw_partial = true;
            // Output past the cap decides the answer without waiting for a terminal row: more
            // output can only make it larger, and every further read would re-materialise it.
            if (read->capped || verdict.output.size() > limits.max_output_bytes) {
                out.outcome = LiveOutcome::kOk;
                out.output = std::move(verdict.output);
                if (!apply_output_cap(out, limits, read->capped))
                    return too_large();
                return out;
            }
        }
    }
    LivePollOutcome out;
    if (polls > 0 && degraded == polls) {
        out.outcome = LiveOutcome::kStoreDegraded;
    } else if (saw_partial) {
        out.outcome = LiveOutcome::kIncomplete;
        out.detail = std::string(kLiveIncompleteDetail); // the partial output is discarded
    } else {
        out.outcome = LiveOutcome::kTimeout;
    }
    return out;
}

LivePollOutcome poll_live_output(const ResponseStore& store, const std::string& command_id,
                                 std::string_view agent_id, const ForensicsPluginSet* forensics_plugins,
                                 const LivePollLimits& limits, const LiveSleepFn& sleep_fn,
                                 const LiveStopFn& should_stop, const LiveClockFn& now_fn) {
    // #4990: this poll reads back a command the caller dispatched itself from the fixed live
    // kinds (device info plugins, none Forensics-tier), so the Forensics tier is excluded
    // outright rather than derived from the caller. A null set refuses every row.
    const auto tier = ResponseTierFilter::for_fixed_plugin_poll(forensics_plugins);
    ResponseQuery q;
    q.agent_id = std::string(agent_id); // scoped in SQL, before the LIMIT
    q.limit = kLivePollRowLimit;
    // Rank by id alone: ids are the order the reducer trusts, a stored timestamp can step
    // backwards, and a timestamp ranking could then cut the terminal row (the newest by id) at
    // the row limit or the byte cap before the reducer sees it. With `order_by_id`, query_bounded
    // keeps the newest row by id (the terminal row) and cuts the older rows at the byte cap, so
    // the LIMIT edge is deterministic. A cut or a row-limit hit means the head of the answer is
    // missing: `capped`.
    q.order_by_id = true;
    return poll_live_output(
        [&]() -> std::optional<LiveRowsRead> {
            auto bounded = store.query_bounded(command_id, tier, q, std::nullopt, limits.max_output_bytes);
            if (!bounded)
                return std::nullopt;
            LiveRowsRead read;
            read.capped = bounded->row_cap_hit || bounded->byte_cap_hit;
            read.rows = std::move(bounded->rows);
            return read;
        },
        agent_id, limits, sleep_fn, should_stop, now_fn);
}

} // namespace yuzu::server::live
